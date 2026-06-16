// Copyright (C) 2026 Mullvad VPN AB
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Domain fronting server implementation. See [`Server`]

use std::{
    collections::HashMap,
    convert::Infallible,
    fmt::Display,
    future::{Future, pending},
    io,
    net::SocketAddr,
    ops::DerefMut as _,
    pin::Pin,
    str::FromStr as _,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::bail;
use futures::{Stream, StreamExt, TryStreamExt, stream::abortable};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Either, Empty, StreamBody};
use hyper::body::{Body, Bytes, Frame};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, tcp},
    sync::OwnedMutexGuard,
    time::sleep,
};
use tokio_util::{io::ReaderStream, sync::CancellationToken};
use uuid::Uuid;

use crate::DomainFronting;

/// Factory trait for creating upstream connections.
///
/// This trait abstracts how upstream connections are created, allowing
/// injection of test doubles or alternative transports.
pub trait UpstreamConnector: Clone + Send + Sync + 'static {
    /// The read-half of the stream roduced by this connector.
    type Read: AsyncRead + Unpin + Send + 'static;
    /// The write-half of the stream roduced by this connector.
    type Write: AsyncWrite + Unpin + Send + 'static;

    /// Connect to the given address.
    fn connect(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = io::Result<(Self::Read, Self::Write)>> + Send;
}

/// Default connector using [`tokio`] TCP streams.
#[derive(Clone, Default)]
pub struct TcpConnector;

impl UpstreamConnector for TcpConnector {
    type Read = tcp::OwnedReadHalf;
    type Write = tcp::OwnedWriteHalf;

    async fn connect(&self, addr: SocketAddr) -> io::Result<(Self::Read, Self::Write)> {
        TcpStream::connect(addr).await.map(|tcp| tcp.into_split())
    }
}

/// Domain fronting server. Handles HTTP requests and proxies data over the [`UpstreamConnector`].
pub struct Server<C: UpstreamConnector = TcpConnector> {
    config: Config,
    connector: C,
    stats: Arc<AtomicStats>,
    sessions: Mutex<HashMap<Uuid, Weak<Session<C>>>>,
}

struct Session<C: UpstreamConnector> {
    upstream_read: Arc<tokio::sync::Mutex<C::Read>>,
    upstream_write: tokio::sync::Mutex<C::Write>,
    ct: CancellationToken,
    session_id: Uuid,
    server: Weak<Server<C>>,
}

impl<C: UpstreamConnector> Drop for Session<C> {
    fn drop(&mut self) {
        if let Some(server) = self.server.upgrade() {
            self.ct.cancel();
            let mut sessions = server.sessions.lock().unwrap();
            sessions.remove(&self.session_id);
        }
    }
}

impl<C: UpstreamConnector> std::fmt::Debug for Server<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .field("stats", &self.stats.freeze())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Address of the upstream host.
    pub upstream: SocketAddr,
    /// HTTP header key used for the shared secret.
    pub auth_key: String,
    /// Shared secret.
    pub auth: String,
    /// HTTP header key used for the session id.
    pub session_key: String,
    /// Total timeout of one HTTP request.
    pub total_timeout: Option<Duration>,
    /// Timeout of one HTTP request when no data is being sent in either direction.
    pub idle_timeout: Option<Duration>,
}

impl Config {
    pub fn new(upstream: SocketAddr, auth: String) -> Self {
        Self {
            upstream,
            auth,
            auth_key: DomainFronting::DEFAULT_AUTH_KEY.into(),
            session_key: DomainFronting::DEFAULT_SESSION_KEY.into(),
            total_timeout: None,
            idle_timeout: None,
        }
    }

    pub fn with_auth_key(self, auth_key: String) -> Self {
        Self { auth_key, ..self }
    }

    pub fn with_session_key(self, session_key: String) -> Self {
        Self {
            session_key,
            ..self
        }
    }
}

#[derive(Debug, Default)]
struct AtomicStats {
    bytes_tx: AtomicU64,
    bytes_rx: AtomicU64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub bytes_tx: u64,
    pub bytes_rx: u64,
}

impl Server<TcpConnector> {
    /// Create a new server with the default TCP connector.
    pub fn new(config: Config) -> Arc<Self> {
        Self::with_connector(config, TcpConnector)
    }
}

impl<C: UpstreamConnector> Server<C> {
    /// Create a new server with a custom connector.
    ///
    /// This allows injecting test doubles or alternative transports.
    pub fn with_connector(config: Config, connector: C) -> Arc<Self> {
        let server = Server {
            config,
            connector,
            stats: Default::default(),
            sessions: Default::default(),
        };
        Arc::new(server)
    }

    /// Connect to [`Config::upstream`] and start forwarding data between the HTTP request,
    /// body and the upstream connection.
    ///
    /// # Errors
    /// - If [`UpstreamConnector::connect`] returns an error, the status code will be `BAD REQUEST`.
    /// - Otherwise, the status code will be `OK`.
    /// - If any error occurs after `connect`, the stream will be abruptly terminated.
    pub async fn handle_request<B, E>(
        self: Arc<Self>,
        request: Request<B>,
    ) -> Response<Either<Empty<Bytes>, StreamBody<impl Stream<Item = io::Result<Frame<Bytes>>>>>>
    where
        B: Body<Data = Bytes, Error = E>,
        B: Send + Unpin + 'static,
        E: Display + Send + 'static,
    {
        let (head, body) = request.into_parts();

        let auth = head.headers.get(&self.config.auth_key);
        if auth.is_none_or(|value| value != &self.config.auth) {
            log::warn!("Invalid auth header: {auth:?}");
            return bad_request().map(Either::Left);
        };

        let is_read_request = match head.method {
            Method::GET => true,
            Method::POST => false,
            _ => return bad_request().map(Either::Left),
        };

        let session_id = head
            .headers
            .get(&self.config.session_key)
            .and_then(|s| s.to_str().ok())
            .and_then(|s| Uuid::from_str(s).ok());
        let Some(session_id) = session_id else {
            return bad_request().map(Either::Left);
        };

        // TODO: race condition between creating session, and putting it in the map
        let existing_session = self
            .sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .and_then(|weak| weak.upgrade());

        let session = match existing_session {
            Some(existing_session) => existing_session,
            None => match self.new_session(session_id).await {
                Ok(new_session) => new_session,
                Err(e) => {
                    log::error!("{e}");
                    return bad_request().map(Either::Left); // failed to create session
                }
            },
        };

        if is_read_request {
            self.handle_read_request(session).await.map(Either::Right)
        } else {
            self.handle_write_request(body, session)
                .await
                .map(Either::Left)
        }
    }

    /// Stream data from `request_body` to [`Session::upstream_write`].
    async fn handle_write_request<E>(
        self: Arc<Self>,
        request_body: impl Body<Data = Bytes, Error = E> + Unpin,
        session: Arc<Session<C>>,
    ) -> Response<Empty<Bytes>>
    where
        E: Display,
    {
        let mut upstream_write = session.upstream_write.lock().await;
        let n = session
            .ct
            .run_until_cancelled(Self::http_body_to_writer(
                self.stats.clone(),
                request_body,
                &mut *upstream_write,
                session.ct.clone(),
            ))
            .await;

        match n {
            Some(0) | None => bad_request(),
            Some(1..) => Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Empty::new())
                .expect("Response is valid"),
        }
    }

    /// Stream data from [`Session::upstream_read`] into the response body.
    async fn handle_read_request(
        self: Arc<Self>,
        session: Arc<Session<C>>,
    ) -> Response<StreamBody<impl Stream<Item = io::Result<Frame<Bytes>>>>> {
        struct LockedRead<R>(OwnedMutexGuard<R>);

        impl<R: AsyncRead + Unpin> AsyncRead for LockedRead<R> {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                let inner = self.get_mut().0.deref_mut();
                let inner = Pin::new(inner);
                AsyncRead::poll_read(inner, cx, buf)
            }
        }

        let session_id = session.session_id.to_string();
        let upstream_read = LockedRead(session.upstream_read.clone().lock_owned().await);

        // stream data from upstream connection into the HTTP response
        let response_stream = self.reader_to_http_body(upstream_read, session);
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CACHE_CONTROL, "no-cache, no-store, no-transform")
            .header(header::TRANSFER_ENCODING, "chunked")
            .header(&self.config.session_key, session_id)
            .body(response_stream)
            .expect("Response is valid")
    }

    /// Connect to upstream and crate a new `session`.
    ///
    /// Returns `Err` if connection to upstream fails.
    async fn new_session(self: &Arc<Self>, session_id: Uuid) -> anyhow::Result<Arc<Session<C>>> {
        let ct = CancellationToken::new();

        // TODO: implement self.config.idle timeout
        if let Some(total_timeout) = self.config.total_timeout {
            let ct = ct.clone();
            tokio::spawn(ct.clone().run_until_cancelled_owned(async move {
                sleep(total_timeout).await;
                ct.cancel();
            }));
        } else {
            todo!("a timeout is required, or sessions will live forever");
        }

        let connect_fut = self.connector.connect(self.config.upstream);
        let connect_fut = ct.run_until_cancelled(connect_fut);
        let (upstream_read, upstream_write) = match connect_fut.await {
            Some(Ok(conn)) => conn,
            Some(Err(e)) => bail!("Failed to connect to upstream server: {e}"),
            None => bail!("Timeout when connecting to upstream server"),
        };

        let session = Arc::new(Session {
            upstream_read: Arc::new(tokio::sync::Mutex::new(upstream_read)),
            upstream_write: tokio::sync::Mutex::new(upstream_write),
            ct: ct.clone(),
            server: Arc::downgrade(self),
            session_id,
        });

        {
            // Keep session alive until cancelled (e.g. when timeout is reached)
            let session = Arc::clone(&session);
            tokio::spawn(ct.clone().run_until_cancelled_owned(async move {
                let _session = session;
                pending::<Infallible>().await
            }));
        }

        self.sessions
            .lock()
            .unwrap()
            .insert(session_id, Arc::downgrade(&session));

        Ok(session)
    }

    /// Create a stream that reads all bytes from `reader` into an HTTP body.
    fn reader_to_http_body<R: AsyncRead + Unpin + Send + 'static>(
        &self,
        reader: R,
        session: Arc<Session<C>>,
    ) -> StreamBody<impl Stream<Item = io::Result<Frame<Bytes>>> + use<C, R>> {
        let ct = session.ct.clone();
        let stats = Arc::clone(&self.stats);
        let stream = ReaderStream::new(reader)
            .inspect_ok(move |bytes| {
                let n = bytes.len() as u64;
                stats.bytes_rx.fetch_add(n, Ordering::Relaxed);
            })
            .inspect(move |_| {
                // Cheeky way of moving `session` into the stream,
                // such that it is kept alive until the stream closes.
                _ = &session;
            })
            .map_ok(Frame::data);

        // interrupt the stream it the CancellationToken is triggered
        let (stream, abort_handle) = abortable(stream);
        tokio::spawn(async move {
            ct.cancelled().await;
            abort_handle.abort();
        });

        StreamBody::new(stream)
    }

    /// Write all [`Bytes`] from an HTTP body into an [`AsyncWrite`].
    async fn http_body_to_writer<E>(
        stats: Arc<AtomicStats>,
        stream: impl Body<Data = Bytes, Error = E> + Unpin,
        mut writer: impl AsyncWrite + Unpin,
        ct: CancellationToken,
    ) -> usize
    where
        E: Display,
    {
        let mut stream = stream.into_data_stream();
        let mut total_written = 0;
        loop {
            let Some(data) = stream.next().await else {
                break;
            };

            let data = match data {
                Ok(data) => data,
                Err(e) => {
                    log::debug!("[http->tcp] read error: {e}");
                    ct.cancel();
                    break;
                }
            };

            if let Err(e) = writer.write_all(&data).await {
                log::debug!("[http->tcp] write error: {e}");
                ct.cancel();
                break;
            };

            let n = data.len();
            total_written += n;
            stats.bytes_tx.fetch_add(n as u64, Ordering::Relaxed);
        }

        total_written
    }

    pub fn take_stats(&self) -> Stats {
        self.stats.take()
    }
}

/// Build an HTTP [`Response`] with status code `400` and no data.
fn bad_request() -> Response<Empty<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Empty::new())
        .unwrap()
}

impl AtomicStats {
    /// Make a copy of the current stats.
    fn freeze(&self) -> Stats {
        Stats {
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
        }
    }

    /// Make a copy of the current stats and zero `self`.
    fn take(&self) -> Stats {
        Stats {
            bytes_tx: self.bytes_tx.swap(0, Ordering::Relaxed),
            bytes_rx: self.bytes_rx.swap(0, Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;
    use http_body_util::Full;
    use tokio::io::{AsyncReadExt as _, DuplexStream, ReadHalf, WriteHalf, split};

    /// Mock connector that just echoes incoming data.
    #[derive(Clone)]
    struct MockConnector {}

    impl MockConnector {
        fn new() -> Self {
            Self {}
        }
    }

    impl UpstreamConnector for MockConnector {
        type Read = ReadHalf<DuplexStream>;
        type Write = WriteHalf<DuplexStream>;

        async fn connect(&self, _addr: SocketAddr) -> io::Result<(Self::Read, Self::Write)> {
            let (local, mut remote) = tokio::io::duplex(8192);

            // Spawn a task to write a response on the upstream side
            tokio::spawn(async move {
                let mut buf = [0u8; 100];
                // Read the client's data first
                let n = remote.read(&mut buf[..]).await.unwrap();
                let data = &buf[..n];
                // Echo the request, and some more
                remote.write_all(b"general kenobi!").await.unwrap();
                remote.write_all(data).await.unwrap();
            });

            Ok(split(local))
        }
    }

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }

    /// Verify that we can send and receive data, and that `take_stats` returns the correct values.
    #[tokio::test(start_paused = true)]
    async fn stats() {
        let connector = MockConnector::new();
        let auth = "password";
        let config = Config::new(dummy_addr(), auth.to_string());
        let server = Server::with_connector(config.clone(), connector);

        assert_eq!(server.take_stats(), Stats::default());

        // Proxied data should increment stats counter
        let session_id = Uuid::new_v4();
        let reader = server
            .clone()
            .handle_request(
                Request::builder()
                    .method(Method::GET)
                    .header(&config.auth_key, auth)
                    .header(&config.session_key, session_id.to_string())
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .into_body();
        assert!(!reader.is_end_stream());
        let write_response = server
            .clone()
            .handle_request(
                Request::builder()
                    .method(Method::POST)
                    .header(&config.auth_key, auth)
                    .header(&config.session_key, session_id.to_string())
                    .body(Full::new(Bytes::from("hello there")))
                    .unwrap(),
            )
            .await;
        assert_eq!(write_response.status(), StatusCode::NO_CONTENT);
        let body = reader.collect().await.unwrap();
        assert_eq!(body.to_bytes().len(), 26);
        let stats = server.take_stats();
        assert_eq!(stats.bytes_tx, 11);
        assert_eq!(stats.bytes_rx, 26);

        // Proxied data should have been zeroed by `take_stats`
        let stats = server.take_stats();
        assert_eq!(stats, Default::default());

        // Proxied data should increment stats counter again
        let session_id = Uuid::new_v4();
        let reader = server
            .clone()
            .handle_request(
                Request::builder()
                    .method(Method::GET)
                    .header(&config.auth_key, auth)
                    .header(&config.session_key, session_id.to_string())
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .into_body();
        assert!(!reader.is_end_stream());
        let write_response = server
            .clone()
            .handle_request(
                Request::builder()
                    .method(Method::POST)
                    .header(&config.auth_key, auth)
                    .header(&config.session_key, session_id.to_string())
                    .body(Full::new(Bytes::from("hello again!!!")))
                    .unwrap(),
            )
            .await;
        assert_eq!(write_response.status(), StatusCode::NO_CONTENT);
        let body = reader.collect().await.unwrap();
        assert_eq!(body.to_bytes().len(), 29);
        let stats = server.take_stats();
        assert_eq!(stats.bytes_tx, 14);
        assert_eq!(stats.bytes_rx, 29);
    }
}
