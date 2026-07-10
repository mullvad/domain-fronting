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
    collections::{HashMap, hash_map},
    error::Error,
    fmt::Display,
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    str::FromStr as _,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, bail};
use bytes::BytesMut;
use futures::{Stream, StreamExt, stream};
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Either, Empty, StreamBody};
use hyper::body::{Body, Bytes, Frame};
use kameo::{
    Actor,
    actor::{ActorRef, WeakActorRef},
    prelude::Message,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, tcp},
    task::AbortHandle,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::DomainFronting;

/// Factory trait for creating upstream connections.
///
/// This trait abstracts how upstream connections are created, allowing
/// injection of test doubles or alternative transports.
pub trait UpstreamConnector: Clone + Send + Sync + 'static {
    /// The read-half of the stream produced by this connector.
    type Read: AsyncRead + Unpin + Send + Sync + 'static;
    /// The write-half of the stream produced by this connector.
    type Write: AsyncWrite + Unpin + Send + Sync + 'static;

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
    sessions: Mutex<HashMap<Uuid, WeakActorRef<Session<C>>>>,
}

/// A boxed trait object for a [`Stream`] of bytes.
type ByteStreamDyn = Pin<Box<dyn Stream<Item = io::Result<Frame<Bytes>>> + Send + 'static>>;

struct SessionArgs<C: UpstreamConnector> {
    session_id: Uuid,
    upstream: SocketAddr,
    server: Arc<Server<C>>,
    stats: Arc<AtomicStats>,
    ct: CancellationToken,
    idle_timeout: Option<Duration>,
}

struct Session<C: UpstreamConnector> {
    session_id: Uuid,
    upstream_read: Option<C::Read>,
    upstream_write: C::Write,
    idle_timeout: Option<Duration>,
    idle_timeout_task: Option<AbortHandle>,
    server: Weak<Server<C>>,
    stats: Arc<AtomicStats>,
    ct: CancellationToken,
}

impl<C: UpstreamConnector> Actor for Session<C> {
    type Args = SessionArgs<C>;
    type Error = anyhow::Error;

    async fn on_start(args: Self::Args, actor_ref: ActorRef<Self>) -> Result<Self, Self::Error> {
        let idle_timeout_task = args
            .idle_timeout
            .map(|idle_timeout| idle_timeout_watchdog(idle_timeout, &actor_ref));

        let (upstream_read, upstream_write) = args
            .server
            .connector
            .connect(args.upstream)
            .await
            .context("Failed to connect to upstream server")?;

        let mut session = Session {
            session_id: args.session_id,
            upstream_read: Some(upstream_read),
            upstream_write,
            idle_timeout: args.idle_timeout,
            idle_timeout_task,
            server: Arc::downgrade(&args.server),
            stats: args.stats,
            ct: args.ct,
        };

        session.pet_idle_watchdog(&actor_ref);

        Ok(session)
    }
}

/// Read bytes from [`Session::upstream_read`]
struct SessionRead;

impl<C: UpstreamConnector> Message<SessionRead> for Session<C> {
    type Reply = Option<ByteStreamDyn>;

    async fn handle(
        &mut self,
        _msg: SessionRead,
        ctx: &mut kameo::prelude::Context<Self, Self::Reply>,
    ) -> Self::Reply {
        // There can only ever be one reader.
        // If we get another read request, ignore it
        let reader = self.upstream_read.take()?;

        struct StreamState<C: UpstreamConnector> {
            reader: C::Read,
            session: WeakActorRef<Session<C>>,
            buf: BytesMut,
            stats: Arc<AtomicStats>,
            ct: CancellationToken,
        }

        let state = StreamState {
            reader,
            session: ctx.actor_ref().downgrade(),
            buf: BytesMut::new(),
            stats: self.stats.clone(),
            ct: self.ct.clone(),
        };

        let stream = stream::unfold(state, |mut state| async move {
            debug_assert!(state.buf.is_empty());
            if state.buf.capacity() < 1024 {
                state.buf.reserve(4096);
            }

            let read = state.reader.read_buf(&mut state.buf);
            let bytes = match state.ct.run_until_cancelled(read).await {
                Some(Ok(1..)) => state.buf.split().freeze(),
                _ => return None,
            };

            let n = bytes.len() as u64;
            state.stats.bytes_rx.fetch_add(n, Ordering::Relaxed);

            if let Some(session) = state.session.upgrade() {
                let _ = session.tell(SessionPetWatchdog).await;
            }

            let frame = io::Result::Ok(Frame::data(bytes));

            Some((frame, state))
        });

        Some(stream.boxed())
    }
}

/// Write some bytes to [`Session::upstream_write`]
struct SessionWrite(Bytes);

impl<C: UpstreamConnector> Message<SessionWrite> for Session<C> {
    type Reply = ();

    async fn handle(
        &mut self,
        SessionWrite(bytes): SessionWrite,
        ctx: &mut kameo::prelude::Context<Self, Self::Reply>,
    ) -> Self::Reply {
        if let Err(e) = self.upstream_write.write_all(&bytes).await {
            log::debug!("Failed to write data to upstream: {e:?}");
            ctx.stop();
        } else {
            let _ = ctx.actor_ref().tell(SessionPetWatchdog).await;
        }
    }
}

struct SessionPetWatchdog;

impl<C: UpstreamConnector> Message<SessionPetWatchdog> for Session<C> {
    type Reply = ();

    async fn handle(
        &mut self,
        _: SessionPetWatchdog,
        ctx: &mut kameo::prelude::Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.pet_idle_watchdog(ctx.actor_ref());
    }
}

impl<C: UpstreamConnector> Session<C> {
    fn pet_idle_watchdog(&mut self, actor_ref: &ActorRef<Self>) {
        if let Some(task) = self.idle_timeout_task.take() {
            task.abort();
        }

        self.idle_timeout_task = self
            .idle_timeout
            .map(|idle_timeout| idle_timeout_watchdog(idle_timeout, actor_ref));
    }
}

fn idle_timeout_watchdog<C: UpstreamConnector>(
    idle_timeout: Duration,
    actor_ref: &ActorRef<Session<C>>,
) -> AbortHandle {
    let actor_ref = actor_ref.clone();
    tokio::spawn(async move {
        sleep(idle_timeout).await;
        log::debug!("Idle session timed out");
        actor_ref.kill();
    })
    .abort_handle()
}

impl<C: UpstreamConnector> Drop for Session<C> {
    fn drop(&mut self) {
        self.ct.cancel();
        if let Some(server) = self.server.upgrade() {
            let mut sessions = server.sessions.lock().expect("lock poisoned");
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
    /// HTTP header key used for the session id.
    pub session_key: String,
    /// Total timeout of one HTTP request.
    pub total_timeout: Option<Duration>,
    /// Timeout of one HTTP request when no data is being sent in either direction.
    pub idle_timeout: Option<Duration>,
}

impl Config {
    pub fn new(upstream: SocketAddr) -> Self {
        Self {
            upstream,
            session_key: DomainFronting::DEFAULT_SESSION_KEY.into(),
            total_timeout: None,
            idle_timeout: None,
        }
    }

    pub fn with_session_key(self, session_key: String) -> Self {
        Self {
            session_key,
            ..self
        }
    }

    pub fn with_total_timeout(self, total_timeout: Duration) -> Self {
        Self {
            total_timeout: Some(total_timeout),
            ..self
        }
    }

    pub fn with_idle_timeout(self, idle_timeout: Duration) -> Self {
        Self {
            idle_timeout: Some(idle_timeout),
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
        if config.total_timeout.is_none() && config.idle_timeout.is_none() {
            log::warn!("No timeout specified! Sessions will live forever!");
        }
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
        E: Error + Display + Send + Sync + 'static,
    {
        self.handle_request_inner(request)
            .await
            .unwrap_or_else(|err| {
                log::debug!("handle_request error: {err:?}");
                bad_request().map(Either::Left)
            })
    }

    pub async fn handle_request_inner<B, E>(
        self: Arc<Self>,
        request: Request<B>,
    ) -> anyhow::Result<
        Response<Either<Empty<Bytes>, StreamBody<impl Stream<Item = io::Result<Frame<Bytes>>>>>>,
    >
    where
        B: Body<Data = Bytes, Error = E>,
        B: Send + Unpin + 'static,
        E: Error + Display + Send + Sync + 'static,
    {
        let (head, body) = request.into_parts();

        #[derive(PartialEq, Eq)]
        enum Method {
            Get,
            Post,
            Patch,
        }

        let method = match head.method {
            http::Method::GET => Method::Get,
            http::Method::POST => Method::Post,
            http::Method::PATCH => Method::Patch,
            method => bail!("Unexpected HTTP method: {method}"),
        };

        let can_create_session = method != Method::Patch;

        let session_id = head
            .headers
            .get(&self.config.session_key)
            .and_then(|s| s.to_str().ok())
            .and_then(|s| Uuid::from_str(s).ok());
        let Some(session_id) = session_id else {
            bail!("Invalid/missing session ID")
        };

        let session = {
            let mut sessions = self.sessions.lock().expect("lock poisoned");
            match sessions.entry(session_id) {
                hash_map::Entry::Occupied(mut entry) => {
                    if let Some(session) = entry.get().upgrade() {
                        session
                    } else if can_create_session {
                        let session = self.new_session(session_id);
                        entry.insert(session.downgrade());
                        session
                    } else {
                        bail!("Expired session");
                    }
                }
                hash_map::Entry::Vacant(entry) if can_create_session => {
                    let session = self.new_session(session_id);
                    entry.insert(session.downgrade());
                    session
                }
                hash_map::Entry::Vacant(..) => bail!("No session"),
            }
        };

        Ok(if let Method::Get = method {
            self.handle_read_request(session).await?.map(Either::Right)
        } else {
            self.handle_write_request(body, session)
                .await?
                .map(Either::Left)
        })
    }

    /// Stream data from `request_body` to [`Session::upstream_write`].
    async fn handle_write_request<E>(
        self: Arc<Self>,
        request_body: impl Body<Data = Bytes, Error = E> + Unpin,
        session: ActorRef<Session<C>>,
    ) -> anyhow::Result<Response<Empty<Bytes>>>
    where
        E: Error + Display + Send + Sync + 'static,
    {
        let mut data = request_body.into_data_stream();
        let mut total = 0;
        loop {
            let Some(data) = data.next().await else { break };
            let data = data?;
            let n = data.len();
            total += n;
            session.ask(SessionWrite(data)).await?;
            self.stats.bytes_tx.fetch_add(n as u64, Ordering::Relaxed);
        }

        Ok(match total {
            0 => bad_request(),
            1.. => Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Empty::new())
                .expect("Response is valid"),
        })
    }

    /// Stream data from [`Session::upstream_read`] into the response body.
    async fn handle_read_request(
        self: Arc<Self>,
        session: ActorRef<Session<C>>,
    ) -> anyhow::Result<Response<StreamBody<impl Stream<Item = io::Result<Frame<Bytes>>>>>> {
        let stream = session
            .ask(SessionRead)
            .await?
            .context("Multiple read requests are not allowed")?;
        let body = StreamBody::new(stream);
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CACHE_CONTROL, "no-cache, no-store, no-transform")
            .header(header::TRANSFER_ENCODING, "chunked")
            .body(body)
            .expect("Response is valid"))
    }

    /// Connect to upstream and crate a new `session`.
    ///
    /// Returns `Err` if connection to upstream fails.
    fn new_session(self: &Arc<Self>, session_id: Uuid) -> ActorRef<Session<C>> {
        let ct = CancellationToken::new();

        if let Some(total_timeout) = self.config.total_timeout {
            let ct = ct.clone();
            tokio::spawn(ct.clone().run_until_cancelled_owned(async move {
                sleep(total_timeout).await;
                log::debug!("Session timed out");
                ct.cancel();
            }));
        }

        let session = Session::spawn(SessionArgs {
            session_id,
            upstream: self.config.upstream,
            server: Arc::clone(self),
            stats: Arc::clone(&self.stats),
            ct: ct.clone(),
            idle_timeout: self.config.idle_timeout,
        });

        {
            // Keep session alive until cancelled (e.g. when timeout is reached)
            let session = ActorRef::clone(&session);
            tokio::spawn(async move {
                ct.cancelled().await;
                session.kill();
            });
        }

        session
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
        .expect("response is valid")
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
    use futures::FutureExt;
    use http::Method;
    use http_body_util::Full;
    use tokio::{
        io::{DuplexStream, ReadHalf, SimplexStream, WriteHalf, split},
        task::yield_now,
    };

    /// Mock connector that echoes the first incoming chunk and then exits.
    #[derive(Clone)]
    struct EchoConnector;

    impl UpstreamConnector for EchoConnector {
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

    /// Mock connector that drops all written data.
    #[derive(Clone)]
    struct NullConnector;

    impl UpstreamConnector for NullConnector {
        type Read = ReadHalf<SimplexStream>;
        type Write = tokio::io::Empty;

        async fn connect(&self, _addr: SocketAddr) -> io::Result<(Self::Read, Self::Write)> {
            let (local, remote) = tokio::io::simplex(1);

            // Leak the remote end to make calls to `read` wait forever
            Box::leak(Box::new(remote));

            Ok((local, tokio::io::empty()))
        }
    }

    /// Mock connector that always has data to read.
    #[derive(Clone)]
    struct SpamConnector;

    impl UpstreamConnector for SpamConnector {
        type Read = ReadHalf<SimplexStream>;
        type Write = tokio::io::Empty;

        async fn connect(&self, _addr: SocketAddr) -> io::Result<(Self::Read, Self::Write)> {
            let chunk = b"hello there!";
            let (local, mut remote) = tokio::io::simplex(chunk.len());

            // Spawn a task to write data on the upstream side
            tokio::spawn(async move {
                loop {
                    // Spam data
                    if remote.write_all(chunk).await.is_err() {
                        return;
                    }
                }
            });

            Ok((local, tokio::io::empty()))
        }
    }

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }

    async fn get<C: UpstreamConnector>(
        server: &Arc<Server<C>>,
        config: &Config,
        session: Uuid,
    ) -> Either<Empty<Bytes>, StreamBody<impl Stream<Item = io::Result<Frame<Bytes>>>>> {
        eprintln!("sending get request");
        server
            .clone()
            .handle_request(
                Request::builder()
                    .method(Method::GET)
                    .header(&config.session_key, session.to_string())
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .into_body()
    }

    async fn post<C: UpstreamConnector>(
        server: &Arc<Server<C>>,
        config: &Config,
        session: Uuid,
        bytes: impl AsRef<[u8]>,
    ) -> Response<impl Body> {
        let bytes = bytes.as_ref().to_vec();
        eprintln!("sending post request with {} bytes", bytes.len());
        server
            .clone()
            .handle_request(
                Request::builder()
                    .method(Method::POST)
                    .header(&config.session_key, session.to_string())
                    .body(Full::new(Bytes::from(bytes)))
                    .unwrap(),
            )
            .await
    }

    /// Test that idle-timeout works, and that writing to a session keeps it alive
    #[tokio::test(start_paused = true)]
    async fn idle_timeout_write() {
        // create a server with an idle-timeout of 3 seconds
        let config = Config::new(dummy_addr()).with_idle_timeout(Duration::from_secs(3));
        let server = Server::with_connector(config.clone(), NullConnector);

        let wait = async |seconds| {
            // yield a bunch to make sure that background tasks have been polled
            yield_now().await;
            tokio::time::advance(Duration::from_secs(seconds)).await;
            yield_now().await;
        };

        for stalls in [0, 1, 2, 99] {
            let session = Uuid::new_v4();
            let mut reader = get(&server, &config, session).await;
            yield_now().await;

            let mut session_must_be_alive = || {
                let None = reader.frame().now_or_never() else {
                    panic!("Stream should still be alive")
                };
            };

            session_must_be_alive();
            wait(2).await;
            session_must_be_alive();

            // keep the session alive by writing data every 2 seconds
            for _ in 0..stalls {
                post(&server, &config, session, "stay alive!").await;

                wait(2).await;
                session_must_be_alive();
            }

            // trigger a timeout by waiting for more than 3 seconds
            wait(4).await;

            let Some(None) = reader.frame().now_or_never() else {
                panic!("Stream must have ended after idle timeout")
            };
        }
    }

    /// Test that idle-timeout works, and that reading from a session keeps it alive
    #[tokio::test(start_paused = true)]
    async fn idle_timeout_read() {
        // create a server with an idle-timeout of 3 seconds
        let config = Config::new(dummy_addr()).with_idle_timeout(Duration::from_secs(3));
        let server = Server::with_connector(config.clone(), SpamConnector);

        let wait = async |seconds| {
            // yield a bunch to make sure that background tasks have been polled
            yield_now().await;
            tokio::time::advance(Duration::from_secs(seconds)).await;
            yield_now().await;
        };

        for stalls in [0, 1, 2, 99] {
            let session = Uuid::new_v4();
            let mut reader = get(&server, &config, session).await;
            yield_now().await;

            let mut session_must_be_alive = || {
                let Some(Some(Ok(_frame))) = dbg!(reader.frame().now_or_never()) else {
                    panic!("Stream should still be alive")
                };
            };

            session_must_be_alive();

            // keep the session alive by reading data every 2 seconds
            for _ in 0..stalls {
                wait(2).await;
                session_must_be_alive();
            }

            // trigger a timeout by waiting for more than 3 seconds
            wait(4).await;

            let None = dbg!(reader.frame().await) else {
                panic!("Stream must have ended after idle timeout")
            };
        }
    }

    /// Verify that we can send and receive data, and that `take_stats` returns the correct values.
    #[tokio::test(start_paused = true)]
    async fn stats() {
        let config = Config::new(dummy_addr());
        let server = Server::with_connector(config.clone(), EchoConnector);

        assert_eq!(server.take_stats(), Stats::default());

        // Proxied data should increment stats counter
        let session = Uuid::new_v4();
        let reader = get(&server, &config, session).await;
        assert!(!reader.is_end_stream());
        let write_response = post(&server, &config, session, "hello there").await;
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
        let session = Uuid::new_v4();
        let reader = get(&server, &config, session).await;
        assert!(!reader.is_end_stream());
        let write_response = post(&server, &config, session, "hello again!!!").await;
        assert_eq!(write_response.status(), StatusCode::NO_CONTENT);
        let body = reader.collect().await.unwrap();
        assert_eq!(body.to_bytes().len(), 29);
        let stats = server.take_stats();
        assert_eq!(stats.bytes_tx, 14);
        assert_eq!(stats.bytes_rx, 29);
    }
}
