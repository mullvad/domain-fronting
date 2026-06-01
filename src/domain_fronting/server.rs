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

use std::{
    fmt::Display,
    future::Future,
    io,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::BytesMut;
use futures::{FutureExt, Stream, StreamExt, stream};
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Either, Empty, StreamBody};
use hyper::body::{Body, Bytes, Frame};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, tcp},
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

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

/// Manages domain fronting sessions, routing HTTP requests to upstream connections.
pub struct Sessions<C: UpstreamConnector = TcpConnector> {
    config: Config,
    connector: C,
    stats: Arc<AtomicStats>,
}

impl<C: UpstreamConnector> std::fmt::Debug for Sessions<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sessions")
            .field("configuration", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Config {
    pub upstream: SocketAddr,
    pub session_header_key: String,
    pub total_timeout: Option<Duration>,
    pub idle_timeout: Option<Duration>,
}

impl Config {
    pub fn new(upstream: SocketAddr, session_header_key: String) -> Self {
        Self {
            upstream,
            session_header_key,
            total_timeout: None,
            idle_timeout: None,
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

impl Sessions<TcpConnector> {
    /// Create a new session manager with the default TCP connector.
    pub fn new(config: Config) -> Arc<Self> {
        Self::with_connector(config, TcpConnector)
    }
}

impl<C: UpstreamConnector> Sessions<C> {
    /// Create a new session manager with a custom connector.
    ///
    /// This allows injecting test doubles or alternative transports.
    pub fn with_connector(config: Config, connector: C) -> Arc<Self> {
        let sessions = Sessions {
            config,
            connector,
            stats: Arc::new(AtomicStats::default()),
        };
        Arc::new(sessions)
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
        let (head, request_stream) = request.into_parts();

        // TODO: remove this?
        let Some(_session_id) = head
            .headers
            .get(&self.config.session_header_key)
            .and_then(|value| Uuid::try_parse_ascii(value.as_ref()).ok())
        else {
            return bad_request().map(Either::Left);
        };

        let ct = CancellationToken::new();

        if let Some(total_timeout) = self.config.total_timeout {
            let ct = ct.clone();
            tokio::spawn(ct.clone().run_until_cancelled_owned(async move {
                sleep(total_timeout).await;
                ct.cancel();
            }));
        }

        // TODO: timeout
        let (upstream_read, upstream_write) =
            match self.connector.connect(self.config.upstream).await {
                Ok(conn) => conn,
                Err(e) => {
                    log::error!("Failed to connect to upstream server: {e}");
                    return bad_request().map(Either::Left);
                }
            };

        // stream HTTP request data to upstream connection
        tokio::spawn(
            ct.clone()
                .run_until_cancelled_owned(Self::http_body_to_writer(
                    Arc::clone(&self.stats),
                    request_stream,
                    upstream_write,
                    ct.clone(),
                )),
        );

        // stream data from upstream connection into the HTTP response
        let response_stream = self.reader_to_http_body(upstream_read, ct.clone());

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Either::Right(response_stream))
            .expect("Response is valid")
    }

    /// Read all bytes from `reader` into an HTTP body.
    fn reader_to_http_body(
        &self,
        reader: C::Read,
        ct: CancellationToken,
    ) -> StreamBody<impl Stream<Item = io::Result<Frame<Bytes>>> + use<C>> {
        struct StreamState<R> {
            reader: R,
            buf: BytesMut,
            stats: Arc<AtomicStats>,
            ct: CancellationToken,
        }

        let state = StreamState {
            reader,
            buf: BytesMut::new(),
            stats: Arc::clone(&self.stats),
            ct,
        };

        let stream = stream::unfold(state, move |mut state| {
            let ct = state.ct.clone();
            ct.clone()
                .run_until_cancelled_owned(async move {
                    // TODO: make values configurable
                    if state.buf.capacity() < 1024 {
                        state.buf.reserve(4096);
                    }

                    let Ok(n) = state.reader.read_buf(&mut state.buf).await else {
                        state.ct.cancel(); // Cancel the connection on any error
                        return None;
                    };

                    if state.buf.is_empty() {
                        return None; // EOF
                    }

                    state.stats.bytes_rx.fetch_add(n as u64, Ordering::Relaxed);

                    Some((Ok(Frame::data(state.buf.split().freeze())), state))
                })
                .map(|option| option.flatten())
        });

        StreamBody::new(stream)
    }

    /// Write all [`Bytes`] from an HTTP body into an [`AsyncWrite`].
    async fn http_body_to_writer<E>(
        stats: Arc<AtomicStats>,
        stream: impl Body<Data = Bytes, Error = E> + Unpin,
        mut writer: impl AsyncWrite + Unpin,
        ct: CancellationToken,
    ) where
        E: Display,
    {
        let mut stream = stream.into_data_stream();
        loop {
            let Some(data) = stream.next().await else {
                log::debug!("[http->tcp] eof");
                break;
            };

            let data = match data {
                Ok(data) => data,
                Err(e) => {
                    log::debug!("[http->tcp] read error: {e}");
                    ct.cancel(); // Cancel the connection on any error
                    break;
                }
            };

            if let Err(e) = writer.write_all(&data).await {
                log::debug!("[http->tcp] write error: {e}");
                ct.cancel(); // Cancel the connection on any error
                break;
            };

            let n = data.len() as u64;
            stats.bytes_tx.fetch_add(n, Ordering::Relaxed);
        }
    }

    pub fn take_stats(&self) -> Stats {
        Stats {
            bytes_tx: self.stats.bytes_tx.swap(0, Ordering::Relaxed),
            bytes_rx: self.stats.bytes_rx.swap(0, Ordering::Relaxed),
        }
    }
}

/// Build an HTTP [`Response`] with status code `400` and no data.
fn bad_request() -> Response<Empty<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Empty::new())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf, split};

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
        let session_key = "X-Session";
        let config = Config::new(dummy_addr(), session_key.to_string());
        let sessions = Sessions::with_connector(config, connector);

        let session_id = Uuid::new_v4();

        assert_eq!(sessions.take_stats(), Stats::default());

        // First request with upstream response should increment counter
        let response = sessions
            .clone()
            .handle_request(
                Request::builder()
                    .header(session_key, session_id.to_string())
                    .body(Full::new(Bytes::from("hello there")))
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.collect().await.unwrap();
        assert_eq!(body.to_bytes().len(), 26);
        let stats = sessions.take_stats();
        assert_eq!(stats.bytes_tx, 11);
        assert_eq!(stats.bytes_rx, 26);

        // Second request on same session should NOT increment again
        let response = sessions
            .clone()
            .handle_request(
                Request::builder()
                    .header(session_key, session_id.to_string())
                    .body(Full::new(Bytes::from("hello again!!!")))
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.collect().await.unwrap();
        assert_eq!(body.to_bytes().len(), 29);
        let stats = sessions.take_stats();
        assert_eq!(stats.bytes_tx, 14);
        assert_eq!(stats.bytes_rx, 29);
    }
}
