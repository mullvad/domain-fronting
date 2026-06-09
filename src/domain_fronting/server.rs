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

use futures::{Stream, StreamExt, TryStreamExt, stream::abortable};
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Either, Empty, StreamBody};
use hyper::body::{Body, Bytes, Frame};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, tcp},
    time::sleep,
};
use tokio_util::{io::ReaderStream, sync::CancellationToken};

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
}

impl<C: UpstreamConnector> std::fmt::Debug for Server<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("config", &self.config)
            .field("stats", &self.stats.freeze())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct Config {
    /// Address of the upstream host.
    pub upstream: SocketAddr,
    /// HTTP header _key_ used for the shared secret.
    pub auth_header_key: String,
    /// Shared secret.
    pub auth_header_val: String,
    /// Total timeout of one HTTP request.
    pub total_timeout: Option<Duration>,
    /// Timeout of one HTTP request when no data is being sent in either direction.
    pub idle_timeout: Option<Duration>,
}

impl Config {
    pub fn new(upstream: SocketAddr, auth_header_key: String, auth_header_val: String) -> Self {
        Self {
            upstream,
            auth_header_key,
            auth_header_val,
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
            stats: Arc::new(AtomicStats::default()),
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
        let (head, request_stream) = request.into_parts();

        if head
            .headers
            .get(&self.config.auth_header_key)
            .is_none_or(|value| value != &self.config.auth_header_val)
        {
            return bad_request().map(Either::Left);
        };

        let ct = CancellationToken::new();

        // TODO: implement self.config.idle timeout

        if let Some(total_timeout) = self.config.total_timeout {
            let ct = ct.clone();
            tokio::spawn(ct.clone().run_until_cancelled_owned(async move {
                sleep(total_timeout).await;
                ct.cancel();
            }));
        }

        let connect_fut = self.connector.connect(self.config.upstream);
        let connect_fut = ct.run_until_cancelled(connect_fut);
        let (upstream_read, upstream_write) = match connect_fut.await {
            Some(Ok(conn)) => conn,
            Some(Err(e)) => {
                log::error!("Failed to connect to upstream server: {e}");
                return bad_request().map(Either::Left);
            }
            None => {
                log::error!("Timeout when connecting to upstream server");
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

    /// Create a stream that reads all bytes from `reader` into an HTTP body.
    fn reader_to_http_body(
        &self,
        reader: C::Read,
        ct: CancellationToken,
    ) -> StreamBody<impl Stream<Item = io::Result<Frame<Bytes>>> + use<C>> {
        let ct2 = ct.clone();
        let stats = Arc::clone(&self.stats);
        let stream = ReaderStream::new(reader)
            .inspect_ok(move |bytes| {
                let n = bytes.len() as u64;
                stats.bytes_rx.fetch_add(n, Ordering::Relaxed);
            })
            .inspect_err(move |_| ct2.cancel())
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
        let auth_key = "X-Auth";
        let auth_val = "password";
        let config = Config::new(dummy_addr(), auth_key.to_string(), auth_val.to_string());
        let server = Server::with_connector(config, connector);

        assert_eq!(server.take_stats(), Stats::default());

        // Proxied data should increment stats counter
        let response = server
            .clone()
            .handle_request(
                Request::builder()
                    .header(auth_key, auth_val)
                    .body(Full::new(Bytes::from("hello there")))
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.collect().await.unwrap();
        assert_eq!(body.to_bytes().len(), 26);
        let stats = server.take_stats();
        assert_eq!(stats.bytes_tx, 11);
        assert_eq!(stats.bytes_rx, 26);

        // Proxied data should have been zeroed by `take_stats`
        let stats = server.take_stats();
        assert_eq!(stats, Default::default());

        // Proxied data should increment stats counter again
        let response = server
            .clone()
            .handle_request(
                Request::builder()
                    .header(auth_key, auth_val)
                    .body(Full::new(Bytes::from("hello again!!!")))
                    .unwrap(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.collect().await.unwrap();
        assert_eq!(body.to_bytes().len(), 29);
        let stats = server.take_stats();
        assert_eq!(stats.bytes_tx, 14);
        assert_eq!(stats.bytes_rx, 29);
    }
}
