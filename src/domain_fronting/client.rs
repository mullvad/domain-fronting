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

//! Domain fronting client implementation.

#[cfg(feature = "tls")]
use std::sync::Arc;
use std::{io, net::SocketAddr, pin::Pin, task::Poll};

use futures::{SinkExt, StreamExt, TryFutureExt, TryStreamExt, sink::SinkMapErr, stream};
use http::header;
use http_body_util::{BodyDataStream, BodyExt, StreamBody};
use hyper::body::{Body, Bytes, Frame, Incoming};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    task::AbortHandle,
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::{
    io::{CopyToBytes, SinkWriter, StreamReader},
    sync::{PollSendError, PollSender},
};

#[cfg(feature = "tls")]
use tokio::net::TcpStream;

#[cfg(feature = "tls")]
use {crate::tls_stream::TlsStream, tokio_rustls::rustls};

use super::{DomainFronting, Error};

/// Configuration for connecting to a domain fronting proxy.
///
/// Contains the resolved address and domain fronting configuration.
/// Created from [`DomainFronting::proxy_config()`].
#[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug, Clone)]
pub struct ProxyConfig {
    /// The resolved socket address of the CDN.
    pub addr: SocketAddr,
    /// Internal domain fronting configuration
    domain_fronting: DomainFronting,
}

impl ProxyConfig {
    /// Create a new ProxyConfig with the given address and domain fronting configuration.
    pub fn new(addr: SocketAddr, domain_fronting: DomainFronting) -> Self {
        Self {
            addr,
            domain_fronting,
        }
    }

    /// Connect to the proxy using a TCP connection with TLS and a custom certificate configuration.
    ///
    /// Requires the `tls` feature to be enabled.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[cfg(feature = "tls")]
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// use domain_fronting::{DomainFronting, ProxyConfig};
    /// use std::sync::Arc;
    /// use tokio_rustls::rustls;
    ///
    /// let df = DomainFronting::new(
    ///     "cdn.example.com".to_string(),
    ///     "api.example.com".to_string(),
    ///     "X-Auth".to_string(),
    ///     "password".to_string(),
    /// );
    ///
    /// let proxy_config = df.proxy_config().await?;
    ///
    /// // Create your TLS config with desired certificate store
    /// let mut root_store = rustls::RootCertStore::empty();
    /// // Add your certificates...
    ///
    /// let tls_config = Arc::new(
    ///     rustls::ClientConfig::builder()
    ///         .with_root_certificates(root_store)
    ///         .with_no_client_auth()
    /// );
    ///
    /// let client = proxy_config.connect_with_tls(tls_config).await?;
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    #[cfg(feature = "tls")]
    pub async fn connect_with_tls(
        &self,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<ProxyConnection, Error> {
        let tcp_stream = TcpStream::connect(self.addr)
            .await
            .map_err(Error::Connection)?;
        self.connect_stream_with_tls(tcp_stream, tls_config).await
    }

    /// Connect with a custom stream and TLS configuration.
    ///
    /// This allows you to provide your own transport stream (for testing or custom networking)
    /// and your own certificate store and TLS settings.
    ///
    /// Requires the `tls` feature to be enabled.
    #[cfg(feature = "tls")]
    pub async fn connect_stream_with_tls<S>(
        &self,
        stream: S,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<ProxyConnection, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let tls = TlsStream::connect_with_config(stream, self.domain_fronting.front(), tls_config)
            .await
            .map_err(Error::Tls)?;
        ProxyConnection::from_stream(
            tls,
            self.domain_fronting.proxy_host(),
            self.domain_fronting.auth_header_key(),
            self.domain_fronting.auth_header_val(),
        )
        .await
    }

    /// Connect with a custom stream
    ///
    /// This allows using arbitrary transports like in-memory streams for testing
    /// or when TLS is handled externally.
    pub async fn connect_with_stream<S>(&self, stream: S) -> Result<ProxyConnection, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        ProxyConnection::from_stream(
            stream,
            self.domain_fronting.proxy_host(),
            self.domain_fronting.auth_header_key(),
            self.domain_fronting.auth_header_val(),
        )
        .await
    }
}

/// A mess of types to convert a `Sink<Bytes>` into an [`AsyncWrite`].
type RequestTx =
    SinkWriter<SinkMapErr<CopyToBytes<PollSender<Bytes>>, fn(PollSendError<Bytes>) -> io::Error>>;

/// A mess of types to convert a `Stream<Bytes>` into an [`AsyncRead`].
type ResponseRx =
    StreamReader<stream::MapErr<BodyDataStream<Incoming>, fn(hyper::Error) -> io::Error>, Bytes>;

pub struct ProxyConnection {
    /// [`AsyncWrite`] for the HTTP request body.
    request_tx: RequestTx,

    /// [`AsyncRead`] for the HTTP response body.
    response_rx: ResponseRx,

    /// Abort handle for the connection task
    connection_task: AbortHandle,
}

impl ProxyConnection {
    /// Create a proxy connection from any AsyncRead + AsyncWrite stream.
    ///
    /// This performs the HTTP handshake over the provided stream.
    /// Use `ProxyConfig::connect_stream_with_tls` if you need TLS support.
    pub async fn from_stream<S>(
        stream: S,
        proxy_host: &str,
        auth_header_key: &str,
        auth_header_val: &str,
    ) -> Result<Self, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        let conn = conn.inspect_err(|err| {
            log::error!("Domain fronting connection failed: {:?}", err);
        });
        let connection_task = tokio::spawn(conn).abort_handle();

        let (request_tx, request_rx) = mpsc::channel::<Bytes>(1);

        // convert the mpsc::Sender to an AsyncWrite
        let request_tx = CopyToBytes::new(PollSender::new(request_tx));
        let request_tx = request_tx.sink_map_err(io::Error::other as fn(_) -> _);
        let request_tx: RequestTx = SinkWriter::new(request_tx);

        // convert the mpsc::Receiver to a Stream<io::Result<Frame<Bytes>>>
        let request_rx = ReceiverStream::new(request_rx) // mpsc -> Stream
            .map(Frame::data)
            .map(io::Result::Ok);
        let request_body = StreamBody::new(request_rx);

        // exchange HTTP headers and get status code & start streaming data in the background
        let request = create_request(proxy_host, auth_header_key, auth_header_val, request_body);
        let response = sender.send_request(request).await?;

        if !response.status().is_success() {
            return Err(Error::HttpStatusCode(response.status()));
        }

        // convert the response `Incoming` to an `AsyncRead`
        let response_rx = response
            .into_body()
            .into_data_stream()
            .map_err(io::Error::other as fn(_) -> _);
        let response_rx: ResponseRx = StreamReader::new(response_rx);

        Ok(Self {
            request_tx,
            response_rx,
            connection_task,
        })
    }
}

fn create_request<B: Body>(
    proxy_host: &str,
    auth_header_key: &str,
    auth_header_val: &str,
    body: B,
) -> http::Request<B> {
    hyper::Request::post(format!("https://{proxy_host}/"))
        .header(header::HOST, proxy_host)
        .header(header::ACCEPT, "*/*")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(auth_header_key, auth_header_val)
        .body(body)
        .unwrap()
}

impl AsyncRead for ProxyConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.response_rx), cx, buf)
    }
}

impl AsyncWrite for ProxyConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.request_tx), cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.request_tx), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.request_tx), cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write_vectored(Pin::new(&mut self.request_tx), cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        AsyncWrite::is_write_vectored(&self.request_tx)
    }
}

impl Drop for ProxyConnection {
    fn drop(&mut self) {
        // Technically the conneciton task will be shut down once the `request_tx` and `response_rx`
        // streams are dropped, but this behavior is not documented anywhere. As such, let's abort
        // the task ourselves anyway.
        self.connection_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_fronting::server;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, duplex},
        net::TcpListener,
    };

    /// Spawn an echo TCP server for testing. Returns the address it's listening on.
    async fn spawn_echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind echo server");
        let addr = listener.local_addr().expect("Failed to get local addr");

        tokio::spawn(async move {
            loop {
                let (mut socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => break,
                };

                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match socket.read(&mut buf).await {
                            Ok(0) => break, // EOF
                            Ok(n) => {
                                if socket.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        });

        addr
    }

    const AUTH_HEADER: &str = "X-Auth";
    const AUTH: &str = "password";

    fn example_df_config() -> DomainFronting {
        DomainFronting::new(
            "example.com".to_string(),
            "api.example.com".to_string(),
            AUTH_HEADER.to_string(),
            AUTH.to_string(),
        )
    }

    #[tokio::test]
    async fn test_client_server_bidirectional() {
        // Spawn echo server that will be the upstream target
        let echo_addr = spawn_echo_server().await;

        // Create in-memory transport between client and proxy server HTTP layers
        let (client_stream, server_stream) = duplex(8192);

        // Start proxy server with default TCP connector pointing to echo server
        let config = server::Config::new(echo_addr, AUTH_HEADER.to_string(), AUTH.to_string());
        let sessions = server::Server::new(config);
        let sessions_clone = sessions.clone();

        // Spawn HTTP server on server_stream
        tokio::spawn(async move {
            let io = TokioIo::new(server_stream);
            let service = hyper::service::service_fn(move |req| {
                let sessions = sessions_clone.clone();
                async move { Ok::<_, Infallible>(sessions.handle_request(req).await) }
            });

            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        // Create client connection using the in-memory stream (no TLS)
        let proxy_config = ProxyConfig::new(echo_addr, example_df_config());

        let mut client = proxy_config
            .connect_with_stream(client_stream)
            .await
            .expect("Failed to create client connection");

        // Test: write to client, should echo back
        let test_data = b"Hello from client";
        client
            .write_all(test_data)
            .await
            .expect("Failed to write to client");

        // Read the echo response
        let mut buffer = vec![0u8; 1024];
        let n = client
            .read(&mut buffer)
            .await
            .expect("Failed to read from client");

        assert_eq!(
            &buffer[..n],
            test_data,
            "Echo server should return the same data"
        );

        // Test multiple round trips
        let test_data2 = b"Second message";
        client
            .write_all(test_data2)
            .await
            .expect("Failed to write second message");

        let n = client
            .read(&mut buffer)
            .await
            .expect("Failed to read second response");

        assert_eq!(&buffer[..n], test_data2, "Second echo failed");
    }

    #[tokio::test]
    async fn test_multiple_sessions() {
        // Spawn echo server
        let echo_addr = spawn_echo_server().await;

        // Create two separate client-server pairs
        let (client_stream1, server_stream1) = duplex(8192);
        let (client_stream2, server_stream2) = duplex(8192);

        let config = server::Config::new(echo_addr, AUTH_HEADER.to_string(), AUTH.to_string());
        let sessions = server::Server::new(config);

        // Spawn server for first connection
        let sessions_clone1 = sessions.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(server_stream1);
            let service = hyper::service::service_fn(move |req| {
                let sessions = sessions_clone1.clone();
                async move { Ok::<_, Infallible>(sessions.handle_request(req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        // Spawn server for second connection
        let sessions_clone2 = sessions.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(server_stream2);
            let service = hyper::service::service_fn(move |req| {
                let sessions = sessions_clone2.clone();
                async move { Ok::<_, Infallible>(sessions.handle_request(req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        // Create two client connections
        let proxy_config = ProxyConfig::new(echo_addr, example_df_config());

        let mut client1 = proxy_config
            .connect_with_stream(client_stream1)
            .await
            .expect("Failed to create client1");

        let mut client2 = proxy_config
            .connect_with_stream(client_stream2)
            .await
            .expect("Failed to create client2");

        // Write to both clients and verify they get independent echoes
        client1
            .write_all(b"from_client1")
            .await
            .expect("Client 1 write failed");
        client2
            .write_all(b"from_client2")
            .await
            .expect("Client 2 write failed");

        // Read responses
        let mut buf1 = vec![0u8; 1024];
        let mut buf2 = vec![0u8; 1024];

        let n1 = client1.read(&mut buf1).await.expect("Client 1 read failed");
        let n2 = client2.read(&mut buf2).await.expect("Client 2 read failed");

        assert_eq!(&buf1[..n1], b"from_client1", "Client 1 got wrong echo");
        assert_eq!(&buf2[..n2], b"from_client2", "Client 2 got wrong echo");
    }

    #[tokio::test]
    async fn test_connection_task_stopped_on_drop() {
        // Spawn echo server
        let echo_addr = spawn_echo_server().await;

        let (client_stream, server_stream) = duplex(8192);
        let config = server::Config::new(echo_addr, AUTH_HEADER.to_string(), AUTH.to_string());
        let sessions = server::Server::new(config);
        let sessions_clone = sessions.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(server_stream);
            let service = hyper::service::service_fn(move |req| {
                let sessions = sessions_clone.clone();
                async move { Ok::<_, Infallible>(sessions.handle_request(req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let proxy_config = ProxyConfig::new(echo_addr, example_df_config());

        let client = proxy_config
            .connect_with_stream(client_stream)
            .await
            .expect("Failed to create client connection");

        // Grab a handle to the connection task before dropping
        let connection_task = client.connection_task.clone();
        // The task should still be running
        assert!(
            !connection_task.is_finished(),
            "Connection task should be running before drop"
        );

        // Drop the proxy connection
        drop(client);

        // Give the runtime a moment to process the abort
        tokio::task::yield_now().await;

        // The connection task should now be finished (aborted)
        assert!(
            connection_task.is_finished(),
            "Connection task should be stopped after ProxyConnection is dropped"
        );
    }

    #[tokio::test]
    async fn test_large_data_transfer() {
        // Spawn echo server
        let echo_addr = spawn_echo_server().await;

        let (client_stream, server_stream) = duplex(65536);
        let config = server::Config::new(echo_addr, AUTH_HEADER.to_string(), AUTH.to_string());
        let sessions = server::Server::new(config);
        let sessions_clone = sessions.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(server_stream);
            let service = hyper::service::service_fn(move |req| {
                let sessions = sessions_clone.clone();
                async move { Ok::<_, Infallible>(sessions.handle_request(req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        });

        let proxy_config = ProxyConfig::new(echo_addr, example_df_config());

        let mut client = proxy_config
            .connect_with_stream(client_stream)
            .await
            .expect("Failed to create client");

        // Send 100KB of data
        let large_data = vec![0x42u8; 100_000];
        client
            .write_all(&large_data)
            .await
            .expect("Failed to write large data");

        // Read the echo response
        let mut received = Vec::new();
        let mut buffer = vec![0u8; 4096];

        while received.len() < large_data.len() {
            match client.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => received.extend_from_slice(&buffer[..n]),
                Err(e) => panic!("Read error: {}", e),
            }
        }

        assert_eq!(received.len(), large_data.len(), "Did not receive all data");
        assert_eq!(received, large_data, "Data corruption detected");
    }
}
