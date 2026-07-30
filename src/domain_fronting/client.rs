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

use std::sync::Arc;
use std::{io, net::SocketAddr, pin::Pin, sync::Mutex, task::Poll};

use futures::FutureExt;
use futures::{SinkExt, TryFutureExt, future::try_join};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    client::conn::http1,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::task::JoinHandle;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
};
use tokio_util::{
    io::{CopyToBytes, SinkWriter, StreamReader},
    sync::PollSender,
};

use tokio::net::TcpStream;
use uuid::Uuid;

#[cfg(feature = "tls")]
use {crate::tls_stream::TlsStream, tokio_rustls::rustls};

use super::{DomainFronting, Error};

/// Configuration for connecting to a domain fronting proxy.
///
/// Contains the resolved address and domain fronting configuration.
/// Created from [`DomainFronting::proxy_config()`].
#[derive(PartialEq, Debug, Clone)]
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

    /// Connect to the proxy with HTTP/2 using a TCP connection with TLS and a custom certificate configuration.
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
    ///     "https://cdn.example.com".parse().unwrap(),
    ///     "api.example.com".to_string(),
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
    /// let client = proxy_config.connect_https2(tls_config).await?;
    /// # Ok(())
    /// # }
    /// # fn main() {}
    /// ```
    #[cfg(feature = "tls")]
    pub async fn connect_https2(
        &self,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<ProxyConnection, Error> {
        let tcp_stream = TcpStream::connect(self.addr)
            .await
            .map_err(Error::Connection)?;
        self.connect_https2_over_stream(tcp_stream, tls_config)
            .await
    }

    /// Connect to the proxy with HTTP/1.1 using two TCP connections with TLS and a custom certificate configuration.
    ///
    /// See [`Self::connect_https2`] for an example.
    #[cfg(feature = "tls")]
    pub async fn connect_https1_1(
        &self,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<ProxyConnection, Error> {
        let tcp_stream1 = TcpStream::connect(self.addr)
            .await
            .map_err(Error::Connection)?;
        let tcp_stream2 = TcpStream::connect(self.addr)
            .await
            .map_err(Error::Connection)?;
        self.connect_https1_1_over_streams(tcp_stream1, tcp_stream2, tls_config)
            .await
    }

    /// Connect with HTTP/2 using a custom stream and TLS configuration.
    ///
    /// This allows you to provide your own transport stream (for testing or custom networking)
    /// and your own certificate store and TLS settings.
    #[cfg(feature = "tls")]
    pub async fn connect_https2_over_stream<S>(
        &self,
        stream: S,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<ProxyConnection, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if !tls_config.alpn_protocols.contains(&b"h2".to_vec()) {
            return Err(Error::MisconfiguredAlpn);
        }

        let tls =
            TlsStream::connect_with_config(stream, self.domain_fronting.front_host(), tls_config)
                .await
                .map_err(Error::Tls)?;
        ProxyConnection::http2_from_stream(tls, &self.domain_fronting).await
    }

    /// Connect with HTTP/1.1 using a custom stream and TLS configuration.
    ///
    /// This allows you to provide your own transport stream (for testing or custom networking)
    /// and your own certificate store and TLS settings.
    #[cfg(feature = "tls")]
    pub async fn connect_https1_1_over_streams<S>(
        &self,
        stream1: S,
        stream2: S,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> Result<ProxyConnection, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if tls_config.alpn_protocols.contains(&b"h2".to_vec()) {
            return Err(Error::MisconfiguredAlpn);
        }

        let tls1 = TlsStream::connect_with_config(
            stream1,
            self.domain_fronting.front_host(),
            Arc::clone(&tls_config),
        )
        .await
        .map_err(Error::Tls)?;
        let tls2 =
            TlsStream::connect_with_config(stream2, self.domain_fronting.front_host(), tls_config)
                .await
                .map_err(Error::Tls)?;
        ProxyConnection::http1_1_from_streams(tls1, tls2, &self.domain_fronting).await
    }

    pub async fn connect_http1_1(&self) -> Result<ProxyConnection, Error> {
        let tcp_stream1 = TcpStream::connect(self.addr)
            .await
            .map_err(Error::Connection)?;
        let tcp_stream2 = TcpStream::connect(self.addr)
            .await
            .map_err(Error::Connection)?;
        self.connect_http1_1_over_streams(tcp_stream1, tcp_stream2)
            .await
    }

    /// Connect with http/1.1 over a pair of custom streams
    ///
    /// This allows using arbitrary transports like in-memory streams for testing
    /// or when TLS is handled externally.
    pub async fn connect_http1_1_over_streams<S>(
        &self,
        stream1: S,
        stream2: S,
    ) -> Result<ProxyConnection, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        ProxyConnection::http1_1_from_streams(stream1, stream2, &self.domain_fronting).await
    }

    /// Connect with http2 over a custom stream
    ///
    /// This allows using arbitrary transports like in-memory streams for testing
    /// or when TLS is handled externally.
    pub async fn connect_http2_over_stream<S>(&self, stream: S) -> Result<ProxyConnection, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        ProxyConnection::http2_from_stream(stream, &self.domain_fronting).await
    }
}

pub struct ProxyConnection {
    /// [`AsyncWrite`] for the HTTP request body.
    request_tx: Box<dyn AsyncWrite + Unpin + Send>,

    /// [`AsyncRead`] for the HTTP response body.
    response_rx: Box<dyn AsyncRead + Unpin + Send>,

    /// Join handle for the background I/O task.
    io_task: JoinHandle<Result<(), Error>>,
}

/// An HTTP body that may contain bytes.
type Body = Full<Bytes>;

async fn connect_http1_1(
    stream: impl AsyncRead + AsyncWrite + Unpin,
) -> Result<
    (
        http1::SendRequest<Body>,
        impl Future<Output = hyper::Result<()>>,
    ),
    Error,
> {
    let io = TokioIo::new(stream);
    let (sender, conn) = http1::handshake::<_, Body>(io).await?;
    Ok((sender, conn))
}

impl ProxyConnection {
    /// Create a proxy connection from any two AsyncRead + AsyncWrite streams.
    ///
    /// This performs an HTTP/1.1 handshake over each provided stream.
    /// Use `ProxyConfig::connect_stream_with_tls` if you need TLS support.
    ///
    /// One stream is used to streaming data from the proxy to us. The other is used to
    /// push data from us to the proxy. HTTP1.1 can theoretically support streaming the
    /// request/response bodies concurrently, but in practice a lot of implementations
    /// do not support this.
    pub async fn http1_1_from_streams<S>(
        stream1: S,
        stream2: S,
        config: &DomainFronting,
    ) -> Result<Self, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // For HTTP/1.1, use the two connections. One for reading, and one for writing.
        let http = try_join(connect_http1_1(stream1), connect_http1_1(stream2)).await?;
        let ((mut recv_req, conn1), (mut send_req, conn2)) = http;
        let conn = try_join(conn1, conn2).map_ok(|_| ()).map_err(Error::Hyper);

        Self::start_proxy(
            conn,
            move |req| recv_req.send_request(req),
            move |req| send_req.send_request(req),
            config,
        )
    }

    /// Create a proxy connection from any AsyncRead + AsyncWrite stream.
    ///
    /// This performs an HTTP/2 handshake over the provided stream.
    /// Use `ProxyConfig::connect_stream_with_tls` if you need TLS support.
    pub async fn http2_from_stream<S>(stream: S, config: &DomainFronting) -> Result<Self, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let io = TokioIo::new(stream);
        let (sender, conn) =
            hyper::client::conn::http2::handshake::<_, _, Body>(TokioExecutor::new(), io).await?;
        let conn = conn.map_err(Error::Hyper);

        // For HTTP/2, use the same connection to do both read and write requests.
        // let connection_task = tokio::spawn(conn).abort_handle();
        let sender = Arc::new(Mutex::new(sender));
        let (recv_req, send_req) = (sender.clone(), sender);

        Self::start_proxy(
            conn,
            move |req| recv_req.lock().unwrap().send_request(req),
            move |req| send_req.lock().unwrap().send_request(req),
            config,
        )
    }

    /// Create a [`ProxyConnection`] and start proxying data.
    fn start_proxy<Fut>(
        conn: impl Future<Output = Result<(), Error>> + Send + 'static,
        mut recv_req: impl FnMut(Request<Body>) -> Fut + Send + 'static,
        mut send_req: impl FnMut(Request<Body>) -> Fut + Send + 'static,
        config: &DomainFronting,
    ) -> Result<Self, Error>
    where
        Fut: Future<Output = hyper::Result<Response<Incoming>>> + Send,
    {
        let session_id = Uuid::new_v4();

        let (request_tx, request_rx) = mpsc::channel::<Bytes>(1);

        // convert the mpsc::Sender to an AsyncWrite
        let request_tx = CopyToBytes::new(PollSender::new(request_tx));
        let request_tx = request_tx.sink_map_err(io::Error::other);
        let request_tx = SinkWriter::new(request_tx);
        let request_tx = Box::new(request_tx) as Box<dyn AsyncWrite + Unpin + Send>;

        let (response_tx, response_rx) = futures::channel::mpsc::channel::<io::Result<Bytes>>(1);
        let response_rx = StreamReader::new(response_rx);

        let config = config.clone();
        let pump = async move {
            try_join(
                Self::pump_incoming(session_id, response_tx, &mut recv_req, &config),
                Self::pump_outgoing(session_id, request_rx, &mut send_req, &config),
            )
            .await
        };

        let io = try_join(conn, pump).map_ok(|_| ());
        let io_task = tokio::spawn(io);

        Ok(Self {
            request_tx,
            response_rx: Box::new(response_rx),
            io_task,
        })
    }

    /// Send an HTTP request, and stream the response body into `response_tx`.
    async fn pump_incoming<F, Fut>(
        session_id: Uuid,
        mut response_tx: futures::channel::mpsc::Sender<io::Result<Bytes>>,
        send_request: &mut F,
        config: &DomainFronting,
    ) -> Result<(), Error>
    where
        F: FnMut(Request<Body>) -> Fut + 'static,
        Fut: Future<Output = hyper::Result<Response<Incoming>>> + Send,
    {
        // exchange HTTP headers and get status code
        let read_request = create_read_request(config, session_id)?;
        let read_response = send_request(read_request).await?;
        if !read_response.status().is_success() {
            return Err(Error::HttpStatusCode(read_response.status()));
        }

        // start streaming response data
        let mut body = read_response.into_body();
        loop {
            match body.frame().await {
                None => break,
                Some(Err(err)) => {
                    _ = response_tx.send(Err(io::Error::other(err))).await;
                    break;
                }
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if response_tx.send(Ok(data)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Send [`Bytes`] from `request_tx` to the proxy.
    async fn pump_outgoing<F, Fut>(
        session_id: Uuid,
        mut request_rx: mpsc::Receiver<Bytes>,
        send_request: &mut F,
        config: &DomainFronting,
    ) -> Result<(), Error>
    where
        F: FnMut(Request<Body>) -> Fut + 'static,
        Fut: Future<Output = hyper::Result<Response<Incoming>>> + Send,
    {
        // Read a chunk of data, wrap it in an HTTP request, and send it off to the proxy.
        // In theory, we could stream all data in a single request, but some HTTP
        // reverse-proxies won't forward the request body until the body has been completely
        // sent off.
        let mut first = true;
        while let Some(chunk) = request_rx.recv().await {
            let request_body = Body::new(chunk);
            let request = create_write_request(config, session_id, request_body, first)?;
            let write_response = send_request(request).await?;
            if write_response.status() != StatusCode::NO_CONTENT {
                return Err(Error::HttpStatusCode(write_response.status()));
            }
            first = false;
        }
        Ok(())
    }
}

fn create_write_request(
    config: &DomainFronting,
    session_id: Uuid,
    body: Body,
    can_create_session: bool,
) -> Result<http::Request<Body>, Error> {
    let scheme = config.scheme();
    let proxy_host = config.proxy_host();
    let method = if can_create_session {
        Method::POST
    } else {
        Method::PATCH
    };
    // Use a random path in the URI to discourage proxies to cache the request.
    let uri = format!("{scheme}://{proxy_host}/{}", Uuid::new_v4());
    hyper::Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, proxy_host)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(config.session_key(), session_id.to_string())
        .body(body)
        .map_err(Error::Http)
}

fn create_read_request(
    config: &DomainFronting,
    session_id: Uuid,
) -> Result<http::Request<Body>, Error> {
    let scheme = config.scheme();
    let proxy_host = config.proxy_host();
    // Use a random path in the URI to discourage proxies to cache the request.
    let uri = format!("{scheme}://{proxy_host}/{}", Uuid::new_v4());
    hyper::Request::get(uri)
        .header(header::HOST, config.proxy_host())
        .header(header::ACCEPT, "*/*")
        .header(config.session_key(), session_id.to_string())
        .body(Body::default()) // Empty body
        .map_err(Error::Http)
}

macro_rules! check_err {
    ($io_task:expr, $cx:expr) => {
        match $io_task.poll_unpin($cx)? {
            Poll::Pending => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(io::Error::other(err))),

            // The I/O task will never exit with Ok(()) unless it's gracefully closed.
            // It's never gracefully closed unless ProxyConnection is dropped.
            Poll::Ready(Ok(())) => unreachable!("IO task will not stop while connection lives"),
        }
    };
}

impl AsyncRead for ProxyConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        check_err!(self.io_task, cx);
        AsyncRead::poll_read(Pin::new(&mut self.response_rx), cx, buf)
    }
}

impl AsyncWrite for ProxyConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        check_err!(self.io_task, cx);
        AsyncWrite::poll_write(Pin::new(&mut self.request_tx), cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        check_err!(self.io_task, cx);
        AsyncWrite::poll_flush(Pin::new(&mut self.request_tx), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        check_err!(self.io_task, cx);
        AsyncWrite::poll_shutdown(Pin::new(&mut self.request_tx), cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        check_err!(self.io_task, cx);

        // Merge `bufs` into a single contiguous buffer,
        // because each `poll_write` will generate one HTTP request.
        let len: usize = bufs.iter().map(|s| s.len()).sum();
        let mut contiguous = Vec::with_capacity(len);
        for buf in bufs {
            contiguous.extend_from_slice(buf);
        }

        AsyncWrite::poll_write(Pin::new(&mut self.request_tx), cx, &contiguous)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

impl Drop for ProxyConnection {
    fn drop(&mut self) {
        // Technically the IO task will be shut down once the `request_tx` and `response_rx`
        // streams are dropped, but this behavior is not documented anywhere. As such, let's abort
        // the task ourselves anyway.
        self.io_task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_fronting::server::{self, Server};
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

    fn serve_requests(
        io: impl AsyncWrite + AsyncRead + Unpin + Send + 'static,
        server: Arc<Server>,
    ) {
        tokio::spawn(async move {
            let io = TokioIo::new(io);
            let service = hyper::service::service_fn(move |req| {
                let server = server.clone();
                async move { Ok::<_, Infallible>(server.handle_request(req).await) }
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await;
        });
    }

    fn example_df_config() -> DomainFronting {
        DomainFronting::new(
            "example.com".parse().unwrap(),
            "api.example.com".to_string(),
        )
    }

    #[tokio::test]
    async fn test_client_server_bidirectional() {
        // Spawn echo server that will be the upstream target
        let echo_addr = spawn_echo_server().await;

        // Create in-memory transport between client and proxy server HTTP layers
        let (client_stream, server_stream) = duplex(8192);

        // Start proxy server with default TCP connector pointing to echo server
        let config = server::Config::new(echo_addr);
        let server = server::Server::new(config);

        // Spawn a task to serve requests
        serve_requests(server_stream, server.clone());

        // Create client connection using the in-memory stream (no TLS)
        let proxy_config = ProxyConfig::new(echo_addr, example_df_config());

        let mut client = proxy_config
            .connect_http2_over_stream(client_stream)
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

        let config = server::Config::new(echo_addr);
        let server = server::Server::new(config);

        // Spawn tasks to serve requests
        serve_requests(server_stream1, server.clone());
        serve_requests(server_stream2, server.clone());

        // Create two client connections
        let proxy_config = ProxyConfig::new(echo_addr, example_df_config());

        let mut client1 = proxy_config
            .connect_http2_over_stream(client_stream1)
            .await
            .expect("Failed to create client1");

        let mut client2 = proxy_config
            .connect_http2_over_stream(client_stream2)
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
        let config = server::Config::new(echo_addr);
        let server = server::Server::new(config);

        // Spawn a task to serve requests
        serve_requests(server_stream, server.clone());

        let proxy_config = ProxyConfig::new(echo_addr, example_df_config());

        let client = proxy_config
            .connect_http2_over_stream(client_stream)
            .await
            .expect("Failed to create client connection");

        // Grab a handle to the I/O task before dropping
        let io_task = client.io_task.abort_handle();
        // The task should still be running
        assert!(
            !io_task.is_finished(),
            "IO task should be running before drop"
        );

        // Drop the proxy connection
        drop(client);

        // Give the runtime a moment to process the abort
        tokio::task::yield_now().await;

        // The IO task should now be finished (aborted)
        assert!(
            io_task.is_finished(),
            "IO task should be stopped after ProxyConnection is dropped"
        );
    }

    #[tokio::test]
    async fn test_large_data_transfer() {
        // Spawn echo server
        let echo_addr = spawn_echo_server().await;

        let (client_stream, server_stream) = duplex(65536);
        let config = server::Config::new(echo_addr);
        let server = server::Server::new(config);

        // Spawn a task to serve requests
        serve_requests(server_stream, server.clone());

        let proxy_config = ProxyConfig::new(echo_addr, example_df_config());

        let mut client = proxy_config
            .connect_http2_over_stream(client_stream)
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
