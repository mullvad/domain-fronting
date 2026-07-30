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

//! Domain fronting library for tunneling TCP connections through HTTP requests to bypass
//! censorship and access restrictions.
//!
//! The library provides a domain fronting client and a server component.
//!
//! # Client
//!
//! [`client::ProxyConnection`] implements [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`],
//! tunneling data via HTTP requests. The client connects to the proxy sets up a bidirectional
//! stream over HTTP.
//!
//! ## Examples
//! See the binaries in `/src/bin/` for practical example clients.
//!
//! ## Usage
//!
//! With the `tls` feature enabled, provide your own certificate configuration:
//!
//! ```no_run
//! # #[cfg(feature = "tls")]
//! # async fn example_impl() -> Result<(), Box<dyn std::error::Error>> {
//! use domain_fronting::{DomainFronting, ProxyConfig};
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use std::sync::Arc;
//!
//! let df = DomainFronting::new(
//!     "https://cdn.example.com".parse().unwrap(),
//!     "api.example.com".to_string(),
//! );
//!
//! let proxy_config = df.proxy_config().await?;
//!
//! // Create your TLS config with desired certificate store
//! let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
//! // Add your certificates to root_store...
//!
//! let tls_config = Arc::new(
//!     tokio_rustls::rustls::ClientConfig::builder()
//!         .with_root_certificates(root_store)
//!         .with_no_client_auth()
//! );
//!
//! let mut client = proxy_config.connect_https1_1(tls_config).await?;
//!
//! // Use like a regular AsyncRead + AsyncWrite stream
//! client.write_all(b"Hello").await?;
//! let mut buf = vec![0u8; 1024];
//! let n = client.read(&mut buf).await?;
//! # Ok(())
//! # }
//! # fn main() {}
//! ```
//!
//! # Server
//!
//! [`server::Server`] handles HTTP requests, forwarding data to the upstream endpoint.
//!
//! ## Usage
//!
//! ```no_run
//! use domain_fronting::server::{self, Server};
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let upstream_addr = "127.0.0.1:8080".parse()?;
//! let total_timeout = Duration::from_secs(15);
//! let idle_timeout = Duration::from_secs(5);
//! let config = server::Config::new(upstream_addr, total_timeout, idle_timeout);
//! let server = Server::new(config);
//!
//! // Use with hyper to handle HTTP requests
//! // server.handle_request(request).await;
//! # Ok(())
//! # }
//! ```
//!
//! # Testing
//!
//! Both client and server support generic [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`]
//! streams for testing. Use [`client::ProxyConnection::http2_from_stream()`] (or
//! [`client::ProxyConnection::http1_1_from_streams`]) and [`server::Server::with_connector()`] to
//! inject custom transports like [`tokio::io::duplex`] for unit tests.
//!
//! # Protocol
//!
//! TCP data is tunneled through through the server using HTTP requests.
//!
//! - **Client -> CDN -> Server**: Data is sent as the body of repeated `POST`/`PATCH` requests.
//! - **Client <- CDN <- Server**: The client issues one `GET` per session. The server streams
//!   upstream data back in the response body.
//! - **Server <-> Upstream**: The server opens one TCP stream to upstream per session.
//!
//! Requests must provide a session ID as an HTTP header (`X-Session: <random uuid>`). When the
//! server  receives a `GET`/`POST` request for a previously unseen session ID, it will establish a
//! new TCP connection to the upstream target and start tunneling data. Subsequent `PATCH` requests
//! with the same session ID will push data to the same TCP connection.
//!
//! The client supports talking to the CDN with either HTTP/1.1 or HTTP/2. HTTP/2 should be preferred,
//! but may not be supported by all CDNs. HTTP/1.1 requires two separate TCP/TLS connections
//! (one per direction). HTTP/2 uses a single connection with two concurrent streams.

use http::uri::Scheme;
use http::{StatusCode, Uri};
use std::{io, net::SocketAddr};

use crate::client::ProxyConfig;
use crate::dns::{DefaultDnsResolver, DnsResolver as _};

pub mod client;
pub mod dns;
pub mod server;
#[cfg(feature = "tls")]
mod tls_stream;

/// Errors that can occur when establishing a domain fronting connection.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failed to establish TLS connection")]
    Tls(#[source] io::Error),
    #[error("Hyper error")]
    Hyper(#[from] hyper::Error),
    #[error("HTTP error")]
    Http(#[from] http::Error),
    #[error("HTTP request returned {0}")]
    HttpStatusCode(StatusCode),
    #[error("Connection failed")]
    Connection(#[source] io::Error),
    #[error("DNS resolution failed")]
    Dns(#[source] io::Error),
    /// The TLS configuration ALPN must include "h2" if HTTP/2 is used,
    /// and must not include "h2" if HTTP/1.1 is used.
    #[error("Misconfigured ALPN")]
    MisconfiguredAlpn,
    #[error("Empty DNS response")]
    EmptyDnsResponse,
}

/// Configuration for creating a [`ProxyConfig`].
///
/// Contains the fronting domain and proxy host.
#[derive(Clone, Debug, PartialEq)]
pub struct DomainFronting {
    /// Domain that will be used to connect to a CDN.
    front: Uri,
    /// Host that will be reached via the CDN, i.e. this is the Host header value
    proxy_host: String,
    session_key: String,
}

impl DomainFronting {
    pub fn new(front: Uri, proxy_host: String) -> Self {
        DomainFronting {
            front,
            proxy_host,
            session_key: Self::DEFAULT_SESSION_KEY.into(),
        }
    }

    pub const DEFAULT_SESSION_KEY: &str = "X-Session";

    pub fn with_session_key(self, session_key: String) -> Self {
        Self {
            session_key,
            ..self
        }
    }

    /// Returns the fronting domain (used for SNI).
    pub fn front(&self) -> &Uri {
        &self.front
    }

    pub fn front_host(&self) -> &str {
        self.front.host().unwrap_or_default()
    }

    /// Returns the proxy host (used for Host header).
    pub fn proxy_host(&self) -> &str {
        &self.proxy_host
    }

    pub fn session_key(&self) -> &str {
        &self.session_key
    }

    pub fn tls(&self) -> bool {
        // Assume TLS unless HTTP is specifically requested
        self.front.scheme() != Some(&Scheme::HTTP)
    }

    /// Get the HTTP scheme in use.
    pub fn scheme(&self) -> &'static str {
        if self.tls() { "https" } else { "http" }
    }

    pub async fn proxy_config(&self) -> Result<ProxyConfig, Error> {
        let dns_resolver = DefaultDnsResolver;

        let uri = &self.front;

        let port = uri.port_u16().or(self.tls().then_some(443)).unwrap_or(80);

        let addrs = dns_resolver
            .resolve(uri.host().unwrap_or_default())
            .await
            .map_err(Error::Dns)?;
        let &addr = addrs.first().ok_or(Error::EmptyDnsResponse)?;

        Ok(ProxyConfig::new(SocketAddr::new(addr, port), self.clone()))
    }
}
