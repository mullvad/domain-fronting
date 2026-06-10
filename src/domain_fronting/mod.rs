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

//! Domain fronting for API connections.
//!
//! This module provides both client and server components for domain fronting,
//! allowing API connections to be tunneled through an HTTP POST request.
//!
//! # Client
//!
//! [`ProxyConnection`] implements [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`],
//! tunneling data via HTTP POST requests. The client establishes an HTTP/1.1 connection
//! and sets up a bidirectional stream over HTTP.
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
//!     "cdn.example.com".to_string(),
//!     "api.example.com".to_string(),
//!     "X-Auth".to_string(),
//!     "password".to_string(),
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
//! let mut client = proxy_config.connect_with_tls(tls_config).await?;
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
//! [`server::Server`] handles HTTP requests, forwarding data to upstream servers.
//! Each HTTP request gets its own upstream TCP connection, and the HTTP request/response body is
//! streamed to/from the upstream connection.
//!
//! ## Usage
//!
//! ```no_run
//! use domain_fronting::domain_fronting::server::{self, Server};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let upstream_addr = "127.0.0.1:8080".parse()?;
//! let config = server::Config::new(upstream_addr, "X-Auth".to_string(), "shared-secret".to_string());
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
//! streams for testing. Use [`ProxyConnection::from_stream()`] and
//! [`server::Server::with_connector()`] to inject custom transports like [`tokio::io::duplex`]
//! for unit tests.
//!
//! # Protocol
//!
//! - Each HTTP POST request creates a new TCP connection to upstream.
//! - The body of the HTTP request is streamed _to_ upstream.
//! - Data received _from_ upstream is streamed into the HTTP response body.
//! - The HTTP POST request must provide a preshared secret.
//!   This is not intended as a security feature, but to filter random bot traffic.
//!   E.g. `X-Auth: abc123-shared-secret`

use std::{io, net::SocketAddr};

use crate::util::{deserialize_from_str, serialize_to_string};
use crate::{DefaultDnsResolver, DnsResolver};

mod client;
pub mod server;

pub use client::{ProxyConfig, ProxyConnection};
use http::uri::Scheme;
use http::{StatusCode, Uri};

/// Errors that can occur when establishing a domain fronting connection.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failed to establish TLS connection")]
    Tls(#[source] io::Error),
    #[error("HTTP handshake failed")]
    Handshake(#[from] hyper::Error),
    #[error("HTTP request returned {0}")]
    HttpStatusCode(StatusCode),
    #[error("Connection failed")]
    Connection(#[source] io::Error),
    #[error("DNS resolution failed")]
    Dns(#[source] io::Error),
    #[error("Empty DNS response")]
    EmptyDnsResponse,
}

/// Configuration for creating a [`ProxyConfig`].
///
/// Contains the fronting domain, target host, and auth header.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DomainFronting {
    /// Domain that will be used to connect to a CDN.
    #[serde(serialize_with = "serialize_to_string")]
    #[serde(deserialize_with = "deserialize_from_str")]
    front: Uri,
    /// Host that will be reached via the CDN, i.e. this is the Host header value
    proxy_host: String,
    /// HTTP header key used to authorize the proxy request
    auth_header_key: String,
    /// HTTP header value used to authorize the proxy request
    auth_header_val: String,
}

impl DomainFronting {
    pub fn new(
        front: Uri,
        proxy_host: String,
        auth_header_key: String,
        auth_header_val: String,
    ) -> Self {
        DomainFronting {
            front,
            proxy_host,
            auth_header_key,
            auth_header_val,
        }
    }

    /// Returns the fronting domain (used for SNI).
    pub fn front(&self) -> &Uri {
        &self.front
    }

    pub fn front_host(&self) -> &str {
        &self.front.host().unwrap_or_default()
    }

    /// Returns the proxy host (used for Host header).
    pub fn proxy_host(&self) -> &str {
        &self.proxy_host
    }

    /// Returns the auth header key.
    pub fn auth_header_key(&self) -> &str {
        &self.auth_header_key
    }

    /// Returns the auth header value.
    pub fn auth_header_val(&self) -> &str {
        &self.auth_header_val
    }

    pub fn tls(&self) -> bool {
        // Assume TLS unless HTTP is specifically requested
        self.front.scheme() != Some(&Scheme::HTTP)
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
