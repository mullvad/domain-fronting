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
//! allowing API connections to be tunneled through HTTP POST requests.
//!
//! # Client
//!
//! [`ProxyConnection`] implements [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`], tunneling data via HTTP POST requests.
//! The client establishes an HTTP/1.1 connection and uses POST requests with a session ID header
//! to maintain a bidirectional stream over HTTP.
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
//!     "X-Session-Id".to_string(),
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
//! [`server::Sessions`] manages HTTP sessions, forwarding data to upstream servers.
//! Each unique session ID (sent via a configurable session header) gets its own
//! upstream TCP connection that persists across multiple HTTP requests.
//!
//! ## Usage
//!
//! ```no_run
//! use domain_fronting::domain_fronting::server::Sessions;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let upstream_addr = "127.0.0.1:8080".parse()?;
//! let sessions = Sessions::new(upstream_addr, "X-Session-Id".to_string());
//!
//! // Use with hyper to handle HTTP requests
//! // sessions.handle_request(req).await
//! # Ok(())
//! # }
//! ```
//!
//! # Testing
//!
//! Both client and server support generic [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`] streams for testing.
//! Use [`ProxyConnection::from_stream()`] and [`server::Sessions::with_connector()`] to inject
//! custom transports like [`tokio::io::duplex`] for unit tests.
//!
//! # Protocol
//!
//! - Each HTTP POST request contains data to send upstream
//! - Response body contains data received from upstream
//! - Empty POST requests are used for polling when no data needs to be sent
//! - Session cleanup happens when the client disconnects or the upstream closes

use std::{io, net::SocketAddr};

use crate::{DefaultDnsResolver, DnsResolver};

mod client;
pub mod server;

pub use client::{ProxyConfig, ProxyConnection};

/// Errors that can occur when establishing a domain fronting connection.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Failed to establish TLS connection")]
    Tls(#[source] io::Error),
    #[error("HTTP handshake failed")]
    Handshake(#[from] hyper::Error),
    #[error("Connection failed")]
    Connection(#[source] io::Error),
    #[error("DNS resolution failed")]
    Dns(#[source] io::Error),
    #[error("Empty DNS response")]
    EmptyDnsResponse,
}

/// Configuration for creating a [`ProxyConfig`].
///
/// Contains the fronting domain, session header key and target host.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DomainFronting {
    /// Domain that will be used to connect to a CDN, used for SNI
    front: String,
    /// Host that will be reached via the CDN, i.e. this is the Host header value
    proxy_host: String,
    /// HTTP header key used to identify sessions
    session_header_key: String,
}

impl DomainFronting {
    pub fn new(front: String, proxy_host: String, session_header_key: String) -> Self {
        DomainFronting {
            front,
            proxy_host,
            session_header_key,
        }
    }

    /// Returns the fronting domain (used for SNI).
    pub fn front(&self) -> &str {
        &self.front
    }

    /// Returns the proxy host (used for Host header).
    pub fn proxy_host(&self) -> &str {
        &self.proxy_host
    }

    /// Returns the session header key.
    pub fn session_header_key(&self) -> &str {
        &self.session_header_key
    }

    pub async fn proxy_config(&self) -> Result<ProxyConfig, Error> {
        let dns_resolver = DefaultDnsResolver;

        let addrs = dns_resolver
            .resolve(self.front.clone())
            .await
            .map_err(Error::Dns)?;
        let addr = addrs.first().ok_or(Error::EmptyDnsResponse)?;

        Ok(ProxyConfig::new(
            SocketAddr::new(addr.ip(), 443),
            self.clone(),
        ))
    }
}
