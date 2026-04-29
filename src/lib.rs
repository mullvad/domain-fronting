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

//! Domain fronting library for tunneling connections through HTTP POST requests.
//!
//! This crate provides both client and server components for domain fronting,
//! allowing API connections to be tunneled through HTTP POST requests.
//!
//! # Features
//!
//! - **Client**: [`domain_fronting::ProxyConnection`] implements [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`]
//! - **Server**: [`domain_fronting::server::Sessions`] manages HTTP sessions and forwards to upstream
//! - **Testing**: Both components support custom transports for testing
//!
//! # Examples
//!
//! See the module documentation for [`domain_fronting`] for usage examples.

use std::{io, net::SocketAddr};

pub mod domain_fronting;
#[cfg(feature = "tls")]
mod tls_stream;

pub use domain_fronting::{DomainFronting, Error, ProxyConfig, ProxyConnection};

/// DNS resolver trait for resolving hostnames to IP addresses.
#[async_trait::async_trait]
pub trait DnsResolver: 'static + Send + Sync {
    async fn resolve(&self, host: String) -> io::Result<Vec<SocketAddr>>;
}

/// Default DNS resolver that uses `ToSocketAddrs` (`getaddrinfo`).
pub struct DefaultDnsResolver;

#[async_trait::async_trait]
impl DnsResolver for DefaultDnsResolver {
    async fn resolve(&self, host: String) -> io::Result<Vec<SocketAddr>> {
        use std::net::ToSocketAddrs;
        tokio::task::spawn_blocking(move || {
            format!("{host}:443")
                .to_socket_addrs()
                .map(|addrs| addrs.collect())
        })
        .await
        .map_err(io::Error::other)?
    }
}
