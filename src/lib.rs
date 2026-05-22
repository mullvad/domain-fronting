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
//! The client implements `AsyncRead` and `AsyncWrite` for use with async code.
//!
//! # Examples
//!
//! See the module documentation for [`domain_fronting`] for usage examples.

use std::{io, net::IpAddr};

pub mod domain_fronting;
#[cfg(feature = "tls")]
mod tls_stream;

pub use domain_fronting::{DomainFronting, Error, ProxyConfig, ProxyConnection};

/// DNS resolver trait for resolving hostnames to IP addresses.
#[async_trait::async_trait]
pub trait DnsResolver: 'static + Send + Sync {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>>;
}

/// Default DNS resolver that uses `ToSocketAddrs` (`getaddrinfo`).
pub struct DefaultDnsResolver;

#[async_trait::async_trait]
impl DnsResolver for DefaultDnsResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        use std::net::ToSocketAddrs;
        tokio::task::block_in_place(move || {
            (host, 0u16)
                .to_socket_addrs()
                .map(|addrs| addrs.map(|a| a.ip()).collect())
        })
    }
}
