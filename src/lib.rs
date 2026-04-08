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
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    }
}
