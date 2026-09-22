use std::{io, net::IpAddr};

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
