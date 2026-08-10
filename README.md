# Domain Fronting

A Rust library for domain fronting - tunneling TCP connections through HTTP requests to bypass
censorship and access restrictions.

Domain fronting is a technique for connecting to a web server hosted on a CDN without exposing
the hostname in plain text. It works by setting the SNI field of the TLS client hello to a
different domain, hosted on the same CDN, while the inner HTTP Host header points to the obscured
domain. A mismatch in these fields is discouraged by the SNI standard, but not prohibited.

The library provides a domain fronting client and a server component.
The client implements `AsyncRead` and `AsyncWrite` for use with async code.

## Cargo Features

- `tls`: Enables TLS support via `rustls` (disabled by default)
- `examples`: Enables example binaries (includes `tls`)

## Building the server
To build the server on Ubuntu 22.04 and 24.04, you need to have `build-essential` and `rust` installed.
```bash
sudo apt install rustup build-essential
rustup default stable
```

With the dependencies installed, the binary can be built via `cargo`.
```
cargo build --bin domain_fronting_server --features examples --release
```

The binary will reside in
`$CARGO_TARGET_DIR/target/release/domain_fronting_server`, typically this is
in `./target/release/domain_fronting_server`.

## Usage

### Client

See `bin/domain_fronting.rs` and `bin/domain_fronting_stdio.rs` for basic example clients.

Enable the `tls` feature and supply your own `rustls::ClientConfig` with the certificate store of your choice:

```toml
[dependencies]
domain-fronting = { version = "0.1", features = ["tls"] }
```

```rust
use domain_fronting::{DomainFronting, client::ProxyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::ClientConfig;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let df = DomainFronting::new(
        "https://cdn.example.com".parse().unwrap(), // Fronting domain (CDN)
        "api.example.com".to_string(),              // Proxy host
    );

    let proxy_config = df.proxy_config().await?;

    // Create your own TLS config with the certificate store of your choice
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    // Add your certificates to root_store...
    let tls_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    );

    let mut client = proxy_config.connect_https1_1(tls_config).await?;

    // Use like a regular AsyncRead + AsyncWrite stream
    client.write_all(b"Hello").await?;
    let mut buf = vec![0u8; 1024];
    let n = client.read(&mut buf).await?;

    Ok(())
}
```

### Client with custom transport

To provide your own transport stream (e.g. for testing or when the TCP connection is managed externally):

```rust
use domain_fronting::{DomainFronting, client::ProxyConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::ClientConfig;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let df = DomainFronting::new(
        "https://cdn.example.com".parse().unwrap(), // Fronting domain (CDN)
        "api.example.com".to_string(),              // Proxy host
    );

    let proxy_config = df.proxy_config().await?;

    // Create your TLS config with desired certificate store
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    // Add your certificates...
    let mut tls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls_config.alpn_protocols.push(b"h2".to_vec()); // Use HTTP2
    let tls_config = Arc::new(tls_config);

    // Connect with a custom transport and TLS config
    let tcp_stream = TcpStream::connect(proxy_config.addr).await?;
    let mut client = proxy_config
        .connect_http2_over_stream(tcp_stream, tls_config)
        .await?;

    client.write_all(b"Hello").await?;
    let mut buf = vec![0u8; 1024];
    let n = client.read(&mut buf).await?;

    Ok(())
}
```

### Server

```rust
use domain_fronting::server::{self, Server};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let upstream_addr = "127.0.0.1:8080".parse()?;
    let config = server::Config::new(upstream_addr);
    let server = Server::new(config);

    // Use with hyper to handle HTTP requests
    // See examples/domain_fronting_server.rs for a complete example

    // server.handle_request(request).await;

    Ok(())
}
```

## Examples

The crate includes two example binaries:

### Client Example

```bash
cargo run --bin domain_fronting --features examples -- \
    --front https://cdn.example.com \
    --host api.example.com
```

See also `bin/domain_fronting_stdio.rs`.

### Server Example

```bash
cargo run --bin domain_fronting_server --features examples -- \
    --hostname api.example.com \
    --cert-path /path/to/cert.pem \
    --key-path /path/to/key.pem \
    --upstream 127.0.0.1:8080 \
    --port 443
```

For plain TCP (no TLS):

```bash
cargo run --bin domain_fronting_server --features examples -- \
    --upstream 127.0.0.1:8080 \
    --port 8080
```

## Protocol

TCP data is tunneled through the CDN and through the domain fronting server using HTTP requests.

- **Client -> CDN -> Server**: Data is sent as the body of repeated `POST`/`PATCH` requests.
- **Client <- CDN <- Server**: The client issues repeated `GET` requests to long-poll for
  upstream data. The server returns upstream data in the response body.
- **Server <-> Upstream**: The server opens one TCP stream to upstream per session.

Requests must provide a session ID as an HTTP header (`X-Session: <random uuid>`). When the server
receives a `GET`/`POST` request for a previously unseen session ID, it will establish a new TCP
connection to the upstream target and start tunneling data. Subsequent `PATCH` requests with the
same session ID will push data to the same TCP connection.

The client supports talking to the CDN with either HTTP/1.1 or HTTP/2. HTTP/2 should be preferred,
but may not be supported by all CDNs. HTTP/1.1 requires two separate TCP/TLS connections
(one per direction). HTTP/2 uses a single connection with two concurrent streams.

## License

Copyright (C) 2026 Mullvad VPN AB

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

For the full license agreement, see the [LICENSE](./LICENSE.md) file or find it at <https://www.gnu.org/licenses/gpl-3.0>.
