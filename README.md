# Domain Fronting

A Rust library for domain fronting - tunneling connections through HTTP POST requests to bypass censorship and access restrictions.

- **Client**: Implements `AsyncRead` + `AsyncWrite` for seamless integration with async code
- **Server**: HTTP session management with persistent upstream TCP connection per session
- **TLS**: TLS support with SNI (requires the `tls` feature)

## Cargo Features

- `tls`: Enables TLS support via `rustls` (disabled by default)
- `examples`: Enables example binaries (includes `tls`)

## Building the server
To build the server on Ubuntu 22.04 and 24.04, you need to have `build-essential` and at least `1.85` version of the rust toolchain.
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
use domain_fronting::{DomainFronting, ProxyConfig};
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
use domain_fronting::{DomainFronting, ProxyConfig};
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
    let tls_config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    );

    // Connect with a custom transport and TLS config
    let tcp_stream = TcpStream::connect(proxy_config.addr).await?;
    let mut client = proxy_config
        .connect_stream_with_tls(tcp_stream, tls_config)
        .await?;

    client.write_all(b"Hello").await?;
    let mut buf = vec![0u8; 1024];
    let n = client.read(&mut buf).await?;

    Ok(())
}
```

### Server

```rust
use domain_fronting::domain_fronting::server::{self, Server};
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
    --hostname api.example.com \
    --upstream 127.0.0.1:8080 \
    --port 8080
```

## Protocol

The domain fronting protocol works as follows:

1. Client establishes an HTTP/1.1 connection to the fronting domain (CDN)
2. Client sends POST requests with `Host` header set to the target host
3. Server establishes an upstream connection
4. Server starts streaming data from the request body to upstream, and vice versa

## License

Copyright (C) 2026 Mullvad VPN AB

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

For the full license agreement, see the [LICENSE](./LICENSE.md) file or find it at <https://www.gnu.org/licenses/gpl-3.0>.
