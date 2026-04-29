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

use std::sync::Arc;

use clap::Parser;
use domain_fronting::DomainFronting;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;
use tracing_subscriber::{EnvFilter, filter::LevelFilter};

#[derive(Parser, Debug)]
pub struct Arguments {
    /// The domain used to hide the actual destination.
    #[arg(long)]
    front: String,

    /// The host being reached via `front`.
    #[arg(long)]
    host: String,

    /// Session header key used to identify client sessions
    #[clap(short = 's', long)]
    session_header: String,

    /// URL to fetch (defaults to a simple GET request)
    #[clap(short = 'u', long)]
    url: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into()))
        .init();

    let Arguments {
        front,
        host,
        session_header,
        url,
    } = Arguments::parse();

    let df = DomainFronting::new(front, host.clone(), session_header);

    let proxy_config = df.proxy_config().await?;

    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
    );
    let mut connection = proxy_config.connect_with_tls(tls_config).await?;

    // Send a simple HTTP GET request
    let url = url.unwrap_or_else(|| format!("https://{}/", host));
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        url, host
    );

    log::info!("Sending request: {}", request.lines().next().unwrap_or(""));
    connection.write_all(request.as_bytes()).await?;

    // Read response
    let mut response = Vec::new();
    connection.read_to_end(&mut response).await?;

    log::info!("Received {} bytes", response.len());
    println!("{}", String::from_utf8_lossy(&response));

    Ok(())
}
