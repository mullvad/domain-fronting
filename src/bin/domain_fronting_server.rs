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

use clap::Parser;
use domain_fronting::{
    DomainFronting,
    domain_fronting::server::{Config, Server},
};
use futures::FutureExt;
use hyper::{server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use rustls_pki_types::{CertificateDer, pem::PemObject};
use std::{
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig};
use tracing_subscriber::{EnvFilter, filter::LevelFilter};

#[derive(Parser, Debug)]
#[clap(name = "domain_fronting_server")]
struct Args {
    /// Hostname for the server
    #[clap(short = 'H', long)]
    hostname: Option<String>,

    /// Path to certificate file (PEM format). If omitted, plain TCP is used.
    #[clap(short = 'c', long)]
    cert_path: Option<PathBuf>,

    /// Path to private key file (PEM format). Required if cert_path is set.
    #[clap(short = 'k', long)]
    key_path: Option<PathBuf>,

    /// Upstream socket address to forward CONNECT requests to
    #[clap(short = 'u', long)]
    upstream: SocketAddr,

    /// Port to listen on
    #[clap(short, long, default_value = "443")]
    port: u16,

    /// Header key used to authorize against the proxy.
    #[clap(long, default_value = {DomainFronting::DEFAULT_AUTH_KEY})]
    auth_key: String,

    /// Header value used to authorize against the proxy.
    #[clap(short = 'a', long)]
    auth: String,

    /// Header key used for the session id.
    #[clap(long, default_value = {DomainFronting::DEFAULT_SESSION_KEY})]
    session_key: String,

    /// Total timeout of each HTTP request, in seconds.
    #[clap(long)]
    total_timeout: Option<f32>,

    /// Idle timeout of each HTTP request, in seconds.
    #[clap(long)]
    idle_timeout: Option<f32>,
}

fn load_tls_config(cert_path: &Path, key_path: &Path) -> anyhow::Result<ServerConfig> {
    // Load certificate chain
    let cert_file = File::open(cert_path)?;
    let cert_chain =
        CertificateDer::pem_reader_iter(&mut std::io::BufReader::new(BufReader::new(cert_file)))
            .collect::<Result<Vec<_>, _>>()?;

    // Load private key
    let key = rustls_pki_types::PrivateKeyDer::from_pem_file(key_path)?;

    // Create server configuration
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

    Ok(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into()))
        .init();

    let Args {
        hostname,
        cert_path,
        key_path,
        upstream,
        port,
        auth_key,
        auth,
        session_key,
        total_timeout,
        idle_timeout,
    } = Args::parse();
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;

    let tls_acceptor = match (cert_path, key_path, hostname) {
        (Some(cert_path), Some(key_path), Some(hostname)) => {
            log::info!("Starting TLS domain fronting server on {}", bind_addr);
            log::info!("Hostname: {hostname}");
            log::info!("Cert path: {}", cert_path.display());
            log::info!("Key path: {}", key_path.display());
            let tls_config =
                tokio::task::spawn_blocking(move || load_tls_config(&cert_path, &key_path)).await?;
            Some(TlsAcceptor::from(Arc::new(tls_config?)))
        }
        (None, None, None) => {
            log::info!("Starting plain TCP domain fronting server on {}", bind_addr);
            log::warn!("No TLS certificate provided - running without encryption");
            None
        }
        _ => {
            return Err("To enable TLS, all 3 arguments (--cert-path, --key-path and --hostname) must be used".into());
        }
    };

    log::info!("Upstream: {}", upstream);

    let listener = TcpListener::bind(bind_addr).await?;

    let mut config = Config::new(upstream, auth)
        .with_auth_key(auth_key)
        .with_session_key(session_key);
    config.total_timeout = total_timeout.map(Duration::from_secs_f32);
    config.idle_timeout = idle_timeout.map(Duration::from_secs_f32);
    let server = Server::new(config);

    let mut connections_since_report: u64 = 0;
    let mut last_report: Option<Instant> = None;
    loop {
        let (stream, addr) = listener.accept().await?;

        connections_since_report += 1;
        if last_report.is_none_or(|t| t.elapsed() >= Duration::from_secs(5)) {
            let stats = server.take_stats();
            log::info!(
                "{connections_since_report} new connection(s), bytes-tx={}, bytes-rx={}",
                stats.bytes_tx,
                stats.bytes_rx,
            );
            connections_since_report = 0;
            last_report = Some(Instant::now());
        }

        log::debug!("Accepted connection from {addr}");

        let server = server.clone();
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            match tls_acceptor {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        serve_connection(TokioIo::new(tls_stream), server, addr).await;
                    }
                    Err(err) => {
                        log::error!("TLS handshake failed for {addr}: {err}");
                    }
                },
                None => {
                    serve_connection(TokioIo::new(stream), server, addr).await;
                }
            }
        });
    }
}

async fn serve_connection<S>(io: S, server: Arc<Server>, addr: SocketAddr)
where
    S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |req| server.clone().handle_request(req).map(Ok::<_, String>));

    if let Err(err) = http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await
    {
        log::error!("Error serving connection from {addr}: {err}");
    }
}
