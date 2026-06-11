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

use std::sync::Arc;

use anyhow::{Context as _, anyhow, bail};
use clap::Parser;
use domain_fronting::DomainFronting;
use http::Uri;
use tokio::io::{copy_bidirectional, stdin, stdout};
use tracing_subscriber::{EnvFilter, filter::LevelFilter};

/// Send stdin/stdout through a domain fronting proxy.
#[derive(Parser, Debug)]
pub struct Arguments {
    /// The domain used to hide the actual destination.
    #[arg(long)]
    front: Uri,

    #[arg(long)]
    http2: bool,

    /// The host being reached via `front`.
    #[arg(long)]
    host: String,

    /// Header key used to authorize against the proxy.
    #[clap(long, default_value = "X-Auth")]
    auth_key: String,

    /// Header value used to authorize against the proxy.
    #[clap(short = 'a', long)]
    auth: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(LevelFilter::INFO.into()))
        .init();

    let Arguments {
        host,
        front,
        auth_key,
        auth,
        http2,
    } = Arguments::parse();

    let domain_fronting =
        DomainFronting::new(front.clone(), host.clone(), auth).with_auth_key(auth_key);
    let proxy_config = domain_fronting
        .proxy_config()
        .await
        .context("Failed to resolve proxy")?;

    let mut connection = if domain_fronting.tls() {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };

        let mut tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        if http2 {
            tls_config.alpn_protocols.push(b"h2".to_vec());
        }

        let tls_config = Arc::new(tls_config);

        if http2 {
            proxy_config.connect_https2(tls_config).await
        } else {
            proxy_config.connect_https1_1(tls_config).await
        }
    } else if http2 {
        bail!("HTTP/2 requires TLS")
    } else {
        proxy_config.connect_http1_1().await
    }
    .context(anyhow!("Failed to connect to {host:?} with front {front}"))?;

    let mut stdio = tokio::io::join(stdin(), stdout());

    copy_bidirectional(&mut connection, &mut stdio).await?;

    Ok(())
}
