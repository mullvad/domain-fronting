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

use anyhow::{Context, anyhow};
use clap::Parser;
use domain_fronting::DomainFronting;
use tokio::{
    io::{copy_bidirectional, stdin, stdout},
    net::TcpStream,
};

/// Send stdin/stdout through a domain fronting proxy.
#[derive(Parser, Debug)]
pub struct Arguments {
    /// The domain used to hide the actual destination.
    #[arg(long)]
    front: String,

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
    let Arguments {
        host,
        front,
        auth_key,
        auth,
    } = Arguments::parse();

    let domain_fronting = DomainFronting::new(front, host.clone(), auth_key, auth);
    let proxy_config = domain_fronting
        .proxy_config()
        .await
        .context("Failed to resolve proxy")?;

    let tcp_stream = TcpStream::connect(&host)
        .await
        .context(anyhow!("Failed to connect to {host:?}"))?;

    // perform HTTP handshake and set up bidirectional stream over HTTP
    let mut proxy_conn = proxy_config
        .connect_with_stream(tcp_stream)
        .await
        .context(anyhow!("Failed to establish proxy with {host:?}"))?;

    let mut stdio = tokio::io::join(stdin(), stdout());

    copy_bidirectional(&mut proxy_conn, &mut stdio).await?;

    Ok(())
}
