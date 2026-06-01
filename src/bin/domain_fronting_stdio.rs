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
use bytes::Bytes;
use clap::Parser;
use futures::stream;
use http::{HeaderValue, Request};
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    body::{Body, Frame},
    client::conn::http1::SendRequest,
};
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, stdin, stdout},
    net::TcpStream,
    select,
};

/// Send stdin/stdout through a domain fronting proxy.
#[derive(Parser, Debug)]
pub struct Arguments {
    /// The host being reached via `front`.
    #[arg(long)]
    host: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Arguments { host } = Arguments::parse();

    let tcp_stream = TcpStream::connect(&host)
        .await
        .context(anyhow!("Failed to connect to {host:?}"))?;

    let (http, connection) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(tcp_stream))
        .await
        .context("HTTP handshake failed")?;

    // Create a Stream that reads from stdin and yields Frame<Bytes>
    let stdin = BufReader::new(stdin());
    let stdin_to_proxy = StreamBody::new(stream::unfold(stdin, |mut stdin| {
        Box::pin(async move {
            let mut line = String::new();
            // read a line from stdin, exiting on EOF
            stdin.read_line(&mut line).await.ok().filter(|&n| n > 0)?;
            let frame = Frame::data(Bytes::from(line));
            Some((anyhow::Ok(frame), stdin))
        })
    }));

    let proxy = proxy_to_stdout(http, stdin_to_proxy);

    select! {
        r = connection => r?,
        r = proxy => r?,
    }

    Ok(())
}

async fn start_proxy<B: Body + 'static>(mut http: SendRequest<B>, body: B) -> anyhow::Result<()> {
    let mut stdout = stdout();

    let request = Request::post("/")
        .header(
            "X-Session-Id",
            HeaderValue::from_static("95c891ac-d08f-4722-b73c-42b1b8de1597"),
        )
        .body(body)
        .expect("Request is valid");

    let response = http
        .send_request(request)
        .await
        .context("Failed to send HTTP request")?;
    let (_head, mut body) = response.into_parts();

    loop {
        let frame = body
            .frame()
            .await
            .context("No more frames")?
            .context("Frame error")?;
        let Ok(data) = frame.into_data() else {
            continue;
        };

        stdout.write_all(&data).await?;
    }
}
