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
        .await?;

    let stdin_to_proxy = StreamBody::new(stream::unfold(stdin, |mut stdin| {
        Box::pin(async move {
            let mut line = String::new();
            log::info!("read from outgoing stream");
            stdin.read_line(&mut line).await.ok().filter(|&n| n > 0)?;
            dbg!(&line);
            let data = Bytes::from(line);
            let frame = Frame::data(data);
            Some((anyhow::Ok(frame), stdin))
        })
    }));

    let proxy_to_stdout = async move {
        let request = Request::post("/")
            .header(
                "X-Session-Id",
                HeaderValue::from_static("95c891ac-d08f-4722-b73c-42b1b8de1597"),
            )
            .body(stdin_to_proxy)
            .unwrap();
        let response = http.send_request(request).await.unwrap();
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

        #[expect(unreachable_code)]
        anyhow::Ok(())
    };

    select! {
        _ = connection => {}
        _ = proxy_to_stdout => {}
    }

    Ok(())
}
