// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 BMDarkLight
//
// This file is part of Radii.
//
// Radii is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for the full text and
// additional terms.

//! A client on the plain tunnel that finishes sending and shuts down its
//! write side still gets its response.
//!
//! `relay::pump` calls `writer.shutdown()` when it reaches EOF, so a
//! half-close propagates along a chain. The plain tunnel spliced with
//! `tokio::io::copy`, which flushes but never shuts the writer down, so the
//! client's FIN stopped at Fetch and never reached the upstream. An upstream
//! that reads to EOF before replying — HTTP/1.0, `curl --http1.0`, an SSH
//! session closing stdin — therefore waited forever for a FIN that was
//! already sent, and the response never came.

use radii_fetch::server::run_on;
use radii_integration::{bind_local, wait_ready};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The response body size. Large enough that a truncated read is unambiguous.
const BODY_LEN: usize = 64 * 1024;

/// An upstream that reads to EOF before answering. Reaching EOF at all is
/// the thing under test: it only happens if the client's FIN was forwarded.
async fn run_read_to_eof_upstream(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        tokio::spawn(async move {
            let mut request = Vec::new();
            let _ = stream.read_to_end(&mut request).await;
            let _ = stream.write_all(&vec![b'R'; BODY_LEN]).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
        });
    }
}

#[tokio::test]
async fn tunnel_delivers_a_response_after_the_client_half_closes() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap().to_string();
    let upstream_handle = tokio::spawn(run_read_to_eof_upstream(upstream));

    let (listener, fetch_addr) = bind_local().await.unwrap();
    let target = upstream_addr.clone();
    let fetch_handle = tokio::spawn(async move { run_on(listener, &target).await });
    wait_ready(&fetch_addr).await.unwrap();

    let mut client = TcpStream::connect(&fetch_addr).await.unwrap();
    client.write_all(b"REQUEST").await.unwrap();
    // Done sending, still owed a response. The FIN must reach the upstream.
    client.shutdown().await.unwrap();

    let mut received = Vec::new();
    let outcome =
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut received)).await;

    fetch_handle.abort();
    upstream_handle.abort();

    match outcome {
        Err(_) => panic!(
            "the client half-closed and the response never arrived: the FIN did not \
             reach the upstream"
        ),
        Ok(Err(err)) => panic!("reading the tunnelled response failed: {err}"),
        Ok(Ok(_)) => assert_eq!(
            received.len(),
            BODY_LEN,
            "the response was truncated after a half-close"
        ),
    }
}
