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

//! A client that finishes sending and shuts down its write side still gets
//! its response.
//!
//! The relay splice used to return as soon as *either* direction saw EOF,
//! which cancelled the other direction mid-flight. A half-close — HTTP/1.0,
//! `curl --http1.0`, an SSH session closing stdin — therefore discarded the
//! entire response.
//!
//! The plain tunnel had the mirror-image bug — it waited for both directions
//! but never shut a write side down on EOF, so a half-close hung instead of
//! truncating. See `fetch_tunnel_half_close.rs`; both paths are covered now.

use radii_integration::pki::TestCa;
use radii_integration::{bind_local, wait_ready};
use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, RadiiMessage, RouteHop};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The response body size. Large enough that a truncated read is unambiguous.
const BODY_LEN: usize = 64 * 1024;

/// An origin that reads the request, pauses, and only then answers — the
/// ordering that makes a cancelled reverse direction observable. A real
/// origin doing any work at all behaves this way.
async fn run_deliberate_origin(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let _ = stream.read(&mut buf).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = stream.write_all(&vec![b'R'; BODY_LEN]).await;
            let _ = stream.flush().await;
            let _ = stream.shutdown().await;
        });
    }
}

fn relay_config(ca: &TestCa, node_id: &str, bind: &str) -> radii_fetch::config::RelayConfig {
    radii_fetch::config::RelayConfig {
        bind: bind.to_string(),
        node_id: node_id.to_string(),
        max_hops: 8,
        max_concurrent_total: 16,
        max_concurrent_per_peer: 4,
        idle_timeout_ms: 30_000,
        handshake_timeout_ms: 10_000,
        max_pending_total: 256,
        max_pending_per_addr: 16,
        allow_peers: Vec::new(),
        tls: Some(ca.issue(node_id)),
    }
}

#[tokio::test]
async fn a_client_half_close_still_receives_the_whole_response() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_deliberate_origin(origin_listener));

    let (t_listener, t_addr) = bind_local().await.unwrap();
    let t_runtime = radii_fetch::relay::RelayRuntime::new(
        relay_config(&ca, "node-t", &t_addr),
        origin_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(t_listener, t_runtime));
    wait_ready(&t_addr).await.unwrap();

    let mut hop = radii_proto::tls::dial_expecting(&t_addr, Some(&client_identity), Some("node-t"))
        .await
        .unwrap();
    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![RouteHop {
                node_id: "node-t".into(),
                addr: t_addr.clone(),
            }],
        },
    )
    .await
    .unwrap();
    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "tunnel_ready"),
        other => panic!("expected tunnel_ready, got {other:?}"),
    }
    let e2e = radii_proto::tls::connect_on(hop, &t_addr, Some(&client_identity), Some("node-t"))
        .await
        .unwrap();

    let (mut reader, mut writer) = tokio::io::split(e2e);
    writer.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    // The half-close. The client is done sending; it is not done listening.
    writer.shutdown().await.unwrap();

    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), reader.read_to_end(&mut received))
        .await
        .expect("the chain must deliver the response, not hang")
        .expect("the response must arrive intact, not as a truncated stream");

    assert_eq!(
        received.len(),
        BODY_LEN,
        "the response was truncated: a half-close must not cancel the reverse direction"
    );
    assert!(received.iter().all(|byte| *byte == b'R'));
}
