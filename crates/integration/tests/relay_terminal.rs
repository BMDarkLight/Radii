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

//! A chain of length one: the initiator opens a tunnel whose only hop is the
//! target itself, then speaks end-to-end TLS through it.

use radii_integration::pki::TestCa;
use radii_integration::{bind_local, wait_ready};
use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, RadiiMessage, RouteHop};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn run_echo(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
    }
}

#[tokio::test]
async fn terminal_node_acks_and_tunnels_to_its_upstream() {
    let ca = TestCa::new();
    let tunnel_identity = TlsIdentity::load(&ca.issue("node-t")).unwrap();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let config = radii_fetch::config::RelayConfig {
        bind: relay_addr.to_string(),
        node_id: "node-t".into(),
        max_hops: 8,
        max_concurrent_total: 16,
        max_concurrent_per_peer: 4,
        idle_timeout_ms: 30_000,
        handshake_timeout_ms: 10_000,
        max_pending_total: 256,
        max_pending_per_addr: 16,
        allow_peers: Vec::new(),
        tls: Some(ca.issue("node-t")),
    };

    let runtime =
        radii_fetch::relay::RelayRuntime::new(config, echo_addr.to_string(), Some(tunnel_identity))
            .unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));
    wait_ready(&relay_addr).await.unwrap();

    // Hop-local session.
    let mut hop = radii_proto::tls::dial_expecting(
        &relay_addr.to_string(),
        Some(&client_identity),
        Some("node-t"),
    )
    .await
    .unwrap();

    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![RouteHop {
                node_id: "node-t".into(),
                addr: relay_addr.to_string(),
            }],
        },
    )
    .await
    .unwrap();

    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "tunnel_ready"),
        other => panic!("expected tunnel_ready, got {other:?}"),
    }

    // End-to-end session, nested inside the hop-local one.
    let mut e2e = radii_proto::tls::connect_on(
        hop,
        &relay_addr.to_string(),
        Some(&client_identity),
        Some("node-t"),
    )
    .await
    .unwrap();

    e2e.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    e2e.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test]
async fn rejects_a_tunnel_open_addressed_to_another_node() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let config = radii_fetch::config::RelayConfig {
        bind: relay_addr.to_string(),
        node_id: "node-t".into(),
        max_hops: 8,
        max_concurrent_total: 16,
        max_concurrent_per_peer: 4,
        idle_timeout_ms: 30_000,
        handshake_timeout_ms: 10_000,
        max_pending_total: 256,
        max_pending_per_addr: 16,
        allow_peers: Vec::new(),
        tls: Some(ca.issue("node-t")),
    };
    let runtime =
        radii_fetch::relay::RelayRuntime::new(config, echo_addr.to_string(), None).unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));
    wait_ready(&relay_addr).await.unwrap();

    let mut hop = radii_proto::tls::dial_expecting(
        &relay_addr.to_string(),
        Some(&client_identity),
        Some("node-t"),
    )
    .await
    .unwrap();

    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![RouteHop {
                node_id: "someone-else".into(),
                addr: relay_addr.to_string(),
            }],
        },
    )
    .await
    .unwrap();

    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "tunnel_misaddressed"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}
