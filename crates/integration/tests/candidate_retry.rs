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

//! The retry loop: fetch walks ranked candidates and fails over to the next
//! when one doesn't work, so a dead target or a broken hop no longer drops
//! the connection.

use radii_core::routing::{NodeId, ResolvedHop, ResolvedRoute};
use radii_integration::pki::TestCa;
use radii_integration::{bind_local, wait_ready};
use radii_proto::tls::TlsIdentity;
use std::sync::{Arc, RwLock};
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
async fn falls_over_to_the_second_candidate_when_the_first_is_dead() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    // Only the second target is actually running.
    let (t_listener, t_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::relay::run(
        t_listener,
        radii_fetch::relay::RelayRuntime::new(
            relay_config(&ca, "node-t2", &t_addr),
            echo_addr.to_string(),
            Some(TlsIdentity::load(&ca.issue("node-t2")).unwrap()),
        )
        .unwrap(),
    ));
    wait_ready(&t_addr).await.unwrap();

    let routes = vec![
        // Dead: nothing listens here.
        ResolvedRoute {
            hops: vec![ResolvedHop {
                node_id: NodeId("node-t1".into()),
                addr: "127.0.0.1:1".into(),
            }],
            score: 1.0,
        },
        ResolvedRoute {
            hops: vec![ResolvedHop {
                node_id: NodeId("node-t2".into()),
                addr: t_addr.to_string(),
            }],
            score: 2.0,
        },
    ];

    let (fetch_listener, fetch_addr) = bind_local().await.unwrap();
    let shared = Arc::new(RwLock::new(routes));
    tokio::spawn(radii_fetch::server::run_on_dynamic_with_tls(
        fetch_listener,
        "127.0.0.1:1".to_string(),
        shared,
        3000,
        None,
        Some(client_identity),
    ));
    wait_ready(&fetch_addr).await.unwrap();

    let mut client = tokio::net::TcpStream::connect(&fetch_addr).await.unwrap();
    client.write_all(b"failover").await.unwrap();
    let mut buf = [0u8; 8];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(
        &buf, b"failover",
        "the client must not observe the dead candidate"
    );
}

/// The failure mode `terminate()`'s dial-before-ack ordering exists to
/// close: a first candidate that is a REAL, reachable relay terminal — the
/// hop-local handshake succeeds and the node is very much up — but whose own
/// configured upstream is a dead address. Before the fix, this relay would
/// ack `tunnel_ready` before ever dialing its upstream, so `chain::establish`
/// would return Ok and the retry loop would stop, never reaching the second,
/// working candidate. The client must still get its data.
#[tokio::test]
async fn falls_over_when_the_first_candidates_own_upstream_is_dead() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    // First candidate: a real, reachable relay terminal whose own upstream
    // is a dead address. The hop-local handshake with this node succeeds —
    // it is genuinely up — but it can never reach its backend.
    let (t1_listener, t1_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::relay::run(
        t1_listener,
        radii_fetch::relay::RelayRuntime::new(
            relay_config(&ca, "node-t1", &t1_addr),
            "127.0.0.1:1".to_string(), // dead: this node's own upstream is down
            Some(TlsIdentity::load(&ca.issue("node-t1")).unwrap()),
        )
        .unwrap(),
    ));
    wait_ready(&t1_addr).await.unwrap();

    // Second candidate: a real, reachable relay terminal with a working
    // upstream.
    let (t2_listener, t2_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::relay::run(
        t2_listener,
        radii_fetch::relay::RelayRuntime::new(
            relay_config(&ca, "node-t2", &t2_addr),
            echo_addr.to_string(),
            Some(TlsIdentity::load(&ca.issue("node-t2")).unwrap()),
        )
        .unwrap(),
    ));
    wait_ready(&t2_addr).await.unwrap();

    let routes = vec![
        ResolvedRoute {
            hops: vec![ResolvedHop {
                node_id: NodeId("node-t1".into()),
                addr: t1_addr.to_string(),
            }],
            score: 1.0,
        },
        ResolvedRoute {
            hops: vec![ResolvedHop {
                node_id: NodeId("node-t2".into()),
                addr: t2_addr.to_string(),
            }],
            score: 2.0,
        },
    ];

    let (fetch_listener, fetch_addr) = bind_local().await.unwrap();
    let shared = Arc::new(RwLock::new(routes));
    tokio::spawn(radii_fetch::server::run_on_dynamic_with_tls(
        fetch_listener,
        "127.0.0.1:1".to_string(),
        shared,
        3000,
        None,
        Some(client_identity),
    ));
    wait_ready(&fetch_addr).await.unwrap();

    let mut client = tokio::net::TcpStream::connect(&fetch_addr).await.unwrap();
    client.write_all(b"failover").await.unwrap();
    let mut buf = [0u8; 8];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(
        &buf, b"failover",
        "a dead backend behind a live relay terminal must not consume the candidate"
    );
}

#[tokio::test]
async fn falls_back_to_the_static_upstream_when_every_candidate_fails() {
    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let routes = vec![ResolvedRoute {
        hops: vec![ResolvedHop {
            node_id: NodeId("node-dead".into()),
            addr: "127.0.0.1:1".into(),
        }],
        score: 1.0,
    }];

    // The static upstream is plaintext here, same as `run_echo` is used
    // elsewhere in this suite (e.g. as a relay's terminal upstream) — an
    // operator-configured static target is not assumed to speak Radii's
    // mTLS at all, hence no TLS identity is passed for this dial.
    let (fetch_listener, fetch_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::server::run_on_dynamic_with_tls(
        fetch_listener,
        echo_addr.to_string(),
        Arc::new(RwLock::new(routes)),
        1000,
        None,
        None,
    ));
    wait_ready(&fetch_addr).await.unwrap();

    let mut client = tokio::net::TcpStream::connect(&fetch_addr).await.unwrap();
    client.write_all(b"static").await.unwrap();
    let mut buf = [0u8; 6];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"static");
}
