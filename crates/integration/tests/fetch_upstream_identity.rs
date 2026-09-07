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

//! Regression coverage for graph-resolved tunnel upstreams.
//!
//! Fetch dials whatever address Crawl's node registry advertises for its
//! target. That registry is written by peers, so the address is a claim: a
//! poisoned `listen_addrs` used to silently redirect the tunnel to an
//! attacker, and upstream mTLS did not help because nothing checked *which*
//! node answered — only that it held some CA-issued certificate.

use radii_core::routing::{NodeId, ResolvedHop, ResolvedRoute};
use radii_fetch::server::run_on_dynamic_with_tls;
use radii_integration::pki::TestCa;
use radii_integration::{bind_local, wait_ready};
use radii_proto::tls::TlsIdentity;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A TLS listener that echoes, standing in for whatever host the poisoned
/// address points at.
async fn run_tls_echo(listener: TcpListener, identity: TlsIdentity) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let identity = identity.clone();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = radii_proto::tls::accept(stream, Some(&identity)).await {
                let mut buf = [0u8; 64];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        });
    }
}

/// A plain (non-TLS) byte echo, standing in for whatever service a relay's
/// terminal node forwards to once it has terminated the end-to-end session.
async fn run_plain_echo(listener: TcpListener) {
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
    relay_config_with_identity(ca, node_id, node_id, bind)
}

/// Like [`relay_config`], but lets the certificate identity diverge from the
/// relay's own `node_id` — the shape a poisoned registry entry takes: a
/// node that claims to be `node_id` in the route (and so passes `validate`'s
/// `hops[0] == self` check) while actually authenticating as `cert_name`.
fn relay_config_with_identity(
    ca: &TestCa,
    node_id: &str,
    cert_name: &str,
    bind: &str,
) -> radii_fetch::config::RelayConfig {
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
        tls: Some(ca.issue(cert_name)),
    }
}

async fn tunnel_through(
    route: Option<ResolvedRoute>,
    listener_tls: Option<TlsIdentity>,
    upstream_tls: Option<TlsIdentity>,
    static_upstream: String,
) -> std::io::Result<usize> {
    let (fetch_listener, fetch_addr) = bind_local().await.unwrap();
    let shared = Arc::new(RwLock::new(route.into_iter().collect::<Vec<_>>()));
    let handle = tokio::spawn(async move {
        let _ = run_on_dynamic_with_tls(
            fetch_listener,
            static_upstream,
            shared,
            3000,
            listener_tls,
            upstream_tls,
        )
        .await;
    });
    wait_ready(&fetch_addr).await.unwrap();

    let mut client = TcpStream::connect(&fetch_addr).await.unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 64];
    let result = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
        .await
        .unwrap_or(Ok(0));
    handle.abort();
    result
}

/// The hijack: the graph advertises an address for `node-b`, but the host
/// answering there authenticates as a different node. Fetch must refuse
/// rather than relay bytes to it — even though that host holds a perfectly
/// valid certificate from the same CA.
///
/// Since Task 10 the data path always goes through `chain::establish`, which
/// speaks the relay protocol rather than dialing a bare TLS socket. A plain
/// TLS echo standing in for the attacker would make this test pass for the
/// wrong reason: `establish` writes `TunnelOpen`, the echo reflects those
/// bytes back verbatim, and `read_message` bails with a decode/protocol
/// error having never reached the identity check at all — deleting the CN
/// check entirely would leave this test green. So the attacker fixture here
/// is a real relay terminal node — `RelayConfig.node_id = "node-b"`, so
/// `validate`'s `hops[0] == self` check passes and it would happily ack —
/// but whose TLS identity is a certificate issued to `attacker`. The only
/// thing that can still stop the chain is the hop-local CN check in
/// `dial_expecting`, which is exactly the property this test exists to
/// prove.
#[tokio::test]
async fn refuses_an_upstream_that_is_not_the_intended_node() {
    let ca = TestCa::new();
    let fetch_identity = TlsIdentity::load(&ca.issue("fetch")).unwrap();

    // A real, working upstream behind the attacker relay's terminate() step
    // — not a dead address — so that if every identity check were bypassed
    // the hijack would genuinely succeed (bytes echoed back) rather than
    // failing anyway for the unrelated reason of a dead fallback address.
    let (plain_echo_listener, plain_echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_plain_echo(plain_echo_listener));

    let (attacker_listener, attacker_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::relay::run(
        attacker_listener,
        radii_fetch::relay::RelayRuntime::new(
            // Claims to be "node-b" (so it passes the relay's own hop
            // validation) but authenticates with an "attacker" certificate
            // on both the hop-local listener and the nested end-to-end
            // session, so a bypass of either layer's identity check is
            // still caught by the other rather than by an incidental
            // transport error.
            relay_config_with_identity(&ca, "node-b", "attacker", &attacker_addr),
            plain_echo_addr,
            Some(TlsIdentity::load(&ca.issue("attacker")).unwrap()),
        )
        .unwrap(),
    ));
    wait_ready(&attacker_addr).await.unwrap();

    let bytes = tunnel_through(
        Some(ResolvedRoute {
            hops: vec![ResolvedHop {
                node_id: NodeId("node-b".into()),
                addr: attacker_addr,
            }],
            score: 1.0,
        }),
        None,
        Some(fetch_identity),
        "127.0.0.1:1".to_string(),
    )
    .await;

    assert!(
        matches!(bytes, Ok(0)) || bytes.is_err(),
        "fetch must not relay bytes to a host that is not the intended node"
    );
}

/// Pins *why* the tunnel above refuses: the handshake itself succeeds — the
/// attacker holds a valid certificate from the same CA — and the connection
/// is rejected specifically because the authenticated node id is not the one
/// asked for. Without this, the end-to-end test could pass for an unrelated
/// TLS failure and still look green.
#[tokio::test]
async fn dial_expecting_rejects_a_valid_cert_for_the_wrong_node() {
    let ca = TestCa::new();
    let attacker_identity = TlsIdentity::load(&ca.issue("attacker")).unwrap();
    let fetch_identity = TlsIdentity::load(&ca.issue("fetch")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    let echo_handle = tokio::spawn(run_tls_echo(echo_listener, attacker_identity));

    // Same address, same CA, same everything — only the expectation differs.
    let accepted = radii_proto::tls::dial_expecting(&echo_addr, Some(&fetch_identity), None).await;
    assert!(
        accepted.is_ok(),
        "the peer is a legitimate CA-issued host, so an unconstrained dial connects"
    );

    let refused =
        radii_proto::tls::dial_expecting(&echo_addr, Some(&fetch_identity), Some("node-b")).await;
    // `BoxedStream` isn't `Debug`, so unwrap the error by hand.
    let message = match refused {
        Ok(_) => panic!("expected the node id mismatch to be refused"),
        Err(err) => err.to_string(),
    };
    assert!(
        message.contains("attacker") && message.contains("node-b"),
        "error should name both the actual and expected node: {message}"
    );

    echo_handle.abort();
}

/// The honest path still works: the host answering at the advertised address
/// authenticates as the node the route was planned to.
///
/// Since Task 10, a resolved route is walked via `chain::establish`, which
/// speaks the relay protocol (`TunnelOpen`/`Ack` plus a nested end-to-end
/// handshake) even for a single-hop route — the target of any graph-resolved
/// route is now assumed to run a relay listener, terminate-only or not. So
/// the honest node in this test must actually be a terminal relay node
/// rather than a bare TLS echo; the identity check under test still runs at
/// the very first step of `establish` (the hop-local dial), unchanged.
#[tokio::test]
async fn tunnels_to_an_upstream_that_proves_its_node_id() {
    let ca = TestCa::new();
    let fetch_identity = TlsIdentity::load(&ca.issue("fetch")).unwrap();

    let (plain_echo_listener, plain_echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_plain_echo(plain_echo_listener));

    let (b_listener, b_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::relay::run(
        b_listener,
        radii_fetch::relay::RelayRuntime::new(
            relay_config(&ca, "node-b", &b_addr),
            plain_echo_addr,
            Some(TlsIdentity::load(&ca.issue("node-b")).unwrap()),
        )
        .unwrap(),
    ));
    wait_ready(&b_addr).await.unwrap();

    let bytes = tunnel_through(
        Some(ResolvedRoute {
            hops: vec![ResolvedHop {
                node_id: NodeId("node-b".into()),
                addr: b_addr,
            }],
            score: 1.0,
        }),
        None,
        Some(fetch_identity),
        "127.0.0.1:1".to_string(),
    )
    .await
    .expect("tunnel to the correct node should succeed");

    assert_eq!(bytes, 4, "expected the echoed \"ping\" back");
}
