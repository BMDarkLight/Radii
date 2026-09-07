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

//! Admission and resource bounds on the relay listener.
//!
//! Admission is deliberately open by default — any peer holding a
//! certificate from the configured CA may relay — because donated public
//! nodes are the point. That makes the bounds here the only thing standing
//! between a relay and a peer that wants all of it: without a per-peer cap
//! the global cap is decorative, since one identity can consume the lot.

// These tests deliberately do NOT call `wait_ready`. `bind_local` returns a
// listener that is already bound and listening, so `relay::run` only has to
// start accepting — a connection made before it does simply waits in the
// backlog. Probing for readiness would be redundant, and worse: the probe
// opens a connection of its own, which occupies a pre-admission slot. In a
// test that caps those slots at one, the probe races the test for the only
// slot it has.
use radii_core::routing::{NodeId, ResolvedHop, ResolvedRoute};
use radii_integration::bind_local;
use radii_integration::pki::TestCa;
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

/// A one-hop route to `node-t` at `addr`.
fn route_to(addr: &str) -> ResolvedRoute {
    ResolvedRoute {
        hops: vec![ResolvedHop {
            node_id: NodeId("node-t".into()),
            addr: addr.to_string(),
        }],
        score: 1.0,
    }
}

/// Establishes a chain, retrying while the relay is momentarily at
/// pre-admission capacity.
///
/// A pre-admission slot is handed back inside the relay's own task, at the
/// moment a chain is admitted — which is *after* the initiator has already
/// seen `establish` succeed. So with a cap of one, the next connection can
/// legitimately arrive before the previous slot has been released, and be
/// turned away by a plain TCP close.
///
/// That is not a leak, and the property under test is not "a slot is back
/// instantly" — it is "a slot comes back". Retrying to a deadline encodes
/// exactly that: if slots genuinely leaked, every attempt inside the window
/// would fail and this still reports the leak. A fixed sleep would only be
/// guessing how busy the machine is.
async fn establish_eventually(
    route: &ResolvedRoute,
    identity: &TlsIdentity,
) -> anyhow::Result<radii_proto::BoxedStream> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut last: anyhow::Error = anyhow::anyhow!("never attempted");
    while std::time::Instant::now() < deadline {
        match radii_fetch::chain::establish(route, Some(identity), Some(identity)).await {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                last = err;
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        }
    }
    Err(last)
}

/// With `allow_peers` set, CA membership stops being sufficient — the
/// operator has narrowed admission to an explicit list.
#[tokio::test]
async fn refuses_a_peer_outside_a_configured_allowlist() {
    let ca = TestCa::new();
    let stranger = TlsIdentity::load(&ca.issue("node-stranger")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-t", &relay_addr);
    config.allow_peers = vec!["node-friend".to_string()];
    let runtime = radii_fetch::relay::RelayRuntime::new(config, echo_addr.clone(), None).unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));

    let mut hop = radii_proto::tls::dial_expecting(&relay_addr, Some(&stranger), Some("node-t"))
        .await
        .unwrap();

    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![RouteHop {
                node_id: "node-t".into(),
                addr: relay_addr.clone(),
            }],
        },
    )
    .await
    .unwrap();

    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "relay_forbidden"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// An empty `allow_peers` admits any CA-valid peer — the donated-node
/// posture. Guards against the allowlist check accidentally inverting.
#[tokio::test]
async fn admits_any_ca_valid_peer_when_no_allowlist_is_set() {
    let ca = TestCa::new();
    let stranger = TlsIdentity::load(&ca.issue("node-stranger")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let config = relay_config(&ca, "node-t", &relay_addr);
    let runtime = radii_fetch::relay::RelayRuntime::new(
        config,
        echo_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));

    let mut stream =
        radii_fetch::chain::establish(&route_to(&relay_addr), Some(&stranger), Some(&stranger))
            .await
            .expect("a CA-valid peer must be admitted when no allowlist is configured");

    stream.write_all(b"open").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"open");
}

/// The load-bearing cap. Without it the global cap means nothing, because a
/// single identity can take every slot.
#[tokio::test]
async fn caps_concurrent_chains_per_peer() {
    let ca = TestCa::new();
    let peer = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-t", &relay_addr);
    config.max_concurrent_per_peer = 1;
    let runtime = radii_fetch::relay::RelayRuntime::new(
        config,
        echo_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));

    let route = route_to(&relay_addr);

    // Hold the first chain open. The permit must outlive the handshake and
    // stay held for as long as this stream is spliced — releasing it when
    // the handshake returns would make the cap unenforceable.
    let mut held = radii_fetch::chain::establish(&route, Some(&peer), Some(&peer))
        .await
        .expect("first chain should be admitted");
    held.write_all(b"hold").await.unwrap();
    let mut buf = [0u8; 4];
    held.read_exact(&mut buf).await.unwrap();

    let second = radii_fetch::chain::establish(&route, Some(&peer), Some(&peer)).await;
    let err = match second {
        Ok(_) => panic!("second concurrent chain should have been refused"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("relay_busy"),
        "expected relay_busy, got: {err}"
    );
}

/// `caps_concurrent_chains_per_peer` above uses one identity twice, which
/// proves nothing about *which* dimension is capped — a tally keyed by a
/// constant, or by source IP, or by anything else that happens to be the
/// same for both calls in that test, would pass it too. This test uses two
/// DISTINCT identities: peer A holds a chain against
/// `max_concurrent_per_peer = 1`, and peer B — genuinely different, not just
/// a different connection — must still be admitted, proving the tally is
/// keyed by the authenticated peer.
#[tokio::test]
async fn per_peer_cap_is_keyed_by_authenticated_identity_not_shared_globally() {
    let ca = TestCa::new();
    let peer_a = TlsIdentity::load(&ca.issue("node-a")).unwrap();
    let peer_b = TlsIdentity::load(&ca.issue("node-b")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-t", &relay_addr);
    config.max_concurrent_per_peer = 1;
    let runtime = radii_fetch::relay::RelayRuntime::new(
        config,
        echo_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));

    let route = route_to(&relay_addr);

    // Peer A holds its one permitted slot open.
    let mut held = radii_fetch::chain::establish(&route, Some(&peer_a), Some(&peer_a))
        .await
        .expect("peer A's first chain should be admitted");
    held.write_all(b"hold").await.unwrap();
    let mut buf = [0u8; 4];
    held.read_exact(&mut buf).await.unwrap();

    // Peer B is a genuinely different authenticated identity and must be
    // admitted even though peer A is already at its per-peer cap — if the
    // tally were keyed by anything other than the authenticated peer (a
    // constant, the shared source IP, the relay itself), this would
    // incorrectly refuse peer B too.
    let mut other = radii_fetch::chain::establish(&route, Some(&peer_b), Some(&peer_b))
        .await
        .expect("a distinct peer must be admitted despite peer A being at its own cap");
    other.write_all(b"also").await.unwrap();
    let mut buf2 = [0u8; 4];
    other.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"also");
}

/// `max_concurrent_total` was never set low enough to actually trip in the
/// existing suite. This sets it to 1 with two distinct peers, so the second
/// admitted peer is refused purely by the global cap even though neither has
/// touched its own per-peer limit.
#[tokio::test]
async fn max_concurrent_total_refuses_a_second_peer_once_tripped() {
    let ca = TestCa::new();
    let peer_a = TlsIdentity::load(&ca.issue("node-a")).unwrap();
    let peer_b = TlsIdentity::load(&ca.issue("node-b")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-t", &relay_addr);
    config.max_concurrent_total = 1;
    let runtime = radii_fetch::relay::RelayRuntime::new(
        config,
        echo_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));

    let route = route_to(&relay_addr);

    let mut held = radii_fetch::chain::establish(&route, Some(&peer_a), Some(&peer_a))
        .await
        .expect("first chain should be admitted under the global cap");
    held.write_all(b"hold").await.unwrap();
    let mut buf = [0u8; 4];
    held.read_exact(&mut buf).await.unwrap();

    let second = radii_fetch::chain::establish(&route, Some(&peer_b), Some(&peer_b)).await;
    let err = match second {
        Ok(_) => panic!("second peer should have been refused by the global cap"),
        Err(err) => err,
    };
    assert!(
        err.to_string().contains("relay_busy"),
        "expected relay_busy, got: {err}"
    );
}

/// A slot must come back when its chain ends, or the cap degrades into a
/// permanent lockout after `max_concurrent_per_peer` connections.
#[tokio::test]
async fn releases_a_slot_when_the_chain_ends() {
    let ca = TestCa::new();
    let peer = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-t", &relay_addr);
    config.max_concurrent_per_peer = 1;
    let runtime = radii_fetch::relay::RelayRuntime::new(
        config,
        echo_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));

    let route = route_to(&relay_addr);

    for attempt in 0..3 {
        let mut stream = radii_fetch::chain::establish(&route, Some(&peer), Some(&peer))
            .await
            .unwrap_or_else(|err| panic!("attempt {attempt} refused: {err}"));
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        drop(stream);

        // Give the relay a moment to notice the close and drop its permit.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// A chain that goes quiet in BOTH directions is dropped, so a peer cannot
/// complete a handshake, occupy a concurrency slot, and then hold it forever
/// without sending anything.
#[tokio::test]
async fn drops_a_chain_that_goes_idle() {
    let ca = TestCa::new();
    let peer = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-t", &relay_addr);
    config.idle_timeout_ms = 300;
    let runtime = radii_fetch::relay::RelayRuntime::new(
        config,
        echo_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));

    let mut stream =
        radii_fetch::chain::establish(&route_to(&relay_addr), Some(&peer), Some(&peer))
            .await
            .unwrap();

    // Send nothing and wait past the idle window.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    let mut buf = [0u8; 1];
    let read = stream.read(&mut buf).await;
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "an idle chain must be dropped, got {read:?}"
    );
}

/// Traffic keeps a chain alive past the idle window. Guards against the
/// watchdog being a total deadline rather than an inactivity timer — that
/// mistake would kill every long-lived tunnel.
#[tokio::test]
async fn keeps_a_busy_chain_alive_past_the_idle_window() {
    let ca = TestCa::new();
    let peer = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-t", &relay_addr);
    config.idle_timeout_ms = 300;
    let runtime = radii_fetch::relay::RelayRuntime::new(
        config,
        echo_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));

    let mut stream =
        radii_fetch::chain::establish(&route_to(&relay_addr), Some(&peer), Some(&peer))
            .await
            .unwrap();

    // Six round trips spanning ~1.2s, four times the idle window.
    for _ in 0..6 {
        stream.write_all(b"tick").await.unwrap();
        let mut buf = [0u8; 4];
        stream
            .read_exact(&mut buf)
            .await
            .expect("a chain carrying traffic must not be dropped as idle");
        assert_eq!(&buf, b"tick");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// The concurrency caps above govern *admitted* chains. They are taken only
/// after the mTLS accept and the first frame read have both succeeded, so on
/// their own they leave the handshake window itself unbounded: a peer could
/// open connections without limit and hold each one for `handshake_timeout_ms`
/// at no accounting cost.
///
/// Bounding that window is awkward on purpose. Before the TLS handshake
/// completes there is no authenticated identity to key an allowance on —
/// the identity is precisely what the handshake produces, and refusing to
/// pay for the handshake means refusing to learn it. The source address is
/// the only handle available, so that is what the pre-admission caps use,
/// with a global ceiling behind it.
#[tokio::test]
async fn refuses_a_connection_beyond_the_pre_admission_cap() {
    let ca = TestCa::new();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-t", &relay_addr);
    config.max_pending_per_addr = 1;
    let runtime = radii_fetch::relay::RelayRuntime::new(config, echo_addr.clone(), None).unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));
    // Occupy the single pre-admission slot: connect, then never send a
    // ClientHello, so the relay sits in its TLS accept.
    let _stalled = tokio::net::TcpStream::connect(&relay_addr).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // A second connection from the same address must be dropped before the
    // relay spends a handshake on it. It gets a plain TCP close: sending a
    // Radii status would itself require completing the handshake we are
    // declining to pay for.
    let mut refused = tokio::net::TcpStream::connect(&relay_addr).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), refused.read(&mut buf))
        .await
        .expect("relay should close a beyond-cap connection promptly, not hold it");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "expected the second pre-admission connection to be closed, got {read:?}"
    );
}

/// The global pre-admission ceiling, independent of source address.
#[tokio::test]
async fn refuses_a_connection_beyond_the_global_pre_admission_cap() {
    let ca = TestCa::new();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-t", &relay_addr);
    config.max_pending_total = 1;
    config.max_pending_per_addr = 64; // so the per-address cap cannot be what trips
    let runtime = radii_fetch::relay::RelayRuntime::new(config, echo_addr.clone(), None).unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));
    let _stalled = tokio::net::TcpStream::connect(&relay_addr).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let mut refused = tokio::net::TcpStream::connect(&relay_addr).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), refused.read(&mut buf))
        .await
        .expect("relay should close a beyond-ceiling connection promptly");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "expected the second connection to be closed, got {read:?}"
    );
}

/// A pre-admission slot must be released once its connection is admitted, or
/// the relay locks itself out after `max_pending_total` successful chains.
#[tokio::test]
async fn releases_a_pre_admission_slot_once_a_chain_is_admitted() {
    let ca = TestCa::new();
    let peer = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-t", &relay_addr);
    // One pre-admission slot, but several admitted chains allowed. Each
    // chain must hand its slot back on admission, or the second attempt
    // never gets a handshake.
    config.max_pending_total = 1;
    config.max_pending_per_addr = 1;
    let runtime = radii_fetch::relay::RelayRuntime::new(
        config,
        echo_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));

    let route = route_to(&relay_addr);
    let mut held = Vec::new();
    for attempt in 0..3 {
        let mut stream = establish_eventually(&route, &peer)
            .await
            .unwrap_or_else(|err| {
                panic!("attempt {attempt} refused — a pre-admission slot leaked: {err}")
            });
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        // Keep the chain open: it holds a chain permit, but must no longer
        // hold a pre-admission slot.
        held.push(stream);
    }
}
