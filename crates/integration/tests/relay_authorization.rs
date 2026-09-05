//! Regression coverage for the `FromHead` relay path.
//!
//! Crawl binds a peer's claims to its authenticated identity, but the
//! `FromHead` envelope used to skip that check entirely: wrapping a spoofed
//! `NodeHello` in one was enough for any CA-issued peer to register arbitrary
//! node ids and listen addresses. These tests pin the two controls that close
//! it — a peer must be a configured relay, and the relayed claim must match
//! the identity the relaying Head authenticated for its own client.

use radii_crawl::server::{run_on_with_state, CrawlState};
use radii_integration::pki::TestCa;
use radii_integration::{bind_local, wait_ready};
use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, RadiiMessage, RelayedMessage};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

fn relay_peers(ids: &[&str]) -> HashSet<String> {
    ids.iter().map(|id| id.to_string()).collect()
}

fn spoofed_hello() -> RelayedMessage {
    RelayedMessage::NodeHello {
        node_id: "victim-node".into(),
        roles: vec!["resource".into()],
        listen_addrs: vec!["6.6.6.6:9000".into()],
    }
}

async fn start_crawl(
    identity: TlsIdentity,
    relay_peers: HashSet<String>,
) -> (String, Arc<RwLock<CrawlState>>, tokio::task::JoinHandle<()>) {
    let (listener, addr) = bind_local().await.unwrap();
    let state = Arc::new(RwLock::new(CrawlState {
        relay_peers,
        ..CrawlState::default()
    }));
    let state_clone = Arc::clone(&state);
    let handle = tokio::spawn(async move {
        let _ = run_on_with_state(listener, state_clone, Some(identity)).await;
    });
    wait_ready(&addr).await.unwrap();
    (addr, state, handle)
}

/// The original proof of concept: an ordinary authenticated peer — not a Head
/// at all — wraps a spoofed hello in `FromHead` and gets it ingested. The
/// direct form was already rejected; the wrapped form must be too.
#[tokio::test]
async fn from_head_no_longer_bypasses_the_identity_check() {
    let ca = TestCa::new();
    let crawl = TlsIdentity::load(&ca.issue("crawl")).unwrap();
    let attacker = TlsIdentity::load(&ca.issue("attacker")).unwrap();

    // No relay peers configured — the default posture.
    let (addr, state, handle) = start_crawl(crawl, HashSet::new()).await;

    let mut stream = radii_proto::tls::dial(&addr, Some(&attacker))
        .await
        .unwrap();

    // Direct spoof: rejected before this change, and still rejected.
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "victim-node".into(),
            roles: vec![],
            listen_addrs: vec!["6.6.6.6:9000".into()],
        },
    )
    .await
    .unwrap();
    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "unauthorized_node_id"),
        other => panic!("unexpected reply to direct spoof: {other:?}"),
    }

    // Same payload, wrapped. This is what used to succeed.
    write_message(
        &mut stream,
        &RadiiMessage::FromHead {
            source: "i-am-not-a-head".into(),
            client_identity: Some("victim-node".into()),
            message: spoofed_hello(),
        },
    )
    .await
    .unwrap();
    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "unauthorized_relay_peer"),
        other => panic!("unexpected reply to wrapped spoof: {other:?}"),
    }

    assert!(
        !state.read().await.nodes.contains_key("victim-node"),
        "the wrapped spoof must not reach the node registry"
    );
    handle.abort();
}

/// Being a configured relay peer is permission to relay, not permission to
/// claim anything: a Head cannot launder a spoofed identity for its client.
#[tokio::test]
async fn configured_relay_cannot_forge_the_client_identity() {
    let ca = TestCa::new();
    let crawl = TlsIdentity::load(&ca.issue("crawl")).unwrap();
    let head = TlsIdentity::load(&ca.issue("head-1")).unwrap();

    let (addr, state, handle) = start_crawl(crawl, relay_peers(&["head-1"])).await;
    let mut stream = radii_proto::tls::dial(&addr, Some(&head)).await.unwrap();

    // The relay is trusted to relay, and says its client authenticated as
    // "someone-else" — but the inner hello claims to be "victim-node".
    write_message(
        &mut stream,
        &RadiiMessage::FromHead {
            source: "127.0.0.1:9".into(),
            client_identity: Some("someone-else".into()),
            message: spoofed_hello(),
        },
    )
    .await
    .unwrap();
    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "unauthorized_node_id"),
        other => panic!("unexpected: {other:?}"),
    }

    // An unauthenticated bridge client cannot write state through a Head
    // either — end-to-end authentication is required, not just Head-to-Crawl.
    write_message(
        &mut stream,
        &RadiiMessage::FromHead {
            source: "127.0.0.1:9".into(),
            client_identity: None,
            message: spoofed_hello(),
        },
    )
    .await
    .unwrap();
    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "unauthorized_node_id"),
        other => panic!("unexpected: {other:?}"),
    }

    assert!(!state.read().await.nodes.contains_key("victim-node"));
    handle.abort();
}

/// The legitimate path still works: a configured relay forwarding a claim
/// that matches the client it authenticated.
#[tokio::test]
async fn configured_relay_forwards_a_matching_claim() {
    let ca = TestCa::new();
    let crawl = TlsIdentity::load(&ca.issue("crawl")).unwrap();
    let head = TlsIdentity::load(&ca.issue("head-1")).unwrap();

    let (addr, state, handle) = start_crawl(crawl, relay_peers(&["head-1"])).await;
    let mut stream = radii_proto::tls::dial(&addr, Some(&head)).await.unwrap();

    write_message(
        &mut stream,
        &RadiiMessage::FromHead {
            source: "127.0.0.1:9".into(),
            client_identity: Some("node-b".into()),
            message: RelayedMessage::NodeHello {
                node_id: "node-b".into(),
                roles: vec!["resource".into()],
                listen_addrs: vec!["10.0.0.5:9000".into()],
            },
        },
    )
    .await
    .unwrap();
    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "head_message_received"),
        other => panic!("unexpected: {other:?}"),
    }

    let guard = state.read().await;
    let entry = guard.nodes.get("node-b").expect("relayed hello ingested");
    assert_eq!(entry.listen_addrs, vec!["10.0.0.5:9000".to_string()]);
    drop(guard);
    handle.abort();
}
