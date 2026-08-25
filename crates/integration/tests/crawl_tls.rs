use radii_crawl::server::{run_on_with_state, CrawlState};
use radii_integration::pki::TestCa;
use radii_integration::{bind_local, wait_ready};
use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, RadiiMessage};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

/// A TLS-enabled Crawl listener must reject a peer that is authenticated
/// (via a cert signed by the trusted CA) but claims a `node_id` that doesn't
/// match its own certificate identity — and must accept the same peer
/// claiming its own identity.
#[tokio::test]
async fn tls_enabled_crawl_authorizes_by_peer_identity() {
    let ca = TestCa::new();
    let crawl_identity = TlsIdentity::load(&ca.issue("crawl")).unwrap();
    let node_a_identity = TlsIdentity::load(&ca.issue("node-a")).unwrap();

    let (listener, addr) = bind_local().await.unwrap();
    let state = Arc::new(RwLock::new(CrawlState::default()));
    let state_clone = Arc::clone(&state);
    let handle = tokio::spawn(async move {
        run_on_with_state(listener, state_clone, Some(crawl_identity)).await
    });
    wait_ready(&addr).await.unwrap();

    let mut stream = radii_proto::tls::dial(&addr, Some(&node_a_identity))
        .await
        .unwrap();

    // Authenticated as "node-a", but claiming to *be* "node-b" — rejected.
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "node-b".into(),
            roles: vec![],
            listen_addrs: vec!["10.0.0.1:1".into()],
        },
    )
    .await
    .unwrap();
    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "unauthorized_node_id"),
        other => panic!("unexpected: {other:?}"),
    }
    assert!(!state.read().await.nodes.contains_key("node-b"));

    // Claiming its own authenticated identity — accepted.
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "node-a".into(),
            roles: vec![],
            listen_addrs: vec!["10.0.0.2:2".into()],
        },
    )
    .await
    .unwrap();
    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "hello_received"),
        other => panic!("unexpected: {other:?}"),
    }
    assert!(state.read().await.nodes.contains_key("node-a"));

    handle.abort();
}

/// A TLS-enabled Crawl listener must not accept plaintext Radii framing —
/// the TLS handshake fails and the connection is dropped before any message
/// is processed.
#[tokio::test]
async fn tls_enabled_crawl_rejects_plaintext_connections() {
    let ca = TestCa::new();
    let crawl_identity = TlsIdentity::load(&ca.issue("crawl")).unwrap();

    let (listener, addr) = bind_local().await.unwrap();
    let state = Arc::new(RwLock::new(CrawlState::default()));
    let handle =
        tokio::spawn(async move { run_on_with_state(listener, state, Some(crawl_identity)).await });
    wait_ready(&addr).await.unwrap();

    let mut stream = TcpStream::connect(&addr).await.unwrap();
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "node-a".into(),
            roles: vec![],
            listen_addrs: vec![],
        },
    )
    .await
    .unwrap();

    let result = read_message(&mut stream).await;
    assert!(
        result.is_err(),
        "expected a plaintext connection to a TLS-only listener to fail"
    );

    handle.abort();
}
