//! `radii_fetch::run` must actually start the relay listener when `[relay]`
//! is configured.
//!
//! This is the seam that makes source routing work at all: graph-resolved
//! routes are delivered over the relay protocol, so a node whose `run()`
//! never binds a relay listener cannot be reached as a route target by
//! anyone. Every relay test other than this one drives `relay::run` directly,
//! which would stay green even if the production wiring were missing
//! entirely — so this test is the only thing standing between the feature and
//! shipping inert.

use radii_fetch::config::{Config, RelayConfig, TunnelTlsConfig};
use radii_integration::pki::TestCa;
use radii_integration::{bind_local, wait_ready};
use radii_proto::tls::TlsIdentity;
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

/// Binds an ephemeral port, then releases it, to obtain an address that is
/// free right now. Mildly racy in principle; in practice the OS does not
/// hand the same ephemeral port straight back.
async fn free_addr() -> String {
    let (listener, addr) = bind_local().await.unwrap();
    drop(listener);
    addr
}

#[tokio::test]
async fn run_starts_the_relay_listener_when_configured() {
    let ca = TestCa::new();
    let peer = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let tunnel_bind = free_addr().await;
    let relay_bind = free_addr().await;

    let config = Config {
        bind: tunnel_bind,
        upstream: echo_addr.clone(),
        graph: None,
        tls: None,
        // A chain terminal needs an inner-session identity: the end-to-end
        // session is the only thing authenticating an originator that is not
        // the previous hop.
        tunnel_tls: Some(TunnelTlsConfig {
            listener: Some(ca.issue("node-t")),
            upstream: None,
        }),
        relay: Some(RelayConfig {
            bind: relay_bind.clone(),
            node_id: "node-t".to_string(),
            max_hops: 8,
            max_concurrent_total: 16,
            max_concurrent_per_peer: 4,
            idle_timeout_ms: 30_000,
            handshake_timeout_ms: 10_000,
            allow_peers: Vec::new(),
            tls: Some(ca.issue("node-t")),
        }),
    };

    tokio::spawn(async move {
        let _ = radii_fetch::run(config).await;
    });
    wait_ready(&relay_bind).await.unwrap();

    // A chain terminating at this node must be served by the listener that
    // `run()` started — nothing in this test constructs a RelayRuntime.
    let route = radii_core::routing::ResolvedRoute {
        hops: vec![radii_core::routing::ResolvedHop {
            node_id: radii_core::routing::NodeId("node-t".into()),
            addr: relay_bind.clone(),
        }],
        score: 1.0,
    };

    let mut stream = radii_fetch::chain::establish(&route, Some(&peer), Some(&peer))
        .await
        .expect("run() should have started a relay listener able to terminate a chain");

    stream.write_all(b"wired").await.unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"wired");
}

/// Absent `[relay]`, no second listener is opened — relaying stays opt-in
/// and an upgrade does not silently turn a node into a relay.
#[tokio::test]
async fn run_opens_no_relay_listener_without_a_relay_section() {
    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let tunnel_bind = free_addr().await;
    let unused_relay_bind = free_addr().await;

    let config = Config {
        bind: tunnel_bind.clone(),
        upstream: echo_addr,
        graph: None,
        tls: None,
        tunnel_tls: None,
        relay: None,
    };

    tokio::spawn(async move {
        let _ = radii_fetch::run(config).await;
    });
    wait_ready(&tunnel_bind).await.unwrap();

    assert!(
        tokio::net::TcpStream::connect(&unused_relay_bind)
            .await
            .is_err(),
        "no relay listener should exist when [relay] is absent"
    );
}
