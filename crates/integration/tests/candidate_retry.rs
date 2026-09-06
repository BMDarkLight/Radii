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
