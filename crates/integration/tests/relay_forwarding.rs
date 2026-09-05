//! A chain longer than one hop: the intermediate relay dials the next hop,
//! passes the tail of the path along, and once the terminal node acks,
//! carries opaque end-to-end bytes between the initiator and the target.

use radii_integration::pki::TestCa;
use radii_integration::{bind_local, wait_ready};
use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, RadiiMessage, RouteHop};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn run_echo(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else { break };
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
        allow_peers: Vec::new(),
        tls: Some(ca.issue(node_id)),
    }
}

#[tokio::test]
async fn a_two_hop_chain_carries_bytes_end_to_end() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    // Terminal node.
    let (t_listener, t_addr) = bind_local().await.unwrap();
    let t_runtime = radii_fetch::relay::RelayRuntime::new(
        relay_config(&ca, "node-t", &t_addr),
        echo_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(t_listener, t_runtime));

    // Intermediate relay.
    let (r_listener, r_addr) = bind_local().await.unwrap();
    let r_runtime = radii_fetch::relay::RelayRuntime::new(
        relay_config(&ca, "node-r", &r_addr),
        "127.0.0.1:1".to_string(), // never used: this node only forwards
        None,
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(r_listener, r_runtime));

    wait_ready(&t_addr).await.unwrap();
    wait_ready(&r_addr).await.unwrap();

    let mut hop =
        radii_proto::tls::dial_expecting(&r_addr, Some(&client_identity), Some("node-r"))
            .await
            .unwrap();

    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![
                RouteHop {
                    node_id: "node-r".into(),
                    addr: r_addr.clone(),
                },
                RouteHop {
                    node_id: "node-t".into(),
                    addr: t_addr.clone(),
                },
            ],
        },
    )
    .await
    .unwrap();

    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "tunnel_ready"),
        other => panic!("expected tunnel_ready, got {other:?}"),
    }

    // The end-to-end identity check binds to the TARGET, not to the relay we
    // actually dialed. This is the property that makes an opaque relay safe.
    let mut e2e = radii_proto::tls::connect_on(hop, &t_addr, Some(&client_identity), Some("node-t"))
        .await
        .unwrap();

    e2e.write_all(b"through").await.unwrap();
    let mut buf = [0u8; 7];
    e2e.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"through");
}

#[tokio::test]
async fn rejects_a_path_that_repeats_a_node() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();
    let (r_listener, r_addr) = bind_local().await.unwrap();
    let runtime = radii_fetch::relay::RelayRuntime::new(
        relay_config(&ca, "node-r", &r_addr),
        "127.0.0.1:1".to_string(),
        None,
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(r_listener, runtime));
    wait_ready(&r_addr).await.unwrap();

    let mut hop =
        radii_proto::tls::dial_expecting(&r_addr, Some(&client_identity), Some("node-r"))
            .await
            .unwrap();

    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![
                RouteHop {
                    node_id: "node-r".into(),
                    addr: r_addr.clone(),
                },
                RouteHop {
                    node_id: "node-r".into(),
                    addr: r_addr.clone(),
                },
            ],
        },
    )
    .await
    .unwrap();

    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "tunnel_path_loops"),
        other => panic!("expected a loop refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_a_path_longer_than_the_local_limit() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();
    let (r_listener, r_addr) = bind_local().await.unwrap();
    let mut config = relay_config(&ca, "node-r", &r_addr);
    config.max_hops = 1; // terminate-only posture
    let runtime =
        radii_fetch::relay::RelayRuntime::new(config, "127.0.0.1:1".to_string(), None).unwrap();
    tokio::spawn(radii_fetch::relay::run(r_listener, runtime));
    wait_ready(&r_addr).await.unwrap();

    let mut hop =
        radii_proto::tls::dial_expecting(&r_addr, Some(&client_identity), Some("node-r"))
            .await
            .unwrap();

    write_message(
        &mut hop,
        &RadiiMessage::TunnelOpen {
            hops: vec![
                RouteHop {
                    node_id: "node-r".into(),
                    addr: r_addr.clone(),
                },
                RouteHop {
                    node_id: "node-t".into(),
                    addr: "127.0.0.1:9".into(),
                },
            ],
        },
    )
    .await
    .unwrap();

    match read_message(&mut hop).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "tunnel_too_long"),
        other => panic!("expected a length refusal, got {other:?}"),
    }
}
