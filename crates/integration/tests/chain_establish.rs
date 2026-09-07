//! The initiator side of source routing: turning a resolved route into a
//! working end-to-end byte stream, and surfacing a hop's refusal when the
//! chain cannot be established.

use radii_core::routing::{NodeId, ResolvedHop, ResolvedRoute};
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
async fn establishes_a_two_hop_chain_and_returns_an_end_to_end_stream() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo(echo_listener));

    let (t_listener, t_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::relay::run(
        t_listener,
        radii_fetch::relay::RelayRuntime::new(
            relay_config(&ca, "node-t", &t_addr),
            echo_addr.to_string(),
            Some(TlsIdentity::load(&ca.issue("node-t")).unwrap()),
        )
        .unwrap(),
    ));

    let (r_listener, r_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::relay::run(
        r_listener,
        radii_fetch::relay::RelayRuntime::new(
            relay_config(&ca, "node-r", &r_addr),
            "127.0.0.1:1".to_string(),
            None,
        )
        .unwrap(),
    ));

    wait_ready(&t_addr).await.unwrap();
    wait_ready(&r_addr).await.unwrap();

    let route = ResolvedRoute {
        hops: vec![
            ResolvedHop {
                node_id: NodeId("node-r".into()),
                addr: r_addr.to_string(),
            },
            ResolvedHop {
                node_id: NodeId("node-t".into()),
                addr: t_addr.to_string(),
            },
        ],
        score: 1.0,
    };

    let mut stream =
        radii_fetch::chain::establish(&route, Some(&client_identity), Some(&client_identity))
            .await
            .unwrap();

    stream.write_all(b"chain").await.unwrap();
    let mut buf = [0u8; 5];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"chain");
}

#[tokio::test]
async fn fails_when_a_hop_refuses_the_chain() {
    let ca = TestCa::new();
    let client_identity = TlsIdentity::load(&ca.issue("node-s")).unwrap();

    let (r_listener, r_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_fetch::relay::run(
        r_listener,
        radii_fetch::relay::RelayRuntime::new(
            relay_config(&ca, "node-r", &r_addr),
            "127.0.0.1:1".to_string(),
            None,
        )
        .unwrap(),
    ));
    wait_ready(&r_addr).await.unwrap();

    // Next hop points at a closed port, so the relay cannot reach it.
    let route = ResolvedRoute {
        hops: vec![
            ResolvedHop {
                node_id: NodeId("node-r".into()),
                addr: r_addr.to_string(),
            },
            ResolvedHop {
                node_id: NodeId("node-t".into()),
                addr: "127.0.0.1:1".into(),
            },
        ],
        score: 1.0,
    };

    // `BoxedStream` (the `Ok` type) isn't `Debug`, so `unwrap_err` can't be
    // used here — it requires `T: Debug` to format a would-be `Ok` in its
    // panic message. Match instead.
    let err =
        match radii_fetch::chain::establish(&route, Some(&client_identity), Some(&client_identity))
            .await
        {
            Ok(_) => panic!("expected the chain to be refused"),
            Err(err) => err,
        };

    assert!(
        err.to_string().contains("tunnel_hop_unreachable"),
        "the refusal status should reach the initiator; got: {err}"
    );
}
