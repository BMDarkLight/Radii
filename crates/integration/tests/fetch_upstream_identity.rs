//! Regression coverage for graph-resolved tunnel upstreams.
//!
//! Fetch dials whatever address Crawl's node registry advertises for its
//! target. That registry is written by peers, so the address is a claim: a
//! poisoned `listen_addrs` used to silently redirect the tunnel to an
//! attacker, and upstream mTLS did not help because nothing checked *which*
//! node answered — only that it held some CA-issued certificate.

use radii_fetch::graph::ResolvedTarget;
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

async fn tunnel_through(
    target: Option<ResolvedTarget>,
    listener_tls: Option<TlsIdentity>,
    upstream_tls: Option<TlsIdentity>,
    static_upstream: String,
) -> std::io::Result<usize> {
    let (fetch_listener, fetch_addr) = bind_local().await.unwrap();
    let shared = Arc::new(RwLock::new(target));
    let handle = tokio::spawn(async move {
        let _ = run_on_dynamic_with_tls(
            fetch_listener,
            static_upstream,
            shared,
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
#[tokio::test]
async fn refuses_an_upstream_that_is_not_the_intended_node() {
    let ca = TestCa::new();
    let attacker_identity = TlsIdentity::load(&ca.issue("attacker")).unwrap();
    let fetch_identity = TlsIdentity::load(&ca.issue("fetch")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    let echo_handle = tokio::spawn(run_tls_echo(echo_listener, attacker_identity));

    let bytes = tunnel_through(
        Some(ResolvedTarget {
            addr: echo_addr,
            node_id: "node-b".into(),
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
    echo_handle.abort();
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
#[tokio::test]
async fn tunnels_to_an_upstream_that_proves_its_node_id() {
    let ca = TestCa::new();
    let node_b_identity = TlsIdentity::load(&ca.issue("node-b")).unwrap();
    let fetch_identity = TlsIdentity::load(&ca.issue("fetch")).unwrap();

    let (echo_listener, echo_addr) = bind_local().await.unwrap();
    let echo_handle = tokio::spawn(run_tls_echo(echo_listener, node_b_identity));

    let bytes = tunnel_through(
        Some(ResolvedTarget {
            addr: echo_addr,
            node_id: "node-b".into(),
        }),
        None,
        Some(fetch_identity),
        "127.0.0.1:1".to_string(),
    )
    .await
    .expect("tunnel to the correct node should succeed");

    assert_eq!(bytes, 4, "expected the echoed \"ping\" back");
    echo_handle.abort();
}
