use radii_fetch::server::run_on_with_tls;
use radii_integration::pki::TestCa;
use radii_integration::{bind_local, wait_ready};
use radii_proto::tls::TlsIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// End-to-end: a client dials Fetch over mTLS, Fetch itself dials the
/// upstream over a *separate* mTLS session, and bytes still tunnel through
/// correctly in both directions.
#[tokio::test]
async fn fetch_tunnels_over_mtls_both_sides() {
    let ca = TestCa::new();
    let listener_identity = TlsIdentity::load(&ca.issue("fetch-listener")).unwrap();
    let client_identity = TlsIdentity::load(&ca.issue("client")).unwrap();
    let upstream_identity = TlsIdentity::load(&ca.issue("fetch-upstream-dialer")).unwrap();
    let echo_identity = TlsIdentity::load(&ca.issue("echo")).unwrap();

    // A TLS-terminated echo server standing in for the upstream.
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap().to_string();
    let echo_handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = echo_listener.accept().await else {
                break;
            };
            let identity = echo_identity.clone();
            tokio::spawn(async move {
                let Ok((mut stream, _)) = radii_proto::tls::accept(stream, Some(&identity)).await
                else {
                    return;
                };
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf).await {
                    if n > 0 {
                        let _ = stream.write_all(&buf[..n]).await;
                    }
                }
            });
        }
    });

    let (fetch_listener, fetch_addr) = bind_local().await.unwrap();
    let fetch_handle = tokio::spawn(async move {
        run_on_with_tls(
            fetch_listener,
            echo_addr,
            Some(listener_identity),
            Some(upstream_identity),
        )
        .await
    });
    wait_ready(&fetch_addr).await.unwrap();

    let mut client = radii_proto::tls::dial(&fetch_addr, Some(&client_identity))
        .await
        .unwrap();
    client.write_all(b"ping-tls").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("timed out reading tunnel echo")
        .unwrap();
    assert_eq!(&buf[..n], b"ping-tls");

    fetch_handle.abort();
    echo_handle.abort();
}

/// A client without a trusted certificate must not be able to tunnel
/// through a listener-side-mTLS-enabled Fetch. TLS's post-handshake client
/// auth means a rejected client's `dial()` call doesn't always surface the
/// failure synchronously (rustls may tear the session down right after
/// verifying the client cert, rather than during the handshake future
/// itself) — so the property that actually matters, and the one this test
/// checks, is that no application bytes make it through the tunnel either
/// way.
#[tokio::test]
async fn fetch_rejects_untrusted_client_on_tls_listener() {
    let ca = TestCa::new();
    let listener_identity = TlsIdentity::load(&ca.issue("fetch-listener")).unwrap();
    let trusted_client_identity = TlsIdentity::load(&ca.issue("trusted-client")).unwrap();

    let other_ca = TestCa::new();
    let mut outsider_config = other_ca.issue("outsider");
    // Trust the *real* CA (so it can verify Fetch's cert) while presenting a
    // leaf cert signed by a completely different, untrusted CA.
    outsider_config.ca = ca.ca_path();
    let outsider_identity = TlsIdentity::load(&outsider_config).unwrap();

    // A real, reachable plaintext echo upstream — proves any tunnel failure
    // below is caused by the untrusted client, not an unreachable upstream.
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap().to_string();
    let echo_handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                if let Ok(n) = stream.read(&mut buf).await {
                    if n > 0 {
                        let _ = stream.write_all(&buf[..n]).await;
                    }
                }
            });
        }
    });

    let (fetch_listener, fetch_addr) = bind_local().await.unwrap();
    let fetch_handle = tokio::spawn(async move {
        run_on_with_tls(fetch_listener, echo_addr, Some(listener_identity), None).await
    });
    wait_ready(&fetch_addr).await.unwrap();

    // Sanity check: a *trusted* client on the same setup does get its bytes
    // echoed back, so the rejection below is specific to the untrusted cert.
    let mut trusted_client = radii_proto::tls::dial(&fetch_addr, Some(&trusted_client_identity))
        .await
        .unwrap();
    trusted_client.write_all(b"trusted!").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        trusted_client.read(&mut buf),
    )
    .await
    .expect("timed out reading trusted client's echo")
    .unwrap();
    assert_eq!(&buf[..n], b"trusted!");

    let round_trip = async {
        let mut stream = radii_proto::tls::dial(&fetch_addr, Some(&outsider_identity)).await?;
        stream.write_all(b"untrusted").await?;
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await?;
        anyhow::Ok(buf[..n].to_vec())
    };
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), round_trip).await;
    let delivered = matches!(outcome, Ok(Ok(bytes)) if bytes == b"untrusted");
    assert!(
        !delivered,
        "expected no application bytes to reach an untrusted client through the tunnel"
    );

    fetch_handle.abort();
    echo_handle.abort();
}
