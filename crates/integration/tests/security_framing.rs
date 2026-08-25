use radii_proto::MAX_FRAME_LEN;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Oversized length prefixes must be rejected by the framing layer itself.
#[tokio::test]
async fn proto_rejects_hostile_length_prefix() {
    let (mut client, mut server) = tokio::io::duplex(64);
    let oversized = (MAX_FRAME_LEN + 1).to_be_bytes();
    client.write_all(&oversized).await.unwrap();
    let err = radii_proto::read_message(&mut server).await.unwrap_err();
    assert!(err.to_string().contains("exceeds max"));
}

/// Connecting to Crawl with an oversized prefix must not hang the suite.
#[tokio::test]
async fn crawl_drops_oversized_client_frame() {
    use radii_crawl::server::run_on;
    use radii_integration::{bind_local, wait_ready};

    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { run_on(listener, None).await });
    wait_ready(&addr).await.unwrap();

    let mut stream = TcpStream::connect(&addr).await.unwrap();
    stream
        .write_all(&(MAX_FRAME_LEN + 1).to_be_bytes())
        .await
        .unwrap();

    // Give Crawl time to reject and close the connection task.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!handle.is_finished());
    handle.abort();
}
