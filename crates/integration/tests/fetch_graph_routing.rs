use radii_crawl::server::{run_on_with_state, CrawlState};
use radii_fetch::config::GraphConfig;
use radii_fetch::graph::{self, SharedTarget};
use radii_fetch::server::run_on_dynamic;
use radii_integration::{bind_local, wait_ready};
use radii_proto::{read_message, write_message, RadiiMessage};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// End-to-end: Crawl learns that "fetch -> node-b" is reachable and where
/// node-b listens, Fetch's graph poller picks that up, and a fresh inbound
/// connection tunnels to the graph-resolved address rather than the static
/// fallback upstream.
#[tokio::test]
async fn fetch_tunnels_to_graph_resolved_upstream() {
    let (crawl_listener, crawl_addr) = bind_local().await.unwrap();
    let crawl_state = Arc::new(tokio::sync::RwLock::new(CrawlState::default()));
    let crawl_handle =
        tokio::spawn(async move { run_on_with_state(crawl_listener, crawl_state).await });
    wait_ready(&crawl_addr).await.unwrap();

    // A real upstream endpoint that echoes back what it receives; this is
    // what node-b's listen_addrs will point to.
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

    let mut stream = TcpStream::connect(&crawl_addr).await.unwrap();
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "node-b".into(),
            roles: vec!["resource".into()],
            listen_addrs: vec![echo_addr.clone()],
        },
    )
    .await
    .unwrap();
    read_message(&mut stream).await.unwrap();

    write_message(
        &mut stream,
        &RadiiMessage::ReachabilityReport {
            from: "fetch".into(),
            target: "node-b".into(),
            protocol: "ssh".into(),
            reachable: true,
            rtt_ms: Some(9),
            observed_addr: None,
        },
    )
    .await
    .unwrap();
    read_message(&mut stream).await.unwrap();

    let target: SharedTarget = Arc::new(RwLock::new(None));
    let graph_config = GraphConfig {
        crawl_upstream: crawl_addr.clone(),
        source_node_id: "fetch".into(),
        target_node_id: "node-b".into(),
        poll_interval_ms: 20,
        allowed_protocols: vec!["ssh".into()],
        max_hops: 4,
    };
    let poll_handle = tokio::spawn(graph::run_poll(graph_config, Arc::clone(&target)));

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if target.read().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("timed out waiting for fetch to learn the graph target");
    assert_eq!(target.read().unwrap().as_deref(), Some(echo_addr.as_str()));

    let (fetch_listener, fetch_addr) = bind_local().await.unwrap();
    let fetch_handle = tokio::spawn(async move {
        run_on_dynamic(fetch_listener, "127.0.0.1:1".to_string(), target).await
    });
    wait_ready(&fetch_addr).await.unwrap();

    let mut client = TcpStream::connect(&fetch_addr).await.unwrap();
    client.write_all(b"ping-graph").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf))
        .await
        .expect("timed out reading tunnel echo")
        .unwrap();
    assert_eq!(&buf[..n], b"ping-graph");

    fetch_handle.abort();
    poll_handle.abort();
    echo_handle.abort();
    crawl_handle.abort();
}
