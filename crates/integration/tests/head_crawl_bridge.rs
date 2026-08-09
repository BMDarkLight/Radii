use radii_crawl::server::{run_on_with_state, CrawlState};
use radii_head::radii::run_radii_on;
use radii_integration::{bind_local, wait_ready};
use radii_proto::{read_message, write_message, RadiiMessage};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

#[tokio::test]
async fn head_radii_bridge_forwards_to_crawl() {
    let (crawl_listener, crawl_addr) = bind_local().await.unwrap();
    let state = Arc::new(RwLock::new(CrawlState::default()));
    let state_clone = Arc::clone(&state);
    let crawl_handle =
        tokio::spawn(async move { run_on_with_state(crawl_listener, state_clone).await });
    wait_ready(&crawl_addr).await.unwrap();

    let (head_listener, head_addr) = bind_local().await.unwrap();
    let crawl_upstream = crawl_addr.clone();
    let head_handle =
        tokio::spawn(async move { run_radii_on(head_listener, crawl_upstream).await });
    wait_ready(&head_addr).await.unwrap();

    let mut stream = TcpStream::connect(&head_addr).await.unwrap();
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "bridged".into(),
            roles: vec!["access".into()],
            listen_addrs: vec![],
        },
    )
    .await
    .unwrap();

    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "head_message_received"),
        other => panic!("unexpected: {other:?}"),
    }

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(state.read().await.nodes.contains_key("bridged"));

    head_handle.abort();
    crawl_handle.abort();
}
