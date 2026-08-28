use radii_crawl::server::{run_on_with_state, CrawlState};
use radii_integration::{bind_local, wait_ready};
use radii_proto::{read_message, write_message, RadiiMessage};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

#[tokio::test]
async fn hello_probe_and_report_are_acked_and_stored() {
    let (listener, addr) = bind_local().await.unwrap();
    let state = Arc::new(RwLock::new(CrawlState::default()));
    let state_clone = Arc::clone(&state);
    let handle = tokio::spawn(async move { run_on_with_state(listener, state_clone, None).await });

    wait_ready(&addr).await.unwrap();

    let mut stream = TcpStream::connect(&addr).await.unwrap();
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "node-a".into(),
            roles: vec!["crawl".into()],
            listen_addrs: vec!["127.0.0.1:1".into()],
        },
    )
    .await
    .unwrap();
    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "hello_received"),
        other => panic!("unexpected: {other:?}"),
    }

    write_message(
        &mut stream,
        &RadiiMessage::ReachabilityProbe {
            from: "node-a".into(),
            to: "node-b".into(),
            sent_at_unix_ms: 1,
        },
    )
    .await
    .unwrap();
    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "probe_received"),
        other => panic!("unexpected: {other:?}"),
    }

    write_message(
        &mut stream,
        &RadiiMessage::ReachabilityReport {
            from: "node-a".into(),
            target: "node-b".into(),
            protocol: "radii".into(),
            reachable: true,
            rtt_ms: Some(33),
            observed_addr: None,
        },
    )
    .await
    .unwrap();
    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "report_received"),
        other => panic!("unexpected: {other:?}"),
    }

    {
        let guard = state.read().await;
        assert_eq!(
            guard.nodes.get("node-a").unwrap().listen_addrs,
            vec!["127.0.0.1:1".to_string()]
        );
        assert_eq!(guard.reachability.len(), 1);
    }

    handle.abort();
}

#[tokio::test]
async fn from_head_wrapper_is_ingested() {
    let (listener, addr) = bind_local().await.unwrap();
    let state = Arc::new(RwLock::new(CrawlState::default()));
    let state_clone = Arc::clone(&state);
    let handle = tokio::spawn(async move { run_on_with_state(listener, state_clone, None).await });
    wait_ready(&addr).await.unwrap();

    let mut stream = TcpStream::connect(&addr).await.unwrap();
    write_message(
        &mut stream,
        &RadiiMessage::FromHead {
            source: "127.0.0.1:9".into(),
            message: Box::new(RadiiMessage::NodeHello {
                node_id: "via-head".into(),
                roles: vec!["resource".into()],
                listen_addrs: vec![],
            }),
        },
    )
    .await
    .unwrap();
    match read_message(&mut stream).await.unwrap() {
        RadiiMessage::Ack { status } => assert_eq!(status, "head_message_received"),
        other => panic!("unexpected: {other:?}"),
    }

    assert!(state.read().await.nodes.contains_key("via-head"));
    handle.abort();
}
