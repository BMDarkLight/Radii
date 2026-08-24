use radii_crawl::server::{run_on_with_state, CrawlState};
use radii_head::config::GraphConfig;
use radii_head::decision::{DecisionEngine, GraphRoutePolicy};
use radii_head::graph::{self, GraphState};
use radii_head::http::serve_http_on;
use radii_integration::{bind_local, wait_ready};
use radii_proto::{write_message, RadiiMessage};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::net::TcpStream;

/// End-to-end: Crawl learns a reachable node-b via a report, Head polls
/// Crawl's graph, and the decision engine resolves "example.com" to node-b's
/// registered address instead of the static host_map fallback.
#[tokio::test]
async fn head_resolves_backend_from_crawl_graph() {
    let (crawl_listener, crawl_addr) = bind_local().await.unwrap();
    let crawl_state = Arc::new(tokio::sync::RwLock::new(CrawlState::default()));
    let crawl_state_clone = Arc::clone(&crawl_state);
    let crawl_handle =
        tokio::spawn(async move { run_on_with_state(crawl_listener, crawl_state_clone).await });
    wait_ready(&crawl_addr).await.unwrap();

    // node-b registers its address, then a report shows head -> node-b is
    // reachable over http.
    let mut stream = TcpStream::connect(&crawl_addr).await.unwrap();
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "node-b".into(),
            roles: vec!["resource".into()],
            listen_addrs: vec!["10.0.0.5:9000".into()],
        },
    )
    .await
    .unwrap();
    radii_proto::read_message(&mut stream).await.unwrap();

    write_message(
        &mut stream,
        &RadiiMessage::ReachabilityReport {
            from: "head".into(),
            target: "node-b".into(),
            protocol: "http".into(),
            reachable: true,
            rtt_ms: Some(12),
            observed_addr: None,
        },
    )
    .await
    .unwrap();
    radii_proto::read_message(&mut stream).await.unwrap();

    // Head's graph poller pulls that snapshot on an interval.
    let graph_state: graph::SharedGraphState = Arc::new(RwLock::new(GraphState::default()));
    let graph_config = GraphConfig {
        crawl_upstream: crawl_addr.clone(),
        source_node_id: "head".into(),
        poll_interval_ms: 20,
        allowed_protocols: vec!["http".into()],
        max_hops: 4,
        node_map: HashMap::new(),
    };
    let poll_handle = tokio::spawn(graph::run_poll(graph_config, Arc::clone(&graph_state)));

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if !graph_state.read().unwrap().listen_addrs.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("timed out waiting for head to learn the graph");

    let mut node_map = HashMap::new();
    node_map.insert("example.com".to_string(), "node-b".to_string());
    let graph_policy = GraphRoutePolicy::new(
        node_map,
        "head".to_string(),
        vec!["http".to_string()],
        4,
        graph_state,
    );

    let decision = DecisionEngine::from_config_with_graph(
        &radii_head::config::RoutingConfig {
            default_backend: "http://127.0.0.1:9000".into(),
            host_map: HashMap::new(),
        },
        Some(graph_policy),
    );

    let (head_listener, head_addr) = bind_local().await.unwrap();
    let head_handle = tokio::spawn(async move { serve_http_on(head_listener, decision).await });
    wait_ready(&head_addr).await.unwrap();

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{head_addr}/x"))
        .header("Host", "example.com")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    assert_eq!(response["backend"], "10.0.0.5:9000");
    assert_eq!(response["decision_reason"], "graph_route");

    head_handle.abort();
    poll_handle.abort();
    crawl_handle.abort();
}
