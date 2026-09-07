use radii_head::decision::DecisionEngine;
use radii_head::http::serve_http_on;
use radii_integration::{bind_local, wait_ready};
use std::collections::HashMap;

#[tokio::test]
async fn health_and_host_map_decision() {
    let (listener, addr) = bind_local().await.unwrap();
    let mut host_map = HashMap::new();
    host_map.insert("example.com".into(), "http://10.0.0.10:9000".into());
    let decision = DecisionEngine::from_config(&radii_head::config::RoutingConfig {
        default_backend: "http://127.0.0.1:9000".into(),
        host_map,
    });

    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });
    wait_ready(&addr).await.unwrap();

    let base = format!("http://{addr}");
    let client = reqwest::Client::new();

    let health = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(health.status(), 200);

    let matched = client
        .get(format!("{base}/x"))
        .header("Host", "example.com")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(matched["backend"], "http://10.0.0.10:9000");
    assert_eq!(matched["decision_reason"], "host_map");

    let fallback = client
        .get(format!("{base}/y"))
        .header("Host", "other.local")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(fallback["backend"], "http://127.0.0.1:9000");
    assert_eq!(fallback["decision_reason"], "default");

    handle.abort();
}

/// Head reports every reachable backend for a host, best first, so a caller
/// that dials them can fail over. Head does not proxy, so it cannot fail
/// over itself — the list is the seam that lets its caller.
#[tokio::test]
async fn head_reports_ranked_candidates() {
    use radii_core::routing::{GraphSnapshot, Link, NodeId, ProtocolId};
    use radii_head::decision::GraphRoutePolicy;
    use radii_head::graph::{GraphState, SharedGraphState};
    use std::sync::{Arc, RwLock};

    // node-c is cheaper than node-b, so it must rank first regardless of the
    // order the host maps them in.
    let mut snapshot = GraphSnapshot::new();
    for (to, rtt) in [("node-b", 200u32), ("node-c", 20)] {
        snapshot.add_link(Link {
            from: NodeId("head".into()),
            to: NodeId(to.into()),
            protocol: ProtocolId::new("http"),
            reachable: true,
            latency_ms: Some(rtt),
        });
    }
    let mut listen_addrs = HashMap::new();
    listen_addrs.insert(
        "node-b".to_string(),
        vec![("10.0.0.11:9000".to_string(), "http".to_string())],
    );
    listen_addrs.insert(
        "node-c".to_string(),
        vec![("10.0.0.12:9000".to_string(), "http".to_string())],
    );
    let state: SharedGraphState = Arc::new(RwLock::new(GraphState {
        snapshot,
        listen_addrs,
    }));

    let mut node_map = HashMap::new();
    node_map.insert(
        "site.example".to_string(),
        vec!["node-b".to_string(), "node-c".to_string()],
    );
    let policy = GraphRoutePolicy::new(
        node_map,
        "head".to_string(),
        vec!["http".to_string()],
        4,
        3,
        state,
    );
    let decision = DecisionEngine::from_config_with_graph(
        &radii_head::config::RoutingConfig {
            default_backend: "http://127.0.0.1:9000".into(),
            host_map: HashMap::new(),
        },
        Some(policy),
    );

    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });
    wait_ready(&addr).await.unwrap();

    let response = reqwest::Client::new()
        .get(format!("http://{addr}/x"))
        .header("Host", "site.example")
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();

    let candidates = response["candidates"].as_array().expect("candidates array");
    assert_eq!(candidates.len(), 2, "both mapped nodes should be reachable");
    assert_eq!(
        candidates[0], "10.0.0.12:9000",
        "the cheaper node must rank first"
    );
    assert_eq!(
        response["backend"], candidates[0],
        "backend must be the top candidate"
    );
    assert_eq!(response["decision_reason"], "graph_route");

    handle.abort();
}
