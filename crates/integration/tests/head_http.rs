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
