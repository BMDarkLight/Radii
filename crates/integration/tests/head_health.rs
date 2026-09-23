// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 BMDarkLight
//
// This file is part of Radii.
//
// Radii is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for the full text and
// additional terms.

//! `/health` must reflect whether Head can actually do its job.
//!
//! The protocol registry already takes the process down when a runner
//! *fails*. The gap is a runner that is merely *degraded*: the graph poller
//! logs a warning and retries on every failed query, so a Head cut off from
//! Crawl keeps routing from a snapshot that gets older every interval while
//! answering 200. A load balancer has no way to see that, which is exactly
//! the case a health check exists for.

use radii_head::decision::DecisionEngine;
use radii_head::graph::{GraphState, SharedGraphState};
use radii_head::http::{self, HealthWatch};
use radii_integration::{bind_local, wait_ready};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

fn engine() -> DecisionEngine {
    DecisionEngine::from_config(&radii_head::config::RoutingConfig {
        default_backend: "http://127.0.0.1:9000".into(),
        host_map: Default::default(),
    })
}

async fn serve(health: HealthWatch) -> String {
    let (listener, addr) = bind_local().await.unwrap();
    let state = http::state_with(
        engine(),
        Duration::from_millis(3000),
        Duration::from_millis(30_000),
        None,
    )
    .with_health(health);
    tokio::spawn(async move { http::serve_http_on_with(listener, state).await });
    wait_ready(&addr).await.unwrap();
    format!("http://{addr}")
}

async fn health_status(base: &str) -> (u16, serde_json::Value) {
    let response = reqwest::Client::new()
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap())
}

/// No `[graph]` configured: there is no freshness to report on, and Head is
/// serving exactly what it was asked to serve.
#[tokio::test]
async fn health_is_ok_when_no_graph_is_configured() {
    let base = serve(HealthWatch::none()).await;
    let (status, body) = health_status(&base).await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["graph"], "not_configured");
}

#[tokio::test]
async fn health_is_ok_when_the_graph_poll_is_fresh() {
    let state: SharedGraphState = Arc::new(RwLock::new(GraphState::default()));
    state.write().unwrap().last_refresh = Some(Instant::now());

    let base = serve(HealthWatch::graph(state, Duration::from_secs(30))).await;
    let (status, body) = health_status(&base).await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["graph"], "fresh");
}

/// The case the old unconditional 200 hid: Crawl is unreachable, the poller
/// is logging a warning every interval, and Head is routing from a snapshot
/// that is only getting older.
#[tokio::test]
async fn health_is_degraded_when_the_graph_poll_has_gone_stale() {
    let state: SharedGraphState = Arc::new(RwLock::new(GraphState::default()));
    state.write().unwrap().last_refresh = Some(Instant::now() - Duration::from_secs(120));

    let base = serve(HealthWatch::graph(state, Duration::from_secs(30))).await;
    let (status, body) = health_status(&base).await;
    assert_eq!(status, 503, "a stale graph must not report healthy: {body}");
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["graph"], "stale");
}

/// Before the first successful poll Head has no routes at all. That is
/// startup, not steady state, but it is still not ready to serve.
#[tokio::test]
async fn health_is_degraded_before_the_first_successful_poll() {
    let state: SharedGraphState = Arc::new(RwLock::new(GraphState::default()));

    let base = serve(HealthWatch::graph(state, Duration::from_secs(30))).await;
    let (status, body) = health_status(&base).await;
    assert_eq!(status, 503);
    assert_eq!(body["graph"], "never_refreshed");
}
