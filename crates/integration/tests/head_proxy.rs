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

//! Head as a reverse proxy.
//!
//! Before this, Head answered every request with a JSON document describing
//! the backend it *would* pick, so none of the source-routing work — ranked
//! candidates, path diversity, failover — reached HTTP traffic at all.

use radii_head::decision::DecisionEngine;
use radii_head::http::serve_http_on;
use radii_integration::bind_local;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn routing(
    default_backend: &str,
    host_map: HashMap<String, String>,
) -> radii_head::config::RoutingConfig {
    radii_head::config::RoutingConfig {
        default_backend: default_backend.to_string(),
        host_map,
    }
}

/// A minimal origin that always answers with `body`.
async fn run_origin(listener: TcpListener, body: &'static str) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let _ = stream.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

/// An origin that answers with the request head it received, so a test can
/// assert on exactly which headers Head forwarded.
///
/// The request head goes in the BODY rather than a header: header values
/// reject control characters, and the point here is to inspect raw request
/// bytes including ones that would be rejected.
async fn run_echo_origin(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let seen = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                seen.len(),
                seen
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

#[tokio::test]
async fn proxies_a_request_to_a_static_backend_and_returns_the_body() {
    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_origin(origin_listener, "hello from origin"));

    let mut host_map = HashMap::new();
    host_map.insert("example.com".to_string(), origin_addr.clone());
    let decision = DecisionEngine::from_config(&routing(&origin_addr, host_map));

    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let body = reqwest::Client::new()
        .get(format!("http://{addr}/some/path"))
        .header("Host", "example.com")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(body, "hello from origin");
    handle.abort();
}

#[tokio::test]
async fn health_is_answered_locally_and_not_proxied() {
    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_origin(origin_listener, "origin"));

    let decision = DecisionEngine::from_config(&routing(&origin_addr, HashMap::new()));
    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let response = reqwest::get(format!("http://{addr}/health")).await.unwrap();
    // 200 because this Head has no `[graph]` to be stale about; the body is
    // Head's own health document, never the origin's response.
    assert_eq!(response.status(), 200);
    let body = response.text().await.unwrap();
    assert!(
        !body.contains("origin"),
        "health must be answered by Head, not forwarded to an origin; got: {body}"
    );
    assert!(
        body.contains("\"status\":\"ok\""),
        "health must report Head's own status; got: {body}"
    );
    handle.abort();
}

#[tokio::test]
async fn forwards_host_and_strips_hop_by_hop_headers() {
    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo_origin(origin_listener));

    let mut host_map = HashMap::new();
    host_map.insert("example.com".to_string(), origin_addr.clone());
    let decision = DecisionEngine::from_config(&routing(&origin_addr, host_map));

    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let seen = reqwest::Client::new()
        .get(format!("http://{addr}/"))
        .header("Host", "example.com")
        .header("X-Custom-Hop", "secret")
        // Naming a header in `Connection` makes it hop-by-hop for this
        // message. Forwarding it is request-smuggling surface, and it is the
        // part proxies most often get wrong.
        .header("Connection", "X-Custom-Hop")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert!(
        seen.contains("host: example.com"),
        "Host must reach the origin so it can serve the right vhost: {seen}"
    );
    assert!(
        !seen.contains("x-custom-hop"),
        "a Connection-named header must not be forwarded: {seen}"
    );
    assert!(
        !seen.contains("connection:"),
        "Connection itself must not be forwarded: {seen}"
    );
    assert!(
        seen.contains("x-forwarded-for"),
        "the immediate peer should be recorded: {seen}"
    );
    handle.abort();
}

#[tokio::test]
async fn appends_to_an_existing_forwarded_for_rather_than_replacing_it() {
    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_echo_origin(origin_listener));

    let mut host_map = HashMap::new();
    host_map.insert("example.com".to_string(), origin_addr.clone());
    let decision = DecisionEngine::from_config(&routing(&origin_addr, host_map));

    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let seen = reqwest::Client::new()
        .get(format!("http://{addr}/"))
        .header("Host", "example.com")
        .header("X-Forwarded-For", "203.0.113.7")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    // Appended, not replaced — though note the inbound value is recorded,
    // never believed: any client can send one.
    assert!(
        seen.contains("203.0.113.7, 127.0.0.1"),
        "an existing X-Forwarded-For should be appended to: {seen}"
    );
    handle.abort();
}

#[tokio::test]
async fn a_backend_that_cannot_be_reached_is_a_502() {
    // Nothing listens on port 1.
    let decision = DecisionEngine::from_config(&routing("127.0.0.1:1", HashMap::new()));
    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
    assert_eq!(response.status(), 502);
    handle.abort();
}

#[tokio::test]
async fn the_decision_json_moved_to_its_own_path() {
    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_origin(origin_listener, "origin body"));

    let decision = DecisionEngine::from_config(&routing(&origin_addr, HashMap::new()));
    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let json: serde_json::Value = reqwest::get(format!("http://{addr}/_radii/decision"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        json.get("backend").is_some(),
        "the decision endpoint should still report a backend"
    );

    // Every other path proxies now, so the backend map is no longer
    // disclosed on arbitrary paths — one route to firewall instead of all.
    let other = reqwest::get(format!("http://{addr}/anything"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(other, "origin body");
    handle.abort();
}

/// A response larger than any internal buffer must arrive intact, which is
/// what proves the body is streamed rather than collected.
#[tokio::test]
async fn streams_a_response_larger_than_a_buffer() {
    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = origin_listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _ = stream.read(&mut buf).await;
                let body = "x".repeat(512 * 1024);
                let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
            });
        }
    });

    let decision = DecisionEngine::from_config(&routing(&origin_addr, HashMap::new()));
    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let body = reqwest::get(format!("http://{addr}/big"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(body.len(), 512 * 1024, "the whole body must arrive intact");
    handle.abort();
}

/// The feature, end to end: a client makes an ordinary HTTP request, the
/// response comes from an origin reached over a source-routed relay chain,
/// and when the first candidate's node is dead the client still gets the
/// response from the second — never observing the failure.
///
/// This is the test the whole reverse-proxy design exists for. Before it,
/// Head returned JSON and none of the source-routing work reached HTTP.
#[tokio::test]
async fn fails_over_to_a_second_node_without_the_client_noticing() {
    use radii_core::routing::{GraphSnapshot, Link, NodeId, ProtocolId};
    use radii_head::decision::GraphRoutePolicy;
    use radii_head::graph::{GraphState, SharedGraphState};
    use radii_integration::pki::TestCa;
    use radii_proto::tls::TlsIdentity;
    use std::sync::{Arc, RwLock};

    let ca = TestCa::new();
    let head_identity = TlsIdentity::load(&ca.issue("head")).unwrap();

    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_origin(origin_listener, "served by node-c"));

    // Only node-c is actually running.
    let (relay_listener, relay_addr) = bind_local().await.unwrap();
    let runtime = radii_fetch::relay::RelayRuntime::new(
        radii_fetch::config::RelayConfig {
            bind: relay_addr.clone(),
            node_id: "node-c".to_string(),
            max_hops: 8,
            max_concurrent_total: 16,
            max_concurrent_per_peer: 8,
            idle_timeout_ms: 30_000,
            handshake_timeout_ms: 10_000,
            max_pending_total: 256,
            max_pending_per_addr: 64,
            allow_peers: Vec::new(),
            tls: Some(ca.issue("node-c")),
        },
        origin_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-c")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(relay_listener, runtime));

    let mut snapshot = GraphSnapshot::new();
    for to in ["node-b", "node-c"] {
        snapshot.add_link(Link {
            from: NodeId("head".into()),
            to: NodeId(to.into()),
            protocol: ProtocolId::new("http"),
            reachable: true,
            // node-b looks cheaper so it is tried first — and it is dead.
            latency_ms: Some(if to == "node-b" { 10 } else { 200 }),
        });
    }
    let mut listen_addrs: HashMap<String, Vec<(String, String)>> = HashMap::new();
    listen_addrs.insert(
        "node-b".into(),
        vec![("127.0.0.1:1".into(), "relay".into())],
    );
    listen_addrs.insert("node-c".into(), vec![(relay_addr.clone(), "relay".into())]);
    let state: SharedGraphState = Arc::new(RwLock::new(GraphState {
        snapshot,
        listen_addrs,
        ..GraphState::default()
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
    let decision = DecisionEngine::new().with_policy(policy);

    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move {
        radii_head::http::serve_http_on_with(
            listener,
            radii_head::http::state_with(
                decision,
                std::time::Duration::from_millis(3000),
                std::time::Duration::from_millis(30_000),
                Some(head_identity),
            ),
        )
        .await
    });

    let body = reqwest::Client::new()
        .get(format!("http://{addr}/"))
        .header("Host", "site.example")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(
        body, "served by node-c",
        "the client must get the live node's response without ever seeing the dead one"
    );
    handle.abort();
}

/// The backend spelling every shipped config uses.
///
/// `head.example.toml` writes `routing.default_backend` and every
/// `routing.host_map` value as `http://HOST:PORT`, and Head hands the decided
/// address to `TcpStream::connect`. `normalize_upstream` stripped `ssh://`
/// and `tcp://` but not `http://`, so name resolution failed and every
/// request to a statically configured backend answered 502 — on the example
/// config, out of the box. The existing proxy tests all pass a bare
/// `host:port` from `bind_local`, so none of them could see it.
#[tokio::test]
async fn proxies_to_a_static_backend_written_with_an_http_scheme() {
    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_origin(origin_listener, "hello from origin"));

    let with_scheme = format!("http://{origin_addr}");
    let mut host_map = HashMap::new();
    host_map.insert("example.com".to_string(), with_scheme.clone());
    // Both the host_map hit and the default carry the scheme, since both
    // reach the same dial.
    let decision = DecisionEngine::from_config(&routing(&with_scheme, host_map));

    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move { serve_http_on(listener, decision).await });

    let mapped = reqwest::Client::new()
        .get(format!("http://{addr}/some/path"))
        .header("Host", "example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(mapped.status(), 200, "host_map backend must be reachable");
    assert_eq!(mapped.text().await.unwrap(), "hello from origin");

    let defaulted = reqwest::Client::new()
        .get(format!("http://{addr}/some/path"))
        .header("Host", "unmapped.example")
        .send()
        .await
        .unwrap();
    assert_eq!(defaulted.status(), 200, "default backend must be reachable");
    assert_eq!(defaulted.text().await.unwrap(), "hello from origin");

    handle.abort();
}

/// Head reaches a backend that is only reachable *through* another node.
///
/// `head → node-r → node-b`, with no direct `head → node-b` link in the
/// graph. Head must open a two-hop chain: dial node-r, hand it the tail, and
/// speak end-to-end with node-b through it.
///
/// node-b's relay sets `allow_peers = ["node-r"]`, which is what makes the
/// regression visible rather than merely theoretical. Every listener in a
/// test lives on 127.0.0.1, so a collapsed one-hop chain straight to node-b
/// would *connect* — and would have passed a test that only asserted on the
/// body. With the allow-list, node-b admits a chain handed to it by node-r
/// and refuses one dialed by head, so the two behaviours give different
/// answers: 200 for the real chain, 502 for the collapse.
///
/// Before this, `plan_backends` passed `hop_role: None`, which dropped
/// node-r from the resolved route instead of resolving it. Head planned
/// through node-r and then dialed node-b directly, at an address the graph
/// never said it could reach. Multi-hop routing silently did not happen.
#[tokio::test]
async fn reaches_a_backend_only_through_an_intermediate_relay() {
    use radii_core::routing::{GraphSnapshot, Link, NodeId, ProtocolId};
    use radii_head::decision::GraphRoutePolicy;
    use radii_head::graph::{GraphState, SharedGraphState};
    use radii_integration::pki::TestCa;
    use radii_proto::tls::TlsIdentity;
    use std::sync::{Arc, RwLock};

    fn relay_config(
        ca: &TestCa,
        node_id: &str,
        bind: &str,
        allow_peers: Vec<String>,
    ) -> radii_fetch::config::RelayConfig {
        radii_fetch::config::RelayConfig {
            bind: bind.to_string(),
            node_id: node_id.to_string(),
            max_hops: 8,
            max_concurrent_total: 16,
            max_concurrent_per_peer: 8,
            idle_timeout_ms: 30_000,
            handshake_timeout_ms: 10_000,
            max_pending_total: 256,
            max_pending_per_addr: 64,
            allow_peers,
            tls: Some(ca.issue(node_id)),
        }
    }

    let ca = TestCa::new();
    let head_identity = TlsIdentity::load(&ca.issue("head")).unwrap();

    let (origin_listener, origin_addr) = bind_local().await.unwrap();
    tokio::spawn(run_origin(origin_listener, "served through node-r"));

    // The terminal, which only accepts chains handed to it by node-r.
    let (b_listener, b_addr) = bind_local().await.unwrap();
    let b_runtime = radii_fetch::relay::RelayRuntime::new(
        relay_config(&ca, "node-b", &b_addr, vec!["node-r".to_string()]),
        origin_addr.clone(),
        Some(TlsIdentity::load(&ca.issue("node-b")).unwrap()),
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(b_listener, b_runtime));

    // The intermediate. Forwards only, so its own upstream is never used.
    let (r_listener, r_addr) = bind_local().await.unwrap();
    let r_runtime = radii_fetch::relay::RelayRuntime::new(
        relay_config(&ca, "node-r", &r_addr, Vec::new()),
        "127.0.0.1:1".to_string(),
        None,
    )
    .unwrap();
    tokio::spawn(radii_fetch::relay::run(r_listener, r_runtime));

    // head -> node-r -> node-b. Deliberately no direct head -> node-b link.
    let mut snapshot = GraphSnapshot::new();
    for (from, to) in [("head", "node-r"), ("node-r", "node-b")] {
        snapshot.add_link(Link {
            from: NodeId(from.into()),
            to: NodeId(to.into()),
            protocol: ProtocolId::new("http"),
            reachable: true,
            latency_ms: Some(10),
        });
    }
    let mut listen_addrs: HashMap<String, Vec<(String, String)>> = HashMap::new();
    listen_addrs.insert("node-r".into(), vec![(r_addr.clone(), "relay".into())]);
    listen_addrs.insert("node-b".into(), vec![(b_addr.clone(), "relay".into())]);
    let state: SharedGraphState = Arc::new(RwLock::new(GraphState {
        snapshot,
        listen_addrs,
        ..GraphState::default()
    }));

    let mut node_map = HashMap::new();
    node_map.insert("site.example".to_string(), vec!["node-b".to_string()]);
    let policy = GraphRoutePolicy::new(
        node_map,
        "head".to_string(),
        vec!["http".to_string()],
        4,
        3,
        state,
    );
    // No host_map and no default: a fallback would mask a collapsed chain
    // behind some other backend's response. The graph route is the only way
    // this request can be served.
    let decision = DecisionEngine::new().with_policy(policy);

    let (listener, addr) = bind_local().await.unwrap();
    let handle = tokio::spawn(async move {
        radii_head::http::serve_http_on_with(
            listener,
            radii_head::http::state_with(
                decision,
                std::time::Duration::from_millis(3000),
                std::time::Duration::from_millis(30_000),
                Some(head_identity),
            ),
        )
        .await
    });

    let response = reqwest::Client::new()
        .get(format!("http://{addr}/"))
        .header("Host", "site.example")
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        200,
        "Head must open a two-hop chain through node-r; a collapsed one-hop \
         chain is refused by node-b and surfaces as 502"
    );
    assert_eq!(response.text().await.unwrap(), "served through node-r");
    handle.abort();
}
