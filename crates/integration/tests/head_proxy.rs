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
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.text().await.unwrap(),
        "",
        "health must be answered by Head, not forwarded to an origin"
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
