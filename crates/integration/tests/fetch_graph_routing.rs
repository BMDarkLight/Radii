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

use radii_crawl::server::{run_on_with_state, CrawlState};
use radii_fetch::graph::{self, SharedRoutes};
use radii_fetch::server::run_on_dynamic_with_tls;
use radii_integration::pki::TestCa;
use radii_integration::{bind_local, wait_ready};
use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, ListenAddr, RadiiMessage};
use std::io::Write;
use std::sync::{Arc, RwLock};
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn relay_config(ca: &TestCa, node_id: &str, bind: &str) -> radii_fetch::config::RelayConfig {
    radii_fetch::config::RelayConfig {
        bind: bind.to_string(),
        node_id: node_id.to_string(),
        max_hops: 8,
        max_concurrent_total: 16,
        max_concurrent_per_peer: 4,
        idle_timeout_ms: 30_000,
        handshake_timeout_ms: 10_000,
        max_pending_total: 256,
        max_pending_per_addr: 16,
        allow_peers: Vec::new(),
        tls: Some(ca.issue(node_id)),
    }
}

/// End-to-end: Crawl learns that "fetch -> node-b" is reachable and where
/// node-b listens, Fetch's graph poller picks that up, and a fresh inbound
/// connection tunnels to the graph-resolved address rather than the static
/// fallback upstream.
///
/// The route's target is dialed via `chain::establish` (Task 10), which
/// speaks the relay protocol even for a single-hop route — every node a
/// resolved route can point at is assumed to run a relay listener,
/// terminate-only or not (see `relay.rs`). So node-b here is a real relay
/// terminal node forwarding to a plain echo backend, rather than a bare
/// echo listener as it was before source routing existed.
#[tokio::test]
async fn fetch_tunnels_to_graph_resolved_upstream() {
    let ca = TestCa::new();
    let fetch_identity = TlsIdentity::load(&ca.issue("fetch")).unwrap();

    let (crawl_listener, crawl_addr) = bind_local().await.unwrap();
    let crawl_state = Arc::new(tokio::sync::RwLock::new(CrawlState::default()));
    let crawl_handle =
        tokio::spawn(async move { run_on_with_state(crawl_listener, crawl_state, None).await });
    wait_ready(&crawl_addr).await.unwrap();

    // The real upstream endpoint that echoes back what it receives, reached
    // only once node-b's relay listener has terminated the end-to-end
    // session.
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

    // node-b's relay listener: what its listen_addrs actually advertises.
    let (b_listener, b_addr) = bind_local().await.unwrap();
    let relay_handle = tokio::spawn(radii_fetch::relay::run(
        b_listener,
        radii_fetch::relay::RelayRuntime::new(
            relay_config(&ca, "node-b", &b_addr),
            echo_addr.clone(),
            Some(TlsIdentity::load(&ca.issue("node-b")).unwrap()),
        )
        .unwrap(),
    ));
    wait_ready(&b_addr).await.unwrap();

    let mut stream = TcpStream::connect(&crawl_addr).await.unwrap();
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "node-b".into(),
            roles: vec!["resource".into()],
            listen_addrs: vec![ListenAddr {
                addr: b_addr.clone(),
                role: "relay".into(),
            }],
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

    let routes: SharedRoutes = Arc::new(RwLock::new(Vec::new()));
    let mut config_file = NamedTempFile::new().unwrap();
    writeln!(config_file, "bind = \"0.0.0.0:0\"").unwrap();
    writeln!(config_file, "upstream = \"127.0.0.1:1\"").unwrap();
    writeln!(config_file, "[graph]").unwrap();
    writeln!(config_file, "crawl_upstream = \"{crawl_addr}\"").unwrap();
    writeln!(config_file, "source_node_id = \"fetch\"").unwrap();
    writeln!(config_file, "target_node_id = \"node-b\"").unwrap();
    writeln!(config_file, "poll_interval_ms = 20").unwrap();
    writeln!(config_file, "allowed_protocols = [\"ssh\"]").unwrap();
    writeln!(config_file, "max_hops = 4").unwrap();
    let graph_config = radii_fetch::config::load(config_file.path())
        .unwrap()
        .graph
        .expect("graph config present");
    let poll_handle = tokio::spawn(graph::run_poll(graph_config, Arc::clone(&routes), None));

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if !routes.read().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("timed out waiting for fetch to learn the graph target");
    {
        let guard = routes.read().unwrap();
        let resolved = guard.first().expect("graph route resolved");
        let last = resolved.hops.last().expect("non-empty hops");
        assert_eq!(last.addr, b_addr);
        assert_eq!(last.node_id.0, "node-b");
    }

    let (fetch_listener, fetch_addr) = bind_local().await.unwrap();
    let fetch_handle = tokio::spawn(async move {
        run_on_dynamic_with_tls(
            fetch_listener,
            "127.0.0.1:1".to_string(),
            routes,
            3000,
            None,
            Some(fetch_identity),
        )
        .await
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
    relay_handle.abort();
    echo_handle.abort();
    crawl_handle.abort();
}
