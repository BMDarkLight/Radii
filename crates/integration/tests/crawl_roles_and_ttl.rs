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
use radii_integration::{bind_local, wait_ready};
use radii_proto::{query_graph, read_message, write_message, ListenAddr, RadiiMessage};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

#[tokio::test]
async fn graph_query_reflects_declared_roles() {
    let (listener, addr) = bind_local().await.unwrap();
    let state = Arc::new(RwLock::new(CrawlState::default()));
    let handle = tokio::spawn(async move { run_on_with_state(listener, state, None).await });
    wait_ready(&addr).await.unwrap();

    let mut stream = TcpStream::connect(&addr).await.unwrap();
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "wave-a".into(),
            roles: vec!["wave".into()],
            listen_addrs: vec![ListenAddr {
                addr: "127.0.0.1:9500".into(),
                role: "relay".into(),
            }],
        },
    )
    .await
    .unwrap();
    read_message(&mut stream).await.unwrap();

    let (nodes, _reports) = query_graph(&addr).await.unwrap();
    let node = nodes
        .iter()
        .find(|n| n.node_id == "wave-a")
        .expect("node present in graph query reply");
    assert_eq!(node.roles, vec!["wave".to_string()]);

    handle.abort();
}

#[tokio::test]
async fn graph_query_drops_nodes_past_their_ttl() {
    let (listener, addr) = bind_local().await.unwrap();
    let state = Arc::new(RwLock::new(CrawlState {
        node_ttl_ms: Some(50),
        ..CrawlState::default()
    }));
    let handle = tokio::spawn(async move { run_on_with_state(listener, state, None).await });
    wait_ready(&addr).await.unwrap();

    let mut stream = TcpStream::connect(&addr).await.unwrap();
    write_message(
        &mut stream,
        &RadiiMessage::NodeHello {
            node_id: "wave-a".into(),
            roles: vec!["wave".into()],
            listen_addrs: vec![ListenAddr {
                addr: "127.0.0.1:9500".into(),
                role: "relay".into(),
            }],
        },
    )
    .await
    .unwrap();
    read_message(&mut stream).await.unwrap();

    tokio::time::sleep(Duration::from_millis(150)).await;

    let (nodes, _reports) = query_graph(&addr).await.unwrap();
    assert!(
        nodes.iter().all(|n| n.node_id != "wave-a"),
        "node past its TTL must not appear in the graph query reply"
    );

    handle.abort();
}
