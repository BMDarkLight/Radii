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

//! The acceptance test for role-tagged addresses.
//!
//! One node advertises two differently-tagged listeners in a single
//! `NodeHello`, and a consumer asking for one role must get that role's
//! address and never the other's. Before roles, both read the same entry and
//! one of them was always wrong.
//!
//! The roles here are fixtures for the mechanism, not a picture of a
//! deployment: in production both Fetch and Head resolve `relay`, and
//! nothing resolves `http`. This test uses the two tags precisely because
//! they must not be confusable.

use radii_core::routing::{resolve_candidates, GraphSnapshot, Link, NodeId, ProtocolId, RoleId};
use radii_integration::{bind_local, wait_ready};
use radii_proto::{ListenAddr, RadiiMessage};
use std::collections::HashMap;

#[tokio::test]
async fn one_node_serves_both_consumers_from_one_hello() {
    let (crawl_listener, crawl_addr) = bind_local().await.unwrap();
    tokio::spawn(radii_crawl::server::run_on(
        crawl_listener,
        None,
        Some(60_000),
        Default::default(),
    ));
    wait_ready(&crawl_addr).await.unwrap();

    // One hello, two roles.
    let mut stream = radii_proto::tls::dial(&crawl_addr, None).await.unwrap();
    let ack = radii_proto::send_hello_on(
        &mut stream,
        "node-b".to_string(),
        vec!["resource".to_string()],
        vec![
            ListenAddr {
                addr: "10.0.0.5:2224".into(),
                role: "relay".into(),
            },
            ListenAddr {
                addr: "10.0.0.5:9000".into(),
                role: "http".into(),
            },
        ],
    )
    .await
    .unwrap();
    assert!(matches!(ack, RadiiMessage::Ack { .. }));

    let mut query = radii_proto::tls::dial(&crawl_addr, None).await.unwrap();
    let (nodes, _reports) = radii_proto::query_graph_on(&mut query).await.unwrap();

    let listen_addrs: HashMap<String, Vec<(String, String)>> = nodes
        .into_iter()
        .map(|node| {
            (
                node.node_id,
                node.listen_addrs
                    .into_iter()
                    .map(|entry| (entry.addr, entry.role))
                    .collect(),
            )
        })
        .collect();

    let mut snapshot = GraphSnapshot::new();
    snapshot.add_link(Link {
        from: NodeId("s".into()),
        to: NodeId("node-b".into()),
        protocol: ProtocolId::new("radii"),
        reachable: true,
        latency_ms: Some(10),
    });

    // Asking for `relay` on every hop, as Fetch and Head both do.
    let fetch = resolve_candidates(
        &snapshot,
        &listen_addrs,
        &NodeId("s".into()),
        &[NodeId("node-b".into())],
        &[ProtocolId::new("radii")],
        4,
        3,
        Some(&RoleId::new(RoleId::RELAY)),
        &RoleId::new(RoleId::RELAY),
    );
    assert_eq!(fetch.len(), 1);
    assert_eq!(fetch[0].hops.last().unwrap().addr, "10.0.0.5:2224");

    // Asking for a different role on the target, and skipping intermediates
    // (`hop_role: None`), must select that role's address instead. Note what
    // `None` costs: the path collapses to its target, so this shape is only
    // correct for a caller that does not dial the intermediates it planned
    // through.
    let head = resolve_candidates(
        &snapshot,
        &listen_addrs,
        &NodeId("s".into()),
        &[NodeId("node-b".into())],
        &[ProtocolId::new("radii")],
        4,
        3,
        None,
        &RoleId::new(RoleId::HTTP),
    );
    assert_eq!(head.len(), 1);
    assert_eq!(head[0].hops.last().unwrap().addr, "10.0.0.5:9000");
}
