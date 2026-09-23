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

//! A `GraphQuery` must always be answerable.
//!
//! Crawl's entry caps bound how MANY observations it holds, and the wire
//! bounds now cap how large each one is — but the two ceilings multiply out
//! to far more than one frame can carry, so a legitimately full table still
//! encodes past `MAX_FRAME_LEN`. `write_message` refused such a frame, the
//! connection dropped, and every `GraphQuery` — from every Head and Fetch
//! poller in the mesh — failed for as long as those entries lived. Routing
//! from a partial view is survivable; routing from no view is not, so
//! overflow truncates.

use radii_crawl::server::{
    run_on_with_state, CrawlState, ReachabilityEntry, MAX_REACHABILITY_ENTRIES_PER_PEER,
};
use radii_integration::{bind_local, wait_ready};
use radii_proto::{read_message, write_message, RadiiMessage, MAX_NODE_ID_LEN, MAX_PROTOCOL_LEN};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

/// Comfortably past one frame at the maximum legal entry size, and well
/// inside the global entry cap.
const PEERS: usize = 4;

async fn graph_query(addr: &str) -> anyhow::Result<(usize, usize)> {
    let mut stream = TcpStream::connect(addr).await?;
    write_message(&mut stream, &RadiiMessage::GraphQuery).await?;
    match read_message(&mut stream).await? {
        RadiiMessage::GraphSnapshot { nodes, reports } => Ok((nodes.len(), reports.len())),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}

async fn send_report(stream: &mut TcpStream, target: String) -> anyhow::Result<String> {
    write_message(
        stream,
        &RadiiMessage::ReachabilityReport {
            from: "peer".into(),
            target,
            protocol: "radii".into(),
            reachable: true,
            rtt_ms: Some(1),
            observed_addr: None,
        },
    )
    .await?;
    match read_message(stream).await? {
        RadiiMessage::Ack { status } => Ok(status),
        other => anyhow::bail!("unexpected reply: {other:?}"),
    }
}

#[tokio::test]
async fn graph_query_still_answers_when_the_table_outgrows_one_frame() {
    let (listener, addr) = bind_local().await.unwrap();
    let state = Arc::new(RwLock::new(CrawlState::default()));
    let state_clone = Arc::clone(&state);
    tokio::spawn(async move { run_on_with_state(listener, state_clone, None).await });
    wait_ready(&addr).await.unwrap();

    graph_query(&addr)
        .await
        .expect("baseline graph query must succeed");

    // An entry at the maximum legal size is accepted; one byte over is
    // refused before it can reach the table at all.
    let mut client = TcpStream::connect(&addr).await.unwrap();
    assert_eq!(
        send_report(&mut client, "t".repeat(MAX_NODE_ID_LEN))
            .await
            .unwrap(),
        "report_received",
        "an entry at the size bound must be accepted"
    );
    assert!(
        send_report(&mut client, "t".repeat(MAX_NODE_ID_LEN + 1))
            .await
            .is_err(),
        "an oversized entry must be refused at decode"
    );

    // Fill the table with maximum-size-but-legal entries, through the same
    // `record_report` the wire path uses so every cap still applies. Done
    // against the shared state rather than over the wire purely for speed —
    // the query below is what actually exercises serialization.
    {
        let mut guard = state.write().await;
        for peer in 0..PEERS {
            let from = format!("{peer:03}{}", "f".repeat(MAX_NODE_ID_LEN - 3));
            for i in 0..MAX_REACHABILITY_ENTRIES_PER_PEER {
                let target = format!("{i:04}{}", "t".repeat(MAX_NODE_ID_LEN - 4));
                let protocol = "p".repeat(MAX_PROTOCOL_LEN);
                assert!(
                    guard.record_report(
                        (from.clone(), target, protocol),
                        ReachabilityEntry {
                            reachable: true,
                            rtt_ms: Some(1),
                            observed_addr: None,
                            last_seen_unix_ms: 0,
                        },
                    ),
                    "peer {peer} entry {i} refused; this test's premise no longer holds"
                );
            }
        }
    }

    // The mesh must still be able to route. A truncated snapshot is the
    // designed outcome; no snapshot at all is the regression.
    let (_, reports) = graph_query(&addr)
        .await
        .expect("graph query must still answer once the table outgrows a frame");
    assert!(
        reports > 0,
        "a truncated snapshot must still carry what fits"
    );
    assert!(
        reports < PEERS * MAX_REACHABILITY_ENTRIES_PER_PEER,
        "this test only means something if the table really did overflow"
    );

    // And it must keep answering — the failure this guards against was
    // permanent, not transient.
    graph_query(&addr)
        .await
        .expect("graph query must keep answering");
}
