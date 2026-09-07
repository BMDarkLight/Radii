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

use crate::config::GraphConfig;
use radii_core::routing::{
    resolve_candidates, GraphSnapshot, Link, NodeId, ProtocolId, ResolvedRoute, RoleId,
};
use radii_proto::tls::TlsIdentity;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// The currently ranked routes, refreshed by [`run_poll`]. Empty means no
/// reachable route has been found yet; callers fall back to their static
/// configured upstream in that case.
pub type SharedRoutes = Arc<RwLock<Vec<ResolvedRoute>>>;

/// Thin seam over `resolve_candidates` so the polling logic is unit-testable
/// without a live Crawl.
#[allow(clippy::too_many_arguments)]
pub fn plan_from(
    snapshot: &GraphSnapshot,
    listen_addrs: &HashMap<String, Vec<(String, String)>>,
    source: &NodeId,
    targets: &[NodeId],
    allowed_protocols: &[ProtocolId],
    max_hops: usize,
    max_candidates: usize,
) -> Vec<ResolvedRoute> {
    resolve_candidates(
        snapshot,
        listen_addrs,
        source,
        targets,
        allowed_protocols,
        max_hops,
        max_candidates,
        Some(&RoleId::new(RoleId::RELAY)),
        &RoleId::new(RoleId::RELAY),
    )
}

/// Polls Crawl for its reachability graph on a fixed interval, plans routes
/// from `source_node_id` to every one of `target_node_ids`, and keeps
/// `routes` pointed at the ranked, dialable results. Runs until the process
/// shuts down; transient query or planning failures are logged and retried
/// rather than propagated, so a Crawl outage does not take Fetch down with
/// it.
pub async fn run_poll(
    config: GraphConfig,
    routes: SharedRoutes,
    tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    let interval = Duration::from_millis(config.poll_interval_ms.max(1));
    let source = NodeId(config.source_node_id.clone());
    let targets: Vec<NodeId> = config.target_node_ids.iter().cloned().map(NodeId).collect();
    let allowed_protocols: Vec<ProtocolId> = config
        .allowed_protocols
        .iter()
        .cloned()
        .map(ProtocolId::new)
        .collect();

    loop {
        match fetch_once(&config.crawl_upstream, tls.as_ref()).await {
            Ok((snapshot, listen_addrs)) => {
                let planned = plan_from(
                    &snapshot,
                    &listen_addrs,
                    &source,
                    &targets,
                    &allowed_protocols,
                    config.max_hops,
                    config.max_candidates,
                );
                if planned.is_empty() {
                    tracing::warn!(?targets, "fetch found no reachable route to any target");
                }
                tracing::debug!(
                    candidates = planned.len(),
                    "fetch refreshed route candidates"
                );
                *routes.write().expect("fetch routes poisoned") = planned;
            }
            Err(err) => {
                tracing::warn!(
                    upstream = %config.crawl_upstream,
                    error = %err,
                    "fetch graph query failed"
                );
            }
        }
        tokio::time::sleep(interval).await;
    }
}

/// Queries Crawl once, returning the snapshot and the node registry.
async fn fetch_once(
    crawl_upstream: &str,
    tls: Option<&TlsIdentity>,
) -> anyhow::Result<(GraphSnapshot, HashMap<String, Vec<(String, String)>>)> {
    let mut stream = radii_proto::tls::dial(crawl_upstream, tls).await?;
    let (nodes, reports) = radii_proto::query_graph_on(&mut stream).await?;

    let mut snapshot = GraphSnapshot::new();
    for report in reports {
        snapshot.add_link(Link {
            from: NodeId(report.from),
            to: NodeId(report.target),
            protocol: ProtocolId::new(report.protocol),
            reachable: report.reachable,
            latency_ms: report.rtt_ms,
        });
    }
    if snapshot.dropped_links() > 0 {
        tracing::warn!(
            upstream = %crawl_upstream,
            dropped = snapshot.dropped_links(),
            "crawl graph exceeded the local size cap; planning from a partial view"
        );
    }
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
    Ok((snapshot, listen_addrs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use radii_core::routing::{GraphSnapshot, Link, NodeId, ProtocolId};

    #[test]
    fn plans_across_every_configured_target() {
        let mut snapshot = GraphSnapshot::new();
        for (from, to, rtt) in [("s", "t1", 100u32), ("s", "t2", 10)] {
            snapshot.add_link(Link {
                from: NodeId(from.into()),
                to: NodeId(to.into()),
                protocol: ProtocolId::new("radii"),
                reachable: true,
                latency_ms: Some(rtt),
            });
        }
        let listen: HashMap<String, Vec<(String, String)>> = [
            (
                "t1".to_string(),
                vec![("10.0.0.1:2224".to_string(), "relay".to_string())],
            ),
            (
                "t2".to_string(),
                vec![("10.0.0.2:2224".to_string(), "relay".to_string())],
            ),
        ]
        .into_iter()
        .collect();

        let routes = plan_from(
            &snapshot,
            &listen,
            &NodeId("s".into()),
            &[NodeId("t1".into()), NodeId("t2".into())],
            &[ProtocolId::new("radii")],
            4,
            3,
        );

        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].target().0, "t2", "cheaper target ranks first");
    }

    #[test]
    fn plans_only_to_targets_advertising_a_relay_address() {
        let mut snapshot = GraphSnapshot::new();
        for to in ["t-relay", "t-http"] {
            snapshot.add_link(Link {
                from: NodeId("s".into()),
                to: NodeId(to.into()),
                protocol: ProtocolId::new("radii"),
                reachable: true,
                latency_ms: Some(10),
            });
        }
        let mut listen: HashMap<String, Vec<(String, String)>> = HashMap::new();
        listen.insert(
            "t-relay".into(),
            vec![("10.0.0.1:2224".into(), "relay".into())],
        );
        // Advertises only an http backend, so it is not a relay target.
        listen.insert(
            "t-http".into(),
            vec![("10.0.0.2:9000".into(), "http".into())],
        );

        let routes = plan_from(
            &snapshot,
            &listen,
            &NodeId("s".into()),
            &[NodeId("t-relay".into()), NodeId("t-http".into())],
            &[ProtocolId::new("radii")],
            4,
            5,
        );

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].target().0, "t-relay");
    }
}
