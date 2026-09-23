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
use radii_core::routing::{GraphSnapshot, Link, NodeId, ProtocolId, RoleId};
use radii_proto::tls::TlsIdentity;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Live view of Crawl's reachability graph plus the node listen-address
/// registry, refreshed on an interval by [`run_poll`].
#[derive(Default)]
pub struct GraphState {
    pub snapshot: GraphSnapshot,
    pub listen_addrs: HashMap<String, Vec<(String, String)>>,
    /// When the last *successful* query landed. `None` means no poll has
    /// ever succeeded, so the snapshot above is empty rather than stale.
    ///
    /// A failed query is logged and retried rather than propagated, which
    /// keeps a Crawl outage from taking Head down — but it also means
    /// nothing else records that Head is now routing from an increasingly
    /// old view. This is what `/health` reads to report that.
    pub last_refresh: Option<Instant>,
}

pub type SharedGraphState = Arc<RwLock<GraphState>>;

/// Polls Crawl for its current graph on a fixed interval, updating `state` in
/// place. Runs until the process shuts down; transient query failures are
/// logged and retried rather than propagated, so a Crawl outage does not take
/// Head down with it.
pub async fn run_poll(
    config: GraphConfig,
    state: SharedGraphState,
    tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    let interval = Duration::from_millis(config.poll_interval_ms.max(1));
    loop {
        match fetch_once(&config.crawl_upstream, tls.as_ref()).await {
            Ok((snapshot, listen_addrs)) => {
                let mut guard = state.write().expect("graph state poisoned");
                guard.snapshot = snapshot;
                guard.listen_addrs = listen_addrs;
                guard.last_refresh = Some(Instant::now());
                tracing::debug!(upstream = %config.crawl_upstream, "head graph refreshed");
            }
            Err(err) => {
                tracing::warn!(upstream = %config.crawl_upstream, error = %err, "head graph query failed");
            }
        }
        tokio::time::sleep(interval).await;
    }
}

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
            "crawl graph exceeded the local size cap; routing from a partial view"
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

/// All reachable backends for `targets`, best first.
///
/// Head reaches a decided backend over a source-routed chain, which
/// terminates at the target's `relay` listener and splices to that node's
/// own configured upstream — the same listener Fetch resolves for every hop
/// of a chain it establishes. Resolving `http` here would name an endpoint
/// Head never dials directly once it proxies over chains, so it resolves the
/// same role Fetch does.
///
/// Intermediates are resolved too (`hop_role: Some(RELAY)`), for the same
/// reason and with the same value Fetch passes. While Head only printed a
/// decision, passing `None` was right: it handed its caller the target's
/// address and never touched the path. Once it began establishing chains
/// that became wrong in a way nothing could see — `None` drops intermediates
/// from the resolved route rather than failing it, so a planned
/// `head → node-r → node-b` collapsed to a one-hop chain that dialed
/// `node-b` directly, at an address the graph never said Head could reach.
/// Multi-hop routing silently did not happen, and a route that only worked
/// via a relay looked identical to one that did not need it.
///
/// The cost of resolving them is that a path whose intermediate advertises
/// no `relay` address is now dropped instead of collapsed. That is correct —
/// Head cannot dial a hop it has no address for — but it does mean a
/// registry missing relay tags yields fewer candidates rather than
/// silently-direct ones.
pub fn plan_backends(
    state: &SharedGraphState,
    source: &NodeId,
    targets: &[NodeId],
    allowed_protocols: &[ProtocolId],
    max_hops: usize,
    limit: usize,
) -> Vec<radii_core::routing::ResolvedRoute> {
    let Ok(guard) = state.read() else {
        return Vec::new();
    };
    radii_core::routing::resolve_candidates(
        &guard.snapshot,
        &guard.listen_addrs,
        source,
        targets,
        allowed_protocols,
        max_hops,
        limit,
        Some(&RoleId::new(RoleId::RELAY)),
        &RoleId::new(RoleId::RELAY),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with(reports: Vec<(&str, &str, &str, bool, Option<u32>)>) -> SharedGraphState {
        let mut snapshot = GraphSnapshot::new();
        for (from, to, protocol, reachable, latency_ms) in reports {
            snapshot.add_link(Link {
                from: NodeId(from.into()),
                to: NodeId(to.into()),
                protocol: ProtocolId::new(protocol),
                reachable,
                latency_ms,
            });
        }
        let mut listen_addrs = HashMap::new();
        listen_addrs.insert(
            "node-b".to_string(),
            vec![("10.0.0.5:9000".to_string(), "relay".to_string())],
        );
        Arc::new(RwLock::new(GraphState {
            snapshot,
            listen_addrs,
            ..GraphState::default()
        }))
    }

    /// Adds a `relay` listen address for a node the default fixture omits.
    fn register_relay(state: &mut SharedGraphState, node_id: &str, addr: &str) {
        state
            .write()
            .expect("graph state poisoned")
            .listen_addrs
            .insert(
                node_id.to_string(),
                vec![(addr.to_string(), "relay".to_string())],
            );
    }

    #[test]
    fn resolves_backend_for_reachable_route() {
        let state = state_with(vec![("head", "node-b", "http", true, Some(15))]);
        let routes = plan_backends(
            &state,
            &NodeId("head".into()),
            &[NodeId("node-b".into())],
            &[ProtocolId::new("http")],
            4,
            3,
        );
        let route = routes.first().expect("expected a route");
        assert_eq!(route.hops.last().unwrap().addr, "10.0.0.5:9000");
        assert_eq!(route.hops.len(), 1);
    }

    #[test]
    fn returns_none_when_target_unreachable() {
        let state = state_with(vec![("head", "node-b", "http", false, Some(15))]);
        let routes = plan_backends(
            &state,
            &NodeId("head".into()),
            &[NodeId("node-b".into())],
            &[ProtocolId::new("http")],
            4,
            3,
        );
        assert!(routes.is_empty());
    }

    /// A graph where the target is reachable ONLY through an intermediate.
    ///
    /// The resolved route must name both hops in order, because that list is
    /// what `chain::establish` dials and sends as the `TunnelOpen` path. With
    /// `hop_role: None` the intermediate was dropped instead of resolved and
    /// this collapsed to `[node-b]` — a one-hop chain dialing `node-b`
    /// directly, at an address the graph never said Head could reach.
    #[test]
    fn a_multi_hop_route_keeps_its_intermediate_hops() {
        let mut state = state_with(vec![
            ("head", "node-r", "http", true, Some(10)),
            ("node-r", "node-b", "http", true, Some(10)),
        ]);
        // No direct head -> node-b link: the only way there is via node-r.
        register_relay(&mut state, "node-r", "10.0.0.9:9000");

        let routes = plan_backends(
            &state,
            &NodeId("head".into()),
            &[NodeId("node-b".into())],
            &[ProtocolId::new("http")],
            4,
            3,
        );

        let route = routes.first().expect("the target is reachable via node-r");
        let path: Vec<(&str, &str)> = route
            .hops
            .iter()
            .map(|hop| (hop.node_id.0.as_str(), hop.addr.as_str()))
            .collect();
        assert_eq!(
            path,
            vec![("node-r", "10.0.0.9:9000"), ("node-b", "10.0.0.5:9000")],
            "the chain must traverse node-r, not dial node-b directly"
        );
    }

    /// The cost of resolving intermediates: a path through a node that
    /// advertises no `relay` address is dropped, not silently collapsed to a
    /// direct dial of the target. Head has no address for that hop, so the
    /// route is not one it can open.
    #[test]
    fn a_route_through_an_unaddressable_intermediate_is_dropped() {
        // node-r is never registered in `listen_addrs`.
        let state = state_with(vec![
            ("head", "node-r", "http", true, Some(10)),
            ("node-r", "node-b", "http", true, Some(10)),
        ]);

        let routes = plan_backends(
            &state,
            &NodeId("head".into()),
            &[NodeId("node-b".into())],
            &[ProtocolId::new("http")],
            4,
            3,
        );

        assert!(
            routes.is_empty(),
            "a hop with no relay address cannot be dialed, so the route is unusable"
        );
    }
}
