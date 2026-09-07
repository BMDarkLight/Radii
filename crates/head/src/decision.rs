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

use crate::config::RoutingConfig;
use crate::graph::{self, SharedGraphState};
use radii_core::routing::{NodeId, ProtocolId};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Http,
    Other,
}

pub struct DecisionInput<'a> {
    pub protocol: Protocol,
    pub protocol_label: Option<&'a str>,
    pub host: Option<&'a str>,
    pub source: Option<SocketAddr>,
    pub destination_port: Option<u16>,
    pub attributes: &'a [(&'a str, &'a str)],
}

/// How a decided backend can be reached.
///
/// The two are genuinely different, not two spellings of an address. A
/// graph-resolved backend is a *node*, reached over a source-routed chain
/// that terminates at its relay listener — so it needs the node id, which a
/// bare address cannot carry. A statically configured backend came from the
/// operator's own config, has no node identity at all, and may legitimately
/// point at a host that is not part of the mesh.
#[derive(Clone)]
pub enum BackendTarget {
    Chain(Vec<radii_core::routing::ResolvedRoute>),
    Direct(String),
}

#[derive(Clone)]
pub struct BackendDecision {
    pub target: BackendTarget,
    pub reason: DecisionReason,
}

impl BackendDecision {
    /// The address that will be dialed first.
    pub fn backend(&self) -> String {
        match &self.target {
            BackendTarget::Chain(routes) => routes
                .first()
                .and_then(|route| route.hops.last())
                .map(|hop| hop.addr.clone())
                .unwrap_or_else(|| "unreachable".to_string()),
            BackendTarget::Direct(addr) => addr.clone(),
        }
    }

    /// Every address that could be dialed, best first. `backend()` is always
    /// the first, on every path.
    pub fn candidates(&self) -> Vec<String> {
        match &self.target {
            BackendTarget::Chain(routes) => routes
                .iter()
                .filter_map(|route| route.hops.last().map(|hop| hop.addr.clone()))
                .collect(),
            BackendTarget::Direct(addr) => vec![addr.clone()],
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DecisionReason {
    GraphRoute,
    HostMatch,
    Default,
}

pub trait DecisionPolicy: Send + Sync {
    fn evaluate(&self, input: &DecisionInput<'_>) -> Option<BackendDecision>;
}

#[derive(Clone)]
pub struct DecisionEngine {
    policies: Vec<Arc<dyn DecisionPolicy>>,
}

impl DecisionEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn with_policy(mut self, policy: impl DecisionPolicy + 'static) -> Self {
        self.policies.push(Arc::new(policy));
        self
    }

    pub fn from_config(config: &RoutingConfig) -> Self {
        Self::new()
            .with_policy(HostMapPolicy::new(config.host_map.clone()))
            .with_policy(DefaultPolicy::new(config.default_backend.clone()))
    }

    /// Like [`Self::from_config`], but consults a live Crawl reachability
    /// graph ahead of the static host map when `graph_policy` is present.
    pub fn from_config_with_graph(
        config: &RoutingConfig,
        graph_policy: Option<GraphRoutePolicy>,
    ) -> Self {
        let mut engine = Self::new();
        if let Some(policy) = graph_policy {
            engine = engine.with_policy(policy);
        }
        engine
            .with_policy(HostMapPolicy::new(config.host_map.clone()))
            .with_policy(DefaultPolicy::new(config.default_backend.clone()))
    }

    pub fn decide(&self, input: DecisionInput<'_>) -> BackendDecision {
        for policy in &self.policies {
            if let Some(decision) = policy.evaluate(&input) {
                return decision;
            }
        }

        // No policy matched. Both real constructors append a `DefaultPolicy`
        // that always answers, so this is reachable only through a hand-built
        // engine — but `candidates()[0] == backend()` is documented to hold on
        // every path, and a consumer should not have to know which paths are
        // live to rely on it. `Direct("unreachable")` reports the sentinel
        // from both methods, keeping the invariant true here too.
        BackendDecision {
            target: BackendTarget::Direct("unreachable".to_string()),
            reason: DecisionReason::Default,
        }
    }
}

impl Default for DecisionEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolves a backend by planning a route through Crawl's live reachability
/// graph, from Head's own node id to the node mapped to the request host.
/// Falls through (returns `None`) when the host isn't mapped or no reachable
/// route currently exists, leaving the static host map / default as fallback.
pub struct GraphRoutePolicy {
    node_map: HashMap<String, Vec<NodeId>>,
    source: NodeId,
    allowed_protocols: Vec<ProtocolId>,
    max_hops: usize,
    max_candidates: usize,
    state: SharedGraphState,
}

impl GraphRoutePolicy {
    pub fn new(
        node_map: HashMap<String, Vec<String>>,
        source_node_id: String,
        allowed_protocols: Vec<String>,
        max_hops: usize,
        max_candidates: usize,
        state: SharedGraphState,
    ) -> Self {
        Self {
            node_map: node_map
                .into_iter()
                .map(|(host, node_ids)| (host, node_ids.into_iter().map(NodeId).collect()))
                .collect(),
            source: NodeId(source_node_id),
            allowed_protocols: allowed_protocols.into_iter().map(ProtocolId::new).collect(),
            max_hops,
            max_candidates,
            state,
        }
    }
}

impl DecisionPolicy for GraphRoutePolicy {
    fn evaluate(&self, input: &DecisionInput<'_>) -> Option<BackendDecision> {
        let host = input.host?;
        let targets = self.node_map.get(host)?;
        let routes = graph::plan_backends(
            &self.state,
            &self.source,
            targets,
            &self.allowed_protocols,
            self.max_hops,
            self.max_candidates,
        );
        if routes.is_empty() {
            return None;
        }
        tracing::debug!(
            host,
            backend = %routes[0].hops.last().map(|hop| hop.addr.as_str()).unwrap_or("unreachable"),
            hops = routes[0].hops.len(),
            score = routes[0].score,
            candidates = routes.len(),
            "graph route matched"
        );
        Some(BackendDecision {
            target: BackendTarget::Chain(routes),
            reason: DecisionReason::GraphRoute,
        })
    }
}

pub struct HostMapPolicy {
    host_map: HashMap<String, String>,
}

impl HostMapPolicy {
    pub fn new(host_map: HashMap<String, String>) -> Self {
        Self { host_map }
    }
}

impl DecisionPolicy for HostMapPolicy {
    fn evaluate(&self, input: &DecisionInput<'_>) -> Option<BackendDecision> {
        let host = input.host?;
        let backend = self.host_map.get(host)?;
        Some(BackendDecision {
            target: BackendTarget::Direct(backend.clone()),
            reason: DecisionReason::HostMatch,
        })
    }
}

pub struct DefaultPolicy {
    backend: String,
}

impl DefaultPolicy {
    pub fn new(backend: String) -> Self {
        Self { backend }
    }
}

impl DecisionPolicy for DefaultPolicy {
    fn evaluate(&self, _input: &DecisionInput<'_>) -> Option<BackendDecision> {
        Some(BackendDecision {
            target: BackendTarget::Direct(self.backend.clone()),
            reason: DecisionReason::Default,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RoutingConfig;

    /// `candidates[0] == backend` must hold on EVERY path, including the
    /// no-policy-matched sentinel. Both real constructors append a
    /// `DefaultPolicy` that always answers, so this path is reachable only
    /// through a hand-built engine — but a consumer written against the
    /// documented invariant should not have to know that.
    #[test]
    fn the_unmatched_sentinel_keeps_candidates_aligned_with_backend() {
        let decision = DecisionEngine::new().decide(input(Some("anything.example")));

        assert_eq!(decision.backend(), "unreachable");
        assert_eq!(
            decision.candidates().first(),
            Some(&decision.backend()),
            "candidates[0] must equal backend even when no policy matched"
        );
    }

    fn input(host: Option<&str>) -> DecisionInput<'_> {
        DecisionInput {
            protocol: Protocol::Http,
            protocol_label: None,
            host,
            source: None,
            destination_port: None,
            attributes: &[],
        }
    }

    #[test]
    fn prefers_host_map_over_default() {
        let mut host_map = HashMap::new();
        host_map.insert("example.com".into(), "http://10.0.0.10:9000".into());
        let engine = DecisionEngine::from_config(&RoutingConfig {
            default_backend: "http://127.0.0.1:9000".into(),
            host_map,
        });

        let matched = engine.decide(input(Some("example.com")));
        assert_eq!(matched.backend(), "http://10.0.0.10:9000");
        assert!(matches!(matched.reason, DecisionReason::HostMatch));
        assert_eq!(
            matched.candidates().first(),
            Some(&matched.backend()),
            "candidates[0] must equal backend on a host-map hit"
        );

        let fallback = engine.decide(input(Some("other.example")));
        assert_eq!(fallback.backend(), "http://127.0.0.1:9000");
        assert!(matches!(fallback.reason, DecisionReason::Default));
        assert_eq!(
            fallback.candidates().first(),
            Some(&fallback.backend()),
            "candidates[0] must equal backend on the default fallback"
        );
    }

    #[test]
    fn empty_engine_returns_unreachable() {
        let engine = DecisionEngine::new();
        let decision = engine.decide(input(None));
        assert_eq!(decision.backend(), "unreachable");
    }

    fn graph_state_with_reachable_route() -> SharedGraphState {
        use crate::graph::GraphState;
        use radii_core::routing::{GraphSnapshot, Link};
        use std::sync::RwLock;

        let mut snapshot = GraphSnapshot::new();
        snapshot.add_link(Link {
            from: NodeId("head".into()),
            to: NodeId("node-b".into()),
            protocol: ProtocolId::new("http"),
            reachable: true,
            latency_ms: Some(10),
        });
        let mut listen_addrs = HashMap::new();
        listen_addrs.insert(
            "node-b".to_string(),
            vec![("10.0.0.5:9000".to_string(), "relay".to_string())],
        );
        Arc::new(RwLock::new(GraphState {
            snapshot,
            listen_addrs,
        }))
    }

    #[test]
    fn graph_route_takes_priority_over_host_map() {
        let state = graph_state_with_reachable_route();
        let mut node_map = HashMap::new();
        node_map.insert("example.com".to_string(), vec!["node-b".to_string()]);
        let graph_policy = GraphRoutePolicy::new(
            node_map,
            "head".to_string(),
            vec!["http".to_string()],
            4,
            3,
            state,
        );

        let mut host_map = HashMap::new();
        host_map.insert("example.com".into(), "http://10.0.0.10:9000".into());
        let engine = DecisionEngine::from_config_with_graph(
            &RoutingConfig {
                default_backend: "http://127.0.0.1:9000".into(),
                host_map,
            },
            Some(graph_policy),
        );

        let matched = engine.decide(input(Some("example.com")));
        assert_eq!(matched.backend(), "10.0.0.5:9000");
        assert!(matches!(matched.reason, DecisionReason::GraphRoute));
    }

    #[test]
    fn a_static_host_map_hit_is_a_direct_target() {
        let mut host_map = HashMap::new();
        host_map.insert(
            "example.com".to_string(),
            "http://10.0.0.10:9000".to_string(),
        );
        let engine = DecisionEngine::from_config(&RoutingConfig {
            default_backend: "http://127.0.0.1:9000".into(),
            host_map,
        });

        let decision = engine.decide(input(Some("example.com")));
        assert!(matches!(decision.target, BackendTarget::Direct(_)));
        assert_eq!(decision.backend(), "http://10.0.0.10:9000");
        assert_eq!(
            decision.candidates(),
            vec!["http://10.0.0.10:9000".to_string()]
        );
    }

    #[test]
    fn a_graph_route_is_a_chain_target_carrying_node_ids() {
        let state = graph_state_with_reachable_route();
        let mut node_map = HashMap::new();
        node_map.insert("example.com".to_string(), vec!["node-b".to_string()]);
        let policy = GraphRoutePolicy::new(
            node_map,
            "head".to_string(),
            vec!["http".to_string()],
            4,
            3,
            state,
        );
        let engine = DecisionEngine::new().with_policy(policy);

        let decision = engine.decide(input(Some("example.com")));
        let BackendTarget::Chain(routes) = &decision.target else {
            panic!("expected a chain target, got a direct one");
        };
        // The node id is what `chain::establish` needs and what a bare
        // address string cannot carry.
        assert_eq!(routes[0].target().0, "node-b");
        assert_eq!(decision.backend(), routes[0].hops.last().unwrap().addr);
    }

    #[test]
    fn graph_route_falls_through_when_host_unmapped() {
        let state = graph_state_with_reachable_route();
        let graph_policy =
            GraphRoutePolicy::new(HashMap::new(), "head".to_string(), vec![], 4, 3, state);

        let mut host_map = HashMap::new();
        host_map.insert("example.com".into(), "http://10.0.0.10:9000".into());
        let engine = DecisionEngine::from_config_with_graph(
            &RoutingConfig {
                default_backend: "http://127.0.0.1:9000".into(),
                host_map,
            },
            Some(graph_policy),
        );

        let fallback = engine.decide(input(Some("example.com")));
        assert_eq!(fallback.backend(), "http://10.0.0.10:9000");
        assert!(matches!(fallback.reason, DecisionReason::HostMatch));
    }
}
