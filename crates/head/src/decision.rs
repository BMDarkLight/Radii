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

#[derive(Clone)]
pub struct BackendDecision {
    pub backend: String,
    pub reason: DecisionReason,
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

        BackendDecision {
            backend: "unreachable".to_string(),
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
    node_map: HashMap<String, NodeId>,
    source: NodeId,
    allowed_protocols: Vec<ProtocolId>,
    max_hops: usize,
    state: SharedGraphState,
}

impl GraphRoutePolicy {
    pub fn new(
        node_map: HashMap<String, String>,
        source_node_id: String,
        allowed_protocols: Vec<String>,
        max_hops: usize,
        state: SharedGraphState,
    ) -> Self {
        Self {
            node_map: node_map
                .into_iter()
                .map(|(host, node_id)| (host, NodeId(node_id)))
                .collect(),
            source: NodeId(source_node_id),
            allowed_protocols: allowed_protocols.into_iter().map(ProtocolId::new).collect(),
            max_hops,
            state,
        }
    }
}

impl DecisionPolicy for GraphRoutePolicy {
    fn evaluate(&self, input: &DecisionInput<'_>) -> Option<BackendDecision> {
        let host = input.host?;
        let target = self.node_map.get(host)?;
        let (backend, hops, score) = graph::plan_backend(
            &self.state,
            &self.source,
            target,
            &self.allowed_protocols,
            self.max_hops,
        )?;
        tracing::debug!(host, backend = %backend, hops, score, "graph route matched");
        Some(BackendDecision {
            backend,
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
            backend: backend.clone(),
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
            backend: self.backend.clone(),
            reason: DecisionReason::Default,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RoutingConfig;

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
        assert_eq!(matched.backend, "http://10.0.0.10:9000");
        assert!(matches!(matched.reason, DecisionReason::HostMatch));

        let fallback = engine.decide(input(Some("other.example")));
        assert_eq!(fallback.backend, "http://127.0.0.1:9000");
        assert!(matches!(fallback.reason, DecisionReason::Default));
    }

    #[test]
    fn empty_engine_returns_unreachable() {
        let engine = DecisionEngine::new();
        let decision = engine.decide(input(None));
        assert_eq!(decision.backend, "unreachable");
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
        listen_addrs.insert("node-b".to_string(), vec!["10.0.0.5:9000".to_string()]);
        Arc::new(RwLock::new(GraphState {
            snapshot,
            listen_addrs,
        }))
    }

    #[test]
    fn graph_route_takes_priority_over_host_map() {
        let state = graph_state_with_reachable_route();
        let mut node_map = HashMap::new();
        node_map.insert("example.com".to_string(), "node-b".to_string());
        let graph_policy = GraphRoutePolicy::new(
            node_map,
            "head".to_string(),
            vec!["http".to_string()],
            4,
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
        assert_eq!(matched.backend, "10.0.0.5:9000");
        assert!(matches!(matched.reason, DecisionReason::GraphRoute));
    }

    #[test]
    fn graph_route_falls_through_when_host_unmapped() {
        let state = graph_state_with_reachable_route();
        let graph_policy =
            GraphRoutePolicy::new(HashMap::new(), "head".to_string(), vec![], 4, state);

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
        assert_eq!(fallback.backend, "http://10.0.0.10:9000");
        assert!(matches!(fallback.reason, DecisionReason::HostMatch));
    }
}
