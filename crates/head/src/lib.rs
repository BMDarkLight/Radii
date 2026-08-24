pub mod config;
pub mod decision;
pub mod graph;
pub mod http;
pub mod radii;
pub mod runners;

use crate::decision::{DecisionEngine, GraphRoutePolicy};
use radii_core::registry::ProtocolRegistry;
use std::sync::{Arc, RwLock};

pub async fn run(config: config::Config) -> anyhow::Result<()> {
    let graph_state: graph::SharedGraphState = Arc::new(RwLock::new(graph::GraphState::default()));

    let graph_policy = config.graph.as_ref().map(|graph_config| {
        GraphRoutePolicy::new(
            graph_config.node_map.clone(),
            graph_config.source_node_id.clone(),
            graph_config.allowed_protocols.clone(),
            graph_config.max_hops,
            Arc::clone(&graph_state),
        )
    });

    let decision = DecisionEngine::from_config_with_graph(&config.routing, graph_policy);

    let registry = ProtocolRegistry::new()
        .register(runners::HttpRunner::new(
            config.http.bind.clone(),
            decision.clone(),
        ))
        .register(runners::RadiiRunner::maybe_new(config.radii.clone()))
        .register(runners::GraphPollRunner::maybe_new(
            config.graph.clone(),
            graph_state,
        ));

    registry.run_all().await
}
