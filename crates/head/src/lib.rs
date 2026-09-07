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

pub mod config;
pub mod decision;
pub mod graph;
pub mod http;
pub mod radii;
pub mod runners;

use crate::decision::{DecisionEngine, GraphRoutePolicy};
use radii_core::registry::ProtocolRegistry;
use radii_proto::tls::TlsIdentity;
use std::sync::{Arc, RwLock};

pub async fn run(config: config::Config) -> anyhow::Result<()> {
    let tls = config.tls.as_ref().map(TlsIdentity::load).transpose()?;

    let graph_state: graph::SharedGraphState = Arc::new(RwLock::new(graph::GraphState::default()));

    let graph_policy = config.graph.as_ref().map(|graph_config| {
        GraphRoutePolicy::new(
            graph_config.node_map.clone(),
            graph_config.source_node_id.clone(),
            graph_config.allowed_protocols.clone(),
            graph_config.max_hops,
            graph_config.max_candidates,
            Arc::clone(&graph_state),
        )
    });

    let decision = DecisionEngine::from_config_with_graph(&config.routing, graph_policy);

    let registry = ProtocolRegistry::new()
        .register(runners::HttpRunner::new(
            config.http.bind.clone(),
            decision.clone(),
        ))
        .register(runners::RadiiRunner::maybe_new(
            config.radii.clone(),
            tls.clone(),
        ))
        .register(runners::GraphPollRunner::maybe_new(
            config.graph.clone(),
            graph_state,
            tls,
        ));

    registry.run_all().await
}
