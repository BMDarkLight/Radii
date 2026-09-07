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

use radii_core::routing::{
    DefaultScorer, GraphSnapshot, NodeId, ProtocolId, ReachabilityReport, RoutePlanner,
    RouteRequest,
};

#[test]
fn plan_from_jsonl_shaped_reports() {
    let reports = [
        ReachabilityReport {
            from: "edge".into(),
            target: "relay".into(),
            protocol: "radii".into(),
            reachable: true,
            rtt_ms: Some(20),
        },
        ReachabilityReport {
            from: "relay".into(),
            target: "origin".into(),
            protocol: "radii".into(),
            reachable: true,
            rtt_ms: Some(30),
        },
    ];
    let snapshot = GraphSnapshot::from_reports(reports);
    let planner = RoutePlanner::new(DefaultScorer);
    let routes = planner.plan(
        &snapshot,
        &RouteRequest {
            source: NodeId("edge".into()),
            target: NodeId("origin".into()),
            allowed_protocols: vec![ProtocolId::new("radii")],
            max_hops: 4,
        },
        1,
    );
    assert_eq!(routes.len(), 1);
    assert_eq!(
        routes[0].hops,
        vec![
            NodeId("edge".into()),
            NodeId("relay".into()),
            NodeId("origin".into())
        ]
    );
}
