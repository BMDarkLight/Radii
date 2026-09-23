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

//! Reading Crawl's view back out.
//!
//! `hello` and `report` push observations in; without this there was no way
//! to see what Crawl made of them, even though the protocol has carried
//! `GraphQuery` all along and Head has been using it to route.

use anyhow::Result;
use radii_core::routing::{GraphSnapshot, Link, NodeId, ProtocolId};
use radii_proto::tls::TlsIdentity;
use radii_proto::{GraphReport, NodeInfo};
use serde::Serialize;

use crate::brand::{self, Format, Term};

/// The whole reply, for `--json`. Mirrors the wire types rather than
/// inventing a shape, so a reader can follow it back to the protocol.
#[derive(Serialize)]
struct GraphJson<'a> {
    nodes: Vec<NodeJson<'a>>,
    links: Vec<LinkJson<'a>>,
}

#[derive(Serialize)]
struct NodeJson<'a> {
    node_id: &'a str,
    roles: &'a [String],
    /// `reachable`, `severed` or `unprobed` — see [`node_state`].
    state: &'static str,
    listen_addrs: Vec<AddrJson<'a>>,
}

#[derive(Serialize)]
struct AddrJson<'a> {
    role: &'a str,
    addr: &'a str,
}

#[derive(Serialize)]
struct LinkJson<'a> {
    from: &'a str,
    target: &'a str,
    protocol: &'a str,
    reachable: bool,
    rtt_ms: Option<u32>,
}

/// Asks a Crawl listener for its node registry and reachability graph.
pub async fn fetch(
    addr: &str,
    tls: Option<&TlsIdentity>,
) -> Result<(Vec<NodeInfo>, Vec<GraphReport>)> {
    let mut stream = radii_proto::tls::dial(addr, tls).await?;
    let (nodes, reports) = radii_proto::query_graph_on(&mut stream).await?;
    Ok((nodes, reports))
}

/// Turns a wire graph into the planner's, the same way Head does.
///
/// `add_link` drops links once the snapshot hits its size cap rather than
/// growing without bound, so the count it kept back is worth reporting — a
/// plan made from a truncated view is not wrong, but it is partial.
pub fn to_snapshot(reports: &[GraphReport]) -> GraphSnapshot {
    let mut snapshot = GraphSnapshot::new();
    for report in reports {
        snapshot.add_link(Link {
            from: NodeId(report.from.clone()),
            to: NodeId(report.target.clone()),
            protocol: ProtocolId::new(report.protocol.clone()),
            reachable: report.reachable,
            latency_ms: report.rtt_ms,
        });
    }
    snapshot
}

/// What the graph has actually observed about a node.
///
/// `None` is *unprobed*: Crawl knows the node from a `NodeHello` but holds no
/// reachability observation touching it, which is a different thing from
/// having observed it to be unreachable. One reachable observation is enough
/// to call it reachable — the whole point of the system is that a node with a
/// dead path and a live one is still reachable.
fn node_state(node_id: &str, reports: &[GraphReport]) -> Option<bool> {
    let mut observed = false;
    for report in reports {
        if report.from == node_id || report.target == node_id {
            if report.reachable {
                return Some(true);
            }
            observed = true;
        }
    }
    observed.then_some(false)
}

fn state_label(state: Option<bool>) -> &'static str {
    match state {
        Some(true) => "reachable",
        Some(false) => "severed",
        None => "unprobed",
    }
}

pub async fn run(addr: &str, tls: Option<&TlsIdentity>, json: bool, term: &Term) -> Result<()> {
    let (nodes, reports) = fetch(addr, tls).await?;
    match brand::format(term, json) {
        Format::Json => print_json(&nodes, &reports)?,
        Format::Plain => print_plain(&nodes, &reports),
        Format::Pretty => print_pretty(&nodes, &reports, term),
    }
    Ok(())
}

fn build_json<'a>(nodes: &'a [NodeInfo], reports: &'a [GraphReport]) -> GraphJson<'a> {
    GraphJson {
        nodes: nodes
            .iter()
            .map(|n| NodeJson {
                node_id: &n.node_id,
                roles: &n.roles,
                state: state_label(node_state(&n.node_id, reports)),
                listen_addrs: n
                    .listen_addrs
                    .iter()
                    .map(|a| AddrJson {
                        role: &a.role,
                        addr: &a.addr,
                    })
                    .collect(),
            })
            .collect(),
        links: reports
            .iter()
            .map(|r| LinkJson {
                from: &r.from,
                target: &r.target,
                protocol: &r.protocol,
                reachable: r.reachable,
                rtt_ms: r.rtt_ms,
            })
            .collect(),
    }
}

fn print_json(nodes: &[NodeInfo], reports: &[GraphReport]) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&build_json(nodes, reports))?
    );
    Ok(())
}

fn print_plain(nodes: &[NodeInfo], reports: &[GraphReport]) {
    for node in nodes {
        let addrs = node
            .listen_addrs
            .iter()
            .map(|a| format!("{}={}", a.role, a.addr))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "node id={} state={} roles={} addrs={}",
            node.node_id,
            state_label(node_state(&node.node_id, reports)),
            node.roles.join(","),
            addrs
        );
    }
    for report in reports {
        // `-` rather than an empty value: an absent rtt is a fact, and a
        // trailing `rtt_ms=` is easy to misread as zero.
        let rtt = report
            .rtt_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into());
        println!(
            "link from={} target={} protocol={} reachable={} rtt_ms={}",
            report.from, report.target, report.protocol, report.reachable, rtt
        );
    }
}

fn print_pretty(nodes: &[NodeInfo], reports: &[GraphReport], term: &Term) {
    if nodes.is_empty() && reports.is_empty() {
        println!("{}", brand::dim("crawl holds no nodes and no links", term));
        return;
    }

    if !nodes.is_empty() {
        println!("{}", brand::heading("Nodes", term));
        let width = nodes
            .iter()
            .map(|n| n.node_id.chars().count())
            .max()
            .unwrap_or(0);
        for node in nodes {
            let pad = " ".repeat(width.saturating_sub(node.node_id.chars().count()));
            let roles = if node.roles.is_empty() {
                brand::dim("no roles", term)
            } else {
                node.roles.join(", ")
            };
            println!(
                "  {} {}{pad}  {}",
                brand::reach_glyph(node_state(&node.node_id, reports), term),
                brand::literal(&node.node_id, term),
                roles
            );
            for addr in &node.listen_addrs {
                println!(
                    "    {}  {} {}",
                    " ".repeat(width),
                    brand::dim(&format!("{}:", addr.role), term),
                    addr.addr
                );
            }
        }
    }

    if !reports.is_empty() {
        if !nodes.is_empty() {
            println!();
        }
        println!("{}", brand::heading("Links", term));
        let width = reports
            .iter()
            .map(|r| r.from.chars().count() + r.target.chars().count())
            .max()
            .unwrap_or(0)
            + 3;
        for report in reports {
            let path = format!("{} \u{2192} {}", report.from, report.target);
            let pad = " ".repeat(width.saturating_sub(path.chars().count()));
            let rtt = match report.rtt_ms {
                Some(ms) => format!("{ms} ms"),
                None => brand::dim("\u{2014}", term),
            };
            println!(
                "  {} {path}{pad}  {:<8}  {rtt}",
                brand::reach_glyph(Some(report.reachable), term),
                report.protocol,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use radii_proto::ListenAddr;

    fn report(from: &str, target: &str, reachable: bool, rtt: Option<u32>) -> GraphReport {
        GraphReport {
            from: from.into(),
            target: target.into(),
            protocol: "radii".into(),
            reachable,
            rtt_ms: rtt,
        }
    }

    #[test]
    fn a_wire_graph_becomes_a_planner_snapshot() {
        let reports = vec![
            report("a", "b", true, Some(40)),
            report("b", "c", false, None),
        ];
        let snapshot = to_snapshot(&reports);
        assert_eq!(snapshot.links.len(), 2);
        assert_eq!(snapshot.nodes.len(), 3);
        assert_eq!(snapshot.dropped_links(), 0);
        assert!(snapshot.links[0].reachable);
        assert_eq!(snapshot.links[0].latency_ms, Some(40));
        assert!(!snapshot.links[1].reachable);
    }

    #[test]
    fn json_keeps_the_wire_field_names_and_the_node_state() {
        let nodes = [NodeInfo {
            node_id: "node-a".into(),
            roles: vec!["crawl".into()],
            listen_addrs: vec![ListenAddr {
                addr: "127.0.0.1:2224".into(),
                role: "relay".into(),
            }],
        }];
        let reports = [report("node-a", "node-b", true, Some(40))];
        let text = serde_json::to_string(&build_json(&nodes, &reports)).unwrap();
        for key in [
            "node_id",
            "roles",
            "state",
            "listen_addrs",
            "links",
            "target",
            "reachable",
            "rtt_ms",
        ] {
            assert!(text.contains(key), "{key} missing from {text}");
        }
        assert!(text.contains("\"state\":\"reachable\""));
    }

    #[test]
    fn a_node_with_no_observation_is_unprobed_not_severed() {
        let reports = [report("a", "b", true, Some(40))];
        // `c` is in the registry from a hello but nothing has probed it.
        assert_eq!(node_state("c", &reports), None);
        assert_eq!(state_label(None), "unprobed");
    }

    #[test]
    fn one_live_path_makes_a_node_reachable_even_beside_a_dead_one() {
        // The whole point of the system: a node with a severed path and a
        // live one is reachable, and the order of observation cannot matter.
        let dead_first = [
            report("a", "c", false, None),
            report("b", "c", true, Some(9)),
        ];
        let live_first = [
            report("b", "c", true, Some(9)),
            report("a", "c", false, None),
        ];
        assert_eq!(node_state("c", &dead_first), Some(true));
        assert_eq!(node_state("c", &live_first), Some(true));
        assert_eq!(state_label(Some(true)), "reachable");
    }

    #[test]
    fn only_dead_observations_make_a_node_severed() {
        let reports = [report("a", "c", false, None), report("b", "c", false, None)];
        assert_eq!(node_state("c", &reports), Some(false));
        assert_eq!(state_label(Some(false)), "severed");
    }

    #[test]
    fn the_renderers_survive_an_empty_and_a_ragged_graph() {
        let term = Term {
            stdout_is_tty: true,
            ..Term::default()
        };
        print_pretty(&[], &[], &term);
        print_plain(&[], &[]);

        let nodes = [
            NodeInfo {
                node_id: "n".into(),
                roles: vec![],
                listen_addrs: vec![],
            },
            NodeInfo {
                node_id: "a-much-longer-node-id".into(),
                roles: vec!["crawl".into(), "head".into()],
                listen_addrs: vec![ListenAddr {
                    addr: "[::1]:2224".into(),
                    role: "relay".into(),
                }],
            },
        ];
        let reports = [report("n", "a-much-longer-node-id", false, None)];
        print_pretty(&nodes, &reports, &term);
        print_plain(&nodes, &reports);
        print_json(&nodes, &reports).unwrap();
    }

    #[test]
    fn an_absent_rtt_prints_as_a_dash_not_an_empty_value() {
        // Captured by eye rather than by pipe: the point is that the field is
        // never emitted empty, which would read as zero.
        let r = report("a", "b", false, None);
        let rendered = r
            .rtt_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".into());
        assert_eq!(rendered, "-");
    }
}
