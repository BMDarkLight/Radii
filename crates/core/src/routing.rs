use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

/// Hard ceilings applied to any graph or request that reaches the planner.
///
/// The reachability graph is assembled from peer-supplied reports, so its size
/// is attacker-influenced. Route planning is super-linear in the graph, which
/// makes an unbounded snapshot a denial-of-service primitive rather than a
/// performance footnote: the previous exhaustive search turned 132 reports
/// (~6 KB on the wire) into 3.7 GB resident and minutes of CPU, on whichever
/// process happened to be planning.
pub const MAX_GRAPH_NODES: usize = 4_096;
pub const MAX_GRAPH_LINKS: usize = 32_768;
pub const MAX_ROUTE_HOPS: usize = 32;
pub const MAX_ROUTE_RESULTS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolId(pub String);

impl ProtocolId {
    pub const HTTP: &'static str = "http";
    pub const HTTPS: &'static str = "https";
    pub const SSH: &'static str = "ssh";
    pub const RADII: &'static str = "radii";

    pub fn new<S: Into<String>>(value: S) -> Self {
        Self(value.into())
    }
}

#[derive(Debug, Clone)]
pub struct Link {
    pub from: NodeId,
    pub to: NodeId,
    pub protocol: ProtocolId,
    pub reachable: bool,
    pub latency_ms: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct GraphSnapshot {
    pub nodes: HashSet<NodeId>,
    pub links: Vec<Link>,
    dropped_links: usize,
}

impl GraphSnapshot {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a link, or drops it if the snapshot is already at its size cap.
    ///
    /// Dropping rather than growing is deliberate: the caller is feeding in
    /// data a remote peer supplied, and a snapshot that refuses to stop
    /// growing is exactly the DoS the caps exist to prevent. Callers that
    /// care can surface [`Self::dropped_links`] to operators.
    pub fn add_link(&mut self, link: Link) -> bool {
        let would_add_nodes = usize::from(!self.nodes.contains(&link.from))
            + usize::from(!self.nodes.contains(&link.to));

        if self.links.len() >= MAX_GRAPH_LINKS
            || self.nodes.len() + would_add_nodes > MAX_GRAPH_NODES
        {
            self.dropped_links += 1;
            return false;
        }

        self.nodes.insert(link.from.clone());
        self.nodes.insert(link.to.clone());
        self.links.push(link);
        true
    }

    /// How many links were refused because the snapshot hit a size cap.
    /// Non-zero means the graph is being truncated and the planner is working
    /// from a partial view — worth logging, and worth investigating.
    pub fn dropped_links(&self) -> usize {
        self.dropped_links
    }

    pub fn from_reports<I>(reports: I) -> Self
    where
        I: IntoIterator<Item = ReachabilityReport>,
    {
        let mut snapshot = Self::new();
        for report in reports {
            snapshot.add_link(Link {
                from: NodeId(report.from),
                to: NodeId(report.target),
                protocol: ProtocolId::new(report.protocol),
                reachable: report.reachable,
                latency_ms: report.rtt_ms,
            });
        }
        snapshot
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReachabilityReport {
    pub from: String,
    pub target: String,
    pub protocol: String,
    pub reachable: bool,
    pub rtt_ms: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RouteRequest {
    pub source: NodeId,
    pub target: NodeId,
    pub allowed_protocols: Vec<ProtocolId>,
    pub max_hops: usize,
}

#[derive(Debug, Clone)]
pub struct RouteCandidate {
    /// Every node on the path, starting with the source and ending with the
    /// target. A direct link is therefore two entries.
    pub hops: Vec<NodeId>,
    /// The protocol of the final link into the target. A path may mix
    /// protocols across hops; every one of them is drawn from the request's
    /// `allowed_protocols`.
    pub protocol: ProtocolId,
    pub score: f64,
}

/// Cost model for traversing a single link.
///
/// The contract is what makes planning tractable: the cost must be
/// **non-negative** and must depend only on the link, never on the path taken
/// to reach it. Both properties are what let the planner find a provably
/// optimal route in bounded time instead of enumerating candidates. A cost
/// that varies with path history would need exhaustive search — which is what
/// this code used to do, and why a small hostile graph could exhaust memory.
pub trait RouteScorer: Send + Sync {
    fn link_cost(&self, link: &Link) -> f64;
}

pub struct DefaultScorer;

impl DefaultScorer {
    /// Charged per hop, so a shorter path wins ties against a longer one of
    /// equal latency. Expressed in milliseconds to keep the cost in one unit.
    pub const HOP_PENALTY_MS: f64 = 10.0;
    /// Assumed latency for a link whose RTT was never measured. Pessimistic
    /// on purpose: an unmeasured link should lose to a measured good one.
    pub const UNKNOWN_LATENCY_MS: f64 = 1000.0;
}

impl RouteScorer for DefaultScorer {
    fn link_cost(&self, link: &Link) -> f64 {
        Self::HOP_PENALTY_MS
            + link
                .latency_ms
                .map(f64::from)
                .unwrap_or(Self::UNKNOWN_LATENCY_MS)
    }
}

pub struct RoutePlanner<S: RouteScorer> {
    scorer: S,
}

/// One resolved path through the graph, carried internally while planning.
#[derive(Debug, Clone)]
struct Path {
    hops: Vec<NodeId>,
    links: Vec<Link>,
    cost: f64,
}

impl Path {
    fn candidate(&self) -> RouteCandidate {
        RouteCandidate {
            hops: self.hops.clone(),
            protocol: self
                .links
                .last()
                .map(|link| link.protocol.clone())
                .unwrap_or_else(|| ProtocolId::new(ProtocolId::RADII)),
            score: self.cost,
        }
    }
}

/// One cell of the hop-limited shortest-path table: the best known cost to
/// reach a node within some hop budget, and the link we arrived on.
#[derive(Clone)]
struct Cell {
    cost: f64,
    /// `(previous node, link taken, the hop layer that previous node sits in)`.
    /// `None` marks the source.
    parent: Option<(NodeId, Link, usize)>,
}

impl<S: RouteScorer> RoutePlanner<S> {
    pub fn new(scorer: S) -> Self {
        Self { scorer }
    }

    /// Returns up to `limit` distinct loop-free routes, cheapest first.
    ///
    /// Unlike the previous implementation, the returned set really is the best
    /// `limit` routes: search is ordered by the same cost function used to
    /// score results, so truncating cannot discard a route better than one
    /// that was kept. `max_hops` and `limit` are both clamped to the module
    /// ceilings, so a hostile or careless config cannot ask for unbounded work.
    pub fn plan(
        &self,
        snapshot: &GraphSnapshot,
        request: &RouteRequest,
        limit: usize,
    ) -> Vec<RouteCandidate> {
        let limit = limit.min(MAX_ROUTE_RESULTS);
        let max_hops = request.max_hops.min(MAX_ROUTE_HOPS);
        if limit == 0 {
            return Vec::new();
        }

        let allowed: HashSet<ProtocolId> = request.allowed_protocols.iter().cloned().collect();
        let adjacency = build_adjacency(snapshot, &allowed);

        let no_nodes = HashSet::new();
        let no_edges = HashSet::new();
        let Some(best) = self.shortest_path(
            &adjacency,
            &request.source,
            &request.target,
            max_hops,
            &no_nodes,
            &no_edges,
        ) else {
            return Vec::new();
        };

        let mut accepted = vec![best];
        let mut candidates: Vec<Path> = Vec::new();

        // Yen's algorithm: each further route is the cheapest path that
        // diverges from an already-accepted one at some node along it.
        while accepted.len() < limit {
            let previous = accepted[accepted.len() - 1].clone();

            for spur_index in 0..previous.hops.len().saturating_sub(1) {
                let spur_node = &previous.hops[spur_index];
                let root = &previous.hops[..=spur_index];

                // Don't re-derive a route we already have: ban the next link
                // of every accepted path sharing this root.
                let mut banned_edges: HashSet<(NodeId, NodeId)> = HashSet::new();
                for path in accepted.iter().chain(candidates.iter()) {
                    if path.hops.len() > spur_index + 1 && path.hops[..=spur_index] == *root {
                        banned_edges.insert((
                            path.hops[spur_index].clone(),
                            path.hops[spur_index + 1].clone(),
                        ));
                    }
                }

                // Keep the spur path loop-free by removing the root's
                // interior nodes from the graph.
                let banned_nodes: HashSet<NodeId> = root[..spur_index].iter().cloned().collect();

                let Some(spur_path) = self.shortest_path(
                    &adjacency,
                    spur_node,
                    &request.target,
                    max_hops - spur_index,
                    &banned_nodes,
                    &banned_edges,
                ) else {
                    continue;
                };

                let mut hops = root[..spur_index].to_vec();
                hops.extend(spur_path.hops.iter().cloned());
                let mut links = previous.links[..spur_index].to_vec();
                links.extend(spur_path.links.iter().cloned());
                let cost = links.iter().map(|link| self.scorer.link_cost(link)).sum();

                let combined = Path { hops, links, cost };
                let already_known = accepted
                    .iter()
                    .chain(candidates.iter())
                    .any(|path| path.hops == combined.hops);
                if !already_known {
                    candidates.push(combined);
                }
            }

            if candidates.is_empty() {
                break;
            }
            // Cheapest candidate becomes the next accepted route.
            let mut best_index = 0;
            for (index, path) in candidates.iter().enumerate() {
                if path.cost.total_cmp(&candidates[best_index].cost) == Ordering::Less {
                    best_index = index;
                }
            }
            accepted.push(candidates.remove(best_index));
        }

        accepted.iter().map(Path::candidate).collect()
    }

    /// Cheapest path from `source` to `target` using at most `max_hops` links,
    /// avoiding `banned_nodes` and `banned_edges`.
    ///
    /// Implemented as a hop-layered relaxation rather than plain Dijkstra
    /// because the hop budget is a hard constraint, not a tiebreak: the
    /// cheapest route overall may be longer than `max_hops`, and Dijkstra
    /// would find that one and then have to discard it. Layering costs
    /// `O(max_hops * links)`, which the module ceilings bound.
    fn shortest_path(
        &self,
        adjacency: &HashMap<NodeId, Vec<Link>>,
        source: &NodeId,
        target: &NodeId,
        max_hops: usize,
        banned_nodes: &HashSet<NodeId>,
        banned_edges: &HashSet<(NodeId, NodeId)>,
    ) -> Option<Path> {
        if banned_nodes.contains(source) || banned_nodes.contains(target) {
            return None;
        }
        if source == target {
            return Some(Path {
                hops: vec![source.clone()],
                links: Vec::new(),
                cost: 0.0,
            });
        }

        let mut layers: Vec<HashMap<NodeId, Cell>> = Vec::with_capacity(max_hops + 1);
        let mut first = HashMap::new();
        first.insert(
            source.clone(),
            Cell {
                cost: 0.0,
                parent: None,
            },
        );
        layers.push(first);

        for hop in 1..=max_hops {
            // A route reachable within `hop - 1` links is also reachable
            // within `hop`, so each layer starts from the previous one.
            let mut layer = layers[hop - 1].clone();

            for (node, cell) in layers[hop - 1].iter() {
                let Some(links) = adjacency.get(node) else {
                    continue;
                };
                for link in links {
                    if banned_nodes.contains(&link.to) {
                        continue;
                    }
                    if banned_edges.contains(&(node.clone(), link.to.clone())) {
                        continue;
                    }
                    let cost = cell.cost + self.scorer.link_cost(link);
                    let improves = match layer.get(&link.to) {
                        Some(existing) => cost.total_cmp(&existing.cost) == Ordering::Less,
                        None => true,
                    };
                    if improves {
                        layer.insert(
                            link.to.clone(),
                            Cell {
                                cost,
                                parent: Some((node.clone(), link.clone(), hop - 1)),
                            },
                        );
                    }
                }
            }

            layers.push(layer);
        }

        reconstruct(&layers, source, target, max_hops)
    }
}

/// Walks the parent pointers back from `target` to `source`.
///
/// Rejects any path that revisits a node. With a strictly positive link cost
/// that cannot happen — revisiting only adds cost and burns hop budget — but a
/// custom [`RouteScorer`] may return zero, and a route that loops is not a
/// route we should hand to a caller that is going to forward traffic along it.
fn reconstruct(
    layers: &[HashMap<NodeId, Cell>],
    source: &NodeId,
    target: &NodeId,
    max_hops: usize,
) -> Option<Path> {
    let cell = layers.get(max_hops)?.get(target)?;
    let cost = cell.cost;

    let mut hops = vec![target.clone()];
    let mut links = Vec::new();
    let mut seen: HashSet<NodeId> = HashSet::new();
    seen.insert(target.clone());

    let mut cursor = (target.clone(), max_hops);
    loop {
        let cell = layers.get(cursor.1)?.get(&cursor.0)?;
        let Some((previous, link, previous_layer)) = cell.parent.clone() else {
            break;
        };
        if !seen.insert(previous.clone()) {
            return None;
        }
        hops.push(previous.clone());
        links.push(link);
        cursor = (previous, previous_layer);
    }

    hops.reverse();
    links.reverse();
    if hops.first() != Some(source) {
        return None;
    }

    Some(Path { hops, links, cost })
}

fn build_adjacency(
    snapshot: &GraphSnapshot,
    allowed: &HashSet<ProtocolId>,
) -> HashMap<NodeId, Vec<Link>> {
    let mut map: HashMap<NodeId, Vec<Link>> = HashMap::new();
    for link in &snapshot.links {
        if !link.reachable {
            continue;
        }
        if !allowed.is_empty() && !allowed.contains(&link.protocol) {
            continue;
        }
        map.entry(link.from.clone()).or_default().push(link.clone());
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn report(from: &str, target: &str, protocol: &str, rtt_ms: u32) -> ReachabilityReport {
        ReachabilityReport {
            from: from.to_string(),
            target: target.to_string(),
            protocol: protocol.to_string(),
            reachable: true,
            rtt_ms: Some(rtt_ms),
        }
    }

    fn nodes(names: &[&str]) -> Vec<NodeId> {
        names.iter().map(|name| NodeId((*name).into())).collect()
    }

    fn request(source: &str, target: &str, protocols: &[&str], max_hops: usize) -> RouteRequest {
        RouteRequest {
            source: NodeId(source.into()),
            target: NodeId(target.into()),
            allowed_protocols: protocols.iter().map(|p| ProtocolId::new(*p)).collect(),
            max_hops,
        }
    }

    #[test]
    fn plans_lowest_score_path() {
        let snapshot = GraphSnapshot::from_reports([
            report("a", "b", "radii", 50),
            report("b", "c", "radii", 40),
            report("a", "c", "radii", 200),
        ]);

        let planner = RoutePlanner::new(DefaultScorer);
        let routes = planner.plan(&snapshot, &request("a", "c", &["radii"], 4), 2);

        assert_eq!(routes.len(), 2);
        // a->b->c costs (10+50)+(10+40)=110; direct a->c costs 10+200=210.
        assert_eq!(routes[0].hops, nodes(&["a", "b", "c"]));
        assert_eq!(routes[1].hops, nodes(&["a", "c"]));
        assert!(routes[0].score <= routes[1].score);
    }

    #[test]
    fn ignores_unreachable_links() {
        let snapshot = GraphSnapshot::from_reports([ReachabilityReport {
            from: "a".into(),
            target: "b".into(),
            protocol: "radii".into(),
            reachable: false,
            rtt_ms: Some(10),
        }]);
        let planner = RoutePlanner::new(DefaultScorer);
        assert!(planner
            .plan(&snapshot, &request("a", "b", &[], 2), 1)
            .is_empty());
    }

    #[test]
    fn filters_disallowed_protocols() {
        let snapshot = GraphSnapshot::from_reports([
            report("a", "b", "ssh", 10),
            report("a", "b", "radii", 50),
        ]);
        let planner = RoutePlanner::new(DefaultScorer);
        let routes = planner.plan(&snapshot, &request("a", "b", &["radii"], 2), 4);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].protocol, ProtocolId::new("radii"));
    }

    #[test]
    fn respects_max_hops() {
        let snapshot = GraphSnapshot::from_reports([
            report("a", "b", "radii", 10),
            report("b", "c", "radii", 10),
            report("c", "d", "radii", 10),
        ]);
        let planner = RoutePlanner::new(DefaultScorer);
        assert!(planner
            .plan(&snapshot, &request("a", "d", &["radii"], 2), 1)
            .is_empty());
    }

    /// The hop budget is a constraint, not a tiebreak: when the cheapest route
    /// is too long, the planner must return the best route that *fits* rather
    /// than finding the cheap one and discarding it.
    #[test]
    fn prefers_a_costlier_route_that_fits_the_hop_budget() {
        let snapshot = GraphSnapshot::from_reports([
            // Cheap but four hops.
            report("a", "x", "radii", 1),
            report("x", "y", "radii", 1),
            report("y", "z", "radii", 1),
            report("z", "d", "radii", 1),
            // Expensive but a single hop.
            report("a", "d", "radii", 500),
        ]);
        let planner = RoutePlanner::new(DefaultScorer);
        let routes = planner.plan(&snapshot, &request("a", "d", &["radii"], 2), 1);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].hops, nodes(&["a", "d"]));
    }

    #[test]
    fn avoids_cycles() {
        let snapshot = GraphSnapshot::from_reports([
            report("a", "b", "radii", 10),
            report("b", "a", "radii", 10),
            report("b", "c", "radii", 10),
        ]);
        let planner = RoutePlanner::new(DefaultScorer);
        let routes = planner.plan(&snapshot, &request("a", "c", &["radii"], 8), 3);
        assert!(!routes.is_empty());
        for route in routes {
            let mut seen = HashSet::new();
            for hop in &route.hops {
                assert!(seen.insert(hop.clone()), "cycle in {:?}", route.hops);
            }
        }
    }

    /// `limit` must return the genuinely best routes. The old search ordered
    /// by raw latency while scoring by latency-plus-hop-penalty, so truncating
    /// could drop a better route than one it kept.
    #[test]
    fn returns_distinct_routes_in_ascending_cost_order() {
        let snapshot = GraphSnapshot::from_reports([
            report("a", "b", "radii", 10),
            report("a", "c", "radii", 20),
            report("a", "d", "radii", 30),
            report("b", "z", "radii", 10),
            report("c", "z", "radii", 10),
            report("d", "z", "radii", 10),
        ]);
        let planner = RoutePlanner::new(DefaultScorer);
        let routes = planner.plan(&snapshot, &request("a", "z", &["radii"], 4), 3);

        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].hops, nodes(&["a", "b", "z"]));
        assert_eq!(routes[1].hops, nodes(&["a", "c", "z"]));
        assert_eq!(routes[2].hops, nodes(&["a", "d", "z"]));
        for pair in routes.windows(2) {
            assert!(pair[0].score <= pair[1].score, "results not cost-ordered");
        }
    }

    /// Regression for the audit's denial-of-service finding. A dense graph
    /// with an unreachable target was the worst case: the old planner
    /// enumerated every simple path and never hit its early exit. 12 fully
    /// connected nodes (132 links) took it past 3.7 GB and four minutes.
    #[test]
    fn dense_graph_with_unreachable_target_completes_quickly() {
        let mut reports = Vec::new();
        for i in 0..12 {
            for j in 0..12 {
                if i != j {
                    reports.push(report(&format!("n{i}"), &format!("n{j}"), "radii", 10));
                }
            }
        }
        assert_eq!(reports.len(), 132);
        let snapshot = GraphSnapshot::from_reports(reports);
        let planner = RoutePlanner::new(DefaultScorer);

        let started = Instant::now();
        let routes = planner.plan(&snapshot, &request("n0", "absent", &["radii"], 10), 1);
        let elapsed = started.elapsed();

        assert!(routes.is_empty());
        assert!(
            elapsed.as_secs() < 5,
            "planning took {elapsed:?}; the search is not bounded"
        );
    }

    /// A peer that reports about endlessly many distinct nodes hits the node
    /// ceiling first, since each link it sends introduces a new one.
    #[test]
    fn caps_node_count_and_reports_the_drops() {
        let mut snapshot = GraphSnapshot::new();
        for i in 0..(MAX_GRAPH_NODES + 100) {
            snapshot.add_link(Link {
                from: NodeId("a".into()),
                to: NodeId(format!("n{i}")),
                protocol: ProtocolId::new("radii"),
                reachable: true,
                latency_ms: Some(1),
            });
        }
        assert!(
            snapshot.nodes.len() <= MAX_GRAPH_NODES,
            "node cap breached: {}",
            snapshot.nodes.len()
        );
        assert!(snapshot.dropped_links() > 0);
    }

    /// A peer that instead reports endless *parallel* links between a handful
    /// of nodes never trips the node cap, so the link cap has to hold on its
    /// own.
    #[test]
    fn caps_link_count_and_reports_the_drops() {
        let mut snapshot = GraphSnapshot::new();
        for i in 0..(MAX_GRAPH_LINKS + 100) {
            snapshot.add_link(Link {
                from: NodeId("a".into()),
                to: NodeId("b".into()),
                protocol: ProtocolId::new(format!("radii-{i}")),
                reachable: true,
                latency_ms: Some(1),
            });
        }
        assert_eq!(snapshot.links.len(), MAX_GRAPH_LINKS);
        assert_eq!(snapshot.nodes.len(), 2);
        assert_eq!(snapshot.dropped_links(), 100);
    }

    #[test]
    fn clamps_hostile_request_bounds() {
        let snapshot = GraphSnapshot::from_reports([report("a", "b", "radii", 10)]);
        let planner = RoutePlanner::new(DefaultScorer);
        let routes = planner.plan(
            &snapshot,
            &request("a", "b", &["radii"], usize::MAX),
            usize::MAX,
        );
        assert_eq!(routes.len(), 1);
    }
}
