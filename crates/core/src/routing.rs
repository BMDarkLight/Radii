use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};

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
}

impl GraphSnapshot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_link(&mut self, link: Link) {
        self.nodes.insert(link.from.clone());
        self.nodes.insert(link.to.clone());
        self.links.push(link);
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
    pub hops: Vec<NodeId>,
    pub protocol: ProtocolId,
    pub score: f64,
}

pub trait RouteScorer: Send + Sync {
    fn score(&self, path: &PathState) -> f64;
}

pub struct DefaultScorer;

impl RouteScorer for DefaultScorer {
    fn score(&self, path: &PathState) -> f64 {
        let hop_penalty = path.hops.len() as f64 * 10.0;
        let latency = path.total_latency_ms.unwrap_or(1000) as f64;
        hop_penalty + latency
    }
}

pub struct RoutePlanner<S: RouteScorer> {
    scorer: S,
}

impl<S: RouteScorer> RoutePlanner<S> {
    pub fn new(scorer: S) -> Self {
        Self { scorer }
    }

    pub fn plan(
        &self,
        snapshot: &GraphSnapshot,
        request: &RouteRequest,
        limit: usize,
    ) -> Vec<RouteCandidate> {
        let allowed: HashSet<ProtocolId> = request.allowed_protocols.iter().cloned().collect();
        let adjacency = build_adjacency(snapshot, &allowed);

        let mut results = Vec::new();
        let mut heap = BinaryHeap::new();
        heap.push(PathState::new(request.source.clone()));

        while let Some(state) = heap.pop() {
            if state.hops.len() > request.max_hops {
                continue;
            }

            if state.current == request.target {
                let score = self.scorer.score(&state);
                results.push(RouteCandidate {
                    hops: state.hops.clone(),
                    protocol: state
                        .protocol
                        .clone()
                        .unwrap_or_else(|| ProtocolId::new(ProtocolId::RADII)),
                    score,
                });
                if results.len() >= limit {
                    break;
                }
                continue;
            }

            if let Some(edges) = adjacency.get(&state.current) {
                for edge in edges {
                    if state.hops.contains(&edge.to) {
                        continue;
                    }
                    let next = state.extend(edge);
                    heap.push(next);
                }
            }
        }

        results.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(Ordering::Equal));
        results
    }
}

#[derive(Debug, Clone)]
pub struct PathState {
    pub current: NodeId,
    pub hops: Vec<NodeId>,
    pub protocol: Option<ProtocolId>,
    pub total_latency_ms: Option<u32>,
}

impl PathState {
    pub fn new(start: NodeId) -> Self {
        Self {
            current: start.clone(),
            hops: vec![start],
            protocol: None,
            total_latency_ms: None,
        }
    }

    pub fn extend(&self, edge: &Link) -> Self {
        let mut hops = self.hops.clone();
        hops.push(edge.to.clone());
        let total_latency_ms = match (self.total_latency_ms, edge.latency_ms) {
            (Some(a), Some(b)) => Some(a.saturating_add(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        Self {
            current: edge.to.clone(),
            hops,
            protocol: Some(edge.protocol.clone()),
            total_latency_ms,
        }
    }
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

impl Ord for PathState {
    fn cmp(&self, other: &Self) -> Ordering {
        let self_score = self.total_latency_ms.unwrap_or(u32::MAX);
        let other_score = other.total_latency_ms.unwrap_or(u32::MAX);
        other_score.cmp(&self_score)
    }
}

impl PartialOrd for PathState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PathState {
    fn eq(&self, other: &Self) -> bool {
        self.current == other.current && self.hops == other.hops
    }
}

impl Eq for PathState {}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(from: &str, target: &str, protocol: &str, rtt_ms: u32) -> ReachabilityReport {
        ReachabilityReport {
            from: from.to_string(),
            target: target.to_string(),
            protocol: protocol.to_string(),
            reachable: true,
            rtt_ms: Some(rtt_ms),
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
        let request = RouteRequest {
            source: NodeId("a".into()),
            target: NodeId("c".into()),
            allowed_protocols: vec![ProtocolId::new("radii")],
            max_hops: 4,
        };

        let routes = planner.plan(&snapshot, &request, 2);
        assert_eq!(routes.len(), 2);
        // Multi-hop a->b->c (90ms + hop penalty) beats direct a->c (200ms).
        assert_eq!(
            routes[0].hops,
            vec![NodeId("a".into()), NodeId("b".into()), NodeId("c".into())]
        );
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
        let request = RouteRequest {
            source: NodeId("a".into()),
            target: NodeId("b".into()),
            allowed_protocols: vec![],
            max_hops: 2,
        };

        assert!(planner.plan(&snapshot, &request, 1).is_empty());
    }

    #[test]
    fn filters_disallowed_protocols() {
        let snapshot = GraphSnapshot::from_reports([
            report("a", "b", "ssh", 10),
            report("a", "b", "radii", 50),
        ]);
        let planner = RoutePlanner::new(DefaultScorer);
        let request = RouteRequest {
            source: NodeId("a".into()),
            target: NodeId("b".into()),
            allowed_protocols: vec![ProtocolId::new("radii")],
            max_hops: 2,
        };
        let routes = planner.plan(&snapshot, &request, 4);
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
        let request = RouteRequest {
            source: NodeId("a".into()),
            target: NodeId("d".into()),
            allowed_protocols: vec![ProtocolId::new("radii")],
            max_hops: 2,
        };
        assert!(planner.plan(&snapshot, &request, 1).is_empty());
    }

    #[test]
    fn avoids_cycles() {
        let snapshot = GraphSnapshot::from_reports([
            report("a", "b", "radii", 10),
            report("b", "a", "radii", 10),
            report("b", "c", "radii", 10),
        ]);
        let planner = RoutePlanner::new(DefaultScorer);
        let request = RouteRequest {
            source: NodeId("a".into()),
            target: NodeId("c".into()),
            allowed_protocols: vec![ProtocolId::new("radii")],
            max_hops: 8,
        };
        let routes = planner.plan(&snapshot, &request, 3);
        assert!(!routes.is_empty());
        for route in routes {
            let mut seen = HashSet::new();
            for hop in &route.hops {
                assert!(seen.insert(hop.clone()), "cycle in {:?}", route.hops);
            }
        }
    }
}
