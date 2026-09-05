use crate::config::GraphConfig;
use radii_core::routing::{
    DefaultScorer, GraphSnapshot, Link, NodeId, ProtocolId, RoutePlanner, RouteRequest,
};
use radii_proto::tls::TlsIdentity;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Live view of Crawl's reachability graph plus the node listen-address
/// registry, refreshed on an interval by [`run_poll`].
#[derive(Default)]
pub struct GraphState {
    pub snapshot: GraphSnapshot,
    pub listen_addrs: HashMap<String, Vec<String>>,
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
) -> anyhow::Result<(GraphSnapshot, HashMap<String, Vec<String>>)> {
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
    let listen_addrs = nodes
        .into_iter()
        .map(|node| (node.node_id, node.listen_addrs))
        .collect();
    Ok((snapshot, listen_addrs))
}

/// Finds the best-scoring reachable route from `source` to `target` in the
/// live graph and resolves it to one of the target node's listen addresses.
pub fn plan_backend(
    state: &SharedGraphState,
    source: &NodeId,
    target: &NodeId,
    allowed_protocols: &[ProtocolId],
    max_hops: usize,
) -> Option<(String, usize, f64)> {
    let guard = state.read().ok()?;
    let planner = RoutePlanner::new(DefaultScorer);
    let request = RouteRequest {
        source: source.clone(),
        target: target.clone(),
        allowed_protocols: allowed_protocols.to_vec(),
        max_hops,
    };
    let route = planner
        .plan(&guard.snapshot, &request, 1)
        .into_iter()
        .next()?;
    let addr = guard.listen_addrs.get(&target.0)?.first()?.clone();
    Some((addr, route.hops.len(), route.score))
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
        listen_addrs.insert("node-b".to_string(), vec!["10.0.0.5:9000".to_string()]);
        Arc::new(RwLock::new(GraphState {
            snapshot,
            listen_addrs,
        }))
    }

    #[test]
    fn resolves_backend_for_reachable_route() {
        let state = state_with(vec![("head", "node-b", "http", true, Some(15))]);
        let backend = plan_backend(
            &state,
            &NodeId("head".into()),
            &NodeId("node-b".into()),
            &[ProtocolId::new("http")],
            4,
        );
        let (addr, hops, _score) = backend.expect("expected a route");
        assert_eq!(addr, "10.0.0.5:9000");
        assert_eq!(hops, 2);
    }

    #[test]
    fn returns_none_when_target_unreachable() {
        let state = state_with(vec![("head", "node-b", "http", false, Some(15))]);
        let backend = plan_backend(
            &state,
            &NodeId("head".into()),
            &NodeId("node-b".into()),
            &[ProtocolId::new("http")],
            4,
        );
        assert!(backend.is_none());
    }
}
