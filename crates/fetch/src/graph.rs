use crate::config::GraphConfig;
use radii_core::routing::{
    DefaultScorer, GraphSnapshot, Link, NodeId, ProtocolId, RoutePlanner, RouteRequest,
};
use radii_proto::tls::TlsIdentity;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// An upstream Fetch learned from Crawl's graph: the address to dial, plus
/// the node id that address is *claimed* to belong to.
///
/// The two travel together on purpose. The address comes from a peer-written
/// node registry, so it is a claim rather than a fact; keeping the node id
/// beside it lets the tunnel verify, at handshake time, that the host which
/// answered is the node the route was planned to. Without that, a poisoned
/// `listen_addrs` silently redirects the tunnel to an attacker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub addr: String,
    pub node_id: String,
}

/// The currently resolved upstream, refreshed by [`run_poll`]. `None` means
/// no reachable route has been found yet; callers fall back to their static
/// configured upstream in that case.
pub type SharedTarget = Arc<RwLock<Option<ResolvedTarget>>>;

/// Polls Crawl for its reachability graph on a fixed interval, plans a route
/// from `source_node_id` to `target_node_id`, and keeps `target` pointed at
/// the resolved address. Runs until the process shuts down; transient query
/// or planning failures are logged and retried rather than propagated, so a
/// Crawl outage does not take Fetch down with it.
pub async fn run_poll(
    config: GraphConfig,
    target: SharedTarget,
    tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    let interval = Duration::from_millis(config.poll_interval_ms.max(1));
    let source = NodeId(config.source_node_id.clone());
    let dest = NodeId(config.target_node_id.clone());
    let allowed_protocols: Vec<ProtocolId> = config
        .allowed_protocols
        .iter()
        .cloned()
        .map(ProtocolId::new)
        .collect();

    loop {
        match resolve_once(
            &config.crawl_upstream,
            &source,
            &dest,
            &allowed_protocols,
            config.max_hops,
            tls.as_ref(),
        )
        .await
        {
            Ok(Some((addr, hops, score))) => {
                tracing::debug!(target = %dest.0, backend = %addr, hops, score, "fetch resolved graph target");
                *target.write().expect("fetch graph target poisoned") = Some(ResolvedTarget {
                    addr,
                    node_id: dest.0.clone(),
                });
            }
            Ok(None) => {
                tracing::warn!(target = %dest.0, "fetch found no reachable route to graph target");
            }
            Err(err) => {
                tracing::warn!(upstream = %config.crawl_upstream, error = %err, "fetch graph query failed");
            }
        }
        tokio::time::sleep(interval).await;
    }
}

async fn resolve_once(
    crawl_upstream: &str,
    source: &NodeId,
    target: &NodeId,
    allowed_protocols: &[ProtocolId],
    max_hops: usize,
    tls: Option<&TlsIdentity>,
) -> anyhow::Result<Option<(String, usize, f64)>> {
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
            "crawl graph exceeded the local size cap; planning from a partial view"
        );
    }
    let listen_addrs: HashMap<String, Vec<String>> = nodes
        .into_iter()
        .map(|node| (node.node_id, node.listen_addrs))
        .collect();

    let planner = RoutePlanner::new(DefaultScorer);
    let request = RouteRequest {
        source: source.clone(),
        target: target.clone(),
        allowed_protocols: allowed_protocols.to_vec(),
        max_hops,
    };
    let Some(route) = planner.plan(&snapshot, &request, 1).into_iter().next() else {
        return Ok(None);
    };
    let Some(addr) = listen_addrs.get(&target.0).and_then(|addrs| addrs.first()) else {
        return Ok(None);
    };

    Ok(Some((addr.clone(), route.hops.len(), route.score)))
}
