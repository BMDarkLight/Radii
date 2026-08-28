use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, BoxedStream, GraphReport, NodeInfo, RadiiMessage};
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub listen_addrs: Vec<String>,
    pub roles: Vec<String>,
    pub last_seen_unix_ms: u64,
}

#[derive(Default, Debug)]
pub struct CrawlState {
    pub nodes: HashMap<String, NodeEntry>,
    pub reachability: Vec<RadiiMessage>,
    /// `None` means nodes never expire (today's behavior, and the default
    /// via `CrawlState::default()`). `Some(ttl)` drops a node from
    /// `GraphQuery` replies once `now - last_seen_unix_ms > ttl`.
    pub node_ttl_ms: Option<u64>,
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub async fn run(bind: &str, tls: Option<TlsIdentity>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, tls = tls.is_some(), "crawl listening");
    run_on(listener, tls).await
}

pub async fn run_on(listener: TcpListener, tls: Option<TlsIdentity>) -> anyhow::Result<()> {
    let state = Arc::new(RwLock::new(CrawlState::default()));
    run_on_with_state(listener, state, tls).await
}

pub async fn run_on_with_state(
    listener: TcpListener,
    state: Arc<RwLock<CrawlState>>,
    tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    loop {
        let (raw_stream, addr) = listener.accept().await?;
        let state = Arc::clone(&state);
        let tls = tls.clone();
        tokio::spawn(async move {
            let result = async {
                let (stream, peer_identity) =
                    radii_proto::tls::accept(raw_stream, tls.as_ref()).await?;
                handle_connection(stream, addr, state, peer_identity).await
            }
            .await;
            if let Err(err) = result {
                tracing::warn!(source = %addr, error = %err, "crawl connection failed");
            }
        });
    }
}

/// When `peer_identity` is `Some` (an mTLS-authenticated connection), a peer
/// may only advertise hellos/reports under its *own* authenticated node id —
/// this stops one authenticated peer from impersonating another and
/// poisoning the graph with claims it isn't entitled to make. Connections
/// with no TLS identity (plaintext) skip this check, matching today's
/// unauthenticated behavior.
fn authorized(peer_identity: &Option<String>, claimed_node_id: &str) -> bool {
    match peer_identity {
        Some(identity) => identity == claimed_node_id,
        None => true,
    }
}

async fn handle_connection(
    mut stream: BoxedStream,
    addr: SocketAddr,
    state: Arc<RwLock<CrawlState>>,
    peer_identity: Option<String>,
) -> anyhow::Result<()> {
    loop {
        let message = read_message(&mut stream).await?;
        match message {
            RadiiMessage::NodeHello {
                node_id,
                roles,
                listen_addrs,
            } => {
                if !authorized(&peer_identity, &node_id) {
                    tracing::warn!(
                        source = %addr,
                        peer = ?peer_identity,
                        claimed = %node_id,
                        "crawl rejected hello: node id does not match authenticated peer"
                    );
                    write_message(
                        &mut stream,
                        &RadiiMessage::Ack {
                            status: "unauthorized_node_id".to_string(),
                        },
                    )
                    .await?;
                    continue;
                }
                let mut state = state.write().await;
                state.nodes.insert(
                    node_id.clone(),
                    NodeEntry {
                        listen_addrs: listen_addrs.clone(),
                        roles: roles.clone(),
                        last_seen_unix_ms: now_unix_ms(),
                    },
                );
                tracing::info!(source = %addr, node = %node_id, "crawl node hello");
                write_message(
                    &mut stream,
                    &RadiiMessage::Ack {
                        status: "hello_received".to_string(),
                    },
                )
                .await?;
            }
            RadiiMessage::ReachabilityProbe { from, to, .. } => {
                tracing::info!(source = %addr, from = %from, to = %to, "crawl probe");
                write_message(
                    &mut stream,
                    &RadiiMessage::Ack {
                        status: "probe_received".to_string(),
                    },
                )
                .await?;
            }
            RadiiMessage::ReachabilityReport {
                from,
                target,
                protocol,
                reachable,
                rtt_ms,
                observed_addr,
            } => {
                if !authorized(&peer_identity, &from) {
                    tracing::warn!(
                        source = %addr,
                        peer = ?peer_identity,
                        claimed = %from,
                        "crawl rejected report: from does not match authenticated peer"
                    );
                    write_message(
                        &mut stream,
                        &RadiiMessage::Ack {
                            status: "unauthorized_node_id".to_string(),
                        },
                    )
                    .await?;
                    continue;
                }
                let mut state = state.write().await;
                state.reachability.push(RadiiMessage::ReachabilityReport {
                    from: from.clone(),
                    target: target.clone(),
                    protocol: protocol.clone(),
                    reachable,
                    rtt_ms,
                    observed_addr: observed_addr.clone(),
                });
                tracing::info!(
                    source = %addr,
                    from = %from,
                    target = %target,
                    protocol = %protocol,
                    reachable = reachable,
                    "crawl report"
                );
                write_message(
                    &mut stream,
                    &RadiiMessage::Ack {
                        status: "report_received".to_string(),
                    },
                )
                .await?;
            }
            RadiiMessage::FromHead { source, message } => {
                tracing::info!(source = %source, "crawl message via head");
                let inner = *message;
                handle_wrapped_message(inner, &state, source.clone()).await?;
                write_message(
                    &mut stream,
                    &RadiiMessage::Ack {
                        status: "head_message_received".to_string(),
                    },
                )
                .await?;
            }
            RadiiMessage::GraphQuery => {
                let guard = state.read().await;
                let (nodes, reports) = graph_snapshot(&guard, now_unix_ms());
                drop(guard);
                tracing::info!(source = %addr, "crawl graph query");
                write_message(&mut stream, &RadiiMessage::GraphSnapshot { nodes, reports }).await?;
            }
            RadiiMessage::GraphSnapshot { .. } => {
                tracing::info!(source = %addr, "crawl received unexpected graph snapshot");
            }
            RadiiMessage::Ack { .. } => {
                tracing::info!(source = %addr, "crawl ack");
            }
        }
    }
}

async fn handle_wrapped_message(
    message: RadiiMessage,
    state: &Arc<RwLock<CrawlState>>,
    source: String,
) -> anyhow::Result<()> {
    match message {
        RadiiMessage::NodeHello {
            node_id,
            roles,
            listen_addrs,
        } => {
            let mut state = state.write().await;
            state.nodes.insert(
                node_id.clone(),
                NodeEntry {
                    listen_addrs,
                    roles,
                    last_seen_unix_ms: now_unix_ms(),
                },
            );
            tracing::info!(via = %source, node = %node_id, "crawl node hello");
        }
        RadiiMessage::ReachabilityProbe { from, to, .. } => {
            tracing::info!(via = %source, from = %from, to = %to, "crawl probe");
        }
        RadiiMessage::ReachabilityReport {
            from,
            target,
            protocol,
            reachable,
            rtt_ms,
            observed_addr,
        } => {
            let mut state = state.write().await;
            state.reachability.push(RadiiMessage::ReachabilityReport {
                from: from.clone(),
                target: target.clone(),
                protocol: protocol.clone(),
                reachable,
                rtt_ms,
                observed_addr: observed_addr.clone(),
            });
            tracing::info!(
                via = %source,
                from = %from,
                target = %target,
                protocol = %protocol,
                reachable = reachable,
                "crawl report"
            );
        }
        _ => {
            tracing::info!(via = %source, "crawl wrapped message ignored");
        }
    }

    Ok(())
}

/// Node ids in `nodes` that are registered but haven't been heard from
/// within `node_ttl_ms`. Returns an empty set when `node_ttl_ms` is `None`
/// (liveness disabled) — a node that never sent a hello at all is not in
/// `nodes` in the first place and is therefore never "expired" by this
/// function; it's simply absent, exactly like today.
fn expired_node_ids(
    nodes: &HashMap<String, NodeEntry>,
    node_ttl_ms: Option<u64>,
    now_unix_ms: u64,
) -> HashSet<String> {
    let Some(ttl) = node_ttl_ms else {
        return HashSet::new();
    };
    nodes
        .iter()
        .filter(|(_, entry)| now_unix_ms.saturating_sub(entry.last_seen_unix_ms) > ttl)
        .map(|(node_id, _)| node_id.clone())
        .collect()
}

/// Builds the `(nodes, reports)` pair for a `GraphSnapshot` reply, excluding
/// expired nodes and any reachability report naming an expired node as
/// `from` or `target`. A report naming a node id that never sent a hello at
/// all (and so never appears in `nodes`) is *not* filtered here — that
/// matches today's behavior, where reachability doesn't require prior
/// registration (see `graph_routing.rs` in `crates/integration`, where
/// `head` reports reachability without ever sending its own hello).
fn graph_snapshot(state: &CrawlState, now_unix_ms: u64) -> (Vec<NodeInfo>, Vec<GraphReport>) {
    let expired = expired_node_ids(&state.nodes, state.node_ttl_ms, now_unix_ms);

    let nodes = state
        .nodes
        .iter()
        .filter(|(node_id, _)| !expired.contains(*node_id))
        .map(|(node_id, entry)| NodeInfo {
            node_id: node_id.clone(),
            listen_addrs: entry.listen_addrs.clone(),
            roles: entry.roles.clone(),
        })
        .collect();

    let reports = state
        .reachability
        .iter()
        .filter_map(|message| match message {
            RadiiMessage::ReachabilityReport {
                from,
                target,
                protocol,
                reachable,
                rtt_ms,
                ..
            } => {
                if expired.contains(from) || expired.contains(target) {
                    None
                } else {
                    Some(GraphReport {
                        from: from.clone(),
                        target: target.clone(),
                        protocol: protocol.clone(),
                        reachable: *reachable,
                        rtt_ms: *rtt_ms,
                    })
                }
            }
            _ => None,
        })
        .collect();

    (nodes, reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(roles: Vec<&str>, last_seen_unix_ms: u64) -> NodeEntry {
        NodeEntry {
            listen_addrs: vec!["127.0.0.1:1".to_string()],
            roles: roles.into_iter().map(String::from).collect(),
            last_seen_unix_ms,
        }
    }

    #[test]
    fn no_ttl_means_nothing_expires() {
        let mut nodes = HashMap::new();
        nodes.insert("a".to_string(), entry(vec![], 0));
        assert!(expired_node_ids(&nodes, None, 1_000_000).is_empty());
    }

    #[test]
    fn node_past_ttl_is_expired() {
        let mut nodes = HashMap::new();
        nodes.insert("fresh".to_string(), entry(vec![], 9_000));
        nodes.insert("stale".to_string(), entry(vec![], 0));
        let expired = expired_node_ids(&nodes, Some(5_000), 10_000);
        assert!(expired.contains("stale"));
        assert!(!expired.contains("fresh"));
    }

    #[test]
    fn graph_snapshot_carries_roles() {
        let mut state = CrawlState::default();
        state
            .nodes
            .insert("wave-a".to_string(), entry(vec!["wave"], 0));
        let (nodes, _) = graph_snapshot(&state, 0);
        let node = nodes.iter().find(|n| n.node_id == "wave-a").unwrap();
        assert_eq!(node.roles, vec!["wave".to_string()]);
    }

    #[test]
    fn graph_snapshot_excludes_expired_node_and_its_reports() {
        let mut state = CrawlState {
            node_ttl_ms: Some(5_000),
            ..CrawlState::default()
        };
        state.nodes.insert("fresh".to_string(), entry(vec![], 9_000));
        state.nodes.insert("stale".to_string(), entry(vec![], 0));
        state.reachability.push(RadiiMessage::ReachabilityReport {
            from: "fresh".to_string(),
            target: "stale".to_string(),
            protocol: "http".to_string(),
            reachable: true,
            rtt_ms: Some(10),
            observed_addr: None,
        });

        let (nodes, reports) = graph_snapshot(&state, 10_000);
        assert!(nodes.iter().all(|n| n.node_id != "stale"));
        assert!(nodes.iter().any(|n| n.node_id == "fresh"));
        assert!(
            reports.is_empty(),
            "report naming an expired node must be dropped"
        );
    }

    #[test]
    fn graph_snapshot_keeps_reports_for_unregistered_node_ids() {
        // "head" never sends its own hello (matches crates/integration's
        // graph_routing.rs) — a report naming it must still come through.
        let mut state = CrawlState::default();
        state
            .nodes
            .insert("node-b".to_string(), entry(vec!["resource"], 0));
        state.reachability.push(RadiiMessage::ReachabilityReport {
            from: "head".to_string(),
            target: "node-b".to_string(),
            protocol: "http".to_string(),
            reachable: true,
            rtt_ms: Some(12),
            observed_addr: None,
        });

        let (_, reports) = graph_snapshot(&state, 0);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].from, "head");
    }
}
