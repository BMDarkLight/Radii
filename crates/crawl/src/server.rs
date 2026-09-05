use radii_proto::tls::TlsIdentity;
use radii_proto::{
    read_message, write_message, BoxedStream, GraphReport, NodeInfo, RadiiMessage, RelayedMessage,
};
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

/// Ceilings on how much reachability state peers can make Crawl hold.
///
/// The per-peer ceiling matters as much as the global one: with only a global
/// cap, a single peer reporting about invented targets fills the table and
/// starves honest peers out of it.
pub const MAX_REACHABILITY_ENTRIES: usize = 16_384;
pub const MAX_REACHABILITY_ENTRIES_PER_PEER: usize = 1_024;

#[derive(Debug, Clone)]
pub struct NodeEntry {
    pub listen_addrs: Vec<String>,
    pub roles: Vec<String>,
    pub last_seen_unix_ms: u64,
}

/// Identifies one observation: who observed it, about what, over which
/// protocol. A fresh report for the same key replaces the old one rather than
/// accumulating beside it — re-sending a report is a heartbeat, not new
/// information, so it must not grow the table.
pub type ReachabilityKey = (String, String, String);

/// One peer's most recent observation about one target and protocol.
#[derive(Debug, Clone)]
pub struct ReachabilityEntry {
    pub reachable: bool,
    pub rtt_ms: Option<u32>,
    pub observed_addr: Option<String>,
    pub last_seen_unix_ms: u64,
}

#[derive(Default, Debug)]
pub struct CrawlState {
    pub nodes: HashMap<String, NodeEntry>,
    /// Keyed rather than appended, and capped. This used to be a `Vec` that
    /// only ever grew: every heartbeat from every peer appended a duplicate,
    /// nothing expired, and each `GraphQuery` cloned the whole thing — while
    /// also being the input to route planning, which is super-linear in it.
    pub reachability: HashMap<ReachabilityKey, ReachabilityEntry>,
    /// `None` means entries never expire (today's behavior, and the default
    /// via `CrawlState::default()`). `Some(ttl)` drops a node *and* a stale
    /// observation from `GraphQuery` replies once
    /// `now - last_seen_unix_ms > ttl`. `NodeHello` and `ReachabilityReport`
    /// are both heartbeats, so one freshness window governs both.
    pub node_ttl_ms: Option<u64>,
    /// Authenticated node ids allowed to relay `FromHead` envelopes. Empty
    /// (the default) means nobody may relay over an authenticated
    /// connection. See `Config::relay_peers`.
    pub relay_peers: HashSet<String>,
}

impl CrawlState {
    /// Records one observation, replacing any previous one from the same peer
    /// about the same target and protocol.
    ///
    /// Returns `false` when the report was refused because the table is full.
    /// A refusal only ever affects a *new* key: an update to an existing entry
    /// costs no growth and is always accepted, so a peer that keeps its
    /// existing reports fresh is never rejected.
    pub fn record_report(&mut self, key: ReachabilityKey, entry: ReachabilityEntry) -> bool {
        if let Some(existing) = self.reachability.get_mut(&key) {
            *existing = entry;
            return true;
        }

        if self.reachability.len() >= MAX_REACHABILITY_ENTRIES {
            self.expire_reports(entry.last_seen_unix_ms);
        }
        if self.reachability.len() >= MAX_REACHABILITY_ENTRIES {
            return false;
        }

        // Counted on demand rather than tracked incrementally: this runs only
        // when a peer introduces a key it has never reported before, which is
        // rare once a mesh has settled, and it keeps one source of truth.
        let from = &key.0;
        let peer_entries = self
            .reachability
            .keys()
            .filter(|(candidate, _, _)| candidate == from)
            .count();
        if peer_entries >= MAX_REACHABILITY_ENTRIES_PER_PEER {
            return false;
        }

        self.reachability.insert(key, entry);
        true
    }

    /// Drops observations older than the configured TTL. No-op when liveness
    /// is disabled.
    fn expire_reports(&mut self, now_unix_ms: u64) {
        let Some(ttl) = self.node_ttl_ms else {
            return;
        };
        self.reachability
            .retain(|_, entry| now_unix_ms.saturating_sub(entry.last_seen_unix_ms) <= ttl);
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub async fn run(
    bind: &str,
    tls: Option<TlsIdentity>,
    node_ttl_ms: Option<u64>,
    relay_peers: HashSet<String>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(
        %bind,
        tls = tls.is_some(),
        relay_peers = relay_peers.len(),
        "crawl listening"
    );
    run_on(listener, tls, node_ttl_ms, relay_peers).await
}

pub async fn run_on(
    listener: TcpListener,
    tls: Option<TlsIdentity>,
    node_ttl_ms: Option<u64>,
    relay_peers: HashSet<String>,
) -> anyhow::Result<()> {
    let state = Arc::new(RwLock::new(CrawlState {
        node_ttl_ms,
        relay_peers,
        ..CrawlState::default()
    }));
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

/// Whether an authenticated peer may relay `FromHead` envelopes at all.
///
/// Relaying is the right to speak for *other* nodes, so it is granted by
/// operator configuration rather than inferred. In particular it cannot be
/// inferred from a peer's advertised roles: roles arrive in that peer's own
/// `NodeHello`, so a peer claiming `roles = ["head"]` is asserting the very
/// thing being checked. Plaintext connections have no identity to match and
/// keep today's unauthenticated behavior, like direct messages do.
fn authorized_relay_peer(peer_identity: &Option<String>, relay_peers: &HashSet<String>) -> bool {
    match peer_identity {
        Some(identity) => relay_peers.contains(identity),
        None => true,
    }
}

/// Whether a relayed message's inner claim is backed by the identity the Head
/// authenticated for its own client.
///
/// The envelope's `source` field is free text chosen by the relaying peer and
/// is deliberately not consulted. On an authenticated connection the claim
/// must match `client_identity`, which means an unauthenticated bridge client
/// (`client_identity: None`) cannot write state through a Head — end-to-end
/// authentication is required, not just Head-to-Crawl authentication.
fn authorized_relayed_claim(
    peer_identity: &Option<String>,
    client_identity: &Option<String>,
    claimed_node_id: &str,
) -> bool {
    match peer_identity {
        Some(_) => client_identity.as_deref() == Some(claimed_node_id),
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
                let accepted = state.record_report(
                    (from.clone(), target.clone(), protocol.clone()),
                    ReachabilityEntry {
                        reachable,
                        rtt_ms,
                        observed_addr: observed_addr.clone(),
                        last_seen_unix_ms: now_unix_ms(),
                    },
                );
                drop(state);
                if !accepted {
                    tracing::warn!(
                        source = %addr,
                        from = %from,
                        target = %target,
                        "crawl dropped report: reachability table is full"
                    );
                    write_message(
                        &mut stream,
                        &RadiiMessage::Ack {
                            status: "reachability_table_full".to_string(),
                        },
                    )
                    .await?;
                    continue;
                }
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
            RadiiMessage::FromHead {
                source,
                client_identity,
                message,
            } => {
                let relay_allowed = {
                    let guard = state.read().await;
                    authorized_relay_peer(&peer_identity, &guard.relay_peers)
                };
                if !relay_allowed {
                    tracing::warn!(
                        source = %addr,
                        peer = ?peer_identity,
                        via = %source,
                        "crawl rejected relay: peer is not a configured relay_peer"
                    );
                    write_message(
                        &mut stream,
                        &RadiiMessage::Ack {
                            status: "unauthorized_relay_peer".to_string(),
                        },
                    )
                    .await?;
                    continue;
                }

                if let Some(claimed) = message.claimed_node_id() {
                    if !authorized_relayed_claim(&peer_identity, &client_identity, claimed) {
                        tracing::warn!(
                            source = %addr,
                            peer = ?peer_identity,
                            client = ?client_identity,
                            claimed = %claimed,
                            "crawl rejected relayed message: claim does not match the \
                             identity the head authenticated for its client"
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
                }

                tracing::info!(source = %source, client = ?client_identity, "crawl message via head");
                handle_wrapped_message(message, &state, source.clone()).await;
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

/// Applies an already-authorized relayed message to the graph.
///
/// Authorization happens at the call site, against the connection's peer
/// identity and the envelope's `client_identity`; this function assumes that
/// check has passed. Taking a [`RelayedMessage`] rather than a
/// `RadiiMessage` is what keeps the two in step — the type cannot represent a
/// nested envelope or a `GraphQuery`, so there is no catch-all arm here that
/// could silently grow a new unauthorized path the way the previous
/// `_ => {}` did.
async fn handle_wrapped_message(
    message: RelayedMessage,
    state: &Arc<RwLock<CrawlState>>,
    source: String,
) {
    match message {
        RelayedMessage::NodeHello {
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
        RelayedMessage::ReachabilityProbe { from, to, .. } => {
            tracing::info!(via = %source, from = %from, to = %to, "crawl probe");
        }
        RelayedMessage::ReachabilityReport {
            from,
            target,
            protocol,
            reachable,
            rtt_ms,
            observed_addr,
        } => {
            let mut state = state.write().await;
            let accepted = state.record_report(
                (from.clone(), target.clone(), protocol.clone()),
                ReachabilityEntry {
                    reachable,
                    rtt_ms,
                    observed_addr,
                    last_seen_unix_ms: now_unix_ms(),
                },
            );
            drop(state);
            if !accepted {
                tracing::warn!(
                    via = %source,
                    from = %from,
                    target = %target,
                    "crawl dropped relayed report: reachability table is full"
                );
                return;
            }
            tracing::info!(
                via = %source,
                from = %from,
                target = %target,
                protocol = %protocol,
                reachable = reachable,
                "crawl report"
            );
        }
    }
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
        .filter(|((from, target, _), entry)| {
            // Drop an observation if either endpoint has gone quiet, or if the
            // observation itself is stale — a peer that stopped probing should
            // not keep a link alive in the graph indefinitely.
            let endpoint_expired = expired.contains(from) || expired.contains(target);
            let report_expired = state
                .node_ttl_ms
                .is_some_and(|ttl| now_unix_ms.saturating_sub(entry.last_seen_unix_ms) > ttl);
            !endpoint_expired && !report_expired
        })
        .map(|((from, target, protocol), entry)| GraphReport {
            from: from.clone(),
            target: target.clone(),
            protocol: protocol.clone(),
            reachable: entry.reachable,
            rtt_ms: entry.rtt_ms,
        })
        .collect();

    (nodes, reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report_entry(last_seen_unix_ms: u64) -> ReachabilityEntry {
        ReachabilityEntry {
            reachable: true,
            rtt_ms: Some(10),
            observed_addr: None,
            last_seen_unix_ms,
        }
    }

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
        state
            .nodes
            .insert("fresh".to_string(), entry(vec![], 9_000));
        state.nodes.insert("stale".to_string(), entry(vec![], 0));
        state.record_report(
            ("fresh".to_string(), "stale".to_string(), "http".to_string()),
            report_entry(10_000),
        );

        let (nodes, reports) = graph_snapshot(&state, 10_000);
        assert!(nodes.iter().all(|n| n.node_id != "stale"));
        assert!(nodes.iter().any(|n| n.node_id == "fresh"));
        assert!(
            reports.is_empty(),
            "report naming an expired node must be dropped"
        );
    }

    /// The heartbeat case that used to grow the table without bound: the same
    /// peer re-reporting the same link forever must cost exactly one entry.
    #[test]
    fn repeated_reports_replace_rather_than_accumulate() {
        let mut state = CrawlState::default();
        let key = ("a".to_string(), "b".to_string(), "http".to_string());
        for tick in 0..1_000 {
            assert!(state.record_report(key.clone(), report_entry(tick)));
        }
        assert_eq!(state.reachability.len(), 1);
        assert_eq!(
            state.reachability[&key].last_seen_unix_ms, 999,
            "the newest observation should win"
        );
    }

    /// One peer must not be able to fill the whole table and starve others.
    #[test]
    fn a_single_peer_cannot_exhaust_the_table() {
        let mut state = CrawlState::default();
        let mut accepted = 0;
        for i in 0..(MAX_REACHABILITY_ENTRIES_PER_PEER + 500) {
            if state.record_report(
                ("noisy".to_string(), format!("t{i}"), "http".to_string()),
                report_entry(0),
            ) {
                accepted += 1;
            }
        }
        assert_eq!(accepted, MAX_REACHABILITY_ENTRIES_PER_PEER);

        // An honest peer still gets in.
        assert!(state.record_report(
            ("honest".to_string(), "b".to_string(), "http".to_string()),
            report_entry(0),
        ));
    }

    /// A stale observation must drop out of the graph even when both of its
    /// endpoints are still sending hellos.
    #[test]
    fn graph_snapshot_drops_a_stale_report_between_live_nodes() {
        let mut state = CrawlState {
            node_ttl_ms: Some(5_000),
            ..CrawlState::default()
        };
        state.nodes.insert("a".to_string(), entry(vec![], 10_000));
        state.nodes.insert("b".to_string(), entry(vec![], 10_000));
        state.record_report(
            ("a".to_string(), "b".to_string(), "http".to_string()),
            report_entry(0),
        );

        let (nodes, reports) = graph_snapshot(&state, 10_000);
        assert_eq!(nodes.len(), 2, "both nodes are still live");
        assert!(
            reports.is_empty(),
            "an observation older than the TTL must not keep a link alive"
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
        state.record_report(
            ("head".to_string(), "node-b".to_string(), "http".to_string()),
            report_entry(0),
        );

        let (_, reports) = graph_snapshot(&state, 0);
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].from, "head");
    }
}
