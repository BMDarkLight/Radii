use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, BoxedStream, GraphReport, NodeInfo, RadiiMessage};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

#[derive(Default, Debug)]
pub struct CrawlState {
    pub nodes: HashMap<String, Vec<String>>,
    pub reachability: Vec<RadiiMessage>,
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
                listen_addrs,
                ..
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
                state.nodes.insert(node_id.clone(), listen_addrs.clone());
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
                let nodes = guard
                    .nodes
                    .iter()
                    .map(|(node_id, listen_addrs)| NodeInfo {
                        node_id: node_id.clone(),
                        listen_addrs: listen_addrs.clone(),
                    })
                    .collect();
                let reports = guard
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
                        } => Some(GraphReport {
                            from: from.clone(),
                            target: target.clone(),
                            protocol: protocol.clone(),
                            reachable: *reachable,
                            rtt_ms: *rtt_ms,
                        }),
                        _ => None,
                    })
                    .collect();
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
            listen_addrs,
            ..
        } => {
            let mut state = state.write().await;
            state.nodes.insert(node_id.clone(), listen_addrs);
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
