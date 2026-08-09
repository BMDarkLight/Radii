use radii_proto::{read_message, write_message, RadiiMessage};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

#[derive(Default)]
pub struct CrawlState {
    pub nodes: HashMap<String, Vec<String>>,
    pub reachability: Vec<RadiiMessage>,
}

pub async fn run(bind: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, "crawl listening");
    let state = Arc::new(RwLock::new(CrawlState::default()));

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, addr, state).await {
                tracing::warn!(source = %addr, error = %err, "crawl connection failed");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    state: Arc<RwLock<CrawlState>>,
) -> anyhow::Result<()> {
    loop {
        let message = read_message(&mut stream).await?;
        match message {
            RadiiMessage::NodeHello {
                node_id,
                listen_addrs,
                ..
            } => {
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
