//! The relay listener: the only surface on which a node accepts a chain.
//!
//! It is separate from the tunnel listener because that one carries raw bytes
//! with no framing, so a `TunnelOpen` preamble cannot be read there without
//! breaking every existing plain client. Keeping it separate also makes relay
//! capability independently firewall-able, which matters when its whole
//! purpose is exposure to peers the operator does not run.

use crate::config::RelayConfig;
use anyhow::{Context, Result};
use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, BoxedStream, RadiiMessage, RouteHop};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

pub struct RelayRuntime {
    pub config: RelayConfig,
    identity: TlsIdentity,
    upstream: String,
    tunnel_listener_tls: Option<TlsIdentity>,
}

impl RelayRuntime {
    pub fn new(
        config: RelayConfig,
        upstream: String,
        tunnel_listener_tls: Option<TlsIdentity>,
    ) -> Result<Arc<Self>> {
        let tls = config
            .tls
            .as_ref()
            .context("[relay.tls] is required for the relay listener")?;
        let identity = TlsIdentity::load(tls)?;
        Ok(Arc::new(Self {
            config,
            identity,
            upstream,
            tunnel_listener_tls,
        }))
    }
}

pub async fn run(listener: TcpListener, runtime: Arc<RelayRuntime>) -> Result<()> {
    tracing::info!(
        bind = %runtime.config.bind,
        node_id = %runtime.config.node_id,
        "relay listening"
    );
    loop {
        let (stream, addr) = listener.accept().await?;
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            if let Err(err) = handle(stream, addr, runtime).await {
                tracing::warn!(source = %addr, error = %err, "relay connection failed");
            }
        });
    }
}

async fn handle(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    runtime: Arc<RelayRuntime>,
) -> Result<()> {
    let (mut inbound, peer) = radii_proto::tls::accept(stream, Some(&runtime.identity)).await?;
    let peer = peer.context("relay listener requires mutual TLS")?;

    let hops = match read_message(&mut inbound).await? {
        RadiiMessage::TunnelOpen { hops } => hops,
        other => {
            tracing::warn!(source = %addr, ?other, "relay expected a TunnelOpen");
            return refuse(&mut inbound, "expected_tunnel_open").await;
        }
    };

    if let Err(status) = validate(&hops, &runtime.config) {
        tracing::warn!(source = %addr, peer = %peer, status, "relay refused a chain");
        return refuse(&mut inbound, status).await;
    }

    if hops.len() == 1 {
        return terminate(inbound, runtime).await;
    }

    // Forwarding lands in Task 7. Until then a multi-hop chain is refused
    // rather than silently mishandled.
    refuse(&mut inbound, "relay_forwarding_unavailable").await
}

/// Local, cheap checks made before any dialing happens. Ordered to avoid
/// work: length and addressing before the duplicate scan.
fn validate(hops: &[RouteHop], config: &RelayConfig) -> Result<(), &'static str> {
    if hops.len() > config.max_hops {
        return Err("tunnel_too_long");
    }
    if hops[0].node_id != config.node_id {
        return Err("tunnel_misaddressed");
    }
    let mut seen = std::collections::HashSet::new();
    if !hops.iter().all(|hop| seen.insert(&hop.node_id)) {
        return Err("tunnel_path_loops");
    }
    Ok(())
}

async fn refuse(stream: &mut BoxedStream, status: &str) -> Result<()> {
    write_message(
        stream,
        &RadiiMessage::Ack {
            status: status.to_string(),
        },
    )
    .await
}

/// This node is the chain's last hop: ack, then run the end-to-end session
/// and splice it to the configured upstream.
async fn terminate(mut inbound: BoxedStream, runtime: Arc<RelayRuntime>) -> Result<()> {
    write_message(
        &mut inbound,
        &RadiiMessage::Ack {
            status: "tunnel_ready".to_string(),
        },
    )
    .await?;

    let (e2e, initiator) =
        radii_proto::tls::accept_on(inbound, runtime.tunnel_listener_tls.as_ref()).await?;
    tracing::info!(
        initiator = ?initiator,
        upstream = %runtime.upstream,
        "relay terminating a chain"
    );

    let upstream =
        tokio::net::TcpStream::connect(crate::server::normalize_upstream(&runtime.upstream))
            .await?;
    splice(e2e, Box::new(upstream)).await
}

pub(crate) async fn splice(a: BoxedStream, b: BoxedStream) -> Result<()> {
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    tokio::try_join!(
        tokio::io::copy(&mut ar, &mut bw),
        tokio::io::copy(&mut br, &mut aw)
    )?;
    Ok(())
}
