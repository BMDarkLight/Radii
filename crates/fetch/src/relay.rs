//! The relay listener: the only surface on which a node accepts a chain.
//!
//! It is separate from the tunnel listener because that one carries raw bytes
//! with no framing, so a `TunnelOpen` preamble cannot be read there without
//! breaking every existing plain client. Keeping it separate also makes relay
//! capability independently firewall-able, which matters when its whole
//! purpose is exposure to peers the operator does not run.

use crate::config::RelayConfig;
use anyhow::{bail, Context, Result};
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

    forward(inbound, hops, runtime).await
}

/// Local, cheap checks made before any dialing happens. Ordered to avoid
/// work: length and addressing before the duplicate scan.
fn validate(hops: &[RouteHop], config: &RelayConfig) -> Result<(), &'static str> {
    if hops.len() > config.max_hops {
        return Err("tunnel_too_long");
    }
    let Some(first) = hops.first() else {
        return Err("tunnel_misaddressed");
    };
    if first.node_id != config.node_id {
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
///
/// At chain length one the originator IS the authenticated TCP peer, so the
/// outer mTLS on the relay listener covers it. Now that chains can be longer
/// than one hop, that stops being true here: this node's direct peer is the
/// previous hop, not the originator, and the inner end-to-end session
/// accepted below is the only remaining proof of who the originator is. A
/// terminal node running with `tunnel_listener_tls = None` therefore accepts
/// an unauthenticated originator relayed from anywhere. This function does
/// not enforce anything about that — it is a later decision — but a terminal
/// node MUST configure `[tunnel_tls.listener]` once forwarding is in use.
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

/// This node is an intermediate hop: dial the next one, pass the tail along,
/// relay its answer back, then carry opaque bytes in both directions.
///
/// Nothing here inspects the payload. The initiator's end-to-end session runs
/// inside this pipe, so what crosses it is ciphertext this node cannot read.
///
/// The path is pinned by the originator: this node forwards the tail it was
/// handed rather than re-planning the next hop from its own view of the
/// network. The originator ranked these routes and will retry a different
/// one if this fails, which only works if intermediate nodes never silently
/// substitute their own choices — and verifying the next hop against a node
/// id the originator chose means a poisoned local view here cannot redirect
/// the chain.
async fn forward(
    mut inbound: BoxedStream,
    hops: Vec<RouteHop>,
    runtime: Arc<RelayRuntime>,
) -> Result<()> {
    let Some(next) = hops.get(1) else {
        bail!("forward called with a chain shorter than two hops");
    };

    let outbound = radii_proto::tls::dial_expecting(
        &next.addr,
        Some(&runtime.identity),
        Some(&next.node_id),
    )
    .await;

    let mut outbound = match outbound {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(
                next = %next.node_id,
                addr = %next.addr,
                error = %err,
                "relay could not reach the next hop"
            );
            return refuse(&mut inbound, "tunnel_hop_unreachable").await;
        }
    };

    write_message(
        &mut outbound,
        &RadiiMessage::TunnelOpen {
            hops: hops[1..].to_vec(),
        },
    )
    .await?;

    // One frame back — the terminal node's ack, or a refusal from any hop
    // downstream — then the pipe goes opaque.
    let ack = read_message(&mut outbound).await?;
    write_message(&mut inbound, &ack).await?;
    if !matches!(&ack, RadiiMessage::Ack { status } if status == "tunnel_ready") {
        return Ok(());
    }

    splice(inbound, outbound).await
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
