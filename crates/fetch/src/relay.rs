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
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::time::timeout;

/// The closed vocabulary of `Ack.status` values this relay understands,
/// whether generated locally or received from a downstream hop.
///
/// A downstream hop's ack is relayed upstream, so its status cannot be
/// passed through as opaque, attacker-controlled bytes: a compromised or
/// merely misbehaving next hop could otherwise return up to `MAX_FRAME_LEN`
/// of arbitrary text — newlines, ANSI escapes, anything — and have it logged
/// verbatim by every upstream hop and the originator. The vocabulary here is
/// closed, so an allowlist is the right shape rather than a length cap.
const KNOWN_ACK_STATUSES: &[&str] = &[
    "tunnel_ready",
    "tunnel_misaddressed",
    "tunnel_too_long",
    "tunnel_path_loops",
    "tunnel_hop_unreachable",
    "relay_forwarding_unavailable",
    "expected_tunnel_open",
    // Admission refusals. These must be listed here, not only generated
    // locally: on a multi-hop chain an admission refusal from a downstream
    // hop is relayed upstream, and anything outside this vocabulary is
    // flattened to `UNKNOWN_DOWNSTREAM_STATUS` — which would destroy the
    // reason exactly when the originator needs it to choose another route.
    "relay_forbidden",
    "relay_busy",
    UNKNOWN_DOWNSTREAM_STATUS,
];

/// Substituted for any `Ack.status` a downstream hop returns that is not in
/// [`KNOWN_ACK_STATUSES`], and for any frame it returns that is not an `Ack`
/// at all. Included in [`KNOWN_ACK_STATUSES`] itself so it survives
/// unchanged if relayed through a further upstream hop.
const UNKNOWN_DOWNSTREAM_STATUS: &str = "relay_downstream_status_unrecognised";

pub struct RelayRuntime {
    pub config: RelayConfig,
    identity: TlsIdentity,
    upstream: String,
    tunnel_listener_tls: Option<TlsIdentity>,
    live: Mutex<Live>,
}

/// Chains currently being carried, counted in total and per authenticated
/// peer. The per-peer tally is the load-bearing half: with admission open to
/// any CA-valid peer, a global cap alone lets one identity take every slot.
#[derive(Default)]
struct Live {
    total: usize,
    per_peer: HashMap<String, usize>,
}

/// Holds one chain's slot. Releasing on `Drop` rather than at an explicit
/// call site is deliberate: a chain can end by refusal, by error, by timeout,
/// or by either side closing mid-splice, and a slot that leaks on any of
/// those paths turns the cap into a permanent lockout after
/// `max_concurrent_per_peer` connections.
pub struct Permit {
    runtime: Arc<RelayRuntime>,
    peer: String,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut live = self.runtime.live.lock().expect("relay accounting poisoned");
        live.total = live.total.saturating_sub(1);
        if let Some(count) = live.per_peer.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                // Drop the entry rather than leaving a zero behind, so the
                // map tracks live peers instead of every peer ever seen.
                live.per_peer.remove(&self.peer);
            }
        }
    }
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
            live: Mutex::new(Live::default()),
        }))
    }

    /// Admission is CA membership — holding a certificate this relay's CA
    /// signed — narrowed to an explicit list when the operator sets one.
    /// An empty `allow_peers` is the open, donated-node posture, not a
    /// closed door.
    ///
    /// `peer` is always the inbound mTLS peer on THIS hop — the previous
    /// node in the chain, not necessarily the chain's originator. At chain
    /// length one those are the same identity, so `allow_peers` really does
    /// restrict who may originate a chain here. Beyond one hop they are not:
    /// `peer` is the upstream relay that forwarded the request, and
    /// `allow_peers` narrows who may *hand this node a chain*, not who may
    /// *originate* one — an operator wanting to restrict origination on a
    /// multi-hop terminal gets no such restriction from this check. The
    /// chain's actual originator is authenticated separately, by the
    /// end-to-end session established in `terminate`/accepted via
    /// `tunnel_listener_tls`, not by this admission check.
    fn admits(&self, peer: &str) -> bool {
        self.config.allow_peers.is_empty() || self.config.allow_peers.iter().any(|id| id == peer)
    }

    /// Takes a slot for `peer`, or `None` when either cap is already met.
    fn acquire(self: &Arc<Self>, peer: &str) -> Option<Permit> {
        let mut live = self.live.lock().expect("relay accounting poisoned");
        if live.total >= self.config.max_concurrent_total {
            return None;
        }
        let count = live.per_peer.entry(peer.to_string()).or_insert(0);
        if *count >= self.config.max_concurrent_per_peer {
            // Leave the entry as-is; it is already non-zero by definition.
            return None;
        }
        *count += 1;
        live.total += 1;
        Some(Permit {
            runtime: Arc::clone(self),
            peer: peer.to_string(),
        })
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

/// Every await before the splice is a peer waiting on this relay, or this
/// relay waiting on some other peer — the inbound mTLS accept, the inbound
/// `TunnelOpen`, dialing and handshaking the next hop, and its ack. None of
/// that is bounded by anything else in the system: a peer holding a valid
/// mesh certificate can authenticate correctly and then simply never speak
/// again, holding a task and up to two TLS sessions open at zero cost to
/// itself. So the whole pre-splice window is wrapped in one timeout here;
/// the splice itself is deliberately outside it; a long-lived tunnel is
/// legitimate; `idle_timeout_ms` bounds its idleness separately.
async fn handle(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    runtime: Arc<RelayRuntime>,
) -> Result<()> {
    let bound = Duration::from_millis(runtime.config.handshake_timeout_ms);
    match timeout(bound, handshake(stream, addr, Arc::clone(&runtime))).await {
        Ok(outcome) => match outcome? {
            // The permit is carried out of the handshake and held for the
            // whole splice. Dropping it when the handshake returned would
            // free the slot the instant a chain came up, which is precisely
            // when the chain starts consuming resources — the cap would
            // count handshakes rather than live chains and bound nothing.
            Some((a, b, permit)) => {
                let idle = Duration::from_millis(runtime.config.idle_timeout_ms.max(1));
                let result = splice_with_idle(a, b, idle).await;
                drop(permit);
                result
            }
            None => Ok(()),
        },
        Err(_elapsed) => {
            tracing::warn!(
                source = %addr,
                handshake_timeout_ms = runtime.config.handshake_timeout_ms,
                "relay handshake did not complete before its bound; dropping the connection"
            );
            Ok(())
        }
    }
}

/// Runs the whole pre-splice handshake and returns the pair of streams to
/// splice, or `None` when the connection was refused or otherwise ends
/// before ever reaching a splice.
async fn handshake(
    stream: tokio::net::TcpStream,
    addr: SocketAddr,
    runtime: Arc<RelayRuntime>,
) -> Result<Option<(BoxedStream, BoxedStream, Permit)>> {
    let (mut inbound, peer) = radii_proto::tls::accept(stream, Some(&runtime.identity)).await?;
    let peer = peer.context("relay listener requires mutual TLS")?;

    let hops = match read_message(&mut inbound).await? {
        RadiiMessage::TunnelOpen { hops } => hops,
        other => {
            tracing::warn!(source = %addr, ?other, "relay expected a TunnelOpen");
            refuse(&mut inbound, "expected_tunnel_open").await?;
            return Ok(None);
        }
    };

    // Admission and accounting run only after the client's frame has been
    // read. Refusing earlier means closing while the peer is still writing
    // that frame, and the resulting connection reset reaches it instead of
    // the status — so the peer learns only that something failed, never
    // that it was forbidden or that the relay was full. The read is bounded
    // by the handshake timeout, so hearing an unadmitted peer out first
    // costs nothing unbounded.
    if !runtime.admits(&peer) {
        tracing::warn!(source = %addr, peer = %peer, "relay refused an unadmitted peer");
        refuse(&mut inbound, "relay_forbidden").await?;
        return Ok(None);
    }

    let Some(permit) = runtime.acquire(&peer) else {
        tracing::warn!(
            source = %addr,
            peer = %peer,
            max_concurrent_total = runtime.config.max_concurrent_total,
            max_concurrent_per_peer = runtime.config.max_concurrent_per_peer,
            "relay at capacity"
        );
        refuse(&mut inbound, "relay_busy").await?;
        return Ok(None);
    };

    if let Err(status) = validate(&hops, &runtime.config) {
        tracing::warn!(source = %addr, peer = %peer, status, "relay refused a chain");
        refuse(&mut inbound, status).await?;
        return Ok(None);
    }

    let pair = if hops.len() == 1 {
        terminate(inbound, runtime).await?
    } else {
        forward(inbound, hops, runtime).await?
    };

    // `permit` drops here on any path that never reaches a splice.
    Ok(pair.map(|(a, b)| (a, b, permit)))
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

/// Writes a refusal and closes the write side gracefully.
///
/// The shutdown matters: dropping the stream straight after the write lets
/// the socket close before the peer has read the frame, and the peer then
/// sees a connection reset instead of the status. A refusal the peer cannot
/// read is indistinguishable from a crash, and the whole point of a status
/// vocabulary is that the other end learns *why*.
async fn refuse(stream: &mut BoxedStream, status: &str) -> Result<()> {
    write_message(
        stream,
        &RadiiMessage::Ack {
            status: status.to_string(),
        },
    )
    .await?;
    // Best-effort: the peer may already be gone, and that is not an error
    // worth failing the connection over — the refusal is what mattered.
    let _ = tokio::io::AsyncWriteExt::shutdown(stream).await;
    Ok(())
}

/// This node is the chain's last hop: dial its own upstream FIRST, then ack,
/// then run the end-to-end session and splice it to that upstream.
///
/// The upstream dial has to happen before the ack. `chain::establish` treats
/// an `Ack{tunnel_ready}` as proof the chain is usable and stops retrying
/// other candidates the moment it sees one — so acking before this node has
/// actually reached its own backend would let a terminal with a dead backend
/// consume the candidate and never be failed over, which is exactly the
/// common case (a backend outage) source routing exists to route around. On
/// a failed dial this refuses with `tunnel_hop_unreachable` instead of
/// acking, so the originator retries the next candidate.
///
/// The ack still comes before the inner TLS accept: the originator waits for
/// it before starting that handshake, so acking any later would deadlock
/// against a peer that is correctly waiting on us.
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
async fn terminate(
    mut inbound: BoxedStream,
    runtime: Arc<RelayRuntime>,
) -> Result<Option<(BoxedStream, BoxedStream)>> {
    let upstream = match tokio::net::TcpStream::connect(crate::server::normalize_upstream(
        &runtime.upstream,
    ))
    .await
    {
        Ok(stream) => stream,
        Err(err) => {
            tracing::warn!(
                upstream = %runtime.upstream,
                error = %err,
                "relay terminal could not reach its own upstream"
            );
            refuse(&mut inbound, "tunnel_hop_unreachable").await?;
            return Ok(None);
        }
    };

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

    Ok(Some((e2e, Box::new(upstream))))
}

/// This node is an intermediate hop: dial the next one, pass the tail along,
/// relay its answer back, then carry opaque bytes in both directions.
///
/// Nothing here inspects the payload. When the originator and the terminal
/// both have `[tunnel_tls]` identities configured, the end-to-end session
/// runs inside this pipe, so what crosses it is ciphertext this node cannot
/// read. That holds only when those identities are actually configured —
/// absent them, `tls::connect_on`/`accept_on` fall back to plaintext, and the
/// chain this node forwards is cleartext, readable by this node and any
/// other relay carrying it. See `config::graph_without_e2e_tls_warning`.
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
) -> Result<Option<(BoxedStream, BoxedStream)>> {
    let Some(next) = hops.get(1) else {
        bail!("forward called with a chain shorter than two hops");
    };

    let outbound =
        radii_proto::tls::dial_expecting(&next.addr, Some(&runtime.identity), Some(&next.node_id))
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
            refuse(&mut inbound, "tunnel_hop_unreachable").await?;
            return Ok(None);
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
    // downstream — then the pipe goes opaque. From here the next hop is
    // untrusted: only an `Ack` is ever relayed upstream, and only with a
    // status this relay recognises. Any other variant, or a status outside
    // the closed vocabulary, becomes one fixed local code instead of being
    // passed upstream byte-for-byte — see `KNOWN_ACK_STATUSES`. The
    // tunnel_ready check below runs against that sanitised status, never
    // against whatever the next hop actually sent.
    let ack = read_message(&mut outbound).await?;
    let status = match ack {
        RadiiMessage::Ack { status } if KNOWN_ACK_STATUSES.contains(&status.as_str()) => status,
        RadiiMessage::Ack { status } => {
            tracing::warn!(
                next = %next.node_id,
                status_len = status.len(),
                "next hop returned an unrecognised ack status"
            );
            UNKNOWN_DOWNSTREAM_STATUS.to_string()
        }
        other => {
            tracing::warn!(next = %next.node_id, ?other, "next hop returned a non-ack frame");
            UNKNOWN_DOWNSTREAM_STATUS.to_string()
        }
    };

    write_message(
        &mut inbound,
        &RadiiMessage::Ack {
            status: status.clone(),
        },
    )
    .await?;
    if status != "tunnel_ready" {
        return Ok(None);
    }

    Ok(Some((inbound, outbound)))
}

/// Copies in both directions until either side closes, or until neither
/// direction has moved a byte for `idle`.
///
/// "Idle" is deliberately a property of the chain, not of one direction. A
/// legitimate tunnel is often quiet one way for a long time — a shell session
/// waiting on the user, a stream the client is only reading — so timing each
/// direction independently would kill working chains. Both directions share
/// one last-activity clock and a watchdog reads it.
///
/// This closes, for the relay path, the connection-timeout gap `SECURITY.md`
/// records as outstanding: without it a peer can complete a handshake, be
/// counted against the concurrency caps, and then hold its slot forever
/// without sending anything.
pub(crate) async fn splice_with_idle(a: BoxedStream, b: BoxedStream, idle: Duration) -> Result<()> {
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    let last = Arc::new(Mutex::new(Instant::now()));
    let watchdog_clock = Arc::clone(&last);

    // Polled rather than reset-per-byte so a busy chain does not pay for a
    // timer reset on every read. A quarter of the window bounds the overshoot.
    let watchdog = async move {
        let tick = (idle / 4).max(Duration::from_millis(10));
        loop {
            tokio::time::sleep(tick).await;
            let elapsed = {
                let guard = watchdog_clock.lock().expect("relay idle clock poisoned");
                guard.elapsed()
            };
            if elapsed >= idle {
                return;
            }
        }
    };

    tokio::select! {
        result = pump(&mut ar, &mut bw, &last) => result,
        result = pump(&mut br, &mut aw, &last) => result,
        _ = watchdog => {
            tracing::info!(idle_ms = idle.as_millis(), "relay dropped an idle chain");
            Ok(())
        }
    }
}

/// One direction of the splice, stamping the shared clock on every read so
/// activity either way keeps the whole chain alive.
async fn pump<R, W>(reader: &mut R, writer: &mut W, last: &Arc<Mutex<Instant>>) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 8192];
    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(());
        }
        *last.lock().expect("relay idle clock poisoned") = Instant::now();
        writer.write_all(&buf[..read]).await?;
    }
}
