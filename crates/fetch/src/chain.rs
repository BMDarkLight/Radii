//! The initiator half of source routing: turn a resolved route into a byte
//! stream that speaks end-to-end with the target.
//!
//! Two TLS layers are involved and they check different things. The hop-local
//! layer authenticates the *first relay* and carries the `TunnelOpen`. The
//! end-to-end layer authenticates the *target* and carries the payload, which
//! every relay in between handles as opaque bytes.

use anyhow::{bail, Result};
use radii_core::routing::ResolvedRoute;
use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, BoxedStream, RadiiMessage, RouteHop};

pub async fn establish(
    route: &ResolvedRoute,
    hop_tls: Option<&TlsIdentity>,
    e2e_tls: Option<&TlsIdentity>,
) -> Result<BoxedStream> {
    let first = route
        .hops
        .first()
        .ok_or_else(|| anyhow::anyhow!("route has no hops"))?;
    let target = route
        .hops
        .last()
        .expect("a route with a first hop has a last hop");

    let mut hop =
        radii_proto::tls::dial_expecting(&first.addr, hop_tls, Some(&first.node_id.0)).await?;

    let hops: Vec<RouteHop> = route
        .hops
        .iter()
        .map(|hop| RouteHop {
            node_id: hop.node_id.0.clone(),
            addr: hop.addr.clone(),
        })
        .collect();
    write_message(&mut hop, &RadiiMessage::TunnelOpen { hops }).await?;

    match read_message(&mut hop).await? {
        RadiiMessage::Ack { status } if status == "tunnel_ready" => {}
        RadiiMessage::Ack { status } => bail!("chain refused: {status}"),
        other => bail!("expected an ack opening a chain, got {other:?}"),
    }

    // The identity checked here is the TARGET's, not the relay we dialed.
    // SNI uses the target's advertised address so certificate SANs are
    // checked against the host actually being reached.
    radii_proto::tls::connect_on(hop, &target.addr, e2e_tls, Some(&target.node_id.0)).await
}
