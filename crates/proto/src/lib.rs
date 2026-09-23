// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 BMDarkLight
//
// This file is part of Radii.
//
// Radii is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version. See the LICENSE file for the full text and
// additional terms.

pub mod tls;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};

/// Maximum accepted Radii frame payload size (1 MiB).
///
/// Protects listeners from unbounded allocations on a hostile length prefix.
pub const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// How much of a frame Crawl may fill with `GraphSnapshot` contents.
///
/// The remainder is headroom for the envelope the contents sit in: the
/// message's variant tag and the two `Vec` length prefixes. A producer that
/// fills to this budget using the `*_encoded_bound` helpers below is
/// guaranteed to emit a frame within [`MAX_FRAME_LEN`].
pub const SNAPSHOT_BUDGET: u32 = MAX_FRAME_LEN - 1024;

/// Upper bound on the postcard encoding of a string.
///
/// postcard writes a varint length followed by the raw bytes. Five bytes
/// covers a varint for any length that could fit in a frame several orders
/// of magnitude larger than [`MAX_FRAME_LEN`], so this never
/// under-estimates.
fn encoded_str_bound(value: &str) -> usize {
    value.len() + 5
}

/// Upper bound on the postcard encoding of one [`NodeInfo`].
pub fn node_info_encoded_bound(node: &NodeInfo) -> usize {
    // Two `Vec`s, each with its own varint length prefix.
    let listen_addrs: usize = node
        .listen_addrs
        .iter()
        .map(|entry| encoded_str_bound(&entry.addr) + encoded_str_bound(&entry.role))
        .sum();
    let roles: usize = node.roles.iter().map(|role| encoded_str_bound(role)).sum();
    encoded_str_bound(&node.node_id) + 5 + listen_addrs + 5 + roles
}

/// Upper bound on the postcard encoding of one [`GraphReport`].
pub fn graph_report_encoded_bound(report: &GraphReport) -> usize {
    encoded_str_bound(&report.from)
        + encoded_str_bound(&report.target)
        + encoded_str_bound(&report.protocol)
        // `reachable` is one byte; `rtt_ms` is a one-byte Option tag plus a
        // u32 varint, which is at most five.
        + 1
        + 6
}

/// Maximum hops in a single `TunnelOpen` path.
///
/// Mirrors `radii_core::routing::MAX_ROUTE_HOPS`. It is duplicated rather
/// than imported because `radii-proto` does not depend on `radii-core`; the
/// wire layer must bound its own input without reaching for domain types.
pub const MAX_TUNNEL_HOPS: usize = 32;

/// Maximum advertised listen addresses per node.
///
/// `listen_addrs` is peer-supplied and was previously unbounded: a hostile
/// `NodeHello` could carry as many addresses as fit in [`MAX_FRAME_LEN`],
/// and Crawl stored every one of them, per node. Bounded here rather than
/// at a call site so the limit applies to anything arriving on the wire.
pub const MAX_LISTEN_ADDRS: usize = 16;
/// Maximum length of one advertised address string.
pub const MAX_LISTEN_ADDR_LEN: usize = 256;
/// Maximum length of one address role string.
pub const MAX_ROLE_LEN: usize = 64;

/// Maximum length of a node id, wherever one appears on the wire.
///
/// Node ids are peer-chosen and Crawl keys its registry and its reachability
/// table by them, so an unbounded one is memory a peer parks permanently.
/// The count of entries was already capped; this caps their size, which is
/// the half that let a peer stay inside every quota and still push a
/// `GraphSnapshot` past [`MAX_FRAME_LEN`]. Applies to `node_id`, and to a
/// report's `from`/`target` — note that `authorized()` constrains only
/// `from` against the peer's certificate, so `target` is bounded here or
/// nowhere.
pub const MAX_NODE_ID_LEN: usize = 256;
/// Maximum length of a protocol identifier (`http`, `radii`, …).
pub const MAX_PROTOCOL_LEN: usize = 64;
/// Maximum node-level roles in a `NodeHello`.
///
/// Distinct from [`MAX_LISTEN_ADDRS`]: those are advertised listeners, these
/// are the node's own declared roles. Both were peer-supplied; only the
/// former was bounded.
pub const MAX_NODE_ROLES: usize = 16;

/// A connected transport, plaintext or TLS — boxing behind this trait lets
/// connection-handling code stay transport-agnostic once the (optional) TLS
/// handshake is done, since [`read_message`]/[`write_message`] only need
/// `AsyncRead`/`AsyncWrite`.
pub trait AsyncDuplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncDuplex for T {}
pub type BoxedStream = Box<dyn AsyncDuplex>;

/// One hop of an initiator-pinned source route.
///
/// Flat by construction, like `RelayedMessage`: a hop list can never nest, so
/// no `TunnelOpen` frame can drive the decoder into unbounded recursion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteHop {
    pub node_id: String,
    pub addr: String,
}

/// One advertised listener, and what it speaks.
///
/// The role is what stops a single registry entry meaning two incompatible
/// things: Fetch reaches a node over its `relay` listener, while Head hands
/// a caller the node's `http` address to dial directly. Without the tag,
/// one consumer inevitably reads the other's address.
///
/// Flat by construction, like `RouteHop` and `RelayedMessage`: a
/// listen-address list can never nest, so a hostile frame cannot drive the
/// decoder into recursion.
///
/// `role` is a free string rather than an enum on purpose. Nodes in a mesh
/// upgrade at different times, and a consumer should ignore a role it does
/// not recognise rather than fail the whole `NodeHello`; an enum would make
/// every future role a flag day. Known roles are named by
/// `radii_core::routing::RoleId`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenAddr {
    pub addr: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RadiiMessage {
    NodeHello {
        node_id: String,
        roles: Vec<String>,
        listen_addrs: Vec<ListenAddr>,
    },
    ReachabilityProbe {
        from: String,
        to: String,
        sent_at_unix_ms: u64,
    },
    ReachabilityReport {
        from: String,
        target: String,
        protocol: String,
        reachable: bool,
        rtt_ms: Option<u32>,
        observed_addr: Option<String>,
    },
    FromHead {
        /// Where the relaying Head saw the message come from — a socket
        /// address, kept for operator logs. Free text chosen by the relaying
        /// peer, so it is never used to authorize anything.
        source: String,
        /// The mTLS-authenticated node id of the client the Head relayed
        /// for, or `None` when the Head's bridge listener is plaintext and
        /// there was no identity to authenticate. Crawl authorizes the inner
        /// claim against *this*, not against `source`.
        client_identity: Option<String>,
        message: RelayedMessage,
    },
    /// Requests the current node registry and reachability graph from Crawl.
    GraphQuery,
    GraphSnapshot {
        nodes: Vec<NodeInfo>,
        reports: Vec<GraphReport>,
    },
    Ack {
        status: String,
    },
    /// Opens a relayed tunnel along an explicit path.
    ///
    /// The list always starts with the node receiving the frame: a relay
    /// checks `hops[0]` names itself, then forwards `hops[1..]` onward. A
    /// single-entry list means the receiver is the chain's terminal node.
    TunnelOpen {
        hops: Vec<RouteHop>,
    },
}

/// The subset of messages a Head may relay to Crawl on a client's behalf.
///
/// Deliberately *flat*. The previous shape was `Box<RadiiMessage>`, which let
/// a `FromHead` contain another `FromHead`: postcard's derived `Deserialize`
/// recurses once per level with no depth limit, and each level cost only two
/// bytes on the wire, so a frame well under [`MAX_FRAME_LEN`] drove the
/// decoder into a stack overflow — aborting the whole process rather than
/// failing the connection. `RelayedMessage` cannot nest, so that frame is now
/// undecodable by construction rather than by a size check that a smaller
/// limit would only have made marginally more expensive to defeat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayedMessage {
    NodeHello {
        node_id: String,
        roles: Vec<String>,
        listen_addrs: Vec<ListenAddr>,
    },
    ReachabilityProbe {
        from: String,
        to: String,
        sent_at_unix_ms: u64,
    },
    ReachabilityReport {
        from: String,
        target: String,
        protocol: String,
        reachable: bool,
        rtt_ms: Option<u32>,
        observed_addr: Option<String>,
    },
}

impl RelayedMessage {
    /// The node id this message speaks for, which Crawl authorizes against
    /// the relayed client identity. A `ReachabilityProbe` only produces a log
    /// line and writes no state, so it claims nothing to check.
    pub fn claimed_node_id(&self) -> Option<&str> {
        match self {
            Self::NodeHello { node_id, .. } => Some(node_id),
            Self::ReachabilityReport { from, .. } => Some(from),
            Self::ReachabilityProbe { .. } => None,
        }
    }
}

impl TryFrom<RadiiMessage> for RelayedMessage {
    type Error = anyhow::Error;

    fn try_from(message: RadiiMessage) -> Result<Self> {
        match message {
            RadiiMessage::NodeHello {
                node_id,
                roles,
                listen_addrs,
            } => Ok(Self::NodeHello {
                node_id,
                roles,
                listen_addrs,
            }),
            RadiiMessage::ReachabilityProbe {
                from,
                to,
                sent_at_unix_ms,
            } => Ok(Self::ReachabilityProbe {
                from,
                to,
                sent_at_unix_ms,
            }),
            RadiiMessage::ReachabilityReport {
                from,
                target,
                protocol,
                reachable,
                rtt_ms,
                observed_addr,
            } => Ok(Self::ReachabilityReport {
                from,
                target,
                protocol,
                reachable,
                rtt_ms,
                observed_addr,
            }),
            other => bail!("message is not relayable through a Head: {other:?}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInfo {
    pub node_id: String,
    pub listen_addrs: Vec<ListenAddr>,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphReport {
    pub from: String,
    pub target: String,
    pub protocol: String,
    pub reachable: bool,
    pub rtt_ms: Option<u32>,
}

pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &RadiiMessage,
) -> Result<()> {
    let payload = postcard::to_allocvec(message)?;
    let len = u32::try_from(payload.len()).map_err(|_| anyhow::anyhow!("frame too large"))?;
    if len > MAX_FRAME_LEN {
        bail!("frame length {len} exceeds max {MAX_FRAME_LEN}");
    }
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    Ok(())
}

/// Opens a fresh plaintext connection to a Crawl (or Crawl-speaking)
/// listener, sends a `GraphQuery`, and returns the node registry and
/// reachability reports from its `GraphSnapshot` reply. Callers that need a
/// TLS-protected connection should dial via [`tls::dial`] and call
/// [`query_graph_on`] on the resulting stream instead.
pub async fn query_graph<A: ToSocketAddrs>(addr: A) -> Result<(Vec<NodeInfo>, Vec<GraphReport>)> {
    let mut stream = TcpStream::connect(addr).await?;
    query_graph_on(&mut stream).await
}

/// Sends a `GraphQuery` over an already-established connection (plaintext or
/// TLS) and returns the node registry and reachability reports from the
/// `GraphSnapshot` reply.
pub async fn query_graph_on<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<(Vec<NodeInfo>, Vec<GraphReport>)> {
    write_message(stream, &RadiiMessage::GraphQuery).await?;
    match read_message(stream).await? {
        RadiiMessage::GraphSnapshot { nodes, reports } => Ok((nodes, reports)),
        other => bail!("unexpected reply to graph query: {other:?}"),
    }
}

/// Opens a fresh plaintext connection and sends a `NodeHello`, returning
/// whatever the peer replies with (typically an `Ack`). Callers that need a
/// TLS-protected connection should dial via [`tls::dial`] and call
/// [`send_hello_on`] on the resulting stream instead.
pub async fn send_hello<A: ToSocketAddrs>(
    addr: A,
    node_id: String,
    roles: Vec<String>,
    listen_addrs: Vec<ListenAddr>,
) -> Result<RadiiMessage> {
    let mut stream = TcpStream::connect(addr).await?;
    send_hello_on(&mut stream, node_id, roles, listen_addrs).await
}

/// Sends a `NodeHello` over an already-established connection (plaintext or
/// TLS) and returns whatever the peer replies with.
pub async fn send_hello_on<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    node_id: String,
    roles: Vec<String>,
    listen_addrs: Vec<ListenAddr>,
) -> Result<RadiiMessage> {
    write_message(
        stream,
        &RadiiMessage::NodeHello {
            node_id,
            roles,
            listen_addrs,
        },
    )
    .await?;
    read_message(stream).await
}

/// Opens a fresh plaintext connection and sends a `ReachabilityReport`,
/// returning whatever the peer replies with. Callers that need a
/// TLS-protected connection should dial via [`tls::dial`] and call
/// [`send_report_on`] on the resulting stream instead.
pub async fn send_report<A: ToSocketAddrs>(
    addr: A,
    from: String,
    target: String,
    protocol: String,
    reachable: bool,
    rtt_ms: Option<u32>,
    observed_addr: Option<String>,
) -> Result<RadiiMessage> {
    let mut stream = TcpStream::connect(addr).await?;
    send_report_on(
        &mut stream,
        from,
        target,
        protocol,
        reachable,
        rtt_ms,
        observed_addr,
    )
    .await
}

/// Sends a `ReachabilityReport` over an already-established connection
/// (plaintext or TLS) and returns whatever the peer replies with.
pub async fn send_report_on<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    from: String,
    target: String,
    protocol: String,
    reachable: bool,
    rtt_ms: Option<u32>,
    observed_addr: Option<String>,
) -> Result<RadiiMessage> {
    write_message(
        stream,
        &RadiiMessage::ReachabilityReport {
            from,
            target,
            protocol,
            reachable,
            rtt_ms,
            observed_addr,
        },
    )
    .await?;
    read_message(stream).await
}

pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<RadiiMessage> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_FRAME_LEN {
        bail!("frame length {len} exceeds max {MAX_FRAME_LEN}");
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;
    let message = postcard::from_bytes(&payload)?;

    if let RadiiMessage::TunnelOpen { hops } = &message {
        if hops.is_empty() || hops.len() > MAX_TUNNEL_HOPS {
            bail!(
                "tunnel_open hop count {} outside 1..={MAX_TUNNEL_HOPS}",
                hops.len()
            );
        }
    }

    validate_message(&message)?;

    Ok(message)
}

/// Bounds every peer-supplied string and list on a decoded message.
///
/// Centralised so the direct and Head-relayed shapes cannot drift: a hello
/// or report relayed through a Head arrives wrapped in `FromHead`, and a
/// bound enforced only on the direct shape is one an attacker reaches
/// around by going via a Head — which is exactly the path Head exists to
/// provide.
fn validate_message(message: &RadiiMessage) -> Result<()> {
    match message {
        RadiiMessage::NodeHello {
            node_id,
            roles,
            listen_addrs,
        } => validate_hello(node_id, roles, listen_addrs),
        RadiiMessage::ReachabilityReport {
            from,
            target,
            protocol,
            observed_addr,
            ..
        } => validate_report(from, target, protocol, observed_addr.as_deref()),
        RadiiMessage::ReachabilityProbe { from, to, .. } => {
            validate_node_id(from)?;
            validate_node_id(to)
        }
        RadiiMessage::FromHead {
            source,
            client_identity,
            message,
        } => {
            if source.len() > MAX_LISTEN_ADDR_LEN {
                bail!(
                    "from_head source length {} exceeds {MAX_LISTEN_ADDR_LEN}",
                    source.len()
                );
            }
            if let Some(identity) = client_identity {
                validate_node_id(identity)?;
            }
            match message {
                RelayedMessage::NodeHello {
                    node_id,
                    roles,
                    listen_addrs,
                } => validate_hello(node_id, roles, listen_addrs),
                RelayedMessage::ReachabilityReport {
                    from,
                    target,
                    protocol,
                    observed_addr,
                    ..
                } => validate_report(from, target, protocol, observed_addr.as_deref()),
                RelayedMessage::ReachabilityProbe { from, to, .. } => {
                    validate_node_id(from)?;
                    validate_node_id(to)
                }
            }
        }
        // A poller reads this from Crawl, so the same bounds are what keep a
        // hostile or compromised Crawl from pushing unbounded strings into
        // Head's and Fetch's route planners.
        RadiiMessage::GraphSnapshot { nodes, reports } => {
            for node in nodes {
                validate_hello(&node.node_id, &node.roles, &node.listen_addrs)?;
            }
            for report in reports {
                validate_report(&report.from, &report.target, &report.protocol, None)?;
            }
            Ok(())
        }
        RadiiMessage::TunnelOpen { hops } => {
            for hop in hops {
                validate_node_id(&hop.node_id)?;
                if hop.addr.len() > MAX_LISTEN_ADDR_LEN {
                    bail!(
                        "tunnel_open hop address length {} exceeds {MAX_LISTEN_ADDR_LEN}",
                        hop.addr.len()
                    );
                }
            }
            Ok(())
        }
        RadiiMessage::Ack { .. } | RadiiMessage::GraphQuery => Ok(()),
    }
}

fn validate_node_id(node_id: &str) -> Result<()> {
    if node_id.len() > MAX_NODE_ID_LEN {
        bail!("node id length {} exceeds {MAX_NODE_ID_LEN}", node_id.len());
    }
    Ok(())
}

fn validate_hello(node_id: &str, roles: &[String], listen_addrs: &[ListenAddr]) -> Result<()> {
    validate_node_id(node_id)?;
    if roles.len() > MAX_NODE_ROLES {
        bail!(
            "node_hello roles count {} exceeds {MAX_NODE_ROLES}",
            roles.len()
        );
    }
    for role in roles {
        if role.len() > MAX_ROLE_LEN {
            bail!(
                "node_hello role length {} exceeds {MAX_ROLE_LEN}",
                role.len()
            );
        }
    }
    validate_listen_addrs(listen_addrs)
}

fn validate_report(
    from: &str,
    target: &str,
    protocol: &str,
    observed_addr: Option<&str>,
) -> Result<()> {
    validate_node_id(from)?;
    validate_node_id(target)?;
    if protocol.len() > MAX_PROTOCOL_LEN {
        bail!(
            "report protocol length {} exceeds {MAX_PROTOCOL_LEN}",
            protocol.len()
        );
    }
    if let Some(addr) = observed_addr {
        if addr.len() > MAX_LISTEN_ADDR_LEN {
            bail!(
                "report observed address length {} exceeds {MAX_LISTEN_ADDR_LEN}",
                addr.len()
            );
        }
    }
    Ok(())
}

/// Bounds a peer-supplied listen-address list.
///
/// Shared by the direct and the Head-relayed `NodeHello` paths so the two
/// cannot drift: a limit enforced on only one of them is not a limit.
fn validate_listen_addrs(listen_addrs: &[ListenAddr]) -> Result<()> {
    if listen_addrs.len() > MAX_LISTEN_ADDRS {
        bail!(
            "node_hello listen_addrs count {} exceeds {MAX_LISTEN_ADDRS}",
            listen_addrs.len()
        );
    }
    for entry in listen_addrs {
        if entry.addr.len() > MAX_LISTEN_ADDR_LEN {
            bail!(
                "node_hello listen address length {} exceeds {MAX_LISTEN_ADDR_LEN}",
                entry.addr.len()
            );
        }
        if entry.role.len() > MAX_ROLE_LEN {
            bail!(
                "node_hello listen address role length {} exceeds {MAX_ROLE_LEN}",
                entry.role.len()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    async fn round_trip(message: RadiiMessage) -> RadiiMessage {
        let (mut client, mut server): (DuplexStream, DuplexStream) = tokio::io::duplex(64 * 1024);
        write_message(&mut client, &message).await.unwrap();
        read_message(&mut server).await.unwrap()
    }

    async fn decode(message: &RadiiMessage) -> Result<RadiiMessage> {
        let mut buf = Vec::new();
        write_message(&mut buf, message).await.unwrap();
        read_message(&mut buf.as_slice()).await
    }

    /// `node_id` is a peer-chosen string that Crawl stores as a registry key.
    /// It was never length-bounded, so one hello could park most of a frame
    /// in Crawl's memory permanently.
    #[tokio::test]
    async fn rejects_a_hello_with_an_oversized_node_id() {
        let err = decode(&RadiiMessage::NodeHello {
            node_id: "n".repeat(MAX_NODE_ID_LEN + 1),
            roles: vec![],
            listen_addrs: vec![],
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("node id"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_a_hello_with_too_many_roles() {
        let err = decode(&RadiiMessage::NodeHello {
            node_id: "n".into(),
            roles: (0..=MAX_NODE_ROLES).map(|i| format!("r{i}")).collect(),
            listen_addrs: vec![],
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("roles"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_a_hello_with_an_oversized_node_level_role() {
        let err = decode(&RadiiMessage::NodeHello {
            node_id: "n".into(),
            roles: vec!["r".repeat(MAX_ROLE_LEN + 1)],
            listen_addrs: vec![],
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("role"), "got: {err}");
    }

    /// `target` and `protocol` are the fields `authorized()` does not check
    /// even on an mTLS listener — only `from` is matched against the peer
    /// identity. Bounding them is what stops an authenticated peer filling
    /// its quota with arbitrarily large entries.
    #[tokio::test]
    async fn rejects_a_report_with_an_oversized_target() {
        let err = decode(&RadiiMessage::ReachabilityReport {
            from: "a".into(),
            target: "t".repeat(MAX_NODE_ID_LEN + 1),
            protocol: "radii".into(),
            reachable: true,
            rtt_ms: None,
            observed_addr: None,
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("node id"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_a_report_with_an_oversized_protocol() {
        let err = decode(&RadiiMessage::ReachabilityReport {
            from: "a".into(),
            target: "b".into(),
            protocol: "p".repeat(MAX_PROTOCOL_LEN + 1),
            reachable: true,
            rtt_ms: None,
            observed_addr: None,
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("protocol"), "got: {err}");
    }

    /// The bound must cover a report relayed through a Head, not only a
    /// direct one — going via a Head is exactly the path Head exists to
    /// provide, and a limit enforced on one shape is not a limit.
    #[tokio::test]
    async fn rejects_a_relayed_report_with_an_oversized_target() {
        let err = decode(&RadiiMessage::FromHead {
            source: "127.0.0.1:1".into(),
            client_identity: Some("a".into()),
            message: RelayedMessage::ReachabilityReport {
                from: "a".into(),
                target: "t".repeat(MAX_NODE_ID_LEN + 1),
                protocol: "radii".into(),
                reachable: true,
                rtt_ms: None,
                observed_addr: None,
            },
        })
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("node id"),
            "a relayed report must be bounded too; got: {err}"
        );
    }

    /// A poller reads `GraphSnapshot` from Crawl, so the same bounds protect
    /// Head and Fetch from a hostile or compromised Crawl.
    #[tokio::test]
    async fn rejects_a_snapshot_carrying_an_oversized_node_id() {
        let err = decode(&RadiiMessage::GraphSnapshot {
            nodes: vec![NodeInfo {
                node_id: "n".repeat(MAX_NODE_ID_LEN + 1),
                listen_addrs: vec![],
                roles: vec![],
            }],
            reports: vec![],
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("node id"), "got: {err}");
    }

    /// Bounds must not reject anything legitimate.
    #[tokio::test]
    async fn accepts_realistic_messages_at_the_bounds() {
        let hello = RadiiMessage::NodeHello {
            node_id: "n".repeat(MAX_NODE_ID_LEN),
            roles: (0..MAX_NODE_ROLES).map(|i| format!("role-{i}")).collect(),
            listen_addrs: vec![ListenAddr {
                addr: "127.0.0.1:7100".into(),
                role: "relay".into(),
            }],
        };
        assert_eq!(decode(&hello).await.unwrap(), hello);

        let report = RadiiMessage::ReachabilityReport {
            from: "node-a".into(),
            target: "t".repeat(MAX_NODE_ID_LEN),
            protocol: "p".repeat(MAX_PROTOCOL_LEN),
            reachable: true,
            rtt_ms: Some(12),
            observed_addr: Some("a".repeat(MAX_LISTEN_ADDR_LEN)),
        };
        assert_eq!(decode(&report).await.unwrap(), report);
    }

    /// The budget helpers must never under-estimate what postcard actually
    /// emits, or Crawl would fill a snapshot right up to a limit it then
    /// exceeded — the exact failure they exist to prevent.
    #[test]
    fn encoded_bounds_never_underestimate_postcard() {
        let nodes = [
            NodeInfo {
                node_id: String::new(),
                listen_addrs: Vec::new(),
                roles: Vec::new(),
            },
            NodeInfo {
                node_id: "node-a".into(),
                listen_addrs: vec![ListenAddr {
                    addr: "127.0.0.1:7100".into(),
                    role: "relay".into(),
                }],
                roles: vec!["crawl".into(), "resource".into()],
            },
            NodeInfo {
                node_id: "n".repeat(4096),
                listen_addrs: (0..MAX_LISTEN_ADDRS)
                    .map(|i| ListenAddr {
                        addr: format!("{i}{}", "a".repeat(MAX_LISTEN_ADDR_LEN - 1)),
                        role: "r".repeat(MAX_ROLE_LEN),
                    })
                    .collect(),
                roles: (0..64).map(|i| format!("role-{i}")).collect(),
            },
        ];
        for node in &nodes {
            let actual = postcard::to_allocvec(node).unwrap().len();
            let bound = node_info_encoded_bound(node);
            assert!(
                bound >= actual,
                "bound {bound} under-estimates actual {actual} for {node:?}"
            );
        }

        let reports = [
            GraphReport {
                from: String::new(),
                target: String::new(),
                protocol: String::new(),
                reachable: false,
                rtt_ms: None,
            },
            GraphReport {
                from: "a".into(),
                target: "b".into(),
                protocol: "radii".into(),
                reachable: true,
                rtt_ms: Some(u32::MAX),
            },
            GraphReport {
                from: "f".repeat(8192),
                target: "t".repeat(8192),
                protocol: "p".repeat(512),
                reachable: true,
                rtt_ms: Some(1),
            },
        ];
        for report in &reports {
            let actual = postcard::to_allocvec(report).unwrap().len();
            let bound = graph_report_encoded_bound(report);
            assert!(
                bound >= actual,
                "bound {bound} under-estimates actual {actual} for {report:?}"
            );
        }
    }

    /// A snapshot filled to `SNAPSHOT_BUDGET` by those bounds must still
    /// encode within `MAX_FRAME_LEN` once the envelope is added.
    #[test]
    fn snapshot_budget_leaves_room_for_the_envelope() {
        let reports: Vec<GraphReport> = (0..20_000)
            .map(|i| GraphReport {
                from: format!("node-{i:06}"),
                target: format!("node-{:06}", i + 1),
                protocol: "radii".into(),
                reachable: true,
                rtt_ms: Some(42),
            })
            .collect();

        let mut used = 0usize;
        let mut kept = Vec::new();
        for report in reports {
            let cost = graph_report_encoded_bound(&report);
            if used + cost > SNAPSHOT_BUDGET as usize {
                break;
            }
            used += cost;
            kept.push(report);
        }
        assert!(!kept.is_empty(), "the budget must admit some reports");

        let encoded = postcard::to_allocvec(&RadiiMessage::GraphSnapshot {
            nodes: Vec::new(),
            reports: kept,
        })
        .unwrap();
        assert!(
            encoded.len() as u32 <= MAX_FRAME_LEN,
            "a budget-filled snapshot encoded to {} bytes, over {MAX_FRAME_LEN}",
            encoded.len()
        );
    }

    #[tokio::test]
    async fn round_trips_node_hello() {
        let original = RadiiMessage::NodeHello {
            node_id: "node-a".into(),
            roles: vec!["crawl".into()],
            listen_addrs: vec![ListenAddr {
                addr: "127.0.0.1:7100".into(),
                role: "relay".into(),
            }],
        };
        assert_eq!(round_trip(original.clone()).await, original);
    }

    #[tokio::test]
    async fn round_trips_report_probe_ack_and_from_head() {
        let report = RadiiMessage::ReachabilityReport {
            from: "a".into(),
            target: "b".into(),
            protocol: "radii".into(),
            reachable: true,
            rtt_ms: Some(12),
            observed_addr: Some("1.2.3.4:9".into()),
        };
        assert_eq!(round_trip(report.clone()).await, report);

        let probe = RadiiMessage::ReachabilityProbe {
            from: "a".into(),
            to: "b".into(),
            sent_at_unix_ms: 42,
        };
        assert_eq!(round_trip(probe.clone()).await, probe);

        let ack = RadiiMessage::Ack {
            status: "ok".into(),
        };
        assert_eq!(round_trip(ack.clone()).await, ack);

        let wrapped = RadiiMessage::FromHead {
            source: "head-1".into(),
            client_identity: Some("node-a".into()),
            message: RelayedMessage::ReachabilityProbe {
                from: "a".into(),
                to: "b".into(),
                sent_at_unix_ms: 7,
            },
        };
        assert_eq!(round_trip(wrapped.clone()).await, wrapped);
    }

    /// A `FromHead` envelope must not be able to carry another `FromHead`.
    ///
    /// The old `Box<RadiiMessage>` shape cost two bytes per nesting level, so
    /// a legal-sized frame carried enough levels to overflow the stack during
    /// deserialization and abort the process. This asserts the frame is now
    /// rejected as a decode error — and, because `RelayedMessage` is flat,
    /// the assertion is reachable at all: the old code aborted the test
    /// binary here instead of returning.
    #[tokio::test]
    async fn rejects_deeply_nested_from_head_frame() {
        // Hand-rolled postcard: FromHead is variant 3, then an empty `source`
        // string, then a `None` client_identity — the same two-bytes-per-level
        // shape the original proof of concept used, plus the new field.
        let depth = 200_000usize;
        let mut payload = Vec::with_capacity(depth * 3 + 2);
        for _ in 0..depth {
            payload.push(3u8); // FromHead
            payload.push(0u8); // source = ""
            payload.push(0u8); // client_identity = None
        }
        payload.push(6u8); // a trailing non-relayable variant
        payload.push(0u8);

        assert!(
            payload.len() < MAX_FRAME_LEN as usize,
            "the attack frame must be within the legal size limit to be meaningful"
        );

        let (mut client, mut server): (DuplexStream, DuplexStream) =
            tokio::io::duplex(2 * 1024 * 1024);
        client
            .write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&payload).await.unwrap();

        assert!(
            read_message(&mut server).await.is_err(),
            "a nested FromHead frame must fail to decode, not recurse"
        );
    }

    #[tokio::test]
    async fn round_trips_graph_query_and_snapshot() {
        assert_eq!(
            round_trip(RadiiMessage::GraphQuery).await,
            RadiiMessage::GraphQuery
        );

        let snapshot = RadiiMessage::GraphSnapshot {
            nodes: vec![NodeInfo {
                node_id: "node-a".into(),
                listen_addrs: vec![ListenAddr {
                    addr: "127.0.0.1:9000".into(),
                    role: "relay".into(),
                }],
                roles: vec!["crawl".into()],
            }],
            reports: vec![GraphReport {
                from: "node-a".into(),
                target: "node-b".into(),
                protocol: "radii".into(),
                reachable: true,
                rtt_ms: Some(12),
            }],
        };
        assert_eq!(round_trip(snapshot.clone()).await, snapshot);
    }

    #[tokio::test]
    async fn rejects_oversized_length_prefix() {
        let (mut client, mut server): (DuplexStream, DuplexStream) = tokio::io::duplex(32);
        let oversized = (MAX_FRAME_LEN + 1).to_be_bytes();
        client.write_all(&oversized).await.unwrap();
        let err = read_message(&mut server).await.unwrap_err();
        assert!(
            err.to_string().contains("exceeds max"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_truncated_frame() {
        let (mut client, mut server): (DuplexStream, DuplexStream) = tokio::io::duplex(32);
        client.write_all(&8u32.to_be_bytes()).await.unwrap();
        client.write_all(b"short").await.unwrap();
        drop(client);
        assert!(read_message(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn rejects_garbage_payload() {
        let (mut client, mut server): (DuplexStream, DuplexStream) = tokio::io::duplex(64);
        // Incomplete varint / truncated postcard payload should fail to decode.
        let garbage = [0xffu8; 16];
        client
            .write_all(&(garbage.len() as u32).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&garbage).await.unwrap();
        assert!(read_message(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn send_hello_on_round_trips_ack() {
        let (mut client, mut server): (DuplexStream, DuplexStream) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let message = read_message(&mut server).await.unwrap();
            assert_eq!(
                message,
                RadiiMessage::NodeHello {
                    node_id: "node-a".into(),
                    roles: vec!["wave".into()],
                    listen_addrs: vec![ListenAddr {
                        addr: "127.0.0.1:1".into(),
                        role: "relay".into(),
                    }],
                }
            );
            write_message(
                &mut server,
                &RadiiMessage::Ack {
                    status: "hello_received".into(),
                },
            )
            .await
            .unwrap();
        });

        let reply = send_hello_on(
            &mut client,
            "node-a".into(),
            vec!["wave".into()],
            vec![ListenAddr {
                addr: "127.0.0.1:1".into(),
                role: "relay".into(),
            }],
        )
        .await
        .unwrap();

        assert_eq!(
            reply,
            RadiiMessage::Ack {
                status: "hello_received".into()
            }
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn send_report_on_round_trips_ack() {
        let (mut client, mut server): (DuplexStream, DuplexStream) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let message = read_message(&mut server).await.unwrap();
            assert_eq!(
                message,
                RadiiMessage::ReachabilityReport {
                    from: "a".into(),
                    target: "b".into(),
                    protocol: "http".into(),
                    reachable: true,
                    rtt_ms: Some(12),
                    observed_addr: None,
                }
            );
            write_message(
                &mut server,
                &RadiiMessage::Ack {
                    status: "report_received".into(),
                },
            )
            .await
            .unwrap();
        });

        let reply = send_report_on(
            &mut client,
            "a".into(),
            "b".into(),
            "http".into(),
            true,
            Some(12),
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            reply,
            RadiiMessage::Ack {
                status: "report_received".into()
            }
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn tunnel_open_round_trips() {
        let message = RadiiMessage::TunnelOpen {
            hops: vec![
                RouteHop {
                    node_id: "r1".into(),
                    addr: "10.0.0.1:2224".into(),
                },
                RouteHop {
                    node_id: "t".into(),
                    addr: "10.0.0.2:2224".into(),
                },
            ],
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &message).await.unwrap();
        let decoded = read_message(&mut buf.as_slice()).await.unwrap();

        assert_eq!(decoded, message);
    }

    #[tokio::test]
    async fn rejects_a_tunnel_open_with_too_many_hops() {
        let hops = (0..=MAX_TUNNEL_HOPS)
            .map(|i| RouteHop {
                node_id: format!("n{i}"),
                addr: "127.0.0.1:1".into(),
            })
            .collect();

        let mut buf = Vec::new();
        write_message(&mut buf, &RadiiMessage::TunnelOpen { hops })
            .await
            .unwrap();

        let err = read_message(&mut buf.as_slice()).await.unwrap_err();
        assert!(
            err.to_string().contains("hop count"),
            "expected a hop-count bound error, got: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_an_empty_tunnel_open() {
        let mut buf = Vec::new();
        write_message(&mut buf, &RadiiMessage::TunnelOpen { hops: Vec::new() })
            .await
            .unwrap();

        let err = read_message(&mut buf.as_slice()).await.unwrap_err();
        assert!(err.to_string().contains("hop count"), "got: {err}");
    }

    #[tokio::test]
    async fn node_hello_round_trips_role_tagged_addresses() {
        let message = RadiiMessage::NodeHello {
            node_id: "node-b".into(),
            roles: vec!["resource".into()],
            listen_addrs: vec![
                ListenAddr {
                    addr: "10.0.0.5:2224".into(),
                    role: "relay".into(),
                },
                ListenAddr {
                    addr: "10.0.0.5:9000".into(),
                    role: "http".into(),
                },
            ],
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &message).await.unwrap();
        assert_eq!(read_message(&mut buf.as_slice()).await.unwrap(), message);
    }

    #[tokio::test]
    async fn rejects_a_hello_with_too_many_listen_addrs() {
        let listen_addrs = (0..=MAX_LISTEN_ADDRS)
            .map(|i| ListenAddr {
                addr: format!("10.0.0.1:{i}"),
                role: "relay".into(),
            })
            .collect();
        let mut buf = Vec::new();
        write_message(
            &mut buf,
            &RadiiMessage::NodeHello {
                node_id: "n".into(),
                roles: vec![],
                listen_addrs,
            },
        )
        .await
        .unwrap();

        let err = read_message(&mut buf.as_slice()).await.unwrap_err();
        assert!(err.to_string().contains("listen_addrs"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_a_hello_with_an_oversized_address() {
        let mut buf = Vec::new();
        write_message(
            &mut buf,
            &RadiiMessage::NodeHello {
                node_id: "n".into(),
                roles: vec![],
                listen_addrs: vec![ListenAddr {
                    addr: "a".repeat(MAX_LISTEN_ADDR_LEN + 1),
                    role: "relay".into(),
                }],
            },
        )
        .await
        .unwrap();

        let err = read_message(&mut buf.as_slice()).await.unwrap_err();
        assert!(err.to_string().contains("address"), "got: {err}");
    }

    /// The listen-address bounds must cover a `NodeHello` relayed through a
    /// Head bridge, not only a direct one. Head's whole purpose on this path
    /// is forwarding a client's hello to Crawl inside a `FromHead` envelope,
    /// so a bound that only matches the direct shape is one an attacker
    /// reaches Crawl through by simply going via a Head.
    #[tokio::test]
    async fn rejects_a_relayed_hello_with_too_many_listen_addrs() {
        let listen_addrs = (0..=MAX_LISTEN_ADDRS)
            .map(|i| ListenAddr {
                addr: format!("10.0.0.1:{i}"),
                role: "relay".into(),
            })
            .collect();

        let mut buf = Vec::new();
        write_message(
            &mut buf,
            &RadiiMessage::FromHead {
                source: "127.0.0.1:1".into(),
                client_identity: Some("node-c".into()),
                message: RelayedMessage::NodeHello {
                    node_id: "node-c".into(),
                    roles: vec![],
                    listen_addrs,
                },
            },
        )
        .await
        .unwrap();

        let err = read_message(&mut buf.as_slice()).await.unwrap_err();
        assert!(
            err.to_string().contains("listen_addrs"),
            "a relayed hello must be bounded too; got: {err}"
        );
    }

    #[tokio::test]
    async fn rejects_a_hello_with_an_oversized_role() {
        let mut buf = Vec::new();
        write_message(
            &mut buf,
            &RadiiMessage::NodeHello {
                node_id: "n".into(),
                roles: vec![],
                listen_addrs: vec![ListenAddr {
                    addr: "10.0.0.1:1".into(),
                    role: "r".repeat(MAX_ROLE_LEN + 1),
                }],
            },
        )
        .await
        .unwrap();

        let err = read_message(&mut buf.as_slice()).await.unwrap_err();
        assert!(err.to_string().contains("role"), "got: {err}");
    }
}
