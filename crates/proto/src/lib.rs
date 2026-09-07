pub mod tls;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};

/// Maximum accepted Radii frame payload size (1 MiB).
///
/// Protects listeners from unbounded allocations on a hostile length prefix.
pub const MAX_FRAME_LEN: u32 = 1024 * 1024;

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

    // Both shapes a `NodeHello` can arrive in. A hello relayed through a
    // Head bridge is wrapped in `FromHead`, so matching only the direct
    // shape would leave the bound reachable-around by going via a Head —
    // which is exactly the path Head exists to provide.
    match &message {
        RadiiMessage::NodeHello { listen_addrs, .. }
        | RadiiMessage::FromHead {
            message: RelayedMessage::NodeHello { listen_addrs, .. },
            ..
        } => validate_listen_addrs(listen_addrs)?,
        _ => {}
    }

    Ok(message)
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
