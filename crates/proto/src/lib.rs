pub mod tls;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};

/// Maximum accepted Radii frame payload size (1 MiB).
///
/// Protects listeners from unbounded allocations on a hostile length prefix.
pub const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// A connected transport, plaintext or TLS — boxing behind this trait lets
/// connection-handling code stay transport-agnostic once the (optional) TLS
/// handshake is done, since [`read_message`]/[`write_message`] only need
/// `AsyncRead`/`AsyncWrite`.
pub trait AsyncDuplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncDuplex for T {}
pub type BoxedStream = Box<dyn AsyncDuplex>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RadiiMessage {
    NodeHello {
        node_id: String,
        roles: Vec<String>,
        listen_addrs: Vec<String>,
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
        source: String,
        message: Box<RadiiMessage>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInfo {
    pub node_id: String,
    pub listen_addrs: Vec<String>,
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
    Ok(message)
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
            listen_addrs: vec!["127.0.0.1:7100".into()],
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
            message: Box::new(RadiiMessage::Ack {
                status: "inner".into(),
            }),
        };
        assert_eq!(round_trip(wrapped.clone()).await, wrapped);
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
                listen_addrs: vec!["127.0.0.1:9000".into()],
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
}
