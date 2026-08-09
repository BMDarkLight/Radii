use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    Ack {
        status: String,
    },
}

pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &RadiiMessage,
) -> Result<()> {
    let payload = bincode::serialize(message)?;
    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    Ok(())
}

pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> Result<RadiiMessage> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    let message = bincode::deserialize(&payload)?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    #[tokio::test]
    async fn round_trips_node_hello() {
        let (mut client, mut server): (DuplexStream, DuplexStream) = tokio::io::duplex(1024);
        let original = RadiiMessage::NodeHello {
            node_id: "node-a".into(),
            roles: vec!["crawl".into()],
            listen_addrs: vec!["127.0.0.1:7100".into()],
        };

        write_message(&mut client, &original).await.unwrap();
        let decoded = read_message(&mut server).await.unwrap();

        match decoded {
            RadiiMessage::NodeHello {
                node_id,
                roles,
                listen_addrs,
            } => {
                assert_eq!(node_id, "node-a");
                assert_eq!(roles, vec!["crawl".to_string()]);
                assert_eq!(listen_addrs, vec!["127.0.0.1:7100".to_string()]);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }
}
