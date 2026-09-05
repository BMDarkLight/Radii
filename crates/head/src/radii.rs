use crate::config::RadiiConfig;
use radii_proto::tls::TlsIdentity;
use radii_proto::{read_message, write_message, BoxedStream, RadiiMessage, RelayedMessage};
use tokio::net::TcpListener;

pub async fn maybe_run_radii(
    config: &Option<RadiiConfig>,
    tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    let Some(config) = config else {
        return Ok(());
    };

    let listener = TcpListener::bind(&config.bind).await?;
    tracing::info!(bind = %config.bind, upstream = %config.crawl_upstream, tls = tls.is_some(), "head radii listening");
    run_radii_on(listener, config.crawl_upstream.clone(), tls).await
}

pub async fn run_radii_on(
    listener: TcpListener,
    crawl_upstream: String,
    tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    loop {
        let (raw_stream, addr) = listener.accept().await?;
        let upstream = crawl_upstream.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let result = async {
                let (stream, peer_identity) =
                    radii_proto::tls::accept(raw_stream, tls.as_ref()).await?;
                handle_connection(stream, upstream, addr, tls, peer_identity).await
            }
            .await;
            if let Err(err) = result {
                tracing::warn!(source = %addr, error = %err, "radii connection failed");
            }
        });
    }
}

/// Bridges one inbound client connection to Crawl over a single persistent
/// upstream session, rather than dialing Crawl anew for every message. The
/// session is opened lazily on the first message (so a connection that never
/// sends anything never costs Crawl a session) and transparently
/// re-established if Crawl drops or restarts. When `tls` is configured, both
/// the inbound bridge listener and the outbound dial to Crawl require mTLS.
///
/// `client_identity` is the mTLS-authenticated node id of the bridge client,
/// forwarded to Crawl in every envelope. Head does not decide what that
/// client may claim — Crawl does, by matching the claim against this identity
/// — but Head must report it truthfully, which is why it is taken from the
/// handshake rather than from anything the client sends.
async fn handle_connection(
    mut stream: BoxedStream,
    crawl_upstream: String,
    source: std::net::SocketAddr,
    tls: Option<TlsIdentity>,
    client_identity: Option<String>,
) -> anyhow::Result<()> {
    let mut upstream: Option<BoxedStream> = None;

    loop {
        let message = read_message(&mut stream).await?;
        let relayed = match RelayedMessage::try_from(message) {
            Ok(relayed) => relayed,
            Err(err) => {
                tracing::warn!(
                    source = %source,
                    error = %err,
                    "radii bridge refused to relay an unsupported message"
                );
                write_message(
                    &mut stream,
                    &RadiiMessage::Ack {
                        status: "unsupported_relay_message".to_string(),
                    },
                )
                .await?;
                continue;
            }
        };
        let wrapped = RadiiMessage::FromHead {
            source: source.to_string(),
            client_identity: client_identity.clone(),
            message: relayed,
        };

        let mut conn = match upstream.take() {
            Some(conn) => conn,
            None => radii_proto::tls::dial(&crawl_upstream, tls.as_ref()).await?,
        };

        let ack = match relay(&mut conn, &wrapped).await {
            Ok(ack) => ack,
            Err(err) => {
                tracing::warn!(
                    source = %source,
                    crawl = %crawl_upstream,
                    error = %err,
                    "radii bridge session dropped, reconnecting"
                );
                conn = radii_proto::tls::dial(&crawl_upstream, tls.as_ref()).await?;
                relay(&mut conn, &wrapped).await?
            }
        };

        upstream = Some(conn);
        write_message(&mut stream, &ack).await?;
    }
}

async fn relay(upstream: &mut BoxedStream, message: &RadiiMessage) -> anyhow::Result<RadiiMessage> {
    write_message(upstream, message).await?;
    read_message(upstream).await
}
