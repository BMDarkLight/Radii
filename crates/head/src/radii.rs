use crate::config::RadiiConfig;
use radii_proto::{read_message, write_message, RadiiMessage};
use tokio::net::{TcpListener, TcpStream};

pub async fn maybe_run_radii(config: &Option<RadiiConfig>) -> anyhow::Result<()> {
    let Some(config) = config else {
        return Ok(());
    };

    let listener = TcpListener::bind(&config.bind).await?;
    tracing::info!(bind = %config.bind, upstream = %config.crawl_upstream, "head radii listening");
    run_radii_on(listener, config.crawl_upstream.clone()).await
}

pub async fn run_radii_on(listener: TcpListener, crawl_upstream: String) -> anyhow::Result<()> {
    loop {
        let (stream, addr) = listener.accept().await?;
        let upstream = crawl_upstream.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, upstream, addr).await {
                tracing::warn!(source = %addr, error = %err, "radii connection failed");
            }
        });
    }
}

/// Bridges one inbound client connection to Crawl over a single persistent
/// upstream session, rather than dialing Crawl anew for every message. The
/// session is opened lazily on the first message (so a connection that never
/// sends anything never costs Crawl a session) and transparently
/// re-established if Crawl drops or restarts.
async fn handle_connection(
    mut stream: TcpStream,
    crawl_upstream: String,
    source: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let mut upstream: Option<TcpStream> = None;

    loop {
        let message = read_message(&mut stream).await?;
        let wrapped = RadiiMessage::FromHead {
            source: source.to_string(),
            message: Box::new(message),
        };

        let mut conn = match upstream.take() {
            Some(conn) => conn,
            None => TcpStream::connect(&crawl_upstream).await?,
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
                conn = TcpStream::connect(&crawl_upstream).await?;
                relay(&mut conn, &wrapped).await?
            }
        };

        upstream = Some(conn);
        write_message(&mut stream, &ack).await?;
    }
}

async fn relay(upstream: &mut TcpStream, message: &RadiiMessage) -> anyhow::Result<RadiiMessage> {
    write_message(upstream, message).await?;
    read_message(upstream).await
}
