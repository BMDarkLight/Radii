use crate::config::RadiiConfig;
use radii_proto::{read_message, write_message, RadiiMessage};
use tokio::net::{TcpListener, TcpStream};

pub async fn maybe_run_radii(config: &Option<RadiiConfig>) -> anyhow::Result<()> {
    let Some(config) = config else {
        return Ok(());
    };

    let listener = TcpListener::bind(&config.bind).await?;
    tracing::info!(bind = %config.bind, upstream = %config.crawl_upstream, "head radii listening");

    loop {
        let (stream, addr) = listener.accept().await?;
        let upstream = config.crawl_upstream.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, upstream, addr).await {
                tracing::warn!(source = %addr, error = %err, "radii connection failed");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    crawl_upstream: String,
    source: std::net::SocketAddr,
) -> anyhow::Result<()> {
    loop {
        let message = read_message(&mut stream).await?;
        let wrapped = RadiiMessage::FromHead {
            source: source.to_string(),
            message: Box::new(message),
        };

        let mut upstream = TcpStream::connect(&crawl_upstream).await?;
        write_message(&mut upstream, &wrapped).await?;
        let ack = read_message(&mut upstream).await?;

        write_message(&mut stream, &ack).await?;
    }
}
