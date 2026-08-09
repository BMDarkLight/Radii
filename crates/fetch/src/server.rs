use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

pub async fn run(bind: &str, upstream: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, %upstream, "fetch tunnel listening");

    loop {
        let (stream, addr) = listener.accept().await?;
        let upstream = upstream.to_string();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, addr, &upstream).await {
                tracing::warn!(source = %addr, error = %err, "fetch tunnel failed");
            }
        });
    }
}

async fn handle_connection(
    mut inbound: TcpStream,
    source: std::net::SocketAddr,
    upstream: &str,
) -> anyhow::Result<()> {
    let target = normalize_upstream(upstream);
    tracing::info!(source = %source, upstream = %target, "fetch tunneling");

    let mut outbound = TcpStream::connect(&target).await?;
    let _ = inbound.write_all(b"").await;
    let _ = outbound.write_all(b"").await;

    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = tokio::io::copy(&mut ri, &mut wo);
    let server_to_client = tokio::io::copy(&mut ro, &mut wi);
    let _ = tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}

fn normalize_upstream(upstream: &str) -> String {
    let trimmed = upstream.trim();
    if let Some(stripped) = trimmed.strip_prefix("ssh://") {
        return stripped.to_string();
    }
    if let Some(stripped) = trimmed.strip_prefix("tcp://") {
        return stripped.to_string();
    }
    trimmed.to_string()
}
