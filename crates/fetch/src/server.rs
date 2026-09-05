use crate::graph::SharedTarget;
use radii_proto::tls::TlsIdentity;
use radii_proto::BoxedStream;
use tokio::net::{TcpListener, TcpStream};

pub async fn run(bind: &str, upstream: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(bind).await?;
    tracing::info!(%bind, %upstream, "fetch tunnel listening");
    run_on(listener, upstream).await
}

pub async fn run_on(listener: TcpListener, upstream: &str) -> anyhow::Result<()> {
    run_on_with_tls(listener, upstream.to_string(), None, None).await
}

/// Like [`run_on`], but resolves the upstream for each new connection from a
/// live-updated graph target, falling back to `static_upstream` when no
/// graph-resolved route is available yet.
pub async fn run_on_dynamic(
    listener: TcpListener,
    static_upstream: String,
    target: SharedTarget,
) -> anyhow::Result<()> {
    run_on_dynamic_with_tls(listener, static_upstream, target, None, None).await
}

/// Like [`run_on`], additionally requiring mTLS on the inbound side
/// (`listener_tls`) and/or dialing the upstream over mTLS (`upstream_tls`)
/// when configured.
pub async fn run_on_with_tls(
    listener: TcpListener,
    upstream: String,
    listener_tls: Option<TlsIdentity>,
    upstream_tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    loop {
        let (stream, addr) = listener.accept().await?;
        let upstream = upstream.clone();
        let listener_tls = listener_tls.clone();
        let upstream_tls = upstream_tls.clone();
        tokio::spawn(async move {
            if let Err(err) =
                accept_and_tunnel(stream, addr, upstream, None, listener_tls, upstream_tls).await
            {
                tracing::warn!(source = %addr, error = %err, "fetch tunnel failed");
            }
        });
    }
}

/// [`run_on_dynamic`] plus the mTLS options from [`run_on_with_tls`].
pub async fn run_on_dynamic_with_tls(
    listener: TcpListener,
    static_upstream: String,
    target: SharedTarget,
    listener_tls: Option<TlsIdentity>,
    upstream_tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    loop {
        let (stream, addr) = listener.accept().await?;
        // A graph-resolved upstream carries the node id it is supposed to
        // belong to, so the dial can verify it. The static fallback carries
        // none: that address came from the operator's own config, which is
        // trusted by definition and may legitimately point at a host with no
        // Radii node identity at all (an SSH daemon, say).
        let resolved = target.read().ok().and_then(|guard| guard.clone());
        let (upstream, expected_node_id) = match resolved {
            Some(resolved) => (resolved.addr, Some(resolved.node_id)),
            None => (static_upstream.clone(), None),
        };
        let listener_tls = listener_tls.clone();
        let upstream_tls = upstream_tls.clone();
        tokio::spawn(async move {
            if let Err(err) = accept_and_tunnel(
                stream,
                addr,
                upstream,
                expected_node_id,
                listener_tls,
                upstream_tls,
            )
            .await
            {
                tracing::warn!(source = %addr, error = %err, "fetch tunnel failed");
            }
        });
    }
}

async fn accept_and_tunnel(
    inbound: TcpStream,
    source: std::net::SocketAddr,
    upstream: String,
    expected_node_id: Option<String>,
    listener_tls: Option<TlsIdentity>,
    upstream_tls: Option<TlsIdentity>,
) -> anyhow::Result<()> {
    let (inbound, _peer_identity) =
        radii_proto::tls::accept(inbound, listener_tls.as_ref()).await?;

    let target = normalize_upstream(&upstream);
    tracing::info!(source = %source, upstream = %target, expected_node_id = ?expected_node_id, "fetch tunneling");
    let outbound = radii_proto::tls::dial_expecting(
        &target,
        upstream_tls.as_ref(),
        expected_node_id.as_deref(),
    )
    .await?;

    handle_connection(inbound, outbound).await
}

async fn handle_connection(inbound: BoxedStream, outbound: BoxedStream) -> anyhow::Result<()> {
    let (mut ri, mut wi) = tokio::io::split(inbound);
    let (mut ro, mut wo) = tokio::io::split(outbound);

    let client_to_server = tokio::io::copy(&mut ri, &mut wo);
    let server_to_client = tokio::io::copy(&mut ro, &mut wi);
    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}

/// Normalize configured upstream addresses by stripping known URL-style prefixes.
pub fn normalize_upstream(upstream: &str) -> String {
    let trimmed = upstream.trim();
    if let Some(stripped) = trimmed.strip_prefix("ssh://") {
        return stripped.to_string();
    }
    if let Some(stripped) = trimmed.strip_prefix("tcp://") {
        return stripped.to_string();
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::normalize_upstream;

    #[test]
    fn strips_known_prefixes_and_whitespace() {
        assert_eq!(normalize_upstream("  ssh://127.0.0.1:22 "), "127.0.0.1:22");
        assert_eq!(normalize_upstream("tcp://10.0.0.1:443"), "10.0.0.1:443");
        assert_eq!(normalize_upstream("127.0.0.1:9000"), "127.0.0.1:9000");
    }
}
