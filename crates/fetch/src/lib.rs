pub mod config;
pub mod graph;
pub mod server;

use radii_proto::tls::TlsIdentity;
use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;

pub async fn run(config: config::Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.bind).await?;
    tracing::info!(bind = %config.bind, upstream = %config.upstream, "fetch tunnel listening");

    let graph_tls = config.tls.as_ref().map(TlsIdentity::load).transpose()?;
    let listener_tls = config
        .tunnel_tls
        .as_ref()
        .and_then(|t| t.listener.as_ref())
        .map(TlsIdentity::load)
        .transpose()?;
    let upstream_tls = config
        .tunnel_tls
        .as_ref()
        .and_then(|t| t.upstream.as_ref())
        .map(TlsIdentity::load)
        .transpose()?;

    match config.graph {
        Some(graph_config) => {
            let target: graph::SharedTarget = Arc::new(RwLock::new(None));
            tokio::spawn(graph::run_poll(
                graph_config,
                Arc::clone(&target),
                graph_tls,
            ));
            server::run_on_dynamic_with_tls(
                listener,
                config.upstream,
                target,
                listener_tls,
                upstream_tls,
            )
            .await
        }
        None => {
            server::run_on_with_tls(listener, config.upstream, listener_tls, upstream_tls).await
        }
    }
}
