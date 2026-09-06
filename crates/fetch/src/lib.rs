pub mod chain;
pub mod config;
pub mod graph;
pub mod relay;
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

    for warning in [
        config::graph_without_relay_warning(&config),
        config::relay_without_tunnel_listener_tls_warning(&config),
        config::graph_without_e2e_tls_warning(&config),
    ]
    .into_iter()
    .flatten()
    {
        tracing::warn!("{warning}");
    }

    // Relaying is opt-in: absent `[relay]`, this node neither forwards
    // chains for others nor terminates one addressed to it, and no second
    // listener is opened. Present, it is bound before the tunnel listener
    // starts serving, so a node advertised as a route target is reachable
    // as soon as it is up rather than after a race.
    if let Some(relay_config) = config.relay.clone() {
        let relay_listener = TcpListener::bind(&relay_config.bind).await?;
        let runtime =
            relay::RelayRuntime::new(relay_config, config.upstream.clone(), listener_tls.clone())?;
        tokio::spawn(async move {
            if let Err(err) = relay::run(relay_listener, runtime).await {
                tracing::error!(error = %err, "relay listener stopped");
            }
        });
    }

    match config.graph {
        Some(graph_config) => {
            let attempt_timeout_ms = graph_config.attempt_timeout_ms;
            let routes: graph::SharedRoutes = Arc::new(RwLock::new(Vec::new()));
            tokio::spawn(graph::run_poll(
                graph_config,
                Arc::clone(&routes),
                graph_tls,
            ));
            server::run_on_dynamic_with_tls(
                listener,
                config.upstream,
                routes,
                attempt_timeout_ms,
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
