pub mod config;
pub mod graph;
pub mod server;

use std::sync::{Arc, RwLock};
use tokio::net::TcpListener;

pub async fn run(config: config::Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.bind).await?;
    tracing::info!(bind = %config.bind, upstream = %config.upstream, "fetch tunnel listening");

    match config.graph {
        Some(graph_config) => {
            let target: graph::SharedTarget = Arc::new(RwLock::new(None));
            tokio::spawn(graph::run_poll(graph_config, Arc::clone(&target)));
            server::run_on_dynamic(listener, config.upstream, target).await
        }
        None => server::run_on(listener, &config.upstream).await,
    }
}
