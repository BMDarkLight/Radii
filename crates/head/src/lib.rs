pub mod config;
pub mod decision;
pub mod http;
pub mod radii;
pub mod runners;

use crate::decision::DecisionEngine;
use radii_core::registry::ProtocolRegistry;

pub async fn run(config: config::Config) -> anyhow::Result<()> {
    let decision = DecisionEngine::from_config(&config.routing);

    let registry = ProtocolRegistry::new()
        .register(runners::HttpRunner::new(
            config.http.bind.clone(),
            decision.clone(),
        ))
        .register(runners::RadiiRunner::maybe_new(config.radii.clone()));

    registry.run_all().await
}
