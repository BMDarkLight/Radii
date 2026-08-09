use crate::{config, decision::DecisionEngine, http, radii};
use radii_core::registry::{BoxFuture, ProtocolRunner};

pub struct HttpRunner {
    bind: String,
    decision: DecisionEngine,
}

impl HttpRunner {
    pub fn new(bind: String, decision: DecisionEngine) -> Self {
        Self { bind, decision }
    }
}

impl ProtocolRunner for HttpRunner {
    fn name(&self) -> &'static str {
        "http"
    }

    fn start(&self) -> BoxFuture<'_> {
        let bind = self.bind.clone();
        let decision = self.decision.clone();
        Box::pin(async move { http::serve_http(&bind, decision).await })
    }
}

pub struct RadiiRunner {
    config: Option<config::RadiiConfig>,
}

impl RadiiRunner {
    pub fn maybe_new(config: Option<config::RadiiConfig>) -> Self {
        Self { config }
    }
}

impl ProtocolRunner for RadiiRunner {
    fn name(&self) -> &'static str {
        "radii"
    }

    fn start(&self) -> BoxFuture<'_> {
        let config = self.config.clone();
        Box::pin(async move { radii::maybe_run_radii(&config).await })
    }
}
