use crate::{config, decision::DecisionEngine, graph, http, radii};
use radii_core::registry::{BoxFuture, ProtocolRunner};
use radii_proto::tls::TlsIdentity;
use std::sync::Arc;

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
    tls: Option<TlsIdentity>,
}

impl RadiiRunner {
    pub fn maybe_new(config: Option<config::RadiiConfig>, tls: Option<TlsIdentity>) -> Self {
        Self { config, tls }
    }
}

impl ProtocolRunner for RadiiRunner {
    fn name(&self) -> &'static str {
        "radii"
    }

    fn start(&self) -> BoxFuture<'_> {
        let config = self.config.clone();
        let tls = self.tls.clone();
        Box::pin(async move { radii::maybe_run_radii(&config, tls).await })
    }
}

pub struct GraphPollRunner {
    config: Option<config::GraphConfig>,
    state: graph::SharedGraphState,
    tls: Option<TlsIdentity>,
}

impl GraphPollRunner {
    pub fn maybe_new(
        config: Option<config::GraphConfig>,
        state: graph::SharedGraphState,
        tls: Option<TlsIdentity>,
    ) -> Self {
        Self { config, state, tls }
    }
}

impl ProtocolRunner for GraphPollRunner {
    fn name(&self) -> &'static str {
        "graph"
    }

    fn start(&self) -> BoxFuture<'_> {
        let config = self.config.clone();
        let state = Arc::clone(&self.state);
        let tls = self.tls.clone();
        Box::pin(async move {
            let Some(config) = config else {
                return Ok(());
            };
            graph::run_poll(config, state, tls).await
        })
    }
}
