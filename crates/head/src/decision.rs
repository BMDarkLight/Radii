use crate::config::RoutingConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Http,
    Other,
}

pub struct DecisionInput<'a> {
    pub protocol: Protocol,
    pub protocol_label: Option<&'a str>,
    pub host: Option<&'a str>,
    pub source: Option<SocketAddr>,
    pub destination_port: Option<u16>,
    pub attributes: &'a [(&'a str, &'a str)],
}

#[derive(Clone)]
pub struct BackendDecision {
    pub backend: String,
    pub reason: DecisionReason,
}

#[derive(Clone, Copy, Debug)]
pub enum DecisionReason {
    HostMatch,
    Default,
}

pub trait DecisionPolicy: Send + Sync {
    fn evaluate(&self, input: &DecisionInput<'_>) -> Option<BackendDecision>;
}

#[derive(Clone)]
pub struct DecisionEngine {
    policies: Vec<Arc<dyn DecisionPolicy>>,
}

impl DecisionEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    pub fn with_policy(mut self, policy: impl DecisionPolicy + 'static) -> Self {
        self.policies.push(Arc::new(policy));
        self
    }

    pub fn from_config(config: &RoutingConfig) -> Self {
        Self::new()
            .with_policy(HostMapPolicy::new(config.host_map.clone()))
            .with_policy(DefaultPolicy::new(config.default_backend.clone()))
    }

    pub fn decide(&self, input: DecisionInput<'_>) -> BackendDecision {
        for policy in &self.policies {
            if let Some(decision) = policy.evaluate(&input) {
                return decision;
            }
        }

        BackendDecision {
            backend: "unreachable".to_string(),
            reason: DecisionReason::Default,
        }
    }
}

impl Default for DecisionEngine {
    fn default() -> Self {
        Self::new()
    }
}

pub struct HostMapPolicy {
    host_map: HashMap<String, String>,
}

impl HostMapPolicy {
    pub fn new(host_map: HashMap<String, String>) -> Self {
        Self { host_map }
    }
}

impl DecisionPolicy for HostMapPolicy {
    fn evaluate(&self, input: &DecisionInput<'_>) -> Option<BackendDecision> {
        let host = input.host?;
        let backend = self.host_map.get(host)?;
        Some(BackendDecision {
            backend: backend.clone(),
            reason: DecisionReason::HostMatch,
        })
    }
}

pub struct DefaultPolicy {
    backend: String,
}

impl DefaultPolicy {
    pub fn new(backend: String) -> Self {
        Self { backend }
    }
}

impl DecisionPolicy for DefaultPolicy {
    fn evaluate(&self, _input: &DecisionInput<'_>) -> Option<BackendDecision> {
        Some(BackendDecision {
            backend: self.backend.clone(),
            reason: DecisionReason::Default,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RoutingConfig;

    fn input(host: Option<&str>) -> DecisionInput<'_> {
        DecisionInput {
            protocol: Protocol::Http,
            protocol_label: None,
            host,
            source: None,
            destination_port: None,
            attributes: &[],
        }
    }

    #[test]
    fn prefers_host_map_over_default() {
        let mut host_map = HashMap::new();
        host_map.insert("example.com".into(), "http://10.0.0.10:9000".into());
        let engine = DecisionEngine::from_config(&RoutingConfig {
            default_backend: "http://127.0.0.1:9000".into(),
            host_map,
        });

        let matched = engine.decide(input(Some("example.com")));
        assert_eq!(matched.backend, "http://10.0.0.10:9000");
        assert!(matches!(matched.reason, DecisionReason::HostMatch));

        let fallback = engine.decide(input(Some("other.example")));
        assert_eq!(fallback.backend, "http://127.0.0.1:9000");
        assert!(matches!(fallback.reason, DecisionReason::Default));
    }

    #[test]
    fn empty_engine_returns_unreachable() {
        let engine = DecisionEngine::new();
        let decision = engine.decide(input(None));
        assert_eq!(decision.backend, "unreachable");
    }
}
