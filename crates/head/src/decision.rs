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
