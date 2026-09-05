use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub bind: String,
    pub upstream: String,
    pub graph: Option<GraphConfig>,
    /// Fetch's mTLS identity for dialing Crawl from the graph poller. Absent
    /// means plaintext, matching today's default. See `docs/tls.md`.
    pub tls: Option<radii_proto::tls::TlsIdentityConfig>,
    /// TLS for the tunnel *data path* itself — independent from `tls`
    /// above, which only protects the graph poller's connection to Crawl.
    pub tunnel_tls: Option<TunnelTlsConfig>,
    /// This node's relay listener. Absent (the default) means the node
    /// neither forwards chains for others nor terminates one addressed to
    /// it.
    pub relay: Option<RelayConfig>,
}

/// Accepts either a bare string or a list, so configs written against the
/// single-target shape keep loading unchanged.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl From<OneOrMany> for Vec<String> {
    fn from(value: OneOrMany) -> Self {
        match value {
            OneOrMany::One(one) => vec![one],
            OneOrMany::Many(many) => many,
        }
    }
}

/// A node's relay listener. Absent means the node neither forwards chains nor
/// terminates them.
#[derive(Debug, Deserialize, Clone)]
pub struct RelayConfig {
    pub bind: String,
    /// This node's own id. A `TunnelOpen` whose first hop names anything else
    /// is refused before any dialing happens.
    pub node_id: String,
    #[serde(default = "default_relay_max_hops")]
    pub max_hops: usize,
    #[serde(default = "default_max_concurrent_total")]
    pub max_concurrent_total: usize,
    #[serde(default = "default_max_concurrent_per_peer")]
    pub max_concurrent_per_peer: usize,
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// Empty means any peer holding a certificate from the configured CA.
    #[serde(default)]
    pub allow_peers: Vec<String>,
    /// Required. Enforced in [`load`], not by serde, so the error names the
    /// field an operator has to add.
    pub tls: Option<radii_proto::tls::TlsIdentityConfig>,
}

fn default_relay_max_hops() -> usize {
    8
}

fn default_max_concurrent_total() -> usize {
    256
}

fn default_max_concurrent_per_peer() -> usize {
    8
}

fn default_idle_timeout_ms() -> u64 {
    30_000
}

fn default_max_candidates() -> usize {
    3
}

fn default_attempt_timeout_ms() -> u64 {
    3000
}

/// `listener` and `upstream` are independent and both optional: `listener`
/// requires inbound clients to authenticate via mTLS before Fetch will
/// tunnel their bytes anywhere; `upstream` dials the upstream over mTLS
/// instead of plaintext TCP. A deployment can enable either, both, or
/// neither.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct TunnelTlsConfig {
    pub listener: Option<radii_proto::tls::TlsIdentityConfig>,
    pub upstream: Option<radii_proto::tls::TlsIdentityConfig>,
}

/// Configures Fetch to resolve its upstream from Crawl's live reachability
/// graph instead of the static `upstream` above. `upstream` remains the
/// fallback used when no reachable route to `target_node_id` exists yet.
#[derive(Debug, Deserialize, Clone)]
pub struct GraphConfig {
    pub crawl_upstream: String,
    #[serde(default = "default_source_node_id")]
    pub source_node_id: String,
    #[serde(rename = "target_node_id", alias = "target_node_ids")]
    target_node_ids_raw: OneOrMany,
    /// Normalised form of `target_node_ids_raw`, populated by [`load`] after
    /// parsing since a bare string or a list must both end up here.
    #[serde(skip)]
    pub target_node_ids: Vec<String>,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default)]
    pub allowed_protocols: Vec<String>,
    #[serde(default = "default_max_hops")]
    pub max_hops: usize,
    #[serde(default = "default_max_candidates")]
    pub max_candidates: usize,
    #[serde(default = "default_attempt_timeout_ms")]
    pub attempt_timeout_ms: u64,
}

fn default_source_node_id() -> String {
    "fetch".to_string()
}

fn default_poll_interval_ms() -> u64 {
    5000
}

fn default_max_hops() -> usize {
    4
}

pub fn load(path: &Path) -> anyhow::Result<Config> {
    let contents = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&contents)?;

    if let Some(graph) = config.graph.as_mut() {
        graph.target_node_ids = graph.target_node_ids_raw.clone().into();
        if graph.target_node_ids.is_empty() {
            anyhow::bail!("graph.target_node_ids must name at least one node");
        }
    }

    if let Some(relay) = config.relay.as_ref() {
        if relay.tls.is_none() {
            anyhow::bail!(
                "[relay.tls] is required: a relay listener without mutual TLS is an open \
                 proxy. See SECURITY.md"
            );
        }
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn loads_bind_and_upstream() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bind = \"0.0.0.0:2223\"").unwrap();
        writeln!(file, "upstream = \"ssh://127.0.0.1:22\"").unwrap();
        let config = load(file.path()).unwrap();
        assert_eq!(config.bind, "0.0.0.0:2223");
        assert_eq!(config.upstream, "ssh://127.0.0.1:22");
    }

    #[test]
    fn relay_is_absent_by_default() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bind = \"0.0.0.0:2223\"").unwrap();
        writeln!(file, "upstream = \"127.0.0.1:22\"").unwrap();
        let config = load(file.path()).unwrap();
        assert!(config.relay.is_none(), "relaying must be opt-in");
    }

    #[test]
    fn loads_relay_with_defaults() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bind = \"0.0.0.0:2223\"").unwrap();
        writeln!(file, "upstream = \"127.0.0.1:22\"").unwrap();
        writeln!(file, "[relay]").unwrap();
        writeln!(file, "bind = \"0.0.0.0:2224\"").unwrap();
        writeln!(file, "node_id = \"node-r\"").unwrap();
        writeln!(file, "[relay.tls]").unwrap();
        writeln!(file, "cert = \"/tmp/c.pem\"").unwrap();
        writeln!(file, "key = \"/tmp/k.pem\"").unwrap();
        writeln!(file, "ca = \"/tmp/ca.pem\"").unwrap();

        let relay = load(file.path()).unwrap().relay.expect("relay present");
        assert_eq!(relay.bind, "0.0.0.0:2224");
        assert_eq!(relay.max_hops, 8);
        assert_eq!(relay.max_concurrent_total, 256);
        assert_eq!(relay.max_concurrent_per_peer, 8);
        assert_eq!(relay.idle_timeout_ms, 30_000);
        assert!(relay.allow_peers.is_empty());
    }

    #[test]
    fn rejects_a_relay_without_tls() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bind = \"0.0.0.0:2223\"").unwrap();
        writeln!(file, "upstream = \"127.0.0.1:22\"").unwrap();
        writeln!(file, "[relay]").unwrap();
        writeln!(file, "bind = \"0.0.0.0:2224\"").unwrap();
        writeln!(file, "node_id = \"node-r\"").unwrap();

        let err = load(file.path()).unwrap_err();
        assert!(
            err.to_string().contains("relay.tls"),
            "a relay without mTLS is an open proxy; got: {err}"
        );
    }

    #[test]
    fn accepts_the_legacy_scalar_target_node_id() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bind = \"0.0.0.0:2223\"").unwrap();
        writeln!(file, "upstream = \"127.0.0.1:22\"").unwrap();
        writeln!(file, "[graph]").unwrap();
        writeln!(file, "crawl_upstream = \"127.0.0.1:7100\"").unwrap();
        writeln!(file, "target_node_id = \"node-b\"").unwrap();

        let graph = load(file.path()).unwrap().graph.expect("graph present");
        assert_eq!(graph.target_node_ids, vec!["node-b".to_string()]);
        assert_eq!(graph.max_candidates, 3);
        assert_eq!(graph.attempt_timeout_ms, 3000);
    }

    #[test]
    fn accepts_a_target_node_id_list() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bind = \"0.0.0.0:2223\"").unwrap();
        writeln!(file, "upstream = \"127.0.0.1:22\"").unwrap();
        writeln!(file, "[graph]").unwrap();
        writeln!(file, "crawl_upstream = \"127.0.0.1:7100\"").unwrap();
        writeln!(file, "target_node_ids = [\"node-b\", \"node-c\"]").unwrap();

        let graph = load(file.path()).unwrap().graph.expect("graph present");
        assert_eq!(
            graph.target_node_ids,
            vec!["node-b".to_string(), "node-c".to_string()]
        );
    }
}
