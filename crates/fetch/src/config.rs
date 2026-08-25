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
    pub target_node_id: String,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default)]
    pub allowed_protocols: Vec<String>,
    #[serde(default = "default_max_hops")]
    pub max_hops: usize,
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
    let config = toml::from_str(&contents)?;
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
}
