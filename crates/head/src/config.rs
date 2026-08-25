use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub http: HttpConfig,
    pub radii: Option<RadiiConfig>,
    pub routing: RoutingConfig,
    pub graph: Option<GraphConfig>,
    /// Head's mTLS identity, used both for the Radii bridge listener
    /// (server role) and for dialing Crawl (client role, for the bridge and
    /// the graph poller). Absent means plaintext, matching today's default.
    /// See `docs/tls.md`.
    pub tls: Option<radii_proto::tls::TlsIdentityConfig>,
}

#[derive(Debug, Deserialize)]
pub struct HttpConfig {
    pub bind: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RadiiConfig {
    pub bind: String,
    pub crawl_upstream: String,
}

#[derive(Debug, Deserialize)]
pub struct RoutingConfig {
    pub default_backend: String,
    #[serde(default)]
    pub host_map: HashMap<String, String>,
}

/// Configures Head to resolve backends from Crawl's live reachability graph
/// instead of (or ahead of) the static `routing.host_map`.
#[derive(Debug, Deserialize, Clone)]
pub struct GraphConfig {
    pub crawl_upstream: String,
    #[serde(default = "default_source_node_id")]
    pub source_node_id: String,
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    #[serde(default)]
    pub allowed_protocols: Vec<String>,
    #[serde(default = "default_max_hops")]
    pub max_hops: usize,
    /// Maps an inbound HTTP host to the Crawl node id that should serve it.
    #[serde(default)]
    pub node_map: HashMap<String, String>,
}

fn default_source_node_id() -> String {
    "head".to_string()
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
    fn loads_example_shape() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            r#"
[http]
bind = "127.0.0.1:8080"

[radii]
bind = "127.0.0.1:7000"
crawl_upstream = "127.0.0.1:7100"

[routing]
default_backend = "http://127.0.0.1:9000"

[routing.host_map]
"example.com" = "http://10.0.0.10:9000"
"#
        )
        .unwrap();

        let config = load(file.path()).unwrap();
        assert_eq!(config.http.bind, "127.0.0.1:8080");
        assert_eq!(
            config.radii.as_ref().unwrap().crawl_upstream,
            "127.0.0.1:7100"
        );
        assert_eq!(
            config.routing.host_map.get("example.com").unwrap(),
            "http://10.0.0.10:9000"
        );
    }
}
