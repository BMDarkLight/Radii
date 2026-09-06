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
    /// Maps an inbound HTTP host to the Crawl node ids that may serve it.
    /// A bare string is accepted for the single-node form, so configs
    /// written before multiple targets existed keep loading.
    #[serde(default, rename = "node_map")]
    node_map_raw: HashMap<String, OneOrMany>,
    /// Normalised form of `node_map_raw`, populated by [`load`].
    #[serde(skip)]
    pub node_map: HashMap<String, Vec<String>>,
    #[serde(default = "default_max_candidates")]
    pub max_candidates: usize,
}

fn default_source_node_id() -> String {
    "head".to_string()
}

fn default_poll_interval_ms() -> u64 {
    5000
}

/// Accepts either a bare string or a list, so a host mapped to one node
/// keeps its original spelling.
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

fn default_max_candidates() -> usize {
    3
}

fn default_max_hops() -> usize {
    4
}

pub fn load(path: &Path) -> anyhow::Result<Config> {
    let contents = fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&contents)?;
    if let Some(graph) = config.graph.as_mut() {
        graph.node_map = graph
            .node_map_raw
            .iter()
            .map(|(host, ids)| (host.clone(), ids.clone().into()))
            .collect();
    }
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

    /// `node_map_raw` is renamed to the TOML key `node_map` so `[graph.node_map]`
    /// is actually read. Without `#[serde(rename = "node_map")]` this field
    /// silently stays empty, `GraphRoutePolicy` matches no host, and every
    /// request falls through to `host_map`/default — exactly the shape of
    /// `head.example.toml`. This test goes through `load()`, not
    /// `GraphRoutePolicy::new` directly, so it actually exercises the
    /// serde/normalisation path that broke.
    #[test]
    fn loads_graph_node_map_from_config() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            r#"
[http]
bind = "127.0.0.1:8080"

[routing]
default_backend = "http://127.0.0.1:9000"

[graph]
crawl_upstream = "127.0.0.1:7100"

[graph.node_map]
"example.com" = ["node-b", "node-c"]
"single.example.com" = "node-b"
"#
        )
        .unwrap();

        let config = load(file.path()).unwrap();
        let graph = config.graph.expect("graph present");
        assert_eq!(
            graph.node_map.get("example.com").unwrap(),
            &vec!["node-b".to_string(), "node-c".to_string()]
        );
        assert_eq!(
            graph.node_map.get("single.example.com").unwrap(),
            &vec!["node-b".to_string()]
        );
    }
}
