use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub bind: String,
    /// Requires mutual TLS on the Crawl listener when present; connections
    /// stay plaintext when absent. See `docs/tls.md`.
    pub tls: Option<radii_proto::tls::TlsIdentityConfig>,
    /// How long a node may go without sending a fresh `NodeHello` before it
    /// drops out of `GraphQuery` replies.
    #[serde(default = "default_node_ttl_ms")]
    pub node_ttl_ms: u64,
}

fn default_node_ttl_ms() -> u64 {
    60_000
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
    fn loads_bind() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bind = \"127.0.0.1:7100\"").unwrap();
        let config = load(file.path()).unwrap();
        assert_eq!(config.bind, "127.0.0.1:7100");
    }

    #[test]
    fn rejects_missing_bind() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "upstream = \"x\"").unwrap();
        assert!(load(file.path()).is_err());
    }

    #[test]
    fn defaults_node_ttl_ms_when_absent() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bind = \"127.0.0.1:7100\"").unwrap();
        let config = load(file.path()).unwrap();
        assert_eq!(config.node_ttl_ms, 60_000);
    }

    #[test]
    fn loads_explicit_node_ttl_ms() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bind = \"127.0.0.1:7100\"\nnode_ttl_ms = 5000").unwrap();
        let config = load(file.path()).unwrap();
        assert_eq!(config.node_ttl_ms, 5000);
    }
}
