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
    /// Authenticated node ids permitted to relay `FromHead` envelopes on
    /// behalf of their own clients — in practice, the Head deployments in
    /// front of this Crawl.
    ///
    /// Empty (the default) means no peer may relay, which is the safe
    /// default: relaying lets a peer submit hellos and reports under an
    /// identity that is not its own, so it must be granted deliberately
    /// rather than inherited from merely holding a CA-issued certificate.
    /// Only enforced on mTLS connections; a plaintext listener has no peer
    /// identity to match against and stays unauthenticated, exactly as
    /// direct messages do.
    #[serde(default)]
    pub relay_peers: Vec<String>,
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

    #[test]
    fn relay_peers_defaults_to_empty() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bind = \"127.0.0.1:7100\"").unwrap();
        let config = load(file.path()).unwrap();
        assert!(
            config.relay_peers.is_empty(),
            "no peer may relay unless the operator names one"
        );
    }

    #[test]
    fn loads_explicit_relay_peers() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            "bind = \"127.0.0.1:7100\"\nrelay_peers = [\"head-1\", \"head-2\"]"
        )
        .unwrap();
        let config = load(file.path()).unwrap();
        assert_eq!(config.relay_peers, vec!["head-1", "head-2"]);
    }
}
