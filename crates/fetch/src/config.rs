use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub bind: String,
    pub upstream: String,
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
