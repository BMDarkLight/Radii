use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub bind: String,
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
}
