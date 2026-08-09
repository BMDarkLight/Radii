use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub http: HttpConfig,
    pub radii: Option<RadiiConfig>,
    pub routing: RoutingConfig,
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
