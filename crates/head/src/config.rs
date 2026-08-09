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
