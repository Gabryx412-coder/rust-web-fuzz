use serde::Deserialize;
use std::path::Path;
use std::fs;
use anyhow::Context;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub network: NetworkConfig,
    pub concurrency: usize,
    pub plugin_path: String,
    pub payload_path: String,
    pub reports_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub timeout_seconds: u64,
    pub user_agent: String,
    pub follow_redirects: bool,
}

pub fn load_config<P: AsRef<Path>>(path: P) -> anyhow::Result<Config> {
    let content = fs::read_to_string(path).context("Failed to read config file")?;
    let config: Config = serde_yaml::from_str(&content).context("Failed to parse YAML config")?;
    Ok(config)
}
