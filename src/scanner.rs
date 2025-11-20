use crate::config::Config;
use reqwest::{ Client, StatusCode };
use serde::{ Serialize, Deserialize };
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Scanner {
    client: Client,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanResult {
    pub url: String,
    pub status: u16,
    pub content_length: Option<u64>,
}

impl Scanner {
    pub fn new(config: Config) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.network.timeout_seconds))
            .user_agent(config.network.user_agent)
            .danger_accept_invalid_certs(true) // For testing/CTFs
            .build()
            .expect("Failed to build HTTP client");

        Self { client }
    }

    pub async fn check_url(&self, url: &str) -> anyhow::Result<ScanResult> {
        let res = self.client.get(url).send().await?;
        Ok(ScanResult {
            url: url.to_string(),
            status: res.status().as_u16(),
            content_length: res.content_length(),
        })
    }

    pub async fn fuzz_get(&self, url: &str, payload: &str) -> anyhow::Result<(StatusCode, String)> {
        // Naive injection: append payload. In a real scenario, parse URL and replace params.
        let target = if url.contains('?') {
            format!("{}{}", url, payload)
        } else {
            format!("{}?q={}", url, payload)
        };

        let res = self.client.get(&target).send().await?;
        let status = res.status();
        let body = res.text().await?;
        Ok((status, body))
    }
}
