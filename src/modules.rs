use async_trait::async_trait;
use crate::scanner::Scanner;
use serde::{ Serialize, Deserialize };
use std::fs;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vulnerability {
    pub name: String,
    pub severity: String, // Low, Medium, High, Critical
    pub description: String,
    pub evidence: String,
}

#[async_trait]
pub trait VulnModule {
    fn name(&self) -> &str;
    async fn scan(&self, target: &str, scanner: &Scanner) -> anyhow::Result<Vec<Vulnerability>>;
}

pub struct ModuleManager;

impl ModuleManager {
    pub fn load_native() -> Vec<Box<dyn VulnModule + Send + Sync>> {
        vec![Box::new(XssModule), Box::new(SqliModule), Box::new(RceProbeModule)]
    }
}

// --- Implementations ---

struct XssModule;
#[async_trait]
impl VulnModule for XssModule {
    fn name(&self) -> &str {
        "Reflected XSS"
    }
    async fn scan(&self, target: &str, scanner: &Scanner) -> anyhow::Result<Vec<Vulnerability>> {
        let payload = "<script>rwf_xss</script>";
        let (_, body) = scanner.fuzz_get(target, payload).await?;

        if body.contains(payload) {
            Ok(
                vec![Vulnerability {
                    name: "Reflected XSS".to_string(),
                    severity: "High".to_string(),
                    description: "Input reflected in response without sanitization".to_string(),
                    evidence: payload.to_string(),
                }]
            )
        } else {
            Ok(vec![])
        }
    }
}

struct SqliModule;
#[async_trait]
impl VulnModule for SqliModule {
    fn name(&self) -> &str {
        "SQL Injection (Error-based)"
    }
    async fn scan(&self, target: &str, scanner: &Scanner) -> anyhow::Result<Vec<Vulnerability>> {
        let payload = "'";
        let (_, body) = scanner.fuzz_get(target, payload).await?;

        let errors = ["SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL"];
        for err in errors {
            if body.contains(err) {
                return Ok(
                    vec![Vulnerability {
                        name: "SQL Injection".to_string(),
                        severity: "Critical".to_string(),
                        description: "Database error message leaked in response".to_string(),
                        evidence: format!("Payload: {}, Match: {}", payload, err),
                    }]
                );
            }
        }
        Ok(vec![])
    }
}

struct RceProbeModule;
#[async_trait]
impl VulnModule for RceProbeModule {
    fn name(&self) -> &str {
        "RCE Probe (Safe)"
    }
    async fn scan(&self, target: &str, scanner: &Scanner) -> anyhow::Result<Vec<Vulnerability>> {
        let payload = "; cat /etc/passwd";
        let (_, body) = scanner.fuzz_get(target, payload).await?;
        if body.contains("root:x:0:0") {
            return Ok(
                vec![Vulnerability {
                    name: "RCE Detected".to_string(),
                    severity: "Critical".to_string(),
                    description: "/etc/passwd leaked".to_string(),
                    evidence: "root:x:0:0 found in body".to_string(),
                }]
            );
        }
        Ok(vec![])
    }
}
