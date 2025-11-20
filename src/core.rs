use crate::config::Config;
use crate::scanner::{ Scanner, ScanResult };
use crate::modules::{ Vulnerability, ModuleManager };
use crate::plugin_host::PluginEngine;
use crate::report::ReportGenerator;
use std::path::PathBuf;
use log::{ info, warn };

pub async fn run_scan(
    target: String,
    wordlist: Option<PathBuf>,
    config: Config
) -> anyhow::Result<()> {
    let scanner = Scanner::new(config.clone());
    let paths = if let Some(wl) = wordlist {
        std::fs
            ::read_to_string(wl)?
            .lines()
            .map(|s| s.to_string())
            .collect()
    } else {
        vec!["admin".to_string(), "login".to_string(), "config".to_string()]
    };

    let mut findings = Vec::new();

    // Directory Enum Phase
    info!("Phase 1: Directory Enumeration");
    for path in paths {
        let url = format!("{}/{}", target.trim_end_matches('/'), path);
        if let Ok(result) = scanner.check_url(&url).await {
            if result.status.is_success() || result.status.is_redirection() {
                info!("Found: {} [{}]", url, result.status);
                findings.push(result);
            }
        }
    }

    // Output results
    let report_path = PathBuf::from(&config.reports_path).join(
        format!("scan_report_{}.json", chrono::Utc::now().timestamp())
    );
    ReportGenerator::save_json(&findings, &report_path)?;
    info!("Scan complete. Report saved to {:?}", report_path);

    Ok(())
}

pub async fn run_fuzz(target: String, config: Config) -> anyhow::Result<()> {
    info!("Initializing Fuzzer Engine...");
    let scanner = Scanner::new(config.clone());
    let modules = ModuleManager::load_native();
    let mut plugin_engine = PluginEngine::new(&config.plugin_path)?;

    let mut vulnerabilities = Vec::new();

    // 1. Native Modules Scan
    info!("Running Native Modules...");
    for module in modules {
        let vulns = module.scan(&target, &scanner).await?;
        for v in vulns {
            warn!("VULNERABILITY FOUND: [{}] {}", v.severity, v.name);
            vulnerabilities.push(v);
        }
    }

    // 2. WASM Plugins Scan
    info!("Running WASM Plugins...");
    let plugin_vulns = plugin_engine.run_all(&target).await?;
    for v in plugin_vulns {
        warn!("PLUGIN FOUND: [{}] {}", v.severity, v.name);
        vulnerabilities.push(v);
    }

    let report_path = PathBuf::from(&config.reports_path).join(
        format!("fuzz_report_{}.json", chrono::Utc::now().timestamp())
    );
    ReportGenerator::save_vulns(&vulnerabilities, &report_path)?;
    info!("Fuzzing complete. Report saved to {:?}", report_path);

    Ok(())
}
