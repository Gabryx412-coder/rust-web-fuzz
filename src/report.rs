use askama::Template;
use crate::modules::Vulnerability;
use crate::scanner::ScanResult;
use std::path::Path;
use std::fs;
use anyhow::Context;

#[derive(Template)]
#[template(path = "report.html")]
struct ReportTemplate {
    vulns: Vec<Vulnerability>,
    date: String,
}

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn save_json<T: serde::Serialize>(data: &T, path: &Path) -> anyhow::Result<()> {
        let f = fs::File::create(path)?;
        serde_json::to_writer_pretty(f, data)?;
        Ok(())
    }

    pub fn save_vulns(vulns: &[Vulnerability], path: &Path) -> anyhow::Result<()> {
        Self::save_json(vulns, path)
    }

    pub fn generate_html_report(
        json_input: impl AsRef<Path>,
        html_output: impl AsRef<Path>
    ) -> anyhow::Result<()> {
        let content = fs::read_to_string(json_input)?;
        let vulns: Vec<Vulnerability> = serde_json
            ::from_str(&content)
            .context("Invalid JSON report")?;

        let tmpl = ReportTemplate {
            vulns,
            date: chrono::Utc::now().to_rfc3339(),
        };

        let html = tmpl.render().context("Failed to render HTML")?;
        fs::write(html_output, html)?;
        Ok(())
    }
}
