pub mod cli;
pub mod html;
pub mod json;
pub mod markdown;
pub mod sarif;

use crate::rules::{Finding, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub scan_time_ms: u64,
    pub files_scanned: usize,
    pub rules_applied: usize,
}

impl ScanResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn high_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::HIGH)
            .collect()
    }

    pub fn medium_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::MEDIUM)
            .collect()
    }

    pub fn has_high_findings(&self) -> bool {
        !self.high_findings().is_empty()
    }

    pub fn summary(&self) -> String {
        format!(
            "Scanned {} files, applied {} rules, found {} findings ({} HIGH, {} MEDIUM)",
            self.files_scanned,
            self.rules_applied,
            self.findings.len(),
            self.high_findings().len(),
            self.medium_findings().len()
        )
    }
}

pub use cli::{print_findings, print_summary};

pub fn format_findings(findings: &[Finding], format: &str) -> String {
    match format {
        "sarif" => sarif::to_sarif(findings),
        "json" => json::to_json(findings),
        "html" => html::to_html(findings),
        "markdown" | "md" => markdown::to_markdown(findings),
        _ => cli::to_cli(findings),
    }
}
