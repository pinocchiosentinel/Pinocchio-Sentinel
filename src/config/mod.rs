use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    pub rules: RuleConfig,
    pub output: OutputConfig,
    pub analysis: AnalysisConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub enabled_rules: Vec<String>,
    pub disabled_rules: Vec<String>,
    pub severity_overrides: std::collections::HashMap<String, String>,
    pub allow_list: Vec<String>,
    #[serde(default)]
    pub min_severity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: String,
    pub output_file: Option<String>,
    pub sarif_file: Option<String>,
    pub json_file: Option<String>,
    pub verbose: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub intra_procedural_only: bool,
    pub max_scan_time_ms: u64,
    pub include_skeletons: bool,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            rules: RuleConfig {
                enabled_rules: vec![
                    "PS-001".to_string(),
                    "PS-002".to_string(),
                    "PS-003".to_string(),
                    "PS-004".to_string(),
                    "PS-005".to_string(),
                    "PS-006".to_string(),
                    "PS-007".to_string(),
                    "PS-008".to_string(),
                    "PS-009".to_string(),
                    "PS-010".to_string(),
                    "PS-011".to_string(),
                    "PS-012".to_string(),
                    "PS-013".to_string(),
                    "PS-014".to_string(),
                ],
                disabled_rules: Vec::new(),
                severity_overrides: std::collections::HashMap::new(),
                allow_list: Vec::new(),
                min_severity: None,
            },
            output: OutputConfig {
                format: "cli".to_string(),
                output_file: None,
                sarif_file: None,
                json_file: None,
                verbose: false,
            },
            analysis: AnalysisConfig {
                intra_procedural_only: true,
                max_scan_time_ms: 5000,
                include_skeletons: true,
            },
        }
    }
}

impl SentinelConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let config: SentinelConfig = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }
    
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
    
    pub fn is_rule_enabled(&self, rule_id: &str) -> bool {
        !self.rules.disabled_rules.contains(&rule_id.to_string())
    }
    
    pub fn get_severity_override(&self, rule_id: &str) -> Option<&str> {
        self.rules.severity_overrides.get(rule_id).map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SentinelConfig::default();
        assert!(config.rules.enabled_rules.contains(&"PS-001".to_string()));
        assert!(config.analysis.intra_procedural_only);
    }

    #[test]
    fn test_is_rule_enabled() {
        let config = SentinelConfig::default();
        assert!(config.is_rule_enabled("PS-001"));
        
        let mut config = config;
        config.rules.disabled_rules.push("PS-001".to_string());
        assert!(!config.is_rule_enabled("PS-001"));
    }
}
