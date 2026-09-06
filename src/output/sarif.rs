use serde::{Deserialize, Serialize};
use crate::rules::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifSchema {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    pub information_uri: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
    pub full_description: SarifMessage,
    pub default_configuration: SarifRuleConfiguration,
    pub help_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRuleConfiguration {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResult {
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifLocation {
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRegion {
    pub start_line: u32,
}

pub fn to_sarif(findings: &[Finding]) -> String {
    let sarif = SarifSchema {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "pinocchio-sentinel".to_string(),
                    version: "0.1.0".to_string(),
                    information_uri: "https://github.com/pinocchio-sentinel/pinocchio-sentinel".to_string(),
                    rules: get_sarif_rules(),
                },
            },
            results: findings.iter().map(|f| finding_to_sarif(f)).collect(),
        }],
    };
    
    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}

fn get_sarif_rules() -> Vec<SarifRule> {
    vec![
        SarifRule {
            id: "PS-001".to_string(),
            name: "MissingSignerCheck".to_string(),
            short_description: SarifMessage {
                text: "Authority account used without is_signer() assertion".to_string(),
            },
            full_description: SarifMessage {
                text: "Account is used without verifying signer status before use".to_string(),
            },
            default_configuration: SarifRuleConfiguration {
                level: "error".to_string(),
            },
            help_uri: "https://github.com/pinocchio-sentinel/pinocchio-sentinel/docs/rules/PS-001".to_string(),
        },
        // Add other rules as needed
    ]
}

fn finding_to_sarif(finding: &Finding) -> SarifResult {
    SarifResult {
        rule_id: finding.rule_id.clone(),
        level: severity_to_sarif_level(&finding.severity),
        message: SarifMessage {
            text: finding.message.clone(),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: "unknown".to_string(), // Would be set from actual file path
                },
                region: SarifRegion {
                    start_line: finding.line_number.unwrap_or(0),
                },
            },
        }],
    }
}

fn severity_to_sarif_level(severity: &Severity) -> String {
    match severity {
        Severity::HIGH | Severity::MEDIUM => "error".to_string(),
        Severity::WARN | Severity::LOW => "warning".to_string(),
        Severity::INFO => "note".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Severity, Confidence};

    #[test]
    fn test_sarif_output() {
        let findings = vec![Finding {
            rule_id: "PS-001".to_string(),
            severity: Severity::HIGH,
            confidence: Confidence::High,
            message: "Test finding".to_string(),
            account_index: Some(0),
            line_number: Some(10),
            evidence: None,
        }];
        
        let sarif = to_sarif(&findings);
        assert!(sarif.contains("PS-001"));
        assert!(sarif.contains("error"));
    }
}
