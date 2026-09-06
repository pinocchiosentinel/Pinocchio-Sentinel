use crate::rules::{Finding, Severity};
use serde::{Deserialize, Serialize};

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
    #[serde(rename = "properties")]
    pub properties: SarifRuleProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifRuleProperties {
    pub tags: Vec<String>,
    pub precision: String,
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
    #[serde(rename = "properties")]
    pub properties: SarifResultProperties,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifResultProperties {
    pub confidence: String,
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

const REPO_BASE: &str = "https://github.com/pinocchio-sentinel/pinocchio-sentinel";

pub fn to_sarif(findings: &[Finding]) -> String {
    let sarif = SarifSchema {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "pinocchio-sentinel".to_string(),
                    version: "0.1.0".to_string(),
                    information_uri: format!("{}/blob/main/README.md", REPO_BASE),
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
        sarif_rule("PS-001", "MissingSignerCheck",
            "Authority account used without is_signer() assertion",
            "Account is used without verifying signer status before use",
            "security", "medium"),
        sarif_rule("PS-002", "MissingOwnerCheck",
            "Account data read without owned_by() assertion",
            "Account data is read without verifying program ownership",
            "security", "medium"),
        sarif_rule("PS-003", "MissingDiscriminantCheck",
            "Account cast without discriminant check",
            "Account data is interpreted without verifying the discriminant bytes",
            "security", "medium"),
        sarif_rule("PS-004", "MissingBoundsCheck",
            "Zero-copy cast without data_len() bounds assertion",
            "Account data is accessed by index without checking data length",
            "security", "medium"),
        sarif_rule("PS-005", "PdaBumpNotCanonical",
            "PDA used without canonical bump verification",
            "Program Derived Address is used without verifying the canonical bump seed",
            "security", "medium"),
        sarif_rule("PS-006", "AccountAliasing",
            "Two account indices may alias, both mutated",
            "Two mutable account references may point to the same account",
            "security", "medium"),
        sarif_rule("PS-007", "ArbitraryCpi",
            "CPI target program ID not compared against constant",
            "Cross-program invocation target is not verified against a known program ID",
            "security", "high"),
        sarif_rule("PS-008", "AccountReinitialization",
            "Initialization path reachable on already-initialized account",
            "Account can be re-initialized because no guard prevents writing init data to an existing account",
            "security", "high"),
        sarif_rule("PS-009", "LamportZeroingMissing",
            "Lamport reduction without data zeroing",
            "Account lamports are reduced without zeroing data, allowing ghost account attacks",
            "security", "high"),
        sarif_rule("PS-010", "MissingWritableCheck",
            "Account mutated without is_writable() assertion",
            "Account is mutated without verifying it was marked as writable",
            "security", "medium"),
        sarif_rule("PS-011", "MissingAccountCountGate",
            "lazy_program_entrypoint! invoked without account-count gate",
            "Account slice is indexed without verifying accounts.len() first",
            "security", "high"),
        sarif_rule("PS-012", "SliceIndexWithoutBounds",
            "Slice index accessed without length assertion",
            "Instruction data or account data is indexed without checking the slice length",
            "security", "medium"),
        sarif_rule("PS-013", "UncheckedCpiReturn",
            "CPI return value not checked",
            "Cross-program invocation return value is not verified for errors",
            "security", "high"),
        sarif_rule("PS-014", "SysvarWithoutPubkeyCheck",
            "Sysvar account used without pubkey comparison",
            "Sysvar account is used without verifying its pubkey matches the known sysvar address",
            "security", "high"),
    ]
}

fn sarif_rule(
    id: &str,
    name: &str,
    short_desc: &str,
    full_desc: &str,
    tag: &str,
    precision: &str,
) -> SarifRule {
    SarifRule {
        id: id.to_string(),
        name: name.to_string(),
        short_description: SarifMessage {
            text: short_desc.to_string(),
        },
        full_description: SarifMessage {
            text: full_desc.to_string(),
        },
        default_configuration: SarifRuleConfiguration {
            level: "error".to_string(),
        },
        help_uri: format!("{}/blob/main/docs/rules/{}.md", REPO_BASE, id),
        properties: SarifRuleProperties {
            tags: vec!["security".to_string(), tag.to_string()],
            precision: precision.to_string(),
        },
    }
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
                    uri: "unknown".to_string(),
                },
                region: SarifRegion {
                    start_line: finding.line_number.unwrap_or(0),
                },
            },
        }],
        properties: SarifResultProperties {
            confidence: format!("{:?}", finding.confidence).to_lowercase(),
        },
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
    use crate::rules::{Confidence, Severity};

    #[test]
    fn test_sarif_output() {
        let findings = vec![Finding {
            rule_id: "PS-001".to_string(),
            severity: Severity::HIGH,
            confidence: Confidence::High,
            message: "Test finding".to_string(),
            handler: "test_handler".to_string(),
            account_index: Some(0),
            line_number: Some(10),
            evidence: None,
            fix_suggestion: None,
        }];

        let sarif = to_sarif(&findings);
        assert!(sarif.contains("PS-001"));
        assert!(sarif.contains("error"));
        assert!(sarif.contains("MissingSignerCheck"));
        assert!(sarif.contains("tags"));
        assert!(sarif.contains("precision"));
        assert!(sarif.contains("confidence"));
    }

    #[test]
    fn test_all_rules_present() {
        let sarif = to_sarif(&[]);
        let rules = [
            "PS-001", "PS-002", "PS-003", "PS-004", "PS-005", "PS-006", "PS-007", "PS-008",
            "PS-009", "PS-010", "PS-011", "PS-012", "PS-013", "PS-014",
        ];
        for rule in rules {
            assert!(sarif.contains(rule), "SARIF should contain {}", rule);
        }
    }
}
