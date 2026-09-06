use serde::{Deserialize, Serialize};
use crate::rules::Finding;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonOutput {
    pub findings: Vec<Finding>,
    pub summary: JsonSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSummary {
    pub total_findings: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub warn_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

pub fn to_json(findings: &[Finding]) -> String {
    let output = JsonOutput {
        findings: findings.to_vec(),
        summary: JsonSummary {
            total_findings: findings.len(),
            high_count: findings.iter().filter(|f| f.severity == crate::rules::Severity::HIGH).count(),
            medium_count: findings.iter().filter(|f| f.severity == crate::rules::Severity::MEDIUM).count(),
            warn_count: findings.iter().filter(|f| f.severity == crate::rules::Severity::WARN).count(),
            low_count: findings.iter().filter(|f| f.severity == crate::rules::Severity::LOW).count(),
            info_count: findings.iter().filter(|f| f.severity == crate::rules::Severity::INFO).count(),
        },
    };
    
    serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
}

pub fn parse_json(input: &str) -> Result<JsonOutput, serde_json::Error> {
    serde_json::from_str(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Severity, Confidence};

    #[test]
    fn test_json_output() {
        let findings = vec![Finding {
            rule_id: "PS-001".to_string(),
            severity: Severity::HIGH,
            confidence: Confidence::High,
            message: "Test finding".to_string(),
            handler: "test_handler".to_string(),
            account_index: Some(0),
            line_number: Some(10),
            evidence: None,
        }];
        
        let json = to_json(&findings);
        assert!(json.contains("PS-001"));
        assert!(json.contains("high_count"));
        
        let parsed: JsonOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.summary.total_findings, 1);
        assert_eq!(parsed.summary.high_count, 1);
    }
}
