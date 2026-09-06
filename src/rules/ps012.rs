use super::{Rule, Finding, Severity, Confidence};
use crate::graph::{AccountAccessGraph, CheckType};

pub struct Ps012;

impl Rule for Ps012 {
    fn id(&self) -> &str {
        "PS-012"
    }

    fn description(&self) -> &str {
        "Slice index accessed without length assertion"
    }

    fn severity(&self) -> Severity {
        Severity::WARN
    }

    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account in &graph.accounts {
            if !graph.has_check_before_use(account.index, &CheckType::DataLen) {
                let name_lower = account.variable_name.to_lowercase();
                let is_slice = name_lower.contains("[")
                    || name_lower.contains("slice")
                    || name_lower.contains("data")
                    || name_lower.contains("instruction");

                if is_slice && account.access_type != crate::graph::AccessType::Read {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Low,
                        message: format!(
                            "Account '{}' (index {}) is accessed by index/slice without data_len() bounds check",
                            account.variable_name, account.index
                        ),
                        account_index: Some(account.index),
                        line_number: account.line_number,
                        handler: graph.handler_name.clone(),
                    evidence: None,
                    fix_suggestion: Some(format!(
                        "Add bounds check: `if data.len() < required_size {{ return Err(ProgramError::InvalidInstructionData); }}`",
                    )),
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{AccountAccess, AccessType, CheckInfo};

    #[test]
    fn test_ps012_slice_no_bounds() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "instruction_data".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps012.check(&graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PS-012");
        assert_eq!(findings[0].severity, Severity::WARN);
    }

    #[test]
    fn test_ps012_with_bounds_check() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "instruction_data".to_string(),
            access_type: AccessType::Write,
            checks: vec![CheckInfo {
                check_type: CheckType::DataLen,
                line_number: 5,
                is_before_use: true,
            }],
            line_number: Some(10),
        });

        let findings = Ps012.check(&graph);
        assert!(findings.is_empty());
    }
}
