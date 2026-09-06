use super::{Rule, Finding, Severity, Confidence};
use crate::graph::{AccountAccessGraph, AccessType, CheckType};

pub struct Ps010;

impl Rule for Ps010 {
    fn id(&self) -> &str {
        "PS-010"
    }

    fn description(&self) -> &str {
        "Account mutated without is_writable() assertion"
    }

    fn severity(&self) -> Severity {
        Severity::HIGH
    }

    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account in &graph.accounts {
            if account.access_type == AccessType::Write || account.access_type == AccessType::Both {
                if !graph.has_check_before_use(account.index, &CheckType::IsWritable) {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Medium,
                        message: format!(
                            "Account '{}' (index {}) is mutated without is_writable() check",
                            account.variable_name, account.index
                        ),
                        account_index: Some(account.index),
                        line_number: account.line_number,
                        handler: graph.handler_name.clone(),
                    evidence: None,
                    fix_suggestion: Some(format!(
                        "Add writable check: `if !{}.is_writable() {{ return Err(ProgramError::InvalidAccountData); }}`",
                        account.variable_name
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
    use crate::graph::{AccountAccess, CheckInfo};

    #[test]
    fn test_ps010_missing_writable() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "accounts[0]".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps010.check(&graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PS-010");
        assert_eq!(findings[0].severity, Severity::HIGH);
    }

    #[test]
    fn test_ps010_with_writable_check() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "accounts[0]".to_string(),
            access_type: AccessType::Write,
            checks: vec![CheckInfo {
                check_type: CheckType::IsWritable,
                line_number: 5,
                is_before_use: true,
            }],
            line_number: Some(10),
        });

        let findings = Ps010.check(&graph);
        assert!(findings.is_empty());
    }
}
