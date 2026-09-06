use super::{Confidence, Finding, Rule, Severity};
use crate::graph::{AccountAccessGraph, CheckType};

pub struct Ps013;

impl Rule for Ps013 {
    fn id(&self) -> &str {
        "PS-013"
    }

    fn description(&self) -> &str {
        "CPI return value not checked"
    }

    fn severity(&self) -> Severity {
        Severity::HIGH
    }

    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account in &graph.accounts {
            let name_lower = account.variable_name.to_lowercase();
            let is_cpi_call = name_lower.contains("invoke")
                || name_lower.contains("cpi")
                || name_lower.contains("target");

            if is_cpi_call {
                let has_check = graph.has_check_before_use(account.index, &CheckType::CpiReturn)
                    || graph.has_check_before_use(
                        account.index,
                        &CheckType::Custom("is_ok".to_string()),
                    )
                    || graph.has_check_before_use(
                        account.index,
                        &CheckType::Custom("unwrap".to_string()),
                    );

                if !has_check {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Medium,
                        message: format!(
                            "CPI call '{}' (index {}) may not have its return value checked",
                            account.variable_name, account.index
                        ),
                        account_index: Some(account.index),
                        line_number: account.line_number,
                        handler: graph.handler_name.clone(),
                        evidence: None,
                        fix_suggestion: Some(format!(
                            "Check CPI return: `invoke(...)?;` instead of `let _ = invoke(...);`",
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
    use crate::graph::{AccessType, AccountAccess, CheckInfo};

    #[test]
    fn test_ps013_unchecked_cpi() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "invoke_target".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps013.check(&graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PS-013");
    }

    #[test]
    fn test_ps013_checked_cpi() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "invoke_target".to_string(),
            access_type: AccessType::Write,
            checks: vec![CheckInfo {
                check_type: CheckType::CpiReturn,
                line_number: 10,
                is_before_use: true,
            }],
            line_number: Some(10),
        });

        let findings = Ps013.check(&graph);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ps013_non_cpi_ignored() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "user_wallet".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps013.check(&graph);
        assert!(findings.is_empty());
    }
}
