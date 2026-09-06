use super::{Rule, Finding, Severity, Confidence};
use crate::graph::{AccountAccessGraph, CheckType};

pub struct Ps007;

impl Rule for Ps007 {
    fn id(&self) -> &str {
        "PS-007"
    }

    fn description(&self) -> &str {
        "CPI target program ID not compared against a known constant"
    }

    fn severity(&self) -> Severity {
        Severity::HIGH
    }

    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account in &graph.accounts {
            let name_lower = account.variable_name.to_lowercase();
            let is_program = name_lower.contains("program")
                || name_lower.contains("cpi")
                || name_lower.contains("target");

            if is_program && account.access_type != crate::graph::AccessType::Read {
                let has_comparison = graph.has_check_before_use(account.index, &CheckType::OwnedBy)
                    || graph.has_check_before_use(account.index, &CheckType::Custom("program_id".to_string()));

                if !has_comparison {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Low,
                        message: format!(
                            "Account '{}' (index {}) appears to be a CPI target but program ID is not compared against a constant",
                            account.variable_name, account.index
                        ),
                        account_index: Some(account.index),
                        line_number: account.line_number,
                        evidence: None,
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
    use crate::graph::{AccountAccess, AccessType};

    #[test]
    fn test_ps007_cpi_target_no_comparison() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "target_program".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps007.check(&graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PS-007");
    }

    #[test]
    fn test_ps007_non_program_ignored() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "user_wallet".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps007.check(&graph);
        assert!(findings.is_empty());
    }
}
