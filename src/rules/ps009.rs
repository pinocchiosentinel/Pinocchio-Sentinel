use super::{Rule, Finding, Severity, Confidence};
use crate::graph::{AccountAccessGraph, AccessType};

pub struct Ps009;

impl Rule for Ps009 {
    fn id(&self) -> &str {
        "PS-009"
    }

    fn description(&self) -> &str {
        "Lamport reduction without data zeroing (possible ghost account)"
    }

    fn severity(&self) -> Severity {
        Severity::HIGH
    }

    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account in &graph.accounts {
            if account.access_type == AccessType::Write || account.access_type == AccessType::Both {
                let name_lower = account.variable_name.to_lowercase();
                let is_lamport_target = name_lower.contains("lamport")
                    || name_lower.contains("balance")
                    || name_lower.contains("rent")
                    || name_lower.contains("fund")
                    || name_lower.contains("payment");

                if is_lamport_target {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Low,
                        message: format!(
                            "Account '{}' (index {}) is mutated - if lamports are reduced, data must be zeroed to prevent ghost account attacks",
                            account.variable_name, account.index
                        ),
                        account_index: Some(account.index),
                        line_number: account.line_number,
                        handler: graph.handler_name.clone(),
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
    use crate::graph::{AccountAccess, CheckInfo};

    #[test]
    fn test_ps009_lamport_target() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "user_lamports".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps009.check(&graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PS-009");
    }

    #[test]
    fn test_ps009_non_lamport_ignored() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "user_data".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps009.check(&graph);
        assert!(findings.is_empty());
    }
}
