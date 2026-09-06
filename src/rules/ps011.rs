use super::{Rule, Finding, Severity, Confidence};
use crate::graph::AccountAccessGraph;

pub struct Ps011;

impl Rule for Ps011 {
    fn id(&self) -> &str {
        "PS-011"
    }

    fn description(&self) -> &str {
        "lazy_program_entrypoint! invoked without account-count gate"
    }

    fn severity(&self) -> Severity {
        Severity::HIGH
    }

    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account in &graph.accounts {
            let name_lower = account.variable_name.to_lowercase();
            let is_direct_access = name_lower.starts_with("accounts[")
                && !name_lower.contains("len")
                && !name_lower.contains("is_empty");

            if is_direct_access && account.checks.is_empty() {
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity(),
                    confidence: Confidence::Low,
                    message: format!(
                        "Direct account access '{}' (index {}) without verifying accounts.len() - risky with lazy_program_entrypoint!",
                        account.variable_name, account.index
                    ),
                    account_index: Some(account.index),
                    line_number: account.line_number,
                    evidence: None,
                });
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
    fn test_ps011_direct_access_no_gate() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "accounts[0]".to_string(),
            access_type: AccessType::Read,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps011.check(&graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PS-011");
    }

    #[test]
    fn test_ps011_non_accounts_ignored() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "authority".to_string(),
            access_type: AccessType::Read,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps011.check(&graph);
        assert!(findings.is_empty());
    }
}
