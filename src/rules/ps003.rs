use super::{Confidence, Finding, Rule, Severity};
use crate::graph::{AccountAccessGraph, CheckType};

pub struct Ps003;

impl Rule for Ps003 {
    fn id(&self) -> &str {
        "PS-003"
    }

    fn description(&self) -> &str {
        "Account cast without a preceding discriminant check; handles 1-byte and 4-byte u32 schemes"
    }

    fn severity(&self) -> Severity {
        Severity::HIGH
    }

    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account in &graph.accounts {
            if account.access_type != crate::graph::AccessType::Read
                && !graph.has_check_before_use(account.index, &CheckType::Discriminant)
            {
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity(),
                    confidence: Confidence::Medium,
                    message: format!(
                        "Account '{}' (index {}) is cast without discriminant check",
                        account.variable_name, account.index
                    ),
                    account_index: Some(account.index),
                    line_number: account.line_number,
                    handler: graph.handler_name.clone(),
                    evidence: None,
                    fix_suggestion: Some(
                        "Add discriminant check: `if &data[0..8] != &EXPECTED_DISCRIMINATOR { return Err(ProgramError::InvalidAccountData); }`"
                            .to_string(),
                    ),
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{AccessType, AccountAccess};

    #[test]
    fn test_ps003_missing_discriminant_check() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "accounts[0]".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps003.check(&graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PS-003");
    }
}
