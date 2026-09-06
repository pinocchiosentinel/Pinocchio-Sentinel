use super::{Rule, Finding, Severity, Confidence};
use crate::graph::{AccountAccessGraph, CheckType};

pub struct Ps014;

impl Rule for Ps014 {
    fn id(&self) -> &str {
        "PS-014"
    }

    fn description(&self) -> &str {
        "Sysvar account used without pubkey comparison"
    }

    fn severity(&self) -> Severity {
        Severity::HIGH
    }

    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account in &graph.accounts {
            let name_lower = account.variable_name.to_lowercase();
            let is_sysvar = name_lower.contains("sysvar")
                || name_lower.contains("rent")
                || name_lower.contains("clock")
                || name_lower.contains("stake_history")
                || name_lower.contains("epoch_schedule")
                || name_lower.contains("slot_hashes");

            if is_sysvar {
                let has_pubkey_check = graph.has_check_before_use(account.index, &CheckType::OwnedBy)
                    || graph.has_check_before_use(account.index, &CheckType::Custom("pubkey".to_string()));

                if !has_pubkey_check {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Medium,
                        message: format!(
                            "Sysvar account '{}' (index {}) used without pubkey comparison against known sysvar address",
                            account.variable_name, account.index
                        ),
                        account_index: Some(account.index),
                        line_number: account.line_number,
                        handler: graph.handler_name.clone(),
                    evidence: None,
                    fix_suggestion: Some(format!(
                        "Add sysvar check: `if {}.key() != &sysvar::ID {{ return Err(ProgramError::InvalidArgument); }}`",
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
    use crate::graph::{AccountAccess, AccessType};

    #[test]
    fn test_ps014_sysvar_no_pubkey() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "rent_sysvar".to_string(),
            access_type: AccessType::Read,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps014.check(&graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PS-014");
        assert_eq!(findings[0].severity, Severity::HIGH);
    }

    #[test]
    fn test_ps014_non_sysvar_ignored() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "user_wallet".to_string(),
            access_type: AccessType::Read,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps014.check(&graph);
        assert!(findings.is_empty());
    }
}
