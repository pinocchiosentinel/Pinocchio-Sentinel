use super::{Rule, Finding, Severity, Confidence};
use crate::graph::{AccountAccessGraph, CheckType};

pub struct Ps008;

impl Rule for Ps008 {
    fn id(&self) -> &str {
        "PS-008"
    }

    fn description(&self) -> &str {
        "Initialization path reachable on already-initialized account"
    }

    fn severity(&self) -> Severity {
        Severity::HIGH
    }

    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account in &graph.accounts {
            let name_lower = account.variable_name.to_lowercase();
            let is_init_target = name_lower.contains("init")
                || name_lower.contains("vault")
                || name_lower.contains("account")
                || name_lower.contains("state")
                || name_lower.contains("config");

            if is_init_target {
                let has_discriminant_check = graph.has_check_before_use(account.index, &CheckType::Discriminant);
                let has_data_len_check = graph.has_check_before_use(account.index, &CheckType::DataLen);

                if !has_discriminant_check && !has_data_len_check && account.access_type != crate::graph::AccessType::Read {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Low,
                        message: format!(
                            "Account '{}' (index {}) may be an init target but has no discriminant or data_len check to verify it is not already initialized",
                            account.variable_name, account.index
                        ),
                        account_index: Some(account.index),
                        line_number: account.line_number,
                        handler: graph.handler_name.clone(),
                    evidence: None,
                    fix_suggestion: Some(format!(
                        "Add init guard: `if account_data.initialized {{ return Err(ProgramError::AccountAlreadyInitialized); }}`",
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
    fn test_ps008_init_no_check() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "init_vault".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps008.check(&graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PS-008");
    }

    #[test]
    fn test_ps008_with_discriminant_check() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "init_vault".to_string(),
            access_type: AccessType::Write,
            checks: vec![CheckInfo {
                check_type: CheckType::Discriminant,
                line_number: 5,
                is_before_use: true,
            }],
            line_number: Some(10),
        });

        let findings = Ps008.check(&graph);
        assert!(findings.is_empty());
    }
}
