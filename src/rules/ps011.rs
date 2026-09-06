use super::{Confidence, Finding, Rule, Severity};
use crate::frontend::EntrypointMacro;
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

        let is_lazy = graph
            .entrypoint_type
            .as_ref()
            .map(|e| *e == EntrypointMacro::LazyProgramEntrypoint)
            .unwrap_or(false);

        if !is_lazy {
            return findings;
        }

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
                    handler: graph.handler_name.clone(),
                    evidence: None,
                    fix_suggestion: Some(format!(
                        "Add account count check: `if accounts.is_empty() {{ return Err(ProgramError::NotEnoughAccountKeys); }}`",
                    )),
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
    fn test_ps011_lazy_entrypoint_no_gate() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.entrypoint_type = Some(EntrypointMacro::LazyProgramEntrypoint);
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
    fn test_ps011_standard_entrypoint_no_flag() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.entrypoint_type = Some(EntrypointMacro::Entrypoint);
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "accounts[0]".to_string(),
            access_type: AccessType::Read,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps011.check(&graph);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ps011_non_accounts_ignored() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.entrypoint_type = Some(EntrypointMacro::LazyProgramEntrypoint);
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
