use super::{Rule, Finding, Severity, Confidence};
use crate::graph::{AccountAccessGraph, CheckType};

pub struct Ps005;

impl Rule for Ps005 {
    fn id(&self) -> &str {
        "PS-005"
    }

    fn description(&self) -> &str {
        "PDA account used without canonical bump seed verification"
    }

    fn severity(&self) -> Severity {
        Severity::MEDIUM
    }

    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account in &graph.accounts {
            let name_lower = account.variable_name.to_lowercase();
            let is_pda = name_lower.contains("pda")
                || name_lower.contains("seeds")
                || name_lower.contains("bump")
                || name_lower.contains("authority")
                || name_lower.contains("vault")
                || name_lower.contains("treasury");

            if is_pda && !graph.has_check_before_use(account.index, &CheckType::PdaBump) {
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity(),
                    confidence: Confidence::Low,
                    message: format!(
                        "Account '{}' (index {}) appears to be a PDA but lacks canonical bump verification",
                        account.variable_name, account.index
                    ),
                    account_index: Some(account.index),
                    line_number: account.line_number,
                    handler: graph.handler_name.clone(),
                    evidence: None,
                    fix_suggestion: Some(format!(
                        "Verify canonical bump: `assert_eq!(bump, canonical_bump)` after find_program_address",
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
    use crate::graph::{AccountAccess, AccessType, CheckInfo};

    #[test]
    fn test_ps005_missing_pda_bump() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "pda_account".to_string(),
            access_type: AccessType::Read,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps005.check(&graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PS-005");
        assert_eq!(findings[0].severity, Severity::MEDIUM);
    }

    #[test]
    fn test_ps005_with_pda_bump() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "pda_account".to_string(),
            access_type: AccessType::Read,
            checks: vec![CheckInfo {
                check_type: CheckType::PdaBump,
                line_number: 5,
                is_before_use: true,
            }],
            line_number: Some(10),
        });

        let findings = Ps005.check(&graph);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_ps005_non_pda_ignored() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "user_wallet".to_string(),
            access_type: AccessType::Read,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = Ps005.check(&graph);
        assert!(findings.is_empty());
    }
}
