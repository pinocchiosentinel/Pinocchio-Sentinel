use super::{Rule, Finding, Severity, Confidence};
use crate::graph::{AccountAccessGraph, CheckType};

pub struct Ps001;

impl Rule for Ps001 {
    fn id(&self) -> &str {
        "PS-001"
    }
    
    fn description(&self) -> &str {
        "Authority account used without an is_signer() assertion"
    }
    
    fn severity(&self) -> Severity {
        Severity::HIGH
    }
    
    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for account in &graph.accounts {
            if !graph.has_check_before_use(account.index, &CheckType::IsSigner) {
                findings.push(Finding {
                    rule_id: self.id().to_string(),
                    severity: self.severity(),
                    confidence: Confidence::Medium,
                    message: format!(
                        "Account '{}' (index {}) is used without is_signer() check",
                        account.variable_name, account.index
                    ),
                    account_index: Some(account.index),
                    line_number: account.line_number,
                    handler: graph.handler_name.clone(),
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
    use crate::graph::{AccountAccess, AccessType, CheckInfo};

    #[test]
    fn test_ps001_missing_signer_check() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "accounts[0]".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });
        
        let findings = Ps001.check(&graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PS-001");
        assert_eq!(findings[0].severity, Severity::HIGH);
    }

    #[test]
    fn test_ps001_with_signer_check() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "accounts[0]".to_string(),
            access_type: AccessType::Write,
            checks: vec![CheckInfo {
                check_type: CheckType::IsSigner,
                line_number: 5,
                is_before_use: true,
            }],
            line_number: Some(10),
        });
        
        let findings = Ps001.check(&graph);
        assert!(findings.is_empty());
    }
}
