use super::{Rule, Finding, Severity, Confidence};
use crate::graph::{AccountAccessGraph, CheckType};

pub struct Ps004;

impl Rule for Ps004 {
    fn id(&self) -> &str {
        "PS-004"
    }
    
    fn description(&self) -> &str {
        "Zero-copy cast without a prior data_len() bounds assertion"
    }
    
    fn severity(&self) -> Severity {
        Severity::HIGH
    }
    
    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for account in &graph.accounts {
            if account.access_type != crate::graph::AccessType::Read {
                if !graph.has_check_before_use(account.index, &CheckType::DataLen) {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::High,
                        message: format!(
                            "Account '{}' (index {}) may be zero-cast without data_len() bounds check",
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
    use crate::graph::{AccountAccess, AccessType, CheckInfo};

    #[test]
    fn test_ps004_missing_bounds_check() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "accounts[0]".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });
        
        let findings = Ps004.check(&graph);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "PS-004");
        assert_eq!(findings[0].severity, Severity::HIGH);
    }

    #[test]
    fn test_ps004_with_bounds_check() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "accounts[0]".to_string(),
            access_type: AccessType::Write,
            checks: vec![CheckInfo {
                check_type: CheckType::DataLen,
                line_number: 5,
                is_before_use: true,
            }],
            line_number: Some(10),
        });
        
        let findings = Ps004.check(&graph);
        assert!(findings.is_empty());
    }
}
