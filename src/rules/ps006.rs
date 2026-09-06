use super::{Rule, Finding, Severity, Confidence};
use crate::graph::{AccountAccessGraph, AccessType};

pub struct Ps006;

impl Rule for Ps006 {
    fn id(&self) -> &str {
        "PS-006"
    }

    fn description(&self) -> &str {
        "Two account indices may alias, both mutated"
    }

    fn severity(&self) -> Severity {
        Severity::MEDIUM
    }

    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding> {
        let mut findings = Vec::new();

        let mutating: Vec<&_> = graph.accounts.iter()
            .filter(|a| a.access_type == AccessType::Write || a.access_type == AccessType::Both)
            .collect();

        for i in 0..mutating.len() {
            for j in (i + 1)..mutating.len() {
                let a = mutating[i];
                let b = mutating[j];
                let name_a = a.variable_name.to_lowercase();
                let name_b = b.variable_name.to_lowercase();

                let alias = name_a == name_b
                    || name_a.contains(&name_b)
                    || name_b.contains(&name_a);

                if alias {
                    findings.push(Finding {
                        rule_id: self.id().to_string(),
                        severity: self.severity(),
                        confidence: Confidence::Low,
                        message: format!(
                            "Accounts '{}' (index {}) and '{}' (index {}) may alias and both are mutated",
                            a.variable_name, a.index, b.variable_name, b.index
                        ),
                        account_index: Some(a.index),
                        line_number: a.line_number,
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
    use crate::graph::{AccountAccess, CheckInfo, CheckType};

    #[test]
    fn test_ps006_alias_detected() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "authority".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });
        graph.add_account(AccountAccess {
            index: 1,
            variable_name: "authority".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(15),
        });

        let findings = Ps006.check(&graph);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "PS-006");
    }

    #[test]
    fn test_ps006_no_alias() {
        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "authority".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });
        graph.add_account(AccountAccess {
            index: 1,
            variable_name: "user_wallet".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(15),
        });

        let findings = Ps006.check(&graph);
        assert!(findings.is_empty());
    }
}
