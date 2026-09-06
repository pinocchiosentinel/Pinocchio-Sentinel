use crate::graph::{CallGraph, AccountAccessGraph, CheckType};
use crate::rules::{Finding, Severity, Confidence};

#[derive(Debug)]
pub struct InterproceduralAnalyzer {
    pub call_graph: CallGraph,
}

impl InterproceduralAnalyzer {
    pub fn new() -> Self {
        Self {
            call_graph: CallGraph::new(),
        }
    }

    pub fn analyze_cross_function_findings(
        &self,
        graph: &AccountAccessGraph,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account in &graph.accounts {
            if let Some(fn_info) = self.call_graph.get_function_requirements(&graph.handler_name) {
                if fn_info.performs_cpi && !self.has_cpi_return_check(graph, account.index) {
                    findings.push(Finding {
                        rule_id: "PS-013-INTER".to_string(),
                        severity: Severity::HIGH,
                        confidence: Confidence::Medium,
                        message: format!(
                            "Function '{}' performs CPI but account '{}' (index {}) may not have return value checked",
                            graph.handler_name, account.variable_name, account.index
                        ),
                        account_index: Some(account.index),
                        line_number: account.line_number,
                        handler: graph.handler_name.clone(),
                        evidence: Some(format!(
                            "CPI function requires return check, but no CpiReturn check found for this account"
                        )),
                        fix_suggestion: None,
                    });
                }
            }
        }

        findings
    }

    fn has_cpi_return_check(&self, graph: &AccountAccessGraph, index: usize) -> bool {
        graph.has_check_before_use(index, &CheckType::CpiReturn)
            || graph.has_check_before_use(index, &CheckType::Custom("is_ok".to_string()))
            || graph.has_check_before_use(index, &CheckType::Custom("unwrap".to_string()))
    }

    pub fn detect_missing_checks_from_callees(
        &self,
        graph: &AccountAccessGraph,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for account in &graph.accounts {
            let checks: Vec<&str> = account.checks.iter().map(|c| {
                match &c.check_type {
                    CheckType::IsSigner => "is_signer",
                    CheckType::OwnedBy => "owned_by",
                    CheckType::IsWritable => "is_writable",
                    CheckType::DataLen => "data_len",
                    CheckType::Discriminant => "discriminant",
                    CheckType::PdaBump => "pda_bump",
                    CheckType::CpiReturn => "cpi_return",
                    CheckType::Custom(name) => name,
                }
            }).collect();

            if checks.is_empty() && account.access_type == crate::graph::AccessType::Write {
                if let Some(fn_info) = self.call_graph.get_function_requirements(&graph.handler_name) {
                    if fn_info.requires_signer.contains(&account.index) {
                        findings.push(Finding {
                            rule_id: "PS-001-INTER".to_string(),
                            severity: Severity::HIGH,
                            confidence: Confidence::Low,
                            message: format!(
                                "Function '{}' requires signer check for account '{}' (index {}) but no check found in handler",
                                graph.handler_name, account.variable_name, account.index
                            ),
                            account_index: Some(account.index),
                            line_number: account.line_number,
                            handler: graph.handler_name.clone(),
                            evidence: None,
                            fix_suggestion: None,
                        });
                    }
                    if fn_info.requires_owner.contains(&account.index) {
                        findings.push(Finding {
                            rule_id: "PS-002-INTER".to_string(),
                            severity: Severity::HIGH,
                            confidence: Confidence::Low,
                            message: format!(
                                "Function '{}' requires owner check for account '{}' (index {}) but no check found in handler",
                                graph.handler_name, account.variable_name, account.index
                            ),
                            account_index: Some(account.index),
                            line_number: account.line_number,
                            handler: graph.handler_name.clone(),
                            evidence: None,
                            fix_suggestion: None,
                        });
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{AccountAccess, AccessType, CheckInfo, FunctionInfo};

    #[test]
    fn test_empty_analyzer() {
        let analyzer = InterproceduralAnalyzer::new();
        let graph = AccountAccessGraph::new("test_handler");
        let findings = analyzer.analyze_cross_function_findings(&graph);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_cpi_without_return_check() {
        let mut analyzer = InterproceduralAnalyzer::new();
        analyzer.call_graph.functions.insert(
            "test_handler".to_string(),
            FunctionInfo {
                name: "test_handler".to_string(),
                file_path: None,
                requires_signer: Vec::new(),
                requires_owner: Vec::new(),
                requires_writable: Vec::new(),
                requires_data_len: Vec::new(),
                performs_cpi: true,
                line_number: 10,
            },
        );

        let mut graph = AccountAccessGraph::new("test_handler");
        graph.add_account(AccountAccess {
            index: 0,
            variable_name: "accounts[0]".to_string(),
            access_type: AccessType::Write,
            checks: Vec::new(),
            line_number: Some(10),
        });

        let findings = analyzer.analyze_cross_function_findings(&graph);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "PS-013-INTER");
    }
}
