pub mod ps001;
pub mod ps002;
pub mod ps003;
pub mod ps004;
pub mod ps005;
pub mod ps006;
pub mod ps007;
pub mod ps008;
pub mod ps009;
pub mod ps010;
pub mod ps011;
pub mod ps012;
pub mod ps014;

use serde::{Deserialize, Serialize};
use crate::graph::AccountAccessGraph;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub handler: String,
    pub account_index: Option<usize>,
    pub line_number: Option<u32>,
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    HIGH,
    MEDIUM,
    WARN,
    LOW,
    INFO,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

pub trait Rule {
    fn id(&self) -> &str;
    fn description(&self) -> &str;
    fn severity(&self) -> Severity;
    fn check(&self, graph: &AccountAccessGraph) -> Vec<Finding>;
}

pub fn get_all_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(ps001::Ps001),
        Box::new(ps002::Ps002),
        Box::new(ps003::Ps003),
        Box::new(ps004::Ps004),
        Box::new(ps005::Ps005),
        Box::new(ps006::Ps006),
        Box::new(ps007::Ps007),
        Box::new(ps008::Ps008),
        Box::new(ps009::Ps009),
        Box::new(ps010::Ps010),
        Box::new(ps011::Ps011),
        Box::new(ps012::Ps012),
        Box::new(ps014::Ps014),
    ]
}

pub fn run_all_rules(graph: &AccountAccessGraph) -> Vec<Finding> {
    let rules = get_all_rules();
    let mut findings = Vec::new();
    
    for rule in rules {
        findings.extend(rule.check(graph));
    }
    
    findings
}
