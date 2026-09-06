use super::{Rule, Finding, Severity};
use crate::graph::AccountAccessGraph;

pub struct Ps008;

impl Rule for Ps008 {
    fn id(&self) -> &str {
        "PS008"
    }
    
    fn description(&self) -> &str {
        "Rule PS008 placeholder - implement detection logic"
    }
    
    fn severity(&self) -> Severity {
        Severity::HIGH
    }
    
    fn check(&self, _graph: &AccountAccessGraph) -> Vec<Finding> {
        // TODO: Implement detection logic for PS008
        Vec::new()
    }
}
