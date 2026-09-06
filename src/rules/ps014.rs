use super::{Rule, Finding, Severity};
use crate::graph::AccountAccessGraph;

pub struct Ps014;

impl Rule for Ps014 {
    fn id(&self) -> &str {
        "PS014"
    }
    
    fn description(&self) -> &str {
        "Rule PS014 placeholder - implement detection logic"
    }
    
    fn severity(&self) -> Severity {
        Severity::HIGH
    }
    
    fn check(&self, _graph: &AccountAccessGraph) -> Vec<Finding> {
        // TODO: Implement detection logic for PS014
        Vec::new()
    }
}
