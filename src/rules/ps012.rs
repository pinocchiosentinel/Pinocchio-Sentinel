use super::{Rule, Finding, Severity};
use crate::graph::AccountAccessGraph;

pub struct Ps012;

impl Rule for Ps012 {
    fn id(&self) -> &str {
        "PS012"
    }
    
    fn description(&self) -> &str {
        "Rule PS012 placeholder - implement detection logic"
    }
    
    fn severity(&self) -> Severity {
        Severity::HIGH
    }
    
    fn check(&self, _graph: &AccountAccessGraph) -> Vec<Finding> {
        // TODO: Implement detection logic for PS012
        Vec::new()
    }
}
