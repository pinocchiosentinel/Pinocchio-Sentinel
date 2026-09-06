use super::{Rule, Finding, Severity};
use crate::graph::AccountAccessGraph;

pub struct Ps011;

impl Rule for Ps011 {
    fn id(&self) -> &str {
        "PS011"
    }
    
    fn description(&self) -> &str {
        "Rule PS011 placeholder - implement detection logic"
    }
    
    fn severity(&self) -> Severity {
        Severity::HIGH
    }
    
    fn check(&self, _graph: &AccountAccessGraph) -> Vec<Finding> {
        // TODO: Implement detection logic for PS011
        Vec::new()
    }
}
