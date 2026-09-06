use super::{Rule, Finding, Severity};
use crate::graph::AccountAccessGraph;

pub struct Ps005;

impl Rule for Ps005 {
    fn id(&self) -> &str {
        "PS005"
    }
    
    fn description(&self) -> &str {
        "Rule PS005 placeholder - implement detection logic"
    }
    
    fn severity(&self) -> Severity {
        Severity::HIGH
    }
    
    fn check(&self, _graph: &AccountAccessGraph) -> Vec<Finding> {
        // TODO: Implement detection logic for PS005
        Vec::new()
    }
}
