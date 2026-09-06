pub mod generator;
pub mod test_runner;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitTest {
    pub rule_id: String,
    pub test_code: String,
    pub is_skeleton: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub rule_id: String,
    pub pre_fix_passed: bool,
    pub post_fix_passed: bool,
    pub output: String,
    pub error: Option<String>,
}

pub trait ExploitGenerator {
    fn generate_test(&self, rule_id: &str, finding: &crate::rules::Finding) -> ExploitTest;
}
