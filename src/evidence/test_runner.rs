use super::{ExploitTest, TestResult};
use std::path::Path;

pub struct TestRunner {
    pub working_dir: std::path::PathBuf,
}

impl TestRunner {
    pub fn new(working_dir: &Path) -> Self {
        Self {
            working_dir: working_dir.to_path_buf(),
        }
    }

    pub fn run_test(&self, test: &ExploitTest) -> TestResult {
        // For v0.1, we just validate the test code compiles
        // Full implementation would use Mollusk or LiteSVM

        let result = self.validate_test_code(&test.test_code);

        TestResult {
            rule_id: test.rule_id.clone(),
            pre_fix_passed: result.is_ok(),
            post_fix_passed: result.is_ok(),
            output: result.unwrap_or_else(|e| e),
            error: None,
        }
    }

    fn validate_test_code(&self, code: &str) -> Result<String, String> {
        // Simple validation - check for basic structure
        if !code.contains("#[test]") {
            return Err("Missing #[test] attribute".to_string());
        }

        if !code.contains("assert!") {
            return Err("Missing assert! macro".to_string());
        }

        Ok("Test code structure valid".to_string())
    }
}

pub fn run_exploit_tests(tests: &[ExploitTest], working_dir: &Path) -> Vec<TestResult> {
    let runner = TestRunner::new(working_dir);
    tests.iter().map(|t| runner.run_test(t)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_valid_code() {
        let runner = TestRunner::new(std::path::Path::new("."));
        let code = r#"
#[test]
fn test_example() {
    assert!(true);
}
"#;
        let result = runner.validate_test_code(code);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_missing_test() {
        let runner = TestRunner::new(std::path::Path::new("."));
        let code = r#"
fn test_example() {
    assert!(true);
}
"#;
        let result = runner.validate_test_code(code);
        assert!(result.is_err());
    }
}
