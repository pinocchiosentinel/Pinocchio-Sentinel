use super::{CheckType, CheckInfo};

#[derive(Debug, Clone)]
pub struct CheckOrdering {
    pub checks: Vec<CheckInfo>,
    pub has_violation: bool,
}

impl CheckOrdering {
    pub fn new() -> Self {
        Self {
            checks: Vec::new(),
            has_violation: false,
        }
    }
    
    pub fn add_check(&mut self, check: CheckInfo) {
        if check.is_before_use {
            self.checks.push(check);
        } else {
            self.has_violation = true;
        }
    }
    
    pub fn has_required_check(&self, check_type: &CheckType) -> bool {
        self.checks.iter().any(|c| &c.check_type == check_type && c.is_before_use)
    }
    
    pub fn get_checks_after_line(&self, line: u32) -> Vec<&CheckInfo> {
        self.checks.iter()
            .filter(|c| c.line_number > line)
            .collect()
    }
}

pub fn analyze_check_ordering(
    checks: Vec<CheckInfo>,
    first_use_line: u32,
) -> CheckOrdering {
    let mut ordering = CheckOrdering::new();
    
    for check in checks {
        let is_before = check.line_number < first_use_line;
        ordering.add_check(CheckInfo {
            is_before_use: is_before,
            ..check
        });
    }
    
    ordering
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ordering() {
        let checks = vec![
            CheckInfo {
                check_type: CheckType::IsSigner,
                line_number: 10,
                is_before_use: true,
            },
            CheckInfo {
                check_type: CheckType::OwnedBy,
                line_number: 15,
                is_before_use: true,
            },
        ];
        
        let ordering = analyze_check_ordering(checks, 20);
        assert!(!ordering.has_violation);
        assert!(ordering.has_required_check(&CheckType::IsSigner));
        assert!(ordering.has_required_check(&CheckType::OwnedBy));
    }

    #[test]
    fn test_violation_ordering() {
        let checks = vec![
            CheckInfo {
                check_type: CheckType::IsSigner,
                line_number: 25, // After use at line 20
                is_before_use: false,
            },
        ];
        
        let ordering = analyze_check_ordering(checks, 20);
        assert!(ordering.has_violation);
        assert!(!ordering.has_required_check(&CheckType::IsSigner));
    }
}
