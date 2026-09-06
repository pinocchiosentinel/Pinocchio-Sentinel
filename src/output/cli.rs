use crate::rules::{Finding, Severity};
use colored::*;

pub fn to_cli(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return format!("{}", "No findings detected".green().bold());
    }

    let mut output = String::new();

    // Header
    output.push_str(&format!(
        "\n{}\n",
        "Pinocchio Sentinel Scan Results".cyan().bold()
    ));
    output.push_str(&format!("{}\n\n", "=".repeat(50)));

    // Summary
    let high_count = findings
        .iter()
        .filter(|f| f.severity == Severity::HIGH)
        .count();
    let medium_count = findings
        .iter()
        .filter(|f| f.severity == Severity::MEDIUM)
        .count();
    let warn_count = findings
        .iter()
        .filter(|f| f.severity == Severity::WARN)
        .count();

    output.push_str(&format!("Summary: {} findings\n", findings.len()));
    output.push_str(&format!("  {} HIGH\n", high_count.to_string().red().bold()));
    output.push_str(&format!(
        "  {} MEDIUM\n",
        medium_count.to_string().yellow().bold()
    ));
    output.push_str(&format!(
        "  {} WARN\n\n",
        warn_count.to_string().blue().bold()
    ));

    // Findings
    for (i, finding) in findings.iter().enumerate() {
        output.push_str(&format!(
            "{}. [{}] {}\n",
            (i + 1).to_string().cyan(),
            finding.rule_id.yellow().bold(),
            finding.message
        ));

        output.push_str(&format!("   Handler: {}\n", finding.handler.dimmed()));

        if let Some(line) = finding.line_number {
            output.push_str(&format!("   Line: {}\n", line.to_string()));
        }

        if let Some(ref evidence) = finding.evidence {
            output.push_str(&format!("   Evidence: {}\n", evidence.dimmed()));
        }

        if let Some(ref fix) = finding.fix_suggestion {
            output.push_str(&format!("   Fix: {}\n", fix.green()));
        }

        output.push_str("\n");
    }

    output
}

pub fn print_findings(findings: &[Finding]) {
    print!("{}", to_cli(findings));
}

pub fn print_summary(findings: &[Finding]) {
    let high_count = findings
        .iter()
        .filter(|f| f.severity == Severity::HIGH)
        .count();

    if high_count > 0 {
        println!(
            "\n{}: {} HIGH severity findings detected",
            "ERROR".red().bold(),
            high_count.to_string().red().bold()
        );
        println!("CI gate: {}", "FAILED".red().bold());
    } else {
        println!("\n{}: No HIGH severity findings", "SUCCESS".green().bold());
        println!("CI gate: {}", "PASSED".green().bold());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Confidence, Severity};

    #[test]
    fn test_cli_output_empty() {
        let findings = vec![];
        let output = to_cli(&findings);
        assert!(output.contains("No findings detected"));
    }

    #[test]
    fn test_cli_output_with_findings() {
        let findings = vec![Finding {
            rule_id: "PS-001".to_string(),
            severity: Severity::HIGH,
            confidence: Confidence::High,
            message: "Test finding".to_string(),
            handler: "test_handler".to_string(),
            account_index: Some(0),
            line_number: Some(10),
            evidence: None,
            fix_suggestion: None,
        }];

        let output = to_cli(&findings);
        assert!(output.contains("PS-001"));
        assert!(output.contains("HIGH"));
    }
}
