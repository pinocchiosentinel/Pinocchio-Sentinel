use crate::rules::{Finding, Severity};
use std::fmt::Write;

pub fn to_html(findings: &[Finding]) -> String {
    let mut html = String::new();

    // HTML header
    html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pinocchio Sentinel Security Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; border-radius: 10px; margin-bottom: 30px; }
        header h1 { font-size: 2.5em; margin-bottom: 10px; }
        header p { opacity: 0.9; font-size: 1.1em; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .summary-card h3 { font-size: 2.5em; margin-bottom: 5px; }
        .summary-card p { color: #666; font-size: 0.9em; }
        .high { color: #e53e3e; }
        .medium { color: #dd6b20; }
        .warn { color: #3182ce; }
        .success { color: #38a169; }
        .findings { background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
        .findings h2 { padding: 20px; border-bottom: 1px solid #eee; }
        .finding { padding: 20px; border-bottom: 1px solid #eee; }
        .finding:last-child { border-bottom: none; }
        .finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
        .rule-id { background: #667eea; color: white; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.9em; }
        .severity { padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.8em; text-transform: uppercase; }
        .severity-high { background: #fed7d7; color: #c53030; }
        .severity-medium { background: #fefcbf; color: #b7791f; }
        .severity-warn { background: #bee3f8; color: #2b6cb0; }
        .handler { color: #666; font-size: 0.9em; }
        .message { margin: 10px 0; font-size: 1.1em; }
        .fix { background: #f0fff4; border-left: 4px solid #38a169; padding: 10px 15px; margin-top: 10px; border-radius: 0 4px 4px 0; }
        .fix strong { color: #38a169; }
        footer { text-align: center; padding: 30px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Pinocchio Sentinel</h1>
            <p>Security Audit Report</p>
        </header>
"#);

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

    write!(
        html,
        r#"
        <div class="summary">
            <div class="summary-card">
                <h3 class="high">{}</h3>
                <p>HIGH Severity</p>
            </div>
            <div class="summary-card">
                <h3 class="medium">{}</h3>
                <p>MEDIUM Severity</p>
            </div>
            <div class="summary-card">
                <h3 class="warn">{}</h3>
                <p>WARN Severity</p>
            </div>
            <div class="summary-card">
                <h3>{}</h3>
                <p>Total Findings</p>
            </div>
        </div>
"#,
        high_count,
        medium_count,
        warn_count,
        findings.len()
    )
    .unwrap();

    // Findings list
    html.push_str(
        r#"
        <div class="findings">
            <h2>Findings</h2>
"#,
    );

    for finding in findings.iter() {
        let severity_class = match finding.severity {
            Severity::HIGH => "severity-high",
            Severity::MEDIUM => "severity-medium",
            _ => "severity-warn",
        };

        let severity_label = match finding.severity {
            Severity::HIGH => "HIGH",
            Severity::MEDIUM => "MEDIUM",
            _ => "WARN",
        };

        write!(
            html,
            r#"
            <div class="finding">
                <div class="finding-header">
                    <span class="rule-id">{}</span>
                    <span class="severity {}">{}</span>
                    <span class="handler">Handler: {}</span>
                </div>
                <div class="message">{}</div>
"#,
            finding.rule_id, severity_class, severity_label, finding.handler, finding.message
        )
        .unwrap();

        if let Some(ref fix) = finding.fix_suggestion {
            write!(
                html,
                r#"
                <div class="fix">
                    <strong>Fix:</strong> {}
                </div>
"#,
                fix
            )
            .unwrap();
        }

        html.push_str("</div>\n");
    }

    html.push_str(
        r#"
        </div>
        <footer>
            <p>Generated by Pinocchio Sentinel - Static Analysis for Solana Programs</p>
        </footer>
    </div>
</body>
</html>
"#,
    );

    html
}
