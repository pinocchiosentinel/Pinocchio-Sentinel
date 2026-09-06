use pinocchio_sentinel::{build_access_graph, parse_program, run_all_rules, SentinelConfig};
use std::path::PathBuf;

fn get_benchmark_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("benchmarks")
        .join(name)
}

fn scan_benchmark(name: &str) -> Vec<pinocchio_sentinel::rules::Finding> {
    let path = get_benchmark_path(name);
    let config = SentinelConfig::default();
    let mut findings = Vec::new();

    if let Ok(program) = parse_program(&path, &config) {
        if let Some(ref router) = program.router {
            let ep_type = program.entrypoint.as_ref().map(|e| &e.macro_type);
            for handler in &router.handlers {
                let graph = build_access_graph(handler, &program.ast, ep_type);
                findings.extend(run_all_rules(&graph));
            }
        }
    }

    findings
}

#[test]
fn test_01_missing_signer_check() {
    let findings = scan_benchmark("01-missing-signer-check.rs");
    assert!(
        !findings.is_empty(),
        "01-missing-signer-check should have findings"
    );
    let has_high = findings
        .iter()
        .any(|f| f.severity == pinocchio_sentinel::rules::Severity::HIGH);
    assert!(has_high, "Should have HIGH severity findings");
}

#[test]
fn test_02_missing_owner_check() {
    let findings = scan_benchmark("02-missing-owner-check.rs");
    assert!(
        !findings.is_empty(),
        "02-missing-owner-check should have findings"
    );
}

#[test]
fn test_03_account_data_matching() {
    let findings = scan_benchmark("03-account-data-matching.rs");
    assert!(
        !findings.is_empty(),
        "03-account-data-matching should have findings"
    );
}

#[test]
fn test_04_type_cosplay() {
    let findings = scan_benchmark("04-type-cosplay.rs");
    assert!(!findings.is_empty(), "04-type-cosplay should have findings");
}

#[test]
fn test_05_pda_bump_seed() {
    let findings = scan_benchmark("05-pda-bump-seed.rs");
    assert!(
        !findings.is_empty(),
        "05-pda-bump-seed should have findings"
    );
}

#[test]
fn test_06_account_reinitialization() {
    let findings = scan_benchmark("06-account-reinitialization.rs");
    assert!(
        !findings.is_empty(),
        "06-account-reinitialization should have findings"
    );
}

#[test]
fn test_07_arbitrary_cpi() {
    let findings = scan_benchmark("07-arbitrary-cpi.rs");
    assert!(
        !findings.is_empty(),
        "07-arbitrary-cpi should have findings"
    );
}

#[test]
fn test_09_closing_accounts() {
    let findings = scan_benchmark("09-closing-accounts.rs");
    assert!(
        !findings.is_empty(),
        "09-closing-accounts should have findings"
    );
}

#[test]
fn test_10_duplicate_mutable_accounts() {
    let findings = scan_benchmark("10-duplicate-mutable-accounts.rs");
    assert!(
        !findings.is_empty(),
        "10-duplicate-mutable-accounts should have findings"
    );
}

#[test]
fn test_10_missing_writable() {
    let findings = scan_benchmark("10-missing-writable.rs");
    assert!(
        !findings.is_empty(),
        "10-missing-writable should have findings"
    );
}

#[test]
fn test_12_sysvar_validation() {
    let findings = scan_benchmark("12-sysvar-account-validation.rs");
    assert!(
        !findings.is_empty(),
        "12-sysvar-account-validation should have findings"
    );
}

#[test]
fn test_all_benchmarks_have_findings() {
    let benchmarks = [
        "01-missing-signer-check.rs",
        "02-missing-owner-check.rs",
        "03-account-data-matching.rs",
        "04-type-cosplay.rs",
        "05-pda-bump-seed.rs",
        "06-account-reinitialization.rs",
        "07-arbitrary-cpi.rs",
        "09-closing-accounts.rs",
        "10-duplicate-mutable-accounts.rs",
        "10-missing-writable.rs",
        "12-sysvar-account-validation.rs",
    ];

    for benchmark in benchmarks {
        let findings = scan_benchmark(benchmark);
        assert!(
            !findings.is_empty(),
            "Benchmark {} should have findings",
            benchmark
        );
    }
}

#[test]
fn test_findings_have_handler_names() {
    let findings = scan_benchmark("01-missing-signer-check.rs");
    for finding in &findings {
        assert!(
            !finding.handler.is_empty(),
            "Finding should have handler name"
        );
    }
}

#[test]
fn test_findings_have_line_numbers() {
    let findings = scan_benchmark("01-missing-signer-check.rs");
    for finding in &findings {
        assert!(
            finding.line_number.is_some(),
            "Finding should have line number"
        );
    }
}

#[test]
fn test_findings_have_valid_rule_ids() {
    let valid_rules = [
        "PS-001", "PS-002", "PS-003", "PS-004", "PS-005", "PS-006", "PS-007", "PS-008", "PS-009",
        "PS-010", "PS-011", "PS-012", "PS-013", "PS-014",
    ];
    let findings = scan_benchmark("01-missing-signer-check.rs");
    for finding in &findings {
        assert!(
            valid_rules.contains(&finding.rule_id.as_str()),
            "Invalid rule ID: {}",
            finding.rule_id
        );
    }
}
