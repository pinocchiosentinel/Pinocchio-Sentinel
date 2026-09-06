use pinocchio_sentinel::{build_access_graph, parse_program, run_all_rules, SentinelConfig};
use std::path::PathBuf;
use std::time::Instant;

fn get_benchmark_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("benchmarks")
        .join(name)
}

fn scan_benchmark(name: &str) -> (Vec<pinocchio_sentinel::rules::Finding>, u64) {
    let path = get_benchmark_path(name);
    let config = SentinelConfig::default();
    let mut findings = Vec::new();

    let start = Instant::now();
    if let Ok(program) = parse_program(&path, &config) {
        if let Some(ref router) = program.router {
            let ep_type = program.entrypoint.as_ref().map(|e| &e.macro_type);
            for handler in &router.handlers {
                let graph = build_access_graph(handler, &program.ast, ep_type);
                findings.extend(run_all_rules(&graph));
            }
        }
    }
    let elapsed = start.elapsed().as_millis() as u64;

    (findings, elapsed)
}

#[test]
fn benchmark_all_programs() {
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

    let mut total_findings = 0;
    let mut total_time = 0;
    let mut passed = 0;

    for benchmark in &benchmarks {
        let (findings, time) = scan_benchmark(benchmark);
        total_findings += findings.len();
        total_time += time;
        passed += 1;

        println!("  {} — {} findings, {}ms", benchmark, findings.len(), time);
    }

    println!();
    println!("Summary:");
    println!("  Programs scanned: {}", passed);
    println!("  Total findings: {}", total_findings);
    println!("  Total time: {}ms", total_time);
    println!(
        "  Average time per program: {}ms",
        total_time / passed as u64
    );
    println!(
        "  Average findings per program: {:.1}",
        total_findings as f64 / passed as f64
    );

    assert!(total_findings > 0, "Should find at least one finding");
    assert!(total_time < 1000, "Should complete in under 1 second");
}

#[test]
fn benchmark_vulnerable_program() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("programs")
        .join("vulnerable-program")
        .join("src")
        .join("lib.rs");

    let config = SentinelConfig::default();
    let mut findings = Vec::new();

    let start = Instant::now();
    if let Ok(program) = parse_program(&path, &config) {
        if let Some(ref router) = program.router {
            let ep_type = program.entrypoint.as_ref().map(|e| &e.macro_type);
            for handler in &router.handlers {
                let graph = build_access_graph(handler, &program.ast, ep_type);
                findings.extend(run_all_rules(&graph));
            }
        }
    }
    let elapsed = start.elapsed().as_millis() as u64;

    println!(
        "  vulnerable-program — {} findings, {}ms",
        findings.len(),
        elapsed
    );

    assert!(
        findings.len() >= 5,
        "Should find at least 5 findings in vulnerable program"
    );
    assert!(elapsed < 500, "Should complete in under 500ms");
}
