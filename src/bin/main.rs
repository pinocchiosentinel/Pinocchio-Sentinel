use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use std::path::{Path, PathBuf};
use std::time::Instant;

use pinocchio_sentinel::graph::{CallGraph, InterproceduralAnalyzer};
use pinocchio_sentinel::rules::{self, Severity};
use pinocchio_sentinel::{
    build_access_graph, format_findings, parse_program, print_findings, print_summary,
    run_all_rules, ScanResult, SentinelConfig,
};

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Cli,
    Sarif,
    Json,
    Html,
    Markdown,
}

#[derive(Parser)]
#[command(name = "pinocchio-sentinel")]
#[command(about = "Static analysis for Solana programs written without Anchor")]
#[command(version = "0.1.0")]
struct Cli {
    /// Path to the Cargo workspace, program directory, or single .rs file
    #[arg(short, long, default_value = ".")]
    path: PathBuf,

    /// Output format (cli, sarif, json)
    #[arg(short, long, default_value = "cli", value_enum)]
    format: OutputFormat,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// SARIF output file path
    #[arg(long)]
    sarif: Option<PathBuf>,

    /// JSON output file path
    #[arg(long)]
    json: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Configuration file path
    #[arg(short, long, default_value = "sentinel.toml")]
    config: PathBuf,

    /// Fail on HIGH severity findings (for CI)
    #[arg(long)]
    fail_on_high: bool,

    /// Minimum severity to report (high, medium, warn, low, info)
    #[arg(long)]
    min_severity: Option<String>,

    /// Rule IDs to suppress (comma-separated, e.g., PS-001,PS-002)
    #[arg(long)]
    allow: Option<String>,

    /// Include skeleton tests in output
    #[arg(long)]
    include_skeletons: bool,

    /// Auto-apply fix suggestions to source files
    #[arg(long)]
    fix: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new sentinel.toml configuration
    Init {
        #[arg(short, long, default_value = "sentinel.toml")]
        output: PathBuf,
    },
    /// Show information about rules
    Rules { rule_id: Option<String> },
    /// Run full audit with detailed report
    Audit {
        /// Path to scan
        #[arg(short, long, default_value = ".")]
        path: PathBuf,
        /// Output format (cli, sarif, json)
        #[arg(short, long, default_value = "cli", value_enum)]
        format: OutputFormat,
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    /// Run tests for generated exploit tests
    Test {
        #[arg(short, long)]
        path: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init { output }) => {
            let config = SentinelConfig::default();
            config.save(&output)?;
            println!("Created sentinel.toml at {}", output.display());
            return Ok(());
        }
        Some(Commands::Rules { rule_id }) => {
            show_rules(rule_id.as_deref());
            return Ok(());
        }
        Some(Commands::Audit {
            path,
            format,
            output,
            verbose,
        }) => {
            return run_audit(&path, &format, output.as_ref(), verbose);
        }
        Some(Commands::Test { path }) => {
            println!("Testing at {}", path.display());
            return Ok(());
        }
        None => {}
    }

    let config = if cli.config.exists() {
        SentinelConfig::load(&cli.config)?
    } else {
        SentinelConfig::default()
    };

    let start = Instant::now();
    let source_files = find_source_files(&cli.path)?;

    if source_files.is_empty() {
        eprintln!("No Rust source files found at {}", cli.path.display());
        std::process::exit(1);
    }

    if cli.verbose {
        tracing::info!("Found {} source files to scan", source_files.len());
    }

    let mut all_findings = Vec::new();
    let mut files_scanned = 0;

    // Build call graph for interprocedural analysis
    let mut call_graph = CallGraph::new();

    for source_file in &source_files {
        if cli.verbose {
            tracing::info!("Analyzing {}", source_file.display());
        }

        match parse_program(source_file, &config) {
            Ok(program) => {
                // Add functions to call graph
                call_graph.analyze_file(&program.ast, Some(&source_file.to_string_lossy()));

                if let Some(ref router) = program.router {
                    let ep_type = program.entrypoint.as_ref().map(|e| &e.macro_type);
                    for handler in &router.handlers {
                        let graph = build_access_graph(handler, &program.ast, ep_type);
                        let findings = run_all_rules(&graph);
                        all_findings.extend(findings);
                    }
                }
                files_scanned += 1;
            }
            Err(e) => {
                if cli.verbose {
                    tracing::warn!("Failed to parse {}: {}", source_file.display(), e);
                }
            }
        }
    }

    // Run interprocedural analysis
    let analyzer = InterproceduralAnalyzer { call_graph };
    for source_file in &source_files {
        if let Ok(program) = parse_program(source_file, &config) {
            if let Some(ref router) = program.router {
                let ep_type = program.entrypoint.as_ref().map(|e| &e.macro_type);
                for handler in &router.handlers {
                    let graph = build_access_graph(handler, &program.ast, ep_type);
                    let inter_findings = analyzer.analyze_cross_function_findings(&graph);
                    all_findings.extend(inter_findings);
                    let caller_findings = analyzer.detect_missing_checks_from_callees(&graph);
                    all_findings.extend(caller_findings);
                }
            }
        }
    }

    // Apply filters from CLI flags
    if let Some(ref min_severity) = cli.min_severity {
        let min = parse_severity(min_severity);
        all_findings.retain(|f| severity_rank(&f.severity) >= severity_rank(&min));
    } else if let Some(ref min_severity) = config.rules.min_severity {
        let min = parse_severity(min_severity);
        all_findings.retain(|f| severity_rank(&f.severity) >= severity_rank(&min));
    }

    if let Some(ref allow_list) = cli.allow {
        let allowed: Vec<&str> = allow_list.split(',').map(|s| s.trim()).collect();
        all_findings.retain(|f| !allowed.contains(&f.rule_id.as_str()));
    } else if !config.rules.allow_list.is_empty() {
        let allowed: Vec<&str> = config.rules.allow_list.iter().map(|s| s.as_str()).collect();
        all_findings.retain(|f| !allowed.contains(&f.rule_id.as_str()));
    }

    let scan_time = start.elapsed().as_millis() as u64;

    let result = ScanResult {
        findings: all_findings,
        scan_time_ms: scan_time,
        files_scanned,
        rules_applied: config.rules.enabled_rules.len(),
    };

    match &cli.format {
        OutputFormat::Sarif => {
            let sarif_output = pinocchio_sentinel::output::sarif::to_sarif(&result.findings);
            if let Some(ref path) = cli.output {
                std::fs::write(path, sarif_output)?;
                if cli.verbose {
                    tracing::info!("SARIF output written to {}", path.display());
                }
            } else {
                println!("{}", sarif_output);
            }
        }
        OutputFormat::Json => {
            let json_output = pinocchio_sentinel::output::json::to_json(&result.findings);
            if let Some(ref path) = cli.output {
                std::fs::write(path, json_output)?;
                if cli.verbose {
                    tracing::info!("JSON output written to {}", path.display());
                }
            } else {
                println!("{}", json_output);
            }
        }
        OutputFormat::Html => {
            let html_output = pinocchio_sentinel::output::html::to_html(&result.findings);
            if let Some(ref path) = cli.output {
                std::fs::write(path, html_output)?;
                if cli.verbose {
                    tracing::info!("HTML output written to {}", path.display());
                }
            } else {
                // Default to report.html if no output path specified
                let path = std::path::PathBuf::from("report.html");
                std::fs::write(&path, html_output)?;
                if cli.verbose {
                    tracing::info!("HTML output written to {}", path.display());
                }
            }
        }
        OutputFormat::Markdown => {
            let md_output = pinocchio_sentinel::output::markdown::to_markdown(&result.findings);
            if let Some(ref path) = cli.output {
                std::fs::write(path, md_output)?;
                if cli.verbose {
                    tracing::info!("Markdown output written to {}", path.display());
                }
            } else {
                // Default to report.md if no output path specified
                let path = std::path::PathBuf::from("report.md");
                std::fs::write(&path, md_output)?;
                if cli.verbose {
                    tracing::info!("Markdown output written to {}", path.display());
                }
            }
        }
        OutputFormat::Cli => {
            if let Some(ref sarif_path) = cli.sarif {
                let sarif_output = pinocchio_sentinel::output::sarif::to_sarif(&result.findings);
                std::fs::write(sarif_path, sarif_output)?;
                if cli.verbose {
                    tracing::info!("SARIF output written to {}", sarif_path.display());
                }
            }

            if let Some(ref json_path) = cli.json {
                let json_output = pinocchio_sentinel::output::json::to_json(&result.findings);
                std::fs::write(json_path, json_output)?;
                if cli.verbose {
                    tracing::info!("JSON output written to {}", json_path.display());
                }
            }

            if let Some(ref output_path) = cli.output {
                let output_text = format_findings(&result.findings, "cli");
                std::fs::write(output_path, output_text)?;
                if cli.verbose {
                    tracing::info!("Output written to {}", output_path.display());
                }
            } else {
                print_findings(&result.findings);
            }
        }
    }

    print_summary(&result.findings);

    if cli.fix && !result.findings.is_empty() {
        apply_fixes(&result.findings, cli.verbose);
    }

    if cli.fail_on_high && result.has_high_findings() {
        std::process::exit(1);
    }

    Ok(())
}

fn find_source_files(path: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if path.is_file() {
        if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path.to_path_buf());
        }
        return Ok(files);
    }

    // Try Cargo workspace first
    if let Some(cargo_toml) = find_cargo_toml(path) {
        if let Some(workspace_members) = parse_workspace_members(&cargo_toml) {
            let cargo_dir = cargo_toml.parent().unwrap_or(path);
            for member in workspace_members {
                let member_path = cargo_dir.join(&member);
                if member_path.exists() {
                    collect_rs_files_from_crate(&member_path, &mut files)?;
                }
            }
            if !files.is_empty() {
                return Ok(files);
            }
        }
    }

    // Fall back to directory scan
    collect_rs_files(path, &mut files)?;
    Ok(files)
}

fn find_cargo_toml(path: &Path) -> Option<PathBuf> {
    let cargo_toml = path.join("Cargo.toml");
    if cargo_toml.exists() {
        return Some(cargo_toml);
    }
    None
}

fn parse_workspace_members(cargo_toml: &Path) -> Option<Vec<String>> {
    let content = std::fs::read_to_string(cargo_toml).ok()?;
    let toml: toml::Value = toml::from_str(&content).ok()?;

    if let Some(workspace) = toml.get("workspace") {
        if let Some(members) = workspace.get("members") {
            if let Some(arr) = members.as_array() {
                return Some(
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect(),
                );
            }
        }
    }

    None
}

fn collect_rs_files(path: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in walkdir::WalkDir::new(path) {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "rs" {
                    let path_str = path.to_string_lossy();
                    if !path_str.contains("target") {
                        files.push(path.to_path_buf());
                    }
                }
            }
        }
    }
    Ok(())
}

fn collect_rs_files_from_crate(path: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    let src_dir = path.join("src");
    if src_dir.exists() {
        collect_rs_files(&src_dir, files)?;
    }
    Ok(())
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "high" => Severity::HIGH,
        "medium" => Severity::MEDIUM,
        "warn" | "warning" => Severity::WARN,
        "low" => Severity::LOW,
        "info" => Severity::INFO,
        _ => Severity::INFO,
    }
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::HIGH => 4,
        Severity::MEDIUM => 3,
        Severity::WARN => 2,
        Severity::LOW => 1,
        Severity::INFO => 0,
    }
}

fn run_audit(
    path: &Path,
    format: &OutputFormat,
    output: Option<&PathBuf>,
    verbose: bool,
) -> anyhow::Result<()> {
    let config = SentinelConfig::default();
    let start = Instant::now();

    let source_files = find_source_files(path)?;
    if source_files.is_empty() {
        eprintln!("No Rust source files found at {}", path.display());
        std::process::exit(1);
    }

    if verbose {
        tracing::info!("Auditing {} source files", source_files.len());
    }

    let mut all_findings = Vec::new();
    let mut files_scanned = 0;
    let mut call_graph = CallGraph::new();

    for source_file in &source_files {
        if verbose {
            tracing::info!("Analyzing {}", source_file.display());
        }

        match parse_program(source_file, &config) {
            Ok(program) => {
                call_graph.analyze_file(&program.ast, Some(&source_file.to_string_lossy()));
                if let Some(ref router) = program.router {
                    let ep_type = program.entrypoint.as_ref().map(|e| &e.macro_type);
                    for handler in &router.handlers {
                        let graph = build_access_graph(handler, &program.ast, ep_type);
                        all_findings.extend(run_all_rules(&graph));
                    }
                }
                files_scanned += 1;
            }
            Err(e) => {
                if verbose {
                    tracing::warn!("Failed to parse {}: {}", source_file.display(), e);
                }
            }
        }
    }

    let analyzer = InterproceduralAnalyzer { call_graph };
    for source_file in &source_files {
        if let Ok(program) = parse_program(source_file, &config) {
            if let Some(ref router) = program.router {
                let ep_type = program.entrypoint.as_ref().map(|e| &e.macro_type);
                for handler in &router.handlers {
                    let graph = build_access_graph(handler, &program.ast, ep_type);
                    all_findings.extend(analyzer.analyze_cross_function_findings(&graph));
                    all_findings.extend(analyzer.detect_missing_checks_from_callees(&graph));
                }
            }
        }
    }

    let scan_time = start.elapsed().as_millis() as u64;
    let result = ScanResult {
        findings: all_findings,
        scan_time_ms: scan_time,
        files_scanned,
        rules_applied: config.rules.enabled_rules.len(),
    };

    // Print audit report header
    println!("\n{}", "Pinocchio Sentinel Audit Report".cyan().bold());
    println!("{}", "=".repeat(50));
    println!("Path: {}", path.display());
    println!("Files scanned: {}", files_scanned);
    println!("Scan time: {}ms", scan_time);
    println!("Rules applied: {}", result.rules_applied);
    println!();

    match format {
        OutputFormat::Sarif => {
            let sarif_output = pinocchio_sentinel::output::sarif::to_sarif(&result.findings);
            if let Some(path) = output {
                std::fs::write(path, sarif_output)?;
            } else {
                println!("{}", sarif_output);
            }
        }
        OutputFormat::Json => {
            let json_output = pinocchio_sentinel::output::json::to_json(&result.findings);
            if let Some(path) = output {
                std::fs::write(path, json_output)?;
            } else {
                println!("{}", json_output);
            }
        }
        OutputFormat::Html => {
            let html_output = pinocchio_sentinel::output::html::to_html(&result.findings);
            if let Some(path) = output {
                std::fs::write(path, html_output)?;
            } else {
                let path = std::path::PathBuf::from("report.html");
                std::fs::write(&path, html_output)?;
                println!("HTML report written to {}", path.display());
            }
        }
        OutputFormat::Markdown => {
            let md_output = pinocchio_sentinel::output::markdown::to_markdown(&result.findings);
            if let Some(path) = output {
                std::fs::write(path, md_output)?;
            } else {
                let path = std::path::PathBuf::from("report.md");
                std::fs::write(&path, md_output)?;
                println!("Markdown report written to {}", path.display());
            }
        }
        OutputFormat::Cli => {
            print_findings(&result.findings);
        }
    }

    print_summary(&result.findings);

    Ok(())
}

fn apply_fixes(findings: &[pinocchio_sentinel::rules::Finding], verbose: bool) {
    use std::collections::HashMap;
    use std::fs;

    // Group findings by source file
    let mut fixes_by_file: HashMap<String, Vec<&pinocchio_sentinel::rules::Finding>> =
        HashMap::new();

    for finding in findings {
        if finding.fix_suggestion.is_some() {
            // We need to find the actual source file path
            // For now, we'll use the handler name to locate the file
            let file_key = finding.handler.clone();
            fixes_by_file.entry(file_key).or_default().push(finding);
        }
    }

    let mut fixed_count = 0;
    let mut files_modified = Vec::new();

    for (handler, file_findings) in &fixes_by_file {
        // Find the source file containing this handler
        if let Some(source_path) = find_source_file_for_handler(handler) {
            if let Ok(mut content) = fs::read_to_string(&source_path) {
                let mut modified = false;

                for finding in file_findings {
                    if let Some(ref fix) = finding.fix_suggestion {
                        if let Some(line_num) = finding.line_number {
                            if verbose {
                                println!(
                                    "  {} {} at line {}: {}",
                                    "FIX".cyan(),
                                    finding.rule_id,
                                    line_num,
                                    fix
                                );
                            }

                            // Parse the fix suggestion and apply it
                            if apply_fix_to_content(&mut content, line_num, fix, &finding.rule_id) {
                                modified = true;
                                fixed_count += 1;
                            }
                        }
                    }
                }

                if modified {
                    if let Err(e) = fs::write(&source_path, &content) {
                        eprintln!("Failed to write {}: {}", source_path.display(), e);
                    } else {
                        files_modified.push(source_path.display().to_string());
                        if verbose {
                            println!("  {} Modified {}", "OK".green(), source_path.display());
                        }
                    }
                }
            }
        }
    }

    if fixed_count > 0 {
        println!(
            "\n{}: Applied {} fixes to {} files",
            "FIX".green().bold(),
            fixed_count.to_string().green(),
            files_modified.len().to_string().green()
        );
        for file in &files_modified {
            println!("  Modified: {}", file);
        }
    } else {
        println!(
            "\n{}: No fixes could be auto-applied",
            "FIX".yellow().bold()
        );
        println!("Use the fix suggestions above to manually apply fixes.");
    }
}

fn find_source_file_for_handler(handler_name: &str) -> Option<std::path::PathBuf> {
    // Search for the handler function in the current directory
    let current_dir = std::env::current_dir().ok()?;
    find_source_file_recursive(&current_dir, handler_name)
}

fn find_source_file_recursive(
    dir: &std::path::Path,
    handler_name: &str,
) -> Option<std::path::PathBuf> {
    use std::fs;

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path
                    .file_name()
                    .is_some_and(|n| n == "target" || n == ".git")
                {
                    continue;
                }
                if let Some(found) = find_source_file_recursive(&path, handler_name) {
                    return Some(found);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if content.contains(&format!("fn {}", handler_name))
                        || content.contains(&format!("pub fn {}", handler_name))
                    {
                        return Some(path);
                    }
                }
            }
        }
    }
    None
}

fn apply_fix_to_content(content: &mut String, line_num: u32, fix: &str, rule_id: &str) -> bool {
    let lines: Vec<String> = content.lines().map(String::from).collect();
    let mut new_lines = Vec::new();
    let mut applied = false;

    for (i, line) in lines.iter().enumerate() {
        new_lines.push(line.clone());

        // Apply fix after the line with the issue
        if (i + 1) as u32 == line_num && !applied {
            let indent = line
                .chars()
                .take_while(|c| c.is_whitespace())
                .collect::<String>();

            match rule_id {
                "PS-001" => {
                    // Missing signer check - add is_signer check
                    let account_var = extract_account_variable(line);
                    if !account_var.is_empty() {
                        let fix_line = format!(
                            "{}if !{}.is_signer() {{ return Err(ProgramError::MissingRequiredSignature); }}",
                            indent, account_var
                        );
                        new_lines.push(fix_line);
                        applied = true;
                    }
                }
                "PS-002" => {
                    // Missing owner check - add owned_by check
                    let account_var = extract_account_variable(line);
                    if !account_var.is_empty() {
                        let fix_line = format!(
                            "{}if !{}.owned_by(&crate::ID) {{ return Err(ProgramError::IncorrectProgramId); }}",
                            indent, account_var
                        );
                        new_lines.push(fix_line);
                        applied = true;
                    }
                }
                "PS-010" => {
                    // Missing writable check - add is_writable check
                    let account_var = extract_account_variable(line);
                    if !account_var.is_empty() {
                        let fix_line = format!(
                            "{}if !{}.is_writable() {{ return Err(ProgramError::InvalidAccountData); }}",
                            indent, account_var
                        );
                        new_lines.push(fix_line);
                        applied = true;
                    }
                }
                _ => {
                    // For other rules, just add a comment
                    let fix_comment = format!("// SENTINEL FIX: {}", fix);
                    new_lines.push(format!("{}{}", indent, fix_comment));
                    applied = true;
                }
            }
        }
    }

    if applied {
        *content = new_lines.join("\n");
    }

    applied
}

fn extract_account_variable(line: &str) -> String {
    // Extract account variable name from line like "let vault = accounts.get(0)..."
    // or "let user = &accounts[0]..."
    let trimmed = line.trim();

    // Pattern: let <var> = <expr>
    if let Some(eq_pos) = trimmed.find('=') {
        let lhs = trimmed[..eq_pos].trim();
        if let Some(space_pos) = lhs.find(' ') {
            let var_name = lhs[space_pos + 1..].trim();
            // Check if RHS contains accounts
            let rhs = trimmed[eq_pos + 1..].trim();
            if rhs.contains("accounts") {
                return var_name.to_string();
            }
        }
    }

    // Pattern: accounts[n] or accounts.get(n) used directly
    if trimmed.contains("accounts[") || trimmed.contains("accounts.get(") {
        return "accounts".to_string();
    }

    String::new()
}

fn show_rules(rule_id: Option<&str>) {
    let all_rules = rules::get_all_rules();

    if let Some(id) = rule_id {
        if let Some(rule) = all_rules.iter().find(|r| r.id() == id) {
            println!("Rule: {}", rule.id());
            println!("Description: {}", rule.description());
            println!("Severity: {:?}", rule.severity());
        } else {
            eprintln!("Rule {} not found", id);
        }
    } else {
        println!("Available rules:");
        println!();
        for rule in &all_rules {
            println!(
                "  {} - {} ({:?})",
                rule.id(),
                rule.description(),
                rule.severity()
            );
        }
    }
}
