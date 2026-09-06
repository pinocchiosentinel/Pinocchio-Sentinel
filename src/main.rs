mod frontend;
mod graph;
mod rules;
mod evidence;
mod output;
mod config;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::Instant;

use config::SentinelConfig;
use frontend::parse_program;
use graph::build_access_graph;
use rules::run_all_rules;
use output::{ScanResult, format_findings, print_findings, print_summary};

#[derive(Parser)]
#[command(name = "pinocchio-sentinel")]
#[command(about = "Static analysis for Solana programs written without Anchor")]
#[command(version = "0.1.0")]
struct Cli {
    /// Path to the Cargo workspace or program directory
    #[arg(short, long, default_value = ".")]
    path: PathBuf,
    
    /// Output format (cli, sarif, json)
    #[arg(short, long, default_value = "cli")]
    format: String,
    
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
    
    /// Include skeleton tests in output
    #[arg(long)]
    include_skeletons: bool,
    
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new sentinel.toml configuration
    Init {
        /// Output path for sentinel.toml
        #[arg(short, long, default_value = "sentinel.toml")]
        output: PathBuf,
    },
    
    /// Show information about rules
    Rules {
        /// Rule ID to show details for
        rule_id: Option<String>,
    },
    
    /// Run tests for generated exploit tests
    Test {
        /// Path to the program to test
        #[arg(short, long)]
        path: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing
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
        Some(Commands::Test { path }) => {
            println!("Testing at {}", path.display());
            // TODO: Implement test runner
            return Ok(());
        }
        None => {}
    }
    
    // Load configuration
    let config = if cli.config.exists() {
        SentinelConfig::load(&cli.config)?
    } else {
        SentinelConfig::default()
    };
    
    // Find Rust source files
    let start = Instant::now();
    let source_files = find_source_files(&cli.path)?;
    
    if source_files.is_empty() {
        eprintln!("No Rust source files found at {}", cli.path.display());
        std::process::exit(1);
    }
    
    let mut all_findings = Vec::new();
    let mut files_scanned = 0;
    
    // Analyze each file
    for source_file in &source_files {
        if cli.verbose {
            tracing::info!("Analyzing {}", source_file.display());
        }
        
        match parse_program(source_file, &config) {
            Ok(program) => {
                if let Some(ref router) = program.router {
                    let graph = build_access_graph(
                        &router.handlers[0], // Simplified for v0.1
                        &program.ast,
                    );
                    
                    let findings = run_all_rules(&graph);
                    all_findings.extend(findings);
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
    
    let scan_time = start.elapsed().as_millis() as u64;
    
    // Create scan result
    let result = ScanResult {
        findings: all_findings,
        scan_time_ms: scan_time,
        files_scanned,
        rules_applied: config.rules.enabled_rules.len(),
    };
    
    // Output results
    if let Some(ref sarif_path) = cli.sarif {
        let sarif_output = output::sarif::to_sarif(&result.findings);
        std::fs::write(sarif_path, sarif_output)?;
        if cli.verbose {
            tracing::info!("SARIF output written to {}", sarif_path.display());
        }
    }
    
    if let Some(ref json_path) = cli.json {
        let json_output = output::json::to_json(&result.findings);
        std::fs::write(json_path, json_output)?;
        if cli.verbose {
            tracing::info!("JSON output written to {}", json_path.display());
        }
    }
    
    if let Some(ref output_path) = cli.output {
        let output_text = format_findings(&result.findings, &cli.format);
        std::fs::write(output_path, output_text)?;
        if cli.verbose {
            tracing::info!("Output written to {}", output_path.display());
        }
    } else {
        print_findings(&result.findings);
    }
    
    // Print summary
    print_summary(&result.findings);
    
    // Exit with error if HIGH findings and fail-on-high is set
    if cli.fail_on_high && result.has_high_findings() {
        std::process::exit(1);
    }
    
    Ok(())
}

fn find_source_files(path: &PathBuf) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    
    if path.is_file() {
        if path.extension().map_or(false, |ext| ext == "rs") {
            files.push(path.clone());
        }
        return Ok(files);
    }
    
    // Walk directory for .rs files
    for entry in walkdir::WalkDir::new(path) {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "rs" {
                    // Skip target directory and test files
                    let path_str = path.to_string_lossy();
                    if !path_str.contains("target") && !path_str.contains("tests") {
                        files.push(path.to_path_buf());
                    }
                }
            }
        }
    }
    
    Ok(files)
}

fn show_rules(rule_id: Option<&str>) {
    let rules = rules::get_all_rules();
    
    if let Some(id) = rule_id {
        if let Some(rule) = rules.iter().find(|r| r.id() == id) {
            println!("Rule: {}", rule.id());
            println!("Description: {}", rule.description());
            println!("Severity: {:?}", rule.severity());
        } else {
            eprintln!("Rule {} not found", id);
        }
    } else {
        println!("Available rules:");
        println!();
        for rule in &rules {
            println!("  {} - {} ({:?})", rule.id(), rule.description(), rule.severity());
        }
    }
}
