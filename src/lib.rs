pub mod config;
pub mod evidence;
pub mod frontend;
pub mod graph;
pub mod output;
pub mod rules;

pub use config::SentinelConfig;
pub use frontend::{parse_program, ParsedProgram};
pub use graph::{build_access_graph, AccountAccessGraph};
pub use rules::{run_all_rules, get_all_rules, Finding, Severity, Confidence, Rule};
pub use output::{ScanResult, format_findings, print_findings, print_summary};
