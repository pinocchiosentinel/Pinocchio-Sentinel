pub mod config;
pub mod evidence;
pub mod frontend;
pub mod graph;
pub mod output;
pub mod rules;

pub use config::SentinelConfig;
pub use frontend::{parse_program, EntrypointMacro, ParsedProgram};
pub use graph::{build_access_graph, AccountAccessGraph};
pub use output::{format_findings, print_findings, print_summary, ScanResult};
pub use rules::{get_all_rules, run_all_rules, Confidence, Finding, Rule, Severity};
