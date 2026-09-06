# Pinocchio Sentinel

[![CI](https://github.com/pinocchio-sentinel/Pinocchio-Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/pinocchio-sentinel/Pinocchio-Sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)

Static analysis for Solana programs written without Anchor.

---

## What is Pinocchio Sentinel?

Pinocchio Sentinel is a security-focused static analysis tool for Solana programs built with [Pinocchio](https://github.com/anza-xyz/pinocchio) or raw `solana_program`. It detects the security-check omissions that Anchor prevents structurally and that Pinocchio, by design, does not.

The tool works by:

1. **Recovering the instruction router** from the entrypoint macro (`entrypoint!`, `lazy_program_entrypoint!`)
2. **Building an account access graph** that models how each handler reads and writes accounts
3. **Checking for missing validations** — signer checks, owner checks, discriminant verification, and more
4. **Reporting findings** with severity, confidence, and actionable fix suggestions

## Why Sentinel?

Anchor enforces security invariants at compile time. When you use Anchor, certain classes of vulnerabilities are structurally impossible. But Anchor has overhead: larger binaries, slower builds, and constraints on program design.

Pinocchio gives you low-level control with minimal overhead. The tradeoff is that you're responsible for your own security checks. Sentinel fills that gap — it catches the checks you forgot.

## Features

| Feature | Description |
|---------|-------------|
| **14 security rules** | Covers critical Solana program vulnerabilities |
| **Router recovery** | Automatic instruction dispatch detection |
| **Variable alias tracking** | Follows `let authority = &accounts[0]` |
| **Entrypoint discovery** | Supports `entrypoint!`, `lazy_program_entrypoint!`, `no_allocator!` |
| **Interprocedural analysis** | Detects issues across function boundaries |
| **Fix suggestions** | Actionable code snippets for every finding |
| **Multiple output formats** | CLI (colored), SARIF 2.1.0, JSON |
| **CI/CD integration** | GitHub Actions workflow included |
| **Workspace scanning** | Scan entire projects or individual files |

## Installation

### From crates.io

```bash
cargo install pinocchio-sentinel
```

### From source

```bash
git clone https://github.com/pinocchio-sentinel/Pinocchio-Sentinel.git
cd Pinocchio-Sentinel
cargo build --release
```

The binary will be at `target/release/pinocchio-sentinel`.

## Quick Start

```bash
# Scan a single file
pinocchio-sentinel --path src/lib.rs

# Scan a project directory
pinocchio-sentinel --path ./my-program

# Scan with SARIF output for CI
pinocchio-sentinel --path . --format sarif -o sentinel.sarif --fail-on-high
```

## CLI Reference

### Basic Usage

```bash
pinocchio-sentinel [OPTIONS] --path <PATH>
pinocchio-sentinel <COMMAND>
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --path <PATH>` | Path to scan (file, directory, or workspace) | `.` |
| `-f, --format <FORMAT>` | Output format: `cli`, `sarif`, `json` | `cli` |
| `-o, --output <PATH>` | Write output to file | stdout |
| `--min-severity <LEVEL>` | Filter by severity: `high`, `medium`, `warn`, `low`, `info` | none |
| `--allow <RULES>` | Suppress rules (comma-separated, e.g., `PS-001,PS-002`) | none |
| `--fail-on-high` | Exit with code 1 if HIGH findings exist | off |
| `--fix` | Display fix suggestions | off |
| `-v, --verbose` | Enable verbose logging | off |
| `-c, --config <PATH>` | Configuration file path | `sentinel.toml` |

### Commands

| Command | Description |
|---------|-------------|
| `init` | Generate a default `sentinel.toml` configuration |
| `rules [RULE_ID]` | List all rules or show details for a specific rule |
| `audit` | Run a full audit with detailed report |

### Examples

```bash
# Scan and filter to HIGH severity only
pinocchio-sentinel --path ./program --min-severity high

# Suppress specific rules
pinocchio-sentinel --path ./program --allow PS-001,PS-012

# Generate SARIF for GitHub Code Scanning
pinocchio-sentinel --path . --format sarif -o .github/sentinel.sarif --fail-on-high

# Run full audit with JSON output
pinocchio-sentinel audit --path ./program --format json -o audit.json

# Initialize configuration
pinocchio-sentinel init
```

## Rules

Pinocchio Sentinel implements 14 security rules covering the most critical Solana program vulnerabilities:

### Account Validation

| Rule | Description | Severity | What it catches |
|------|-------------|----------|-----------------|
| PS-001 | Missing `is_signer()` check | HIGH | Authority used without signature verification |
| PS-002 | Missing `owned_by()` check | HIGH | Account data read without ownership verification |
| PS-003 | Missing discriminant check | HIGH | Account cast without type verification |
| PS-010 | Missing `is_writable()` check | HIGH | Account mutated without write permission |

### Data Safety

| Rule | Description | Severity | What it catches |
|------|-------------|----------|-----------------|
| PS-004 | Missing `data_len()` bounds | HIGH | Zero-copy cast without size verification |
| PS-012 | Slice index without bounds | WARN | Array access without length check |

### PDA Security

| Rule | Description | Severity | What it catches |
|------|-------------|----------|-----------------|
| PS-005 | PDA without canonical bump | MEDIUM | PDA used without bump seed verification |

### Account Uniqueness

| Rule | Description | Severity | What it catches |
|------|-------------|----------|-----------------|
| PS-006 | Account aliasing | MEDIUM | Same account passed twice as mutable |

### CPI Security

| Rule | Description | Severity | What it catches |
|------|-------------|----------|-----------------|
| PS-007 | Arbitrary CPI target | HIGH | CPI to unverified program ID |
| PS-011 | Missing account count gate | HIGH | `lazy_program_entrypoint!` without length check |
| PS-013 | Unchecked CPI return | HIGH | CPI failure not handled |

### Account Lifecycle

| Rule | Description | Severity | What it catches |
|------|-------------|----------|-----------------|
| PS-008 | Account reinitialization | HIGH | Init path reachable on existing account |
| PS-009 | Lamport zeroing missing | HIGH | Balance reduction without data cleanup |

### Sysvar Security

| Rule | Description | Severity | What it catches |
|------|-------------|----------|-----------------|
| PS-014 | Sysvar without pubkey check | HIGH | Clock/sysvar used without address verification |

## Configuration

Create a `sentinel.toml` in your project root:

```toml
[analysis]
intra_procedural_only = false    # Enable interprocedural analysis
max_scan_time_ms = 10000         # Maximum scan time
include_skeletons = true         # Include skeleton tests in output

[output]
format = "cli"                   # Default output format

[rules]
# Rules to enable (all enabled by default)
enabled_rules = [
    "PS-001", "PS-002", "PS-003", "PS-004", "PS-005",
    "PS-006", "PS-007", "PS-008", "PS-009", "PS-010",
    "PS-011", "PS-012", "PS-013", "PS-014"
]

# Rules to disable
disabled_rules = []

# Override severity for specific rules
severity_overrides = { "PS-012" = "low" }

# Rules to suppress globally
allow_list = []

# Minimum severity to report
min_severity = "medium"
```

## CI Integration

### GitHub Actions

Add this to `.github/workflows/sentinel.yml`:

```yaml
name: Security Audit

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Install Pinocchio Sentinel
        run: cargo install pinocchio-sentinel

      - name: Run security audit
        run: |
          pinocchio-sentinel \
            --path . \
            --format sarif \
            -o sentinel.sarif \
            --fail-on-high

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sentinel.sarif
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: pinocchio-sentinel
        name: Pinocchio Sentinel
        entry: pinocchio-sentinel --path . --fail-on-high
        language: system
        pass_filenames: false
```

## Output Formats

### CLI (default)

Colorized terminal output with findings grouped by severity:

```
Pinocchio Sentinel Scan Results
==================================================

Summary: 8 findings
  7 HIGH
  0 MEDIUM
  1 WARN

1. [PS-001] Account 'accounts[0]' (index 0) is used without is_signer() check
   Handler: process_instruction
   Line: 8
   Fix: Add `if !accounts[0].is_signer() { return Err(ProgramError::MissingRequiredSignature); }` before use
```

### SARIF 2.1.0

JSON format compatible with GitHub Code Scanning and other SARIF viewers:

```bash
pinocchio-sentinel --path . --format sarif -o output.sarif
```

### JSON

Machine-readable format with summary statistics:

```bash
pinocchio-sentinel --path . --format json -o output.json
```

## Project Structure

```
pinocchio-sentinel/
├── src/
│   ├── lib.rs                    # Library crate root
│   ├── bin/main.rs               # CLI binary
│   ├── frontend/                 # Program parsing
│   │   ├── mod.rs                # ParsedProgram, HandlerInfo
│   │   ├── entrypoint.rs         # Entrypoint macro detection
│   │   ├── router.rs             # Instruction router recovery
│   │   └── discriminator.rs      # Discriminator inference
│   ├── graph/                    # Analysis graphs
│   │   ├── mod.rs                # Graph types
│   │   ├── access_graph.rs       # Account access graph
│   │   ├── call_graph.rs         # Function call graph
│   │   ├── interprocedural.rs    # Cross-function analysis
│   │   └── check_ordering.rs     # Check-before-use ordering
│   ├── rules/                    # Security rules
│   │   ├── mod.rs                # Rule trait, Finding type
│   │   └── ps001.rs - ps014.rs   # Individual rules
│   ├── output/                   # Output formatters
│   │   ├── mod.rs                # Output types
│   │   ├── cli.rs                # Colored terminal output
│   │   ├── sarif.rs              # SARIF 2.1.0 format
│   │   └── json.rs               # JSON format
│   ├── evidence/                 # Exploit test generation
│   │   ├── mod.rs                # ExploitTest types
│   │   ├── generator.rs          # Test generation
│   │   └── test_runner.rs        # Test runner
│   └── config/                   # Configuration
│       └── mod.rs                # SentinelConfig
├── tests/
│   ├── benchmark_tests.rs        # Integration tests
│   ├── benchmark_perf.rs         # Performance benchmarks
│   ├── benchmarks/               # 11 benchmark programs
│   └── programs/                 # Test fixtures
├── docs/
│   └── rules/                    # Rule documentation
├── .github/workflows/
│   ├── ci.yml                    # CI pipeline
│   └── release.yml               # Release workflow
├── sentinel.toml                 # Default configuration
├── Cargo.toml                    # Rust project manifest
└── README.md                     # This file
```

## Development

### Prerequisites

- Rust 1.70+
- Visual Studio 2022 Build Tools (Windows only)

### Building

```bash
cargo build --release
```

### Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test suite
cargo test --test benchmark_tests
cargo test --test benchmark_perf
```

### Benchmarks

Performance benchmarks run in <10ms for 11 programs:

```bash
cargo test --test benchmark_perf -- --nocapture
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
