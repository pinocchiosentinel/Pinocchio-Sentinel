# Pinocchio Sentinel

Static analysis for Solana programs written without Anchor.

## Overview

Pinocchio Sentinel detects security-check omissions that Anchor prevents structurally and that Pinocchio, by design, does not. It recovers a program's instruction router from its entrypoint macro, models how each handler reads and writes the account slice, and reports accounts that are used before they are validated.

## Features

- **14 security rules** covering critical Solana program vulnerabilities
- **Router recovery** with match dispatch and single-function fallback
- **Variable alias tracking** (`let authority = &accounts[0]`)
- **Entrypoint discovery** for `entrypoint!`, `lazy_program_entrypoint!`, `no_allocator!`
- **Interprocedural analysis** across function boundaries
- **Exploit test generation** for each finding
- **Multiple output formats**: CLI (colored), SARIF 2.1.0, JSON
- **CI/CD integration** with GitHub Actions

## Installation

```bash
cargo install pinocchio-sentinel
```

Or build from source:

```bash
git clone https://github.com/pinocchio-sentinel/Pinocchio-Sentinel.git
cd Pinocchio-Sentinel
cargo build --release
```

## Usage

### Basic scan

```bash
pinocchio-sentinel --path /path/to/program
```

### SARIF output

```bash
pinocchio-sentinel --path /path/to/program --format sarif -o output.sarif
```

### JSON output

```bash
pinocchio-sentinel --path /path/to/program --format json -o output.json
```

### Initialize configuration

```bash
pinocchio-sentinel init
```

### List rules

```bash
pinocchio-sentinel rules
```

### CI mode (fail on HIGH findings)

```bash
pinocchio-sentinel --path . --fail-on-high
```

## Rules

| ID | Description | Severity |
| --- | --- | --- |
| PS-001 | Authority account used without `is_signer()` assertion | HIGH |
| PS-002 | Account data read without `owned_by(&crate::ID)` | HIGH |
| PS-003 | Account cast without discriminant check | HIGH |
| PS-004 | Zero-copy cast without `data_len()` bounds assertion | HIGH |
| PS-005 | PDA used without canonical bump verification | MEDIUM |
| PS-006 | Two account indices may alias, both mutated | MEDIUM |
| PS-007 | CPI target program ID not compared against constant | HIGH |
| PS-008 | Initialization path reachable on already-initialized account | HIGH |
| PS-009 | Lamport reduction without data zeroing | HIGH |
| PS-010 | Account mutated without `is_writable()` assertion | HIGH |
| PS-011 | `lazy_program_entrypoint!` without account-count gate | HIGH |
| PS-012 | Slice index accessed without length assertion | WARN |
| PS-013 | CPI return value not checked | HIGH |
| PS-014 | Sysvar account without pubkey comparison | HIGH |

## Configuration

Create a `sentinel.toml` in your project root:

```toml
[analysis]
intra_procedural_only = false
max_scan_time_ms = 10000
include_skeletons = true

[output]
format = "cli"

[rules]
enabled_rules = [
    "PS-001", "PS-002", "PS-003", "PS-004", "PS-005",
    "PS-006", "PS-007", "PS-008", "PS-009", "PS-010",
    "PS-011", "PS-012", "PS-013", "PS-014"
]
disabled_rules = []
severity_overrides = {}
allow_list = []
```

## CI Integration

### GitHub Actions

```yaml
- name: Run Pinocchio Sentinel
  run: |
    cargo install pinocchio-sentinel
    pinocchio-sentinel --path . --format sarif -o sentinel.sarif --fail-on-high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel.sarif
```

## Project Structure

```
src/
  lib.rs                    - Library crate root
  bin/main.rs               - CLI binary
  frontend/
    mod.rs                  - Program parsing, AST types
    entrypoint.rs           - Entrypoint macro detection
    router.rs               - Instruction router recovery
    discriminator.rs        - Discriminator inference
  graph/
    mod.rs                  - Graph types
    access_graph.rs         - Account access graph
    call_graph.rs           - Function call graph
    interprocedural.rs      - Cross-function analysis
    check_ordering.rs       - Check-before-use ordering
  rules/
    mod.rs                  - Rule trait, Finding type
    ps001.rs - ps014.rs     - Security rules
  output/
    mod.rs                  - Output types
    cli.rs                  - Colored terminal output
    sarif.rs                - SARIF 2.1.0 format
    json.rs                 - JSON format
  evidence/
    mod.rs                  - Exploit test types
    generator.rs            - Test generation
    test_runner.rs          - Test runner
  config/
    mod.rs                  - Configuration
tests/
  benchmark_tests.rs        - Integration tests
  benchmarks/               - Benchmark programs
  programs/                 - Test fixtures
```

## Benchmarks

The tool is validated against 11 benchmark programs from [mira4sol/solana-security-examples](https://github.com/mira4sol/solana-security-examples), migrated to pinocchio 0.11.2 patterns.

## License

Apache-2.0
