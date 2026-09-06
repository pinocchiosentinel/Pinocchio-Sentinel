# Pinocchio Sentinel

Static analysis for Solana programs written without Anchor.

## Overview

Pinocchio Sentinel detects the security-check omissions that Anchor prevents structurally and that Pinocchio, by design, does not. It recovers a program's instruction router from its entrypoint macro, models how each handler reads and writes the account slice, and reports accounts that are used before they are validated.

## Installation

```bash
cargo install pinocchio-sentinel
```

## Usage

### Basic scan

```bash
pinocchio-sentinel --path /path/to/program
```

### SARIF output for GitHub Actions

```bash
pinocchio-sentinel --path /path/to/program --sarif output.sarif --fail-on-high
```

### JSON output

```bash
pinocchio-sentinel --path /path/to/program --json output.json
```

### Initialize configuration

```bash
pinocchio-sentinel init
```

### List rules

```bash
pinocchio-sentinel rules
```

## Rules

| ID | Condition detected | Severity |
| --- | --- | --- |
| PS-001 | Authority account used without is_signer() assertion | HIGH |
| PS-002 | Account data read without owned_by(&crate::ID) | HIGH |
| PS-003 | Account cast without discriminant check | HIGH |
| PS-004 | Zero-copy cast without data_len() bounds assertion | HIGH |
| PS-005 | PDA used without canonical bump verification | MEDIUM |
| PS-006 | Two account indices may alias, both mutated | MEDIUM |
| PS-007 | CPI target program id not compared against constant | HIGH |
| PS-008 | Initialization path reachable on already-initialized account | HIGH |
| PS-009 | Lamport reduction without data zeroing | HIGH |
| PS-010 | Account mutated without is_writable() assertion | HIGH |
| PS-011 | lazy_program_entrypoint! without account-count gate | HIGH |
| PS-012 | Slice index accessed without length assertion | WARN |
| PS-014 | Sysvar account without pubkey comparison | HIGH |

## Configuration

Create a `sentinel.toml` in your project root:

```toml
[analysis]
intra_procedural_only = true
max_scan_time_ms = 5000

[output]
format = "cli"

[rules]
enabled = ["PS-001", "PS-002", "PS-003", "PS-004"]
```

## CI Integration

### GitHub Actions

```yaml
- name: Run Pinocchio Sentinel
  run: |
    cargo install pinocchio-sentinel
    pinocchio-sentinel --path . --sarif sentinel.sarif --fail-on-high
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel.sarif
```

## License

Apache-2.0
