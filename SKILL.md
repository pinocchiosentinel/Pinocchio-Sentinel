# Pinocchio Sentinel Development Skill

## Overview
Pinocchio Sentinel is a Rust CLI static analyzer for Solana programs written without Anchor. It detects security-check omissions that Anchor prevents structurally.

## Project Structure
```
pinocchio-sentinel/
├── src/
│   ├── lib.rs              # Library crate root
│   ├── bin/main.rs         # CLI binary
│   ├── frontend/           # AST parsing, entrypoint discovery, router recovery
│   ├── graph/              # Account access graph, call graph, interprocedural analysis
│   ├── rules/              # PS-001 through PS-014 security rules
│   ├── output/             # CLI, SARIF, JSON, HTML, Markdown formatters
│   ├── evidence/           # Exploit test generation
│   └── config/             # Configuration handling
├── tests/
│   ├── benchmarks/         # 11 benchmark programs for testing
│   └── benchmark_tests.rs  # Integration tests
└── docs/rules/             # Rule documentation
```

## Key Commands

### Build
```bash
cargo build --release
```

### Test
```bash
cargo test                    # Run all tests
cargo test --test benchmark_tests  # Run integration tests only
```

### Lint
```bash
cargo fmt --all -- --check    # Check formatting
cargo clippy --all-targets --all-features -- -D warnings  # Check clippy
```

### Run
```bash
./target/release/pinocchio-sentinel --path ./program.rs
./target/release/pinocchio-sentinel audit --path ./program.rs
./target/release/pinocchio-sentinel --path ./program.rs --format html -o report.html
```

## Development Workflow

1. **Adding a new rule:**
   - Create `src/rules/ps0XX.rs`
   - Implement the `Rule` trait
   - Add to `src/rules/mod.rs`
   - Add benchmark test in `tests/benchmarks/`
   - Add integration test in `tests/benchmark_tests.rs`

2. **Modifying the frontend:**
   - `src/frontend/entrypoint.rs` - Macro detection
   - `src/frontend/router.rs` - Instruction dispatch recovery
   - `src/frontend/discriminator.rs` - Discriminant handling

3. **Modifying the graph:**
   - `src/graph/access_graph.rs` - Account access tracking
   - `src/graph/call_graph.rs` - Function call analysis
   - `src/graph/interprocedural.rs` - Cross-function analysis

## Key Patterns

### Account Access Detection
The tool tracks accounts via:
- `accounts[n]` - Direct index access
- `accounts.get(n)` - Method call access
- Variable aliases: `let vault = accounts.get(0)`

### Check Detection
The tool detects security checks via method calls:
- `is_signer()` - PS-001
- `owned_by()` - PS-002
- `is_writable()` - PS-010
- `data_len()` - PS-004

### Output Formats
- `cli` - Colored terminal output (default)
- `sarif` - Static Analysis Results Interchange Format
- `json` - JSON output
- `html` - Styled HTML report
- `markdown` - Markdown report

## Testing

### Benchmark Tests
Located in `tests/benchmark_tests.rs`, these test each rule against known vulnerable programs.

### Running Specific Tests
```bash
cargo test test_01_missing_signer_check
cargo test --test benchmark_tests
```

## CI/CD

### GitHub Actions
- `ci.yml` - Lint, test, build on push/PR
- `release.yml` - Build and publish on tag

### Release Process
```bash
git tag v0.1.0
git push origin v0.1.0
# Triggers release workflow
```

## Common Issues

1. **Clippy warnings:** Run `cargo clippy --all-targets --all-features -- -D warnings`
2. **Formatting:** Run `cargo fmt --all`
3. **Test failures:** Check `tests/benchmarks/` for correct test programs

## Dependencies

Key dependencies:
- `syn` - Rust AST parsing
- `clap` - CLI argument parsing
- `serde` / `serde_json` - Serialization
- `colored` - Terminal colors
- `anyhow` - Error handling
