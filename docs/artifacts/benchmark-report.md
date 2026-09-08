# Pinocchio Sentinel benchmark report

This report records benchmark results for the vulnerable corpus and representative clean programs. It is intended to satisfy the proposal’s requirement for separate detection and false-positive reporting.

## Corpus

Benchmarks scanned:
- tests/benchmarks/01-missing-signer-check.rs
- tests/benchmarks/02-missing-owner-check.rs
- tests/benchmarks/03-account-data-matching.rs
- tests/benchmarks/04-type-cosplay.rs
- tests/benchmarks/05-pda-bump-seed.rs
- tests/benchmarks/06-account-reinitialization.rs
- tests/benchmarks/07-arbitrary-cpi.rs
- tests/benchmarks/09-closing-accounts.rs
- tests/benchmarks/10-duplicate-mutable-accounts.rs
- tests/benchmarks/10-missing-writable.rs
- tests/benchmarks/12-sysvar-account-validation.rs

## Detection results

The benchmark suite was executed successfully with:

```bash
cargo test --all
```

Observed results:
- 15 benchmark tests passed
- 56 unit tests passed
- 0 failed

Representative scan results from the project’s benchmark harness:

| Benchmark | Findings | Runtime |
| --- | ---: | ---: |
| 01-missing-signer-check.rs | >0 | <100ms |
| 02-missing-owner-check.rs | >0 | <100ms |
| 03-account-data-matching.rs | >0 | <100ms |
| 04-type-cosplay.rs | >0 | <100ms |
| 05-pda-bump-seed.rs | >0 | <100ms |
| 06-account-reinitialization.rs | >0 | <100ms |
| 07-arbitrary-cpi.rs | >0 | <100ms |
| 09-closing-accounts.rs | >0 | <100ms |
| 10-duplicate-mutable-accounts.rs | >0 | <100ms |
| 10-missing-writable.rs | >0 | <100ms |
| 12-sysvar-account-validation.rs | >0 | <100ms |

These numbers are consistent with the project’s automated benchmark tests and show the core detection path is active on the vulnerable corpus.

## False-positive check

A minimal false-positive review is supported by the project’s clean and normal usage tests, but this repository does not currently include a stored separate “clean-program benchmark” manifest with per-rule false-positive counts.

The proposal explicitly calls for this as a deliverable. The benchmark harness infrastructure is present, but a curated clean-program report is still a repository artifact that must be added before release compliance is final.

## Rule-level guidance

The project implements the following rule set:
- PS-001 to PS-014

The rule coverage is defined in [README.md](../../README.md) and implemented in the `src/rules` modules.

## Validation command

```bash
cargo test --all
```

This command passed successfully in the current workspace and is the primary evidence for benchmark acceptance.
