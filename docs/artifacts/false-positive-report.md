# False-positive dataset for clean programs

This document formalizes the clean-program corpus used to estimate false positives for the rule set.

## Scope

The purpose of this dataset is to validate that the analyzer does not fire on known-safe programs that perform the required checks in the correct order.

## Corpus

The clean corpus currently includes:
- `tests/clean-programs/safe-program.rs`

## Clean-program evaluation

The following program represents a safe Pinocchio-style path with the expected validations applied:

- signer check before use
- ownership check before use
- writable check before mutation
- data length guard before indexing
- no unsafe aliasing

This prevents the typical high-severity rules from triggering.

## Expected findings on the clean program

Expected result: zero HIGH findings.

This is the baseline false-positive test case for the following rules:
- PS-001
- PS-002
- PS-004
- PS-010

## Validation command

```bash
cargo run -- --path tests/clean-programs/safe-program.rs
```

Expected output: the project should not report a HIGH-severity violation for the safe sample.

## Interpretation

A clean program should not trigger the energetic rule predicates that are meant to identify missing validation. This dataset serves as the minimal false-positive baseline for the project’s v0.1 reporting.
