# Evidence artifacts for PS-004 and PS-011

This document records the generated exploit-test evidence required by the grant proposal.

## Scope

The repository includes generated exploit logic in [src/evidence/generator.rs](../../src/evidence/generator.rs) for the following rule IDs:
- PS-004
- PS-011

These are the two rules flagged in the proposal as having full exploit generators rather than skeletons.

## Observed behavior

The generator emits Rust test code that demonstrates the issue pattern without requiring the full Solana runtime to be executed in this workspace.

### PS-004 pattern
The generated test captures the core vulnerability:
- zero-copy read without a prior `data_len()` check
- exploit succeeds when insufficient data is interpreted as valid
- fix is to assert the required bounds before indexing

### PS-011 pattern
The generated test captures the core vulnerability:
- `lazy_program_entrypoint!` usage without an account-count gate
- direct indexing into `accounts[0]` without verifying `accounts.len()` first
- fix is to reject the instruction when the input slice is too short

## Validation evidence

The project includes benchmark coverage for the vulnerable corpus and the evidence generator is present, but the repository does not yet store a saved pre-fix and post-fix execution transcript for these rules.

This artifact is therefore a compliance placeholder that records the expected evidence workflow and the exact generator location.

## Command used to validate project structure

```bash
cargo test --all
```

This passed successfully in the current workspace.

## Recommended next step for full proposal compliance

Generate a saved artifact file from the concrete exploit generator output for PS-004 and PS-011, capturing:
- vulnerable pre-fix code path
- fixed code path
- pass/fail output demonstrating the exploit
