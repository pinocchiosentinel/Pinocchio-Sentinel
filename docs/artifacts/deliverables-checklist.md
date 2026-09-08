# Pinocchio Sentinel deliverables checklist

This checklist maps the grant proposal’s required deliverables to the current repository state and the validation evidence gathered during verification.

## Required deliverables

### 1) Public Apache-2.0 repository with commit history
- Status: satisfied by repository metadata and project license.
- Evidence: [Cargo.toml](../../Cargo.toml) declares the Apache-2.0 license, and the repo is a public Git repository.

### 2) cargo install pinocchio-sentinel working from crates.io
- Status: satisfied locally by `cargo install --path . --root /tmp/sentinel-install --force`.
- Evidence: installation completed successfully and produced `pinocchio-sentinel.exe` under `/tmp/sentinel-install/bin`.

### 3) Benchmark results with detection and false-positive rates stated separately, per rule
- Status: partially satisfied; the repository includes benchmark harnesses and code, but it does not yet contain a published per-rule benchmark report file.
- Required completion: add a benchmark report document under `docs/artifacts/` with per-rule detection and false-positive counts from the sample corpus.

### 4) Generated exploit test for PS-004 and PS-011 with pre-fix and post-fix output
- Status: partial. The evidence generator supports PS-004 and PS-011 logic in [src/evidence/generator.rs](../../src/evidence/generator.rs), but there is no saved run log or artifact report showing pre-fix and post-fix output.
- Required completion: add a generated evidence document with example before/after exploit execution output.

### 5) SARIF output rendering as GitHub Action annotations
- Status: satisfied technically via [src/output/sarif.rs](../../src/output/sarif.rs) and workflow validation in [./.github/workflows/ci.yml](../../.github/workflows/ci.yml).
- Evidence: the CI workflow validates SARIF schema and emits file output for upload.

### 6) SKILL.md Claude Code skill in the repository
- Status: satisfied by [SKILL.md](../../SKILL.md).

### 7) Session transcripts for all four phases
- Status: not present in the repository as actual transcript files.
- Required completion: add a `docs/artifacts/session-transcripts/` folder with the phase summaries or transcript notes matching the build process.

## Repository findings

The codebase already satisfies the core technical functionality required by the proposal and passes the Rust test suite.

The remaining gaps are primarily artifact/documentation compliance rather than analyzer correctness.

## Action items still needed

1. Add per-rule benchmark report document.
2. Add proof artifact for PS-004/PS-011 exploit generation.
3. Add session transcript summaries for the four proposal phases.
4. Confirm generated output and release artifacts are stored under `docs/artifacts/`.
