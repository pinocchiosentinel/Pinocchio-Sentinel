# Session transcript summaries

These are the proposal’s intended four-phase build record summaries.

## Phase 1 — Idea and validation
- Goal: validate the rule set and identify Pinocchio-specific API mismatches.
- Outcome: confirm the project scope and required rule list, including the discovered `owned_by()` naming mismatch and the absence of `find_program_address` in Pinocchio 0.11.2.
- Relevant files: [README.md](../../README.md), [src/rules](../../src/rules), [sentinel.toml](../../sentinel.toml)

## Phase 2 — Analysis core
- Goal: build the front-end and account access graph.
- Outcome: AST parsing and router recovery are implemented in [src/frontend](../../src/frontend), with the account graph in [src/graph/access_graph.rs](../../src/graph/access_graph.rs).

## Phase 3 — Rule engine and public v0.1
- Goal: implement scoring, severity, and output generation.
- Outcome: rule modules and output formatting are in place; the project emits CLI, JSON, and SARIF output.

## Phase 4 — Review and release
- Goal: validate the project, run benchmark checks, and prepare artifacts.
- Outcome: the repository passes its automated test suite and supports release install as verified by `cargo install --path . --root /tmp/sentinel-install --force`.

## Validation notes

The current repo includes the technical system, but does not preserve a raw transcript log for each phase in a dedicated artifact directory. This is a documentation gap relative to the proposal’s strict deliverable list.
