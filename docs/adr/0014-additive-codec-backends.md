# ADR-0014: codec backend features are additive

- Status: accepted
- Date: 2026-07-28
- Supersedes: ADR-0005

## Context

Cargo features are additive. Rejecting a build that enables both
`portable-codecs` and `native-codecs` made `--all-features`, downstream feature
unification, and ordinary workspace tooling invalid configurations. It also
prevented one process from comparing or selecting already compiled backends.

Backend availability and archive/filter capability are separate concerns. The
canonical capability ledger records the latter; build-aware capability queries
combine that ledger with the enabled Cargo features.

## Decision

- `portable-codecs` remains the default profile.
- `native-codecs` is additive. Enabling both profiles is supported.
- `BackendPreference::{Auto, Portable, Native}` selects a compiled backend at
  runtime. `Auto` prefers native when it is compiled and otherwise selects
  portable.
- `Pipeline`, synchronous and asynchronous readers/writers, built-in provider
  sets, and `ArchiveEngine` accept or propagate the same preference.
- Requesting a backend that is not compiled returns a typed capability error.
- Independent producer fixtures and cross-backend writer/reader tests run with
  both profiles enabled.
- Capability reporting, provider queries, CLI output, and the generated support
  matrix are derived from the canonical ledger rather than duplicated boolean
  tables.

## Consequences

- `cargo check --all-features` and downstream feature unification are valid.
- Portable-only and native-only builds remain useful dependency-audit targets.
- Compiling both profiles increases dependency and binary surface, but callers
  can choose a backend without rebuilding.
- Encoded byte identity across backends is not an API contract. Decoded bytes,
  validation, limits, and error classification remain the interoperability
  contract.
