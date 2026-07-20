# ADR-0005: codec backend profiles are explicit and mutually exclusive

- Status: accepted
- Date: 2026-07-20
- Tracks: RM-115 / issue #44

## Context

The five Tier 1 outer filters need a C/FFI-free default for portable builds and
an explicit native-library path for comparative performance. Individual codec
features already exist and are used by downstream crates. Selecting backends
at runtime would duplicate state machines, obscure the dependency graph, and
make disabled capabilities harder to reason about.

Cargo's `--all-features` necessarily selects every additive feature. It cannot
represent two features whose contract is mutual exclusion.

## Decision

- `portable-codecs` is the default feature and enables gzip, bzip2, zstd,
  xz/LZMA2, and LZ4 frame through Rust implementations.
- `native-codecs` is selected only with `--no-default-features`. It enables the
  same codec surface through libz, libbz2, libzstd, liblzma, and liblz4.
- Selecting both profiles produces a crate-level `compile_error!` with the
  native invocation. CI and local gates build maximal portable and native
  configurations separately and also test the expected conflict.
- Existing `gzip`, `bzip2`, `zstd`, `xz`, and `lz4` features remain compatible.
  If neither profile marker is present, they select portable implementations.
- Backend choice is compile-time static dispatch. Pipeline, synchronous,
  futures-io, Tokio, create, and compatibility CLI paths preserve one bounded
  protocol and the same typed malformed/limit outcomes.
- Normal/build dependency graphs, not source inspection alone, are the
  portable-profile authority. The gate rejects codec C/FFI packages and proves
  that the native profile contains all five intended system backends.

## Consequences

- Ordinary builds and `cargo install` use the portable profile without C codec
  toolchains.
- Native builds are explicit and auditable, but may require a C compiler or
  platform build prerequisites from the selected `*-sys` crates.
- Regular build, test, lint, documentation, MSRV, package-smoke, fuzz, and
  big-endian commands use a profile matrix. `cargo deny` may still inspect the
  union graph because it performs dependency analysis rather than compiling
  the mutually exclusive crate configuration.
- Compressed bytes are deterministic within one profile but are not promised
  identical across profiles. Decoded bytes, framing validation, limits, and
  error classes are the compatibility contract.