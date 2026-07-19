# ADR-0001: v0.2 sans-I/O state-machine architecture

- Status: accepted
- Date: 2026-07-19
- Supersedes: v0.1 slice-reader and sink contracts

## Context

The v0.1 public surface called whole-slice readers and whole-entry buffered
writers "streaming", exposed runtime-dispatch enum variants, split incremental
tar from `EntryReader`, and could not preserve an underlying I/O error. Those
constraints made every additional format more expensive and made format/codec
additions semver-breaking.

## Decision

- Keep `libarchive_oxide-core` on `no_std + alloc`, zero dependencies, safe
  Rust, and static dispatch.
- Use `ArchiveDecoder` and `ArchiveEncoder` as the only format protocols.
- Use one EOF-aware `Codec` protocol for outer filters.
- Keep actual I/O out of core. Sync, futures-io, and Tokio adapters drive the
  same state machines.
- Represent sequential and seek-required inputs/outputs with different public
  adapter types. Spooling is always explicit.
- Keep runtime dispatch variants private and expose opaque wrappers plus
  non-exhaustive identifiers.
- Use private-field, builder-created metadata that preserves archive-native
  names and unknown namespaced extensions.
- Inject finite-by-default `Limits` into every parser, codec pipeline, and
  filesystem operation.
- Require consuming writer finalization; dropping or aborting never emits an
  implicit trailer.

## Protocol invariants

- A step never reports consumption or production beyond its caller buffers.
- Zero progress is valid only when requesting input, requesting output, or
  reporting a structural/terminal event.
- EOF is explicit and truncated input is an error.
- `Done` is terminal; later non-empty input or write commands are errors.
- Entry data and outer-filter output are bounded by caller limits.
- Implementations may retain bounded headers, indexes, and codec dictionaries,
  but never a normal file payload or decoded archive solely for convenience.

## Capability matrix

| Format | Read | Write |
|---|---|---|
| tar | sequential | sequential, known size |
| cpio | sequential | sequential, known size |
| ar | sequential | sequential, known size |
| zip | seek for authoritative metadata | sequential with descriptors |
| 7z | seek | seek |
| ISO 9660 | seek | seek |

Sequential callers may opt into a bounded spool to obtain seek capability.

## Consequences

- v0.2 is intentionally source-incompatible with v0.1.
- Adding a built-in format or codec does not expose a new public payload enum
  variant.
- Async support does not fork parser logic.
- Seek requirements, unknown-size requirements, and resource consumption are
  visible API decisions rather than implicit whole-archive buffering.
