# ADR-0001: Core architecture

- Status: accepted
- Date: 2026-07-19

## Context

- Archive formats and compression filters vary independently.
- Embedded use requires `no_std`.
- Callers may need explicit buffer and I/O control.
- Runtime format detection is required.

## Decision

- Keep `libarchive_oxide-core` on `no_std` + `alloc`.
- Keep the core free of external dependencies.
- Use `Transform::{step, finish}` as the sans-IO base.
- Keep format and filter traits independent.
- Provide paired read/write and decode/encode interfaces.
- Use sealed enums for runtime dispatch.
- Put codecs, filesystem I/O, zip, and 7z in `libarchive_oxide`.

## Consequences

- Adding a format does not require filter changes.
- Adding a filter does not require format changes.
- Runtime dispatch adds enum variants and exhaustive match arms.
- The core cannot directly use third-party codecs.
- Trait changes require compatibility review.
