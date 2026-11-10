# Bounded static RAR3 standard filters

## Status

Proposed

Date: 2026-08-17

## Context

RAR3 permits filter programs, but a general interpreter would expand the parser and resource surface.

## Decision

Accept only standard transforms matched by checksum and fingerprint through a closed enum.
Keep descriptor parsing and transforms in the separate bounded `RARVM` primitive crate.
Charge program tables, pending invocations, blocks, and scratch in codec preflight.

## Alternatives

Rejecting all filters preserves a smaller surface but loses common archives.
Executing arbitrary programs needs a separate instruction and resource model.

## Consequences

Unknown programs remain typed unsupported.
Standard transforms add a independently licensed package and provenance obligation.
Reconsider interpreter support only with an explicit reviewed execution model.

## Confirmation

`just architecture`, primitive unit tests, and [legacy `RAR` tests](../../libarchive_oxide/tests/rar_legacy.rs) cover dependency direction, descriptors, checksums, program limits, scratch bounds, and known fixtures.
