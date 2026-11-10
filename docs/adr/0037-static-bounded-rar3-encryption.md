# Bounded `RAR3` password attempts

## Status

Proposed

Date: 2026-08-17

## Context

RAR3 password validation depends on header or decoded-payload checksums.
Ordered candidates can multiply computation and temporary memory.

## Decision

Use a separate concrete cryptography provider with zeroizing keys.
Cap candidates at 16 and account for ciphertext, candidate plaintext, decoded output, and codec workspace.
Deliver file data only after decoded size and CRC32 agree.
Bound encrypted-header size hypotheses.

## Alternatives

Streaming candidate plaintext exposes data before validation.
Unbounded retries or whole-file copies without accounting violate resource limits.

## Consequences

Whole-member buffering is deliberate and finite.
Encrypted solid, split-volume, and symlink payloads remain unsupported.
Reconsider those modes only with replay semantics that preserve validation before delivery.

## Confirmation

Cryptography unit vectors and [legacy `RAR` tests](../../libarchive_oxide/tests/rar_legacy.rs) cover ordered candidates, wrong passwords, truncation, exact sizes, checksums, and limits.
Provenance identifies adopted `ISC` source.
