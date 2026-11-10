# Bounded legacy `RAR` container reads

## Status

Proposed

Date: 2026-08-14

## Context

Legacy `RAR` needs container compatibility while compression and provenance remain separate concerns.

## Decision

Parse legacy headers and Store payloads with finite metadata, path, decoded-byte, and source limits.
Verify header and payload checksums.
Delegate compressed payloads to typed providers and require explicit volume sources.
Keep writing unavailable.

## Alternatives

Recognizing names alone leaves ordinary archives unusable.
Importing a general archive implementation would broaden licensing and parser responsibilities.

## Consequences

Unsupported methods and malformed continuations produce distinct typed errors.
Container support doesn't imply every compression or encryption mode.
Reconsider supported methods only with reviewed codecs and fixtures.

## Confirmation

[Legacy `RAR` tests](../../libarchive_oxide/tests/rar_legacy.rs) and volume tests exercise checksums, metadata, resource limits, and physical continuation.
Fixture provenance records producer and license boundaries.
