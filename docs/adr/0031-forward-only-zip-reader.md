# Bounded forward-only `ZIP` reads

## Status

Proposed

Date: 2026-08-15

## Context

Stream callers lack the terminal index required by the seek reader.
Descriptor signatures can also appear inside stored payloads.

## Decision

Parse local records incrementally and commit only bytes owned by each codec.
Use exact worker acknowledgements or decoder checkpoints where needed.
Verify descriptor counts, checksums, and encryption authentication before entry completion.
Reject ambiguous unsupported boundaries rather than scanning without limits.

## Alternatives

Spooling enables the complete seek reader but needs caller-approved storage.
Buffering payloads for rollback violates the streaming contract.

## Consequences

Late trailers can invalidate already delivered data.
Transactional extraction uses the existing plan/apply path.
Central-only attributes remain available from seek input.
Reconsider unsupported descriptor forms only with an independent boundary or explicit spool policy.

## Confirmation

[ZIP stream tests](../../libarchive_oxide/tests/zip_stream_read.rs), encryption tests, and codec interoperability tests cover chunking, descriptors, authentication, truncation, and limits.
