# Isolate bounded `LHA` LH3 decoding

## Status

Proposed

Date: 2026-08-16

## Context

LH3 has no payload terminator independent of declared member sizes.
Framing and payload decoding need separate limits.

## Decision

Keep raw LH3 state in the codec crate and `LHA` metadata, extents, and CRC16 in the flagship.
Preflight complete buffers, an 8 KiB history, and tree workspace.
Use a private concrete enum for buffered LH2 and LH3 decoders.

## Alternatives

Putting the algorithm in the container couples responsibilities.
A resumable codec would reduce buffering but requires independent state-machine work.

## Consequences

The first-party specification vector covers a literal and overlapping match.
It isn't independent producer evidence.
Writing remains unavailable.
Reconsider buffering or compatibility claims when a real producer corpus is available.

## Confirmation

[`LHA` tests](../../libarchive_oxide/tests/interop_lha.rs) and codec tests cover chunking, invalid trees, limits, exact size, CRC16, and skipped entries.
