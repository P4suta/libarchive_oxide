# Bounded compressed `XAR` writing

## Status

Proposed

Date: 2026-08-14

## Context

`XAR` places its compressed table before an offset-addressed heap.
A writer needs final payload sizes before publishing the header.

## Decision

Keep Store as the default and add typed zlib and feature-gated BZip2 choices.
Compress each member into the bounded spill spool.
Charge codec workspace and framing expansion before allocation.

## Alternatives

Buffering the heap in memory violates large-archive bounds.
Keeping Store alone avoids codec work but leaves existing read capabilities without corresponding creation options.

## Consequences

Writing remains seek-based and may use temporary storage.
Unavailable codecs fail before output.
Reconsider sequential output only with an explicit framing or spooling contract.

## Confirmation

[`XAR` writer tests](../../libarchive_oxide/tests/xar_write.rs) cover round trips, codec availability, size limits, and CLI options.
