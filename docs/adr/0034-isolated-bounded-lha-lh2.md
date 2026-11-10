# Isolate bounded `LHA` LH2 decoding

## Status

Proposed

Date: 2026-08-16

## Context

The existing `LHA` container parser lacks the uncommon LH2 payload method.
The adopted decoder buffers complete input and output.

## Decision

Put read-only LH2 decoding below the container layer.
Keep headers, metadata, extents, and CRC16 in the `LHA` adapter.
Charge complete buffers, caller windows, dictionary, and tree workspace before allocation.

## Alternatives

Adding the algorithm inside the container couples framing and compression.
Leaving LH2 unsupported avoids buffering but loses compatibility.

## Consequences

The decoder bounds memory but buffers complete members.
The first-party compcol fixture doesn't prove independent producer interoperability.
Reconsider the codec when a resumable implementation or independently produced fixture becomes available.

## Confirmation

[`LHA` integration tests](../../libarchive_oxide/tests/interop_lha.rs) cover exact sizes, limits, checksums, truncation, and skip behavior.
Fixture provenance records the producer.
