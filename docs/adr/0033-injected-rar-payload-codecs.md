# Inject typed `RAR` payload codecs

## Status

Proposed

Date: 2026-08-16

## Context

`RAR` framing and payload algorithms have different responsibilities and provenance boundaries.

## Decision

Let core request payload decoders through associated types without importing concrete algorithms.
Compose concrete `RAR` codecs in the flagship and transfer owned state for solid continuation.
Preflight dictionaries, blocks, model heaps, queues, and output before allocation.
Verify exact extents and plaintext checksums in the container.

## Alternatives

Direct codec imports invert the layer graph.
Runtime trait objects conceal concrete state and duplicate the static extension mechanism.

## Consequences

Some legacy paths buffer whole members within explicit limits.
Unsupported generations and writing remain unavailable.
Reconsider a method only with independently reviewed provenance and resource equations.

## Confirmation

`just architecture`, [`RAR` tests](../../libarchive_oxide/tests/rar5.rs), legacy tests, and volume tests check layer boundaries, continuation, checksums, and limits.
Vendor provenance files identify adopted source.
