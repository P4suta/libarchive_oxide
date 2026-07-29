# ADR-0012: Codec-capability contract and the completeness-deficit model

- Status: accepted
- Date: 2026-07-23
- Tracks: RM-307 (informs RM-300 method depth, RM-306 feasibility, RM-400 gate)

## Context

libarchive_oxide is a safe archive *engine*: container formats, bounded
streaming inspection, a session-bound plan/apply model, digest verification, a
capability-reporting filesystem contract, and package/OCI profiles built on top.
Compression *codecs* (deflate, bzip2, zstd, xz/LZMA, lz4, …) are a different
concern — they are algorithms the engine composes, not archive logic — and the
pure-Rust codec ecosystem is uneven. Most mainstream codecs have complete
pure-Rust read and write (deflate via `miniz_oxide`, bzip2 via `libbz2-rs-sys`,
xz/LZMA via `lzma-rust2`, lz4 via `lz4_flex`). Two gaps remain: a pure-Rust
*streaming, bounded-memory* zstd **encoder**, and Deflate64 in either direction.

This unevenness creates a standing temptation to let the ecosystem's state leak
into the engine — to weaken a core guarantee so a limited codec "fits" (buffer a
whole member because the only pure encoder is one-shot), to change an API shape
around a missing codec, or to silently fall back. The opposite failure is just
as corrosive: to treat "we documented it as read-only" as a resting state, so
the library slowly becomes an honest wrapper over whatever the ecosystem happens
to provide. Neither is acceptable. A Modern Replacement's purity and usability
must not be a hostage to library availability, **and** honest disclosure of a
gap must not be mistaken for discharging the obligation to close it.

## Decision

1. **The engine commits to a codec *contract*, not to codec *completeness*.**
   Codecs live behind the compile-time provider boundary (`CodecProvider`,
   `PipelineCodec`, the `portable-codecs` / `native-codecs` profiles). The engine
   depends on the *interface* and its bounded-progress contract, never on any
   particular codec being present or complete. Codec completeness is an ecosystem
   responsibility; the engine's job is to compose whatever satisfies the contract
   and to report precisely what it has.

2. **Core invariants are codec-independent and never bend to a codec.** The
   crate keeps `#![forbid(unsafe_code)]`; provider dispatch uses the bounded,
   application-owned registry from ADR-0015; the `portable-codecs` profile stays C/FFI-free
   by dependency-graph proof (RM-400); reads and writes stay bounded in memory
   regardless of payload size; and the public API shape is fixed independent of
   which codecs a build enables. A codec that cannot meet a core guarantee is
   **refused for that path**, not accommodated by weakening the guarantee. The
   canonical case: a one-shot whole-buffer encoder cannot produce a ZIP member
   within the bounded-streaming write contract, so that write path is refused on
   the profile that only has the one-shot encoder — the engine does not quietly
   buffer the whole member to make it "work".

3. **Absence and limitation are typed capabilities, never surprises.** A codec
   that is missing, disabled, or unequal to a path is surfaced through the
   capability query (`ProviderCapability`: available / disabled / unknown) and a
   structured `ErrorKind::Unsupported` at the point of use. It is never a panic,
   never a silent fallback to a different behavior, and never a change in API
   shape. Enumeration and inspection continue across an unsupported member.

4. **Capability honesty is necessary but not sufficient.** Every read/write
   asymmetry and every missing method or codec is a **tracked deficit**, not a
   settled fact. A deficit carries a declared *resolution path* — an upstream
   contribution to the codec crate, a dedicated pure-Rust codec crate the engine
   then merely consumes, or the `native-codecs` profile — and a tracking
   reference. Documenting a gap opens a debt; it does not pay it. The
   portable/native split is a **pressure valve toward completeness, not a
   destination**: relegating a capability to `native-codecs` is a temporary state
   with a path back to portable parity, not a place to leave it. The Modern
   Replacement claim (RM-400) is *not* satisfied while a Tier-1 codec deficit is
   merely documented rather than closed.

5. **The support matrix is the accountability surface.** Capability is presented
   as a legible grid — format × method × direction (read/write) × profile
   (portable/native), with encryption and metadata as their own axes — so every
   "no" is a single data point rather than prose buried in a cell, and every
   deficit links to its resolution path and tracking item. Asymmetry is made
   *systematic and visible*, which is what keeps it from quietly becoming the
   norm.

### Current tracked deficits

There is no open Tier-1 codec deficit in this campaign. Permanent writer
exclusions (RAR, UDF, Deflate64, and Quantum) are product-scope decisions, not
partially exposed runtime capabilities.

Every mainstream compression codec used by the engine (deflate, bzip2, zstd,
xz/LZMA, lz4) has complete pure-Rust read **and** write on the
`portable-codecs` profile.
Deflate64 read is complete on both profiles; ADR-0013 classifies its unavailable
write direction as a permanent won't-do rather than an open codec deficit.
The 7z and CAB read-method ledgers no longer have deferred decoders.

CAB LZX method 3 was resolved on 2026-07-29. ADR-0018 records why a
chunk-framed audited `lzxd` fork replaced the originally proposed `compcol`
adapter after independent makecab evidence exposed missing CFDATA word
realignment.

CAB Quantum method 2 was resolved on 2026-07-29. ADR-0019 records the bounded
folder-state adapter over `compcol` 0.6.8, the independent 16-CFDATA libmspack
fixture, and the workspace-wide Rust 1.88 MSRV required by the upstream safety
fix.

The legacy Unix `compress(1)` filter now has a bounded portable read path over
`compcol` LZW, including sync/async public archive readers, resource limits,
independent `compress` and bsdtar fixtures, and fuzz replay. Its writer remains
an explicit non-Tier-1 completeness debt and is absent from creation APIs; the
typed capability ledger advertises read only.

### 7z BCJ2 resolution (2026-07-28)

BCJ2 read is closed with a bounded four-input junction over
`lzma-rust2::filter::bcj2::Bcj2Reader`. Each packed input is an independently
positioned extent over one shared seekable archive source, so suspending among
main/call/jump/range-control streams does not spool any complete stream or
folder. Supported single-input coders can feed each branch and an optional
linear tail.

The parser requires the exact four-input/one-output shape and rejects BCJ2
properties. Before constructing the graph, it sums the junction's four 256 KiB
windows with every live branch/tail dictionary or workspace and applies
`Limits::codec_memory`; decoded-size and CRC gates remain in the common folder
path. Interoperability uses `compcol` 0.6.8 as an independent stream splitter
and oracle, `sevenz-rust2` 0.21.3 as an independent 7z graph consumer, and
arca under seven-byte short reads. Corrupt range-control and undersized-memory
tests plus a committed `read_7z` seed cover the principal failure paths. BCJ2
writing is intentionally absent.

### 7z PPMd7 resolution (2026-07-28)

The PPMd deficit is closed by a thin streaming adapter over `ppmd-rust` 1.4.0.
The container parser validates the five PPMd7 properties (model order plus
little-endian model memory) before construction, and `Limits::codec_memory`
rejects an oversized model before allocation.

7z PPMd7 streams normally omit an end marker. The decoder stage is therefore
bounded structurally by the folder's declared output size; it never probes for
another decoded symbol after that boundary. Existing folder-size and CRC checks
still reject early EOF and corrupt output. An independent `sevenz-rust2`
producer and consumer cover interoperability, while malformed range
initialization, property limits, model-memory limits, and the committed
`read_7z` fuzz seed cover the failure surface. PPMd writing remains
intentionally absent from the public writer API.

### Portable ZIP Zstandard resolution (2026-07-28)

The earlier survey correctly found that `ruzstd` 0.8.3 exposes a pull-to-EOF
`FrameCompressor`, not a suspendable push encoder. The deficit is now closed
without whole-entry buffering or a worker thread: the portable ZIP writer emits
a single standards-compliant Zstandard frame made of raw blocks.

- The state machine retains at most one 1 KiB block, advertises the matching
  minimum Zstandard window, and rejects a `codec_memory` budget smaller than
  its fixed one-block state before entry bytes reach the destination.
- Native builds retain the level-3 `compression-codecs` encoder. When both
  profiles are compiled, `BackendPreference::{Portable, Native}` selects either
  implementation at runtime.
- Portable output is decoded independently by `zip` and libzstd. Tests cover
  multi-megabyte chunked input, empty files, codec-memory failure, both runtime
  backends, corruption/truncation, and decoded-output limits.

## Consequences

The engine's guarantees — no `unsafe`, static dispatch, C-free portable profile,
bounded streaming, stable API — are now explicitly *load-bearing invariants* that
a codec's state can never override; a codec either meets a path's contract or is
typed as unsupported for it. The support matrix becomes a grid where the
remaining deficits are visible data points with named paths, not warts and not
silent read-only settling. Closing portable ZIP Zstandard with bounded raw
blocks demonstrates the rule: wire-format validity, memory bounds, runtime
backend choice, and independent interoperability matter more than depending on
a nominal encoder API. New codecs and methods inherit this contract: land the
capability honestly, express any gap as a typed capability, and record the
deficit with its resolution path rather than letting the ecosystem's current
shape define the engine's.
