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
   crate keeps `#![forbid(unsafe_code)]`; dispatch stays static (no trait-object
   registry, the `no-dyn` gate); the `portable-codecs` profile stays C/FFI-free
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

| Deficit | Where it shows | Why | Resolution path | Tracking |
|---|---|---|---|---|
| Portable **streaming** zstd **encode** | ZIP member write method 93 is `native-codecs`-only; portable selection returns a structured `Unsupported` error | `ruzstd` (pinned `0.8.3`, latest as of the RM-309 survey below) offers only `ruzstd::encoding::compress_to_vec` (one-shot, whole output collected into a `Vec`) and `FrameCompressor` (a *pull*-based `set_source(Read)` → `set_drain(Write)` driver whose single blocking `compress()` runs the source to EOF). Both serve outer-filter *frames* and `create --zstd`, where the engine owns the whole `Read`. Neither can be driven by the engine's *push*-based, synchronous ZIP-member write loop (`payload_step` feeds bounded chunks and pulls bounded output per step) without inverting control — i.e. buffering the entire member or spawning a thread — which would break the core bounded-memory guarantee. The `native-codecs` `compression-codecs` encoder is a true push-streaming encoder. | A push-drivable (incremental feed/flush), single-stream, spec-robust pure-Rust zstd encoder — contributed upstream to `ruzstd` or provided as a dedicated crate the engine consumes behind the codec-provider boundary. The engine core does not absorb the encoder. Adoption seam when one lands: open the portable arm of `map_zip_method` (`src/provider.rs`, currently returns the deferred `Unsupported` message for `ZipMethod::Zstd` on `not(native-codecs)`) and add a portable `zstd_step`/finalize path in `src/zip_stream.rs` mirroring the existing `native-codecs` method-93 steps; interop evidence = round-trip against libzstd/`unzip` per ADR-0011 before flipping the support-matrix cell. | RM-307 (this ADR), RM-309 / DEV-123 (survey re-affirmed) → follow-on codec initiative |
| Deflate64 read and write | ZIP method 9 returns a structured `Unsupported` error and still enumerates | No pure-Rust Deflate64 encoder exists; decoders are scarce and the write direction has effectively no consumer demand. | Feasibility decision (own pure-Rust decoder for read-only, external decoder, or leave unsupported); no encoder is planned. | RM-306 feasibility ADR |
| 7z **PPMd** decode (method `03 04 01`) | A 7z folder coded with PPMd lists normally; extraction returns a structured `Unsupported` error and enumeration continues | 7z's PPMd7 (variant H) has no wired bounded-memory pure-Rust decoder, and the engine core will not absorb the model. This is a *new decoder deferred*, not a bent guarantee — the coder graph parses, the capability is typed. | Adopt or contribute a pure-Rust PPMd7 decoder consumed behind the codec-provider boundary; read-only, no encoder planned. | RM-303 → follow-on codec initiative |
| 7z **BCJ2** decode (method `03 03 01 1B`) | A 7z coder graph containing BCJ2 lists normally; extraction returns a structured `Unsupported` error and enumeration continues | BCJ2 is a four-input, multi-stream branch converter that does not fit the one-active-linear-folder decode model that keeps 7z decoding bounded. This is a *multi-stream decode deferred* — the graph resolver already validates its bind pairs; only the decode stage is absent. | Extend the folder decoder with a bounded four-stream BCJ2 junction stage; read-only, no encoder planned. | RM-303 → follow-on decoder slice |

Every mainstream compression codec used by the engine (deflate, bzip2, xz/LZMA,
lz4) has complete pure-Rust read **and** write on the `portable-codecs` profile.
The two 7z-only entries (PPMd, BCJ2) are read-only-deferred coders behind an
already-typed capability, not bent guarantees; this table is the entire ledger,
not a pervasive condition.

### RM-309 portable zstd-encoder survey (2026-07-24, re-affirms the deficit)

RM-309 / DEV-123 re-surveyed the pure-Rust zstd-encoder landscape to test whether
the "Portable streaming zstd encode" deficit can now be closed. Verdict: **no
suitable crate exists yet; the deficit stands and the `native-codecs`-only
method-93 write remains a legitimate tracked interim.** No `src/` change and no
support-matrix flip in this pass.

- **`ruzstd` `0.8.3`** (pinned in `Cargo.lock`; latest release, published
  2026-07-12) exposes in `ruzstd::encoding`: `compress` / `compress_to_vec`
  (one-shot) and `FrameCompressor` (`new`, `set_source(R: Read)`,
  `set_drain(W: Write)`, `compress()`, take/replace accessors). `FrameCompressor`
  is *pull*-based — one blocking `compress()` reads the source to EOF — so it fits
  cases where the engine owns the whole `Read` (outer-filter frames, `create
  --zstd`) but **cannot** be driven by the ZIP-member writer's *push* loop without
  buffering the whole member or spawning a thread. Neither is permitted by the
  bounded-memory / no-dyn / sync core invariants. There is **no** `StreamingEncoder`
  or incremental feed/flush API in `0.8.3`. (A `StreamingEncoder` name appears in
  some upstream prose but is not in the published `0.8.3` API surface; if a future
  release ships a genuine push-drivable encoder, it becomes the adoption vehicle.)
- **`structured-zstd`** (a `ruzstd` fork adding dictionary support) inherits the
  same `FrameCompressor` architecture with no push-streaming encoder, and adopting
  a fork carries a supply-chain/maintenance cost; not suitable.
- **`zstd` / `zstd-safe`** wrap the C `zstd-sys` library — disqualified from the
  `portable-codecs` (C/FFI-free) profile by construction; they are effectively the
  `native-codecs` path already in use.

Resolution path is unchanged and re-affirmed: adopt a push-drivable pure-Rust zstd
encoder (upstream `ruzstd` contribution or a dedicated crate) behind the
codec-provider boundary, then open the seam noted in the ledger row. Until then the
portable ZIP method-93 write stays typed `Unsupported`, per Decision items 2 and 4.

## Consequences

The engine's guarantees — no `unsafe`, static dispatch, C-free portable profile,
bounded streaming, stable API — are now explicitly *load-bearing invariants* that
a codec's state can never override; a codec either meets a path's contract or is
typed as unsupported for it. The support matrix becomes a grid where the two
current deficits are visible data points with named paths, not warts and not
silent read-only settling. Because a relegation to `native-codecs` is defined as
a tracked debt with a path back to portable parity, "portable can't write zstd
yet" is a liability the roadmap owns, not an excuse the library rests on — which
is precisely the distinction between an incomplete-but-honest wrapper and a
Modern Replacement that is closing on completeness. New codecs and methods inherit
this contract: land the capability honestly, express any gap as a typed
capability, and record the deficit with its resolution path rather than letting
the ecosystem's current shape define the engine's.
