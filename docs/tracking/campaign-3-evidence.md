# Campaign 3 completion evidence

This snapshot records the technical evidence for the interoperability-evidence
slices of RM-300, beginning with RM-301: a reusable interoperability-evidence
harness that later format slices (ZIP, 7z, tar, cpio, ar, ISO, CAB, XAR) all sit
on, plus a producer-corpus provenance policy. RM-301 adds no new archive method
and no `src/` runtime change; it proves the machinery on already-supported
formats by reading each independent producer's output back through arca and
requiring identical normalized shapes and contents, and by handing arca's own
writer output to independent consumers that must reconstruct the same content.
The harness carries heterogeneous producers and consumers as bare `fn` pointers
inside concrete non-generic case structs, so RM-302/303/304 add cases by writing
a free function and a `&[]` array without editing the harness. RM-301 is based on
its working tree. The parent epic closes only after every slice has passed its
required remote checks and reached `main`.

No tag, package publication, GitHub Release, release-workflow execution, version
change, or versioned release candidate is part of this snapshot.

## Implementation map

| Work | Unit | Source | Evidence |
|---|---|---|---|
| Reusable interop-evidence harness | RM-301 | `libarchive_oxide/tests/common/mod.rs` | `EntryShape`, `LogicalEntry`, `CompressionMethod`, `ProducerCase`, `ConsumerCase`, `read_with_arca`, `assert_producers_agree`, `assert_consumers_accept`, `zip_crate_decode`, `sevenz_rust2_decode` |
| Demo/self-test binary proving the machinery | RM-301 | `libarchive_oxide/tests/interop_foundation.rs` | ZIP Store/Deflate and 7z LZMA2 interop tests over the shared harness |
| Interop-evidence design decision | RM-301 | `docs/adr/0011-interop-evidence-and-fixture-provenance.md` | static-dispatch `fn`-pointer case model, content-only `EntryShape` equality, dir-slash normalization, deterministic in-code producer corpus |
| Support-matrix encryption/metadata column split | RM-301 | `docs/support-matrix.md` | Archive-containers table gains an explicit `Encryption` column separated from `Metadata/method notes` |
| Producer-corpus provenance registries | RM-301 | `libarchive_oxide/tests/fixtures/zip/PROVENANCE.md`, `libarchive_oxide/tests/fixtures/sevenz/PROVENANCE.md` | per-format `crate@version` producer/consumer registry and deterministic in-code generation policy |
| This evidence snapshot | RM-301 | `docs/tracking/campaign-3-evidence.md` | RM-301 harness scope, formats proven, and reproduced gates |
| ZIP BZip2 (method 12) read | RM-302 | `libarchive_oxide/src/seek_stream.rs`, `libarchive_oxide/src/zip.rs` | `ZipBody::Bzip2` low-level `bzip2::Decompress` streaming arm mirroring Deflate; CRC-32, size, bomb, and truncation guards; feature-off fall-through to the structured `Unsupported` error |
| ZIP BZip2 (method 12) write | RM-302 | `libarchive_oxide/src/zip_stream.rs`, `libarchive_oxide/src/provider.rs` | `StreamZipMethod::Bzip2` + `bzip2::Compress` Run/Finish encoder mirroring Deflate; `ZipMethod::Bzip2` public variant flows through `provider.rs`; version-needed 46 in local and central headers |
| ZIP BZip2 3x2 interop + adversarial evidence | RM-302 | `libarchive_oxide/tests/interop_zip_bzip2.rs`, `libarchive_oxide/tests/seek_stream_v2.rs` | three producers (arca, `zip@8.6.0`, first-party raw `.bz2` builder) × two consumers (arca, `zip@8.6.0`); round-trip loop plus truncation, bomb, and feature-off Unsupported tests |
| Support-matrix ZIP BZip2 update | RM-302 | `docs/support-matrix.md` | ZIP row lists Store/Deflate/BZip2; the not-yet-implemented note drops BZip2 |
| ZIP Zstandard (method 93) read | RM-302 | `libarchive_oxide/src/seek_stream.rs`, `libarchive_oxide/src/zip.rs` | `ZipBody::Zstd` drives the shared `PipelineCodec` (portable `ruzstd` / native `compression-codecs`) behind one static-dispatch enum — no new trait object; CRC-32, size, bomb (`Limits::decoded_total`), and truncation guards; gated on `zstd`, present on BOTH profiles |
| ZIP Zstandard (method 93) write | RM-302 | `libarchive_oxide/src/zip_stream.rs`, `libarchive_oxide/src/provider.rs` | `StreamZipMethod::Zstd` + streaming `compression_codecs::ZstdEncoder` (pinned level 3) gated on `native-codecs`; version-needed 63 in local and central headers; on the portable profile the two `provider.rs` dispatch sites route to a deferred structured `Unsupported` error surfaced at entry-open |
| ZIP Zstandard interop + adversarial evidence | RM-302 | `libarchive_oxide/tests/interop_zip_zstd.rs`, `libarchive_oxide/tests/seek_stream_v2.rs` | READ proven on both profiles by two external producers (`zip@8.6.0`, first-party raw-zstd builder over independent-C `zstd` 0.13.3) × two consumers (arca, `zip@8.6.0`); WRITE + a third producer (arca) proven on native-codecs, decoded by both the `zip` crate and independent-C libzstd; truncation, bomb, portable-write-Unsupported, and feature-off Unsupported adversarial tests |
| Support-matrix ZIP Zstandard update | RM-302 | `docs/support-matrix.md` | ZIP row splits Read (adds Zstandard) from Write (Zstandard native-codecs only); the not-yet-implemented note drops Zstandard and records the write profile-asymmetry |
| ZIP LZMA (method 14) read | RM-302 | `libarchive_oxide/src/seek_stream.rs`, `libarchive_oxide/src/zip.rs` | `ZipBody::Lzma` parses the 9-byte ZIP-LZMA header (prop_size==5, props byte, dict size), validates the dict against `codec_memory`, buffers the raw LZMA1 member, and drives a pull-based `lzma_rust2::LzmaReader` with the central-directory uncompressed size (handles both EOS-marker and known-size conventions); CRC-32, size, bomb (`Limits::decoded_total`), truncation, and bad-header guards; gated on `xz`, present on BOTH profiles |
| ZIP LZMA (method 14) write | RM-302 | `libarchive_oxide/src/zip_stream.rs`, `libarchive_oxide/src/provider.rs` | `StreamZipMethod::Lzma` + `lzma_rust2::LzmaWriter::new_no_header` (raw LZMA1, EOS marker) drained through an in-crate `VecSink` (no trait object, `#![forbid(unsafe_code)]` intact); pinned preset 6 (props 93, 8 MiB dict); emits the 9-byte ZIP-LZMA header once at entry start; general-purpose bit 1 (`0x0002`) set in local+central flags outside the `0x0809` cross-check mask; version-needed 63 |
| ZIP LZMA interop + adversarial evidence | RM-302 | `libarchive_oxide/tests/interop_zip_lzma.rs`, `libarchive_oxide/tests/seek_stream_v2.rs`, `libarchive_oxide/tests/fixtures/zip/python-lzma/` | three producers (arca + first-party raw-LZMA1 builder, both `lzma-rust2`; + committed CPython 3.14.6/liblzma fixture, independent codec) × two consumers (arca, `zip@8.6.0` with `lzma`); WRITE evidence = the `zip` crate decodes arca's method-14 output byte-identically; round-trip, empty-member, truncation, bad-property-size, bomb, and feature-off Unsupported tests; the committed fixture + `generate.py` are byte-reproducible (SHA-256 recorded in `PROVENANCE.md`) |
| Support-matrix + PROVENANCE ZIP LZMA update | RM-302 | `docs/support-matrix.md`, `libarchive_oxide/tests/fixtures/zip/PROVENANCE.md` | ZIP row adds LZMA to Read and Write; the not-yet-implemented note now lists ONLY Deflate64; PROVENANCE records the committed-fixture escape hatch and the two-independent-codecs honesty note |
| CAB read-only provider | RM-305 | `libarchive_oxide/src/cab.rs`, `libarchive_oxide-core/src/format.rs`, `libarchive_oxide/src/provider.rs`, `libarchive_oxide/src/seek_stream.rs` | `CabSeekReader`: MSCF header, CFFOLDER/CFFILE/CFDATA tables, Store + MSZIP (the 32 KiB LZ window is carried across a folder's `CFDATA` blocks via a miniz_oxide wrapping ring); QUANTUM/LZX/cross-cabinet/spanning are structured `Unsupported`; registered as a read-only seek-native provider (`FormatId::Cab`, capability decode-only) |
| XAR read-only provider | RM-305 | `libarchive_oxide/src/xar.rs`, `.../format.rs`, `.../provider.rs`, `.../seek_stream.rs` | `XarSeekReader`: big-endian header, zlib TOC bounded by `metadata_bytes`, a hand-rolled bounded XML pull-scanner over the `<file>` tree, stored + zlib (`x-gzip`) heap data; `x-bzip2`/unknown encodings are structured `Unsupported`; `FormatId::Xar`, decode-only |
| CAB/XAR interop + adversarial evidence | RM-305 | `libarchive_oxide/tests/interop_cab_meta.rs`, `libarchive_oxide/tests/interop_xar_meta.rs`, `libarchive_oxide/tests/fixtures/{cab,xar}/PROVENANCE.md` | first-party in-code raw builders (independent DEFLATE/zlib via `flat2`) read back through the RM-301 harness; multi-file/nested/empty round trips plus unsupported-method and truncated-header structured-error negatives; a three-lens adversarial review with a verification pass |
| Support-matrix CAB/XAR read-only rows | RM-305 | `docs/support-matrix.md` | CAB and XAR added to the archive-containers table as read-only seek providers; removed from the not-implemented list (RAR5/UDF remain, tracked by RM-306) |

## RM-301

- ADR-0011 specifies the interoperability-evidence harness: a normalized
  `EntryShape` capturing the raw path bytes, kind, full uncompressed content, and
  (where a source exposes it) compression method, so shapes from different
  producers compare for equality of content rather than merely count. Equality is
  a field-subset projection over `(path, kind, content)`; the optional method and
  the derived size are excluded, so a Store producer and a Deflate producer of the
  same logical entry set still compare equal. The sole constructor `EntryShape::new`
  centralizes dir-slash normalization (one trailing `b'/'` stripped when the kind
  is a directory), so arca's directory path `b"sub"` and a spec-conformant raw
  `b"sub/"` read back as the same canonical shape. Paths are `Vec<u8>`/`&[u8]`
  end to end; `String` never appears, so non-UTF-8 names survive losslessly.
- `read_with_arca` reads any arca-readable bytes through `SeekArchiveReader`,
  accumulating every `Data` chunk into the shape's content so equality checks are
  real, never count-only; its `ReaderEvent` match handles the entry, data,
  metadata, and end variants and returns on `Done`, with a wildcard arm guarding
  the `#[non_exhaustive]` enum's future variants.
  `assert_producers_agree` feeds the same logical entry set to each producer and
  requires every read-back to equal the canonical shapes derived from that set
  (the single source of truth), so a bug shared by all producers cannot pass —
  this is the "≥3 producers can be read" evidence, applied repeatedly.
  `assert_consumers_accept` hands arca's writer output to each independent consumer
  and requires each to reconstruct the same content — the "≥2 consumers accept"
  evidence. Both take arbitrary N and M as slices, so RM-302/303/304 pass their
  own producer/consumer arrays unchanged.
- The demo binary proves the machinery on already-supported formats. ZIP Store and
  ZIP Deflate are each proven with three independent producers (arca's ZIP writer,
  the `zip` crate's `ZipWriter`, and a first-party hand-built raw-ZIP builder) and
  two independent consumers (arca via `read_with_arca` and the `zip` crate via
  `zip_crate_decode`), with method evidence asserted through `assert_method` where
  the ZIP consumer exposes `.compression()`. The entry set exercises a file, a
  directory, and a file in a subdirectory to hit the dir-slash normalization path.
  Under the `sevenz` feature, 7z LZMA2 is proven with two producers (arca's
  `SeekArchiveWriter` and `sevenz-rust2`) and two consumers (arca and
  `sevenz-rust2` via `sevenz_rust2_decode`).
- Provenance is deterministic in-code generation from the pinned
  `[dev-dependencies]`: no binaries are committed for ZIP or 7z this slice, every
  producer and consumer records its identity as `crate@version` taken verbatim
  from the Cargo pins (`zip@8.6.0`, `sevenz-rust2@0.21.3`) and embedded in the
  case name, so any interop failure names the exact producer and version that
  disagreed. Per-format registries
  `libarchive_oxide/tests/fixtures/zip/PROVENANCE.md` and
  `libarchive_oxide/tests/fixtures/sevenz/PROVENANCE.md` record the
  producers and consumers, the generation policy, the reserved external-tool
  corpus layout, and a "how to extend" guide for RM-302/303/304. The harness adds
  no trait object, no closure, no generic parameter, and no new runtime
  dependency, and the crate keeps `#![forbid(unsafe_code)]`.

## RM-302

- RM-302 is the first slice to add a new archive method through the RM-301
  harness: ZIP BZip2 (method code 12), read and write, gated behind the `bzip2`
  feature (on by default via `portable-codecs`, and also present in
  `native-codecs`). The runtime `bzip2` crate is already an optional dependency,
  so no new runtime dependency is added; the codec works identically on the
  portable (`libbz2-rs-sys`) and native (`libbz2`) backends because only the
  backend-neutral `Decompress`/`Compress`/`Action`/`Status`/`Compression` surface
  is used.
- Read: `ZipBody::Bzip2` is a gated variant of the seek reader's body enum that
  mirrors the existing `Deflate` arm but swaps miniz `inflate` for the low-level
  `bzip2::Decompress::decompress` streaming call. Because that call returns only
  `Result<Status, Error>` (not a consumed/written pair), progress is derived from
  `total_in()`/`total_out()` deltas snapshotted around each call. A ZIP method-12
  payload is a complete standalone `.bz2` stream, so `Status::StreamEnd` drives
  finalization, at which point the produced size is checked against the central
  directory and the running CRC-32 (`crate::filter::gzip::Crc32`) is verified. The
  same per-iteration `decoded_total` + `Limits::decoded_total()` check as Deflate
  bounds a decompression bomb before the whole payload is buffered; a stalled
  decoder with no remaining input is reported as a truncated-stream `Malformed`
  error, and every `Err(_)`/`MemNeeded` maps to a structured error rather than a
  panic. `prepare_zip_body` selects the Bzip2 body only under the feature; with the
  feature off, method 12 falls through to the existing `Unsupported { method,
  end_offset }` arm, so a method-12 member still enumerates and skips and yields
  the structured "payload coder 12 is unsupported" error on read.
- Write: `StreamZipMethod::Bzip2` and the public `ZipMethod::Bzip2` variant are
  both gated, so a feature-off caller cannot even name the method (compile-time
  exclusion, no runtime panic path). The encoder mirrors the Deflate contract with
  `bzip2::Compress`: `Action::Run` per data chunk and `Action::Finish` at
  end-entry, single library call per invocation, returning `NeedOutput` on
  `FinishOk` and terminating on `StreamEnd`, with progress again derived from the
  `total_in()`/`total_out()` counters. Local and central "version needed to
  extract" fields are written as 46 for method-12 members. Both `ZipMethod ->
  StreamZipMethod` match sites in `provider.rs` are gated by the same cfg, so each
  match stays exhaustive with no wildcard on both builds.
- Evidence reuses the RM-301 harness. `tests/interop_zip_bzip2.rs` (whole-file
  gated on `bzip2`) proves method 12 with three independent producers — arca's ZIP
  writer with `ZipMethod::Bzip2`, the `zip` crate with `CompressionMethod::Bzip2`
  (its dev-dependency gains the `bzip2` feature), and a first-party raw-ZIP builder
  that stores a raw `.bz2` stream produced by the `bzip2` crate directly with
  method 12 and version-needed 46 — and two consumers (arca via `read_with_arca`
  and the `zip` crate via `zip_crate_decode`, which now maps
  `CompressionMethod::Bzip2`), asserting byte-level content equality plus the BZip2
  codec on non-empty file members. `tests/seek_stream_v2.rs` adds `ZipMethod::Bzip2`
  to the streaming round-trip loops and three adversarial tests: a truncated
  bzip2 payload yields a `Malformed` structured error, a bzip2 bomb is bounded by a
  small `Limits::decoded_total` (`Limit` error), and — under `#[cfg(not(feature =
  "bzip2"))]` — a method-12 member reports the `Unsupported` structured error while
  still enumerating. The crate keeps `#![forbid(unsafe_code)]` and adds no trait
  object (`ZipMethod`/`StreamZipMethod`/`ZipBody` remain plain enums).

### RM-302 Zstandard sub-slice (method 93) — profile-asymmetric

- The Zstandard sub-slice deliberately splits READ from WRITE by build profile.
  READ works on BOTH codec profiles and is gated on `zstd` (both `portable-codecs`
  and `native-codecs` enable it): a ZIP method-93 payload is a RAW zstd frame — the
  exact input both existing `ZstdDecoder` impls consume — so `ZipBody::Zstd` does
  not hand-drive `ruzstd`/`compression_codecs`. Instead it boxes and drives
  `crate::pipeline_codec::PipelineCodec`, the enum that already unifies the two
  profiles (portable `ruzstd::FrameDecoder`; native `ExternalDecoder<ZstdDecoder>`
  with a `window_log_max` derived from `Limits::codec_memory()`). This adds NO new
  trait object (`PipelineCodec` is an enum, `ExternalDecoder<D>` is generic), so the
  xtask no-dyn guard stays green. The read arm mirrors the Bzip2 refill/CRC/size
  loop but reads progress from `CodecStep`; `PipelineCodec::process` returns a
  structured `ArchiveError` (`.with_format("zstd")`) on truncation/corruption, and
  the same per-iteration `Limits::decoded_total()` check bounds a bomb on both
  profiles (the portable `ruzstd` decoder accepts no window cap, so the decoded-total
  check is the load-bearing defense there).
- WRITE works ONLY under `native-codecs` and is gated on `native-codecs` (NOT
  `zstd`): the portable `ruzstd` path is treated as decode-only for ZIP production.
  `StreamZipMethod::Zstd` drives a true streaming `compression_codecs::ZstdEncoder`
  at a pinned deterministic level 3 — `encode`/`finish` over `PartialBuffer`,
  mirroring the Bzip2 Run/Finish arm; small members that buffer internally and emit
  `(consumed, 0)` are tolerated as back-pressure, and the frame is terminated by the
  `finish` loop at end-entry. Local and central "version needed to extract" for
  method 93 is written as 63 (the APPNOTE 6.3.x codec-introduction version used by
  the libarchive/7-Zip/info-zip lineage; APPNOTE defines no version for zstd and the
  `zip` crate emits its generic 45 default — both are advisory and interop-safe, and
  63 ≥ 45 so the zip64 escalation is preserved).
- The public `ZipMethod::Zstd` variant is gated on `zstd`, so it is nameable on a
  portable read-only build; because `StreamZipMethod::Zstd` exists only under
  `native-codecs`, the two `provider.rs` dispatch sites map `ZipMethod::Zstd ->
  StreamZipMethod::Zstd` only when both cfgs hold, and otherwise defer a structured
  `Unsupported` error ("ZIP Zstandard write requires the native-codecs profile")
  raised at the first entry-open — a clean structured error, never a panic or a
  compile break. With the `zstd` feature off entirely, `ZipMethod::Zstd`,
  `StreamZipMethod::Zstd`, and `ZipBody::Zstd` are all cfg'd out and a method-93 read
  falls through to the existing `Unsupported { method, end_offset }` arm, staying
  enumerable (identical to the bzip2-off behavior).
- Evidence (`tests/interop_zip_zstd.rs`, whole-file gated on `zstd`) is stated with
  its profile asymmetry honestly: READ is proven on BOTH profiles by TWO independent
  external producers — the `zip` crate with `CompressionMethod::Zstd` (its
  dev-dependency gains the `zstd` feature) and a first-party raw-ZIP builder
  embedding a raw zstd frame from the independent-C `zstd` crate (dev-dep
  `zstd-codec`, package `zstd` 0.13.3) — each read back byte-identical by arca and by
  the `zip` crate, with a method-93 assertion through the `zip` consumer. WRITE plus
  a THIRD producer (arca itself) are proven ONLY under `native-codecs`: arca's
  method-93 members are decoded to identical content by both the `zip` crate and, via
  a central-directory frame extraction, the independent-C `zstd` crate. Portable runs
  therefore assert two producers, not three. `tests/seek_stream_v2.rs` adds
  `ZipMethod::Zstd` to the streaming round-trip loops only under `native-codecs`
  (round-trip needs the encoder), keeps portable read coverage via the raw-zstd
  fixture, and adds adversarial tests: a truncated zstd payload yields a `Malformed`
  structured error, a zstd bomb is bounded by a small `Limits::decoded_total`
  (`Limit` error), a portable `ZipMethod::Zstd` write is rejected with the deferred
  `Unsupported` error at entry-open, and — under `#[cfg(not(feature = "zstd"))]` — a
  method-93 member reports the `Unsupported` structured error while still
  enumerating. No new source file is created, no new runtime dependency is added
  (`ruzstd` via `zstd`, `compression-codecs` via `native-codecs`), and the crate
  keeps `#![forbid(unsafe_code)]`.

### RM-302 LZMA sub-slice (method 14) — committed-fixture + two-independent-codecs

- The LZMA sub-slice wires ZIP compression method 14, read and write, gated behind
  the `xz` feature (which enables `lzma-rust2`, already a dependency for 7z/xz).
  Unlike Zstandard there is no portable-vs-native split: `xz` is on for BOTH the
  `portable-codecs` and `native-codecs` profiles, so LZMA read+write are available
  on both, and `map_zip_method` returns `StreamZipMethod::Lzma` with no deferred
  Unsupported. With `xz` off, `ZipMethod::Lzma` does not exist (it is a
  `#[cfg(feature = "xz")]` public variant, unselectable at the type level) and a
  method-14 read falls through to the structured `Unsupported { method, end_offset }`
  arm, staying enumerable.
- Wire format (PKWARE APPNOTE 5.8): arca emits — and accepts — a 9-byte ZIP-LZMA
  header (2-byte informational SDK version `[9,20]`, `u16 LE` prop_size == 5, the
  lc/lp/pb props byte, `u32 LE` dict size) followed by a raw LZMA1 range-coded
  stream terminated by an end-of-stream marker. The writer always uses the
  EOS-marker convention (general-purpose bit 1, `0x0002`, set in both local and
  central flags, deliberately outside the `0x0809` local/central cross-check mask);
  the reader handles BOTH conventions by driving `LzmaReader::new_with_props` with
  the central-directory uncompressed size unconditionally (size-or-marker, whichever
  first), matching the `zip` crate. Pinned preset 6 gives props byte 93 (lc=3, lp=0,
  pb=2) and an 8 MiB dict, reproducing CPython/liblzma's header near byte-for-byte;
  version-needed is 63 (APPNOTE 6.3.0). The one intentional deviation from the
  bzip2/zstd chunked-input arms: `lzma-rust2` exposes only a pull-based `LzmaReader`
  that owns its source (which cannot borrow the shared archive handle), so the
  compressed member is buffered once via `take(payload_len).read_to_end` (grows with
  actual bytes — a lying `compressed_size` cannot pre-allocate) with the dict
  validated against `codec_memory` and output still bounded incrementally by
  `decoded_total`. The writer drains `LzmaWriter`'s output through an in-crate
  `VecSink(Vec<u8>)` (a `std::io::Write` newtype, not a trait object) so
  `#![forbid(unsafe_code)]` and the `no-dyn` gate both hold.
- Evidence is stated with its two-independent-codecs limit honestly: only
  `lzma-rust2` (pure-Rust) and `liblzma` (C) exist. `tests/interop_zip_lzma.rs`
  (whole-file gated on `xz`) runs a three-producer / two-consumer matrix — producers
  `arca` and a first-party raw-LZMA1 ZIP builder (both `lzma-rust2`, independent ZIP
  *container* builders) plus the committed `python-lzma/lzma-basic.zip` fixture (the
  sole INDEPENDENT-codec liblzma reference), consumers arca and `zip@8.6.0` (with its
  `lzma` feature). Because the `zip` crate cannot WRITE LZMA, WRITE evidence is the
  `zip` crate decoding arca's method-14 output to byte-identical content with a
  method-14 assertion — the strong ZIP-container + header + stream validity check.
  The committed fixture is generated deterministically by `generate.py` (committed
  alongside, SPDX header inline; SHA-256 recorded in `PROVENANCE.md` and verified
  byte-reproducible), covered by the existing `REUSE.toml` `**/tests/fixtures/**`
  override with no `.license` sidecar (same mechanism as `tests/fixtures/zstd/*.zst`);
  its `sub/empty.txt` member exercises the zero-length (EOS-only) LZMA read edge.
  `tests/seek_stream_v2.rs` adds `ZipMethod::Lzma` to both streaming round-trip
  sweeps and adversarial tests: round-trip, empty-member round-trip, a truncated
  stream (`Malformed`), a bad property-size header (`Malformed`), an LZMA bomb bounded
  by a small `Limits::decoded_total` (`Limit`), and — under
  `#[cfg(not(feature = "xz"))]` — the feature-off `Unsupported` path. No new source
  file is created, no new runtime dependency is added (`lzma-rust2` was already
  present via `xz`/`sevenz`), and the crate keeps `#![forbid(unsafe_code)]`.

## RM-307

- ADR-0012 (`docs/adr/0012-codec-capability-contract.md`) codifies the
  codec-capability contract: the engine commits to a codec *contract* and an
  honest capability model, and the core guarantees (`#![forbid(unsafe_code)]`,
  static `no-dyn` dispatch, the C-free `portable-codecs` profile, bounded
  streaming, a stable API) never bend to a codec's absence or limitation. A codec
  that cannot meet a path's contract is refused for that path and surfaced as a
  typed capability (`ProviderCapability` + `ErrorKind::Unsupported`), never a
  panic, a silent fallback, or an API-shape change.
- The ADR fixes that capability honesty is necessary but *not sufficient*: every
  read/write asymmetry or missing method is a **tracked deficit** with a declared
  resolution path (an upstream contribution, a dedicated pure-Rust crate the
  engine consumes, or the native profile), and the portable/native split is a
  pressure valve toward completeness rather than a resting state — the RM-400
  claim is not satisfied while a Tier-1 deficit is merely documented.
- The canonical worked example is portable zstd *encode*: `ruzstd` ships only a
  one-shot whole-buffer encoder (`ruzstd::encoding::compress_to_vec`, already used
  for outer-filter frames and `create --zstd`), which cannot emit a ZIP member as
  a bounded stream without buffering the whole member and breaking the memory
  guarantee, so ZIP method-93 write is `native-codecs` only — the engine refuses
  the path rather than weaken the guarantee. This and Deflate64 (method 9) are the
  entire current deficit ledger; every other mainstream codec is complete
  read+write on portable.
- `docs/support-matrix.md` is refactored to the accountability grid: the ZIP row
  points to a `method × {read,write} × {portable,native}` table where every `—` is
  a data point (a structured `Unsupported`, enumeration continues), plus a
  "Codec capability deficits" ledger linking each gap to its resolution path and
  tracking item, with the outer-filter zstd-encode note reconciled against the
  ZIP-member write deficit.
- RM-307 adds no runtime code and no dependency; it is an
  architecture-and-documentation slice establishing the contract that RM-302..306
  and future codec work inherit.

## RM-305

- CAB and XAR are arca's FIRST read-only built-in seek-native providers: every
  prior built-in format (ZIP, 7z, ISO, tar, cpio, ar) is read+write, so RM-305
  also proves the read-only registration path. Both decode through the always-on
  `miniz_oxide` codec, so they need no feature gate and stay pure-Rust / C-free on
  the portable profile.
- Registration (five points, all in the scaffold): `FormatId::Cab` / `FormatId::Xar`
  (`libarchive_oxide-core/src/format.rs`) with `MSCF` / `xar!` probe signatures;
  `format_capability` → `FormatCapabilities::new(true, false, true)` (decode yes,
  encode NO, seek yes) and `format_name` in `provider.rs`; a `SeekDispatch::Cab` /
  `SeekDispatch::Xar` arm plus signature detection in `SeekArchiveReader::open`; and
  `mod cab` / `mod xar` in `lib.rs`. Each reader implements the same
  `new`/`next_event`/`skip_entry`/`into_inner`/`source_ref` contract as the 7z
  reader and drives the identical `Idle → Entry → Data(≤64 KiB) → EndEntry → Done`
  phase machine.
- **CAB** (`cab.rs`): a bounded MSCF parser. The `CFHEADER` (with optional reserve
  and prev/next-cabinet strings), the `CFFOLDER` and `CFFILE` tables, and the
  per-folder `CFDATA` blocks are all walked within the `Limits` budget. A folder is
  a solid unit decoded one `CFDATA` block at a time — no whole folder is
  materialized. Store copies bytes through; MSZIP verifies the `CK` block magic and
  inflates each block's raw DEFLATE while carrying the folder's 32 KiB LZ77 window
  across blocks via a fresh `DecompressorOxide` over a preserved power-of-two
  wrapping ring (so a back-reference in block N resolves into block N−1's output).
  QUANTUM/LZX methods, cross-cabinet continuation files (`iFolder` sentinels), and
  spanning blocks (`cbUncomp == 0`) list their metadata then surface a structured
  `Unsupported` on the payload.
- **XAR** (`xar.rs`): the 28-byte big-endian header locates the zlib-compressed TOC
  (inflated with `DataFormat::Zlib`, capped at `min(toc_length_uncompressed,
  metadata_bytes)` and length-verified) and the heap (`heap_start = header.size +
  toc_length_compressed`, never a hard-coded 28). A hand-rolled bounded XML
  pull-scanner (an explicit DFS `<file>`-frame stack, no DOM, no XML crate) resolves
  each entry's `/`-joined path, emitting a directory before its children, bounded by
  `entries` / `path_bytes` / a nesting-depth cap. Regular files stream their heap
  blob per entry (seek-per-blob for the unordered/shared-heap model) as stored
  (`octet-stream`, `S == L` enforced) or zlib (`x-gzip`, RFC-1950 — decoded as zlib,
  NOT gzip), with the decoded length verified against `<length>`. `x-bzip2` and any
  unknown encoding are structured `Unsupported`; version ≠ 1 is `Unsupported`.
- Write is rejected without a code path of its own: the decode-only capability makes
  `format_encoder` return a typed `Capability` error, and `SeekArchiveWriter::with_format`
  falls through its default arm to `Unsupported` for `FormatId::Cab`/`Xar`.
- `#![forbid(unsafe_code)]`, the `no-dyn` gate, and bounded memory hold: both readers
  are plain generic structs over `R: Read + Seek` with concrete enums (no trait
  objects), stream payload in ≤ 64 KiB chunks, and return a structured `StreamError`
  for every malformed/truncated/unsupported/limit case (never a panic/unwrap).
- Evidence: `tests/interop_cab_meta.rs` and `tests/interop_xar_meta.rs` build valid
  archives with first-party in-code raw byte builders (independent DEFLATE/zlib via
  `flat2`, which arca re-inflates with `miniz_oxide` — codec independence), read
  them back through the RM-301 harness, and assert content round trips over
  multi-file/nested/empty corpora, plus negatives for an unsupported compression
  method and a truncated/out-of-range header. A three-lens adversarial review
  (panic/bounds, spec-correctness, malformed-input) with an independent verification
  pass was run over both modules before commit. Per-format `PROVENANCE.md` registers
  the in-code raw builder and documents the external independent producers
  (makecab/gcab/cabextract for CAB; the `xar` CLI / `bsdtar --format=xar` for XAR).

## Reproduced gates

- Working tree, Windows x86_64, portable codec profile with `--features sevenz,aes`:
  `cargo test -p libarchive_oxide --features sevenz,aes --test interop_foundation`
  passed 3/3 (`zip_store_interop`, `zip_deflate_interop`, `sevenz_lzma2_interop`).
  Without the `sevenz` feature the 7z case is `#[cfg]`-gated out and 2/2 remain.
- `cargo test -p libarchive_oxide --features sevenz,aes --test sevenz_differential`
  passed 4/4 after the differential tests were routed through the shared harness
  (test count unchanged from `main`).
- The full `cargo test -p libarchive_oxide --features sevenz,aes` suite passed
  (0 failed), including the new `interop_foundation` demo alongside the existing
  engine, codec, zip, 7z, OCI, and package suites.
- `cargo fmt --check`,
  `cargo clippy -p libarchive_oxide --tests --features sevenz,aes -- -D warnings`,
  the `no-dyn` gate (heterogeneous producers/consumers are bare `fn` pointers, not
  trait objects), and
  `RUSTDOCFLAGS="-D warnings" cargo doc -p libarchive_oxide --no-deps --features sevenz,aes`
  all pass; the crate keeps `#![forbid(unsafe_code)]` (`src/lib.rs`) with no new
  runtime dependency (`Cargo.toml` unchanged).
- RM-302 Zstandard sub-slice, Windows x86_64: the portable read profile
  (`cargo test -p libarchive_oxide --features sevenz,aes`) and the native
  read+write profile
  (`cargo test -p libarchive_oxide --no-default-features --features "native-codecs,aes,sevenz"`)
  both passed with 0 failures — `interop_zip_zstd` runs `zip_zstd_interop` on both
  profiles and additionally `zip_zstd_write_is_decoded_by_independent_libzstd_and_zip_crate`
  on native; `seek_stream_v2` gains `zip_zstd_roundtrips_through_seek_reader`,
  `zip_zstd_truncated_payload_is_structured_error`, `zip_zstd_bomb_is_bounded_by_limits`,
  the portable-only `zip_zstd_write_without_encoder_is_structured_unsupported`, and
  the feature-off `zip_method_93_is_unsupported_without_zstd_feature`. The feature-off
  build `cargo build -p libarchive_oxide --no-default-features --features "gzip,bzip2,xz,lz4,aes,sevenz"`
  compiles with method 93 degrading to the structured `Unsupported` read path, and
  `cargo clippy -p libarchive_oxide --tests` on both `portable-codecs` and
  `native-codecs` plus `cargo fmt --check` are clean.

## Out of scope for this slice

RM-301 adds no new archive method: it proves the harness on already-supported
formats (ZIP Store/Deflate and 7z LZMA2) only. Extending interop evidence to new
ZIP and 7z methods — and to the remaining formats (tar, cpio, ar, ISO, CAB, XAR)
with three producers and two consumers per method — is RM-302, RM-303, RM-304,
and their successors, each of which adds free producer/consumer functions and a
`&[]` array without editing the harness. Byte-exact external-tool artifacts,
their `tests/fixtures/<format>/<producer>/` corpus rows, and the regeneration
provenance blocks are created only when a future slice needs them. Remote checks
and reaching `main` remain required before the RM-300 epic can close.
