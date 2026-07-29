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
| ZIP Zstandard (method 93) write | RM-302 + follow-on | `libarchive_oxide/src/zip_stream.rs`, `libarchive_oxide/src/provider.rs` | portable push state emits one bounded raw-block Zstandard frame with a 1 KiB window; native uses `compression_codecs::ZstdEncoder` level 3; runtime `BackendPreference` selects either when both are compiled; version-needed 63 in local and central headers |
| ZIP Zstandard interop + adversarial evidence | RM-302 + follow-on | `libarchive_oxide/tests/interop_zip_zstd.rs`, `libarchive_oxide/tests/seek_stream_v2.rs` | READ proven on both profiles by two external producers (`zip@8.6.0`, first-party raw-zstd builder over independent-C `zstd` 0.13.3) × two consumers (arca, `zip@8.6.0`); WRITE proven on portable and native and decoded by both the `zip` crate and independent-C libzstd; multi-megabyte bounded streaming, runtime-backend coexistence, codec-memory, truncation, bomb, and feature-off Unsupported tests |
| Support-matrix ZIP Zstandard update | RM-302 + follow-on | `docs/support-matrix.md` | canonical ledger reports method 93 read/write on portable and native; generated support matrix has no Zstandard deficit |
| ZIP LZMA (method 14) read | RM-302 | `libarchive_oxide/src/seek_stream.rs`, `libarchive_oxide/src/zip.rs` | `ZipBody::Lzma` parses the 9-byte ZIP-LZMA header (prop_size==5, props byte, dict size), validates the dict against `codec_memory`, buffers the raw LZMA1 member, and drives a pull-based `lzma_rust2::LzmaReader` with the central-directory uncompressed size (handles both EOS-marker and known-size conventions); CRC-32, size, bomb (`Limits::decoded_total`), truncation, and bad-header guards; gated on `xz`, present on BOTH profiles |
| ZIP LZMA (method 14) write | RM-302 | `libarchive_oxide/src/zip_stream.rs`, `libarchive_oxide/src/provider.rs` | `StreamZipMethod::Lzma` + `lzma_rust2::LzmaWriter::new_no_header` (raw LZMA1, EOS marker) drained through an in-crate `VecSink` (no trait object, `#![forbid(unsafe_code)]` intact); pinned preset 6 (props 93, 8 MiB dict); emits the 9-byte ZIP-LZMA header once at entry start; general-purpose bit 1 (`0x0002`) set in local+central flags outside the `0x0809` cross-check mask; version-needed 63 |
| ZIP LZMA interop + adversarial evidence | RM-302 | `libarchive_oxide/tests/interop_zip_lzma.rs`, `libarchive_oxide/tests/seek_stream_v2.rs`, `libarchive_oxide/tests/fixtures/zip/python-lzma/` | three producers (arca + first-party raw-LZMA1 builder, both `lzma-rust2`; + committed CPython 3.14.6/liblzma fixture, independent codec) × two consumers (arca, `zip@8.6.0` with `lzma`); WRITE evidence = the `zip` crate decodes arca's method-14 output byte-identically; round-trip, empty-member, truncation, bad-property-size, bomb, and feature-off Unsupported tests; the committed fixture + `generate.py` are byte-reproducible (SHA-256 recorded in `PROVENANCE.md`) |
| Support-matrix + PROVENANCE ZIP LZMA update | RM-302 | `docs/support-matrix.md`, `libarchive_oxide/tests/fixtures/zip/PROVENANCE.md` | ZIP row adds LZMA to Read and Write; the not-yet-implemented note now lists ONLY Deflate64; PROVENANCE records the committed-fixture escape hatch and the two-independent-codecs honesty note |
| CAB read-only provider | RM-305 + LZX/Quantum/volume follow-ons | `libarchive_oxide/src/cab.rs`, `libarchive_oxide/src/cab/volume.rs`, `libarchive_oxide-codecs/src/lzx/`, `libarchive_oxide-core/src/capability.rs`, `docs/adr/0018-cab-lzx-frame-boundaries.md`, `docs/adr/0019-cab-quantum-compcol.md`, `docs/adr/0021-cab-volume-set.md` | `CabSeekReader`: bounded MSCF tables and streamed Store/MSZIP/Quantum/LZX folders; aggregate folder/file metadata accounting, fallible attacker-sized allocations, CFDATA checksums, sticky typed failure state, and pre-allocation codec/in-flight/decoded/scan limits. LZX keeps history across word-aligned CFDATA bitstreams and Quantum keeps its dictionary/models across injected alignment trailers. `advanced::CabVolumeReader` and `CabVolumeProvider` validate a caller-owned `VolumeSet`, lazily concatenate physical split blocks, and preserve codec state across cabinets; the ordinary single-source reader retains structured `Unsupported` for continuation. Capabilities are read-only and additively `cab-lzx`/`cab-quantum`-gated |
| XAR read-only provider | RM-305 | `libarchive_oxide/src/xar.rs`, `.../format.rs`, `.../provider.rs`, `.../seek_stream.rs` | `XarSeekReader`: big-endian header, zlib TOC bounded by `metadata_bytes`, a hand-rolled bounded XML pull-scanner over the `<file>` tree, and streaming stored, zlib (`x-gzip`), and feature-gated bzip2 (`x-bzip2`) heap data; unknown encodings are structured `Unsupported`; `FormatId::Xar`, decode-only |
| CAB/XAR interop + adversarial evidence | RM-305 + follow-ons | `libarchive_oxide/tests/interop_cab_meta.rs`, `libarchive_oxide/tests/cab_volumes.rs`, `libarchive_oxide/tests/interop_xar_meta.rs`, `libarchive_oxide/tests/fixtures/{cab,xar}/PROVENANCE.md` | first-party Store/MSZIP builders, a Microsoft makecab two-volume fixture independently consumed by `extrac32`, and libmspack LZX/Quantum evidence; multi-frame and cross-cabinet history/alignment, missing/wrong/cyclic/duplicate/out-of-order cabinets, split-block corruption, aggregate metadata, poisoned retries, window, truncation, decoded-total/codec-memory/in-flight, and E8 regressions; XAR retains its independent bzip2 evidence |
| Support-matrix CAB/XAR read-only rows | RM-305 | `docs/support-matrix.md` | CAB and XAR added to the archive-containers table as read-only seek providers; removed from the not-implemented list (RAR5/UDF remain, tracked by RM-306) |
| RAR5/UDF/Deflate64 feasibility ADR | RM-306 | `docs/adr/0013-rar5-udf-deflate64-feasibility.md`, `docs/support-matrix.md` | Deflate64 read = go (adopt external pure-Rust `deflate64` behind the codec-provider boundary, follow-on slice) / write = won't-do; UDF read-only go (rev 1.02/1.50/2.01, follow-on); RAR5 deferred in its entirety (no clean-room pure-Rust decompressor); codec-deficit ledger + not-yet-implemented prose updated; no `src/` change, no dependency added |
| ZIP Deflate64 read implementation | RM-306 follow-on | `libarchive_oxide/src/seek_stream.rs`, `libarchive_oxide/tests/interop_zip_deflate64.rs`, `libarchive_oxide/tests/fixtures/zip/{7zip,PROVENANCE.md}`, `xtask/src/main.rs` | method 9 streams through `deflate64` 0.1.12 under `gzip` on portable/native; fixed 64 KiB chunks, CRC/size/extent/no-progress/truncation/bomb checks; official 7-Zip 26.02 fixture exercises a >32 KiB distance; write remains absent/won't-do and package-smoke compile-fail coverage locks the lack of a public `ZipMethod::Deflate64` variant |
| WinZip AES + Deflate64 read composition | RM-306 follow-on | `libarchive_oxide/src/seek_stream.rs`, `libarchive_oxide/tests/zip_aes.rs` | method 99 AE-2 metadata with real method 9 streams ciphertext through AES-CTR/HMAC and the bounded Deflate64 decoder; deterministic raw fixture covers correct/wrong password, authentication tamper, truncation, decoded bomb, and gzip-feature-off Unsupported |
| UDF Phase 1 read implementation | RM-306 follow-on | `libarchive_oxide/src/udf.rs`, `libarchive_oxide/tests/udf.rs`, `fuzz/{fuzz_targets/read_udf.rs,corpus/read_udf/seed.udf}` | read-only seek provider for 1.02/1.50/2.01: VRS/bridge priority, backup anchors, Main→Reserve/continued VDS with prevailing descriptors, Type 1 maps, FSD/root ICB, FE/EFE strategy 4, short/long/inline/chained/multi/sparse allocation, streamed FIDs, OSTA Unicode/timestamps, symlink/hardlink metadata, checked ranges and all applicable archive `Limits`; shared sync/engine/range/futures/Tokio parser and adversarial replay |
| UDF continued FSD and stream follow-on | RM-306 follow-on | `libarchive_oxide/src/udf.rs`, `libarchive_oxide/tests/udf.rs`, `libarchive_oxide/tests/fixtures/udf/PROVENANCE.md`, `fuzz/corpus/read_udf/seed.udf` | ECMA-167 Next Extent File Set Descriptor traversal with default file-set-zero/prevailing selection plus UDF 2.01 System Stream Directory and named-stream reads; safe synthetic archive paths and typed owner/kind/metadata extensions; tag checksum/CRC/location, partition bounds, FID order/version/long-ad/Unique ID, role-correct Stream/metadata flags, EFE Object Size, graph cycle/depth, and metadata/in-flight/path/entry limits are covered by deterministic positive/negative builders and stable fuzz replay |
| UDF 2.50/2.60 Metadata Partition follow-on | RM-306 follow-on | `libarchive_oxide/src/udf.rs`, `libarchive_oxide/tests/udf.rs`, `libarchive_oxide/tests/fixtures/udf/PROVENANCE.md` | Type-2 Metadata Partition Map parsing paired with its physical Type-1 map; bounded short-AD Metadata File translation across allocation-unit boundaries; shared/duplicate mirror validation with Integrity/Malformed-only fallback; optional Metadata Bitmap ICB/SBD validation; deterministic revision, missing/wrong-type, alignment, overlap, cycle, corruption, mirror, limit, seek/engine/range-provider tests |
| UDF Sparable Partition follow-on | RM-306 follow-on | `libarchive_oxide/src/udf.rs`, `libarchive_oxide/tests/udf.rs`, `libarchive_oxide/tests/fixtures/udf/{mkudffs-sparable-2.01.udf,PROVENANCE.md}`, `fuzz/corpus/read_udf/sparable-partition.udf` | UDF 1.50–2.60 Type-2 Sparable maps with profile-valid 16/32-block packets; validated packet-disjoint redundant Sparing Tables with highest-sequence agreement, corruption fallback, and the 65,535-byte descriptor-CRC cap; bounded whole-packet remapping across allocation continuations; UDF 2.50/2.60 Metadata-over-Sparable composition; deterministic malformed/range/overlap and exact capacity-based cumulative metadata-limit tests; public Seek/Engine/Range wiring; stable corpus replay; and independent `mkudffs` 2.3 interop evidence |
| Metadata-fidelity harness extension | RM-304 | `libarchive_oxide/tests/common/mod.rs` | additive `read_seq_with_arca` (sequential `ArchiveReader`), `MetaShape` (REAL kind + mode/uid/gid/mtime/link_target, no kind folding), `read_meta_seq_with_arca` / `read_meta_seek_with_arca`, `assert_producers_agree_seq`; the content-only `EntryShape` path is unchanged |
| tar producer corpus + metadata round trip | RM-304 | `libarchive_oxide/tests/interop_tar_meta.rs`, `libarchive_oxide/tests/fixtures/tar/PROVENANCE.md` | 3 producers (arca, `tar@0.4`, first-party raw ustar builder) × 2 consumers (arca sequential reader, `tar@0.4`); mode/uid/gid/mtime and symlink-target fidelity |
| cpio producer corpus + metadata round trip | RM-304 | `libarchive_oxide/tests/interop_cpio_meta.rs`, `libarchive_oxide/tests/fixtures/cpio/PROVENANCE.md` | 3 producers (arca `newc`, first-party raw `newc`, first-party raw `odc` — genuinely distinct on-disk framings) × 2 consumers (arca, first-party raw `newc` parser); mode/uid/gid/mtime plus a typed hardlink pair (File payload + Hardlink alias) |
| ar producer corpus + metadata round trip | RM-304 | `libarchive_oxide/tests/interop_ar_meta.rs`, `libarchive_oxide/tests/fixtures/ar/PROVENANCE.md` | 3 producers (arca, `ar@0.9`, first-party raw `!<arch>` builder) × 2 consumers (arca, `ar@0.9`); mode/uid/gid/mtime (ar is flat regular-files-only, so no dir/symlink fidelity) |
| ISO producer corpus + Rock Ridge metadata round trip | RM-304 + follow-on | `libarchive_oxide/src/{iso_stream,seek_stream}.rs`, `libarchive_oxide/tests/interop_iso_meta.rs`, `libarchive_oxide/tests/fixtures/iso/PROVENANCE.md` | arca self round trip plus an external `xorriso`/`genisoimage`/`mkisofs` independent producer (graceful skip); Rock Ridge PX/TF/SL fidelity and bounded SUSP CE continuation read/write, including multi-sector SL data, range and in-flight-limit failures |
| ZIP Info-ZIP Unix uid/gid read | RM-308 | `libarchive_oxide/src/seek_stream.rs` | `zip_unix_owner` parses the Info-ZIP New Unix (0x7855) central body into `Owner` uid/gid; `zip_times` gains a 0x5855 (`UX`) access/modification-time arm. The central `UX` uid/gid trailer (a local-header layout) is deliberately not read to avoid a positional guess; both are bounded, structured-error walks reusing the shared `le16`/`.get()` guards |
| ZIP Extended-Timestamp / Unix uid/gid write-back | RM-308 | `libarchive_oxide/src/zip_stream.rs` | `push_extended_timestamp` (0x5455) and `push_infozip_unix` (0x7855) synthesize extras from typed `EntryTimes`/`Owner`, guarded by `zip_extra_contains_id` so a preserved raw field is never duplicated; accounted against the metadata and extra-field budgets in both local and central headers |
| ZIP extra structured-interpretation tests | RM-308 | `libarchive_oxide/tests/seek_stream_v2.rs` | typed-owner read, owner+timestamp round trip from typed metadata, no-duplicate preserved timestamp, and short-field no-misread |
| ZIP extra 3x2 interop + metadata fidelity | RM-308 | `libarchive_oxide/tests/interop_zip_extra.rs` | three producers (arca from typed metadata, `zip@8.6.0`, raw builder embedding 0x7855/0x5455) × two consumers (arca, `zip@8.6.0`); asserts uid/gid/mtime fidelity through arca on both the raw producer and arca's own output; malformed/truncated extras stay covered by the existing `read_zip` fuzz target |
| Support-matrix ZIP metadata update | RM-308 | `docs/support-matrix.md` | ZIP row records typed interpretation of Unicode/timestamp/Info-ZIP Unix extras and write synthesis |

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
- WRITE is available on both profiles behind `zstd`. The portable push state
  accumulates at most one 1 KiB block and emits a single standards-compliant
  Zstandard frame using raw blocks plus a terminal empty block. Its window
  descriptor matches that bound, and entry-open rejects a `codec_memory` budget
  smaller than the fixed one-block state before bytes reach the destination.
  The native arm retains the true streaming
  `compression_codecs::ZstdEncoder` at deterministic level 3.
  `BackendPreference::{Portable, Native}` reaches the ZIP member writer, so a
  build containing both profiles can select either implementation at runtime.
  Local and central "version needed to extract" remains 63.
- The public `ZipMethod::Zstd` and internal `StreamZipMethod::Zstd` are both
  gated only on `zstd`; there is no deferred runtime-`Unsupported` writer path.
  With the feature off, the public method is unnameable and method-93 reads
  retain the enumerable structured `Unsupported` behavior.
- Evidence (`tests/interop_zip_zstd.rs`) proves read and write on portable and
  native. External producers remain `zip@8.6.0` and a raw-ZIP builder over
  independent-C zstd; arca output is decoded by both `zip@8.6.0` and libzstd.
  A 3 MiB input fed in 97-byte chunks locks bounded block aggregation and output
  overhead, a low codec-memory budget fails with `Limit`, and a coexistence test
  explicitly selects both runtime backends. `tests/seek_stream_v2.rs` includes
  method 93 in both streaming writer loops whenever `zstd` is enabled and keeps
  truncation, decoded-output bomb, and feature-off failures. No new dependency
  or unsafe code is introduced.

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

## RM-306

- ADR-0013 (`docs/adr/0013-rar5-udf-deflate64-feasibility.md`) resolves the RAR5,
  UDF, and Deflate64 feasibility questions RM-300 and ADR-0012 delegated here. It
  is a feasibility-and-scope decision that lands no provider; each support-matrix
  cell still flips only when its provider is implemented.
- **Deflate64 (method 9):** read is a *go* via the external pure-Rust `deflate64`
  decoder consumed behind the codec-provider boundary (satisfies the C-free
  portable profile, keeps `#![forbid(unsafe_code)]` and bounded 64 KiB-window
  decode), landing in a follow-on slice; write is a retired *won't-do* (no
  pure-Rust encoder exists, demand is nil). This supersedes ADR-0012's
  "Deflate64 (read + write)" deficit, now recorded as a write-only won't-do row.
- **UDF:** a *go* for a scoped read-only in-tree pure-Rust provider (Phase 1:
  revisions 1.02/1.50/2.01, AVDP → VDS → File Set Descriptor → ICB/File Entry →
  FIDs/allocation descriptors), activated from the Volume Recognition Sequence
  arca already parses for ISO 9660; UDF 2.50/2.60 Metadata Partitions,
  Virtual/VAT reads, and Sparable Partition reads were out of Phase-1 scope
  and are now implemented as bounded follow-on slices. UDF creation and
  sequential-media write remain out of scope. ECMA-167 and OSTA
  UDF specs are free public PDFs with only generic RAND boilerplate, recorded as a
  low-but-nonzero tracked IP risk.
- **RAR5:** legally defensible as an independent read-only decoder (RAR compression
  is a trade secret, not a patent; the UnRAR license does not reach non-derived
  code), but the provider is *deferred in its entirety*: no clean-room,
  forbid(unsafe), pure-Rust RAR5 decompressor exists, FFI to C UnRAR is disqualified
  by the portable profile, and a metadata-plus-Stored-only cut would read almost no
  real archive (`.rar` in the wild is almost always compressed). Recorded as a
  tracked deficit; decode-only / clean-room / nominative-naming constraints are
  fixed for any future work.
- The ADR itself added no runtime code. Its follow-on implementation has now
  landed `deflate64` 0.1.12 plus the in-tree UDF reader, the corresponding
  support-matrix cells, provenance records, and `read_udf` fuzz target. RAR5
  remains deferred exactly as the ADR decided.

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
- The original worked example, portable zstd encode, has since been resolved
  without weakening the guarantee: method 93 emits bounded 1 KiB raw Zstandard
  blocks instead of adapting `ruzstd`'s pull-to-EOF encoder. Deflate64 read is
  complete on both profiles and its write direction is a permanent won't-do.
  PPMd7 read is also complete with a pre-allocation model-memory gate and an
  exact declared-output boundary. BCJ2 read is complete through a bounded
  four-stream shared-seek junction, independently split by `compcol` and
  container-validated by `sevenz-rust2`; no deferred 7z reader remains.
- `docs/support-matrix.md` is refactored to the accountability grid: the ZIP row
  points to a `method × {read,write} × {portable,native}` table where every `—` is
  a data point (a structured `Unsupported`, enumeration continues), plus a
  "Codec capability deficits" ledger linking each gap to its resolution path and
  tracking item. The generated method-93 row now records read/write for both
  portable and native backends.
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
  `format_capability` →
  `FormatCapabilities::uniform(DirectionSet::READ, AccessMode::Sequential)` (decode yes,
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
  inflates each block's raw DEFLATE while carrying at most 32 KiB of valid folder
  history in a 64 KiB non-wrapping workspace. This accepts a back-reference into
  block N−1 while rejecting references before the beginning of the folder.
  Feature-gated LZX uses the audited `no_std + alloc` regular-LZX fork: each CFDATA
  receives a fresh word-aligned bitstream while window/tree/recent-offset/E8
  state persists across the folder. Aggregate metadata, CFDATA checksum,
  codec-memory, in-flight, decoded-total, and scan-work checks happen before
  attacker-sized allocation or decode; a decode failure poisons the stream so
  retry cannot skip a rejected entry/block. Feature-gated Quantum follows the
  same bounded stateful model. The advanced `CabVolumeReader` validates an
  application-owned `VolumeSet`, joins `cbUncomp == 0` physical fragments
  before decode, and preserves Store/MSZIP/LZX/Quantum folder state across
  `iFolder` continuation sentinels. The ordinary single-source reader still
  lists continuation metadata and returns structured `Unsupported` on payload.
- **XAR** (`xar.rs`): the 28-byte big-endian header locates the zlib-compressed TOC
  (inflated with `DataFormat::Zlib`, capped at `min(toc_length_uncompressed,
  metadata_bytes)` and length-verified) and the heap (`heap_start = header.size +
  toc_length_compressed`, never a hard-coded 28). A hand-rolled bounded XML
  pull-scanner (an explicit DFS `<file>`-frame stack, no DOM, no XML crate) resolves
  each entry's `/`-joined path, emitting a directory before its children, bounded by
  `entries` / `path_bytes` / a nesting-depth cap. Regular files stream their heap
  blob per entry (seek-per-blob for the unordered/shared-heap model) as stored
  (`octet-stream`, `S == L` enforced), zlib (`x-gzip`, RFC-1950 — decoded as zlib,
  NOT gzip), or feature-gated bzip2 (`x-bzip2`), with the decoded length verified
  against `<length>`. The bzip2 path is caller-driven and enforces codec-memory,
  truncation/corruption, and decoded-size limits before allocation. Unknown
  encodings are structured `Unsupported`; version ≠ 1 is `Unsupported`.
- Write is rejected without a code path of its own: the decode-only capability makes
  `format_encoder` return a typed `Capability` error, and `SeekArchiveWriter::with_format`
  falls through its default arm to `Unsupported` for `FormatId::Cab`/`Xar`.
- `#![forbid(unsafe_code)]`, the `no-dyn` gate, and bounded memory hold: both readers
  are plain generic structs over `R: Read + Seek` with concrete enums (no trait
  objects), stream payload in ≤ 64 KiB chunks, and return a structured `StreamError`
  for every malformed/truncated/unsupported/limit case (never a panic/unwrap).
- Evidence: `tests/interop_cab_meta.rs` and `tests/interop_xar_meta.rs` combine
  first-party raw builders with byte-exact external fixtures and assert content
  round trips over multi-file/nested/empty corpora. CAB LZX uses a three-CFDATA
  Microsoft makecab fixture (verified with `expand.exe`) and libmspack's mixed
  MSZIP/LZX/Quantum corpus, proving history persistence, word realignment, and
  nonzero Microsoft/libmspack CFDATA checksums. The XAR bzip2 case uses an independently produced
  stream and covers large/empty payloads, corruption, exact decoded length, and
  memory limits. Negatives also cover an unsupported compression method and a
  truncated/out-of-range header. This proves independent container
  framing, not codec independence on portable builds: `flate2` and arca's inflater
  share the `miniz_oxide` implementation family there. A three-lens adversarial review
  (panic/bounds, spec-correctness, malformed-input) with an independent verification
  pass was run over both modules before commit. Per-format `PROVENANCE.md` registers
  the in-code raw builder and documents the external independent producers
  (Microsoft makecab/expand and the libmspack corpus for CAB; the `xar` CLI /
  `bsdtar --format=xar` for XAR). `gcab` is not claimed as LZX evidence because
  its writer does not produce CAB LZX folders.
## RM-304

- RM-304 lifts the RM-301 interoperability harness from content-only evidence to
  metadata fidelity for the sequential and disc formats, and it is a test/corpus
  slice: no `src/` runtime change. tar/cpio/ar already encode and decode their
  metadata (see `libarchive_oxide-core/tests/protocol_v2.rs`); RM-304 proves it
  through the high-level `ArchiveWriter`/`ArchiveReader` against independent
  producers and consumers.
- Harness extension (`tests/common/mod.rs`, additive — the content-only
  `EntryShape` path is untouched): `read_seq_with_arca` reads tar/cpio/ar through
  the non-seek `ArchiveReader` (the seek reader only indexes ZIP/ISO); `MetaShape`
  preserves the REAL entry kind (Symlink/Hardlink are no longer folded to File) and
  the typed mode/uid/gid/mtime/link-target; `read_meta_seq_with_arca` /
  `read_meta_seek_with_arca` project an archive into path-sorted `MetaShape`s; and
  `assert_producers_agree_seq` mirrors `assert_producers_agree` through the
  sequential reader. Producers/consumers stay bare `fn` pointers, so `no-dyn` and
  `#![forbid(unsafe_code)]` hold.
- **tar**: three producers (arca, the `tar` crate at 0.4, and a first-party raw
  ustar builder with a computed header checksum) agree on content through arca's
  sequential reader, and arca's output is accepted by both arca and the `tar`
  crate. Metadata fidelity asserts mode `0o640`, uid/gid, mtime, and a symlink
  target survive both arca's own writer and the `tar` crate's — the strongest,
  fully in-code slice.
- **cpio**: three producers (arca `newc`, a first-party raw `newc`, and a
  first-party raw `odc`) and two consumers (arca and a first-party raw `newc`
  parser). Honesty note: no mature pure-Rust cpio *producer* crate exists, so the
  third producer is a second first-party builder in a genuinely different on-disk
  dialect (octal `odc` vs hex `newc`, no padding vs 4-byte alignment) rather than a
  third-party crate — real on-disk-layout independence, not third-party-crate
  independence. Metadata fidelity covers mode/uid/gid/mtime and a typed hardlink
  pair (a payload-bearing File with `nlink=2` and its zero-size `Hardlink` alias
  with a `link_target`). Crc and the binary dialects are covered by
  `protocol_v2.rs`.
- **ar**: three producers (arca, the `ar` crate at 0.9, and a first-party raw
  `!<arch>` builder) and two consumers (arca and the `ar` crate). ar is flat
  regular-files-only (no directory or symlink concept), so fidelity is mode (masked
  to the low 12 bits on read)/uid/gid/mtime; names are kept short so all producers
  stay on the byte-compatible short-name path (long BSD/GNU names are covered in
  `protocol_v2.rs`).
- **ISO**: producer independence is fundamentally narrower — there is no usable
  pure-Rust independent ISO reader on every target (`iso9660` is a libcdio C
  binding; `cdfs` needs FUSE), confirmed by `iso_differential.rs`. Content interop
  is therefore an arca write → arca read self round trip, and the INDEPENDENT
  producer is an external mastering tool (`xorriso`/`genisoimage`/`mkisofs`, `-R -J`)
  that arca reads back, with a graceful skip when none is installed. Metadata
  fidelity round-trips mode/uid/gid/mtime and a symlink target through arca's
  DEFAULT Rock Ridge emission (PX/TF/SL, emitted unconditionally by `iso_stream.rs`
  and auto-detected by the reader), read via the seek reader. The follow-on
  continuation slice emits CE records when system-use fields exceed a directory
  record, packs their data into a dedicated region, and follows CE chains with
  image-range, cycle, nesting, in-flight, and metadata limits. A multi-sector
  split-SL fixture plus out-of-range and low-budget failures keep the claim gated.
- New dev-dependencies (test-only, no effect on the shipped crate's portable/C-free
  profile): `tar = "0.4"` and `ar = "0.9"`, both pure-Rust independent
  producers/consumers. Per-format `PROVENANCE.md` registries record each producer,
  its independence, and the external-tool escape hatch for ISO.
## RM-308

- ZIP extra fields carry typed metadata the reader previously left opaque. Before
  RM-308 the central-directory parser already promoted ZIP64 (0x0001), WinZip AES
  (0x9901), Info-ZIP Unicode path/comment (0x7075/0x6375), and the Extended
  Timestamp (0x5455) / NTFS (0x000a) fields into structured metadata, but the
  Info-ZIP Unix uid/gid fields were left only as opaque `zip-extra` blobs. RM-308
  adds `zip_unix_owner`, which parses the Info-ZIP New Unix (`Ux`, 0x7855) central
  body into `Owner` uid/gid, and extends `zip_times` with an Info-ZIP Unix (`UX`,
  0x5855) access/modification-time arm. Both are bounded single-purpose walks over
  the extra buffer that reuse the shared `le16`/`.get()` truncation guards and
  return a structured `Malformed` error rather than misreading a short or
  overrunning field.
- Owner surfacing is honestly scoped to the central directory the seek reader
  indexes. Info-ZIP places `Ux`/`UX` uid/gid in the LOCAL header (the central `Ux`
  body is empty and the central `UX` body is times-only), so a strict foreign
  archive's uid/gid is preserved as raw extra but not surfaced as typed `Owner`;
  the central `UX` uid/gid trailer is not read to avoid a positional guess. arca
  writes uid/gid into the central directory so its own round trips keep ownership.
  A local-header owner-hydration pass (mirroring the symlink-target hydration) is a
  tracked follow-up if strict foreign-archive owner fidelity is needed.
- The raw bytes of every extra remain preserved in the `zip-extra` namespace, so
  the typed fields are an additive view and round trips stay byte-lossless — a
  design that avoids the precision loss (NTFS 100 ns) and local/central-header
  asymmetry that stripping-and-regenerating would introduce.
- On write, `push_extended_timestamp` (0x5455) and `push_infozip_unix` (0x7855)
  synthesize the extras from typed `EntryTimes`/`Owner` for entries created from
  metadata alone (the previous writer emitted only a DOS 2-second modification
  time). `zip_extra_contains_id` guards both so an entry that already carries an
  equivalent raw form never gains a duplicate copy: the timestamp guard covers
  every raw field the reader promotes into `EntryTimes` — the Extended Timestamp
  (0x5455), NTFS (0x000a), and Info-ZIP `UX` (0x5855) — so a preserve round trip of
  any of them stays byte-idempotent; the owner guard covers 0x7855 and 0x5855. A
  uid/gid that overflows the 16-bit form is left unrepresented rather than silently
  wrapped. The synthesized bytes are counted against the metadata and extra-field
  budgets and appear identically in the local and central headers (emitted exactly
  once, before both the local-header serialization and the move into the central
  record).
- `#![forbid(unsafe_code)]`, the `no-dyn` static-dispatch gate, and bounded memory
  are all preserved: the new parsers and emitters are plain functions with no trait
  object and no new dependency.
- Evidence: `tests/seek_stream_v2.rs` adds a typed-owner read for 0x7855, a
  times-only read for 0x5855, an owner+timestamp round trip synthesized purely from
  typed metadata, a no-duplicate check for a preserved Extended Timestamp, a
  no-second-synthesis check for preserved 0x5855/0x000a times, and a short-field
  no-misread check. `tests/interop_zip_extra.rs` proves content interop across three
  independent producers (arca from typed metadata, `zip@8.6.0`, and a raw builder
  embedding 0x7855/0x5455 verbatim) and two consumers (arca, `zip@8.6.0`), asserts
  uid/gid/mtime fidelity through arca for both the raw producer's and arca's own
  output, and independently rescans arca's raw output bytes for the exact
  synthesized 0x7855/0x5455 TLVs so a shared writer/reader convention error cannot
  pass undetected. Malformed and truncated extras remain covered by the existing
  `read_zip` fuzz target, which exercises the central-directory parse path.
- A three-lens adversarial review (round-trip, bounds-safety, spec-interop) with an
  independent verification pass was run over the diff before commit; its two
  confirmed findings — a timestamp no-duplicate guard blind to 0x5855/0x000a, and a
  central-vs-local uid/gid layout assumption — were fixed and their fixes are the
  guard-widening and central-`UX`-uid/gid-suppression described above.

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
