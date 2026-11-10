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
| ZIP LZMA (method 14) read | RM-302 + follow-on | `libarchive_oxide/src/{seek_stream,zip_read,filter/lzip}.rs` | seek members use a source-owning length limit, while forward-only plain, ZipCrypto, and WinZip AES entries use the bounded pull-worker bridge and never buffer a whole compressed member; known extents accept EOS-marker and declared-size conventions, and EOS streams accept signed/unsigned classic/ZIP64 descriptors through exact acknowledged input ownership; all paths parse the 9-byte header, preflight `codec_memory`, and enforce CRC-32, size, authentication, decoded, truncation, and bad-header guards; gated on `xz`, present on BOTH profiles |
| ZIP LZMA (method 14) write | RM-302 | `libarchive_oxide/src/zip_stream.rs`, `libarchive_oxide/src/provider.rs` | `StreamZipMethod::Lzma` + `lzma_rust2::LzmaWriter::new_no_header` (raw LZMA1, EOS marker) drained through an in-crate `VecSink` (no trait object, `#![forbid(unsafe_code)]` intact); pinned preset 6 (props 93, 8 MiB dict); emits the 9-byte ZIP-LZMA header once at entry start; general-purpose bit 1 (`0x0002`) set in local+central flags outside the `0x0809` cross-check mask; version-needed 63 |
| ZIP LZMA interop + adversarial evidence | RM-302 + follow-on | `libarchive_oxide/tests/{interop_zip_lzma,seek_stream_v2,zip_stream_read}.rs`, `libarchive_oxide/tests/fixtures/zip/python-lzma/`, `fuzz/fuzz_lib/src/lib.rs` | three producers (arca + first-party raw-LZMA1 builder, both `lzma-rust2`; + committed CPython 3.14.6/liblzma fixture, independent codec) × two consumers (arca, `zip@8.6.0` with `lzma`); WRITE evidence = the `zip` crate decodes arca's method-14 output byte-identically; seek and one-byte/buffered sync/futures/Tokio forward reads cover both size conventions, plain/ZipCrypto/AES known extents and signed/unsigned classic/ZIP64 descriptors, CRC/size/authentication/truncation/property/dictionary/decoded limits, feature-off Unsupported, and valid-envelope fuzz replay; descriptor framing without EOS is explicitly Unsupported; the committed fixture + `generate.py` are byte-reproducible (SHA-256 recorded in `PROVENANCE.md`) |
| ZIP PPMd8 (method 98) forward read + interop evidence | RM-302 follow-on | `libarchive_oxide/src/{seek_stream,zip_read,zip_stream,filter/lzip}.rs`, `libarchive_oxide/tests/{interop_zip_ppmd,zip_stream_read}.rs`, `fuzz/fuzz_lib/src/lib.rs` | variant-I revision-1 parameter words are validated before model allocation; seek and forward-only known extents stream without whole-member buffering, while EOS-terminated signed/unsigned classic/ZIP64 descriptors use exact range-decoder acknowledgements to retain framing bytes. Plain, ZipCrypto, and WinZip AES paths share CRC/size/authentication/truncation/model/decoded gates and one-byte sync/futures plus buffered sync/Tokio coverage. `zip@8.6.0` independently produces archives consumed by arca and consumes arca's streaming writer output; valid-envelope fuzz replay exercises plain and encrypted known/descriptor envelopes |
| Support-matrix + PROVENANCE ZIP LZMA update | RM-302 | `docs/support-matrix.md`, `libarchive_oxide/tests/fixtures/zip/PROVENANCE.md` | ZIP row adds LZMA to Read and Write; the not-yet-implemented note now lists ONLY Deflate64; PROVENANCE records the committed-fixture escape hatch and the two-independent-codecs honesty note |
| CAB read-only provider | RM-305 + LZX/Quantum/volume follow-ons | `libarchive_oxide/src/cab.rs`, `libarchive_oxide/src/cab/volume.rs`, `libarchive_oxide-codecs/src/lzx/`, `libarchive_oxide-core/src/capability.rs`, `docs/adr/0018-cab-lzx-frame-boundaries.md`, `docs/adr/0019-cab-quantum-compcol.md`, `docs/adr/0021-cab-volume-set.md` | `CabSeekReader`: bounded MSCF tables and streamed Store/MSZIP/Quantum/LZX folders; aggregate folder/file metadata accounting, fallible attacker-sized allocations, CFDATA checksums, sticky typed failure state, and pre-allocation codec/in-flight/decoded/scan limits. LZX keeps history across word-aligned CFDATA bitstreams and Quantum keeps its dictionary/models across injected alignment trailers. `advanced::CabVolumeReader` and `CabVolumeProvider` validate a caller-owned `VolumeSet`, lazily concatenate physical split blocks, and preserve codec state across cabinets; the ordinary single-source reader retains structured `Unsupported` for continuation. Capabilities are read-only and additively `cab-lzx`/`cab-quantum`-gated |
| XAR read/write provider | RM-305 + follow-on | `libarchive_oxide/src/xar.rs`, `src/xar/write.rs`, `src/write_options.rs`, `.../seek_stream.rs`, `docs/adr/0026-xar-compressed-writer.md` | `XarSeekReader` streams Store/zlib/BZip2 heap data; `XarSeekWriter` emits bounded Store/zlib/BZip2 payloads with independent per-entry framing, codec-memory preflight, encoded-expansion bounds, and spill-to-disk heap storage. Unknown or feature-disabled encodings fail typed; `FormatId::Xar` remains seek-native and writer-free on inspection-only WASI |
| CAB/XAR interop + adversarial evidence | RM-305 + follow-ons | `libarchive_oxide/tests/interop_cab_meta.rs`, `libarchive_oxide/tests/cab_volumes.rs`, `libarchive_oxide/tests/interop_xar_meta.rs`, `libarchive_oxide/tests/fixtures/{cab,xar}/PROVENANCE.md` | first-party Store/MSZIP builders, a Microsoft makecab two-volume fixture independently consumed by `extrac32`, and libmspack LZX/Quantum evidence; multi-frame and cross-cabinet history/alignment, missing/wrong/cyclic/duplicate/out-of-order cabinets, split-block corruption, aggregate metadata, poisoned retries, window, truncation, decoded-total/codec-memory/in-flight, and E8 regressions; XAR retains its independent bzip2 evidence |
| Support-matrix CAB/XAR rows | RM-305 + follow-ons | `docs/support-matrix.md` | CAB remains read-only; XAR Store/zlib/BZip2 are generated as seek read/write capabilities, with BZip2 feature-gated |
| LHA UNLHA32 LHx read follow-on | RM-307 follow-on | `libarchive_oxide/src/lha.rs`, `libarchive_oxide/tests/interop_lha.rs`, `libarchive_oxide/tests/fixtures/lha/PROVENANCE.md`, `fuzz/corpus/read_lha/unlha32-lhx.hex` | Existing Safe Rust `delharc` backend gains its opt-in LHx decoder; the 512 KiB history is capability-recorded and rejected before decoder construction when over `codec_memory`; a real UNLHA32.DLL 2.67a level-2 member locks auto-probing, streamed decode, CRC16, exact/under-bound behavior, provenance, and fuzz replay. LHA writing and LH2/LH3 remain absent |
| LHA PMArc PM1/PM2 read follow-on | RM-307 follow-on | `libarchive_oxide/src/lha.rs`, `libarchive_oxide/tests/interop_lha.rs`, `libarchive_oxide/tests/fixtures/lha/{pmarc-1.24-pm1.pma.hex,pmarc2-pm2.pma.hex}`, `fuzz/corpus/read_lha/pmarc-pm{1,2}.hex` | The pinned Safe Rust `delharc` backend enables PMArc PM1/PM2 with unchecked assertion elision disabled; fixed 16 KiB/8 KiB histories are capability-recorded and rejected before decoder construction when over `codec_memory`. Real Lhasa PMArc 1.24/2 fixtures lock paths, methods, decoded lengths, independent CRC32 values, exact/under-bound behavior, truncation, provenance, and fuzz replay. LHA writing and LH2/LH3 remain absent |
| Rust 1.88 codec-consumer maintenance | RM-307 follow-on | `libarchive_oxide/vendor/{delharc,sevenz-rust2}/`, `xtask/src/main.rs`, `Justfile` | The full-feature CI graph resolves a publishable, uniquely named `libarchive_oxide-delharc` fork of upstream 0.8.0, with post-MSRV syntax/APIs and all unchecked operations replaced by checked Safe Rust while retaining LHx/PMArc. The dev-only upstream `sevenz-rust2` 0.21.3 corpus consumer pins compatible `nt-time` 0.13.0 and forbids unsafe code. Tag commits, crates.io checksums, licenses, package contents/resolution, all-feature Rust 1.88 builds, LHA corpus/fuzz replay, and 7z differential tests are committed evidence; no runtime capability claim changes. |
| Protocol/format/codec dependency split | architecture follow-on | `libarchive_oxide-protocol/`, `libarchive_oxide-{core,codecs}/`, `docs/adr/0032-protocol-format-codec-layers.md`, `xtask/src/main.rs` | Dependency-free Safe Rust `no_std + alloc` protocol/error/limit types move below format core and codecs. Core retains identical public re-exports, codecs remove all format-core imports, and a recursive architecture gate fixes the downward-only DAG. Independent unit, bare-metal, WASI, MSRV, package-license, external package/type-identity, and full feature/profile gates cover the split without changing format capability claims. |
| RAR payload codec isolation | architecture follow-on | `libarchive_oxide-rar/`, `libarchive_oxide/src/provider.rs`, `docs/adr/0033-injected-rar-payload-codecs.md`, `xtask/src/main.rs` | Bounded RAR3/RAR5 payload algorithms move out of the generic codec collection into a Safe Rust `no_std + alloc` protocol-only sibling. The flagship retains closed-enum static dispatch; both attributed decoder trees are locally owned, the RAR crate has no `compcol` dependency, and the architecture gate rejects core/generic-codec/upward dependencies, boxed algorithm trait objects, or a return of RAR source/features to the generic crate. Bare-metal, WASI, MSRV, package-consumer, unit, and full-profile gates exercise the publishable boundary without changing capability cells. |
| Owned RAR5 Delta/ARM filters | architecture follow-on | `libarchive_oxide-rar/src/rar5/`, `libarchive_oxide-rar/UPSTREAM.md`, `fuzz/fuzz_lib/src/lib.rs`, `docs/adr/0033-injected-rar-payload-codecs.md` | The dedicated crate owns the attributed MIT RAR5 decoder derivative and no longer enables `compcol/rar5`. Delta and ARM join x86 E8/E9 with direct and queue-integration tests; the existing RAR5 fuzz/replay target now drives bounded arbitrary payload blocks and mutations of a valid compressed block directly. One-block-per-call consumption, a finite pending-descriptor cap, checked narrowing, backward-filter rejection, and 2.5-window/filter-scratch accounting preserve finite memory and fail-closed behavior. At this slice rare filter types 4-7, generation 1, solid compression, encryption, and every RAR writer remained unavailable; the sequential solid follow-on is recorded below. |
| RAR5 sequential solid continuation | architecture follow-on | `libarchive_oxide-core/src/{payload,format/rar5}.rs`, `libarchive_oxide-rar/src/{adapter,lib,rar5/decoder}.rs`, `libarchive_oxide/src/provider.rs`, `libarchive_oxide/tests/rar5.rs` | The associated-type provider consumes a completed concrete decoder and returns the same statically dispatched type for the next member. The owned codec retains only its dictionary, Huffman tables, and distance history while resetting and independently bounding member extents, output, filters, and block framing. Premature reuse and changed dictionaries fail closed. A 677-byte BSD-licensed libarchive v3.8.8 corpus validates four 4096-byte members with real cross-member references under one-byte delivery. At this slice generation 1, rare filters, encryption, and solid split-volume continuation remained unavailable; the volume follow-on is recorded below. |
| RAR3 sequential solid continuation | architecture follow-on | `libarchive_oxide-core/src/{payload,format/rar_legacy}.rs`, `libarchive_oxide-rar/src/{adapter,lib,rar3/decoder}.rs`, `libarchive_oxide-ppmd/src/`, `libarchive_oxide/src/provider.rs`, `libarchive_oxide/tests/{rar_legacy.rs,fixtures/rar-legacy/PROVENANCE.md}` | The same associated-type ownership transfer carries a completed concrete RAR3 decoder across sequential solid members. LZ dictionary/Huffman/distance state or the PPMd-H statistical model plus shared output window persist; member-local input, output, exact extents, CRC32, and budgets reset. The dependency-free Safe Rust PPMd primitive crate uses a bounded flat heap with integer offsets and RAR's carryless range decoder. Missing predecessor state and a solid file outside an archive-level solid set fail closed. A 464-byte external RAR4 corpus validates nine LZ members, while a 381-byte CC0 WinRAR corpus validates two PPMd members and exact 307-byte output under one-byte delivery. Corruption, truncation, and insufficient model memory fail with typed errors. RarVM, encryption, and solid split-volume continuation remain unavailable. |
| RAR3 standard VM filters | architecture follow-on | `libarchive_oxide-rarvm/`, `libarchive_oxide-rar/src/rar3/decoder.rs`, `libarchive_oxide/tests/{rar_legacy.rs,fixtures/rar-legacy/PROVENANCE.md}`, `docs/adr/0036-bounded-rar3-standard-filters.md` | A dependency-free BSD-2-Clause Safe Rust primitive parses bounded descriptors and recognizes Delta, E8, E8/E9, RGB, and Audio by validated XOR plus length/CRC32 fingerprints. Closed-enum transforms use caller-owned output/scratch; arbitrary bytecode is never interpreted. The RAR decoder retains the finite standard-program table across solid members, clears member-local pending invocations, validates overlap/chaining, and preflights program, queue, descriptor, and scratch memory. A 94,301-byte BSD libarchive fixture produces the independently verified 204,288-byte executable under one-byte delivery. Unit tests cover every transform, truncation, checksum, descriptor, table, register, and scratch bound. |
| Bounded static RAR3 header/data decryption | architecture follow-on | `libarchive_oxide-rar-crypto/`, `libarchive_oxide-core/src/{rar_crypto,format/rar_legacy}.rs`, `libarchive_oxide/src/{engine,provider,transcode}.rs`, `libarchive_oxide-cli/src/oxarchive.rs`, `libarchive_oxide/tests/{rar_legacy.rs,fixtures/rar-legacy/PROVENANCE.md}`, `libarchive_oxide-cli/tests/oxarchive.rs`, `docs/adr/0037-static-bounded-rar3-encryption.md` | An independently publishable ISC `no_std` Safe Rust primitive owns RAR3's fixed-round SHA-1 KDF, long-password compatibility behavior, zeroizing key material, and AES-128-CBC. Core owns framing, 16-candidate and memory bounds, encrypted-header target hypotheses, candidate-local compressed decoders, and CRC-before-plaintext release behind a generic in-place provider; the flagship owns ordered zeroizing passwords and per-candidate/salt key caches with static dispatch. Independent KDF/AES vectors, two ISC real archives, a nonempty independently encrypted Store oracle, one-byte delivery, wrong-first/wrong-only passwords, truncation, block alignment, workspace bounds, and CLI list/convert/edit cover header and non-solid/non-split Store/LZ/PPMd data. Encrypted solid/split/symlink payloads and all RAR writing remain unavailable. |
| RAR5/UDF/Deflate64 feasibility ADR | RM-306 | `docs/adr/0013-rar5-udf-deflate64-feasibility.md`, `docs/support-matrix.md` | Deflate64 read = go (adopt pinned upstream pure-Rust `deflate64` behind the codec-provider boundary, follow-on slice) / write = won't-do; UDF read-only go (rev 1.02/1.50/2.01, follow-on); RAR5 deferred in its entirety (no clean-room pure-Rust decompressor); codec-deficit ledger + not-yet-implemented prose updated; no `src/` change, no dependency added |
| RAR5 bounded Store/compressed volume sequencing | follow-on | `libarchive_oxide-core/src/format/rar5.rs`, `libarchive_oxide-rar/src/lib.rs`, `libarchive_oxide/src/{provider,rar5_volume,volume_stream}.rs`, `libarchive_oxide/tests/rar5_volumes.rs` | the root `VolumeArchiveReader` detects RAR5 and follows only authenticated physical end-header continuation through a caller-owned bounded `VolumeSet`; each physical main header must carry stable volume/solid flags, explicit numbers are sequence-checked, missing volumes preserve `RangeReadErrorKind::MissingVolume`, later physical main metadata is hidden from the one logical event stream, and a final volume never triggers speculative resolver requests. The physical parser emits raw compressed extents and the volume layer owns one bounded concrete generation-0 decoder across ordinary, split, and solid members, including a solid member split across two physical files. Every non-final packed part and final logical CRC32/BLAKE2sp are verified; missing state, dictionary drift, continuation mismatch, declared-size errors, and archive-budget overflow fail closed. Split service data, generation-1 compression, and encryption remain typed unsupported. |
| RAR7 generation-1 decode | follow-on | `libarchive_oxide-rar/src/{lib,rar5/decoder}.rs`, `libarchive_oxide-core/src/format/rar5.rs`, `libarchive_oxide/src/provider.rs`, `libarchive_oxide/tests/{rar5.rs,fixtures/rar5/PROVENANCE.md}`, `fuzz/corpus/read_rar5/rars-rar7-generation1.rar` | A typed static algorithm selector extends the clean-room decoder from generation 0's 64 distance symbols to generation 1's 80, retains up-to-1-TiB distances in `u64`, sizes the combined Huffman table per generation, and replaces power-of-two masks with overflow-safe exact-window wrap functions. Header parsing distinguishes generation-1 dictionary layout from its old-algorithm compatibility flag; ordinary, service, solid, and split-volume provider paths use the same concrete decoder without `Box<dyn>`. Address-space, dictionary, block, filter, output, and workspace budgets fail before allocation. Direct tests fix maximum distance and fractional wrap boundaries; a complete method-5/192-KiB RAR7 archive streams under one-byte delivery, replays in fuzz, and matches its producer plus independent 7-Zip 26.02 integrity, method, size, and SHA-256 oracle. RAR writing remains license-excluded. |
| RAR5 encryption metadata boundaries | follow-on | `libarchive_oxide-core/src/format/rar5.rs`, `libarchive_oxide/tests/rar5.rs`, `fuzz/fuzz_lib/src/lib.rs` | file-encryption extra records strictly validate algorithm version, flags, KDF-count byte, fixed salt/IV, optional password-check length, duplicates, truncation, and trailing data. Valid records mark `EntryMetadata::is_encrypted()` under one-byte input, preserve the raw extra, and fail typed before any ciphertext is emitted as `Data`. Header-encryption headers likewise validate version, flags, KDF-count byte, fixed salt, optional password check, forbidden common fields, placement, truncation, and trailing data; valid headers expose raw archive metadata before ciphertext can be parsed as a plaintext header. Synthetic valid-envelope fuzzing reaches both boundaries on every replay. Header/data decryption remains unavailable and is not capability-claimed |
| RAR5 compressed sequential services | follow-on | `libarchive_oxide-core/src/{protocol,format/rar5}.rs`, `libarchive_oxide/src/stream.rs`, `libarchive_oxide/tests/rar5.rs`, `fuzz/fuzz_lib/src/lib.rs` | Generation-0 CMT, QO, RR, ACL, and STM service payloads reuse the associated-type codec provider with a concrete temporary decoder distinct from retained solid-file state. `DecodeEvent::Progress` lets the driver consume bounded internal plaintext without exposing it as entry data or falsely requesting input/output. Exact packed/unpacked sizes, decoded-total, metadata retention, codec workspace, CRC32/BLAKE2sp, truncation, feature-off dispatch, one-byte delivery, and a valid compressed-service fuzz envelope fail closed. Solid and split services remain typed unsupported. |
| RAR 3.x/4.x encryption metadata boundaries | follow-on | `libarchive_oxide-core/src/format/rar_legacy.rs`, `libarchive_oxide/tests/rar_legacy.rs`, `fuzz/fuzz_lib/src/lib.rs` | known Store/LZ/PPMd method headers with `FHD_PASSWORD` expose `EntryMetadata::is_encrypted()` under one-byte input, retain the raw method/optional fields, accept ciphertext/plaintext size differences, and validate an optional fixed 8-byte salt before metadata. The feature-off/no-provider payload step fails typed before ciphertext can be emitted as `Data`; encrypted stored symlink targets remain fail-closed. Main-header encryption exposes raw flags/version and an archive marker before encrypted header bytes can be parsed as plaintext. Synthetic valid-envelope fuzzing varies method, salt, and header-version presence/value on every replay. The later bounded decryption follow-on is recorded above. |
| RAR 3.x/4.x bounded Store/compressed volume sequencing | follow-on | `libarchive_oxide-core/src/format/rar_legacy.rs`, `libarchive_oxide/src/{rar_legacy_volume,volume_stream}.rs`, `libarchive_oxide/tests/rar_legacy_volumes.rs`, `fuzz/fuzz_lib/src/lib.rs` | the root `VolumeArchiveReader` detects legacy RAR sets and follows only CRC-verified ENDARC continuation through a caller-owned bounded `VolumeSet`; physical main headers require MHD_VOLUME, later MHD_FIRSTVOLUME is rejected, missing volumes retain `RangeReadErrorKind::MissingVolume`, and logical entry/decoded limits span the set. Complete Store entries form one event stream. Split Store parts stream without whole-payload buffering; non-solid RAR3 LZ parts retain a packed copy within the combined in-flight/codec-memory equation and decode through the static provider. Non-final packed CRC32 when present, final logical CRC32, stable continuation metadata, declared logical size, prior/after flags, archive budgets, exact memory boundary, and missing volumes are tested. Final volumes cause no speculative resolution; split non-file, PPMd/RarVM/solid, and encrypted entries remain typed unsupported |
| Bounded 7z/RAR adjacent path discovery and complete session identity | follow-on | `libarchive_oxide/src/engine.rs`, `libarchive_oxide/tests/{sevenz_volumes,rar5_volumes,rar_legacy_volumes}.rs`, `libarchive_oxide-cli/tests/oxarchive.rs`, `docs/adr/0030-bounded-adjacent-volume-discovery.md` | explicit path-only discovery accepts numeric `.001` 7z, width-preserving modern `.part1.rar`, and legacy RAR 3.x/4.x `.rar`/`.r00` naming without directory scans or cross-directory derivation. `SourceLimits` remain authoritative, non-primary/incoherent names fail before opening siblings, missing RAR continuations retain the typed range error, and `ArchiveEngine::open_volumes` traverses once before digesting so lazily reached physical sources are included in inspect/plan/apply identity. Library and CLI tests cover split Store joins, digest inequality on second-volume changes, extraction, explicit formats, and 7z compatibility |
| Standard split ZIP/ZIP64 read and terminal-path discovery | follow-on | `libarchive_oxide/src/{zip_volume,seek_stream,engine}.rs`, `libarchive_oxide/tests/zip_volumes.rs`, `libarchive_oxide-cli/tests/oxarchive.rs`, `fuzz/fuzz_lib/src/lib.rs` | the common bounded `VolumeSet` reader maps classic and ZIP64 EOCD/locator/central disk numbers plus disk-relative central and local offsets onto immutable sources; payloads can cross physical boundaries and reuse every existing ZIP compression/password decoder without an archive-sized join buffer. Explicit terminal `.zip` discovery pre-resolves exactly the EOCD-declared `.z01` and later disks in the same directory, preserving `MissingVolume` and `VolumeCountExceeded`. Store boundary crossing, a later-disk local header, ZIP64 sentinels, engine inspection, CLI list/inspect/plan/verify/extract, regular ZIP regression, and framed/valid fuzz envelopes are covered |
| Forward-only ZIP/ZIP64 local-header reader | follow-on | `libarchive_oxide/src/{zip_read,provider,filter/{lzip,xz}}.rs`, `libarchive_oxide/vendor/deflate64`, `libarchive_oxide/tests/{zip_stream_read,interop_zip_deflate64,interop_zip_ppmd}.rs`, `fuzz/fuzz_lib/src/lib.rs` | the common sequential sync/futures/Tokio provider decodes Store, Deflate, feature-gated Deflate64/BZip2/LZMA/Zstandard/XZ/PPMd8 without `Seek` or an archive-sized spool. All support known-size entries plus signed classic/ZIP64 descriptors; self-terminating Deflate/Deflate64/BZip2/PPMd8, EOS-terminated LZMA, and single-frame Zstandard additionally accept unsigned descriptors, while Store/XZ require the signature to keep payload boundaries unambiguous. LZMA and PPMd8 bounded workers report only range-decoder-acknowledged input, so descriptor/authentication look-ahead stays uncommitted; LZMA known extents accept declared-size or EOS conventions and descriptors require EOS, while PPMd8 known extents stop at declared output and descriptor entries stop at EOS. Fixed-size Zstandard and bounded XZ structure trackers prevent descriptor look-ahead on portable and native codecs; known-size Zstandard/XZ retain concatenated-stream behavior. A minimal vendored MIT patch exposes the Deflate64 inflater's existing exact checkpoint position; loaded but uncommitted Huffman look-ahead stays in the bounded pipeline until a later checkpoint or EOB assigns it to the compressed stream. One-byte sync/futures input, buffered sync/Tokio input, independent `zip@8.6.0` output, official 7-Zip 26.02 Deflate64 output re-framed with classic/ZIP64 descriptors, the CPython/liblzma LZMA fixture, first-party known/descriptor envelopes, aligned XZ padding, false/unsigned descriptors, archive comments, CRC/count/truncation/trailing extent, entry/path/data/metadata/in-flight/codec-memory limits, feature-off compilation, and stable valid-envelope fuzz mutations exercise the same bounded state machine |
| Forward-only ZIP ZipCrypto Store/Deflate/Deflate64/BZip2/LZMA/PPMd8/Zstandard/XZ | follow-on | `libarchive_oxide/src/{stream,async_stream,provider,registry,zip_read,zipcrypto,filter/{lzip,xz}}.rs`, `libarchive_oxide/vendor/deflate64`, `libarchive_oxide/tests/{open_options,zip_stream_read}.rs`, `fuzz/fuzz_lib/src/lib.rs` | common `OpenOptions` candidates reach the sequential ZIP decoder without exposing secrets; known-size and signed classic/ZIP64 entries validate the 12-byte header, committed ciphertext extent, decrypted CRC32 and sizes, while EOS-terminated LZMA, PPMd8, and Deflate64 additionally accept unsigned descriptors. Store uses bounded descriptor/next-record look-ahead; Deflate previews with a cloned key stream; Deflate64 advances the authoritative key stream only through exact inflater checkpoints; LZMA and PPMd8 commit only worker-acknowledged ciphertext; BZip2 commits its direct decompressor's consumed count; Zstandard/XZ share bounded structural frame validators. Independent `zip@8.6.0`, deterministic known-size fixtures, official 7-Zip Deflate64 payloads, one-byte sync/futures, buffered sync/Tokio, multiple/wrong/missing passwords, verifier/payload/descriptor tamper, truncation, decoded/entry/in-flight/codec-memory limits, per-codec minimal feature builds, and valid-envelope fuzzing cover typed outcomes |
| Forward-only ZIP WinZip AES Store/Deflate/Deflate64/BZip2/LZMA/PPMd8/Zstandard/XZ | follow-on | `libarchive_oxide/src/{zip_read,zipaes,filter/{lzip,xz}}.rs`, `libarchive_oxide/vendor/deflate64`, `libarchive_oxide/tests/{zip_aes,zip_stream_read}.rs`, `fuzz/fuzz_lib/src/lib.rs` | the sequential reader parses method 99 AE-2 local extras, tries ordered `OpenOptions` candidates, and streams known-size or signed classic/ZIP64 entries at AES-128/192/256; EOS-terminated LZMA, PPMd8, and Deflate64 additionally accept unsigned classic/ZIP64 descriptors. A shared cloneable Safe-Rust CTR128LE/HMAC state lets Deflate and pipeline codecs preview without authenticating unconsumed bytes; Store uses bounded tag/descriptor look-ahead, every method verifies the ten-byte tag before `EndEntry`, and encrypted XZ padding is accepted only under `in_flight_bytes` after zero-plaintext, HMAC, and size agreement. Deflate64 advances the authoritative cipher/MAC only through exact inflater checkpoints, and LZMA/PPMd8 advance only through worker acknowledgements, leaving tag and descriptor look-ahead uncommitted. One-byte and buffered sync input, futures/Tokio adapters, wrong/missing password, ciphertext/tag/descriptor tamper, truncation, decoded/model limits, bidirectional `zip@8.6.0` interoperability, and valid-envelope fuzzing cover typed outcomes |
| ZIP Deflate64 read implementation | RM-306 follow-on | `libarchive_oxide/src/{seek_stream,zip_read}.rs`, `libarchive_oxide/vendor/deflate64`, `libarchive_oxide/tests/{interop_zip_deflate64,zip_stream_read}.rs`, `libarchive_oxide/tests/fixtures/zip/{7zip,PROVENANCE.md}`, `xtask/src/main.rs` | method 9 streams through a minimally patched vendored `deflate64` 0.1.12 under `gzip` on portable/native; known extents plus signed/unsigned classic/ZIP64 descriptors, fixed 64 KiB output chunks, exact checkpoint ownership, CRC/size/extent/no-progress/truncation/bomb checks; official 7-Zip 26.02 fixture exercises a >32 KiB distance and buffered descriptor look-ahead; write remains absent/won't-do and package-smoke compile-fail coverage locks the lack of a public `ZipMethod::Deflate64` variant |
| WinZip AES + Deflate64 read composition | RM-306 follow-on | `libarchive_oxide/src/{seek_stream,zip_read}.rs`, `libarchive_oxide/vendor/deflate64`, `libarchive_oxide/tests/zip_aes.rs` | method 99 AE-2 metadata with real method 9 streams ciphertext through AES-CTR/HMAC and the bounded Deflate64 decoder on seek and forward-only known-size or signed/unsigned classic/ZIP64 descriptor paths; deterministic raw fixtures cover one-byte/buffered input, correct/wrong password, authentication and descriptor tamper, truncation, decoded bomb, and gzip-feature-off Unsupported |
| 7z AES password-candidate and archive-metadata property boundaries | follow-on | `libarchive_oxide/src/{sevenz,transcode}.rs`, `libarchive_oxide/tests/{sevenz_differential,seek_stream_v2,transcode}.rs` | codec-graph decoder failures from unauthenticated header/folder plaintext remain candidate-local regardless of `io::ErrorKind`; marked underlying seek/read failures still propagate as `Io`; fixed `sevenz-rust2` salt/IV material 96 deterministically reproduces the former flaky classification and an injected source error guards the opposite boundary. Repeated pre-entry archive-property replacement retains only the current set in the metadata budget; unknown archive/file properties round-trip, while the archive end marker and container-owned FilesInfo properties fail direct writes before entries and become explicit `ArchiveExtensions` transcoder loss |
| ISO/7z timestamp range and projection boundaries | follow-on | `libarchive_oxide/src/{iso_stream,sevenz,transcode}.rs`, `libarchive_oxide/tests/{seek_stream_v2,transcode}.rs` | ISO direct writes require every typed time to fit the Rock Ridge year 0–9999 long form at exact 10 ms precision; 7z direct writes retain only mtime and use checked 100 ns `u64` FILETIME conversion, with the decoder covering the full unsigned range instead of clamping through `i64`. Direct range/precision/non-mtime failures are `Unsupported` before entry output; ISO year 0/9999 and FILETIME 0/`u64::MAX` round-trip; transcoding quantizes only in-range values and reports out-of-range mtime loss |
| ISO direct entry metadata projection boundaries | follow-on | `libarchive_oxide/src/{iso_stream,transcode}.rs`, `libarchive_oxide/tests/{seek_stream_v2,transcode}.rs` | direct writes accept only File/Dir/Symlink/Char/Block/Fifo/Socket plus exact u32 PX/PN numeric fields, 12-bit modes, representable timestamps, canonical raw SUSP fields, and u32 entry sizes; hardlinks, owner names, oversized numeric fields or payload declarations, filesystem device/flags/checksum/comment, sparse/xattr/ACL/encryption, and other unrepresentable typed/raw fields fail before entry output. Tar→ISO comments and hardlinks are reported as explicit metadata loss instead of being silently projected |
| cpio/ISO numeric transcoder projection boundaries | follow-on | `libarchive_oxide/src/transcode.rs`, `libarchive_oxide/tests/transcode.rs` | cpio and ISO retain inode/link/device components through their u32 newc/PX/PN maximum and drop oversized optional groups with explicit `InodeAndLinkCount`/`Devices` losses before writer dispatch; ISO Char/Block entries with missing or oversized required PN metadata fail `Unsupported` before entry output. A public cpio→ISO round trip proves inode 42/link-count 1 survives through both providers and the Rock Ridge reader |
| cpio/mtree wire-control path boundaries | follow-on | `libarchive_oxide-core/src/format/{cpio,mtree}.rs`, `libarchive_oxide/src/transcode.rs`, `libarchive_oxide/tests/{stream_v2,mtree}.rs` | cpio direct writes and destination projection reject the exact `TRAILER!!!` end marker before output so an entry cannot disappear into archive termination; mtree octal-escapes leading comment markers and rejects absolute or NUL-containing entry paths before output because its reader intentionally accepts only relative NUL-free paths |
| 7z direct entry metadata and symlink projection boundaries | follow-on | `libarchive_oxide/src/{sevenz,transcode}.rs`, `libarchive_oxide/tests/{seek_stream_v2,transcode,sevenz_differential,format_write_options}.rs` | direct writes accept only File/Dir/Symlink plus NUL-free UTF-8 name bytes, exact nonzero permission modes, representable mtime, declared size, and symlink target; unsupported kinds, owner/inode/device/sparse/xattr/ACL/flags/checksum/encryption/comment/entry-extension fields, lossy mode/path values, nonzero directory size, and mismatched symlink size fail before entry output. Tar→7z symlink size is projected to the metadata-owned target and source payload events are counted but not written twice; independent `sevenz-rust2` and every coder/filter/encryption profile remain green |
| UDF Phase 1 read implementation | RM-306 follow-on | `libarchive_oxide/src/udf.rs`, `libarchive_oxide/tests/udf.rs`, `fuzz/{fuzz_targets/read_udf.rs,corpus/read_udf/seed.udf}` | read-only seek provider for 1.02/1.50/2.01: VRS/bridge priority, backup anchors, Main→Reserve/continued VDS with prevailing descriptors, Type 1 maps, FSD/root ICB, FE/EFE strategy 4, short/long/inline/chained/multi/sparse allocation, streamed FIDs, OSTA Unicode/timestamps, symlink/hardlink metadata, checked ranges and all applicable archive `Limits`; shared sync/engine/range/futures/Tokio parser and adversarial replay |
| UDF continued FSD and stream follow-on | RM-306 follow-on | `libarchive_oxide/src/udf.rs`, `libarchive_oxide/tests/udf.rs`, `libarchive_oxide/tests/fixtures/udf/PROVENANCE.md`, `fuzz/corpus/read_udf/seed.udf` | ECMA-167 Next Extent File Set Descriptor traversal with default file-set-zero/prevailing selection plus UDF 2.01 System Stream Directory and named-stream reads; safe synthetic archive paths and typed owner/kind/metadata extensions; tag checksum/CRC/location, partition bounds, FID order/version/long-ad/Unique ID, role-correct Stream/metadata flags, EFE Object Size, graph cycle/depth, and metadata/in-flight/path/entry limits are covered by deterministic positive/negative builders and stable fuzz replay |
| UDF 2.50/2.60 Metadata Partition follow-on | RM-306 follow-on | `libarchive_oxide/src/udf.rs`, `libarchive_oxide/tests/udf.rs`, `libarchive_oxide/tests/fixtures/udf/PROVENANCE.md` | Type-2 Metadata Partition Map parsing paired with its physical Type-1 map; bounded short-AD Metadata File translation across allocation-unit boundaries; shared/duplicate mirror validation with Integrity/Malformed-only fallback; optional Metadata Bitmap ICB/SBD validation; deterministic revision, missing/wrong-type, alignment, overlap, cycle, corruption, mirror, limit, seek/engine/range-provider tests |
| UDF Sparable Partition follow-on | RM-306 follow-on | `libarchive_oxide/src/udf.rs`, `libarchive_oxide/tests/udf.rs`, `libarchive_oxide/tests/fixtures/udf/{mkudffs-sparable-2.01.udf,PROVENANCE.md}`, `fuzz/corpus/read_udf/sparable-partition.udf` | UDF 1.50–2.60 Type-2 Sparable maps with profile-valid 16/32-block packets; validated packet-disjoint redundant Sparing Tables with highest-sequence agreement, corruption fallback, and the 65,535-byte descriptor-CRC cap; bounded whole-packet remapping across allocation continuations; UDF 2.50/2.60 Metadata-over-Sparable composition; deterministic malformed/range/overlap and exact capacity-based cumulative metadata-limit tests; public Seek/Engine/Range wiring; stable corpus replay; and independent `mkudffs` 2.3 interop evidence |
| Metadata-fidelity harness extension | RM-304 | `libarchive_oxide/tests/common/mod.rs` | additive `read_seq_with_arca` (sequential `ArchiveReader`), `MetaShape` (REAL kind + mode/uid/gid/mtime/link_target, no kind folding), `read_meta_seq_with_arca` / `read_meta_seek_with_arca`, `assert_producers_agree_seq`; the content-only `EntryShape` path is unchanged |
| tar producer corpus + metadata round trip | RM-304 | `libarchive_oxide/tests/interop_tar_meta.rs`, `libarchive_oxide/tests/fixtures/tar/PROVENANCE.md` | 3 producers (arca, `tar@0.4`, first-party raw ustar builder) × 2 consumers (arca sequential reader, `tar@0.4`); mode/uid/gid/mtime and symlink-target fidelity |
| Tar/cpio/ar/ZIP metadata lossless-or-error validation | follow-on | `libarchive_oxide-core/src/format/{tar,cpio,ar}.rs`, `libarchive_oxide/src/{zip_stream,transcode}.rs`, `libarchive_oxide/tests/{stream_v2,seek_stream_v2,transcode,zip_aes}.rs` | direct writers reject volume names, format-foreign extensions, unsupported kinds, and every typed entry field they cannot encode before emitting headers; Tar retains opaque global PAX plus last-wins comment multiplicity, typed entry comments/xattr/ACL/time, field-exact GNU sparse records, and Char/Block referenced-device major/minor through the 8-byte GNU base-256 maximum `2^56-1`. Global path/size/owner/time/xattr/ACL/sparse keys that cannot be prevalidated against future entries are rejected or become `ArchiveExtensions` loss; contradictory/malformed/untyped/unsupported sparse properties, missing/overflowing/wrong-kind device metadata, and other typed/raw or inode/flag/checksum/encryption conflicts fail before entry headers or become explicit `Devices` loss. Tar/cpio/ar/ZIP accept only 12-bit permission modes on direct writes; transcoding preserves the lower bits and reports `Mode` when a source supplies more instead of allowing a silent mask. Cpio retains numeric owner, non-negative whole-second mtime, inode/link/device, and dialect-correct CRC metadata while default-newc conversion rejects a missing size or a declaration above u32 before dispatch; ar retains its fixed-width regular-file mode/owner/mtime fields and rejects a missing or overflowing ten-digit total size including BSD inline-name bytes; ISO conversion likewise preflights its u32 file-size field. ZIP retains nonempty comments, bounded owner/time/mode metadata, metadata-owned unencrypted symlink targets, field-coherent 0x5455/0x000a/0x5855/0x7855 projections including NTFS creation/100 ns times, and applicable 0x7075/0x6375 path/comment values, reports empty archive/entry comments and target-size projections across Tar→ZIP, and avoids target double writes across ZIP→ZIP, while malformed/contradictory extras, post-directory-suffix pathname overflow, encrypted symlinks, indistinguishable empty typed comments, and unsupported typed fields fail closed |
| WARC synthesized path/mode transcode boundary | follow-on | `libarchive_oxide/src/transcode.rs`, `libarchive_oxide-cli/src/oxarchive.rs`, `libarchive_oxide/tests/transcode.rs`, `libarchive_oxide-cli/tests/oxarchive.rs` | WARC destinations require declared content sizes during projection, preserve WARC named-field extensions and streamed payloads, normalize their virtual filesystem mode to `0644`, and report every source archive path as `EntryPath` because the wire format regenerates collision-free record-ID/sequence paths instead of encoding source paths. Public WARC→WARC coverage fixes the report contract and `oxarchive convert --json` names the field `entry_path` |
| Destination-aware filesystem creation metadata | follow-on | `libarchive_oxide/src/create.rs`, `libarchive_oxide-cli/tests/oxarchive.rs` | the common streaming/seek filesystem builder projects host modification times to ZIP whole-second i32, ISO year-0–9999 10 ms, 7z 100 ns unsigned-FILETIME, cpio u32-second, and ar fixed-width-second boundaries; numeric owners are retained only within each destination's paired ID fields, and WARC virtual metadata is canonicalized. Direct writers remain lossless-or-error, while all 38 CLI command-contract tests prove ZIP encryption/compression and ISO/7z/XAR creation remain usable with real host metadata |
| cpio producer corpus + metadata round trip | RM-304 | `libarchive_oxide/tests/interop_cpio_meta.rs`, `libarchive_oxide/tests/fixtures/cpio/PROVENANCE.md` | 3 producers (arca `newc`, first-party raw `newc`, first-party raw `odc` — genuinely distinct on-disk framings) × 2 consumers (arca, first-party raw `newc` parser); mode/uid/gid/mtime plus a typed hardlink pair (File payload + Hardlink alias) |
| ar producer corpus + metadata round trip | RM-304 + follow-on | `libarchive_oxide-core/src/format/ar.rs`, `libarchive_oxide/src/transcode.rs`, `libarchive_oxide/tests/{interop_ar_meta,stream_v2}.rs`, `libarchive_oxide/tests/fixtures/ar/PROVENANCE.md` | 3 producers (arca, `ar@0.9`, first-party raw `!<arch>` builder) × 2 consumers (arca, `ar@0.9`); mode/uid/gid/mtime (ar is flat regular-files-only, so no dir/symlink fidelity). Control-looking short paths `/`, `/SYM64`, `/123`, and `#1/7` switch from ambiguous SysV fields to four-byte-padded BSD inline names and round-trip through both consumers; the shared padded-name helper also keeps transcoder ten-digit member-size preflight identical to the writer |
| ISO producer corpus + Rock Ridge metadata, multi-extent, interleaved, extended-attribute reads, and archive-volume metadata validation | RM-304 + follow-on | `libarchive_oxide/src/{iso_stream,seek_stream,transcode}.rs`, `libarchive_oxide/tests/{interop_iso_meta,iso_differential,seek_stream_v2,async_seek_v2,range_source}.rs`, `libarchive_oxide/tests/common/mod.rs`, `libarchive_oxide/tests/fixtures/iso/PROVENANCE.md`, `fuzz/fuzz_lib/src/lib.rs` | arca self round trip plus an external `xorriso`/`genisoimage`/`mkisofs` independent producer (graceful skip); Rock Ridge PX/TF/SL fidelity and bounded SUSP CE continuation read/write; consecutive extents, compact file-unit/gap patterns, and ECMA extended-attribute allocations stream over sync/futures/Tokio/range paths with physical/aggregate bounds, primary/Joliet descriptor geometry, declared volume bounds and sequence validation, logical-block record/padding validation, typed metadata/hostile cases, PVD-exact volume names through 32 bytes, lossless-or-error nonempty/non-trimmed system/application identifiers, and exact canonical unknown SUSP fields (including final-value replacement under an exact setter budget) with explicit transcoder loss reporting, parser-recognizable fuzz envelopes, and optional independent libarchive/bsdtar extraction of the fully mastered multi-extent fixture |
| ZIP Info-ZIP Unix uid/gid read | RM-308 | `libarchive_oxide/src/seek_stream.rs` | `zip_unix_owner` parses the Info-ZIP New Unix (0x7855) central body into `Owner` uid/gid; `zip_times` gains a 0x5855 (`UX`) access/modification-time arm. The central `UX` uid/gid trailer (a local-header layout) is deliberately not read to avoid a positional guess; both are bounded, structured-error walks reusing the shared `le16`/`.get()` guards |
| ZIP Extended-Timestamp / Unix uid/gid write-back | RM-308 + follow-on | `libarchive_oxide/src/zip_stream.rs` | a bounded structured-extra parser mirrors seek-reader precedence for 0x5455/0x000a/0x5855/0x7855; raw-covered fields must exactly match typed `EntryTimes`/`Owner`, while `push_extended_timestamp` and `push_infozip_unix` synthesize only uncovered fields. NTFS FILETIME creation and 100 ns values remain raw-backed; malformed or contradictory values fail before output; all bytes count against local/central metadata budgets |
| ZIP extra structured-interpretation tests | RM-308 + follow-on | `libarchive_oxide/tests/{seek_stream_v2,stream_v2}.rs` | typed-owner/time and Unicode path/comment reads, coherent raw no-duplicate round trips, partial-field synthesis with second-pass extension stability, NTFS creation/100 ns fidelity, applicable-Unicode and time/owner typed/raw conflict refusal, stale-CRC Unicode preservation, invalid UTF-8/truncation refusal, directory-suffix pathname overflow refusal, and short-field no-misread |
| ZIP extra 3x2 interop + metadata fidelity | RM-308 | `libarchive_oxide/tests/interop_zip_extra.rs` | three producers (arca from typed metadata, `zip@8.6.0`, raw builder embedding 0x7855/0x5455) × two consumers (arca, `zip@8.6.0`); asserts uid/gid/mtime fidelity through arca on both the raw producer and arca's own output; malformed/truncated extras stay covered by the existing `read_zip` fuzz target |
| Support-matrix ZIP metadata update | RM-308 + follow-on | `docs/support-matrix.md` | ZIP row records typed interpretation of Unicode/timestamp/Info-ZIP Unix extras and write synthesis; exact raw-extra validation rejects malformed IDs and container-owned ZIP64/AES fields rather than silently dropping them |

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
  the declared uncompressed size (or the LZMA end marker when bit 1 is set),
  matching the `zip` crate. Pinned preset 6 gives props byte 93 (lc=3, lp=0,
  pb=2) and an 8 MiB dict, reproducing CPython/liblzma's header near byte-for-byte;
  version-needed is 63 (APPNOTE 6.3.0). `lzma-rust2` exposes a pull-based
  `LzmaReader` that owns its source. The seek path therefore gives it a
  length-limited source and takes that source back at member end; the
  forward-only path uses the existing bounded request/response worker and a
  synthetic LZMA-alone header. Known-size entries feed no bytes beyond the
  local compressed extent. For descriptor entries, tokenized input is reported
  consumed only after the range decoder acknowledges the exact prefix it owned
  at EOS, leaving queued descriptor or encrypted authentication bytes in the
  caller's bounded pipeline. Signed/unsigned classic/ZIP64 descriptors compose
  with plain, ZipCrypto, and WinZip AES entries when the EOS convention supplies
  the codec boundary; a descriptor without EOS stays typed `Unsupported`.
  Neither path buffers the compressed member. Dictionary memory is validated
  before decoder construction and output is bounded incrementally by
  `decoded_total`. The writer drains
  `LzmaWriter`'s output through an in-crate
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
  `tests/zip_stream_read.rs` additionally covers the committed CPython fixture
  one byte at a time and through futures/Tokio adapters, both size conventions,
  plain/ZipCrypto/AES known extents, signed/unsigned classic/ZIP64 descriptors,
  CRC/size/authentication/truncation/property/dictionary/decoded limits, and the
  no-EOS descriptor rejection; the shared fuzz case continuously replays valid
  known-size and descriptor method-14 envelopes around mutated payloads.

## RM-306

- ADR-0013 (`docs/adr/0013-rar5-udf-deflate64-feasibility.md`) resolves the RAR5,
  UDF, and Deflate64 feasibility questions RM-300 and ADR-0012 delegated here. It
  is a feasibility-and-scope decision that lands no provider; each support-matrix
  cell still flips only when its provider is implemented.
- **Deflate64 (method 9):** read is a *go* via pinned upstream pure-Rust `deflate64`
  source compiled privately behind the codec-provider boundary (satisfies the C-free
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
  landed vendored `deflate64` 0.1.12 plus the in-tree UDF reader, the corresponding
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

- The original RM-304 slice lifts the RM-301 interoperability harness from content-only evidence to metadata fidelity for the sequential and disc formats;
  that initial slice made no `src/` runtime change.
  tar/cpio/ar already encode and decode their metadata (see `libarchive_oxide-core/tests/protocol_v2.rs`); RM-304 proves it through the high-level `ArchiveWriter`/`ArchiveReader` against independent producers and consumers.
- Harness extension (`tests/common/mod.rs`, additive — the content-only `EntryShape` path is untouched): `read_seq_with_arca` reads tar/cpio/ar through the non-seek `ArchiveReader` (the seek reader only indexes ZIP/ISO); `MetaShape` preserves the REAL entry kind (Symlink/Hardlink are no longer folded to File) and the typed mode/uid/gid/mtime/link-target; `read_meta_seq_with_arca` / `read_meta_seek_with_arca` project an archive into path-sorted `MetaShape`s; and `assert_producers_agree_seq` mirrors `assert_producers_agree` through the sequential reader.
  Producers/consumers stay bare `fn` pointers, so `no-dyn` and `#![forbid(unsafe_code)]` hold.
- **tar**: three producers (arca, the `tar` crate at 0.4, and a first-party raw ustar builder with a computed header checksum) agree on content through arca's sequential reader, and arca's output is accepted by both arca and the `tar` crate.
  Metadata fidelity asserts mode `0o640`, uid/gid, mtime, and a symlink target survive both arca's own writer and the `tar` crate's — the strongest,
  fully in-code slice.
- **cpio**: three producers (arca `newc`, a first-party raw `newc`, and a first-party raw `odc`) and two consumers (arca and a first-party raw `newc` parser).
  Honesty note: no mature pure-Rust cpio *producer* crate exists, so the third producer is a second first-party builder in a genuinely different on-disk dialect (octal `odc` vs hex `newc`, no padding vs 4-byte alignment) rather than a third-party crate — real on-disk-layout independence, not third-party-crate independence.
  Metadata fidelity covers mode/uid/gid/mtime and a typed hardlink pair (a payload-bearing File with `nlink=2` and its zero-size `Hardlink` alias with a `link_target`).
  Crc and the binary dialects are covered by `protocol_v2.rs`.
- **ar**: three producers (arca, the `ar` crate at 0.9, and a first-party raw `!<arch>` builder) and two consumers (arca and the `ar` crate).
  ar is flat regular-files-only (no directory or symlink concept), so fidelity is mode (masked to the low 12 bits on read)/uid/gid/mtime; names are kept short so all producers stay on the byte-compatible short-name path (long BSD/GNU names are covered in `protocol_v2.rs`).
- **ISO**: producer independence is fundamentally narrower — there is no usable pure-Rust independent ISO reader on every target (`iso9660` is a libcdio C binding; `cdfs` needs FUSE), confirmed by `iso_differential.rs`.
  Content interop is therefore an arca write → arca read self round trip, and the INDEPENDENT producer is an external mastering tool (`xorriso`/`genisoimage`/`mkisofs`, `-R -J`) that arca reads back, with a graceful skip when none is installed.
  Metadata fidelity round-trips mode/uid/gid/mtime and a symlink target through arca's DEFAULT Rock Ridge emission (PX/TF/SL, emitted unconditionally by `iso_stream.rs` and auto-detected by the reader), read via the seek reader.
  The follow-on continuation slice emits CE records when system-use fields exceed a directory record, packs their data into a dedicated region, and follows CE chains with image-range, cycle, nesting, in-flight, and metadata limits.
  A multi-sector split-SL fixture plus out-of-range and low-budget failures keep the claim gated.
- The multi-extent follow-on indexes consecutive directory records with the same file identifier until the final-section flag clears.
  It streams their physical extents in logical record order without reading intervening blocks and applies image-range, aggregate entry/decoded, persistent metadata, and allocation checks before delivery.
  Sync, futures-io, Tokio, and immutable range readers share the regression fixture; skip, missing-final, mismatched-identifier,
  out-of-image, invalid-padding, and interleaved-file failures are asserted with typed errors.
  A separate fixture starts from arca's fully mastered primary and Joliet image, patches both trees into noncontiguous sections, and is extracted by libarchive/bsdtar when present.
  The `read_iso` invariant additionally wraps every arbitrary input in a parser-recognizable two-section envelope, so stable replay exercises the new state transition rather than relying on random bytes to synthesize it.
- The interleaving follow-on stores only the file-unit and gap widths on each section, so metadata remains proportional to directory records rather than file size.
  Physical-span arithmetic is checked before indexing; delivery seeks across gaps at unit boundaries and `skip_entry` uses the final physical data position.
  A writer-mastered primary/Joliet fixture relocates a 5,000-byte file into three one-block units separated by two poison-filled blocks and exercises sync/futures/Tokio/range readers.
  A second fuzz envelope always crosses two gaps.
  Invalid gap-without-unit, interleaved-directory, out-of-image,
  entry/decoded-limit, skip, and extended-attribute-record cases are typed.
  The behavior is grounded in ECMA-119 6th edition sections 7.4.2–7.4.3 and 10.1.8–10.1.9; libarchive 3.8.4 ignores these two directory-record fields, so no independent-consumer interleaving claim is made.
- The extended-attribute follow-on implements ECMA-119 6th edition sections 7.4.6, 10.1.2, and 10.5.
  File, root-directory, and child-directory extents begin after the declared EA block allocation.
  The indexer reads only the fixed 250-byte header plus the checked application-use and escape-sequence lengths, keeping large padded allocations out of resident metadata.
  The final section supplies typed owner/group, read/execute mode, creation time,
  and modification time; each semantic record is also retained under the `iso-extended-attribute` namespace, and Rock Ridge fields take precedence.
  Unknown versions are typed unsupported, while inconsistent both-endian lengths, permission/record/protection flags, timestamps, reserved bytes, ranges, and memory budgets are malformed or limited before payload delivery.
  A writer-mastered primary/Joliet fixture exercises sync/futures/Tokio/range readers, and a fuzz envelope puts up to 1,024 arbitrary bytes in application use.
  Installed libarchive 3.8.4 ignores the EA length and extracts the record as payload, so no independent-consumer EA behavior claim is made.
- Directory traversal additionally enforces ECMA-119 section 10.1's logical-block layout: a directory record cannot straddle a 2,048-byte block,
  and every byte after the first zero-length padding marker through the end of that block must be zero.
  Focused adversarial tests place an otherwise valid record ten bytes before a boundary and poison later padding; validation reads no more than one block at a time.
- The volume-boundary follow-on validates each primary/Joliet `Volume Space Size` in both byte orders against the physical source, and requires the descriptor-set terminator to fit.
  The selected descriptor's declared byte length then bounds root/child directory extents, extended-attribute allocations, SUSP CE areas, and regular, multi-extent, or interleaved file spans.
  Tests distinguish an inert trailer (accepted) from any directory,
  metadata, or payload reference into that trailer (malformed), including a Joliet tree with a smaller declared volume.
- Volume-set handling validates nonzero, both-endian set sizes and sequence numbers in primary/Joliet descriptors, including the embedded root record,
  then checks every special, directory, and multi-extent section record against the selected descriptor.
  A current-volume member of a larger set is accepted;
  any record naming another volume stops with typed `Unsupported` before a local seek, while zero, out-of-set, or endian-inconsistent identifiers are malformed.
- Primary and recognized Joliet descriptors now share the same geometry gate:
  both-endian logical-block sizes must agree and equal 2,048, while the embedded root record must retain its fixed 34-byte layout, root identifier,
  directory-only flag, and zero file-unit/gap widths.
  Focused cases select a Joliet tree with a contradictory block size and independently corrupt every root geometry field.
- New dev-dependencies (test-only, no effect on the shipped crate's portable/C-free profile): `tar = "0.4"` and `ar = "0.9"`, both pure-Rust independent producers/consumers.
  Per-format `PROVENANCE.md` registries record each producer,
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
- The raw body bytes of every non-structural extra remain preserved in the
  `zip-extra` namespace, so typed fields are an additive view and their round
  trips stay byte-lossless. Container-owned ZIP64 and AES fields are derived
  from sizes/writer encryption settings and cannot be replayed as arbitrary
  metadata; direct writes reject them and transcoding records
  `EntryExtensions` loss. This avoids pretending that stripping and regenerating
  those fields preserved NTFS 100 ns precision or local/central-header details.
- Applicable Info-ZIP Unicode Path/Comment (0x7075/0x6375) bodies are checked
  against the CRC of the name/comment the writer will actually serialize. Their
  UTF-8 projection must equal that typed value; a different projection is
  `Unsupported` and invalid applicable UTF-8 is `Malformed`. A stale CRC remains
  inert and byte-preserved, which is required when re-encoding metadata already
  promoted by the seek reader. Directory `/` normalization happens before this
  CRC check and before `path_bytes`/u16 bounds, so suffix addition cannot create
  an unchecked path override or a 65,536-byte field.
- On write, a bounded structured-extra pass mirrors `zip_times` and
  `zip_unix_owner` precedence for Extended Timestamp (0x5455), NTFS (0x000a),
  Info-ZIP `UX` (0x5855), and `Ux` (0x7855). Every raw-covered field must exactly
  match its typed `EntryTimes`/`Owner` projection, so raw values cannot silently
  override caller intent; truncated timestamp/tag bodies are `Malformed`.
  `push_extended_timestamp` and `push_infozip_unix` then synthesize only fields
  not covered by raw metadata. This preserves coherent NTFS creation time and
  100 ns precision, supports a raw mtime plus typed-only atime, and keeps repeated
  read/write passes extension-idempotent. Unsupported partial/overflowing typed
  values remain `Unsupported`. Preserved and synthesized bytes are counted
  against the metadata and local/central extra-field budgets.
- `#![forbid(unsafe_code)]`, the `no-dyn` static-dispatch gate, and bounded memory
  are all preserved: the new parsers and emitters are plain functions with no trait
  object and no new dependency.
- Evidence: `tests/seek_stream_v2.rs` and `tests/stream_v2.rs` cover typed owner/
  time and Unicode reads, coherent no-duplicate preservation, partial-field
  synthesis with exact second-pass extensions, NTFS creation and 100 ns
  precision, typed/raw conflicts, applicable/stale/invalid Unicode extras,
  post-suffix pathname bounds, truncated UT/NTFS bodies, and short fields.
  `tests/interop_zip_extra.rs`
  proves content interop across three
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
- The 7z AES follow-on separates codec-generated `io::Error` values from genuine
  source failures before a seekable input enters an encrypted header or folder
  graph. Any unauthenticated decoder failure rejects only that password
  candidate and exhaustion reports `Integrity`; source read/seek errors carry a
  private marker through the graph and remain `Io`. `sevenz-rust2` AES options
  use fixed test-only salt/IV material, with material 96 locking the former
  random failure and an injected backward-seek read error proving propagation.

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
