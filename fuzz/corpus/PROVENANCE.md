<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Fuzz seed corpus provenance

The `read_tar` corpus is also reused by that target's WARC harness. Each seed
is both offered directly to the explicit WARC reader (malformed-path coverage)
and wrapped as the content block of a length-correct WARC 1.1 record
(deep streaming coverage). This adds WARC fuzz and stable-replay evidence
without increasing the target inventory or duplicating corpus data.

The directories below are the first-party seed inputs supplied to local
`cargo-fuzz`, deterministic stable replay, and OSS-Fuzz. Seed contents are
published to OSS-Fuzz and may be incorporated into generated corpora or crash
research, so only redistributable synthetic or explicitly attributed inputs
belong here.

## Origin and license

- `seed.*`, `minimal.hex`, `empty-*.hex`, `lead.hex`, and the round-trip
  `seed.bin` inputs are deterministic, synthetic fixtures committed by
  libarchive_oxide contributors. The `.hex` inputs are textual encodings decoded
  by `fuzz_lib` before validation.
- `roundtrip_xar/seed.bin` drives the bounded XAR Store writer through the same
  deterministic entry synthesis and adversarial mutation stream as the other
  seek-writer round trips.
- `codec_base64/rfc4648.txt` is the RFC 4648 encoding of the synthetic ASCII
  string `foobar`; it is a first-party deterministic seed.
- `codec_uuencode/cat.txt` is the canonical uuencoding of the synthetic ASCII
  string `Cat`; it is a first-party deterministic seed.
- `codec_lzop/compressed-match` is a first-party textual `hex:` fixture.
  It contains a deterministic lzop header and one 100-byte output block encoded
  as one literal, a two-byte distance-one match, and a 97-byte distance-one M3
  match, with exact Adler-32 checksums and an end marker. It was constructed
  directly from the public lzop framing and LZO1X command grammar; no producer
  program or third-party content is redistributed.
- The package_rpm/wrapper-empty.hex seed is a first-party textual hex fixture
  with the 96-byte RPM lead, empty signature header, empty main header, and
  empty payload. It exercises the bounded outer-wrapper decoder before
  mutations smash the big-endian header counts and signature padding.
- Hash-named files in `codec_xz` and `codec_zstd` are codec regression inputs
  introduced with commits `b7c3843` and `fe14bab`, respectively. The latter
  commit records the Zstandard panic-abort regression; neither commit records a
  standalone byte-generation command.
- `codec_lzw/compress-hello.hex` is the exact Unix `compress(1)` stream produced
  by `printf "hello world" | compress -c | xxd -p`. The textual `hex:` wrapper
  is decoded by `fuzz_lib` before exercising the bounded portable LZW decoder.
- `codec_lzw/bsdtar-seed-tar.hex` is a 165-byte `.Z` stream produced by
  bsdtar 3.8.4 using
  `tar -acf seed.tar.Z -C fuzz/corpus/extraction_plan seed.txt`. Its decompressed
  tar contains the first-party `seed.txt` path-policy fixture. The compressed
  SHA-256 is
  `E1D4B4626FF85F13FEBABA6F58724065092831DF234E2D698E4540D84469A56F`.
- `codec_lzip/bsdtar-seed-tar.hex` is the exact 137-byte lzip stream produced
  by bsdtar 3.8.4 / libarchive 3.8.4 with liblzma 5.8.1. It contains the same
  first-party `seed.txt` payload in a ustar archive, advertises an 8 MiB lzip
  dictionary, and has SHA-256
  `1F27F1C23757ADBAE2C2F0E55878C7313191958739EC6303C82BCB87CED1F384`.
  The byte-exact command and independent `tar -tf` / `tar -xOf` evidence are
  recorded in `libarchive_oxide/tests/fixtures/lzip/PROVENANCE.md`. This is a
  stable-replay corpus only; no cargo-fuzz target is added or run in this
  slice.
- `codec_lzma/lzma-rust2-hello.hex` is the 36-byte LZMA-alone example published
  in the Apache-2.0 `lzma-rust2` 0.18.0 `LzmaReader` documentation. It decodes
  to the ASCII string `Hello, world!`, uses the conventional properties byte
  and 8 MiB dictionary, and declares an unknown uncompressed size so mutations
  exercise the end-marker path. The textual `hex:` wrapper is decoded by the
  shared fuzz harness.
- `read_7z_graph` contains synthetic archives covering arca and independently
  generated coder-graph shapes. Commit `b7dea0b` records arca and
  `sevenz-rust2` as the producers used for those differential scenarios; their
  payloads contain no third-party content.
- `read_iso/seed.iso` is a 59,392-byte deterministic first-party ISO image
  (SHA-256
  `E00C198564887F0F84D81304B1B14FAA0E1EACAE9797207782CE110F8D9CACB8`).
  In addition to offering every seed and mutation directly to the seek parser,
  the shared invariant wraps up to 1,024 arbitrary input bytes in a
  parser-recognizable first-party PVD/root-directory envelope with one logical
  `FUZZ.BIN` split across two noncontiguous file sections. This guarantees
  bounded multi-extent indexing, cross-gap seek, streamed reconstruction, and
  zero-length final-section coverage on every replay without adding third-party
  bytes. A second first-party envelope repeats bounded arbitrary input to 4,097
  bytes and records it in three one-block file units separated by two poison
  gaps, guaranteeing interleaved seek/reconstruction coverage on every replay.
  A third envelope converts the same image to a one-block extended-attribute
  allocation, stores up to 1,024 arbitrary input bytes as bounded application
  use, and shifts the 4,097-byte payload behind it. This guarantees version,
  both-endian length, permission, raw-record, and data-offset coverage.
  The separately tested fully mastered primary/Joliet fixtures are retained as
  Rust-generated test data rather than duplicating them in the corpus.
- `read_udf/seed.udf` is generated by the first-party UDF builder documented in
  `libarchive_oxide/tests/fixtures/udf/PROVENANCE.md`. It reaches a continued
  File Set Descriptor sequence plus UDF 2.01 named and system streams. Its
  SHA-256 is
  `1894a8f6cfa16dbc1e0474f11adb99d0a89a9031036cb64483a16a5e263c750a`
  and its size is 1,433,600 bytes.
- `read_udf/metadata-partition.udf` is generated by the same first-party
  builder. It is a UDF 2.60 image with a Type-2 Metadata Partition Map,
  two allocation units, duplicate Metadata Mirror File allocations, and a
  Metadata Bitmap File. Its SHA-256 is
  `92d29e6fa775626141c337120710366373c3f453d676c78b6829857004fd1c5b`
  and its size is 1,433,600 bytes.
- `read_udf/virtual-vat.udf` is a deterministic UDF 2.60 Virtual Partition
  image from that builder. It retains split Allocation Extent continuations
  and bounded Previous VAT history. Its SHA-256 is
  `1424FCB3A1B6898C212C4B2F4A43FE8B90204E4B8F340F1CBEDDE333300F2696`
  and its size is 1,433,600 bytes.
- `read_udf/sparable-partition.udf` is a deterministic UDF 2.60 Sparable
  Partition image from that builder. Two Sparing Table generations make
  highest-sequence selection mutation-reachable; two prevailing packet remaps
  cover both normal ICB/data reads and an Allocation Extent continuation
  boundary, while the original packets are zeroed. Its SHA-256 is
  `66F3406ED6F026BD950F9CE1F808B63007B0368775BDC29D5C3A9C6A380A8319`
  and its size is 1,433,600 bytes.
- `read_cab/lzx_makecab_history.hex` is the exact 640-byte Microsoft makecab
  fixture recorded in `libarchive_oxide/tests/fixtures/cab/PROVENANCE.md`
  (SHA-256
  `CD46014EED4CBAA5CD42D761A4F19BD62B95F40BAD6722AAB5949F0EE305813D`).
  `lzx_e8_sentinel.hex` is a first-party hostile mutation of that fixture.
- `read_cab/lzx_libmspack.hex` is the exact 379-byte
  `mszip_lzx_qtm.cab` from the LGPL-2.1-or-later libmspack test corpus (SHA-256
  `0CE0B55FE705B744D41BB361170C0467DB30DA0C7F9BDD386D5DADE71A78E171`);
  its upstream URL and redistribution attribution are recorded in the same
  CAB provenance file.
- `read_cab/quantum_libmspack_history.hex` is the exact 285-byte
  `cve-2010-2801-qtm-flush.cab` from the LGPL-2.1-or-later libmspack/cabextract
  regression corpus (SHA-256
  `78BB4C9540E36D3D4228E22CDFF0A5677F9C2DDDC4239C322277D0B9125D8364`).
  Its 16 Quantum CFDATA blocks exercise retained arithmetic-model and window
  state; full provenance is recorded in the same CAB provenance file.
- `read_cab/two_volume_store.hex` is a deterministic first-party two-cabinet
  Store fixture containing one three-byte file split across physical CFDATA
  records. It uses the fuzz harness's versioned `OXCV 01` envelope: a one-byte
  volume count followed by little-endian `u32` lengths and exact cabinet bytes.
  The decoded 203-byte envelope has SHA-256
  `B829108ED61744587CEA4B907C57D85B268D04A2DB37DE71C40675817B6DD45A`.
  The seed exercises resolver, continuation, logical-CAB synthesis, and lazy
  cross-volume payload reads without adding another cargo-fuzz target.
- `read_rar_legacy/payload.txt` is a first-party ASCII payload. The shared
  invariant offers it directly to the bounded RAR 3.x/4.x parser and also
  wraps up to 256 KiB in a checksum-correct Store archive. With the `rar`
  feature it additionally decodes the compact raw RAR3 member recorded in the
  legacy RAR fixture provenance on every replay. The envelope is
  derived from public wire-format facts in the BSD-2-Clause libarchive reader;
  it contains a checksum-verified recovery block, a regular entry with
  extended mtime and raw file-header metadata, a main-header encryption-version
  field, and a CRC-preflighted stored Unix symlink. A parallel valid encrypted
  file envelope derives its known method, salt presence, and bounded ciphertext
  from the same input, asserts encrypted entry metadata, and requires typed
  `Unsupported` before ciphertext can escape as entry data. A header-encryption
  envelope derives version presence and value from the input, asserts raw
  archive metadata, and stops before ciphertext can be parsed as a plaintext
  header. The corpus payload itself contains no external bytes or user data;
  the fixed compressed invariant has the separate on-disk provenance described
  above and contains no RARLAB program or UnRAR source.
- `read_rar_legacy/ssokolow-rar3-solid.hex` is a byte-identical copy of the
  CC0-1.0 `ssokolow-rar3-solid.cbr.hex` fixture documented under
  `libarchive_oxide/tests/fixtures/rar-legacy/PROVENANCE.md`. Its decoded
  381-byte RAR3 archive SHA-256 is
  `610376CFA11EC11BF55CD117F5D5B83DD11DDED6AAD2F825B41DBE84D7F3098D`.
  The portable replay mutates every truncation and byte window around the real
  PPMd-H headers/range stream while retaining the same independent two-member
  solid interoperability oracle.
- `read_rar_legacy/libarchive-rar3-filter.rar` is a byte-identical copy of the
  BSD-2-Clause standard-VM-filter fixture documented under
  `libarchive_oxide/tests/fixtures/rar-legacy/PROVENANCE.md`. Its 94,301-byte
  archive SHA-256 is
  `B058412ADCD3329A868CB66561A224EB0ACF22AD2D380EF5D9E17E432A47D6A8`.
  Stable replay uses bounded strided truncation/field-smash samples across the
  complete archive; nightly coverage-guided fuzzing remains unrestricted.
- `read_rar5/payload.txt` is a first-party ASCII payload. The shared fuzz
  invariant first offers it directly to the explicit bounded RAR5 parser, then
  deterministically wraps its first 256 KiB in a checksum-correct RAR5 Store
  archive derived solely from RARLAB's public technote. With the `rar` feature
  it additionally decodes the compact raw generation-0 member recorded in the
  RAR5 fixture provenance on every replay. The corpus payload itself contains
  no external bytes or user data; the fixed compressed invariant contains no
  RARLAB program or UnRAR source. Arbitrary and mutated inputs therefore reach a
  valid main-header archive name/creation/locator path, CRC-verified UTF-8
  archive-comment service, file-header/data-CRC path, high-precision time,
  numeric Unix owner, unknown-extra parsing, child-associated CRC-verified ACL
  and alternate-stream services, a generation-1 solid empty Store continuation
  with the largest fractional dictionary step, a CRC-verified/skipped quick-open
  cache, and a declared CRC-verified/skipped recovery record after the file. A
  parallel valid envelope derives its file-encryption record fields from the
  same bounded input, asserts encrypted entry metadata, and requires typed
  `Unsupported` before any ciphertext can escape as entry data. Another valid
  envelope derives header-encryption flags and its KDF-count byte from the same
  input, asserts raw archive metadata, and requires typed `Unsupported` before
  encrypted header bytes can be parsed as plaintext. A
  second fixed one-byte envelope uses the official BLAKE2sp known-answer value,
  so hash-record parsing and successful streaming verification are also reached
- `read_rar5/rarfile-rar5-data-password.rar` is a byte-identical copy of the
  ISC-licensed `rarfile` revision
  `c4bb54b3aa6d8316b77e8d15947bd59e27b6f9b5` fixture `rar5-psw.rar`, already
  documented under `libarchive_oxide/tests/fixtures/rar5/PROVENANCE.md`. Its
  SHA-256 is
  `b6840e95152a1c3b5acd736dc34f988509866f04158b67da1b5a29e166a31355`.
  The shared harness supplies the fixture password `password`, so stable replay
  and nightly mutations reach bounded PBKDF2, password verification, AES-CBC,
  compressed and Store payload authentication, and the no-plaintext-before-
  authentication invariant instead of stopping at encrypted metadata.
  on every replay in addition to malformed-container parsing.
- `read_lha/lhmelt-level2.hex` is the textual `hex:` form of the 203-byte
  LHMelt 1.65.3.6 level-2 fixture retained at
  `libarchive_oxide/tests/fixtures/lha/lhmelt-1.65.3.6-h2-subdir.lzh.hex`.
  Its upstream commit, producer, payload, redistribution basis, and SHA-256 are
  recorded in that fixture directory's `PROVENANCE.md`. The shared invariant
  also wraps every input in a checksum-correct, first-party level-0 Store
  envelope behind a 97-byte synthetic MZ SFX prefix, asserts its reported
  offset, and forces arbitrary inputs through a recognizable LH5 header.
- `read_lha/unlha32-lhx.hex` is the textual form of the 6,903-byte
  UNLHA32.DLL 2.67a level-2 `-lhx-` fixture retained at
  `libarchive_oxide/tests/fixtures/lha/unlha32-2.67a-h2-lhx.lzh.hex`.
  Its immutable upstream commit, compressed-member metadata, SHA-256, and
  conservative GPL annotation are recorded in that fixture directory's
  `PROVENANCE.md` and `REUSE.toml`.
- `read_lha/pmarc-pm1.hex` and `read_lha/pmarc-pm2.hex` are textual copies of
  the Lhasa PMArc 1.24/2 fixtures retained under
  `libarchive_oxide/tests/fixtures/lha/`. Their immutable upstream commit,
  producer descriptions, archive SHA-256 identities, independent decoded
  length/CRC32 values, and conservative GPL annotation are recorded in that
  fixture directory's `PROVENANCE.md` and `REUSE.toml`.
- `read_lha/compcol-lh2.hex` is the textual form of the 79-byte first-party
  level-0 LH2 vector retained at
  `libarchive_oxide/tests/fixtures/lha/compcol-0.6.8-lh2-level0.lzh.hex`.
  Its exact generator version, plaintext, sizes, CRC16, SHA-256, and
  same-codec-evidence limitation are recorded in that fixture directory's
  `PROVENANCE.md` and ADR-0034.
- `read_lha/first-party-lh3.hex` is the textual form of the 74-byte first-party
  level-0 LH3 canonical-tree/match vector retained under
  `libarchive_oxide/tests/fixtures/lha/`. Its exact bitstream construction,
  decoded body, CRC16, SHA-256, non-independent status, and negative bsdtar
  3.8.4 result are recorded in that directory's `PROVENANCE.md` and ADR-0035.
- `package_alpine/alpine-keys-2.5-r0.apk` is the exact 13,390-byte MIT-licensed
  package from Alpine Linux v3.22 `main/x86_64` (SHA-256
  `1069FA68769607690E46B0D689F1AD9B5E346BE2752ECE313685B4F29EC70E25`).
  Its immutable URL, signing key, canonical signer fingerprint, and independent
  `apk verify` evidence are recorded in
  `libarchive_oxide-package/tests/fixtures/alpine_apk_v2/PROVENANCE.md`.
- `package_app/aosp-v2-rsa.apk` and `package_app/aosp-v3-rsa.apk` are exact
  Apache-2.0 AOSP `platform/tools/apksig` reference fixtures at commit
  `184702d9d18877edf9e5296c4e191cf0aa2b5fbb`; their SHA-256 values are
  `2670D3A8EC0B5F0BE3AC33527A3AA6704C244A1B86CB5E42A6B03596414DF383`
  and
  `6E606307A39C826330DB293A63C677566265D593BCB9B5C6FA58B34F86102668`.
  Full provenance is recorded in
  `libarchive_oxide-package/tests/fixtures/android_apk_v2_v3/PROVENANCE.md`.
- `package_app/aosp-v31-rotation.apk` and
  `package_app/aosp-v31-wrong-lineage.apk` are exact Apache-2.0 AOSP
  `platform/tools/apksig` v3.1 targeted-rotation fixtures from that same commit.
  Their SHA-256 values are
  `5D6554386A76C453499B6BB6E3A4B183EB5098F89058FEDBEC101C39588EDC6B`
  and
  `26F7571DAB499D3D9EF6E87EA0564E315F88EA5F593263AA54BB2E648D77C69C`.
  The first verifies a two-certificate SDK 24..33 / 34..MAX rotation; the
  second carries an incorrect lineage key and must fail closed. Full provenance
  is recorded in
  `libarchive_oxide-package/tests/fixtures/android_apk_v2_v3/PROVENANCE.md`.
- `package_app/apk-v4-cts-mutations.hex` is a first-party one-byte selector
  that drives bounded offset/XOR mutations over the exact AOSP CTS v4.0 APK and
  `.idsig` pair already retained in
  `libarchive_oxide-package/tests/fixtures/android_apk_v4/`. The selector
  contains no copied producer bytes; the pair's commit, Apache-2.0 license,
  sizes, and SHA-256 identities are recorded in that directory's
  `PROVENANCE.md`.
- `package_app/microsoft-test-windows.msix` is the exact 1,948-byte
  `TestWindows.msix` fixture from Microsoft’s MIT-licensed MSIX reference SDK
  at commit `efeb9dad695a200c2beaddcba54a52c8320bd135` (SHA-256
  `F9B5C5A4A43A31557242C34C1C2CD74BC04671DA70FB8B6AD25D45691160EA61`).
  Full provenance is recorded in
  `libarchive_oxide-package/tests/fixtures/msix_blockmap/PROVENANCE.md`.
- `extraction_plan/seed.txt` is a first-party path-policy spelling added with the
  OSS-Fuzz bundle. The `windows-*.txt` inputs are first-party deterministic
  selectors for case, trailing-dot, trailing-space, and NFC/NFD destination
  identity mutations generated inside `fuzz_lib`.
- `read_tar/mtree-v2.txt` is a first-party signed mtree v2 manifest derived
  from the public FreeBSD `mtree(5)` grammar. It exercises auto-detection,
  defaults, octal pathname escapes, and unknown-keyword preservation through
  the shared sequential archive fuzz target. Stable-test provenance and the
  optional bsdtar 3.8.4 differential procedure are recorded in
  `libarchive_oxide/tests/fixtures/mtree/PROVENANCE.md`.
- `roundtrip_tar/seed.bin` now drives both bounded tar and WARC sequential
  writer/reader invariants. WARC record IDs and dates are deterministic
  first-party metadata synthesized inside `fuzz_lib`; no additional producer
  bytes or user data are stored in the corpus.

First-party corpus files are covered by the repository `REUSE.toml` override as
`MIT OR Apache-2.0`. The libmspack exception retains its upstream
LGPL-2.1-or-later attribution, and the Alpine seed retains the package's MIT
license. The two AOSP APK seeds retain Apache-2.0, and the Microsoft MSIX seed
retains MIT. No producer program or user data is redistributed. Early corpus
commits without byte-for-byte generator commands are coverage starting points
rather than independent interoperability evidence.

## Maintenance policy

- Keep at least one non-empty file in every directory named by `cargo fuzz
  list`; `oss-fuzz/build.sh` enforces this correspondence.
- Keep individual seeds below the common 2 MiB OSS-Fuzz input ceiling.
- Prefer minimal inputs that reach distinct parser, codec, extraction, or package
  verifier states.
- Record a producer, exact command/version, digest, and redistribution basis
  here before adding externally generated bytes.
- When a crash is fixed, minimize its reproducer, add it to the matching target
  directory, and retain the regression in stable corpus replay.
