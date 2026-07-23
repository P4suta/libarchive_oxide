# Support matrix

This document describes the current implementation. “Planned” never means
“supported”, and a format name alone does not imply every method, encryption
scheme, metadata field, or producer quirk is accepted.

## Archive containers

| Container | Access | Read | Write | Encryption | Metadata/method notes |
|---|---|---|---|---|---|
| tar | sequential | v7, ustar, pax, GNU | yes | none | pax extensions and GNU sparse; known-size entry creation |
| cpio | sequential | binary little/big endian, odc, newc, crc | yes | none | known-size entry creation |
| ar | sequential | GNU and BSD | yes | none | thin members are reported as external references and are never materialized automatically |
| ZIP/ZIP64 | seek or streaming | see [ZIP compression methods](#zip-compression-methods) grid | see grid | optional WinZip AES-256 AE-2; ZipCrypto not enabled by default | descriptors, ZIP64, Unicode path/comment, and extended/NTFS/Info-ZIP-UX timestamp extras are interpreted as typed metadata; Info-ZIP Unix uid/gid are surfaced when recorded in the central directory (as arca writes them) and synthesized on write; unknown extras are preserved verbatim |
| 7z | seek | LZMA/LZMA2, encoded headers, solid single-folder archives | yes | none (AES unsupported) | optional `sevenz`; multiple folders and general coder graphs are unsupported |
| ISO 9660 | seek | ISO 9660, Rock Ridge, Joliet | yes | none | UDF and continuation-area coverage are not complete |

### ZIP compression methods

Capability is a grid: each method is reported per direction (read/write) and per
codec profile (portable/native). A `—` cell is not a silent gap — a member using
that method returns a structured `Unsupported` error and still enumerates. Cells
that are a *tracked deficit* rather than a permanent limit are listed under
[Codec capability deficits](#codec-capability-deficits).

| Method | Code | Read (portable) | Read (native) | Write (portable) | Write (native) | Feature |
|---|---|:---:|:---:|:---:|:---:|---|
| Store | 0 | ✓ | ✓ | ✓ | ✓ | — |
| Deflate | 8 | ✓ | ✓ | ✓ | ✓ | — |
| Deflate64 | 9 | — | — | — | — | — |
| BZip2 | 12 | ✓ | ✓ | ✓ | ✓ | `bzip2` |
| LZMA | 14 | ✓ | ✓ | ✓ | ✓ | `xz` |
| Zstandard | 93 | ✓ | ✓ | — | ✓ | `zstd` (read) / `native-codecs` (write) |

Notes: BZip2 and LZMA are complete read+write on both profiles (`libbz2-rs-sys` /
`lzma-rust2`, both pure-Rust on portable). LZMA emits raw LZMA1 with the 9-byte
ZIP-LZMA header and an end-of-stream marker (general-purpose bit 1) and reads both
the end-marker and known-size conventions. Zstandard read is pure-Rust on both
profiles (`ruzstd` / `compression-codecs`); Zstandard *write* is `native-codecs`
only — see the deficit table for why, and note this is a tracked debt, not a
resting state. Deflate64 (method 9) is not yet implemented in either direction; per
[ADR-0013](adr/0013-rar5-udf-deflate64-feasibility.md) the read path is decided
(adopt the external pure-Rust `deflate64` decoder behind the codec-provider
boundary, landing in a follow-on slice) and write is a retired won't-do (no
pure-Rust encoder exists). Traditional ZipCrypto is not enabled by default.

7z BCJ/Delta, Deflate, BZip2, Zstandard, PPMd, AES, multi-folder, and arbitrary
coder-graph coverage remain roadmap work.

### Codec capability deficits

Per [ADR-0012](adr/0012-codec-capability-contract.md), a codec gap never bends a
core guarantee (`#![forbid(unsafe_code)]`, static dispatch, C-free portable
profile, bounded streaming, stable API) and is never a silent fallback: it is a
typed capability plus a *tracked deficit* with a declared resolution path.
Documenting a gap opens a debt; it does not discharge it. This is the complete
ledger — every other mainstream codec (deflate, bzip2, xz/LZMA, lz4) is complete
read+write on portable.

| Deficit | Surfaces as | Why | Resolution path | Tracking |
|---|---|---|---|---|
| Portable **streaming** zstd encode | ZIP write method 93 on `portable-codecs` → structured `Unsupported`; `native-codecs` write works | `ruzstd` ships only a one-shot whole-buffer encoder (`ruzstd::encoding::compress_to_vec`, used for outer-filter frames and `create --zstd`). It cannot emit a single ZIP member as a bounded stream without buffering the whole member, which would break the core bounded-memory guarantee. The engine refuses the path rather than weaken the guarantee. | A streaming, single-stream pure-Rust zstd encoder — upstream to `ruzstd` or a dedicated crate the engine consumes. | RM-307 → follow-on codec initiative |
| Deflate64 (method 9) | ZIP method 9 read/write → structured `Unsupported` (not yet implemented) | Read: a mature pure-Rust decoder (`deflate64`) exists but is not yet wired. Write: no pure-Rust encoder exists and demand is effectively nil (matches libarchive). | Read: adopt the external `deflate64` decoder behind the codec-provider boundary in a follow-on slice. Write: **won't-do**, retired per [ADR-0013](adr/0013-rar5-udf-deflate64-feasibility.md). | RM-306 / ADR-0013 |

RAR5 and UDF read scope is resolved by
[ADR-0013](adr/0013-rar5-udf-deflate64-feasibility.md): UDF is a scoped read-only
go (revisions 1.02/1.50/2.01 first, activated from the shared Volume Recognition
Sequence), pending its implementation slice; RAR5 read is feasible in principle,
but the provider is deferred in its entirety until a clean-room pure-Rust
decompressor exists, because `.rar` archives in the wild are almost always
compressed. CAB and XAR remain read-only targets tracked by RM-305. All four are
not yet implemented; each cell flips only when its provider lands.

## Outer compression filters

| Filter | Decode | Encode | Dependency profile today |
|---|:---:|:---:|---|
| gzip/DEFLATE | yes | yes | portable `miniz_oxide`; native libz |
| bzip2 | yes | yes | portable `libbz2-rs-sys`; native libbz2 |
| zstd | yes | yes | portable `ruzstd`; native libzstd |
| xz/LZMA2 | yes | yes | portable `lzma-rust2`; native liblzma |
| LZ4 frame | yes | yes | portable `lz4_flex`; native liblz4 |

`portable-codecs` is the dependency-verified default. `native-codecs` is an
explicit `--no-default-features` profile, and selecting both fails compilation.
Profile-less individual codec features remain portable. Sync, Pipeline,
futures-io, Tokio, create, and CLI paths share the same conformance and
malformed corpus; see [codec profile evidence](codec-profiles.md).

The portable zstd *encode* above is `ruzstd`'s one-shot frame encoder, which
serves outer-filter frames and `create --zstd`. It is deliberately not reused
for bounded-streaming ZIP-member writing (a single member must stream within the
memory budget), which is why ZIP method 93 write is `native-codecs` only; see
[Codec capability deficits](#codec-capability-deficits) and
[ADR-0012](adr/0012-codec-capability-contract.md).

## Compile-time providers

| Surface | Built-in compatibility | Downstream registration |
|---|---|---|
| format read | unchanged | sequential alternative `FormatProvider` |
| format write | unchanged | `ProviderArchiveWriter` / `create_registered` |
| outer codec read/write | unchanged | bounded alternative `CodecProvider` frames |
| engine events/inspect/plan/apply | unchanged | same concrete chain survives rewind |
| capability query | available/disabled/unknown | available/disabled/unknown |

Registration is static generic composition: there is no trait-object registry,
global mutable registration, dynamic library loading, or plugin ABI. Invalid
probe/progress contracts and ambiguous different-ID matches fail with typed
errors. External seek-native providers are not currently supported. See the
[provider contract and evidence](providers.md).

## Filesystem restoration

`ArchiveSession::apply_with_adapter` drives a compile-time `FilesystemAdapter`
after session identity, path normalization, policy, resource-limit, and
hardlink-order checks. Existing `apply(plan, cap_std::fs::Dir)` creates the
standard adapter. Every requested entry/metadata operation has an applied,
unsupported, refused, partial, or OS-error finding in `ApplyReport`; omitted
evidence is converted to `Partial`.

| Operation | Standard portable path | Linux reference path |
|---|---|---|
| regular file | temporary-sibling atomic publish | same, metadata applied by open descriptor |
| directory | no-follow creation/finalization | same |
| mode | Unix targets | yes |
| access/modification time | yes | yes, descriptor-based |
| numeric uid/gid | reported unsupported | yes; permission errors remain typed |
| xattr | reported unsupported | yes |
| POSIX ACL | reported unsupported | numeric access/default ACL text |
| sparse extents | Unix targets; Windows reported unsupported | logical and allocated-block evidence tested |
| symlink/hardlink | explicit policy only | explicit policy only |
| FIFO/socket/device | reported unsupported | explicit policy only |
| change/birth time, filesystem flags | reported unsupported | reported unsupported |

The default policy still rejects traversal, pre-existing destinations, links,
and special files. Commit failure removes the sibling without publishing an
invalid destination. See [the filesystem adapter contract](filesystem-adapters.md).

## Command-line surface

| Surface | Implemented contract | Bounded/atomic behavior |
|---|---|---|
| `oxarchive inspect` | human events or schema-versioned JSON Lines | streams `ReaderEvent`; no collected entry list; completion sentinel |
| `oxarchive plan` | human or advisory JSON | finite entry/metadata limits; never reusable apply input |
| `oxarchive apply` | human or JSON outcomes plus filesystem findings | same immutable session; per-file atomic commit |
| `oxarchive create` | tar/cpio/ar/zip; optional gzip/bzip2/xz/zstd/lz4 | common `CreateOptions`; 64 KiB copy buffer; file output staged and no-replace published |
| `oxarchive verify` | human or JSON digest/count result | streams payload events with checked counters |
| `oxarchive oci` | inspect/verify/apply over the shared layer engine; machine JSON only | bounded JSON-Lines inspection; digest verified before apply; `apply` needs a seekable layer |
| `oxarchive package validate` | `--type`-selected profile over the shared validators; one machine JSON record | bounded no-extract; shared typed findings and stable severity; deb/rpm accept `-`, ZIP-container profiles need a seekable file |
| `oxtar`, `oxcpio`, `oxcat`, `oxunzip` | documented compatibility subsets | shared exit 0/1/2, stdout/stderr, limits, and safe extraction contracts |

`create ARCHIVE=-` reserves stdout for archive bytes and can leave a partial
prefix on a late exit-1 failure. JSON inspection records already flushed remain
valid after a late parser error, but only `inspect_complete` marks success. See
the [CLI and streaming-output contract](cli-contract.md) and
[ADR-0008](adr/0008-bounded-cli-streams.md).

## Profiles

OCI layers, Debian packages, RPM payloads, and ZIP-based package families are
validation profiles built from the primitives above. A profile is only marked
supported when its container, codec, metadata, security, and interoperability
tests all pass. Registry communication and authentication are outside the OCI
layer-engine scope.

Package validation is bounded and never extracts or whole-buffers an untrusted
package. Two verdicts are reported separately and must not be conflated: a
*container-readable* result means the outer container structure could be parsed
at all, and a *profile-valid* result means the package additionally satisfied
its profile with no blocking findings. A readable container can still fail its
profile, and "planned" means neither verdict is produced yet.

| Profile | Package container | Container-readable check | Profile-valid verdict | Notes |
|---|---|---|:---:|---|
| Debian `.deb` | `ar` with leading `debian-binary`, then `control.tar.*` and `data.tar.*` | yes | yes | bounded no-extract; inner tarballs stored plain or under one gzip/xz/zstd/bzip2 filter; member order, duplicates, unsafe names/paths, truncation, and decompression bombs are typed findings; a method this build cannot decode is a capability finding, not a hard failure |
| RPM | lead + signature/main header + cpio payload | yes | yes | bounded no-extract; the fixed 96-byte lead and both RPM headers are parsed by a bounded hand-written parser that refuses a header bomb before it is allocated; cpio payload stored plain (`none`) or under one gzip/xz/zstd/bzip2 filter; invalid lead/header magic, an oversized header, a `PAYLOADFORMAT` other than `cpio`, a detected filter that disagrees with `PAYLOADCOMPRESSOR`, unsafe/duplicate cpio entry paths, truncation, and decompression bombs are typed findings; a method this build cannot decode is a capability finding, not a hard failure; signature and digest verification remain follow-on work |
| Alpine `apk` | signed control/data `tar.gz` segments | planned | planned | |
| Java `JAR` | ZIP with `META-INF/MANIFEST.MF` | yes | yes | bounded no-extract; the central directory is read for member names, order, methods, and encryption flags without decompressing any payload; unsafe/duplicate paths, encryption, an undecodable method, and a decompression bomb (summed declared uncompressed size over the budget) are typed findings |
| Android `APK` | ZIP with root `AndroidManifest.xml` | yes | yes | bounded no-extract; requires root `AndroidManifest.xml`; detects the v1 (`META-INF/*.SF` + `*.(RSA\|DSA\|EC)`), v2, and v3 signing schemes (the APK Signing Block magic before the central directory is confirmed and its id-value pairs are scanned under a cap for the v2/v3 ids); signature findings are informational and do not invalidate the profile; shares the ZIP-structure defenses of the JAR profile |
| Apple `IPA` | ZIP with `Payload/*.app` | yes | yes | bounded no-extract; requires a `Payload/<name>.app/Info.plist` bundle (structure only; the code signature lives inside the `.app`); shares the ZIP-structure defenses of the JAR profile |
| `MSIX`/APPX | ZIP with `OPC`/`AppxManifest.xml` | yes | yes | bounded no-extract; requires `AppxManifest.xml`, `[Content_Types].xml`, and `AppxBlockMap.xml`; an `AppxSignature.p7x` member is detected as an informational signature finding; shares the ZIP-structure defenses of the JAR profile |
| NuGet `.nupkg` | ZIP with `[Content_Types].xml` and one root `.nuspec` | yes | yes | bounded no-extract; requires `[Content_Types].xml` and exactly one root `*.nuspec`; shares the ZIP-structure defenses of the JAR profile |
| Python `Wheel` | ZIP with `*.dist-info/{METADATA,RECORD,WHEEL}` | yes | yes | bounded no-extract; requires the three `*.dist-info` members; shares the ZIP-structure defenses of the JAR profile |
| `EPUB` | ZIP with `mimetype` and `META-INF/container.xml` | yes | yes | bounded no-extract; the first member must be a stored `mimetype` whose body is `application/epub+zip` (the only member body read, and only the media-type length), plus `META-INF/container.xml`; a compressed, misordered, or wrong-bodied `mimetype` is a typed finding |

The Debian profile is exercised by twelve bounded validation tests
(`tests/package_deb.rs`), the RPM profile by ten (`tests/package_rpm.rs`), the
four ZIP-container profiles (JAR, NuGet, Wheel, EPUB) by nineteen
(`tests/package_zip.rs`), and the three OS/app profiles (APK, IPA, MSIX) by
twenty-two (`tests/package_app.rs`); all are described in
[ADR-0010](adr/0010-package-profiles.md).

The `oxarchive package validate PACKAGE --type <profile>` CLI surface (RM-215)
drives these same validators and renders their shared typed findings and stable
severity as one `package_validation` JSON record, re-implementing no
package-structure interpretation. The record reports `container_readable` and
`profile_valid` as the two separate verdicts named above, so the CLI never
conflates them; exit is 0 when the profile is valid, 1 when the container was
read but the profile was not satisfied, and 2 on a usage error. The `deb` and
`rpm` profiles accept `-` for standard input; the ZIP-container profiles require
a seekable file. It is exercised by nine CLI contract tests
(`libarchive_oxide-cli/tests/package_cli.rs`); see the
[CLI and streaming-output contract](cli-contract.md).
