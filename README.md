# libarchive_oxide

[![CI](https://github.com/P4suta/libarchive_oxide/actions/workflows/ci.yml/badge.svg)](https://github.com/P4suta/libarchive_oxide/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/libarchive_oxide.svg)](https://crates.io/crates/libarchive_oxide)
[![docs.rs](https://img.shields.io/docsrs/libarchive_oxide.svg)](https://docs.rs/libarchive_oxide)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Safe-Rust archive reading, writing, compression, and extraction.

This project is independent of the upstream
[libarchive](https://www.libarchive.org/) project. It is not a binding.
Project-owned crates forbid unsafe code. The default codec profile is C/FFI-free;
an explicit native performance profile is also available. See [Codec backends](#codec-backends).

## Support

| Format | Current read support | Current write support | Important limits |
|---|---|---|---|
| tar | sequential v7/ustar/pax/GNU | sequential | known-size entries; GNU sparse supported |
| cpio | sequential binary/odc/newc/crc | sequential | known-size entries |
| ar | sequential GNU/BSD | sequential | thin references are identified, never followed |
| ZIP/ZIP64 | seek, Store/Deflate/Deflate64/BZip2/Zstandard/LZMA; bounded payload events | streaming with descriptors on both codec profiles (Deflate64 is not a write-method option) | optional WinZip AES write for Store/Deflate and read for Store/Deflate/Deflate64 |
| 7z | seek, LZMA/LZMA2/PPMd7/Deflate/BZip2/Zstandard with BCJ/Delta/BCJ2 graphs | seek | optional `sevenz`; PPMd7 and bounded four-stream BCJ2 are read-only |
| ISO 9660 | seek, Rock Ridge/Joliet with bounded SUSP continuation traversal | seek, including generated CE continuation areas | single-extent file payloads |
| UDF | seek, read-only 1.02–2.60 | none | 2048-byte optical images; continued/prevailing File Set Descriptors, named/system streams, external EA spaces, Metadata Partition translation/mirror recovery, 1.50+ Sparable Partition packet remapping (including Metadata-over-Sparable), and 1.50/2.00+ Virtual Partition/VAT translation |
| Microsoft CAB | seek, Store/MSZIP/Quantum/LZX | none | all four standard methods are read-only; `advanced::CabVolumeReader` resolves continuation through a caller-owned bounded `VolumeSet`, while the ordinary single-source reader rejects it |
| empty | sequential zero-byte archive | none | recognized only at EOF with no decoded bytes |
| raw | explicit sequential single `data` entry | none | never auto-detected; decoded byte limits apply |
| WARC | sequential WARC 1.0/1.1 records | none | exact CRLF signature/framing; mandatory bounded `Content-Length`; named fields preserved |

| Outer compression | Decode | Encode | Current backend note |
|---|:---:|:---:|---|
| gzip/DEFLATE | yes | yes | portable `miniz_oxide`; native libz |
| bzip2 | yes | yes | portable `libbz2-rs-sys`; native libbz2 |
| zstd | yes | yes | portable `ruzstd`; native libzstd |
| xz/LZMA2 | yes | yes | portable `lzma-rust2`; native liblzma |
| LZ4 frame | yes | yes | portable `lz4_flex`; native liblz4 |
| Unix `compress(1)` / `.Z` | yes | no | bounded portable `compcol` LZW; writer is absent |

The [detailed support matrix](docs/support-matrix.md) distinguishes archive
dialects, compression methods, encryption, metadata, and unsupported cases.
Signatureless raw input must be selected explicitly with
`ArchiveReader::with_format(input, FormatId::Raw)` or
`ArchiveEngine::open_with_format`; it is never used as a detection fallback.
WARC records become collision-free `warc/<sequence>/<encoded-record-id>.record`
entries (falling back to the sequence when the identifier exceeds the path
budget), and every validated named field is retained in the `warc` extension
namespace.
The [Modern Replacement roadmap](docs/modern-replacement.md) defines the
larger goal without presenting planned formats as implemented.

## Installation

```toml
[dependencies]
libarchive_oxide = "0.2"
```

For `no_std`:

```toml
[dependencies]
libarchive_oxide-core = "0.2"
libarchive_oxide-codecs = { version = "0.2", features = ["gzip", "zstd", "lz4"] }
```

CLI tools:

```sh
cargo install libarchive_oxide-cli --locked

# Unified safe workflow
oxarchive inspect artifact.tar.zst
oxarchive plan --json artifact.zip
oxarchive apply artifact.tar.gz destination
oxarchive create --format tar --filter zstd artifact.tar.zst input/
oxarchive verify artifact.7z
oxarchive package validate artifact.apk --type android-apk
oxarchive package validate artifact.apk --type android-apk \
  --idsig-file artifact.apk.idsig --trusted-signer-sha256 <64-hex-pin>
oxarchive package validate signed.jar --type jar --trusted-signer-sha256 <64-hex-pin>
oxarchive package validate package.apk --type alpine-apk \
  --alpine-rsa-key-file alpine-devel@example.org-12345678.rsa.pub \
  --trusted-signer-sha256 <public-key-pkcs1-der-sha256>
```

`oxarchive` uses the high-level session engine. Its JSON plan is an advisory
report and is deliberately not accepted back by `apply`; application always
plans and applies the same immutable input snapshot in one process. Inspection
uses flushed, schema-versioned JSON Lines directly from `ReaderEvent`, and
creation shares `ArchiveEngine`, `CreateOptions`, finite limits, and the safe
filesystem walker. File archives are staged and published without replacement;
stdout archives remain explicit binary streams.

Ecosystem package rules live in the separate `libarchive_oxide-package` crate.
`PackageInspector` reports structure while `PackageVerifier` keeps integrity,
signature validity, and offline issuer trust as independent verdicts. It never
performs implicit network access. Alpine and Android packages use the distinct
stable IDs `alpine-apk` and `android-apk`; the ambiguous `apk` ID is rejected.
JAR manifest SHA-2 digests and Wheel `RECORD` hashes/sizes are checked over
streamed entry bytes. JAR and Android APK v1 additionally verify their `.SF`
whole-manifest, main-attributes, and individual-section digests over exact
manifest bytes plus every bounded embedded CMS signer offline, then compare all
verified signer-certificate SHA-256 fingerprints with explicit `TrustPolicy`
pins. APK v1 requires every signer to cover every payload entry. Alpine APK v2
verifies RSA/SHA-1, RSA/SHA-256, or RSA/SHA-512 over the
exact compressed control member and checks `.PKGINFO datahash` over the
compressed data member; verification keys and trust pins are deliberately
separate. The CLI emits every verified certificate/public-key fingerprint.
Android APK v2/v3 additionally verifies RSA-PSS, RSA-PKCS#1, and
P-256/P-384 ECDSA-with-SHA-256 Signing Block signatures plus streamed 1 MiB
chunked SHA-256/SHA-512 and 4 KiB fs-verity SHA-256 APK content digests against
official AOSP fixtures. For every signer, the AOSP platform-range policy
selects the strongest signature at each represented algorithm-introduction SDK
and every selected record must verify; only the digest kinds requested by those
winners contribute to content-integrity checks. Authenticated v1 anti-stripping
metadata is enforced, and every detected v1/v2/v3 scheme contributes to the
result so one valid scheme cannot mask a different scheme's failure. Bounded v3
proof-of-rotation
and v3.1 targeted rotation verify every lineage signature, exact certificate
continuity, flags and algorithms, SDK ranges, release/development boundaries,
and rotation-min-SDK stripping protection. The lineage report does not grant
issuer trust. DSA, ECDSA-with-SHA-512/P-521, out-of-backend RSA sizes, and
unknown lineage algorithms remain explicit `unsupported`. An explicitly
supplied APK v4/v4.1 `.idsig` is bounded and verified separately: every signing
info, its exact v2/v3/v3.1 certificate-and-digest binding, and the SHA-256
Merkle root/tree are checked and emitted in a nested verdict. No API or CLI
guesses a sibling sidecar or grants trust from validity. Binary-manifest SDK
declarations and complete installability across an Android platform range are
not claimed.
MSIX/APPX verification parses `AppxBlockMap.xml` under the shared
metadata, nesting, path, and entry budgets and checks exact file coverage,
declared sizes/local-header sizes, compressed-block sizes, and SHA-256 hashes
over streamed uncompressed 64-KiB blocks. The encrypted/delta 2015/2017
BlockMap vocabularies are explicitly unsupported. `AppxSignature.p7x` is still
reported as `not-evaluated`; its presence is never presented as signature
validity.

## High-level engine

`ArchiveEngine` is the preferred safe application surface. Preparing a session
creates a bounded immutable snapshot, so an `ExtractionPlan` cannot be applied
to a different input. Collected inspection is metadata-budgeted; callers can
use `ArchiveSession::next_event` instead when they need constant-memory event
processing.

Extraction plans validate every destination before application. Unix destination
identity stays byte-exact and case-sensitive; Windows rejects reserved/ADS and
trailing-dot/space spellings and detects case-insensitive plus NFC/NFD aliases
before the filesystem adapter receives payload bytes.

```rust
use std::io::Read;

use libarchive_oxide::ArchiveEngine;

fn inspect(input: impl Read) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = ArchiveEngine::new().prepare(input)?;
    let inspection = session.inspect()?;
    println!("{:?}: {} entries", inspection.format(), inspection.entries().len());
    Ok(())
}
```

`ArchiveEngine::open(input)` returns a true streaming `ArchiveReader` and never
spools implicitly. Inspect/plan/apply workflows opt in with `prepare(input)` or
`PreparedArchive::spool` followed by `open_prepared`.

## Low-level example

```rust
use std::io::Read;

use libarchive_oxide::{ArchiveReader, ReaderEvent};

fn list(input: impl Read) -> Result<(), Box<dyn std::error::Error>> {
    let mut archive = ArchiveReader::new(input);
    loop {
        match archive.next_event()? {
            ReaderEvent::Entry(metadata) => {
                println!("{}", metadata.path().display_lossy());
            }
            ReaderEvent::Done => break,
            _ => {}
        }
    }
    Ok(())
}
```

## Features

| Feature | Default | Enables |
|---|:---:|---|
| `portable-codecs` | yes | five read/write outer codecs, read-only `compress` LZW and lzip, and safe-Rust CAB LZX read |
| `native-codecs` | no | adds all five native outer-codec backends plus shared CAB LZX; may be combined with portable |
| `gzip` | via profile | gzip plus ZIP Deflate64 read; portable when selected alone |
| `bzip2` | via profile | bzip2; portable when selected alone |
| `zstd` | via profile | zstd; portable when selected alone |
| `xz` | via profile | xz; portable when selected alone |
| `lz4` | via profile | LZ4 frame; portable when selected alone |
| `compress` | via portable profile | read-only Unix `compress(1)` / `.Z` LZW |
| `lzip` | via portable profile | strict read-only concatenated lzip/LZMA members |
| `cab-lzx` | via profile | read-only CAB LZX with bounded window/history and per-CFDATA alignment |
| `aes` | no | WinZip AES-256 AE-2 |
| `sevenz` | no | 7z |
| `async` | no | runtime-neutral futures-io adapters |
| `tokio` | no | Tokio I/O adapters |

Sequential I/O uses `ArchiveReader` / `ArchiveWriter`; seek-required formats
use `SeekArchiveReader` / `SeekArchiveWriter`. The `async` feature adds both
`AsyncArchive*` and `AsyncSeekArchive*`, while `tokio` adds the corresponding
`TokioArchive*` and `TokioSeekArchive*` adapters. Filesystem application always
uses `ArchiveEngine::prepare` → `ArchiveSession::plan` → `apply`; asynchronous
transports do not expose a second extraction-policy path.
`advanced::Pipeline` is the direct caller-driven API and incrementally composes
up to the configured number of gzip, bzip2, zstd, xz, lz4, and read-only
`compress(1)` LZW or lzip layers.

## Provider registry

Downstream crates can build an immutable `advanced::Registry` from boxed object-safe
`IncrementalFormatProvider` and `IncrementalCodecProvider` implementations.
`Pipeline`, `ArchiveReader`, and `ArchiveEngine::from_registry` use that same
registry for events, inspection, rewind, planning, apply, and registered
creation. Duplicate IDs are rejected before I/O, and custom `FormatId` /
`FilterId` values use a collision-free validated range. Registration is
application-owned; there is no global mutable registry or plugin ABI. See the
[provider contract](docs/providers.md).

## Validated metadata and errors

Encoded paths, timestamps, sparse extents, and algorithm-tagged checksums use
validated constructors. `EntryMetadataBuilder::try_build` checks cross-field
link and sparse-layout invariants, and every writer validates again before
emitting an entry. Normal I/O APIs return one root `Error` with a stable
`ErrorKind`, optional format and entry context, and the original archive or I/O
source. Sans-I/O errors and provider/source machinery are under `advanced`.

## Filesystem adapters

`ArchiveSession::apply_with_adapter` keeps session identity, path policy,
resource limits, hardlink ordering, and archive events in the engine while a
compile-time `FilesystemAdapter` performs normalized relative operations.
`ApplyReport::filesystem_findings` records applied, unsupported, refused,
partial, and OS-error outcomes for every requested entry or metadata operation;
an adapter cannot silently omit an advertised attribute. Existing
`apply(plan, cap_std::fs::Dir)` remains a shortcut to the built-in atomic
`CapStdFilesystemAdapter`. Linux additionally restores descriptor-based
mode/time, numeric ownership, xattrs, POSIX ACLs, and sparse layout. See the
[filesystem adapter contract](docs/filesystem-adapters.md).

## Codec backends

`libarchive_oxide-core` is the zero-dependency `no_std + alloc` protocol and
validated-value layer. `libarchive_oxide-codecs` owns the caller-driven,
`no_std + alloc` portable codec state machines; it has no default algorithms,
so downstream users opt into only the codec features they need. All
project-owned crates use `#![forbid(unsafe_code)]`. `portable-codecs` is the
flagship crate's default and its normal/build graph rejects codec C/FFI
packages. Add the native performance backends with `--features native-codecs`; use
`--no-default-features --features native-codecs` only when a native-only
dependency graph is desired. Cargo features remain additive, and individual
codec features without a profile marker select portable implementations for
compatibility. Both backend families drive the same bounded state-machine
contract and corpus. See the [profile evidence](docs/codec-profiles.md).

## Requirements

| Crate | MSRV |
|---|---:|
| `libarchive_oxide-core` | Rust 1.88 |
| `libarchive_oxide-codecs` | Rust 1.88 |
| `libarchive_oxide` | Rust 1.88 |
| `libarchive_oxide-package` | Rust 1.88 |
| `libarchive_oxide-cli` | Rust 1.88 |

All published crates use `#![forbid(unsafe_code)]`.

## Documentation

- [API documentation](https://docs.rs/libarchive_oxide)
- [CLI reference](libarchive_oxide-cli/README.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Architecture decisions](docs/adr/)
- [Object-safe provider registry](docs/providers.md)
- [Filesystem adapter contract](docs/filesystem-adapters.md)
- [CLI and streaming-output contract](docs/cli-contract.md)
- [Detailed support matrix](docs/support-matrix.md)
- [Modern Replacement roadmap](docs/modern-replacement.md)
- [Modern Replacement issue tracker](https://github.com/P4suta/libarchive_oxide/issues/28)
- [v0.1 → v0.2 migration](docs/migration-0.2.md)

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
