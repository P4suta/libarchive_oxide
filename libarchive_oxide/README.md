# libarchive_oxide

[![crates.io](https://img.shields.io/crates/v/libarchive_oxide.svg)](https://crates.io/crates/libarchive_oxide)
[![docs.rs](https://img.shields.io/docsrs/libarchive_oxide.svg)](https://docs.rs/libarchive_oxide)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

Safe-Rust archive detection, compression, extraction, and creation over
[`libarchive_oxide-core`](https://crates.io/crates/libarchive_oxide-core).

The crate supports tar, cpio, ar, ZIP/ZIP64 (including Deflate64 read),
optional 7z coder graphs, ISO 9660, read-only UDF 1.02–2.60 with bounded
Metadata, Sparable, Metadata-over-Sparable, and Virtual/VAT Partition
translation, seek-native XAR Store/zlib/BZip2 reads and bounded writes,
and seek-native read-only LHA/LZH levels 0–3, plus sequential WARC 1.0/1.1
read/write with format-specific limits. Outer filters are
gzip, bzip2, zstd, xz, LZ4 frame, lzop, Base64, explicit-only LZMA-alone, lzip, and
Unix `compress(1)` / `.Z` LZW in both directions, plus read-only RPM wrapper
removal with nested payload-filter detection. Lzip reads strict
concatenated members and writes a canonical single member. The crate forbids
unsafe code; its default `portable-codecs` profile is dependency-gated to
C/FFI-free backends across sync and async adapters. See the repository's
[support matrix](https://github.com/P4suta/libarchive_oxide/blob/main/docs/support-matrix.md)
for method- and metadata-level details.

This project is independent of the upstream libarchive project. It is not a
binding.

On `wasm32-wasip1`, the flagship exposes streaming and seekable inspection
readers plus portable formats/codecs. Host-filesystem extraction, spooling,
OCI application/creation, and Tokio adapters are intentionally absent from
that target; CI compiles this inspection-only surface on stable Rust.

## High-level engine

`ArchiveSession::plan` validates the complete destination set before apply.
Unix keeps byte-exact case-sensitive path identity. Windows rejects reserved
devices, ADS and trailing-dot/space spellings, and classifies case-insensitive
or NFC/NFD aliases as typed destination collisions before payload publication.

`ArchiveEngine` opens a bounded immutable snapshot and provides session-bound
inspection, planning, application, and creation. Plans cannot be serialized,
cloned, replayed, or applied to another session. Use the session event API
instead of collected inspection for huge entry sets.

```rust
use std::io::Read;

use libarchive_oxide::{ArchiveEngine, Error};

fn inspect(input: impl Read) -> Result<(), Error> {
    let mut session = ArchiveEngine::new().prepare(input)?;
    let inspection = session.inspect()?;
    println!("{:?}: {} entries", inspection.format(), inspection.entries().len());
    Ok(())
}
```

`ArchiveEngine::open(input)` is streaming. Snapshot-backed inspection,
planning, and application use the explicit `prepare(input)` convenience or
`PreparedArchive::spool` plus `open_prepared`.

Authenticated ZIP/7z inspection uses the equally explicit
`prepare_with_password(input, SecretBytes)` or
`open_prepared_with_password(prepared, SecretBytes)` path. The session retains
the redacted, zeroizing password across `rewind`, which is required by
inspect/plan/apply, and rejects it for formats that cannot consume it. This
password path does not add spooling to ordinary `open(input)`.

`OpenOptions` is the common reader configuration for synchronous, futures-io,
Tokio, and range adapters.
It carries optional explicit `FormatId` and `FilterId` selections, finite `Limits` and `SourceLimits`, a bounded application-owned `PasswordProvider`, and an optional bounded `VolumeSet`.
Explicit Base64 and signatureless LZMA-alone filters are shared by sync,
futures-io, Tokio, seek, and range readers.
Filtered seek/range inputs require the inner format; random-access multi-volume providers reject outer filters.
Password candidates remain in zeroizing storage and are tried in provider order.
Forward-only ZIP readers use them for traditional ZipCrypto and WinZip AES-128/192/256 Store/Deflate/BZip2/Zstandard/XZ entries with known sizes or signed classic/ZIP64 descriptors across sync, futures-io, and Tokio.
WinZip AES also composes with known-size Deflate64 entries; volume options still require a seek, range, or volume reader.
Adjacent-volume discovery is off by default.
With feature `sevenz`,
`ArchiveEngine::open_path_with_options` consumes that explicit opt-in only for a first path ending in numeric physical-volume one (for example `.001`), then opens same-directory `.002`, `.003`, and later siblings lazily under `SourceLimits`.
It rejects stdin, handles, ambiguous suffixes, non-first paths,
and a caller-supplied `VolumeSet`.
`VolumeArchiveReader::with_options` consumes the configured `VolumeSet` for built-in multi-cabinet CAB and byte-split 7z input.
The 7z provider keeps a lazy extent table instead of joining payload bytes; encrypted data folders with stored CRCs authenticate ordered password candidates before exposing plaintext, and encrypted headers try the same candidates with structural validation.
`with_registry` applies the same option contract to application-owned random-access providers.
`ArchiveEngine::open_volumes` promotes the built-in path to a rewindable inspect/plan/apply session.
The session digest includes volume identifiers,
lengths, and all encoded bytes, and reads use a fixed-size buffer.

With feature `aes`, sequential RAR3 and RAR5 readers use the same bounded password candidates.
RAR3 covers encrypted headers and single-volume,
non-solid Store/LZ/PPMd data.
RAR5 covers AES-256-CBC headers, services, and single-volume non-solid Store/LZ data with PBKDF2-HMAC-SHA256 and raw or HMAC-tweaked CRC32/BLAKE2sp authentication.
Static providers cache zeroizing keys per candidate and salt; containers preflight whole ciphertext, candidate,
output, and KDF work budgets and release no plaintext until exact size and integrity agree.
Encrypted solid/split members remain typed unsupported.

With feature `aes`, `ArchiveEngine::create_with_password` and
`StreamingArchiveBuilder::with_engine_and_password` create streaming WinZip
AES-128/192/256 AE-2 ZIP output selected through `ZipWriteOptions`; the default
encrypted profile remains AES-256. They reject non-ZIP formats and outer
filters before writing bytes. The same options expose traditional `ZipCrypto`
for legacy interoperability; it is intentionally documented as weak and is not
the default.

`SeekArchiveBuilder::with_engine` applies the same bounded filesystem walk,
safe-name checks, deterministic ordering, and metadata profiles to seek-native 7z, ISO 9660, and XAR output.
`XarWriteOptions` selects Store, zlib, or BZip2 regular-file payloads while retaining the TOC-before-heap layout.
Each entry is an independent stream, codec memory is preflighted, and the encoded heap uses a bounded memory/temporary-file spool.
The default remains Store.
With feature `aes`, `SeekArchiveBuilder::with_engine_and_password` delegates to `ArchiveEngine::create_seek_with_password` for typed 7z AES-256 profiles without bypassing that filesystem contract.

`ArchiveTranscoder` rewrites archives through the same bounded reader and writer state machines.
Its four methods cover sequential/seek source and destination combinations without buffering a complete payload.
Every unrepresentable archive or entry metadata field is returned as a typed `MetadataLoss`; `MetadataLossPolicy::Reject` fails before the affected entry is started.
Both the number and allocation size of loss findings are finite.
Metadata-only mtree input/output is rejected because conversion would otherwise discard or invent file bodies.

`ArchiveEditor` performs bounded whole-archive rename/remove rewrites over the same four sequential/seek access combinations.
It validates every retained or renamed path with the extraction planner's host-identity rules, rejects traversal, aliases, duplicate/topology conflicts, unmatched operations, and dangling hardlinks, and updates exact matching hardlink targets after a rename.
Removed payloads are decoded but never buffered or written.
Edit operations and the retained-path index share the configured path and metadata budgets;
`EditReport` includes counts plus the same typed metadata-loss report as transcoding.

`CreateOptions::with_format_options` accepts typed `FormatWriteOptions`.
`ZipWriteOptions` selects Store, Deflate, feature-enabled BZip2, LZMA, PPMd8,
XZ, or Zstd and declares the intended encryption wrapper.
`SevenZipWriteOptions` describes the coder, optional Delta/BCJ preprocessor, solid mode, and encryption.
A profile that is recognized but not implemented is rejected before archive bytes are written.
The 7z writer supports solid and non-solid Store, LZMA1,
LZMA2, PPMd7, Deflate, BZip2, and Zstandard folders, optional Delta or BCJ preprocessing, and AES-256/SHA-256 encryption.
The encrypted ZIP writer supports WinZip AES-128/192/256 AE-2 and traditional `ZipCrypto` over Store, Deflate,
BZip2, LZMA, PPMd8, Zstandard, and XZ.

Signatureless raw streams are intentionally excluded from automatic detection.
Use `ArchiveEngine::new().open_with_format(input, FormatId::Raw)` or
`ArchiveReader::with_format` to expose the decoded bytes as one bounded file
entry named `data`.

WARC records are exposed as regular-file entries over their exact content
blocks. Validated, case-insensitive named fields remain available as `warc`
metadata extensions. A sequence prefix makes paths collision-free even when
record IDs repeat; oversized or absent IDs use the sequence-only fallback.

## Low-level example

```rust
use std::io::Read;

use libarchive_oxide::{ArchiveReader, Error, ReaderEvent};

fn list(input: impl Read) -> Result<(), Error> {
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

See [docs.rs](https://docs.rs/libarchive_oxide) and [`examples`](examples/).

## Features

| Feature | Default | Effect |
|---|:---:|---|
| `portable-codecs` | yes | eleven read/write outer codecs plus bounded CAB LZX/Quantum, LHA read, and ZIP PPMd8 |
| `native-codecs` | no | five native outer codecs plus shared CAB LZX/Quantum, LHA read, and ZIP PPMd8; use with `--no-default-features` |
| `gzip` | via profile | gzip plus ZIP Deflate64 read; portable when selected alone |
| `bzip2` | via profile | bzip2; portable when selected alone |
| `zstd` | via profile | zstd; portable when selected alone |
| `xz` | via profile | xz / LZMA2; portable when selected alone |
| `lz4` | via profile | LZ4 frame; portable when selected alone |
| `lzop` | via portable profile | bounded Safe Rust LZO1X read and deterministic stored-block write |
| `compress` | via portable profile | bounded Unix `compress(1)` / `.Z` LZW read/write |
| `lzip` | via portable profile | strict concatenated reads and canonical single-member writes |
| `lzma` | via portable profile | explicit-only LZMA-alone read/write |
| `cab-lzx` | via profile | read-only CAB LZX with bounded window/history and per-CFDATA alignment |
| `cab-quantum` | via profile | read-only CAB Quantum with bounded window/models and per-CFDATA alignment |
| `lha` | via profile | read-only LHA/LZH levels 0–3 with bounded fixed-dictionary decoding |
| `aes` | no | WinZip AES-128/192/256 AE-2, legacy ZipCrypto, RAR3 AES-128/SHA-1 read, RAR5 AES-256/PBKDF2-SHA256 read, and 7z AES-256/SHA-256 |
| `sevenz` | no | 7z read/write |
| `async` | no | runtime-neutral `futures-io` adapters |
| `tokio` | no | Tokio I/O adapters |

`--no-default-features` retains uncompressed formats and zip store mode.

The default portable graph is CI-checked to require Rust backends and exclude
codec C/FFI packages. The native profile is separately checked to select libz,
libbz2, libzstd, liblzma, and liblz4. Both markers can be compiled together;
`BackendPreference` selects the implementation at runtime.

Sequential, seek, futures-io, and Tokio adapters all drive the same archive
state machines. Seek variants are named `SeekArchive*`, `AsyncSeekArchive*`,
and `TokioSeekArchive*`. Filesystem extraction is deliberately separate from
those transports: explicitly prepare an immutable snapshot, create a
session-bound plan with the root `Policy`, then call `apply` or
`apply_with_adapter`. Archive-level properties can be supplied before the
first entry with `set_archive_metadata`.

Immutable remote or application-owned ZIP, 7z, ISO, UDF, CAB, and LHA objects can implement object-safe `advanced::ReadAt` or feature-gated `advanced::AsyncRangeSource`.
The adapters require a validated stable opaque identity, revalidate it around I/O, enforce encoded-source and read-ahead budgets, report exact request/byte metrics, and continue to use the same `SeekArchiveReader` parser without an implicit spool.
For a multi-cabinet CAB or byte-split 7z,
the root `VolumeArchiveReader` consumes a bounded application-owned `advanced::VolumeSet` from `OpenOptions`; the format-specific `advanced::CabVolumeReader`/`CabVolumeProvider` and `SevenZipVolumeReader`/`SevenZipVolumeProvider` remain available for low-level integrations.
`advanced::VolumeId` maps directly to CAB `iCabinet` or the ordered 7z physical segment index.
Handle-based resolution is explicit through `advanced::VolumeResolver` and never follows archive names or performs network access.
The separate, explicitly opted-in path opener follows only the numeric 7z sibling pattern described above.
SDK-specific HTTP/S3/GCS/Azure adapters remain outside this crate; see the [`range_source` example](examples/range_source.rs).

Metadata construction validates encoded paths, timestamps, sparse extents,
checksum algorithms, and cross-field link/layout rules. Everyday I/O methods
return the root `Error`; low-level sans-I/O errors, providers, registries,
events, and range sources are grouped under `advanced`.

MSRV: Rust 1.88.

## Security

All readers use finite [`Limits`](https://docs.rs/libarchive_oxide-core/latest/libarchive_oxide_core/struct.Limits.html)
by default. Filesystem extraction uses a directory capability, atomic regular-file
commit, and a deny-by-default policy for traversal, links, and special files. See the
[security policy](https://github.com/P4suta/libarchive_oxide/blob/main/SECURITY.md).

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
