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
translation, and
sequential read-only WARC 1.0/1.1 with format-specific limits. Outer filters are
gzip, bzip2, zstd, xz, and LZ4 frame in both directions, plus read-only Unix
`compress(1)` / `.Z` LZW and strict concatenated lzip/LZMA. The crate forbids
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

use libarchive_oxide::ArchiveEngine;

fn inspect(input: impl Read) -> Result<(), Box<dyn std::error::Error>> {
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

With feature `aes`, `ArchiveEngine::create_with_password` and
`StreamingArchiveBuilder::with_engine_and_password` create streaming WinZip
AES-256 AE-2 ZIP output. They reject non-ZIP formats and outer filters before
writing bytes.

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

See [docs.rs](https://docs.rs/libarchive_oxide) and [`examples`](examples/).

## Features

| Feature | Default | Effect |
|---|:---:|---|
| `portable-codecs` | yes | five read/write outer codecs, read-only `compress` LZW, and safe-Rust CAB LZX/Quantum read |
| `native-codecs` | no | five native outer codecs plus shared CAB LZX/Quantum; use with `--no-default-features` |
| `gzip` | via profile | gzip plus ZIP Deflate64 read; portable when selected alone |
| `bzip2` | via profile | bzip2; portable when selected alone |
| `zstd` | via profile | zstd; portable when selected alone |
| `xz` | via profile | xz / LZMA2; portable when selected alone |
| `lz4` | via profile | LZ4 frame; portable when selected alone |
| `compress` | via portable profile | read-only Unix `compress(1)` / `.Z` LZW |
| `cab-lzx` | via profile | read-only CAB LZX with bounded window/history and per-CFDATA alignment |
| `cab-quantum` | via profile | read-only CAB Quantum with bounded window/models and per-CFDATA alignment |
| `aes` | no | WinZip AES-256 AE-2 |
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

Immutable remote or application-owned ZIP, 7z, ISO, UDF, and CAB objects can
implement object-safe `advanced::ReadAt` or feature-gated
`advanced::AsyncRangeSource`. The adapters require a validated stable opaque
identity, revalidate it around I/O, enforce encoded-source and read-ahead
budgets, report exact request/byte metrics, and continue to use the same
`SeekArchiveReader` parser without an implicit spool. For a multi-cabinet CAB,
`advanced::CabVolumeReader` (or `advanced::CabVolumeProvider` in a registry)
consumes a bounded application-owned `advanced::VolumeSet`;
`advanced::VolumeId` maps directly to the expected CAB `iCabinet`. Resolution
is explicit through `advanced::VolumeResolver`: the crate never follows CAB
names or performs network access. SDK-specific HTTP/S3/GCS/Azure adapters
remain outside this crate; see the
[`range_source` example](examples/range_source.rs).

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
