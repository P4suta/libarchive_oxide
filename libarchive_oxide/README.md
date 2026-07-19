# libarchive_oxide

[![crates.io](https://img.shields.io/crates/v/libarchive_oxide.svg)](https://crates.io/crates/libarchive_oxide)
[![docs.rs](https://img.shields.io/docsrs/libarchive_oxide.svg)](https://docs.rs/libarchive_oxide)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

Safe-Rust archive detection, compression, extraction, and creation over
[`libarchive_oxide-core`](https://crates.io/crates/libarchive_oxide-core).

The crate supports tar, cpio, ar, ZIP/ZIP64, optional single-folder 7z, and
ISO 9660 with format-specific limits. Outer filters are gzip, zstd, xz, and
LZ4 frame. The crate forbids unsafe code, but some codec dependencies currently
select native C backends. See the repository's
[support matrix](https://github.com/P4suta/libarchive_oxide/blob/main/docs/support-matrix.md)
for method- and metadata-level details.

This project is independent of the upstream libarchive project. It is not a
binding.

## High-level engine

`ArchiveEngine` opens a bounded immutable snapshot and provides session-bound
inspection, planning, application, and creation. Plans cannot be serialized,
cloned, replayed, or applied to another session. Use the session event API
instead of collected inspection for huge entry sets.

```rust
use std::io::Read;

use libarchive_oxide::ArchiveEngine;

fn inspect(input: impl Read) -> Result<(), Box<dyn std::error::Error>> {
    let mut session = ArchiveEngine::new().open(input)?;
    let inspection = session.inspect()?;
    println!("{:?}: {} entries", inspection.format(), inspection.entries().len());
    Ok(())
}
```

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
| `gzip` | yes | gzip |
| `zstd` | yes | zstd |
| `xz` | yes | xz / LZMA2 |
| `lz4` | yes | lz4 frame |
| `aes` | no | WinZip AES-256 AE-2 |
| `sevenz` | no | 7z read/write |
| `async` | no | runtime-neutral `futures-io` adapters |
| `tokio` | no | Tokio I/O adapters |

`--no-default-features` retains uncompressed formats and zip store mode.

The current default feature graph is not yet guaranteed C/FFI-free: zstd
encoding uses a native backend, and async all-features builds may enable other
native codec backends. A dependency-verified portable profile is roadmap work.

Sequential, seek, futures-io, and Tokio adapters all drive the same archive
state machines. Seek variants are named `SeekArchive*`, `AsyncSeekArchive*`,
and `TokioSeekArchive*`; secure Tokio extraction is provided by
`TokioExtractor`. Archive-level properties can be supplied before the first
entry with `set_archive_metadata`.

MSRV: Rust 1.87.

## Security

All readers use finite [`Limits`](https://docs.rs/libarchive_oxide-core/latest/libarchive_oxide_core/struct.Limits.html)
by default. Filesystem extraction uses a directory capability, atomic regular-file
commit, and a deny-by-default policy for traversal, links, and special files. See the
[security policy](https://github.com/P4suta/libarchive_oxide/blob/main/SECURITY.md).

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
