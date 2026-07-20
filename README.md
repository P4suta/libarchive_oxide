# libarchive_oxide

[![CI](https://github.com/P4suta/libarchive_oxide/actions/workflows/ci.yml/badge.svg)](https://github.com/P4suta/libarchive_oxide/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/libarchive_oxide.svg)](https://crates.io/crates/libarchive_oxide)
[![docs.rs](https://img.shields.io/docsrs/libarchive_oxide.svg)](https://docs.rs/libarchive_oxide)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Safe-Rust archive reading, writing, compression, and extraction.

This project is independent of the upstream
[libarchive](https://www.libarchive.org/) project. It is not a binding.
Project-owned crates forbid unsafe code. Some currently enabled codec
dependencies use native C backends; see [Codec backends](#codec-backends).

## Support

| Format | Current read support | Current write support | Important limits |
|---|---|---|---|
| tar | sequential v7/ustar/pax/GNU | sequential | known-size entries; GNU sparse supported |
| cpio | sequential binary/odc/newc/crc | sequential | known-size entries |
| ar | sequential GNU/BSD | sequential | thin references are identified, never followed |
| ZIP/ZIP64 | seek or streaming, Store/Deflate | streaming with descriptors | optional WinZip AES; no Deflate64, BZip2, LZMA, or Zstandard methods yet |
| 7z | seek, LZMA/LZMA2 | seek | optional `sevenz`; single folder; no general coder graph |
| ISO 9660 | seek, Rock Ridge/Joliet | seek | no UDF |

| Outer compression | Decode | Encode | Current backend note |
|---|:---:|:---:|---|
| gzip/DEFLATE | yes | yes | Rust |
| bzip2 | yes | yes | Rust `libbz2-rs-sys`; CI rejects native `bzip2-sys` |
| zstd | yes | yes | Pure-Rust `ruzstd`; native zstd packages rejected by CI |
| xz/LZMA2 | yes | yes | Pure-Rust `lzma-rust2`; native liblzma packages rejected by CI |
| LZ4 frame | yes | yes | Pure-Rust `lz4_flex`; native LZ4 packages rejected by CI |

The [detailed support matrix](docs/support-matrix.md) distinguishes archive
dialects, compression methods, encryption, metadata, and unsupported cases.
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
```

CLI tools:

```sh
cargo install libarchive_oxide-cli --locked

# Unified safe workflow
oxarchive inspect artifact.tar.zst
oxarchive plan --json artifact.zip
oxarchive apply artifact.tar.gz destination
oxarchive verify artifact.7z
```

`oxarchive` uses the high-level session engine. Its JSON plan is an advisory
report and is deliberately not accepted back by `apply`; application always
plans and applies the same immutable input snapshot in one process.

## High-level engine

`ArchiveEngine` is the preferred safe application surface. Opening a session
creates a bounded immutable snapshot, so an `ExtractionPlan` cannot be applied
to a different input. Collected inspection is metadata-budgeted; callers can
use `ArchiveSession::next_event` instead when they need constant-memory event
processing.

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

## Features

| Feature | Default | Enables |
|---|:---:|---|
| `gzip` | yes | gzip |
| `bzip2` | yes | bzip2 through the Rust backend |
| `zstd` | yes | zstd through the Pure-Rust `ruzstd` backend |
| `xz` | yes | xz |
| `lz4` | yes | lz4 frame |
| `aes` | no | WinZip AES-256 AE-2 |
| `sevenz` | no | 7z |
| `async` | no | runtime-neutral futures-io adapters |
| `tokio` | no | Tokio I/O adapters |

Sequential I/O uses `ArchiveReader` / `ArchiveWriter`; seek-required formats
use `SeekArchiveReader` / `SeekArchiveWriter`. The `async` feature adds both
`AsyncArchive*` and `AsyncSeekArchive*`, while `tokio` adds the corresponding
`TokioArchive*`, `TokioSeekArchive*`, and bounded `TokioExtractor` adapters.
`Pipeline` is the direct caller-driven API and incrementally composes up to the
configured number of gzip, bzip2, zstd, xz, and lz4 layers.

## Codec backends

`libarchive_oxide-core` is zero-dependency `no_std + alloc` safe Rust, and all
project-owned crates use `#![forbid(unsafe_code)]`. The bzip2, zstd, xz/LZMA2,
and LZ4 features are dependency-gated to Rust backends in sync, Pipeline,
futures-io, and Tokio configurations. The complete default graph is not yet
advertised as C/FFI-free until the `portable-codecs` profile gate lands.
The roadmap separates a dependency-verified `portable-codecs` profile from an
explicit `native-codecs` performance profile. Until that work lands, do not
interpret “safe Rust” as “no native transitive dependencies.”

## Requirements

| Crate | MSRV |
|---|---:|
| `libarchive_oxide-core` | Rust 1.85 |
| `libarchive_oxide` | Rust 1.87 |
| `libarchive_oxide-cli` | Rust 1.87 |

All published crates use `#![forbid(unsafe_code)]`.

## Documentation

- [API documentation](https://docs.rs/libarchive_oxide)
- [CLI reference](libarchive_oxide-cli/README.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Architecture decisions](docs/adr/)
- [Detailed support matrix](docs/support-matrix.md)
- [Modern Replacement roadmap](docs/modern-replacement.md)
- [Modern Replacement issue tracker](https://github.com/P4suta/libarchive_oxide/issues/28)
- [v0.1 → v0.2 migration](docs/migration-0.2.md)

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
