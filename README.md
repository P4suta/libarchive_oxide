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
| ZIP/ZIP64 | seek or streaming, Store/Deflate | streaming with descriptors | optional WinZip AES; no Deflate64, BZip2, LZMA, or Zstandard methods yet |
| 7z | seek, LZMA/LZMA2 | seek | optional `sevenz`; single folder; no general coder graph |
| ISO 9660 | seek, Rock Ridge/Joliet | seek | no UDF |

| Outer compression | Decode | Encode | Current backend note |
|---|:---:|:---:|---|
| gzip/DEFLATE | yes | yes | portable `miniz_oxide`; native libz |
| bzip2 | yes | yes | portable `libbz2-rs-sys`; native libbz2 |
| zstd | yes | yes | portable `ruzstd`; native libzstd |
| xz/LZMA2 | yes | yes | portable `lzma-rust2`; native liblzma |
| LZ4 frame | yes | yes | portable `lz4_flex`; native liblz4 |

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
oxarchive create --format tar --filter zstd artifact.tar.zst input/
oxarchive verify artifact.7z
```

`oxarchive` uses the high-level session engine. Its JSON plan is an advisory
report and is deliberately not accepted back by `apply`; application always
plans and applies the same immutable input snapshot in one process. Inspection
uses flushed, schema-versioned JSON Lines directly from `ReaderEvent`, and
creation shares `ArchiveEngine`, `CreateOptions`, finite limits, and the safe
filesystem walker. File archives are staged and published without replacement;
stdout archives remain explicit binary streams.

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
| `portable-codecs` | yes | all five outer codecs through C/FFI-free backends |
| `native-codecs` | no | all five outer codecs through native libraries; requires `--no-default-features` |
| `gzip` | via profile | gzip; portable when selected alone |
| `bzip2` | via profile | bzip2; portable when selected alone |
| `zstd` | via profile | zstd; portable when selected alone |
| `xz` | via profile | xz; portable when selected alone |
| `lz4` | via profile | LZ4 frame; portable when selected alone |
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

## Compile-time providers

Downstream crates can prepend statically dispatched `FormatProvider` and
`CodecProvider` implementations to `ProviderSet::builtins()`, or start from a
closed `ProviderSet::empty()`. `Pipeline`, `ArchiveReader`, and `ArchiveEngine`
then use that same concrete chain for events, inspection, rewind, planning,
apply, and `create_registered`; no global registry, `dyn` dispatch, or plugin
ABI is introduced. Providers serve stable `FormatId` / `FilterId` values, and
prepend order selects an alternative implementation. See the
[provider contract](docs/providers.md).

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

`libarchive_oxide-core` is zero-dependency `no_std + alloc` safe Rust, and all
project-owned crates use `#![forbid(unsafe_code)]`. `portable-codecs` is the
default and its normal/build graph rejects codec C/FFI packages. Select the
native performance profile explicitly with
`--no-default-features --features native-codecs`. The two profile markers are
mutually exclusive; individual codec features without a marker remain portable
for compatibility. Both profiles drive the same bounded state-machine contract
and corpus. See the [profile evidence](docs/codec-profiles.md).

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
- [Compile-time provider contract](docs/providers.md)
- [Filesystem adapter contract](docs/filesystem-adapters.md)
- [CLI and streaming-output contract](docs/cli-contract.md)
- [Detailed support matrix](docs/support-matrix.md)
- [Modern Replacement roadmap](docs/modern-replacement.md)
- [Modern Replacement issue tracker](https://github.com/P4suta/libarchive_oxide/issues/28)
- [v0.1 → v0.2 migration](docs/migration-0.2.md)

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
