# libarchive_oxide

[![CI](https://github.com/P4suta/libarchive_oxide/actions/workflows/ci.yml/badge.svg)](https://github.com/P4suta/libarchive_oxide/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/libarchive_oxide.svg)](https://crates.io/crates/libarchive_oxide)
[![docs.rs](https://img.shields.io/docsrs/libarchive_oxide.svg)](https://docs.rs/libarchive_oxide)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Pure-Rust archive reading, writing, compression, and extraction.

This project is independent of the upstream
[libarchive](https://www.libarchive.org/) project. It is not a binding.

## Support

| Format | Read | Write |
|---|:---:|:---:|
| tar | yes | yes |
| cpio | yes | yes |
| ar | yes | yes |
| zip | yes | yes |
| 7z | yes | yes |
| ISO 9660 | yes | yes |

| Compression | Decode | Encode |
|---|:---:|:---:|
| gzip | yes | yes |
| zstd | yes | yes |
| xz | yes | yes |
| lz4 frame | yes | yes |

Additional support includes pax, GNU tar extensions, zip64, WinZip AES-256
AE-2, all standard cpio header dialects, Joliet, and solid LZMA/LZMA2 7z
archives.

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
```

## Example

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
| `zstd` | yes | zstd |
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
configured number of gzip, zstd, xz, and lz4 layers.

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
- [v0.1 → v0.2 migration](docs/migration-0.2.md)

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
