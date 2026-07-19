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
AE-2, Joliet, and single-folder LZMA2 7z archives.

## Installation

```toml
[dependencies]
libarchive_oxide = "0.1"
```

For `no_std`:

```toml
[dependencies]
libarchive_oxide-core = "0.1"
```

CLI tools:

```sh
cargo install libarchive_oxide-cli --locked
```

## Example

```rust
use libarchive_oxide::libarchive_oxide_core::{EntryData, EntryReader};
use libarchive_oxide::{decompress_capped, reader};

fn list(bytes: &[u8]) -> std::io::Result<()> {
    let plain = decompress_capped(bytes, 64 * 1024 * 1024)
        .map_err(std::io::Error::other)?;
    let mut archive = reader(&plain)?;

    while let Some(mut entry) = archive.next_entry()? {
        println!("{}", String::from_utf8_lossy(&entry.meta().path));
        let mut buffer = [0_u8; 8192];
        while entry.data().read_chunk(&mut buffer)? != 0 {}
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

## Requirements

| Crate | MSRV |
|---|---:|
| `libarchive_oxide-core` | Rust 1.81 |
| `libarchive_oxide` | Rust 1.87 |
| `libarchive_oxide-cli` | Rust 1.87 |

All published crates use `#![forbid(unsafe_code)]`.

## Documentation

- [API documentation](https://docs.rs/libarchive_oxide)
- [CLI reference](libarchive_oxide-cli/README.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Architecture decisions](docs/adr/)

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
