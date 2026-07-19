# libarchive_oxide

[![CI](https://github.com/P4suta/libarchive_oxide/actions/workflows/ci.yml/badge.svg)](https://github.com/P4suta/libarchive_oxide/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.87%20flagship%20%2F%201.81%20core-blue.svg)](#msrv)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![crates.io](https://img.shields.io/crates/v/libarchive_oxide.svg)](https://crates.io/crates/libarchive_oxide)
[![docs.rs](https://img.shields.io/docsrs/libarchive_oxide.svg)](https://docs.rs/libarchive_oxide)

Pure-Rust archive reading, writing, compression, extraction, and CLI tools.

- `#![forbid(unsafe_code)]` in every published crate
- `no_std` + `alloc` core with no external dependencies
- sans-IO transforms
- sealed-enum runtime dispatch; no `dyn` in library source

This project is independent of the upstream
[libarchive](https://www.libarchive.org/) project. It is not a binding and links
no C code.

## Formats

| Format | Read | Write | Scope |
|---|:---:|:---:|---|
| tar | yes | yes | ustar, pax, GNU read; GNU long-name write |
| cpio | yes | yes | newc, odc read; newc write |
| ar | yes | yes | GNU, BSD, SysV read; BSD long-name write |
| zip | yes | yes | zip64; WinZip AES-256 AE-2 |
| 7z | yes | yes | single-folder LZMA2 |
| ISO 9660 | yes | yes | Joliet |

| Filter | Decode | Encode | Backend |
|---|:---:|:---:|---|
| gzip | yes | yes | `miniz_oxide` |
| zstd | yes | yes | `ruzstd` |
| xz | yes | yes | `lzma-rust2` |
| lz4 frame | yes | yes | `lz4_flex` |
| bzip2 | no | no | out of scope |

Filters are independent of archive formats. Supported combinations include
`.tar.gz`, `.tar.zst`, `.tar.xz`, and `.tar.lz4`.

## Architecture

```text
Format   tar / cpio / ar / ISO / zip / 7z   EntryReader <-> EntryWriter
Filter   gzip / zstd / xz / lz4             Decoder     <-> Encoder
Base     Transform::{step, finish}           sans-IO
```

See [ADR-0001](docs/adr/0001-core-architecture.md) for the constraints and
trade-offs.

## Features

Features are defined by `libarchive_oxide`.

| Feature | Default | Effect |
|---|:---:|---|
| `gzip` | yes | gzip |
| `zstd` | yes | zstd |
| `xz` | yes | xz / LZMA2 |
| `lz4` | yes | lz4 frame |
| `aes` | no | WinZip AES-256 AE-2 |
| `sevenz` | no | 7z read/write; enables `gzip` for CRC-32 |

`--no-default-features` retains uncompressed formats and zip store mode.

## MSRV

| Crate | Rust |
|---|---:|
| `libarchive_oxide-core` | 1.81 |
| `libarchive_oxide` | 1.87 |
| `libarchive_oxide-cli` | 1.87 |

CI verifies each declared `rust-version`. MSRV increases require a minor release
before 1.0.

## Library example

```rust
use libarchive_oxide::{decompress_capped, reader};
use libarchive_oxide_core::{EntryData, EntryReader};

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

See [docs.rs](https://docs.rs/libarchive_oxide) and
[`libarchive_oxide/examples`](libarchive_oxide/examples).

## CLI

```sh
cargo install libarchive_oxide-cli --locked
```

| Tool | Function |
|---|---|
| `oxtar` | create, list, and extract tar/cpio archives |
| `oxcpio` | create, list, and extract cpio archives |
| `oxcat` | decompress to standard output |
| `oxunzip` | list and extract zip archives |

Supported flags and exit codes are documented in the
[CLI README](libarchive_oxide-cli/README.md).

## Security

- extraction rejects absolute paths, parent traversal, Windows drive/UNC paths,
  and device names;
- `decompress_capped` enforces an output bound;
- the CLI decompression cap is 4 GiB;
- header-derived sizes use checked conversions and arithmetic.

Report vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/P4suta/libarchive_oxide/security/advisories/new).
See [SECURITY.md](SECURITY.md).

## Repository

| Path | Purpose |
|---|---|
| `libarchive_oxide-core` | traits and uncompressed formats |
| `libarchive_oxide` | codecs, zip/7z, detection, extraction |
| `libarchive_oxide-cli` | command-line tools |
| `fuzz` | unpublished fuzz targets and shared cases |
| `docs/adr` | accepted architecture decisions |

See [CONTRIBUTING.md](CONTRIBUTING.md), [ROADMAP.md](ROADMAP.md), and
[CHANGELOG.md](CHANGELOG.md).

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.

Contributions are licensed under the same terms unless explicitly stated
otherwise.
