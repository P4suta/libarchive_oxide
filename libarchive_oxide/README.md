# libarchive_oxide

[![crates.io](https://img.shields.io/crates/v/libarchive_oxide.svg)](https://crates.io/crates/libarchive_oxide)
[![docs.rs](https://img.shields.io/docsrs/libarchive_oxide.svg)](https://docs.rs/libarchive_oxide)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

Archive detection, compression, extraction, and creation over
[`libarchive_oxide-core`](https://crates.io/crates/libarchive_oxide-core).

Supported formats: tar, cpio, ar, zip, 7z, and ISO 9660. Supported filters:
gzip, zstd, xz, and lz4. The crate forbids unsafe code.

This project is independent of the upstream libarchive project. It is not a
binding.

## Example

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

`--no-default-features` retains uncompressed formats and zip store mode.

MSRV: Rust 1.87.

## Security

Use `decompress_capped` for untrusted compressed input. Filesystem extraction
rejects path traversal. See the
[security policy](https://github.com/P4suta/libarchive_oxide/blob/main/SECURITY.md).

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
