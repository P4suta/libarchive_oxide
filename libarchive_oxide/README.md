# libarchive_oxide

[![crates.io](https://img.shields.io/crates/v/libarchive_oxide.svg)](https://crates.io/crates/libarchive_oxide)
[![docs.rs](https://img.shields.io/docsrs/libarchive_oxide.svg)](https://docs.rs/libarchive_oxide)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

The std high-level API of
[`libarchive_oxide`](https://github.com/P4suta/libarchive_oxide): a unified,
streaming, pure-Rust archive library. It reads **and** writes `tar` / `cpio` /
`ar` / `zip` / `7z` / `iso9660` (incl. zip64 and WinZip AES-256), layers
`gzip` / `zstd` / `xz` / `lz4` compression transparently over any format, and adds
auto-detection, safe filesystem extraction, and a sans-IO incremental source.
`#![forbid(unsafe_code)]`, no `dyn` in library source.

An independent from-scratch reimplementation (the "oxidation" of libarchive); not
affiliated with the upstream libarchive project nor any existing `libarchive`
binding crate. It reuses mature pure-Rust codecs (`miniz_oxide`, `ruzstd`,
`lzma-rust2`, `lz4_flex`, RustCrypto) rather than reimplementing them, on top of
the `no_std`
[`libarchive_oxide-core`](https://crates.io/crates/libarchive_oxide-core) algebra.

## Quick start

```rust
use libarchive_oxide::{decompress_capped, reader};
use libarchive_oxide_core::{EntryData, EntryReader};

fn list(bytes: &[u8]) -> std::io::Result<()> {
    let plain = decompress_capped(bytes, 64 * 1024 * 1024)
        .map_err(std::io::Error::other)?;    // auto-detect gzip/zstd/xz/lz4, capped
    let mut r = reader(&plain)?;             // detect tar/cpio/ar/zip/7z/iso
    while let Some(mut entry) = r.next_entry()? {
        println!("{}", String::from_utf8_lossy(&entry.meta().path));
        let mut buf = [0u8; 8192];
        while entry.data().read_chunk(&mut buf)? != 0 {}
    }
    Ok(())
}
```

Key entry points: [`decompress`] / [`decompress_capped`] / [`compress`],
[`reader`] / [`reader_with_password`], [`extract::extract`], and the create
functions [`build_archive`] / [`build_tar`] / [`build_cpio`]. Runnable examples
are under [`examples/`](examples/). Full API on
[docs.rs](https://docs.rs/libarchive_oxide).

## Features

| Feature   | Default | Effect |
|-----------|:-------:|--------|
| `gzip`    | yes     | gzip filter (hand-written sans-IO over `miniz_oxide`) |
| `zstd`    | yes     | zstd filter (adapter over `ruzstd`) |
| `xz`      | yes     | xz / LZMA2 filter (adapter over `lzma-rust2`) |
| `lz4`     | yes     | lz4 frame filter (adapter over `lz4_flex`) |
| `aes`     | no      | WinZip AES-256 (AE-2) zip encryption/decryption (RustCrypto) |
| `sevenz`  | no      | 7z read+write (single-folder LZMA2; implies `gzip`) |

`--no-default-features` builds with the uncompressed formats only and drops every
codec dependency.

## Safe on untrusted input

Extraction rejects path traversal (`..`, absolute paths, Windows drive/UNC), and
[`decompress_capped`] refuses to expand past a caller-set bound (bomb defense).
The whole crate is `#![forbid(unsafe_code)]`. See the
[workspace threat model](../README.md#threat-model) and
[SECURITY.md](../SECURITY.md).

## MSRV

**1.87**, set by the codec closure. `--no-default-features` lowers it toward the
core floor (1.81).

## License

Licensed under either of [MIT](../LICENSES/MIT.txt) or
[Apache-2.0](../LICENSES/Apache-2.0.txt) at your option.

[`decompress`]: https://docs.rs/libarchive_oxide
[`decompress_capped`]: https://docs.rs/libarchive_oxide
[`compress`]: https://docs.rs/libarchive_oxide
[`reader`]: https://docs.rs/libarchive_oxide
[`reader_with_password`]: https://docs.rs/libarchive_oxide
[`extract::extract`]: https://docs.rs/libarchive_oxide
[`build_archive`]: https://docs.rs/libarchive_oxide
[`build_tar`]: https://docs.rs/libarchive_oxide
[`build_cpio`]: https://docs.rs/libarchive_oxide
