# libarchive_oxide-core

[![crates.io](https://img.shields.io/crates/v/libarchive_oxide-core.svg)](https://crates.io/crates/libarchive_oxide-core)
[![docs.rs](https://img.shields.io/docsrs/libarchive_oxide-core.svg)](https://docs.rs/libarchive_oxide-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`no_std` + `alloc` archive traits and uncompressed formats. This crate has no
external dependencies and forbids unsafe code.

This project is independent of the upstream libarchive project. It is not a
binding.

## Contents

- `Transform`, `Filter`, `Format`, `EntryReader`, and `EntryWriter`
- shared entry metadata
- sans-IO transform interfaces
- tar, cpio, ar, and ISO 9660 readers and writers
- sealed-enum runtime dispatch

Use [`libarchive_oxide`](https://crates.io/crates/libarchive_oxide) for codecs,
zip/7z, detection, and filesystem extraction.

## Feature

| Feature | Default | Effect |
|---|:---:|---|
| `std` | no | reserved standard-library adapters |

MSRV: Rust 1.81.

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
