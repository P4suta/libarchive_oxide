# libarchive_oxide-core

[![crates.io](https://img.shields.io/crates/v/libarchive_oxide-core.svg)](https://crates.io/crates/libarchive_oxide-core)
[![docs.rs](https://img.shields.io/docsrs/libarchive_oxide-core.svg)](https://docs.rs/libarchive_oxide-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`no_std` + `alloc` archive traits and uncompressed formats. This crate has no
external dependencies and forbids unsafe code.

This project is independent of the upstream libarchive project. It is not a
binding.

## Contents

- `Codec`, `ArchiveDecoder`, and `ArchiveEncoder` sans-I/O state machines
- private-field `EntryMetadata`, raw `ArchivePath`, `ArchiveMetadata`, and
  namespaced extension preservation
- finite-by-default `Limits` and context-rich `ArchiveError`
- incremental tar, cpio, and ar decoders/encoders, including newc/crc/odc and
  binary LE/BE cpio plus typed hardlink normalization
- opaque format identifiers for adapter-side static dispatch

Use [`libarchive_oxide`](https://crates.io/crates/libarchive_oxide) for codecs,
zip/7z/ISO, sync and async I/O adapters, explicit spooling, and capability-based
filesystem extraction.

## Feature

| Feature | Default | Effect |
|---|:---:|---|
| `std` | no | reserved standard-library adapters |

MSRV: Rust 1.85.

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
