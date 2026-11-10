# libarchive_oxide-core

[![crates.io](https://img.shields.io/crates/v/libarchive_oxide-core.svg)](https://crates.io/crates/libarchive_oxide-core) [![docs.rs](https://img.shields.io/docsrs/libarchive_oxide-core.svg)](https://docs.rs/libarchive_oxide-core) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

`no_std` + `alloc` archive metadata and uncompressed format state machines.
It depends only on the dependency-free `libarchive_oxide-protocol` contract and forbids unsafe code.

This project is independent of the upstream libarchive project.
It is not a binding.

## Contents

- compatibility re-exports of the shared `Codec`, `Limits`, and error types,
  plus archive-specific `ArchiveDecoder` and `ArchiveEncoder` state machines
- private-field `EntryMetadata`, raw `ArchivePath`, `ArchiveMetadata`, and namespaced extension preservation
- finite-by-default `Limits` and context-rich `ArchiveError`
- incremental tar, cpio, ar, mtree, and WARC decoders/encoders, including newc/crc/odc and binary LE/BE cpio plus typed hardlink normalization
- bounded RAR3/RAR5 container state machines with associated-type payload providers and a generic in-place RAR3 cryptography provider; algorithms,
  password storage, and key caching remain outside core with static dispatch
- opaque format identifiers for adapter-side static dispatch

Use [`libarchive_oxide`](https://crates.io/crates/libarchive_oxide) for codecs,
zip/7z/ISO, sync and async I/O adapters, explicit spooling, and capability-based filesystem extraction.

## Feature

| Feature | Default | Effect |
|---|:---:|---|
| `std` | no | reserved standard-library adapters |

MSRV: Rust 1.95.

## License

Licensed under either [MIT](LICENSES/MIT.txt) or [Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
