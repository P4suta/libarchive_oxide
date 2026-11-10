# libarchive_oxide-protocol

[![crates.io](https://img.shields.io/crates/v/libarchive_oxide-protocol.svg)](https://crates.io/crates/libarchive_oxide-protocol) [![docs.rs](https://img.shields.io/docsrs/libarchive_oxide-protocol.svg)](https://docs.rs/libarchive_oxide-protocol) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Dependency-free `no_std + alloc` contracts shared by archive formats, byte codecs, and I/O adapters.
The crate owns only `Codec`, codec progress types,
finite `Limits`, and context-rich `ArchiveError`; it does not know any archive format, filesystem, async runtime, or concrete compression implementation.

`libarchive_oxide-core` re-exports this surface for source compatibility.
Concrete portable codecs depend directly on this crate, keeping them siblings of the archive-format state machines rather than clients of those formats.

MSRV: Rust 1.88.

## License

Licensed under either [MIT](LICENSES/MIT.txt) or [Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
