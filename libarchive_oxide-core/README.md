# libarchive_oxide-core

[![crates.io](https://img.shields.io/crates/v/libarchive_oxide-core.svg)](https://crates.io/crates/libarchive_oxide-core)
[![docs.rs](https://img.shields.io/docsrs/libarchive_oxide-core.svg)](https://docs.rs/libarchive_oxide-core)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

The `no_std` + `alloc`, sans-IO **core** of
[`libarchive_oxide`](https://github.com/P4suta/libarchive_oxide): the frozen trait
algebra and the uncompressed archive formats, with **zero external dependencies**.

This crate is the foundation the flagship `libarchive_oxide` builds on. It is an
independent, from-scratch pure-Rust reimplementation of what C's libarchive does —
not a binding, and not affiliated with the upstream libarchive project.

## What it contains

- **The trait algebra** — `Transform`, `Filter`, `Format`, `EntryReader`,
  `EntryWriter`, and the shared `EntryMeta` / `EntryKind`. Designed as a frozen
  whole so formats and the write path load without changing any trait.
- **The sans-IO pipeline** — every transform is one allocation-free
  `step(input, output)` primitive; there is no I/O, no allocation policy, and no
  `dyn` in this crate.
- **Uncompressed formats, read and write** — `tar` (`ustar`/`pax`/GNU),
  `cpio` (`newc`/`odc`), `ar` (GNU/BSD/SysV), and `iso9660` (incl. Joliet).

It builds on bare metal (`thumbv7em-none-eabi`) with no allocator beyond `alloc`
and no third-party crate in any dependency table. Compression codecs, `std`
filesystem extraction, zip/7z, and auto-detection live in the flagship crate,
which reuses mature pure-Rust codec crates.

## Which crate do I want?

Most users want the std flagship
[`libarchive_oxide`](https://crates.io/crates/libarchive_oxide) instead — it
re-exports this crate and adds codecs, extraction, and detection. Depend on
`libarchive_oxide-core` directly only for `no_std`/embedded targets, or to build
your own format on the raw algebra.

## Features

| Feature | Default | Effect |
|---------|:-------:|--------|
| `std`   | no      | thin `std` adaptors (reserved; the crate is `no_std` + `alloc` by default) |

## MSRV

**1.81** (requires `core::error::Error`, stabilized in Rust 1.81). This is the
lowest floor in the workspace; zero external dependencies keep it there.

## License

Licensed under either of [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt) at your option.
