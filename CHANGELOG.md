# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (0.x pre-1.0 rules:
breaking changes bump the minor).

From here on this file is maintained by [release-plz](https://release-plz.dev),
which derives each entry from the [Conventional Commits](https://www.conventionalcommits.org/)
merged since the previous release. Do not hand-edit released sections.

## [Unreleased]

## [0.1.0] — 2026-07-19

Initial public release of the `libarchive_oxide` workspace: a unified, streaming,
pure-Rust archive library built on one frozen trait algebra, with a `no_std` core.
An independent from-scratch reimplementation (the "oxidation" of libarchive), not
a binding and not affiliated with the upstream libarchive project.

### Added

- **Trait algebra & sans-IO core** (`libarchive_oxide-core`, `no_std` + `alloc`,
  zero external dependencies): `Transform` / `Filter` / `Format` / `EntryReader` /
  `EntryWriter` and the shared `EntryMeta`, with an allocation-free
  `step(input, output)` pipeline and no type erasure (sealed enums, no `dyn`).
- **Archive formats, read + write**:
  - `tar` — `ustar` / `pax` / GNU read; GNU longname/longlink write.
  - `cpio` — `newc` / `odc` read; `newc` write.
  - `ar` — GNU / BSD / SysV read; BSD long-name write (`.deb` composes).
  - `iso9660` — read + write, including the Joliet extension.
  - `zip` — read + write, including **zip64** and **WinZip AES-256** (AE-2).
  - `7z` — read + write, single-folder **LZMA2** subset.
- **Compression filters, decode + encode** (`libarchive_oxide`, `std`): `gzip`
  (hand-written sans-IO over `miniz_oxide`), `zstd` (`ruzstd`), `xz`/LZMA2
  (`lzma-rust2`), `lz4` frame (`lz4_flex`) — composing transparently under any
  format. Available as an incremental source, not only one-shot buffers.
- **High-level std API**: automatic compression + format detection (`reader`),
  safe filesystem extraction (`extract`), path sanitization (`sanitize`), the
  create functions (`build_archive` / `build_tar` / `build_cpio`), and
  bomb-capped decompression (`decompress_capped`).
- **Command-line tools** (`libarchive_oxide-cli`): `oxtar` / `oxcpio` / `oxcat` /
  `oxunzip`, drop-in compatible with `bsdtar` / `bsdcpio` / `bsdcat` / `bsdunzip`
  for the supported flag surface, with a unified exit-code contract (0/1/2) and
  safe-by-default extraction.

### Security

- `#![forbid(unsafe_code)]` across every published crate; no FFI, no C linked.
- Safe defaults for untrusted input: path-traversal rejection and a
  decompression-bomb cap (4 GiB in the CLI). Untrusted-header arithmetic is
  checked before allocation. See [SECURITY.md](SECURITY.md).

### Notes

- `bzip2` is intentionally **not** supported.
- MSRV: `libarchive_oxide-core` 1.81; `libarchive_oxide` and
  `libarchive_oxide-cli` 1.87.

[Unreleased]: https://github.com/P4suta/libarchive_oxide/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/P4suta/libarchive_oxide/releases/tag/v0.1.0
