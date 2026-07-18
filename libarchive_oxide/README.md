# libarchive_oxide

Unified streaming archive library in pure Rust: `tar` / `cpio` / `ar` / `zip` / `7z` / `iso9660`
read+write with `gzip` / `zstd` / `xz` / `lz4` codecs, zip64 and WinZip AES-256, auto-detection, safe
filesystem extraction, and a sans-IO sequential source model. `#![forbid(unsafe_code)]`.

An independent from-scratch reimplementation (the "oxidation" of libarchive); not affiliated with the
libarchive project or any existing `libarchive` bindings crate.

See the [workspace README](../README.md) for the format matrix, feature table, and threat model.

## License

Licensed under either of [MIT](../LICENSES/MIT.txt) or [Apache-2.0](../LICENSES/Apache-2.0.txt) at
your option.
