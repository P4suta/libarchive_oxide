# libarchive_oxide

[![CI](https://github.com/P4suta/libarchive_oxide/actions/workflows/ci.yml/badge.svg)](https://github.com/P4suta/libarchive_oxide/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![MSRV](https://img.shields.io/badge/MSRV-1.87%20flagship%20%2F%201.81%20core-blue.svg)](#minimum-supported-rust-version)
[![unsafe: forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![crates.io](https://img.shields.io/crates/v/libarchive_oxide.svg)](https://crates.io/crates/libarchive_oxide)
[![docs.rs](https://img.shields.io/docsrs/libarchive_oxide.svg)](https://docs.rs/libarchive_oxide)

A pure-Rust, unified, streaming archive library — one trait algebra for archive
**formats**, compression **filters**, and **I/O**, with a `no_std` core.
`#![forbid(unsafe_code)]`, no `dyn` anywhere (a CI grep gate enforces it), and a
`no_std` + `alloc` core with **zero external dependencies**.

> **Not affiliated with any existing project.** `libarchive_oxide` is an
> independent, from-scratch pure-Rust reimplementation — the "oxidation" of what
> C's [libarchive](https://www.libarchive.org/) does. It is **not** affiliated
> with, endorsed by, or derived from the upstream libarchive project, and it is
> **not** the `libarchive` binding crate (`-sys`) — it links no C and reads no
> libarchive source. The `_oxide` suffix marks a native reimplementation
> (in the tradition of `miniz_oxide`), not a binding.

The Rust ecosystem has excellent single-purpose crates (`tar`, `zip`,
`sevenz-rust`) and mature codecs (`miniz_oxide`, `ruzstd`, `lzma-rust2`,
`lz4_flex`), but no *unified streaming* library that composes formats and filters
behind one clean, `no_std`, sans-IO abstraction the way libarchive does.
`libarchive_oxide` is that abstraction: it reuses those mature codecs rather than
reimplementing them, and layers a single frozen algebra over every format so
`.tar.gz`, `.tar.zst`, `.deb`, `.zip`, `.7z`, and `.iso` all detect, extract, and
compose through one entry point.

## Supported formats

Read **and** write across the board, verified end-to-end with `read ∘ write = id`
round-trips and cross-checks against reference tools:

| Format     | Read | Write | Notes |
|------------|:----:|:-----:|-------|
| `tar`      | ✅   | ✅    | `ustar` / `pax` / GNU read; GNU longname/longlink write |
| `cpio`     | ✅   | ✅    | `newc` / `odc` read; `newc` write |
| `ar`       | ✅   | ✅    | GNU / BSD / SysV read; BSD long-name write (`.deb` composes) |
| `zip`      | ✅   | ✅    | incl. **zip64** and **WinZip AES-256** (AE-2) |
| `7z`       | ✅   | ✅    | single-folder **LZMA2** subset |
| `iso9660`  | ✅   | ✅    | incl. **Joliet** extension |

| Compression filter | Decode | Encode | Backend |
|--------------------|:------:|:------:|---------|
| `gzip`             | ✅     | ✅     | hand-written sans-IO filter over `miniz_oxide` |
| `zstd`             | ✅     | ✅     | adapter over `ruzstd` |
| `xz` (LZMA2)       | ✅     | ✅     | adapter over `lzma-rust2` |
| `lz4` (frame)      | ✅     | ✅     | adapter over `lz4_flex` |
| `bzip2`            | —      | —      | **not supported** (deliberately out of scope) |

Filters compose transparently under any format, so `.tar.gz`, `.tar.zst`,
`.tar.xz`, and `.tar.lz4` extract *and* compose through the same entry point.
Decompression is available as an **incremental source** (push/pull sans-IO), not
only a one-shot buffer.

## Architecture

The value of `libarchive_oxide` is the **trait algebra**, designed as a frozen
whole from day one so new formats and the write path load without changing any
trait:

```
Format   tar / cpio / ar / iso / zip / 7z   EntryReader  ⇄  EntryWriter   (a dual)
   ⟂ (orthogonal)
Filter   gzip / zstd / xz / lz4             Decoder      ⇄  Encoder        (a dual)
   │
Base     Transform::{step, finish}          sans-IO, allocation-free, caller-owned
```

- **Sans-IO base.** Every transform is one allocation-free `step(input, output)`
  primitive; push/pull and `std::io` live in thin adapters on top.
- **Orthogonal.** Adding a compression filter changes no format code, and vice
  versa. The format layer reads bytes and never knows if they were compressed.
- **Dual.** `EntryReader`/`EntryWriter` and `Decoder`/`Encoder` are symmetric at
  the type level; the shared `EntryMeta` is produced by readers and consumed by
  writers.
- **Origin-opaque.** A hand-written filter (gzip) and an adapter over a reused
  crate (zstd/xz/lz4) are indistinguishable to callers.
- **No type erasure.** Runtime dispatch uses sealed enums (`AnyReader`,
  `AnyDecoder`), never a trait object — no `Box<dyn>`, `&dyn`, or `&mut dyn` in
  library source, enforced mechanically by `scripts/check-no-dyn.sh` in CI.
- **Pure core.** `libarchive_oxide-core` builds on bare metal
  (`thumbv7em-none-eabi`) with **zero external dependencies**; only the
  heavyweight-codec adapters and the filesystem layer require `std`.

## Cargo features

Features live on the flagship `libarchive_oxide` crate. The core crate is
`no_std` + `alloc` and carries no codec features.

| Feature   | Default | Effect |
|-----------|:-------:|--------|
| `gzip`    | yes     | gzip filter (hand-written sans-IO over `miniz_oxide`) |
| `zstd`    | yes     | zstd filter (adapter over `ruzstd`) |
| `xz`      | yes     | xz / LZMA2 filter (adapter over `lzma-rust2`) |
| `lz4`     | yes     | lz4 frame filter (adapter over `lz4_flex`) |
| `aes`     | no      | WinZip AES-256 (AE-2) zip encryption/decryption (RustCrypto) |
| `sevenz`  | no      | 7z read+write (single-folder LZMA2; implies `gzip` for shared CRC-32) |

`--no-default-features` builds the flagship with the uncompressed formats only
(tar/cpio/ar/iso/zip-store) and drops every codec dependency, which also lowers
the effective MSRV toward the core floor.

## Minimum Supported Rust Version

- **`libarchive_oxide-core`**: **1.81** (needs `core::error::Error`, stabilized
  in 1.81). Zero external dependencies, so this is the true floor.
- **`libarchive_oxide` / `libarchive_oxide-cli`**: **1.87**, set by the codec
  closure (`ruzstd`, `lzma-rust2`, `lz4_flex`, RustCrypto). Building the flagship
  with `--no-default-features` lowers it toward the core floor.

MSRV is measured per crate with `cargo-msrv`, declared via `rust-version`, and
verified in CI. A raise is treated as a minor version bump. The edition stays
2021 to keep the floor low.

## Library quick start

```rust
use libarchive_oxide::{decompress_capped, reader};
use libarchive_oxide_core::{EntryData, EntryReader};

// Decompress untrusted input under a bomb cap, then stream entries.
fn list(bytes: &[u8]) -> std::io::Result<()> {
    // Auto-detects gzip/zstd/xz/lz4 (Cow: borrowed if already uncompressed),
    // and refuses to expand past the cap.
    let plain = decompress_capped(bytes, 64 * 1024 * 1024)
        .map_err(std::io::Error::other)?;

    // Detects tar / cpio / ar / zip / 7z / iso and returns a sealed reader.
    let mut r = reader(&plain)?;
    while let Some(mut entry) = r.next_entry()? {
        println!("{}", String::from_utf8_lossy(&entry.meta().path));
        let mut buf = [0u8; 8192];
        while entry.data().read_chunk(&mut buf)? != 0 { /* consume payload */ }
    }
    Ok(())
}
```

`decompress_capped` and `reader` are **safe on untrusted input by default** — see
the [threat model](#threat-model). Create the dual side with `build_archive`
(codec chosen by output extension), `build_tar`, or `build_cpio`. Full API on
[docs.rs](https://docs.rs/libarchive_oxide); runnable examples live under
[`libarchive_oxide/examples/`](libarchive_oxide/examples/).

## Command-line tools

`libarchive_oxide-cli` builds four binaries whose interfaces are **drop-in
compatible** with libarchive's `bsdtar` / `bsdcpio` / `bsdcat` / `bsdunzip` for
the supported flag surface. The `ox` prefix follows libarchive's own
collision-avoidance naming (and the modern Rust-CLI convention of `rg`/`fd`/`bat`)
so they never clash with a system `tar`/`cpio`/`cat`/`unzip` on `PATH`.

```sh
cargo install libarchive_oxide-cli   # installs oxtar, oxcpio, oxcat, oxunzip
```

| Tool      | bsd equivalent | Role |
|-----------|----------------|------|
| `oxtar`   | `bsdtar`       | create/list/extract tar, with gzip/zstd/xz/lz4 |
| `oxcpio`  | `bsdcpio`      | create/list/extract cpio |
| `oxcat`   | `bsdcat`       | transparent decompress to stdout |
| `oxunzip` | `bsdunzip`     | zip extraction (zip64 / AES) |

```sh
oxtar czf out.tar.zst src/ README.md   # create (codec by extension)
oxtar tf archive.tar.gz                 # list
oxtar xf archive.tar.gz -C ./out        # extract safely into ./out
oxcat archive.tar.gz > archive.tar      # decompress to stdout
oxunzip -l archive.zip                   # list a zip
oxunzip archive.zip -d ./out             # extract a zip
```

| Supported (drop-in) | Intentionally unsupported → exit 2, never a silent no-op |
|---------------------|----------------------------------------------------------|
| `oxtar` `-c`/`-x`/`-t`, `-f FILE`, `-C DIR`, `-v`, `-z`/`--gzip`, `-J`/`--xz`, `--zstd`, `--lz4`, `--format`, member operands, bundled `czf` form | `oxtar -j`/`--bzip2` (bzip2 removed), `-r`/`-u` (append/update) |
| `oxcpio` `-o`/`-i`/`-t`, `-F FILE`, `-v`, `-d`, member operands | `oxcpio -p` (pass-through), `-C` (block size) |
| `oxcat` `[FILE...]`, `--help`, `--version` | — |
| `oxunzip` `-l`, `-d DIR`, `-o`, `-P PASSWORD`, member operands | `oxunzip -n` (never-overwrite), `-x` (exclude) |

Reads always auto-detect compression and format. Classic flags the library cannot
honor faithfully return `unsupported: <flag>` (exit 2) rather than pretending to
work — a deliberate debt-exclusion policy, not an oversight. No nonstandard
"modern-only" flags of our own are added. The CLI's flag/exit-code/output surface
**is** the SemVer contract for that crate — see
[`libarchive_oxide-cli/README.md`](libarchive_oxide-cli/README.md).

## Layout

| Crate                     | Published | `std`? | Role |
|---------------------------|:---------:|:------:|------|
| `libarchive_oxide-core`   | ✅        | no     | Frozen trait algebra, `EntryMeta`, the sans-IO pipeline, and the uncompressed formats (tar/cpio/ar/iso) — readers **and** writers. Zero external deps, `#![forbid(unsafe_code)]`. |
| `libarchive_oxide`        | ✅        | yes    | The std flagship: compression filters (gzip native + zstd/xz/lz4 adapters), zip/7z, AES-256, auto-detection, filesystem extraction, path sanitization, decompression caps. |
| `libarchive_oxide-cli`    | ✅        | yes    | The `oxtar`/`oxcpio`/`oxcat`/`oxunzip` tools (bsd*-compatible). |
| `libarchive_oxide-fuzz` · `-fuzz-cases` | ❌ | yes | cargo-fuzz targets and shared invariant bodies (`publish = false`). |

## Threat model

`libarchive_oxide` is designed to consume **untrusted, attacker-controlled**
archives, so the safe path is the default and the unsafe knob is explicit:

- **Path-traversal rejection.** Extraction refuses entries whose sanitized path
  escapes the destination — `..` components, absolute paths, Windows drive/UNC
  prefixes, and device names — via `libarchive_oxide::sanitize`.
- **Decompression-bomb cap.** `decompress_capped(bytes, max)` fails with
  `LimitExceeded` before expanding past the cap; the CLI applies a 4 GiB cap by
  default. The uncapped `decompress` is opt-in for trusted input.
- **No `unsafe`.** The whole tree is `#![forbid(unsafe_code)]`; there is no FFI
  and no C linked.
- **Checked arithmetic.** Buffer sizes and indices derived from untrusted headers
  use explicit `checked_*` / `saturating_*` arithmetic and are validated before
  allocation.

See [SECURITY.md](SECURITY.md) for the full policy and how to report a
vulnerability.

## Documentation

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — build, test, MSRV/SemVer policy, verification methodology
- [`SECURITY.md`](SECURITY.md) — threat model, hardening, private reporting
- [`ROADMAP.md`](ROADMAP.md) — staged hardening record (OSS-Fuzz, big-endian, `no_std` codecs)
- [`CHANGELOG.md`](CHANGELOG.md) — release history (maintained by release-plz)

## License

Dual-licensed under either of [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt) at your option.

The repository follows the [REUSE](https://reuse.software) specification: every
file declares its licensing via an SPDX header or `REUSE.toml`, and `reuse lint`
passes. Every published crate is `MIT OR Apache-2.0`.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
