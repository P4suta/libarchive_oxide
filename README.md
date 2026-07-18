# libarchive_oxide

A pure-Rust, unified, streaming archive library — one trait algebra for archive
**formats**, compression **filters**, and **I/O**, with a `no_std` core.

`libarchive_oxide` reads and writes `tar`, `cpio`, and `ar` archives, transparently
layered over `gzip`, `zstd`, `xz`, and `lz4` compression — so `.tar.gz`, `.tar.zst`,
`.tar.xz`, and `.deb` all extract *and* compose through a single entry point.
`zip` archives can additionally be read. Runtime format/codec choice is dispatched
over sealed enums with **zero type erasure** — there is no `dyn` anywhere in the
library (a CI grep gate enforces it).

## Why

The Rust ecosystem has excellent single-purpose crates (`tar`, `zip`, `sevenz-rust`)
and mature codecs (`miniz_oxide`, `ruzstd`, `lzma-rust2`, `lz4_flex`), but no
*unified streaming* library that composes formats and filters behind one clean,
`no_std`, sans-IO abstraction the way C's `libarchive` does. `libarchive_oxide` is
that abstraction — an independent, pure-Rust reimplementation (not a binding), and
it reuses those mature codecs rather than reimplementing them.

## Architecture

The value of `libarchive_oxide` is the **trait algebra**, designed as a frozen
whole from day one so new formats and the write path load without changing any
trait:

```
Format   tar / cpio / ar            EntryReader  ⇄  EntryWriter     (a dual)
   ⟂ (orthogonal)
Filter   gzip / zstd / xz / lz4      Decoder      ⇄  Encoder         (a dual)
   │
Base     Transform::{step, finish}   sans-IO, allocation-free, caller-owned
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
- **Borrow-checked, no-seek.** `next_entry()` lends an `Entry<'_, D>` that mutably
  borrows the reader, so you cannot advance until its payload is consumed — the
  streaming contract is enforced by the compiler, not by convention.
- **No type erasure.** `EntryReader::Data`/`EntryWriter::Sink` are associated
  types and runtime dispatch uses sealed enums (`AnyReader`, `AnyDecoder`); the
  library contains no `Box<dyn>`, `&dyn`, or `&mut dyn`, enforced mechanically.
- **Pure core.** `libarchive_oxide-core` builds on bare metal
  (`thumbv7em-none-eabi`) with **zero external dependencies**; only the
  heavyweight-codec adapters and the filesystem layer require `std`.

### Crates

| Crate                     | `std`? | Role |
|---------------------------|--------|------|
| `libarchive_oxide-core`   | no     | Trait algebra, `EntryMeta`, tar/cpio/ar/iso readers+writers, the sans-IO pipeline. No external deps. |
| `libarchive_oxide`        | yes    | Compression filters (gzip native + zstd/xz/lz4 adapters), zip/7z, auto-detection, safe extraction, path sanitization, decompression caps |
| `libarchive_oxide-cli`    | yes    | `oxtar` / `oxcpio` / `oxcat` / `oxunzip` tools |

## Usage

### CLI

```sh
oxtar t archive.tar.zst              # list entries
oxtar x archive.tar.gz -C ./out      # extract safely into ./out
oxtar c out.tar.gz src/ README.md    # create (compression by extension)
oxcat archive.tar.gz > archive.tar   # decompress to stdout
oxunzip -l archive.zip               # list a zip
oxunzip archive.zip -d ./out         # extract a zip
```

Compression and format are auto-detected on read. On create, the codec is
chosen from the output extension (`.gz`/`.tgz`, `.zst`, `.xz`, `.lz4`, or plain
`.tar`). Extraction rejects path traversal (`..`, absolute paths, Windows device
names) and caps the decompressed size to defend against decompression bombs.

### Library

```rust
// Decompress (auto-detected), then read entries.
let plain = libarchive_oxide::decompress(&bytes)?;   // Cow: borrowed if uncompressed
let mut reader = libarchive_oxide::reader(&plain)?;  // detects tar / cpio / ar
while let Some(mut entry) = reader.next_entry()? {
    println!("{}", String::from_utf8_lossy(&entry.meta().path));
    let mut buf = [0u8; 8192];
    while entry.data().read_chunk(&mut buf)? != 0 { /* … */ }
}
```

## Status

**Read and write both work, across all three streaming formats.** Reading: tar
(`ustar`/`pax`/GNU), cpio (`newc`/`odc`), ar (GNU/BSD/SysV), over
gzip/zstd/xz/lz4. Writing: tar (GNU longname/longlink), cpio (`newc`), and ar
(BSD long names) writers, plus all four compression encoders — so
`libarchive_oxide` both extracts and creates `.tar`, `.tar.gz`, `.tar.zst`,
`.tar.xz`, `.tar.lz4`, and composes them into a `.deb`. The `read ∘ write = id`
round-trip and cross-checks against GNU `tar` and an independent gzip decoder are
part of the test suite. Verified end-to-end, adversarially reviewed, and hardened
against malformed-input panics and extraction attacks.

`zip` (read+write, including zip64 and WinZip AES-256), `7z` (single-folder
LZMA2), and `iso9660` are also supported; each implements the very same
`EntryReader`/`EntryWriter` traits, so they plug straight into detection and
extraction. This shows the frozen abstraction reaching across crate boundaries
even for formats whose shape (per-entry compression, metadata at the end)
differs from the tar family.

## Quality gates

`clippy` (pedantic, plus `unwrap`/`expect`/`panic` denied in library code),
`rustfmt`, `typos`, tests, a bare-metal `no_std` build, and a `check-no-dyn`
grep gate that fails on any trait object in library source. The crate forbids
`unsafe`.

## License

MIT OR Apache-2.0.
