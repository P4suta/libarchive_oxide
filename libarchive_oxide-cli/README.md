# libarchive_oxide-cli

[![crates.io](https://img.shields.io/crates/v/libarchive_oxide-cli.svg)](https://crates.io/crates/libarchive_oxide-cli)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Four command-line tools over
[`libarchive_oxide`](https://crates.io/crates/libarchive_oxide). Their interfaces
mirror libarchive's `bsdtar` / `bsdcpio` / `bsdcat` / `bsdunzip` and are **drop-in
compatible** for the supported flag surface below. The `ox` prefix follows
libarchive's own collision-avoidance naming (and the modern Rust-CLI convention of
`rg`/`fd`/`bat`), so these never clash with a system `tar`/`cpio`/`cat`/`unzip`.

```sh
cargo install libarchive_oxide-cli
```

| Tool      | bsd equivalent | Role |
|-----------|----------------|------|
| `oxtar`   | `bsdtar`       | create/list/extract tar, with gzip/zstd/xz/lz4 |
| `oxcpio`  | `bsdcpio`      | create/list/extract cpio |
| `oxcat`   | `bsdcat`       | transparent decompression to stdout |
| `oxunzip` | `bsdunzip`     | zip extraction (zip64 / AES) |

Every tool prints its own contract with `--help`.

## Supported flags

| Tool | Flags |
|------|-------|
| `oxtar`   | `-c`/`-x`/`-t`, `-f FILE` (`-`/omit = stdin/stdout), `-C DIR`, `-v`, `-z`/`--gzip`, `-J`/`--xz`, `--zstd`, `--lz4`, `--format tar\|ustar\|gnutar\|cpio`, member operands on `-x`/`-t`, `--help`, `--version`. Traditional bundled form (`oxtar czf a.tgz .`) works. |
| `oxcpio`  | `-o`/`-i`/`-t` (and `-it` = list), `-F FILE`, `-v`, `-d`, member operands on `-i`/`-t`. `-o` reads filenames from stdin. |
| `oxcat`   | `[FILE...]` (`-`/none = stdin), `--help`, `--version`. |
| `oxunzip` | `-l`, `-d DIR`, `-o`, `-P PASSWORD`, member operands, `--help`, `--version`. |

Reads always auto-detect compression (gzip/zstd/xz/lz4) and format
(tar/cpio/ar/zip/7z/iso).

## Exit codes (unified across all four tools)

| Code | Meaning |
|------|---------|
| `0`  | success |
| `1`  | runtime failure (I/O error, corrupt archive, decompression-bomb cap hit) |
| `2`  | usage error — bad, unknown, or unsupported flag; missing operand |

## Intentionally unsupported (fails with exit 2 — never a silent no-op)

Classic flags the library cannot honor faithfully return `unsupported: <flag>`
rather than pretending to work. This is a deliberate debt-exclusion policy, not an
oversight:

- `oxtar -j` / `--bzip2` — bzip2 is not supported by the library; recompress with `-z`/`-J`/`--zstd`/`--lz4`.
- `oxtar -r` / `-u` — append/update. Rewriting an existing archive's trailer is out of scope for the 0.x line; build afresh with `-c`.
- `oxcpio -p` (pass-through copy), `-C` (I/O block size).
- `oxunzip -n` (never-overwrite), `-x` (exclude).
- Any other classic flag → `unknown flag`.

No nonstandard "modern-only" flags of our own invention are added.

## Safe defaults (a documented divergence from historical tar)

Because these tools are built to consume **untrusted** archives, two safety nets
are **on by default** — unlike classic `tar`:

- **Path-traversal rejection** — entries whose path escapes the destination
  (`../`, absolute, drive/UNC) are refused.
- **Decompression-bomb cap** — transparent decompression is capped at 4 GiB.

## SemVer: the CLI interface *is* the contract

For this crate, the **command-line interface is the public API**, and it is what
SemVer governs. Concretely:

- **Major (breaking):** removing or renaming a flag or subcommand, changing a
  flag's meaning, changing an exit code for an existing condition, or altering the
  parseable shape of stdout for a given invocation.
- **Minor (additive):** adding a new flag, accepting a new input format, or adding
  output that does not change existing lines.
- **Patch:** bug fixes that make behavior match the documented contract.

The bsd* interfaces these tools track are themselves long-frozen, so churn is
expected to be minimal. The internal library API (`libarchive_oxide`) has its own,
separate SemVer surface. See
[CONTRIBUTING.md](https://github.com/P4suta/libarchive_oxide/blob/main/CONTRIBUTING.md) for the full
stability policy and the path to 1.0.

## License

Licensed under either of [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt) at your option.
