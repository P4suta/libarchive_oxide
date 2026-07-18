# libarchive_oxide-cli

bsdtar-family command-line tools over [`libarchive_oxide`](https://crates.io/crates/libarchive_oxide).
Their interfaces mirror `bsdtar`/`bsdcpio`/`bsdcat`/`bsdunzip` and are **drop-in compatible** for the
supported flag surface below:

- `oxtar`   — bsdtar-style tar (with gzip/zstd/xz/lz4)
- `oxcpio`  — bsdcpio-style cpio
- `oxcat`   — bsdcat-style transparent decompression to stdout
- `oxunzip` — bsdunzip-style zip extraction (zip64 / AES)

```sh
cargo install libarchive_oxide-cli
```

Every tool prints its own contract with `--help`.

## Exit codes (unified across all four tools)

| Code | Meaning |
|------|---------|
| `0`  | success |
| `1`  | runtime failure (I/O error, corrupt archive, decompression-bomb cap hit) |
| `2`  | usage error — bad, unknown, or unsupported flag; missing operand |

## Supported flags

| Tool | Flags |
|------|-------|
| `oxtar`   | `-c`/`-x`/`-t`, `-f FILE` (`-`/omit = stdin/stdout), `-C DIR`, `-v`, `-z`/`--gzip`, `-J`/`--xz`, `--zstd`, `--lz4`, `--format tar\|ustar\|gnutar\|cpio`, member operands on `-x`/`-t`, `--help`, `--version`. Traditional bundled form (`oxtar czf a.tgz .`) works. |
| `oxcpio`  | `-o`/`-i`/`-t` (and `-it` = list), `-F FILE`, `-v`, `-d`, member operands on `-i`/`-t`. `-o` reads filenames from stdin. |
| `oxcat`   | `[FILE...]` (`-`/none = stdin), `--help`, `--version`. |
| `oxunzip` | `-l`, `-d DIR`, `-o`, `-P PASSWORD`, member operands, `--help`, `--version`. |

Reads always auto-detect compression (gzip/zstd/xz/lz4) and format (tar/cpio/ar/zip/7z/iso).

## Intentionally unsupported (fails with exit 2 — never a silent no-op)

Classic flags the library cannot honor faithfully return `unsupported: <flag>` rather than pretending
to work. This is a deliberate debt-exclusion policy, not an oversight:

- `oxtar -j` / `--bzip2` — bzip2 was removed from the library; recompress with `-z`/`-J`/`--zstd`/`--lz4`.
- `oxtar -r` / `-u` — append/update. Rewriting an existing archive's trailer is out of scope for the
  0.x line; build afresh with `-c`.
- `oxcpio -p` (pass-through copy), `-C` (I/O block size).
- `oxunzip -n` (never-overwrite), `-x` (exclude).
- Any other classic flag → `unknown flag`.

No nonstandard "modern-only" flags of our own invention are added.

## Safe defaults (a documented divergence from historical tar)

Because these tools are built to consume **untrusted** archives, two safety nets are **on by default**
— unlike classic `tar`:

- **Path-traversal rejection** — entries whose path escapes the destination (`../`, absolute, drive/UNC)
  are refused.
- **Decompression-bomb cap** — transparent decompression is capped (4 GiB).

The full interface and SemVer contract are also documented in the [workspace README](../README.md).

## License

Licensed under either of [MIT](../LICENSES/MIT.txt) or [Apache-2.0](../LICENSES/Apache-2.0.txt) at
your option.
