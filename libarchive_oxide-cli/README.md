# libarchive_oxide-cli

[![crates.io](https://img.shields.io/crates/v/libarchive_oxide-cli.svg)](https://crates.io/crates/libarchive_oxide-cli)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Command-line tools for `libarchive_oxide`.

```sh
cargo install libarchive_oxide-cli --locked

# Explicit native codec profile
cargo install libarchive_oxide-cli --locked --no-default-features --features native-codecs
```

| Tool | Compatible interface | Function |
|---|---|---|
| `oxarchive` | native high-level interface | inspect, plan, apply, create, verify |
| `oxtar` | supported `bsdtar` flags | create, list, extract |
| `oxcpio` | supported `bsdcpio` flags | create, list, extract |
| `oxcat` | supported `bsdcat` flags | decompress to standard output |
| `oxunzip` | supported `bsdunzip` flags | list and extract zip |

## Flags

| Tool | Supported |
|---|---|
| `oxarchive` | `--json`, `inspect`, `plan`, `apply`, `create`, `verify`, `--format`, `--filter`, `--overwrite`, `--allow-symlinks`, `--allow-hardlinks`, `--allow-special-files` |
| `oxtar` | `-c`, `-x`, `-t`, `-f FILE`, `-C DIR`, `-v`, `-z`, `--gzip`, `-j`, `--bzip2`, `-J`, `--xz`, `--zstd`, `--lz4`, `--format`, members, bundled short flags |
| `oxcpio` | `-o`, `-i`, `-t`, `-F FILE`, `-v`, `-d`, members |
| `oxcat` | files, `-`, `--help`, `--version` |
| `oxunzip` | `-l`, `-d DIR`, `-o`, `-P PASSWORD`, members |

### Unified workflow

```sh
oxarchive inspect package.tar.zst
oxarchive plan --json untrusted.zip
oxarchive apply untrusted.zip destination
oxarchive create --format tar --filter zstd package.tar.zst input/
oxarchive verify image.iso
```

`ARCHIVE` may be `-` for standard input. `apply` defaults to the conservative
policy; restoration capabilities must be enabled explicitly with the policy
flags above.

Machine output carries schema version `oxarchive.output.v0alpha1`. Inspection
JSON is a bounded JSON Lines stream with `inspect_start`, one `inspect_entry`
per event, and a required `inspect_complete` success sentinel. Plan JSON is an
advisory report, not a durable plan: `apply` never accepts it and instead opens,
plans, and applies one immutable snapshot in the same process.

`create` supports sequential `tar`, `cpio`, `ar`, and `zip`, with optional
`gzip`, `bzip2`, `xz`, `zstd`, or `lz4`. File output is synchronized and
published without replacing an existing destination. `ARCHIVE=-` writes only
archive bytes to stdout and may leave a partial stream on a later exit-1
failure; `--json create -` is refused. See the
[full CLI and streaming-output contract](https://github.com/P4suta/libarchive_oxide/blob/main/docs/cli-contract.md).

The `oci` command remains gated on the OCI layer engine and is not silently
accepted today.

Unsupported flags return exit code 2. This includes:

- `oxtar -r` and `-u`;
- `oxcpio -p` and `-C`;
- `oxunzip -n` and `-x`.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | success |
| 1 | runtime error |
| 2 | usage or unsupported option |

Flags, exit codes, and parseable output are SemVer compatibility surfaces.

## Security

- extracted paths cannot escape the destination;
- create input names cannot introduce traversal, drive, or absolute archive paths;
- file archive output is staged beside its destination and published without replacement;
- transparent decompression is capped at 4 GiB;
- all binaries use `#![forbid(unsafe_code)]`.

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
