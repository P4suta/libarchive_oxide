# libarchive_oxide-cli

[![crates.io](https://img.shields.io/crates/v/libarchive_oxide-cli.svg)](https://crates.io/crates/libarchive_oxide-cli)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Command-line tools for `libarchive_oxide`.

```sh
cargo install libarchive_oxide-cli --locked
```

| Tool | Compatible interface | Function |
|---|---|---|
| `oxtar` | supported `bsdtar` flags | create, list, extract |
| `oxcpio` | supported `bsdcpio` flags | create, list, extract |
| `oxcat` | supported `bsdcat` flags | decompress to standard output |
| `oxunzip` | supported `bsdunzip` flags | list and extract zip |

## Flags

| Tool | Supported |
|---|---|
| `oxtar` | `-c`, `-x`, `-t`, `-f FILE`, `-C DIR`, `-v`, `-z`, `--gzip`, `-J`, `--xz`, `--zstd`, `--lz4`, `--format`, members, bundled short flags |
| `oxcpio` | `-o`, `-i`, `-t`, `-F FILE`, `-v`, `-d`, members |
| `oxcat` | files, `-`, `--help`, `--version` |
| `oxunzip` | `-l`, `-d DIR`, `-o`, `-P PASSWORD`, members |

Unsupported flags return exit code 2. This includes:

- `oxtar -j`, `--bzip2`, `-r`, and `-u`;
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
- transparent decompression is capped at 4 GiB;
- all binaries use `#![forbid(unsafe_code)]`.

## License

Licensed under either [MIT](LICENSES/MIT.txt) or
[Apache-2.0](LICENSES/Apache-2.0.txt), at your option.
