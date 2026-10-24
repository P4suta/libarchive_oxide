# Archive engine guide

`libarchive_oxide` provides a Rust archive engine and command-line tools.
The source remains pre-1.0, so interfaces can change during the completion program.

Its main crate provides bounded streaming readers and writers, archive inspection and extraction, and a filesystem adapter that reports its capabilities.
The `libarchive_oxide-package` crate checks software-package structure and integrity, with separate results for signature validity and issuer trust.

## Install from source

The repository pins Rust in `mise.toml` and `rust-toolchain.toml`.

```sh
git clone https://github.com/P4suta/libarchive_oxide.git
cd libarchive_oxide
mise install rust
mise x -- cargo install --path libarchive_oxide-cli --locked
```

This builds the checked-out source and installs the `oxarchive` command.

## Check available capabilities

The capability report lists format and codec support in the installed build.

```sh
oxarchive capabilities --json
```

Inspect an archive with `oxarchive inspect archive.tar.gz`.
The command also supports listing, planning, applying, creating, and verifying archives, OCI-layer inspection, and offline package checks.

## Formats and codecs

The [support matrix](support-matrix.md) defines read and write support by format and build feature.
Portable codecs use Rust implementations and form the default profile.
The optional native profile adds native codec backends.

The `libarchive_oxide-core` and `libarchive_oxide-codecs` crates provide `no_std + alloc` layers.
The 7z reader supports more coder graphs than the writer, which emits a reproducible LZMA2 profile.
Cabinet archive continuation requires the advanced bounded volume-reader API, and raw input requires explicit selection.

See [codec profiles](codec-profiles.md) for the build profiles and [the completion roadmap](modern-replacement.md) for planned work.

## Extraction and package checks

Extraction uses the conservative safe policy by default.
Overwrite, links, and special files require explicit options.
The filesystem adapter validates destination paths and resource limits before writes and publishes regular files without replacement.

Machine-readable plans are advisory.
The `apply` command uses its in-process plan.
Package checks work offline and report integrity, signature validity, and trust independently.
Trust requires explicit signer-fingerprint pins.
Encrypted archives take passwords from files or an interactive prompt.

See the [command contract](cli-contract.md) and [filesystem adapters](filesystem-adapters.md) for the detailed behavior and limits.

## Development

See [the contribution guide](../CONTRIBUTING.md) for tool setup, local checks, and release verification.
Ordinary pull requests and merge groups run the portable gate.
Platform matrices, fuzzing, streaming soaks, and the other full checks run before release publication or through an explicit full-verification request.

## License

The source uses the [Massachusetts Institute of Technology license](../LICENSES/MIT.txt) or [Apache License 2.0](../LICENSES/Apache-2.0.txt).
Some Cabinet reference fixtures have [their own license](../LICENSES/LGPL-2.1-or-later.txt).
`REUSE.toml` records their attribution and license.

[Original project overview](https://github.com/P4suta/libarchive_oxide/blob/4b42387e3e66e02ae7d9383e707559a3857ae797/README.md).
