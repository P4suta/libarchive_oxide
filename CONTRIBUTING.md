# Contributing

## Setup

Tools are declared in `mise.toml`. Rust is configured by
`rust-toolchain.toml`.

```sh
mise install
mise run hooks
```

Do not bypass hooks with `--no-verify`.

## Required checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps
bash scripts/check-no-dyn.sh
cargo build -p libarchive_oxide-core --target thumbv7em-none-eabi
cargo deny check
uvx --with charset-normalizer reuse lint
bash scripts/check-license-sync.sh
```

CI also runs:

- tests on Linux, macOS, and Windows;
- MSRV verification;
- `s390x-unknown-linux-gnu` tests under QEMU;
- `cargo-semver-checks`;
- bounded libFuzzer runs;
- CodeQL and workflow linting.

## Design constraints

Changes must preserve [ADR-0001](docs/adr/0001-core-architecture.md):

- `libarchive_oxide-core` remains `no_std` + `alloc`;
- the core has no external dependencies;
- formats and filters remain independent;
- runtime dispatch uses sealed enums, not trait objects;
- read/write and encode/decode use the existing trait interfaces.

Propose a new ADR for a durable, cross-cutting decision. Do not use ADRs for
implementation details, maintenance tasks, or reversals with no compatibility
impact.

## Tests

- Add round-trip tests for new read/write support.
- Add differential tests when an independent implementation is available.
- Add regression tests for malformed input and extraction controls.
- Add or update fuzz cases for parser changes.

Tests may skip unavailable external reference tools. CI must still exercise the
portable assertions.

## Compatibility

| Crate | MSRV |
|---|---:|
| `libarchive_oxide-core` | 1.81 |
| `libarchive_oxide` | 1.87 |
| `libarchive_oxide-cli` | 1.87 |

Before 1.0:

- breaking API or CLI changes require a minor version;
- additive changes and fixes use a patch version;
- CLI flags, exit codes, and parseable output are compatibility surfaces.

`cargo-semver-checks` detects Rust API changes. Tests cover the CLI contract.

## Commits and pull requests

- Use [Conventional Commits](https://www.conventionalcommits.org/).
- Use squash merge.
- Add SPDX headers to new source and configuration files.
- Update user-facing documentation with the implementation.
- Do not edit released CHANGELOG sections.

Release mechanics are defined by
[ADR-0002](docs/adr/0002-workspace-releases.md). Merging a release-plz Release
PR publishes crates and creates the tag and GitHub Release.

## License

The repository uses [REUSE](https://reuse.software/). Run:

```sh
uvx --with charset-normalizer reuse lint
bash scripts/check-license-sync.sh
```

New files must declare `MIT OR Apache-2.0` through an SPDX header or
`REUSE.toml`.

Unless explicitly stated otherwise, submitted contributions are licensed under
MIT OR Apache-2.0 without additional terms.

## Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
