# Contributing

## Setup

Tools are declared in `mise.toml`. Rust is configured by
`rust-toolchain.toml`.

```sh
mise install
mise run hooks
```

Do not bypass hooks with `--no-verify`.

The hooks use two layers:

- `pre-commit` formats and spell-checks staged files, then runs the fast lint,
  static-dispatch, and license checks;
- `pre-push` runs `just ci`, which mirrors every practical CI gate
  available on a developer machine, including all-feature tests, rustdoc,
  bare-metal `no_std`, dependency policy, packaged-crate consumer validation,
  release policy, workflow lint, and both MSRVs.

Run the same suites explicitly when needed:

```sh
just check
just ci
lefthook run local-ci
```

The remote CI remains authoritative for the Linux/macOS/Windows matrix,
CodeQL, nightly libFuzzer, and big-endian s390x/QEMU execution.

## Required checks

```sh
just ci
```

Individual recipes such as `just test`, `just no-std`, and `just deny` run the
same commands independently. Portable repository-specific policy checks live
in the safe-Rust `xtask` crate instead of shell scripts.

`just package-smoke` builds the exact `.crate` contents in a fresh external
consumer workspace. `just release-policy` is a non-publishing static check that
rejects automatic release triggers and loss of the draft-first controls.

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

Modern Replacement work uses stable `RM-NNN` identifiers and the dedicated
Issue Form. Link independently mergeable work to its epic in
[RM-000](https://github.com/P4suta/libarchive_oxide/issues/28), and include
test, corpus, benchmark, or ABI evidence before closing a completion gate.

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
| `libarchive_oxide-core` | 1.85 |
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
[ADR-0002](docs/adr/0002-workspace-releases.md).

Releases intentionally require several independent maintainer actions:

1. Dispatch the release workflow with `prepare` and the `PREPARE` confirmation.
2. Review the generated release PR and manually apply `release-approved`.
3. After merge, dispatch `publish` with the exact tag and `RELEASE`, then approve
   the protected `release` Environment deployment.
4. Dispatch the release-assets workflow with the exact tag and `ASSETS`, approve
   the Environment deployment, and verify every draft asset.
5. Publish the completed draft Release manually in the GitHub UI.

Never automate the approval label, the Environment review, or final draft
publication. A maintainer must make each authorization deliberately.

## License

The repository uses [REUSE](https://reuse.software/). Run:

```sh
just reuse
just license-sync
```

New files must declare `MIT OR Apache-2.0` through an SPDX header or
`REUSE.toml`.

Unless explicitly stated otherwise, submitted contributions are licensed under
MIT OR Apache-2.0 without additional terms.

## Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
