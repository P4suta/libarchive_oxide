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

- `pre-commit` formats and spell-checks staged files, then runs both codec-profile
  host Clippy plus Linux- and macOS-target Clippy before provider-registry and
  license checks;
- `pre-push` runs `just ci`, which mirrors every practical CI gate
  available on a developer machine, including all-feature tests, rustdoc,
  bare-metal `no_std`, dependency policy, packaged-crate consumer validation,
  release policy, workflow lint, and the workspace MSRV.

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

Individual recipes such as `just test`, `just no-std`, `just deny`, and
`just shear` run the same commands independently. Portable repository-specific policy and CI
orchestration that branches, loops, or constructs command matrices lives in
the safe-Rust `xtask` crate instead of shell scripts. Straight-line tool calls
remain visible in `Justfile` and workflow setup steps rather than being wrapped
without adding portability or validation.

`just test` uses cargo-nextest for normal unit and integration tests, then runs
`cargo test --doc` for each maximal codec profile because nextest does not run
doctests. `just test-ci` selects the non-fail-fast CI profile used by all three
host operating systems. Adversarial corpus mutations run as target-specific
tests in a group capped at four processes, so failures identify one fuzz target
without unbounded high-core-count fan-out.

`just fuzz-ci` runs the nightly panic-abort and bounded two-profile libFuzzer
campaign when `FUZZ_TARGET` is set. `just big-endian-ci` runs the exact optimized
s390x/QEMU selection used remotely; both require their CI tools to be installed.

`just package-smoke` builds the exact `.crate` contents in a fresh external
consumer workspace. `just release-policy` is a non-publishing static check that
keeps the workspace at the completion-phase version, rejects a SemVer freeze,
and requires every publisher (including the bootstrap publisher) to remain
manual-only behind its typed confirmation and protected Environment.

CI also runs:

- tests on Linux, macOS, and Windows;
- MSRV verification;
- `s390x-unknown-linux-gnu` tests under QEMU;
- bounded libFuzzer runs;
- cargo-deny supply-chain policy and strict cargo-shear dependency hygiene;
- CodeQL, actionlint, and offline high-severity zizmor workflow auditing.

## Design constraints

Changes must preserve the architecture ADRs, including
[ADR-0001](docs/adr/0001-core-architecture.md) and its later superseding
decisions:

- `libarchive_oxide-core` remains `no_std` + `alloc`;
- the core has no external dependencies;
- formats and filters remain independent;
- built-in codecs retain bounded incremental state machines;
- downstream formats, codecs, random-access sources, and volume resolvers use
  the immutable object-safe registry contracts.

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
| `libarchive_oxide-core` | 1.88 |
| `libarchive_oxide-codecs` | 1.88 |
| `libarchive_oxide` | 1.88 |
| `libarchive_oxide-package` | 1.88 |
| `libarchive_oxide-cli` | 1.88 |

During the current pre-1.0 completion program, breaking API and CLI changes are
allowed when they produce the cleaner design. Do not publish, bump versions,
create tags or release candidates, or freeze SemVer compatibility unless a
maintainer explicitly starts that future phase. Tests still cover the CLI
contract so deliberate changes remain visible.

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
