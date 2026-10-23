# Contributing

## Setup

Tools are declared in `mise.toml`.
Rust is pinned in both `mise.toml` and `rust-toolchain.toml`.

```sh
mise install
mise run hooks
```

Do not bypass hooks with `--no-verify`.

The hooks use two layers:

- `pre-commit` formats and spell-checks staged files, then checks portable host Clippy and licenses.
- `pre-push` runs `just ci`, the same portable gate used by pull requests and merge groups.

Run the same suites explicitly when needed:

```sh
just check
just ci
lefthook run local-ci
```

The ordinary gate checks formatting, strict portable Clippy, workspace regressions, doctests, dependencies, licenses, generated documentation, release policy, and workflows.
It runs on one Linux runner without duplicating checks after merge.

## Required checks

```sh
just ci
```

`just test-portable` runs the portable workspace tests through nextest's non-fail-fast CI profile, followed by doctests.
The committed malformed-input corpus remains part of those regressions.
Individual recipes run the same commands independently.
Repository-specific orchestration lives in the safe-Rust `xtask` crate.

Full verification runs before the protected publisher on the exact workflow revision.
It includes both codec profiles on Linux, macOS, and Windows, the feature matrix, MSRV, 32-bit Windows, bare-metal and WASI builds, packaged consumers, CodeQL, bounded libFuzzer, big-endian emulation, and the four 10 GiB streaming checks.
These checks cover platform compatibility, untrusted archive inputs, and bounded streaming memory before distribution.
They also remain available through a manual CI dispatch with `full` enabled.

```sh
just release-check
```

This command runs the full checks supported on the current developer host.
The nightly fuzzing and QEMU recipes require their documented CI tools.
`just package-smoke` builds the exact packaged sources in a fresh external consumer workspace.
`just release-policy` checks version and manual draft-first publication policy without publishing.
No verification command grants release authorization.

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
