# Contributing

Contributions to `libarchive_oxide` are welcome. It is a unified, streaming,
pure-Rust archive library — one trait algebra for archive **formats**,
compression **filters**, and **I/O**, with a `no_std` core — built around a frozen
abstraction and verified against reference tools.

Read the [README](README.md) first for the architecture; the design decisions
behind it are recorded there and in [ROADMAP.md](ROADMAP.md).

## Setup

The development toolchain is managed via [mise](https://mise.jdx.dev/)
(`mise.toml`); the Rust toolchain itself is owned by `rust-toolchain.toml`.
Declare tools in `mise.toml` and install via `mise install`; do not add them ad
hoc. CI action revisions are pinned independently in the workflow files.

```sh
mise install        # install managed tools (cargo-msrv, cargo-deny, cargo-semver-checks, reuse, typos, ...)
mise run hooks      # once, per clone: install the lefthook pre-commit / commit-msg hooks
```

The `lefthook` pre-commit hook formats, then runs clippy, typos, `reuse lint`, and
the no-dyn gate; the commit-msg hook lints Conventional Commits. Every one of them
is also a CI job, so the hook is a faster failure and never the only one. Do not
bypass hooks with `--no-verify`; if a hook fails, fix the cause.

## Build & test

Everything below runs offline, on any platform:

```sh
cargo test --workspace --all-features                                  # unit + integration + round-trip tests
cargo clippy --workspace --all-targets --all-features -- -D warnings   # warnings are hard errors, like CI
cargo fmt --all --check
cargo doc --workspace --all-features                                   # rustdoc (missing_docs is enforced)

scripts/check-no-dyn.sh                                                 # the no-dyn gate (see below)
cargo build -p libarchive_oxide-core --target thumbv7em-none-eabi      # no_std, zero-dependency core
cargo deny check                                                       # advisories, licenses, sources
reuse lint                                                             # REUSE/SPDX license hygiene
```

`--all-features` matters: without it the `aes` and `sevenz` paths (and their
dependencies) do not compile, so a regression there would slip past the local run.

## The frozen algebra

The value of this library is the trait algebra in `libarchive_oxide-core`, frozen
as a whole so new formats and the write path load without changing any trait.
Hold to its invariants in every change:

- **Sans-IO, allocation-free base.** Transforms are `step(input, output)`; I/O and
  allocation policy live in adapters above.
- **Orthogonal.** A new filter changes no format code, and vice versa.
- **`no_std` core with zero external dependencies.** `libarchive_oxide-core` takes
  no third-party crate in any table and builds on bare metal. Codecs, `std`
  extraction, and detection belong in the flagship, which is free to depend on
  mature codec crates.
- **No type erasure.** Runtime dispatch is sealed enums, never a trait object.

## The no-dyn gate

`scripts/check-no-dyn.sh` greps library source and fails on any `Box<dyn>`,
`&dyn`, or `&mut dyn`. Runtime format/codec choice is dispatched over sealed enums
(`AnyReader`, `AnyDecoder`) with associated types — never a trait object. This is
a CI gate; run it before pushing.

## Verification methodology

- **Round-trip identity.** `read ∘ write = id` is a test for every format that has
  both a reader and a writer.
- **Differential cross-checks.** Outputs are cross-checked against reference tools
  (GNU `tar`, an independent gzip decoder, `unzip`, and so on) where they are on
  `PATH`, with a graceful skip otherwise.
- **Fuzzing.** `libarchive_oxide-fuzz` carries cargo-fuzz targets; their portable
  invariant bodies (`fuzz/fuzz_lib`) are replayed from the normal test suite
  (`tests/fuzz_replay.rs`) so the fuzz invariants run in ordinary CI too. The fuzz
  crate stays OSS-Fuzz compatible (see [ROADMAP.md](ROADMAP.md)).
- **Hardening tests.** Malformed-input panics and extraction attacks
  (path traversal, decompression bombs) have regression tests.
- **`no_std` build.** The core is built for `thumbv7em-none-eabi` in CI to prove
  it stays dependency-free and allocator-generic.

## MSRV policy

MSRV is measured **per crate** with `cargo-msrv` and declared via `rust-version`:

- `libarchive_oxide-core`: **1.81** (the workspace baseline; zero deps).
- `libarchive_oxide` / `libarchive_oxide-cli`: **1.87** (the codec closure).

CI verifies each with `cargo-msrv verify`. Before using a newer `std` or language
feature, check the floor; if the feature is genuinely needed, raise `rust-version`
and treat the bump as a **minor** version change. The edition stays 2021 to keep
the floor low.

## SemVer & stability policy

- **Pre-1.0 (the current 0.x line).** The public API may change between minor
  versions. Breaking changes bump the **minor** (`0.x`), additive/fix changes bump
  the **patch** (`0.x.y`), per Cargo's 0.x SemVer rules. Every breaking change is
  called out in [CHANGELOG.md](CHANGELOG.md).
- **`cargo-semver-checks`** gates each PR: an unintended breaking change to a
  published crate's API fails CI. Intended breaks are made deliberately and noted.
- **The CLI's interface is a SemVer surface.** For `libarchive_oxide-cli`, the
  flags, exit codes, and parseable output shape are the public contract — removing
  or repurposing a flag, or changing an exit code, is a breaking change exactly as
  an API removal is. See
  [`libarchive_oxide-cli/README.md`](libarchive_oxide-cli/README.md).
- **Path to 1.0.** 1.0 is cut once the trait algebra and the CLI contract have
  soaked without a forced break and the hardening items in
  [ROADMAP.md](ROADMAP.md) (OSS-Fuzz enrollment, big-endian verification) are in
  place. Because the core algebra was frozen day one and the bsd* CLI interfaces
  are themselves long-stable, the road to 1.0 is soak time and hardening, not
  redesign.

## Commit & PR rules

- [Conventional Commits](https://www.conventionalcommits.org/) (`feat:` / `fix:` /
  `perf:` / `docs:` / `refactor:` / `test:` / `chore:` / `ci:` / `build:`). The
  commit-msg hook and CI lint every commit.
- **Squash-merge only.**
- Releases are cut by [release-plz](https://release-plz.dev): it opens a release PR
  that bumps versions + `CHANGELOG.md` from the conventional commits, then on merge
  publishes to crates.io in dependency order
  (`libarchive_oxide-core` → `libarchive_oxide` → `libarchive_oxide-cli`) and tags.
  `cargo-semver-checks` gates breaking changes.

## License hygiene (REUSE)

The repository follows [REUSE](https://reuse.software): licensing is declared in
one place — `REUSE.toml` — whose bulk annotations cover the whole tree by glob
(`**/*.rs`, `**/*.toml`, `**/*.sh`, `**/*.yml`, `**/*.md`, the lockfiles, the
extension-less dotfiles, and the binary fuzz-corpus seeds). New source and config
files are therefore covered automatically; only a brand-new *category* of path
(a new top-level extension or dotfile) needs a line added to `REUSE.toml`. An
inline SPDX header is optional and, thanks to `precedence = "aggregate"`, combines
with the bulk annotation rather than conflicting:

```
// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
```

`reuse lint` must pass; it is both a hook and a CI job. Every published crate is
`MIT OR Apache-2.0`.

## Inbound license (dual-license clause)

Unless you explicitly state otherwise, any contribution you intentionally submit
for inclusion in the work, as defined in the Apache-2.0 license, shall be dual
licensed as `MIT OR Apache-2.0`, without any additional terms or conditions.

## Conduct

By participating you agree to uphold our
[Code of Conduct](CODE_OF_CONDUCT.md).
