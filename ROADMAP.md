# Roadmap

This document is the staged-hardening record for `libarchive_oxide`. It tracks
work that is **planned but not yet applied**, so the checklists below are honest
about state. Shipped functionality lives in [CHANGELOG.md](CHANGELOG.md), not
here.

## Continuous fuzzing → OSS-Fuzz enrollment

**State: not yet applied.** The `libarchive_oxide-fuzz` crate already carries
cargo-fuzz targets over the decode/extract paths, and their portable invariant
bodies (`fuzz/fuzz_lib`) are replayed from the normal test suite. The next step is
enrolling the project in [OSS-Fuzz](https://github.com/google/oss-fuzz) for
continuous, at-scale fuzzing.

Enrollment checklist:

- [ ] Keep the fuzz targets OSS-Fuzz compatible (libFuzzer entry points, no
      network, no clock, deterministic corpus).
- [ ] Add an OSS-Fuzz `project.yaml` (language `rust`, the maintainer contact, and
      the `main` branch) in the OSS-Fuzz repo.
- [ ] Add a `build.sh` that runs `cargo fuzz build` and copies the fuzz binaries
      to `$OUT`.
- [ ] Add a `Dockerfile` based on `gcr.io/oss-fuzz-base/base-builder-rust`.
- [ ] Seed each target with a minimal corpus of valid archives per format.
- [ ] Open the OSS-Fuzz onboarding PR and confirm the first ClusterFuzz run is
      green.
- [ ] Wire advisory triage back to the private reporting flow in
      [SECURITY.md](SECURITY.md).

## Big-endian verification

**State: required green gate.** All parsing uses explicit byte-order
conversions. CI cross-compiles and runs the core and flagship library tests
under QEMU on `s390x`; the job joined `ci-required` after three consecutive
green runs on `main`. (The CLI contract suite spawns target binaries as child
processes and therefore cannot use cross's top-level QEMU runner.)

- [x] Add a cross + QEMU CI job (`s390x-unknown-linux-gnu`) initially as
      `continue-on-error: true`.
- [x] Triage the initial failure (CLI child-process emulation, not an endian
      divergence) and scope the job to the two library crates.
- [x] Promote the job to a required gate after three consecutive green `main`
      runs.

## `no_std` codec support

**State: exploratory.** Today the `no_std` core (`libarchive_oxide-core`) carries
only the uncompressed formats; every compression codec lives in the `std`
flagship. The core/flagship split makes future `no_std` codec support a
**non-breaking** addition (a re-export on top of the frozen algebra), so this can
be pursued when there is demand without a SemVer break.

- [ ] Survey `no_std`-capable pure-Rust codec crates (or allocator-generic
      in-house filters) per algorithm.
- [ ] Prototype a `no_std` gzip filter behind an off-by-default core feature.
- [ ] Confirm the addition stays non-breaking and keeps the zero-dependency
      default build intact.

## Examples expansion

**State: incremental.** Grow `libarchive_oxide/examples/` beyond the quick start
to cover the common end-to-end recipes.

- [ ] `.tar.gz` extraction to a directory (safe defaults).
- [ ] Creating a compressed archive by output extension.
- [ ] Reading a zip with WinZip AES-256 (password-protected).
- [ ] Streaming a large archive with the incremental source (no full buffering).

---

Release mechanics (versioning, publishing order, tagging) are handled by
release-plz and documented in [CONTRIBUTING.md](CONTRIBUTING.md); the path to 1.0
(soak time plus the hardening items above) is described there under the SemVer &
stability policy.
