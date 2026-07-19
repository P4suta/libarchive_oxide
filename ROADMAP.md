# Roadmap

Completed work belongs in [CHANGELOG.md](CHANGELOG.md).

The gated path toward a modern libarchive replacement is defined in
[Modern Replacement roadmap](docs/modern-replacement.md) and tracked from
[RM-000](https://github.com/P4suta/libarchive_oxide/issues/28). The sections
below are repository-level supporting work and do not replace those completion
gates.

## OSS-Fuzz

Status: deferred. Do not submit an external onboarding request without
maintainer approval.

- [x] Maintain libFuzzer targets.
- [x] Commit seed corpora.
- [x] Replay portable fuzz invariants in normal CI.
- [ ] Add and locally validate `project.yaml`, `Dockerfile`, and `build.sh`.
- [ ] Submit the OSS-Fuzz onboarding PR.
- [ ] Verify the first ClusterFuzz run.
- [ ] Connect findings to the private reporting process.

## Big-endian

Status: required CI gate.

- [x] Run core and flagship tests on `s390x-unknown-linux-gnu` under QEMU.
- [x] Separate CLI child-process emulation failures from byte-order failures.
- [x] Require the job after three consecutive successful `main` runs.

Triage:

1. Re-run to identify transient runner, QEMU, or toolchain failures.
2. Reproduce byte-order failures with a minimal test.
3. Replace native-endian operations with explicit format byte order.
4. Keep the regression test.

## `no_std` codecs

Status: unplanned.

- [ ] Evaluate pure-Rust `no_std` codec implementations.
- [ ] Prototype gzip behind a disabled-by-default feature.
- [ ] Preserve the zero-dependency default core.

## Examples

- [ ] Extract `.tar.gz` to a directory.
- [ ] Create a compressed archive selected by output extension.
- [ ] Read a password-protected WinZip AES-256 archive.
- [ ] Consume an archive through the incremental source API.
