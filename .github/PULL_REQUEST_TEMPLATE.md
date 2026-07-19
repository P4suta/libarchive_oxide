<!-- Use Conventional Commits. Preserve ADR-0001 unless this PR adds a superseding ADR. -->

## What & why

State the change, reason, and related issue.

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --workspace --all-features` passes
- [ ] `bash scripts/check-no-dyn.sh` passes
- [ ] REUSE/SPDX headers present on new files (`reuse lint`)
- [ ] `cargo semver-checks check-release --workspace` passes
- [ ] `libarchive_oxide-core` builds for `thumbv7em-none-eabi`
- [ ] User-facing documentation is updated
