<!--
Thanks for contributing! A few reminders:
- Commits follow Conventional Commits (feat: / fix: / perf: / docs: / …); Dependabot uses build(deps).
- The abstractions in libarchive_oxide-core are frozen: a new format or direction must land under the
  existing traits (Format / Filter / EntryReader / EntryWriter), with no trait change.
-->

## What & why

Describe the change and the motivation. Link any related issue (`Closes #123`).

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test --workspace --all-features` passes (incl. the `fuzz_replay` adversarial gate)
- [ ] The no-dyn invariant holds (`bash scripts/check-no-dyn.sh` — zero type erasure)
- [ ] REUSE/SPDX headers present on new files (`reuse lint`)
- [ ] No unintended public-API break (`cargo semver-checks`; pair a breaking change with a major bump)
- [ ] `no_std` core stays pure (no `std::`; builds for `thumbv7em-none-eabi`)
- [ ] CHANGELOG / docs updated if user-facing (release-plz derives the entry from the commit)
