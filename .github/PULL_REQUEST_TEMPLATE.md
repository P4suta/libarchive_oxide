<!-- Use Conventional Commits. Preserve ADR-0001 unless this PR adds a superseding ADR. -->

## What & why

State the change, reason, and related issue.

## Checklist

- [ ] `just ci` passes
- [ ] `cargo semver-checks check-release -p libarchive_oxide-core -p libarchive_oxide` passes
- [ ] User-facing documentation is updated
- [ ] Release PR only: a maintainer manually applied `release-approved`
