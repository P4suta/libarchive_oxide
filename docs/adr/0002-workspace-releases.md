# ADR-0002: Workspace releases

- Status: accepted
- Date: 2026-07-19

## Context

- The workspace publishes three dependent crates.
- The crates form one product.
- crates.io publishing is irreversible.
- GitHub releases must contain CLI binaries.

## Decision

- Use one version for all published crates.
- Publish in dependency order:
  `libarchive_oxide-core`, `libarchive_oxide`, `libarchive_oxide-cli`.
- Use one `vX.Y.Z` tag, root changelog, and GitHub Release.
- Require a release-plz Release PR before publishing.
- Require a maintainer to apply the `release-approved` label manually before a
  release PR can satisfy branch protection.
- Prepare and publish through separate manually dispatched workflows. Require
  approval through the protected `release` Environment for both operations.
- Create a draft GitHub Release, attach assets through a separately approved
  workflow, and require a maintainer to publish the completed draft in the
  GitHub UI.
- Authenticate crates.io publishing through GitHub OIDC.
- Build CLI assets before the immutable GitHub Release is published.

## Consequences

- A release updates all three crate versions.
- Merging a Release PR cannot publish a release.
- Publishing requires an exact expected tag, a typed confirmation, and
  Environment approval.
- Removing `release-approved` immediately invalidates the release PR's required
  status check.
- Asset upload and final draft publication remain separately authorized manual
  steps.
- Failed partial publication resumes in dependency order.
- Release PRs require explicit maintainer approval.
