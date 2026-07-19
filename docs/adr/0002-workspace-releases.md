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
- Authenticate crates.io publishing through GitHub OIDC.
- Build CLI assets from the published GitHub Release event.

## Consequences

- A release updates all three crate versions.
- Merging a Release PR starts publishing.
- Failed partial publication resumes in dependency order.
- Release PRs require explicit maintainer approval.
