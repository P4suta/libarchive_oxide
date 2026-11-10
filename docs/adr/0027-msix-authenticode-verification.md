# Separate MSIX validity and trust

## Status

Proposed

Date: 2026-11-11

## Context

A signature member's presence doesn't prove package integrity, signature validity, or issuer trust.

## Decision

Bound signature metadata and parse the Authenticode package profile with exact framing checks.
Stream the canonical unsigned package-view hashes and verify every signer.
Grant trust only through explicit certificate fingerprint pins.
Keep network and platform trust lookup outside the verifier.

## Alternatives

Presence-only reporting preserves a smaller verifier but leaves authenticity unknown.
Delegating to platform trust would add ambient policy and reduce reproducibility.

## Consequences

Reports distinguish block-map integrity, signature validity, and pinned trust.
Unknown profiles return typed unsupported findings.
Reconsider unsupported profiles when normative framing and independent fixtures are available.

## Confirmation

[MSIX signature tests](../../libarchive_oxide-package/tests/package_msix_blockmap.rs) cover signed fixtures, tampering, malformed records, resource limits, and trust pins.
