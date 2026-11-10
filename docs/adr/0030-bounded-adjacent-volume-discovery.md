# Explicit adjacent-volume discovery

## Status

Proposed

Date: 2026-08-15

## Context

Handle and stream APIs must avoid ambient files while path callers need conventional split-archive names.

## Decision

Enable discovery only through explicit path options.
Derive supported 7z, ZIP, and `RAR` sibling names within the primary directory.
Reject non-primary inputs and conflicting volume sources.
Preflight required sources before fixing session identity.

## Alternatives

Requiring a resolver everywhere preserves explicit authority but adds repetitive path code.
Directory enumeration would read beyond the requested naming family.

## Consequences

Session opening performs extra bounded reads and decoding work.
Recovery volumes and cross-directory searches remain unavailable.
Reconsider discovery schemes only with documented naming and bounded extent rules.

## Confirmation

[ZIP volume tests](../../libarchive_oxide/tests/zip_volumes.rs), `RAR` volume tests, and CLI tests check names, missing segments, source identity, and limits.
