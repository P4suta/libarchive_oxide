# Bounded byte-split 7z volumes

## Status

Proposed

Date: 2026-08-14

## Context

Split 7z files form one logical byte stream.
Applications need bounded access without loading every segment or importing filesystem discovery into the parser.

## Decision

Use caller-owned `VolumeSet` sources with a bounded extent table and lazy reads.
Preserve source identity, length checks, password candidates, and encoded-byte limits.
Keep adjacent discovery behind explicit path options.

## Alternatives

Reassembling every segment simplifies seeking but needs archive-sized storage.
Implicit sibling discovery would broaden parser authority.

## Consequences

Segmented reads add seeks and password preflight work.
A missing final segment can resemble truncation when no expected count exists.
Reconsider framing when callers can supply an authenticated segment manifest.

## Confirmation

[Volume tests](../../libarchive_oxide/tests/sevenz_volumes.rs) cover boundary crossing, missing sources, passwords, and limits.
