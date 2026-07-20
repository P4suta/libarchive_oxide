# ADR-0007: capability-reporting filesystem application

- Status: accepted
- Date: 2026-07-20
- Tracks: RM-104 / issue #47

## Context

A `cap_std::fs::Dir` prevents ambient-path extraction, but the previous engine
application path coupled parsing and materialization directly to one concrete
extractor. Its `ExtractionReport` exposed entry rejection while mode/time
failure and unsupported ownership, xattr, ACL, sparse, or platform attributes
could not be represented uniformly. A downstream filesystem integration could
not participate without replacing session identity, path policy, limits, and
archive driving.

## Decision

- Publish `FilesystemAdapter`, `FilesystemCapabilities`, `FilesystemEntry`,
  `FilesystemOperation`, and typed finding/report types.
- Keep the adapter as a stateful compile-time value. No trait-object registry,
  global registration, ambient root, dynamic loading, or plugin ABI is added.
- Keep path normalization, extraction policy, resource limits, hardlink order,
  and archive events in one shared driver. Adapters receive only normalized
  relative operations and bounded data chunks.
- Require capabilities to remain stable for a session. Every requested entry
  or metadata operation must have a finding; the driver synthesizes `Partial`
  when an adapter that declared support omits one.
- Add `ArchiveSession::apply_with_adapter`. Preserve the owned
  `cap_std::fs::Dir` signature of `apply` as a shortcut to
  `CapStdFilesystemAdapter`.
- Extend `ApplyReport` with filesystem findings while retaining
  `extraction()` and `into_extraction()` for source compatibility.
- Treat expected unsupported, refused, partial, and OS failures as report data.
  Reserve fatal adapter errors for invalid state or inability to continue the
  stream.
- Implement the Linux reference behavior with descriptor-based mode,
  ownership, timestamps, xattrs and POSIX ACLs, sparse extent writing,
  policy-gated links/special files, and temporary-sibling atomic publication.

## Atomicity and races

Regular-file bytes and metadata are staged on a unique sibling. The destination
is not published until payload completion and synchronization. Non-overwrite
uses a final hardlink operation so a destination that appears after planning
wins without being replaced; overwrite validates that the pre-existing object
is a regular non-symlink and uses atomic rename. Commit failure removes the
staging sibling. Parent and deferred-directory checks reopen with no-follow
semantics before use.

The report is authoritative for destination-state races and platform fidelity;
the plan remains an advisory description bound to the same immutable input.

## Consequences

Downstream adapters can reuse the engine's parser, provider chain, path policy,
and limits without repository-private APIs. Callers that require exact
restoration can reject any non-`Applied` finding, while callers with a looser
policy can accept a materialized payload and retain precise degradation
evidence.

The low-level `Extractor` and Tokio extraction APIs remain available and
source-compatible. They continue to be convenient concrete `cap-std` surfaces;
the session engine is the preferred capability-reporting path.

Raw ACL records are applied only when they can be represented as numeric POSIX
ACL text. Names are not looked up implicitly. Change/birth times and filesystem
flags remain explicitly unsupported until a race-safe platform implementation
and conformance fixtures exist.