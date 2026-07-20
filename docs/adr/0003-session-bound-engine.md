# ADR-0003: session-bound high-level engine

- Status: accepted
- Date: 2026-07-20
- Tracks: RM-101 / issue #30

## Context

The low-level readers and writers expose the archive state machines accurately,
but safe applications still need to compose format detection, collection
limits, policy decisions, seek/spool choices, and capability extraction. A
detached serialized extraction plan would introduce an input-substitution and
time-of-check/time-of-use boundary.

## Decision

- `ArchiveEngine` owns finite defaults and opens an `ArchiveSession`.
- A session first copies encoded input into a bounded `SpooledTempFile`.
  Memory use stops at the configured threshold; larger snapshots move to an
  automatically deleted temporary file and the total encoded size remains
  capped.
- SHA-256 identifies the encoded snapshot. The snapshot is private and
  immutable from the caller's perspective.
- `ExtractionPlan` has private fields, no serialization contract, no `Clone`,
  and records both the session identity and input digest.
- Applying consumes a plan. A session rejects plans from other sessions and
  rejects every later apply, including a separately generated plan.
- Collected inspection accounts for cumulative owned metadata against
  `Limits::metadata_bytes`. Callers that cannot accept collection use the
  session event API.
- Seek-native ZIP, 7z, and ISO inputs use `SeekArchiveReader`; sequential and
  outer-filtered inputs reuse `ArchiveReader`. Both continue to drive the same
  format and codec state machines.
- `Policy` is translated to the existing capability-rooted `Extractor`.
  Planning is advisory and typed; the apply report remains authoritative for
  destination-state and platform-dependent rejection.
- `CreateOptions` selects existing sequential or seek writers. It does not
  introduce a second creation implementation.

## Consequences

- The first high-level API deliberately pays one bounded snapshot pass. This
  makes plan/apply input identity strong for pipes and mutable external
  sources, at the cost of temporary storage and time-to-first-entry.
- A later range-source session can provide an alternative contract only if it
  can guarantee stable object identity (for example version ID plus digest).
- The Rust plan is explicitly not the CLI JSON schema and is not a durable
  interchange format.
- Compile-time external provider chains are specified by
  [ADR-0006](0006-compile-time-providers.md); immutable range-source identity is
  specified separately by [ADR-0004](0004-immutable-range-sources.md).
