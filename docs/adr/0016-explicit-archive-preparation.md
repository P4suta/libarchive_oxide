# ADR-0016: streaming open and snapshot preparation are separate

- Status: accepted
- Date: 2026-07-28
- Amends: ADR-0003

## Context

`ArchiveEngine::open(Read)` previously copied every input into a bounded spool
before detecting whether the caller only needed sequential streaming. Although
bounded, that hidden I/O made memory/disk use and latency surprising and made
ordinary reads proportional to total input before the first entry appeared.

Inspect/plan/apply sessions still need an immutable seekable snapshot so their
digest and plan identity refer to exactly one encoded byte stream.

## Decision

- `ArchiveEngine::open(Read)` returns the common streaming `ArchiveReader` and
  performs no hidden spool.
- `PreparedArchive::spool` and `spool_with_limits` explicitly create a bounded
  immutable snapshot and its encoded SHA-256 identity.
- `ArchiveEngine::open_prepared` creates an inspect/plan/apply session from that
  snapshot.
- `ArchiveEngine::prepare(Read)` is a clearly named convenience combining the
  configured spool limits with `open_prepared`.
- `ArchiveReader::open` remains the direct everyday streaming constructor.

## Consequences

- Sequential callers can observe the first entry without reading the complete
  archive and without temporary-file I/O.
- Snapshot workflows remain replayable and digest-bound, but the spooling
  decision is visible in the API.
- Seek-native ZIP/7z/ISO/UDF sessions continue through explicit preparation or
  an appropriate seek/range reader.
