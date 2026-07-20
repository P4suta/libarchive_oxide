# ADR-0008: bounded CLI records and atomic archive creation

- Status: accepted
- Date: 2026-07-20
- Tracks: RM-122 / issue #48

## Context

The first `oxarchive inspect --json` implementation called the collected
inspection API and serialized one object containing every entry. That made CLI
memory proportional to entry count even though the parser already exposed
bounded `ReaderEvent` values. Creation existed in compatibility binaries but
the high-level command did not expose `CreateOptions`, and direct file output
could leave a partial destination.

Binary archive output, JSON reports, and diagnostics also require an explicit
stream contract: a late failure cannot retract bytes already sent to stdout.

## Decision

- `oxarchive inspect` consumes `ArchiveSession::next_event` directly.
- JSON inspection is a flushed JSON Lines sequence:
  `inspect_start`, `inspect_entry*`, `inspect_complete`.
- The completion record is the success sentinel. Its absence means the
  preceding valid records form an incomplete report.
- `oxarchive create` supports sequential tar, cpio, ar, and zip plus the five
  outer filters through `ArchiveEngine`, `CreateOptions`, and
  `StreamingArchiveBuilder`.
- `StreamingArchiveBuilder::new` is retained as a compatibility shortcut but
  delegates to the engine/options constructor.
- File creation uses a synchronized temporary sibling and no-replace atomic
  publication. Stdout creation is a binary-only stream and may be partial on
  exit 1; JSON plus stdout archive output is rejected as usage.
- Exit 0/1/2 and stdout/stderr roles are shared across all five binaries.

The pre-1.0 schema identifier remains `oxarchive.output.v0alpha1`; record types
are required on every value so readers can process or reject the stream
incrementally.

## Consequences

Inspection memory no longer grows with entry count. Each emitted JSON line is
independently parseable and a consumer can distinguish completion without
buffering the stream. File creation does not expose a malformed destination
after a normal I/O or input failure.

Stdout creation intentionally cannot provide whole-stream atomicity. Consumers
must check exit status before accepting its bytes. Seek-native 7z and ISO
creation are not exposed by this sequential command; they remain available
through the seek writer API.
