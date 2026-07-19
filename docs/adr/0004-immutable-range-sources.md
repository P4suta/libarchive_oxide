# ADR-0004: immutable range sources share the seek parser

- Status: accepted
- Date: 2026-07-20
- Tracks: RM-102 / issue #34

## Context

ZIP, 7z, and ISO 9660 require random access. Downloading every remote object
before inspection wastes latency and bandwidth, while a second parser written
around HTTP or cloud SDK calls would create semantic and security drift.
Remote objects may also change between range requests, making a plan or parse
unsafe unless every byte is tied to one immutable version.

## Decision

- `RangeSource` and feature-gated `AsyncRangeSource` expose only a declared
  length, an opaque immutable `SourceIdentity`, and reads at explicit offsets.
- Providers are statically linked Rust implementations. The traits have no
  HTTP, object-store, runtime, authentication, or dynamic-plugin dependency.
- `RangeReader` adapts synchronous providers to `Read + Seek`.
  `AsyncRangeArchiveReader` uses the same demand cache as
  `AsyncSeekArchiveReader`. Both drive the existing `SeekArchiveReader`; there
  is no range-specific archive parser.
- The adapter captures identity and length at open. It revalidates them before
  and after provider reads and around async public commands. Any change fails
  closed with a typed `RangeReadError`.
- Providers may return short chunks. Zero progress, explicit short reads,
  invalid counts, offset failures, identity changes, and length changes remain
  distinguishable through a downcastable error stored in `io::Error`.
- Read-ahead is bounded by `Limits::in_flight_bytes`, capped at 128 KiB.
  Cached bytes are bounded by `Limits::metadata_bytes`. A parser request larger
  than that budget is rejected instead of bypassing the limit.
- `RangeMetrics` counts every provider request and every successfully returned
  byte without estimating cache hits.
- The source identity is opaque because version semantics belong to the
  provider. An adapter must use a version ID, generation, or similarly strong
  identifier that cannot be reused for different bytes.

## Consequences

- Remote ZIP/7z/ISO inspection gets bounded range I/O without duplicating
  format logic.
- SDK adapters can enforce conditional requests and translate their native
  version identifiers without becoming dependencies of this crate.
- An ETag is suitable only when its provider contract makes it a strong,
  immutable identity. Weak or reusable validators do not satisfy this API.
- Range sessions are reading primitives, not durable extraction plans.
  Persisted remote plans remain out of scope.
- Exact request metrics make latency, transfer, and cache-policy benchmarks
  possible in later Campaign 1 work.
