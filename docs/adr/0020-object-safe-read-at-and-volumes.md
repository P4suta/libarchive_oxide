# ADR-0020: object-safe random access and bounded volume resolution

- Status: accepted
- Date: 2026-07-29
- Supersedes: ADR-0004's synchronous `RangeSource` contract
- Amends: ADR-0015

## Context

Seek-native formats must not require an implicit whole-input spool. The original
synchronous `RangeSource` used `&mut self` and generic ownership, which made a
downstream trait object awkward and left multi-volume lookup outside the
validated source boundary. Generic provider cons-lists also remained too
prominent after the object-safe registry became the preferred extension path.

## Decision

- `advanced::ReadAt` is the only synchronous positional source trait. It is
  object-safe, `Send + Sync`, and supports short reads plus an overflow-safe
  `read_exact_at`.
- Every source exposes a validated `SourceIdentity`. Identities are non-empty
  and at most 1024 bytes, so revalidation cannot clone attacker-sized transport
  metadata.
- `RangeReader` adapts `ReadAt` to `Read + Seek`; `RangeArchiveReader` continues
  to drive the existing ZIP, 7z, ISO 9660, and UDF parser. It performs no
  whole-input copy.
- `MemoryReadAt`, `SeekReadAt<R>`, and `FileReadAt` are standard adapters.
  `SeekReadAt<R>` owns and serializes an ordinary `Read + Seek` value; its caller
  must prevent mutation through another handle. `FileReadAt` additionally
  revalidates length and modification time before and after positional reads.
  Filesystems that do not provide reliable modification times still require
  the caller to enforce immutability.
- `SourceLimits` is finite by default: 64 GiB per encoded source, 256 distinct
  volumes, and 256 GiB across a resolved volume set. Sync and async archive
  adapters apply the same per-source default before parser I/O.
- `VolumeResolver` is an object-safe application seam. `VolumeSet` maps volume
  zero to the primary source, caches successful and missing lookups, and checks
  source size, distinct request count, and checked total bytes. The count is
  rechecked while committing a concurrent resolution.
- Source protocol failures remain downcastable `RangeReadError` values inside
  `io::Error`. Their stable kind can include byte range, volume ID, and
  observed/limit context.
- `Registry`, `IncrementalFormatProvider`, and `IncrementalCodecProvider` remain
  the canonical downstream provider path under `advanced`. Static generic
  chains are retained only in the doc-hidden `advanced::legacy` namespace for
  workspace migration; registry adapter implementation types are not
  re-exported.

## Consequences

Downstream storage and volume implementations can be stored behind trait
objects without adding an SDK dependency or copying a complete archive.
Seek-format parsers and volume-aware providers share one validated source
contract. Malformed ranges, non-progress, missing volumes, count/byte limits,
and identity changes fail before unsafe parser assumptions are made.
ADR-0021 applies this seam to CAB sets without adding filename lookup or
network policy to the archive parser.

The runtime-neutral async transport trait remains `AsyncRangeSource` because
stable Rust has no object-safe `async fn` trait contract without choosing a
boxing/runtime policy. It uses the same identity and source-size rules.
