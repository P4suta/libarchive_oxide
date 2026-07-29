# ADR-0021: explicit bounded CAB volume sets

- Status: accepted
- Date: 2026-07-29
- Builds on: ADR-0018, ADR-0019, ADR-0020

## Context

A CAB folder and its files may continue into another cabinet. A logical
`CFDATA` block may also be split: predecessor records declare `cbUncomp == 0`
and the first record in the successor supplies the logical uncompressed size.
Store, MSZIP, LZX, and Quantum all require decoder state to persist across that
boundary.

Following `szCabinetNext` as a filesystem path would add ambient filesystem and
network policy to a format parser. Spooling every cabinet would also defeat the
object-safe positional source contract and make resource use proportional to
the encoded set.

## Decision

- The advanced API exposes `CabVolumeReader` and `CabVolumeProvider`. They
  consume a caller-owned `VolumeSet`; no filename or network lookup is
  implicit.
- Volume zero is the primary cabinet and `VolumeId` maps directly to the
  expected `CFHEADER::iCabinet`. The primary must be cabinet zero.
- Opening validates a common `setID`, consecutive cabinet indices, distinct
  stable source identities, previous/next name chains, repeated continued-file
  metadata, continuation sentinels, folder methods, and split-record
  placement. Missing, duplicate, wrong, cyclic, and out-of-order cabinets are
  typed failures.
- The reader constructs bounded logical metadata plus lazy segments into the
  original `ReadAt` sources. Payload bytes are not copied or wholly spooled.
  Physical `CFDATA` headers, checksums, reserve data, and payloads remain intact.
- Consecutive physical fragments are checksum-verified and concatenated before
  one logical block is decoded. Store/MSZIP/LZX/Quantum decoder state then
  persists across every block and cabinet in the continued folder.
- `SourceLimits` bound source count and encoded bytes. Archive limits bound
  entries, path and metadata bytes, decoded output, codec memory, and in-flight
  joined fragments. Synthetic CAB offsets, folder counts, file counts, and
  block counts must remain representable in their on-disk integer widths.
- The ordinary `CabSeekReader` remains a single-source API and returns
  structured `Unsupported` when continuation data is requested.

## Consequences

Applications control how a cabinet index maps to storage, credentials, and
transport policy. The library can read continued files and split blocks for all
four standard CAB methods without ambient I/O or archive-sized buffering.
Opening necessarily resolves and validates volume metadata, but payload reads
remain lazy and positional.

The committed Microsoft makecab two-volume fixture is independently extracted
with Windows `extrac32`. Dedicated tests also split MSZIP, LZX, and Quantum
frames and cover missing/wrong/cyclic/duplicate/out-of-order cabinets,
mid-volume checksum corruption, and source/path/decoded/codec-memory limits.
Fixture commands, hashes, and producer/consumer provenance are recorded in
`libarchive_oxide/tests/fixtures/cab/PROVENANCE.md`.

## Evidence

```text
cargo test -p libarchive_oxide --no-default-features --test cab_volumes
cargo test -p libarchive_oxide --no-default-features --features cab-lzx --test cab_volumes
cargo test -p libarchive_oxide --no-default-features --features cab-quantum --test cab_volumes
cargo test -p libarchive_oxide --no-default-features --features cab-lzx,cab-quantum --test cab_volumes
```
