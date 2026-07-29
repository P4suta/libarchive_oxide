# ADR 0017: validated metadata values and one root error

## Status

Accepted.

## Context

The former metadata model allowed callers to construct invalid UTF-8/UTF-16
paths, out-of-range timestamp fractions, overflowing or overlapping sparse
extents, and checksum bytes with no algorithm. The crate root also called the
sans-I/O `ArchiveError` simply `Error` while everyday reader and writer methods
returned a different `StreamError`.

## Decision

- `ArchivePath::try_from_encoded` validates the declared encoding.
- `Timestamp::new` and `SparseExtent::new` validate their numeric domains and
  expose read-only accessors.
- `Checksum` always carries a `ChecksumAlgorithm` and validates the algorithm's
  output width.
- `EntryMetadataBuilder::try_build` validates empty paths, link relationships,
  timestamp values, and sorted/non-overlapping/in-bounds sparse layouts.
- Every public sequential, seek, async, and registered-provider writer repeats
  metadata validation before it emits entry bytes.
- The root `libarchive_oxide::Error` is the I/O-aware error returned by normal
  archive operations. It exposes `kind`, `format`, `entry`, archive details,
  I/O details, and the standard error source chain. `ErrorKind::Io` classifies
  adapter failures.
- The sans-I/O `ArchiveError`, provider registry, range sources, and caller-
  driven pipeline remain available through `libarchive_oxide::advanced`.

## Consequences

Invalid generated metadata fails before output begins, and downstream code no
longer has to guess a checksum algorithm or normalize invalid timestamp
fractions. The constructor and error-name changes are intentionally breaking;
this project has not frozen SemVer compatibility.
