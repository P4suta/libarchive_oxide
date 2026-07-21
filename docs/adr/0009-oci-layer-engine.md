# ADR-0009: OCI image layer read and apply engine

- Status: accepted
- Date: 2026-07-22
- Tracks: RM-201, RM-202 / DEV-74

## Context

An OCI image layer is a tar stream, optionally wrapped in gzip or zstd, and is
named by two SHA-256 values: the compressed digest over the stored blob (the
descriptor `digest`) and the diffID over the decoded tar stream. A layer also
carries overlay semantics that a plain tar extractor ignores: a `.wh.<name>`
entry deletes `<name>` inherited from a lower layer, and a `.wh..wh..opq` marker
clears the contents of its parent directory.

The session engine already provided bounded, digest-bound inspection and a
capability-reporting filesystem contract (ADR-0003, ADR-0007), but it computed a
single input digest and had no notion of the inner diffID, whiteouts, opaque
directories, or container-to-host ownership shifting. Reusing the general
extraction path would either buffer the layer to hash it twice or silently drop
the overlay markers.

## Decision

- A new `oci` module (`digest`, `layer`, `plan`, `apply`) builds on the existing
  `FilterReader`, `ArchiveReader`, and `FilesystemAdapter` rather than adding a
  parallel parser.
- **Two digests in one decode pass.** `HashingReader` feeds every byte it yields
  into a shared SHA-256 accumulator without retaining the stream. Nesting one
  accumulator under the raw source (compressed digest) and one over the decoded
  tar bytes (diffID) lets `OciLayerEngine::open` compute both digests during a
  single decompression. For an uncompressed tar layer the two values are equal.
  The decoded-output limit still bounds the diffID pass, so a hostile layer
  cannot expand without limit.
- **Whiteout and opaque markers become explicit plan operations.** The planner
  classifies each entry and emits a typed `OciPlanOperation`:
  `Materialize`, `MapOwnership`, `Whiteout`, `OpaqueDir`, or `Reject`. Overlay
  handling is therefore auditable in the plan before anything touches the
  destination, and the marker files themselves are never materialized.
- **Ownership mapping is planned, not improvised.** An `OwnershipMapper`
  (identity, a numeric `OwnershipTable`, or any closure) remaps the archive
  owner during planning; a remap is recorded as a distinct `MapOwnership`
  operation that preserves the original owner for audit.
- **No commit on digest mismatch.** `OciLayerApplier::apply` runs two passes: the
  first fully streams the layer and verifies the compressed digest and then the
  diffID against the plan's expected pair; only if both match does the second
  pass drive the adapter. A mismatch returns `DigestMismatch` and leaves the
  destination completely unchanged — no file, whiteout, or opaque clear runs.
- **Single-use, session-bound plans.** A plan carries its originating applier id
  and its expected digests and is not serializable. Applying a plan to a
  different applier, or applying twice, is a `Session` error, mirroring the core
  engine's single-apply guard.
- **Supported inputs this unit.** tar, tar+gzip, and tar+zstd, with hardlink,
  symlink, xattr, uid/gid mapping, path-conflict, and symlink-escape handling.

Deterministic layer creation, a range-source adapter example, and an
`oxarchive oci` CLI subcommand are deliberately out of scope and are deferred to
later units (RM-203, RM-204, RM-205), along with a full 10 GiB soak.

## Consequences

Reading and verifying a layer no longer requires a second decode pass or
buffering the blob: memory stays bounded by the configured limits regardless of
layer size. Overlay semantics are represented as reviewable plan operations, so
a caller can inspect exactly which deletions and clears a layer requests before
committing. Because verification precedes any adapter call, a tampered or
truncated layer can never partially mutate the destination.

The applier requires a seekable blob so it can rewind between the verify and
apply passes; a purely streaming apply is not offered here. Ownership landing is
still platform-gated by the filesystem adapter, so `MapOwnership` records the
intended mapping on every platform but only realizes it where the adapter
supports ownership. Multi-layer stacking, image manifests, and layer creation
remain the responsibility of later Campaign 2 units.
