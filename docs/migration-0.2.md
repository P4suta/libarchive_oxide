<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Migrating from v0.1 to v0.2

v0.2 intentionally has no source-compatible v0.1 shim.

## Reading

- Replace whole-slice `reader` / `EntryReader` flows with `ArchiveReader<R>`
  and `ReaderEvent`.
- Supply `Limits` when constructing low-level `ArchiveDecoder`, `Codec`,
  `ArchiveEncoder`, or `Pipeline` state machines.
- Use `SeekArchiveReader` for ZIP, 7z, and ISO 9660. A sequential source must
  first be passed through the explicit bounded `SpoolReader`.
- Archive paths are `ArchivePath`; use `as_bytes` for preservation and
  `display_lossy` only for display.

## Writing

- Replace `Sink` writers with `ArchiveWriter<W>` or the low-level
  `ArchiveEncoder` command protocol.
- `EntryMetadata::size()` is optional in the model. tar/cpio/ar return
  `SizeRequired` when it is absent; no implicit entry buffering occurs.
- Call `finish(self)` to obtain the underlying output. `abort(self)` is the
  only way to recover an intentionally incomplete destination.

## Async

- Enable `async` for futures-io or `tokio` for Tokio.
- Use `AsyncArchiveReader` / `AsyncArchiveWriter` for sequential futures-io,
  and `AsyncSeekArchiveReader` / `AsyncSeekArchiveWriter` for seek formats.
- Tokio equivalents use the `Tokio*` prefix. `TokioExtractor` moves blocking
  capability-filesystem work behind a bounded channel and `spawn_blocking`.
- Every adapter drives the same archive state machines; dropping/cancelling a
  writer never performs an implicit finish.

## Metadata and dialects

- Call `set_archive_metadata` before the first entry when preserving archive
  comments, global PAX data, ISO volume properties, or 7z archive properties.
- Use `ArchiveWriter::with_cpio_dialect` (or
  `CpioEncoder::with_dialect`) with `CpioDialect` for newc, crc, odc, or binary
  LE/BE output. crc output requires the typed four-byte payload byte sum in
  entry metadata.

## Extraction

- Construct `Extractor` with a `cap_std::fs::Dir`.
- `ExtractionPolicy::safe()` rejects absolute/traversing paths, pre-existing
  destination objects, links, and special files.
- Inspect every `EntryOutcome` in the returned `ExtractionReport`; policy
  rejection is not reported as silent success.

## Resource and capability changes

- Safe defaults cap decoded totals and entries at 4 GiB, metadata and codec
  workspaces at 64 MiB, and in-flight buffers at 8 MiB.
- Automatic spooling was removed. `SpoolReader` / `SpoolWriter` use an 8 MiB
  memory threshold and a 4 GiB maximum by default.
- Outer compression removes seek capability; seek-required formats therefore
  require explicit spooling after decompression.
