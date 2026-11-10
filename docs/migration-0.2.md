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
- `StreamingArchiveBuilder::new` remains available, but now delegates to the
  same `ArchiveEngine` / `CreateOptions` writer path. Use
  `StreamingArchiveBuilder::with_engine` when engine limits are authoritative.

## Async

- Enable `async` for futures-io or `tokio` for Tokio.
- Use `AsyncArchiveReader` / `AsyncArchiveWriter` for sequential futures-io,
  and `AsyncSeekArchiveReader` / `AsyncSeekArchiveWriter` for seek formats.
- Tokio reader and writer equivalents use the `Tokio*` prefix. They are I/O
  adapters and do not provide a second filesystem-extraction policy path.
- Every adapter drives the same archive state machines; dropping/cancelling a
  writer never performs an implicit finish.

## Metadata and dialects

- Call `set_archive_metadata` before the first entry when preserving archive
  comments, global PAX data, ISO volume properties, or 7z archive properties.
- Use `ArchiveWriter::with_cpio_dialect` (or
  `CpioEncoder::with_dialect`) with `CpioDialect` for newc, crc, odc, or binary
  LE/BE output. crc output requires the typed four-byte payload byte sum in
  entry metadata.
- Use `ArchiveTranscoder::{transcode, transcode_to_seek,
  transcode_from_seek, transcode_seek}` according to the source/destination
  access requirements. Successful output includes a bounded `TranscodeReport`;
  inspect every `MetadataLoss` or select `MetadataLossPolicy::Reject` before
  rewriting. mtree conversion is refused because the format does not carry
  file bodies.
- Use `ArchiveEditor::{rewrite, rewrite_to_seek, rewrite_from_seek,
  rewrite_seek}` for exact-path rename/remove plans. Rewrites validate all
  retained output paths, update hardlink targets on rename, reject removals
  that would leave hardlinks dangling, and fail when an operation matches no
  entry. `EditReport` exposes operation counts and the nested fidelity report.

## Extraction

- `ExtractionPolicy`, `Extractor`, and `TokioExtractor` were removed. Use the
  root `Policy` as the single extraction configuration.
- Call `ArchiveEngine::prepare`, `ArchiveSession::plan(Policy::safe())`, then
  `apply(plan, cap_std::fs::Dir)`. Planning consumes the complete immutable
  snapshot and fixes path identities and collisions before filesystem startup.
- Use `apply_with_adapter` for a downstream `FilesystemAdapter`. It consumes
  the same opaque, session-bound plan; there is no direct event-to-filesystem
  entrypoint that can bypass preflight.
- Inspect every `EntryOutcome` in `ApplyReport::extraction`; policy rejection
  is not reported as silent success.
  Inspect `ApplyReport::filesystem_findings` when restoration fidelity matters;
  unsupported, refused, partial, and OS-error attributes are never implicit
  success.

## Resource and capability changes

- Safe defaults cap decoded totals and entries at 4 GiB, metadata and codec
  workspaces at 64 MiB, and in-flight buffers at 8 MiB.
- Automatic spooling was removed. `SpoolReader` / `SpoolWriter` use an 8 MiB
  memory threshold and a 4 GiB maximum by default.
- Outer compression removes seek capability; seek-required formats therefore
  require explicit spooling after decompression.

## Command line

- `oxarchive create --format FORMAT [--filter FILTER] ARCHIVE INPUT...` uses the
  shared bounded filesystem builder. Existing file destinations are refused;
  successful file output is atomically published from a sibling.
- `SeekArchiveBuilder` and `ArchiveEngine::create_seek` provide the same
  filesystem contract for 7z, ISO 9660, and XAR. The CLI infers `.7z`, `.iso`,
  and `.xar`; these seek-native outputs require a file and reject outer filters.
- `oxarchive convert SOURCE DEST` is the thin CLI wrapper over
  `ArchiveTranscoder`. It selects the required sequential/seek path, publishes
  atomically without replacement, reports bounded typed metadata losses, and
  supports fail-closed `--reject-metadata-loss`.
- `oxarchive edit (--remove PATH | --rename FROM=TO)... SOURCE DEST` wraps
  `ArchiveEditor` with the same access selection and atomic no-replace commit.
  A missing operation, unmatched path, unsafe/conflicting result, or dangling
  hardlink is an error and never publishes `DEST`.
- `oxarchive --json inspect` is JSON Lines, not one collected JSON object.
  Consume `inspect_start`, `inspect_entry*`, and the required
  `inspect_complete` success sentinel.
- Encrypted ZIP/7z reads and encrypted ZIP creation take secrets only through
  `--password-file FILE` or the no-echo, TTY-only `--password-prompt`.
  Command-line values (`--password[=...]` and legacy `-P...`) are rejected
  before I/O.
- Exit meanings are 0 success, 1 operational failure, and 2 usage/unsupported
  option. Diagnostics use stderr. A stdout archive can be partial on exit 1;
  JSON is never mixed with binary archive output.
