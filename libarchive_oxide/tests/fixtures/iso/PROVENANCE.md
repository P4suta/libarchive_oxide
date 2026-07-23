<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# ISO fixture provenance

Provenance registry for the ISO 9660 producers/consumers exercised by the
interoperability-evidence harness (`libarchive_oxide/tests/common/mod.rs`,
consumed by `libarchive_oxide/tests/interop_iso_meta.rs`).

## Generation policy

**No binary fixtures are committed for ISO.** All ISO bytes used by the interop
harness are generated **deterministically, in-code, at test run time** — hermetic,
no network, no committed blobs, nothing that can rot or need re-verification. arca's
own `SeekArchiveWriter` (`FormatId::Iso9660`) masters every image the in-code cases
use; the single INDEPENDENT producer is an external ISO mastering tool invoked at
run time behind a graceful skip (see "External-tool escape hatch" below), never a
committed artifact.

This directory therefore contains **only this policy document** today. It exists as
the reserved location for any future byte-exact external-tool artifact.

## Producer / consumer registry

| Label | Crate / tool | Version | Independent of arca? | What | Generation |
|-------|--------------|---------|----------------------|------|------------|
| `arca` | `libarchive_oxide` | workspace | no (self / system under test) | ISO 9660 + Joliet + Rock Ridge | in-code (`SeekArchiveWriter`) |
| `xorriso` / `genisoimage` / `mkisofs` | system ISO mastering tool | whatever is on `PATH` (recorded per run) | yes (independent C mastering tool) | Rock Ridge (`-R`) + Joliet (`-J`) image, read back by arca | external CLI at run time, **graceful skip** when absent |

Consumers: `arca` only (self, via `read_with_arca` / `read_meta_seek_with_arca`).

### Producer-independence honesty note

Unlike tar/ZIP, ISO has **no usable pure-Rust independent reader on every target**
this suite runs on: the `iso9660` crate is a libcdio (C) binding and `cdfs` pulls in
FUSE, which does not build on Windows. Consequently:

- There is exactly **one in-code producer (`arca`)** and **one in-code consumer
  (`arca`)**; `iso_content_interop` is an arca-write -> arca-read self round trip,
  not a 3x2 matrix.
- The **independent** producer evidence is `arca_reads_system_mastered_image`: an
  external tool masters a Rock Ridge + Joliet image and arca reads the exact file
  content back. It **gracefully skips** when no tool is installed (as it does on the
  Windows dev/CI hosts here — none of xorriso/genisoimage/mkisofs is on `PATH`), so
  the independent leg is opportunistic, not guaranteed on every host.

If a run needs the independent leg to be non-optional, install `xorriso` (or
`genisoimage`/`mkisofs`) on the host; the test then masters and reads a real image.

## Metadata fidelity (Rock Ridge)

`iso_metadata_round_trip` proves arca's metadata survives its own Rock Ridge round
trip. arca's `SeekArchiveWriter` emits Rock Ridge **by default** (no option
required): `rock_ridge_system_use` in `src/iso_stream.rs` unconditionally writes the
`PX` (mode/uid/gid/links/inode), `TF` (timestamps), `NM` (real name), and, for
symlinks, `SL` (link target) system-use fields on the primary tree. On read,
`parse_iso_index`/`detect_rock_ridge` in `src/seek_stream.rs` auto-detect Rock Ridge
and prefer the primary tree over Joliet, so:

- **mode** round-trips via `PX` (`mode & 0o7777`),
- **uid/gid** round-trip via `PX`,
- **mtime** round-trips via `TF` (long-form timestamp; second precision, sub-second
  truncated to hundredths — the test uses `nanos = 0`),
- **symlink target** round-trips via `SL`, and the entry kind is recovered as
  `Symlink`,
- lowercase **names** round-trip via `NM` (the primary d-character tree mangles
  names; `NM` carries the original bytes).

## Method coverage this slice

- **ISO content**: 1 in-code producer + 1 in-code consumer (`arca` self round trip)
  covering a file, an empty file, a nested file, and a directory; plus 1
  independent external producer (`xorriso`/`genisoimage`/`mkisofs`) read back by
  arca, graceful-skip.
- **ISO metadata**: mode / uid / gid / mtime / symlink-target fidelity through
  arca's Rock Ridge, asserted with `MetaShape` via `read_meta_seek_with_arca`.

## Spec reference

- ISO 9660 (ECMA-119): Volume and File Structure of CDROM.
- Joliet: Microsoft Joliet Specification (UCS-2, SVD escape `25 2F 45`).
- Rock Ridge: IEEE P1282 (Rock Ridge Interchange Protocol) over the SUSP
  (System Use Sharing Protocol, IEEE P1281) — `PX`, `TF`, `NM`, `SL` fields.

## License / origin

All ISO bytes are produced at test time by arca's own writer or, when present, by a
system-installed mastering tool; no third-party binary artifact is redistributed in
this repository. First-party generators are covered by this repository's
`MIT OR Apache-2.0` license.

## How to regenerate

There is nothing to regenerate: the bytes do not exist on disk. Run the harness to
reproduce them deterministically:

```sh
cargo test -p libarchive_oxide --test interop_iso_meta
```

The independent external-producer leg additionally requires one of `xorriso`,
`genisoimage`, or `mkisofs` on `PATH`; without it, that test prints a skip line and
passes.

## How to extend

Add a free `fn(&[LogicalEntry]) -> Vec<u8>` producer and/or a
`fn(&[u8]) -> Vec<EntryShape>` consumer, tag it with its `crate@version` (or
tool name + version), and pass it in a `&[]` array to `assert_producers_agree` /
`assert_consumers_accept`. No edit to `tests/common/mod.rs` is required. Add a
corresponding row to the registry table above. A future pure-Rust independent ISO
reader would upgrade the consumer side from 1 to >= 2.

## External-tool escape hatch

The independent producer here shells out to a system tool at run time rather than
committing a blob. When a tool is used, the test records the tool name in its
assertion/skip messages. If a future slice instead needs a **byte-exact** committed
artifact from an external tool, commit it under
`tests/fixtures/iso/<producer>/<case>.iso` and add a row here plus a regeneration
block recording: tool name, exact version, exact command line, capture date,
SHA-256 of the committed file, and the upstream license/redistribution note.
Regeneration must be byte-reproducible.
