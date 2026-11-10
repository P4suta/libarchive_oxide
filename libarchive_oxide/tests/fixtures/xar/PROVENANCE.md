<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# XAR fixture provenance

Provenance registry for the XAR producers exercised by the interoperability-evidence
harness (`libarchive_oxide/tests/common/mod.rs`, consumed by
`libarchive_oxide/tests/interop_xar_meta.rs`).

XAR is a **seek-native** format in arca.
The reader and bounded writer support Store, zlib, and BZip2 payloads.
The writer emits one independent stream per regular file and spools the bounded heap to memory and then a temporary file as necessary because the compressed XML TOC must precede it.
Reader evidence remains producer-driven; writer evidence adds self round trips, an independent miniz zlib decode, and an optional system-libarchive consumer.

## Generation policy

**No binary fixtures are committed for XAR.** All XAR bytes used by the interop
harness are generated **deterministically, in-code, at test run time** — hermetic,
no network, no committed blobs, nothing that can rot. The lockfile-resolved
`[dev-dependencies]` in `libarchive_oxide/Cargo.toml` (`flate2` for the zlib TOC
and `x-gzip` heap blobs) are the single source of truth for producer identity;
when a pin changes, the label strings change with it as a deliberate, reviewed
edit.

This directory therefore contains **only this policy document** today. It exists as
the reserved location for any future byte-exact external-tool artifact (see
"External-tool escape hatch" below).

## Producer registry

| Label | Crate / tool | Version | Independent of arca? | Methods | Generation |
|-------|--------------|---------|----------------------|---------|------------|
| `raw-xar-builder` | first-party bytes in `tests/interop_xar_meta.rs` | n/a | yes (hand-written BE header + zlib TOC XML + heap layout, independent of arca's reader) | STORED (`application/octet-stream`) + zlib (`application/x-gzip`) | in-code |
| `libarchive_oxide-xar-writer` | `SeekArchiveWriter` in `src/xar/write.rs` | workspace | no (self producer) | STORED (`application/octet-stream`), zlib (`application/x-gzip`), BZip2 (`application/x-bzip2`) | `tests/xar_write.rs` |

Consumer: `arca` (self, via `read_with_arca` / `SeekArchiveReader`).

When a system `bsdtar` is present, `tests/xar_write.rs` also feeds writer output to that independent libarchive consumer and verifies its listing.
This test is skipped when the external executable is unavailable so the default suite stays hermetic.

The manifest accepts `flate2` 1.x and the committed `Cargo.lock` currently resolves
it to 1.1.9:

```toml
flate2 = "1"   # zlib (RFC-1950) TOC + x-gzip heap blobs for the raw-xar-builder producer
```

## Layout produced by `raw-xar-builder`

- **Header (28 bytes, BIG-endian):** magic `0x78617221` (`xar!`), `size = 28`,
  `version = 1`, `toc_length_compressed`, `toc_length_uncompressed`, `cksum_alg = 0`.
- **TOC:** a zlib (RFC-1950) stream that inflates to UTF-8 XML: `<xar><toc>` with
  top-level `<file>` roots and one nested `<directory>` carrying a child `<file>`.
  Each regular file has a `<data>` child declaring `<length>` (decoded),
  `<offset>` (heap-relative), `<size>` (stored), and an
  `<encoding style="…"/>`. A `<creation-time>` element is present and ignored.
- **Heap:** STORED blobs are copied verbatim; `x-gzip` blobs are zlib streams and
  `x-bzip2` blobs are independently encoded bzip2 streams, placed at the declared
  offsets. Blobs are addressed only by offset/size (never positional), matching
  XAR's unordered/shared-heap model.

## Case coverage this slice

- **Store writer round trip (`seek_writer_roundtrips_store_tree_and_metadata`):** directories, nested files, XML escaping, symbolic links, numeric owner/mode,
  nanosecond modification time, chunked payloads, and implicit parents survive a writer-to-reader round trip.
- **Writer adversarial coverage:** entry/path/nesting/metadata/entry/decoded/ in-flight and codec-memory limits, encoded-expansion bounds, duplicate paths,
  declared-size mismatches, lossy metadata rejection, abort-without-publication,
  feature-off BZip2 rejection, fuzz/replay profile selection, and futures/Tokio adapters.
  Large zlib output spans multiple reader events, and multiple entries prove independent stream framing.
  The exact zlib heap bytes are also decoded with miniz's one-shot API.

- **Positive round trip (`xar_meta_roundtrip`, `xar_payload_bytes_exact`):**
  small STORED file, larger zlib (`x-gzip`) file, empty file (no `<data>`),
  nested directory + file-in-subdir. arca reads each back to byte-identical
  content, dir before its children.
- **BZip2 interop and adversarial coverage
  (`xar_bzip2_streams_and_enforces_integrity_and_memory_limits`):** a bzip2 stream
  produced independently through the `bzip2` crate is decoded incrementally by
  arca. The case covers large and empty members, corrupt input, an incorrect
  declared decoded length, and a codec-memory limit below the decoder workspace.
- **Negative — unsupported encoding (`xar_unsupported_encoding_errors`):** a
  `<data>` with `style="application/x-lzma"` yields a structured
  `ErrorKind::Unsupported` (format `"xar"`) at read time.
- **Negative — truncated header (`xar_truncated_header_errors`):** a 4-byte input
  (`xar!` magic only) fails to open with a structured error.
- **Negative — TOC region past EOF (`xar_toc_region_past_eof_errors`):** a header
  declaring a compressed-TOC length beyond the file yields structured
  `ErrorKind::Malformed`.

## Spec reference

- XAR: the `xar` on-disk format — 28-byte big-endian `xar_header`, zlib-compressed
  XML table of contents, and an offset-addressed heap.
- TOC compression / `x-gzip` heap blobs: RFC 1950 (zlib) — note that XAR's
  `application/x-gzip` is a **zlib** stream, NOT a gzip/RFC-1952 wrapper.

## License / origin

All XAR bytes are produced at test time by first-party code in this repository and
the lockfile-resolved `flate2` dev-dependency; no third-party binary artifact is
redistributed. First-party generators are covered by this repository's
`MIT OR Apache-2.0` license.

## How to regenerate

There is nothing to regenerate: the bytes do not exist on disk. Run the harness to
reproduce them deterministically:

```sh
cargo test -p libarchive_oxide --test interop_xar_meta
cargo test -p libarchive_oxide --all-features --test xar_write --test async_seek_v2
```

## External-tool / independent-producer escape hatch

Only ONE fully-independent XAR producer runs in this slice (the first-party
`raw-xar-builder`). The arca writer is intentionally recorded as a self-producer,
not independent evidence. If a future slice needs additional producers for stronger
"≥N producers can be read" evidence, the canonical external references are:

- **`xar` CLI** (the reference C implementation / libxar), e.g.
  `xar -c -f out.xar --compression=gzip <inputs>`.
- **`libarchive` `bsdtar`**, e.g. `bsdtar -c -f out.xar --format=xar <inputs>`.

To commit a byte-exact artifact from either, place it under
`tests/fixtures/xar/<producer>/<case>.xar` and add a row here plus a regeneration
block recording: tool name, exact version, exact command line, capture date,
SHA-256 of the committed file, and the upstream license/redistribution note.
Regeneration must be byte-reproducible. REUSE is covered by the repo-wide
`REUSE.toml` override for `**/tests/fixtures/**` (no `.license` sidecar).
