<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# XAR fixture provenance

Provenance registry for the XAR producers exercised by the interoperability-evidence
harness (`libarchive_oxide/tests/common/mod.rs`, consumed by
`libarchive_oxide/tests/interop_xar_meta.rs`).

XAR is a **read-only, seek-native** format in arca — there is no XAR writer — so
the interop evidence is producer-driven: independent producers emit `.xar` bytes
and arca's seek reader (`read_with_arca`) reconstructs identical
`(path, kind, content)` shapes.

## Generation policy

**No binary fixtures are committed for XAR.** All XAR bytes used by the interop
harness are generated **deterministically, in-code, at test run time** — hermetic,
no network, no committed blobs, nothing that can rot. The pinned
`[dev-dependencies]` in `libarchive_oxide/Cargo.toml` (`flat2` for the zlib TOC
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

Consumer: `arca` (self, via `read_with_arca` / `SeekArchiveReader`).

The zlib codec used by the builder is pinned in `libarchive_oxide/Cargo.toml`:

```toml
flat2 = "1"   # zlib (RFC-1950) TOC + x-gzip heap blobs for the raw-xar-builder producer
```

## Layout produced by `raw-xar-builder`

- **Header (28 bytes, BIG-endian):** magic `0x78617221` (`xar!`), `size = 28`,
  `version = 1`, `toc_length_compressed`, `toc_length_uncompressed`, `cksum_alg = 0`.
- **TOC:** a zlib (RFC-1950) stream that inflates to UTF-8 XML: `<xar><toc>` with
  top-level `<file>` roots and one nested `<directory>` carrying a child `<file>`.
  Each regular file has a `<data>` child declaring `<length>` (decoded),
  `<offset>` (heap-relative), `<size>` (stored), and an
  `<encoding style="…"/>`. A `<creation-time>` element is present and ignored.
- **Heap:** STORED blobs are copied verbatim; `x-gzip` blobs are zlib streams,
  placed at the declared offsets. Blobs are addressed only by offset/size (never
  positional), matching XAR's unordered/shared-heap model.

## Case coverage this slice

- **Positive round trip (`xar_meta_roundtrip`, `xar_payload_bytes_exact`):**
  small STORED file, larger zlib (`x-gzip`) file, empty file (no `<data>`),
  nested directory + file-in-subdir. arca reads each back to byte-identical
  content, dir before its children.
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
the pinned `flat2` dev-dependency; no third-party binary artifact is
redistributed. First-party generators are covered by this repository's
`MIT OR Apache-2.0` license.

## How to regenerate

There is nothing to regenerate: the bytes do not exist on disk. Run the harness to
reproduce them deterministically:

```sh
cargo test -p libarchive_oxide --test interop_xar_meta
```

## External-tool / independent-producer escape hatch

Only ONE fully-independent XAR producer runs in this slice (the first-party
`raw-xar-builder`; arca has no XAR writer, so there is no self-producer). If a
future slice needs additional independent producers for stronger
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
