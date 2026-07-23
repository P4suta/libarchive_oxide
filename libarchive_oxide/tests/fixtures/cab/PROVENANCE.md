<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# CAB fixture provenance

Provenance registry for the Microsoft Cabinet (`.cab`) producers exercised by the
CAB interoperability test (`libarchive_oxide/tests/interop_cab_meta.rs`, which
reuses the RM-301 harness in `libarchive_oxide/tests/common/mod.rs`).

## Generation policy

**No binary fixtures are committed for CAB.** All CAB bytes used by the test are
generated **deterministically, in-code, at test run time** — hermetic, no network,
no committed blobs, nothing that can rot or need re-verification. The raw-DEFLATE
streams inside MSZIP folders are produced by the pinned `flat2` dev-dependency;
everything else (`CFHEADER`, `CFFOLDER`, `CFFILE`, `CFDATA` framing) is hand-laid
first-party bytes.

This directory therefore contains **only this policy document** today. It exists as
the reserved location for any future byte-exact external-tool artifact (see
"External-tool escape hatch" below).

## Producer registry

| Label | Crate / tool | Version | Independent of arca? | Method | Generation |
|-------|--------------|---------|----------------------|--------|------------|
| `raw-cab-builder` | first-party bytes in `tests/interop_cab_meta.rs` | n/a | yes (hand-assembled MSCF container, independent of any CAB library) | Store (NONE) | in-code |
| `raw-cab-builder + flat2` | `flat2` (raw DEFLATE) inside a first-party MSZIP frame | flat2 1.x | yes (independent DEFLATE codec; arca inflates with `miniz_oxide`) | MSZIP | in-code |

Consumer: `arca` (self, via `read_with_arca` / `SeekArchiveReader`).

The `flat2` version is pinned in `libarchive_oxide/Cargo.toml`:

```toml
flat2 = "1"
```

## Method coverage this slice

- **CAB Store (NONE, method 0):** first-party raw builder + arca reader; multi-file
  solid folder (small file, empty file, nested-path file), round-tripped
  `(path, kind, content)`.
- **CAB MSZIP (method 1):** first-party raw builder driving `flat2` raw DEFLATE
  + arca reader (`miniz_oxide` inflate). Covered layouts:
  - single-block folder (multi-file solid folder);
  - single block with real LZ77 back-references (repetitive payload);
  - multi-block folder with a file spanning several `CFDATA` blocks (32-byte
    blocks), exercising the folder-stream concatenation and the sliding-window
    carry across blocks.
- **Structured-error paths:** an out-of-scope compression method (`QUANTUM`, 2)
  yields `Unsupported`; an out-of-range `coffFiles` and a sub-`CFHEADER`-truncated
  image each yield a structured error.

### DEFLATE-codec independence note

MSZIP is `'CK'` + raw DEFLATE with the LZ77 window carried across a folder's
blocks. The test's producer compresses with `flat2` (which wraps the C `zlib`
/ `miniz` family) while arca decompresses with the pure-Rust `miniz_oxide`
low-level inflate core driven over a 32 KiB power-of-two wrapping ring. These are
independent DEFLATE implementations, so a shared codec bug cannot mask a framing
error. The in-code multi-block fixtures deflate each block independently (a
spec-valid MSZIP producer choice), so they prove correct block concatenation and
window continuation but not a producer that deliberately emits cross-block
back-references; that stricter evidence is deferred to the external escape hatch.

## Out of scope (structured `Unsupported`)

QUANTUM (2), LZX (3), and cross-cabinet continuation files (`iFolder` sentinels
`0xFFFD`/`0xFFFE`/`0xFFFF`, and spanning `CFDATA` with `cbUncomp == 0`) are listed
where possible but always report a structured `Unsupported` error on payload
access — never a panic.

## Spec reference

- CAB container: Microsoft `[MS-CAB]` Cabinet File Format (`CFHEADER`,
  `CFFOLDER`, `CFFILE`, `CFDATA`).
- MSZIP: the `'CK'`-prefixed DEFLATE variant with a window carried across blocks.
- DEFLATE stream: RFC 1951.
- Compression-method codes: NONE = 0, MSZIP = 1, QUANTUM = 2, LZX = 3
  (`typeCompress & 0x000F`).

## License / origin

All CAB bytes are produced at test time by first-party code and the pinned
`flat2` dev-dependency; no third-party binary artifact is redistributed.
`flat2` is dual-licensed under `MIT OR Apache-2.0`. First-party generators are
covered by this repository's `MIT OR Apache-2.0` license.

## How to regenerate

There is nothing to regenerate: the bytes do not exist on disk. Run the test to
reproduce them deterministically:

```sh
cargo test -p libarchive_oxide --test interop_cab_meta
```

## External-tool escape hatch

If a future slice needs a byte-exact artifact from an independent external
producer — Microsoft `makecab.exe`, `cabextract`/`libmspack`, or `gcab` — commit
it under `tests/fixtures/cab/<producer>/<case>.cab` and add a row here plus a
regeneration block recording: tool name, exact version, exact command line,
capture date, SHA-256 of the committed file, and the upstream
license/redistribution note. Regeneration must be byte-reproducible. Such an
artifact is the intended vehicle for cross-block MSZIP back-reference evidence and
for LZX/Quantum corpora once those methods move into scope.
```
