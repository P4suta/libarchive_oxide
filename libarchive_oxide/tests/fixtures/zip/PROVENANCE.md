<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# ZIP fixture provenance

Provenance registry for the ZIP producers/consumers exercised by the
interoperability-evidence harness (`libarchive_oxide/tests/common/mod.rs`,
consumed by `libarchive_oxide/tests/interop_foundation.rs`).

## Generation policy

**No binary fixtures are committed for ZIP.** All ZIP bytes used by the interop
harness are generated **deterministically, in-code, at test run time** — hermetic,
no network, no committed blobs, nothing that can rot or need re-verification. The
pinned `[dev-dependencies]` in `libarchive_oxide/Cargo.toml` are the single source
of truth for producer identity; when a pin changes, the `crate@version` label
strings change with it as a deliberate, reviewed edit.

This directory therefore contains **only this policy document** today. It exists as
the reserved location for any future byte-exact external-tool artifact (see
"External-tool escape hatch" below).

## Producer / consumer registry

| Label | Crate / tool | Version | Independent of arca? | Method | Generation |
|-------|--------------|---------|----------------------|--------|------------|
| `arca` | `libarchive_oxide` | workspace | no (self / system under test) | Store + Deflate | in-code (`ArchiveWriter`) |
| `zip@8.6.0` | `zip` | 8.6.0 | yes | Store + Deflate | in-code (`ZipWriter`) |
| `raw-zip-builder` | first-party bytes in `tests/interop_foundation.rs` | n/a | yes (independent of both arca and the `zip` crate; hand-written local-header + central-directory layout) | Store (+ Deflate via `flat2`) | in-code |
| `python-lzma` | `CPython zipfile`/`liblzma` | CPython 3.14.6 (MSC v.1944 x64) | yes (independent liblzma reference) | LZMA (14) | committed blob (`python-lzma/lzma-basic.zip`) |

Consumers: `arca` (self, via `read_with_arca`) and `zip@8.6.0` (the `zip` crate,
via `ZipArchive::by_index`).

The `zip` crate version is pinned in `libarchive_oxide/Cargo.toml`:

```toml
zip = { version = "8.6.0", default-features = false, features = ["deflate", "aes-crypto"] }
flat2 = "1"   # deflate stream for the raw-zip-builder producer
```

## Method coverage this slice

- **ZIP Store**: >= 3 producers (`arca` + `zip@8.6.0` + `raw-zip-builder`),
  >= 2 consumers (`arca` + `zip@8.6.0`).
- **ZIP Deflate**: >= 3 producers (same trio), >= 2 consumers (same pair).

## Spec reference

- ZIP: PKWARE .ZIP File Format Specification, APPNOTE.TXT (version 6.3.x).
- Deflate stream: RFC 1951 (DEFLATE Compressed Data Format).
- Compression-method codes: Store = 0, Deflate = 8 (APPNOTE section 4.4.5).

## License / origin

All ZIP bytes are produced at test time by the pinned dev-dependencies or by
first-party code in this repository; no third-party binary artifact is
redistributed. The `zip` crate is MIT-licensed. First-party generators are
covered by this repository's `MIT OR Apache-2.0` license.

## How to regenerate

There is nothing to regenerate: the bytes do not exist on disk. Run the harness to
reproduce them deterministically:

```sh
cargo test -p libarchive_oxide --test interop_foundation
```

## How to extend (RM-302 / RM-303 / RM-304)

Add a free `fn(&[LogicalEntry]) -> Vec<u8>` producer and/or a
`fn(&[u8]) -> Vec<EntryShape>` consumer, tag it with its `crate@version`, and pass
it in a `&[]` array to `assert_producers_agree` / `assert_consumers_accept`. No
edit to `tests/common/mod.rs` is required. Add a corresponding row to this table.

## External-tool escape hatch

If a future slice needs a byte-exact artifact from an external tool (e.g. Info-ZIP,
7-Zip CLI), commit it under `tests/fixtures/zip/<producer>/<case>.zip` and add a row
here plus a regeneration block recording: tool name, exact version, exact command
line, capture date, SHA-256 of the committed file, and the upstream
license/redistribution note. Regeneration must be byte-reproducible.

## Committed LZMA fixture (external-tool escape hatch)

The one committed binary fixture in this tree, used by `tests/interop_zip_lzma.rs`
as the INDEPENDENT-codec reference for ZIP method 14 (LZMA).

- **File:** `python-lzma/lzma-basic.zip`
- **Generator (committed alongside):** `python-lzma/generate.py` (SPDX header inline).
- **Producer:** `CPython 3.14.6 zipfile`/`liblzma` (MSC v.1944 x64) — fully
  independent of both arca and `lzma-rust2`.
- **Exact command:**

  ```sh
  python libarchive_oxide/tests/fixtures/zip/python-lzma/generate.py \
         libarchive_oxide/tests/fixtures/zip/python-lzma/lzma-basic.zip
  ```

- **SHA-256 of the committed `.zip`:**
  `040d334b05510fe4631d49eb9a90a1e4a1f0f501ab4f23d5152c451bab45b739` (size 474 bytes).
  Bound to the exact `generate.py` content; verified byte-reproducible across runs.
- **Fixed inputs (determinism levers):** member set + order
  `readme.txt` (17 B), `sub/big.txt` (8800 B), `sub/empty.txt` (0 B);
  `date_time=(1980,1,1,0,0,0)`; `external_attr=0o644<<16`;
  `compress_type=zipfile.ZIP_LZMA`. No OS metadata; Python stores no explicit
  `sub/` directory entry. All three members carry general-purpose flag `0x0002`
  (EOS-marker convention); `sub/empty.txt` exercises the zero-length LZMA read.
- **REUSE:** covered by the repo-wide `REUSE.toml` override
  (`path = ["**/tests/fixtures/**"]`, `SPDX-License-Identifier = "MIT OR Apache-2.0"`),
  exactly as the committed `tests/fixtures/zstd/*.zst` blobs are — NO `.license`
  sidecar. REUSE-ours is correct here: arca *generated* these bytes with a
  first-party script; CPython's `zipfile`/`lzma` are stdlib tooling, not a
  redistributed third-party artifact.

### Two-independent-codecs honesty note (LZMA / method 14)

Only TWO independent LZMA codecs exist in this ecosystem: `lzma-rust2` (pure-Rust)
and `liblzma` (C). In the method-14 interop matrix, producer `arca` and producer
`raw-zip-lzma-builder` are independent ZIP *container* builders but BOTH drive
`lzma-rust2`; the committed `python-lzma` fixture is the sole INDEPENDENT-codec
(liblzma) reference. The `zip` crate consumer (with its `lzma` feature) is also
`lzma-rust2`-backed, so WRITE evidence — the `zip` crate decoding arca's method-14
output to byte-identical content — proves arca's ZIP-container framing + 9-byte
LZMA header + stream are spec-valid, with the codec shared. The interop
independence for LZMA is real but narrower than for Store/Deflate.

## Method coverage — RM-302 LZMA sub-slice

- **ZIP LZMA (method 14):** 3 producers (`arca` + `raw-zip-lzma-builder`, both
  `lzma-rust2`; + `python-lzma`, independent `liblzma`), 2 consumers
  (`arca` + `zip@8.6.0` with `lzma`). Read + write, gated on the `xz` feature.
