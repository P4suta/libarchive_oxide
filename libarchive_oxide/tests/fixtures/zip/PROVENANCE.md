<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# ZIP fixture provenance

Provenance registry for the ZIP producers/consumers exercised by the
interoperability-evidence harness (`libarchive_oxide/tests/common/mod.rs`,
consumed by `libarchive_oxide/tests/interop_foundation.rs`).

## Generation policy

Except for the explicitly registered external-tool artifacts below, ZIP bytes used by the interop
harness are generated **deterministically, in-code, at test run time** — hermetic,
no network at test time. The
pinned `[dev-dependencies]` in `libarchive_oxide/Cargo.toml` are the single source
of truth for producer identity; when a pin changes, the `crate@version` label
strings change with it as a deliberate, reviewed edit.

This directory contains this registry, deterministic first-party generator
sources, and the two explicitly registered byte-exact external-tool artifacts
described below (`python-lzma/lzma-basic.zip` and
`7zip/deflate64.zip`).

## Producer / consumer registry

| Label | Crate / tool | Version | Independent of arca? | Method | Generation |
|-------|--------------|---------|----------------------|--------|------------|
| `arca` | `libarchive_oxide` | workspace | no (self / system under test) | Store + Deflate | in-code (`ArchiveWriter`) |
| `zip@8.6.0` | `zip` | 8.6.0 | yes | Store + Deflate | in-code (`ZipWriter`) |
| `raw-zip-builder` | first-party bytes in `tests/interop_foundation.rs` | n/a | yes (independent of both arca and the `zip` crate; hand-written local-header + central-directory layout) | Store (+ Deflate via `flate2`) | in-code |
| `python-lzma` | `CPython zipfile`/`liblzma` | CPython 3.14.6 (MSC v.1944 x64) | yes (independent liblzma reference) | LZMA (14) | committed blob (`python-lzma/lzma-basic.zip`) |
| `7zip-26.02` | official 7-Zip Extra `7za.exe` | 26.02 x64 (2026-06-25) | yes | Deflate64 (9) | committed blob (`7zip/deflate64.zip`) |

Store, Deflate, and LZMA consumers: `arca` (self, via `read_with_arca`) and
`zip@8.6.0` (the `zip` crate, via `ZipArchive::by_index`). The committed
Deflate64 fixture is consumed only by `arca`; the `zip` crate does not expose a
method-9 decoder.

The `zip` crate version is pinned in `libarchive_oxide/Cargo.toml`:

```toml
zip = { version = "8.6.0", default-features = false, features = ["deflate", "aes-crypto", "bzip2", "zstd", "lzma"] }
flate2 = "1"   # deflate stream for the raw-zip-builder producer
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

Most ZIP bytes are produced at test time by pinned dev-dependencies or
first-party code in this repository. The two committed archive outputs contain
only synthetic first-party payloads and are registered below with their
producer, hash, and licensing notes; no producer executable or library is
redistributed. The `zip` crate is MIT-licensed. First-party generators are
covered by this repository's `MIT OR Apache-2.0` license.

## How to regenerate

Run the harness to reproduce the in-code cases deterministically:

```sh
cargo test -p libarchive_oxide --test interop_foundation
```

Regenerate each committed artifact with the producer-specific command and fixed
inputs in its section below, then verify the recorded SHA-256 before replacing
the checked-in file.

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

One of the two committed binary fixtures in this tree, used by
`tests/interop_zip_lzma.rs` as the INDEPENDENT-codec reference for ZIP method 14
(LZMA).

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

## Committed Deflate64 fixture

- **File:** `7zip/deflate64.zip`
- **Producer:** official 7-Zip Extra `7za.exe`, version 26.02 x64
  (2026-06-25).
- **Tool source:** <https://www.7-zip.org/download.html>, “7-Zip Extra:
  standalone console version”.
- **Capture date:** 2026-07-28.
- **Exact command:**

  ```powershell
  7za.exe a -tzip deflate64.zip <input-directory>\* `
    -mm=Deflate64 -mx=9 -mfb=64 -mpass=15 -mtc=off -mta=off -mtm=off
  ```

- **Inputs, in lexical order:** `empty.bin` (0 bytes), `small.txt` (the exact
  27 UTF-8/ASCII bytes `Deflate64 streaming fixture`), and
  `wide-window.bin`. To reproduce `wide-window.bin`, initialize a wrapping
  `u32` xorshift state to **`0x12345678`**; for each of 50,000 bytes apply
  `state ^= state << 13`, `state ^= state >> 17`, and
  `state ^= state << 5`, retaining the low eight bits after the third
  operation. Repeat that 50,000-byte sequence three times. This is the same
  authoritative algorithm asserted by
  `tests/interop_zip_deflate64.rs::official_7zip_fixture_exercises_the_64k_window`.
  The repeated sequence requires a match distance beyond the 32 KiB Deflate
  window; 7-Zip reports method `Deflate64` and packed size 51,126 bytes for
  that member.
- **SHA-256:** `053a0dfd2b906e4993ace34d2ae8599b2610f5adbfd5c5bbe50b0e6fedad3d6b`
  (51,469 bytes).
- **Tool downloads:** official `7zr.exe` SHA-256
  `56b8cc9f4971cef253644fafe54063ed7fdca551d4dee0f8c6baa81b855acd72`;
  official `7z2602-extra.7z` SHA-256
  `081df9e9311dfd9c9e0e98c1c80180b99bb51e4cb24156b5f3057fe3c259d70a`.
- **License/redistribution:** 7-Zip is primarily GNU LGPL with BSD-3-Clause
  and unRAR-notice components. Only archive output over first-party synthetic
  content is redistributed; no 7-Zip program or source is committed.
- **Determinism:** timestamps are disabled and therefore normalized to the ZIP
  epoch by 7-Zip. Re-running the command over byte-identical, lexically ordered
  inputs produces the recorded bytes.
