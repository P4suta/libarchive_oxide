<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# 7z fixture provenance

Provenance registry for the 7z producers/consumers exercised by the
interoperability-evidence harness (`libarchive_oxide/tests/common/mod.rs`,
consumed by `libarchive_oxide/tests/interop_foundation.rs`). These paths are gated
behind the `sevenz` cargo feature.

## Generation policy

**No binary fixtures are committed for 7z.** All 7z bytes used by the interop
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
| `arca` | `libarchive_oxide` | workspace | no (self / system under test) | LZMA2 | in-code (`SeekArchiveWriter`) |
| `sevenz-rust2@0.21.3` | `sevenz-rust2` | 0.21.3 | yes | LZMA2 | in-code (`SevenWriter`), feature `sevenz` |
| `sevenz-rust2@0.21.3-ppmd7` | `sevenz-rust2` | 0.21.3 | yes | PPMd7 read fixture | in-code (`SevenWriter` + `PpmdOptions`), feature `sevenz` |
| `compcol@0.6.8-bcj2` | `compcol` | 0.6.8 | yes | BCJ2 stream split/oracle | in-code (`bcj2::encode`/`decode` + spec-level 7z wrapper), feature `sevenz` |

Consumers: `arca` (self, via `read_with_arca`) and `sevenz-rust2@0.21.3`
(via `SevenReader::new` + `Password::empty()`), both under feature `sevenz`.

The `sevenz-rust2` version is pinned in `libarchive_oxide/Cargo.toml`:

```toml
sevenz-rust2 = "0.21.3"
compcol = { version = "0.6.8", default-features = false, features = ["bcj2"] }
```

## Method coverage this slice

- **7z LZMA2**: 2 producers (`arca` + `sevenz-rust2@0.21.3`),
  2 consumers (`arca` + `sevenz-rust2@0.21.3`), under feature `sevenz`.
- **7z PPMd7**: 1 independent producer (`sevenz-rust2@0.21.3`) and
  2 consumers (`arca` + `sevenz-rust2@0.21.3`), plus property, corruption,
  codec-memory, and fuzz-corpus regression coverage under feature `sevenz`.
- **7z BCJ2**: 1 independent stream producer/oracle (`compcol@0.6.8`),
  2 container consumers (`arca` + `sevenz-rust2@0.21.3`), plus seven-byte
  short-read, corruption, aggregate codec-memory, and fuzz-corpus coverage.

## Spec reference

- 7z container format: the `.7z` format as documented by the p7zip / 7-Zip project
  (`DOC/7zFormat.txt`).
- LZMA2 codec: the LZMA2 chunked wrapper over the LZMA algorithm as specified by
  the LZMA SDK.
- PPMd7 codec: variant H with the 7z range coder and a container-declared
  uncompressed-size boundary.
- BCJ2 codec: four streams (main/call/jump/range-control), exact declared
  output boundary, and method id `03 03 01 1B`.

## License / origin

All 7z bytes are produced at test time by pinned dev-dependencies
`sevenz-rust2`/`compcol` or by arca itself; no third-party binary artifact is
redistributed. `sevenz-rust2` is dual-licensed under `MIT OR Apache-2.0`;
`compcol` is MIT-licensed. arca output is covered by this repository's
`MIT OR Apache-2.0` license.

## How to regenerate

There is nothing to regenerate: the bytes do not exist on disk. Run the harness
with the `sevenz` feature to reproduce them deterministically:

```sh
cargo test -p libarchive_oxide --test interop_foundation --features sevenz
```

## How to extend (RM-302 / RM-303 / RM-304)

Add a free `fn(&[LogicalEntry]) -> Vec<u8>` producer and/or a
`fn(&[u8]) -> Vec<EntryShape>` consumer, tag it with its `crate@version`, and pass
it in a `&[]` array to `assert_producers_agree` / `assert_consumers_accept`. No
edit to `tests/common/mod.rs` is required. Add a corresponding row to this table.

## External-tool escape hatch

If a future slice needs a byte-exact artifact from an external tool (e.g. the 7-Zip
or p7zip CLI), commit it under `tests/fixtures/sevenz/<producer>/<case>.7z` and add
a row here plus a regeneration block recording: tool name, exact version, exact
command line, capture date, SHA-256 of the committed file, and the upstream
license/redistribution note. Regeneration must be byte-reproducible.
