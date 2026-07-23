<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# ar fixture provenance

Provenance registry for the ar (Unix archiver) producers/consumers exercised by
the interoperability-evidence harness (`libarchive_oxide/tests/common/mod.rs`,
consumed by `libarchive_oxide/tests/interop_ar_meta.rs`).

## Generation policy

**No binary fixtures are committed for ar.** All ar bytes used by the interop
harness are generated **deterministically, in-code, at test run time** — hermetic,
no network, no committed blobs, nothing that can rot or need re-verification. The
pinned `[dev-dependencies]` in `libarchive_oxide/Cargo.toml` are the single source
of truth for producer identity; when a pin changes, the `crate@version` label
strings change with it as a deliberate, reviewed edit.

This directory therefore contains **only this policy document** today. It exists as
the reserved location for any future byte-exact external-tool artifact (see
"External-tool escape hatch" below).

## Producer / consumer registry

| Label | Crate / tool | Version | Independent of arca? | What | Generation |
|-------|--------------|---------|----------------------|------|------------|
| `arca` | `libarchive_oxide` | workspace | no (self / system under test) | regular-file members, BSD long-name writer | in-code (`ArchiveWriter`, `FormatId::Ar`) |
| `ar@0.9` | `ar` | 0.9.0 | yes | regular-file members via `Builder`/`Header` (common variant for short names) | in-code (`ar::Builder`) |
| `raw-ar-builder` | first-party bytes in `tests/interop_ar_meta.rs` | n/a | yes (independent of both arca and the `ar` crate; hand-written `!<arch>\n` magic + 60-byte SysV member headers) | regular-file members | in-code |

Consumers: `arca` (self, via `read_seq_with_arca`) and `ar@0.9` (the `ar` crate,
via `Archive::next_entry`).

The `ar` crate version is pinned in `libarchive_oxide/Cargo.toml`:

```toml
ar = "0.9"
```

## Corpus shape this slice

`ar` is a FLAT archive of regular files only — it carries no directory or symlink
concept, so no `Dir`/`Symlink` entries and no link-target fidelity are in scope
(contrast the tar slice). The logical corpus is four regular files:
`readme.txt` (15 B), `data.bin` (256 B, all byte values 0..=255), `big.txt`
(2816 B), and `empty` (0 B, exercising the zero-length member). Every member name
is kept **< 16 bytes** so all three producers stay on the short-name path:

- arca writes BSD long names (`#1/LEN`, real name inline at the start of the
  member body) once a name exceeds 15 bytes — see
  `libarchive_oxide-core/src/format/ar.rs` (`ArEncoder::stage_entry`,
  `inline_name = name.len() > 15`).
- the `ar` crate's `Builder` switches to the BSD `#1/` form only at name length
  > 16 **or** on an embedded space (`Header::write`).

Keeping names short therefore avoids BSD-vs-GNU long-name divergence between
producers: all three emit the byte-compatible common/SysV `name/` (or
space-padded) member header that arca's decoder reads identically. Long-name
handling itself is covered separately by
`libarchive_oxide-core/tests/protocol_v2.rs`
(`ar_decoder_supports_bsd_names_at_one_byte_boundaries`).

## Metadata coverage this slice

`ar` records only `mode`, `uid`, `gid`, and `mtime` (no symlink target, no xattrs,
no per-entry type beyond regular file). `ar_metadata_round_trip` asserts all four
survive for both an arca-produced member and an `ar@0.9`-produced member, read
back through arca's `read_meta_seq_with_arca`. arca masks the stored mode to the
low 12 permission bits on read (the `S_IFREG` type bits in `100640` are dropped),
so `0o640` round-trips exactly.

## Method coverage this slice

- **ar (uncompressed member store):** >= 3 producers (`arca` + `ar@0.9` +
  `raw-ar-builder`), >= 2 consumers (`arca` + `ar@0.9`). Content interop + write
  evidence (both consumers decode arca's output to byte-identical content) +
  4-field metadata fidelity.

## Spec reference

- ar format: SysV/System V `ar(5)` common archive format — `!<arch>\n` global
  magic, fixed 60-byte ASCII member headers (name[16], mtime[12], uid[6], gid[6],
  mode[8, octal], size[10], `` `\n `` terminator[2]), members padded to a 2-byte
  boundary with a trailing `\n`.
- BSD long names: `#1/LEN` in the name field with the real name stored at the
  start of the member data (used by BSD `ar` and macOS; arca's writer default).
- GNU long names: `//` string-table member plus `/OFFSET` name references (read
  support only in arca; not emitted by any producer in this slice).

## License / origin

All ar bytes are produced at test time by the pinned dev-dependencies or by
first-party code in this repository; no third-party binary artifact is
redistributed. The `ar` crate is dual MIT/Apache-2.0 licensed. First-party
generators are covered by this repository's `MIT OR Apache-2.0` license.

## How to regenerate

There is nothing to regenerate: the bytes do not exist on disk. Run the harness to
reproduce them deterministically:

```sh
cargo test -p libarchive_oxide --test interop_ar_meta
```

## How to extend (RM-304 and beyond)

Add a free `fn(&[LogicalEntry]) -> Vec<u8>` producer and/or a
`fn(&[u8]) -> Vec<EntryShape>` consumer, tag it with its `crate@version`, and pass
it in a `&[]` array to `assert_producers_agree_seq` / `assert_consumers_accept`. No
edit to `tests/common/mod.rs` is required. Add a corresponding row to this table.

## External-tool escape hatch

If a future slice needs a byte-exact artifact from an external tool (e.g. GNU
`ar`, BSD/macOS `ar`, `llvm-ar`), commit it under
`tests/fixtures/ar/<producer>/<case>.a` and add a row here plus a regeneration
block recording: tool name, exact version, exact command line, capture date,
SHA-256 of the committed file, and the upstream license/redistribution note.
Regeneration must be byte-reproducible.
