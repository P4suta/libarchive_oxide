<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# CPIO fixture provenance

Provenance registry for the cpio producers/consumers exercised by the
interoperability-evidence harness (`libarchive_oxide/tests/common/mod.rs`,
consumed by `libarchive_oxide/tests/interop_cpio_meta.rs`, RM-304).

## Generation policy

**No binary fixtures are committed for cpio.** All cpio bytes used by the interop
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
| `arca` | `libarchive_oxide` | workspace | no (self / system under test) | newc (070701) writer | in-code (`ArchiveWriter::with_cpio_dialect`) |
| `raw-newc-builder` | first-party bytes in `tests/interop_cpio_meta.rs` | n/a | yes (hand-written SVR4 newc: 110-byte header, 13 eight-hex-digit fields, 4-byte header+data padding) | newc (070701) | in-code |
| `raw-odc-builder` | first-party bytes in `tests/interop_cpio_meta.rs` | n/a | yes (hand-written POSIX odc: 76-byte header, octal fields, no padding — a genuinely different on-disk encoding) | odc (070707) | in-code |

Consumers: `arca` (self, via `read_seq_with_arca`) and `raw-newc-parser` (a
first-party newc decoder in `tests/interop_cpio_meta.rs`, independent of arca's
`CpioDecoder`, parsing arca's own newc output a second disjoint way).

## Three-independent-producers honesty note

There is **no mature pure-Rust cpio *producer* crate** in the ecosystem, so a
genuine third-party in-code producer is not available. The third independent
producer here is therefore a **second first-party raw builder in the `odc`
dialect** rather than an external crate. This is real independent evidence, not a
re-encoding of one layout: `odc` uses octal ASCII fields at different fixed
offsets, a 76-byte header vs newc's 110, and 1-byte alignment (no header/data
padding) vs newc's 4-byte padding. arca reading all three (arca-newc, raw-newc,
raw-odc) back to identical shapes+content proves its decoder handles two distinct
on-disk framings. The independence is real but is first-party-code independence,
not third-party-crate independence. An external `cpio(1)` CLI producer with
graceful skip (mirroring `libarchive_oxide-core/tests/tar_write_differential.rs`)
remains available as a future escape hatch but is not used here, to keep the slice
deterministic and network-free.

## Metadata fidelity this slice

cpio carries `mode`, `uid`, `gid`, `mtime`, `nlink`/`inode`, and device numbers;
it has **no** xattr or ACL support. `cpio_metadata_round_trip` asserts through
arca's `MetaShape`:

- a plain file (`file.txt`): `mode` (0o640), `uid`/`gid` (1000/1001), `mtime`
  survive a newc round trip;
- a hardlink group: the payload-bearing member (`target`, nlink 2) surfaces as a
  typed `File` and its zero-size alias (`alias`) surfaces as a typed `Hardlink`
  whose `link_target` points back at `target`.

## Dialect coverage

arca's cpio encoder supports five dialects via `CpioDialect`: `Newc` (070701),
`Crc` (070702), `Odc` (070707), and legacy binary little-/big-endian. This interop
slice drives `Newc` for deterministic, checksum-free bytes. `Crc` — which requires
each entry to carry a four-byte big-endian payload byte-sum — and every other
dialect are covered by
`libarchive_oxide-core/tests/protocol_v2.rs::cpio_encoder_roundtrips_every_supported_dialect`.

## Method coverage this slice

- **cpio content interop:** 3 producers (`arca` newc + `raw-newc-builder` +
  `raw-odc-builder`), 2 consumers (`arca` + `raw-newc-parser`).
- **cpio metadata fidelity:** arca newc writer + arca reader (mode/uid/gid/mtime +
  typed hardlink round trip).

## Spec reference

- cpio SVR4 "newc" (070701) and "crc" (070702): the ASCII header format documented
  in the POSIX.1 / SVR4 cpio and GNU cpio manuals; 110-byte header of a 6-byte
  magic plus 13 eight-hex-digit fields, header+name and data each padded to a
  4-byte boundary.
- cpio POSIX "odc" (070707): the portable ASCII format, 76-byte header of a 6-byte
  magic plus octal fields, 1-byte alignment (no padding). IEEE Std 1003.1 (pax
  `-x cpio` / historical `c_magic` 070707).
- The archive is terminated by a `TRAILER!!!` entry with a single link and zero
  size.

## License / origin

All cpio bytes are produced at test time by first-party code in this repository;
no third-party binary artifact is redistributed. First-party generators are
covered by this repository's `MIT OR Apache-2.0` license.

## How to regenerate

There is nothing to regenerate: the bytes do not exist on disk. Run the harness to
reproduce them deterministically:

```sh
cargo test -p libarchive_oxide --test interop_cpio_meta
```

## How to extend

Add a free `fn(&[LogicalEntry]) -> Vec<u8>` producer and/or a
`fn(&[u8]) -> Vec<EntryShape>` consumer, tag it with its `crate@version` (or
`raw-*` for first-party bytes), and pass it in a `&[]` array to
`assert_producers_agree_seq` / `assert_consumers_accept`. No edit to
`tests/common/mod.rs` is required. Add a corresponding row to the table above.

## External-tool escape hatch

If a future slice needs a byte-exact artifact from an external tool (e.g. GNU
`cpio`, `bsdcpio`/libarchive), commit it under
`tests/fixtures/cpio/<producer>/<case>.cpio` and add a row here plus a regeneration
block recording: tool name, exact version, exact command line, capture date,
SHA-256 of the committed file, and the upstream license/redistribution note.
Regeneration must be byte-reproducible.
