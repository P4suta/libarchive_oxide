<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# tar fixture provenance

Producer-corpus and metadata-fidelity provenance for the tar interoperability
slice (RM-304), exercised by `libarchive_oxide/tests/interop_tar_meta.rs`.

## Generation policy

Every producer is generated deterministically in-code at test time — no binary
blob is committed. The pinned `[dev-dependencies]` are the single source of truth
for producer identity; the `crate@version` labels below change only with a
reviewed dependency bump. This directory holds no committed fixtures; it exists to
register the producer/consumer set and its provenance.

## Producer / consumer registry

| Label | Crate / tool | Version | Independent of arca? | What | Generation |
|-------|--------------|---------|----------------------|------|------------|
| `arca` | `libarchive_oxide` | workspace | no (self / system under test) | ustar via `ArchiveWriter::with_format_and_limits(_, FormatId::Tar, _)` | in-code |
| `tar@0.4` | `tar` | 0.4.x | yes | ustar via `tar::Builder` / `tar::Header::new_ustar` | in-code |
| `raw-ustar-builder` | first-party bytes in `tests/interop_tar_meta.rs` | n/a | yes (hand-written 512-byte ustar headers with a computed checksum, no shared code with arca or the `tar` crate) | in-code |
| `arca` (consumer) | `libarchive_oxide` | workspace | no (self) | sequential `ArchiveReader` via `read_seq_with_arca` / `read_meta_seq_with_arca` | in-code |
| `tar@0.4` (consumer) | `tar` | 0.4.x | yes | `tar::Archive` entries | in-code |

## Metadata coverage this slice

Content interop is proven 3 producers × 2 consumers over a file / directory /
nested-file / empty-file corpus. Metadata fidelity asserts, through arca's
`MetaShape`, that mode (`0o640`), uid/gid, mtime, and a symlink target survive
both arca's own writer and the independent `tar` crate. GNU long names, PAX
extensions, xattr/ACL, and GNU sparse are covered at the codec layer by
`libarchive_oxide-core/tests/protocol_v2.rs`
(`tar_decoder_types_pax_metadata_and_materializes_sparse_holes`).

## Spec reference

POSIX.1-2017 `pax` / ustar (IEEE Std 1003.1); GNU tar manual for the GNU longname
(`L`) and longlink (`K`) extensions.

## License / origin

Generated content is synthetic and authored for this repository; no third-party
payloads are embedded. REUSE is covered by the repo-wide `REUSE.toml`
(`path = ["**/tests/fixtures/**"]`), so no `.license` sidecar is required.

## External-tool escape hatch

Not used for tar: the `tar` crate is a pinned pure-Rust dev-dependency, so the
deterministic in-code default applies. If a future case needs a byte-exact
system-`tar` artifact, commit it under `tests/fixtures/tar/<producer>/<case>.tar`
and record the tool name, exact version, exact command line, capture date,
SHA-256, and upstream license here, regenerable byte-for-byte.
