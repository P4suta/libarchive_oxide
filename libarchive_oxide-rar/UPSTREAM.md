<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# RAR codec provenance

## RAR3 decoder base

`src/rar3/{bits,decoder,huffman,tables}.rs` are derived from the MIT-licensed `compcol` 0.6.8 RAR3 implementation by Karpeles Lab Inc.
The crates.io archive checksum pinned by `Cargo.lock` is `28b37ce533aa0fddc1e6820e331968ba72aa48b5c8bbb2bebdc03d48b6ed0f16`.
The imported source files had these SHA-256 values:

- `bits.rs`: `946e42443d99905309efab9741dab3cd245515b23630e89da0d0426c70a0cc94`
- `decoder.rs`: `72b908ee509ee5021cb8f10942b644d1dfe498c86f4621296ed1004c22d66d61`
- the originally imported `filters.rs`, since removed in favor of the isolated standard-filter crate: `25617585d31821faab9ae988a7505b58f1858c8bbc9114d4f27c39e73f34aed5`
- `huffman.rs`: `62d86b30266b81e1b732b0b30ca8a9d2e9d006fb188818e0b613159a656d0d4c`
- `tables.rs`: `01a6f58224ee693b69097d2c9cbd0ce2196f47c05ab52491aa71ea3a1c4a0de4`

Local changes remove the generic algorithm/encoder surface, narrow visibility,
bridge the concrete decoder through the crate-private static protocol, and retain exact output and memory accounting in the shared RAR adapter.
Local solid continuation retains the completed dictionary, Huffman lengths and tables, LZ distance history, and standard-filter program table while resetting member-local bit input, output, and pending invocations.
It is validated against a nine-member external RAR4 corpus; no UnRAR implementation source is copied or linked.
No RAR encoder or GPL implementation is included.

RAR3 PPMd-H/PPMd-II decoding composes the dependency-free Safe Rust `libarchive_oxide-ppmd` crate.
Its separate `UPSTREAM.md` records the Apache-2.0 derivative source, exact commit and hash, public-domain algorithm lineage, and BSD libarchive cross-check.
The RAR crate owns only block framing,
escape commands, shared output-window integration, limits, and typed error mapping; it retains the concrete model without dynamic dispatch for solid continuation.

## RAR3 standard VM filters

Descriptor parsing, the five standard-program fingerprints, and the Delta,
E8/E8E9, RGB, and Audio transforms are isolated in the dependency-free Safe Rust `libarchive_oxide-rarvm` crate.
Its BSD-2-Clause `UPSTREAM.md` and `NOTICE` pin libarchive commit `44cbcfc560c487020da31d0fb82f0e2395fd90fd` and preserve the required notices.
The RAR crate owns only compressed-stream framing, member-relative scheduling, bounded queue integration, and typed error mapping.
Unknown bytecode is validated but never interpreted.

## RAR5 decoder base

`src/rar5/{bits,decoder,huffman}.rs` and the x86 portion of `filters.rs` are derived from the MIT-licensed `compcol` 0.6.8 RAR5 implementation by Karpeles Lab Inc.
The crates.io archive checksum pinned by `Cargo.lock` is `28b37ce533aa0fddc1e6820e331968ba72aa48b5c8bbb2bebdc03d48b6ed0f16`.
The imported source files had these SHA-256 values:

- `bits.rs`: `dfc5237b366605adf61fefc60d0f02e006f66813de01fceb76507f724747acf7`
- `decoder.rs`: `026ea496c21e87b797924c9bc432adbfb61257193cbd1d0524329f917600870c`
- `filters.rs`: `21950cfc8b6615b663a8d5b1fe1dd84c455130ba235d661911411f1a5f45da9d`
- `huffman.rs`: `9ce5c7b16d4a124b8bd33af5565cc0de175204d9128857141c78f085bc1593a5`

Local changes narrow visibility, bridge the concrete decoder through static dispatch, replace narrowing casts with checked conversions, bound pending filter descriptors, consume at most one self-described compressed block per call, reject filters that reach into emitted output, and account for all filter scratch in the caller's codec-memory budget.
No RAR encoder is present.

## RAR7 generation 1

The generation-1 extension was implemented independently from RARLAB's public `unrar7notes.htm` algorithm notes: its distance alphabet grows from 64 to 80 symbols, the combined Huffman table grows by the same 16 entries, and exact non-power-of-two dictionaries require modulo-equivalent wrap operations.
The codec retains distances in `u64`, validates the concrete dictionary before allocation, and uses checked address-space conversion at the public boundary.
No UnRAR source was copied or linked.

The complete generation-1 integration fixture was produced by the separately executed `rars-cli` 0.7.0 revision `89f825239c17a85b8cb6aad6b0fe0d9e294805d1` and independently decoded by 7-Zip 26.02.
That project was used only as an external corpus producer and oracle; none of its implementation source is included or used as this codec's source.
Exact fixture commands, digests, and results are recorded in `libarchive_oxide/tests/fixtures/rar5/PROVENANCE.md`.

## Delta and ARM filters

The Delta and ARM decode transforms were independently implemented and cross-checked against RARLAB's public RAR 5.0 technote and libarchive 3.8.8's BSD-2-Clause `archive_read_support_format_rar5.c` (`run_delta_filter` and `run_arm_filter`).
No UnRAR-licensed or GPL implementation is included or used as source.
