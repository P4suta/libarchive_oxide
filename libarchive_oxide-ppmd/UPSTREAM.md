<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: Apache-2.0
-->

# Implementation provenance

The index-based Safe Rust PPMd-H model is derived from the original Apache-2.0 Java implementation `app/src/main/java/com/readwide/manager/archive/RarPpmdVarHDecoder.java` in [Readwide](https://github.com/k1717/Readwide) commit `42232449603253bd25edd4ba55b5544c24855bcd` (2026-08-15).
The audited Java file's SHA-256 is `28c6a53350a635014988ab50ef07b1ead2d9b42a3216dd5154d7b55d00cbb779`.
The applicable first-party attribution from Readwide's root `NOTICE` is preserved in this crate's packaged `NOTICE`; unrelated Readwide third-party product notices are not applicable to this derivative.

That implementation documents a clean-room port of Dmitry Shkarin's public-domain PPMd variant H / Igor Pavlov's public-domain Ppmd7 algorithm.
It contains no RARLAB UnRAR or libarchive source.
This Rust port retains the flat-byte-heap and integer offset design, replaces Java exceptions with typed errors, and separates the RAR range decoder from the reusable statistical model.

The RAR carryless range-coder behavior was cross-checked against libarchive's BSD-2-Clause `archive_ppmd7.c`; no libarchive source is copied here.
No UnRAR,
GPL, C, or FFI implementation is copied or linked.
