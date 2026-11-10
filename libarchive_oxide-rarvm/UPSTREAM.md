<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: BSD-2-Clause
-->

# RAR3 VM codec provenance

The RAR3 descriptor grammar, five standard-program fingerprints, and Delta,
E8/E8E9, RGB, and Audio transforms were derived from and cross-checked against libarchive's BSD-2-Clause `libarchive/archive_read_support_format_rar.c` at commit `44cbcfc560c487020da31d0fb82f0e2395fd90fd` (2026-08-16).
The relevant upstream functions are `parse_filter`, `compile_program`, `membr_next_rarvm_number`, and the five `execute_filter_*` routines.
The required upstream copyright notice is preserved in `NOTICE`.

This crate uses an independently structured Safe-Rust implementation with checked slice access and caller-owned scratch.
It recognizes standard programs only after XOR, length, and CRC32 validation and dispatches them through a closed enum.
It does not copy or interpret arbitrary VM instructions, contain UnRAR-licensed/GPL code, or provide a RAR writer.

The integration oracle is libarchive's BSD-2-Clause `test_read_format_rar_filter.rar.uu` from the same commit.
Its decoded RAR has SHA-256 `b058412adcd3329a868cb66561a224eb0acf22ad2d380ef5d9e17e432a47d6a8`;
the 204,288-byte output has SHA-256 `a961532b3a196e0b2c0126ad6f35d511c9fdfeadacbe78a1b15dc221251ad9a2`.
