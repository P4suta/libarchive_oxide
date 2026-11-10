<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: BSD-2-Clause
-->

# libarchive_oxide-rarvm

Bounded, `no_std` Safe-Rust parsing and allocation-free execution of the standard RAR3 VM filters used by `libarchive_oxide-rar`.
The finite program table uses `alloc`; filter execution uses only caller-owned blocks and scratch.
This internal codec crate performs no container parsing, I/O, path handling,
password lookup, arbitrary VM instruction interpretation, or archive writing.

See [UPSTREAM.md](UPSTREAM.md) for the separated BSD-2-Clause provenance and interoperability fixture hashes.
