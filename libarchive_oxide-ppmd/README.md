<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# libarchive_oxide-ppmd

Safe Rust, `no_std + alloc` PPMd building blocks for archive codecs.

The crate deliberately separates the PPMd-H statistical model from archive-specific range coding and framing.
It currently exposes the carryless range decoder used by RAR 3.x/4.x.
It does not contain archive parsing, encryption, or an encoder.

No trait objects, C code, FFI, or `unsafe` Rust are used.
