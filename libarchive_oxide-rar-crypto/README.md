<!-- SPDX-FileCopyrightText: 2026 libarchive_oxide contributors -->
<!-- SPDX-License-Identifier: ISC -->

# libarchive_oxide-rar-crypto

Bounded, `no_std`, Safe-Rust cryptographic primitives used by the read-only RAR implementation in `libarchive_oxide`.

This crate does not implement RAR archive writing and does not contain an UnRAR-derived decompressor.
Its RAR3 password conversion and SHA-1 compatibility behavior follow the independently maintained ISC-licensed `rarfile` implementation.
RAR5 AES-256-CBC, PBKDF2-HMAC-SHA256 password checks, and HMAC-tweaked checksums follow RARLAB's public format note and are covered by independent cryptographic vectors.
See `NOTICE` for provenance.
