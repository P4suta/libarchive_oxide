<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# ADR 0018: CAB LZX uses an audited chunk-framed decoder fork

- Status: Accepted
- Date: 2026-07-29

## Context

CAB LZX keeps dictionary, recent-offset, Huffman-tree, and E8 state across a
folder, but each CFDATA chunk is independently aligned to a 16-bit word at its
32 KiB output boundary. A decoder must therefore preserve semantic history
while replacing its bitstream reader for every CFDATA payload.

The initially evaluated `compcol` 0.3.1 met the workspace MSRV and safe-Rust
requirements, but its public streaming decoder treats all input as one
continuous bitstream and exposes no frame-boundary/re-alignment operation.
Microsoft `makecab.exe` produced a three-CFDATA fixture that decoded the first
32 KiB correctly and then lost 80 bytes because padding was interpreted as the
next frame. The same decoder architecture remains in `compcol` 0.6.8. The
flagship later adopted that release and Rust 1.88 for Quantum (ADR-0019), but
the missing CAB LZX chunk-realignment API remains unchanged.

The upstream `lzxd` 0.2.7 state machine has the required split: every
`decompress_next(chunk, output_len)` creates a new bitstream while retaining
folder history. Its crates.io release, however, contained production
assertions and infallible allocations at an attacker-controlled decode
boundary. Although the upstream project implements LZX DELTA, CAB method 3
uses regular LZX; exposing the delta name without reference-data and extended
match support would overstate this crate's public capability.

## Decision

`libarchive_oxide-codecs::lzx::LzxDecoder` is an explicit, attributed regular-
LZX fork of `lzxd` 0.2.7. It is `no_std + alloc`, forbids unsafe code at the
crate root, converts production assertions/zero progress/overruns and
allocation failures to typed errors, validates available history and
independently encoded tree ranges, uses checked narrowing and shift-width-safe
bit masks, and publishes a conservative non-window workspace bound. Odd
uncompressed-block padding is consumed before its CFDATA bitstream is released.
Exact
upstream commit, source hashes, license, and local changes are recorded in
`libarchive_oxide-codecs/src/lzx/UPSTREAM.md`.

The `cab-lzx` feature uses this fork. Before decoder construction the CAB
adapter validates the `15..=21` window exponent and charges the selected window
plus the audited workspace bound to `Limits::codec_memory`. It bounds aggregate
CFDATA pre-scan work by the cabinet extent, validates decoded-total and
in-flight limits before allocation, verifies nonzero CFDATA checksums, then
decodes one payload at a time without materializing the folder. Folder switches
drop the prior codec before allocating the next dictionary.

`compcol` is not the production CAB LZX decoder. Version 0.6.8 is now a
production dependency only for CAB Quantum and remains a development oracle
for BCJ2.

## Consequences

- Microsoft makecab multi-frame/history output and the libmspack mixed-method
  corpus decode byte-for-byte.
- Truncation, corrupt frame declarations, invalid windows, zero progress,
  chunk overrun, allocation failure, and resource-limit violations are typed
  failures rather than panics.
- The fork creates a maintenance obligation: upstream changes must be reviewed
  and imported deliberately, with source hashes and differential fixtures
  updated together.
- Quantum is resolved independently by ADR-0019. This codec decision did not
  imply cross-cabinet resolution; the later explicit `VolumeSet` design is
  recorded in ADR-0021.
