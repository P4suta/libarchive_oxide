<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# ADR 0019: CAB Quantum uses bounded `compcol` folder state

- Status: Accepted
- Date: 2026-07-29

## Context

CAB method 2 stores the Quantum window exponent and compression level in
`CFFOLDER::typeCompress`, while decoded length and block boundaries live only
in the surrounding CFDATA records. The dictionary and nine adaptive arithmetic
models persist for a complete folder. Every non-final block used in practice
emits 32 KiB; the consumer injects a `0xFF` after each compressed payload so
the decoder can skip up to four alignment zeros at a full-frame boundary.

There is no public Quantum encoder. The available interoperability evidence is
therefore the libmspack/cabextract regression corpus and its published decoded
output. A correct adapter must remain incremental, preserve folder state, stop
at the container-declared size, reject short interior frames, and account for
both the codec's copied input and its attacker-selected dictionary.

`compcol` 0.3.1 was compatible with the former Rust 1.87 flagship floor, but
used unsigned frame accounting: a match that crossed a 32 KiB boundary could
wrap the remaining count and desynchronize the stream. Version 0.6.8 contains
the signed frame-overshoot fix and requires Rust 1.88.

## Decision

The additive `cab-quantum` feature depends exactly on safe-Rust, `no_std +
alloc` `compcol` 0.6.8 with only its `quantum` feature. Both
`portable-codecs` and `native-codecs` include it; disabling it leaves CAB
metadata listable and produces a typed `Unsupported` error on payload access.
The workspace MSRV moves from Rust 1.87 to 1.88. Core and portable codecs
remain `no_std + alloc`, but use the same workspace-wide compiler floor.

Before construction, the CAB adapter validates Quantum levels `1..=7`, window
exponents `10..=21`, reserved bits, all CFDATA extents, the full-frame rule for
non-final blocks, aggregate scan work, decoded output, codec memory, and
in-flight staging. Codec memory charges the selected dictionary plus a
conservative 80 KiB bound for the retained compressed-input allocation,
arithmetic state/snapshots, and bookkeeping. In-flight accounting includes the
adapter payload, `compcol`'s copied framed input, decoded block, and later event
copy.

Each payload receives one synthetic `0xFF` trailer and is pushed into the same
decoder. Arithmetic lookahead may delay a frame's final bytes until the next
payload arrives, so the adapter tracks the folder-wide declared-but-not-yet-
emitted count instead of demanding per-call equality. At the final payload it
permits `compcol`'s single bounded EOF-padding step only while declared bytes
remain; failing to reach that count is malformed. Once the CAB-declared output
length is reached, the adapter stops without probing for an in-band end marker
that Quantum does not have.

## Consequences

- The 379-byte mixed-method libmspack fixture decodes its Quantum member
  byte-for-byte.
- The 285-byte, 16-CFDATA `cve-2010-2801-qtm-flush.cab` fixture proves
  dictionary/model persistence over 524,159 decoded bytes.
- Truncation, checksum corruption, invalid settings, short interior frames,
  scan amplification, and every relevant resource limit have regressions.
- Quantum writing remains absent because no independently implemented encoder
  or writer interoperability evidence exists.
- This codec decision did not imply cross-cabinet folder resolution; the later
  explicit `VolumeSet` design is recorded in ADR-0021.
