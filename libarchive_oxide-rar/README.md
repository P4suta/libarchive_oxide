<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# libarchive_oxide-rar

Safe Rust, no_std + alloc, read-only RAR payload codecs for libarchive_oxide.

This crate is deliberately separate from archive-container parsing and from the generic portable-codec collection.
It depends on the lower-layer libarchive_oxide-protocol interface and the dependency-free libarchive_oxide-ppmd and BSD-2-Clause libarchive_oxide-rarvm primitives.
The RAR3 and RAR5 decoders are owned here under recorded provenance and share a crate-private, static-dispatch protocol, so format-specific dictionaries, filters, and limits can evolve independently without depending on a generic codec collection.
RAR container framing remains in libarchive_oxide-core; the flagship crate joins both sides through a static associated-type provider.

RAR writing is permanently out of scope because of the format's licensing constraints.
The current decoder covers bounded RAR3 LZ77/Huffman,
PPMd-H/PPMd-II, all five standard RAR3 VM filters, and RAR5 generation-0 LZ77/Huffman payloads including x86 E8/E9, Delta, and ARM filters.
RAR3 retains either concrete LZ dictionary/Huffman/distance state or its concrete PPMd model, plus its output window and standard-program table,
across sequential solid members.
RAR5 retains its concrete LZ state.
Dictionaries, PPMd heaps, compressed blocks, filter descriptors/scratch, decoded output, and whole-payload legacy buffers are bounded before or during allocation.
Standard filters are selected by validated length/CRC fingerprints and a closed enum; arbitrary VM bytecode is never interpreted and remains a typed unsupported error, as do unsupported generations and methods.

See [UPSTREAM.md](UPSTREAM.md) for imported-source hashes and the independent algorithm references used for local changes.
