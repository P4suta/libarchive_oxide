# libarchive_oxide-codecs

`no_std + alloc` portable compression state machines for
[`libarchive_oxide`](https://github.com/P4suta/libarchive_oxide).

The crate exposes caller-driven codecs over `libarchive_oxide-core::Codec`.
It intentionally contains no filesystem, blocking I/O, worker thread, async
runtime, or native-library adapter.

MSRV: Rust 1.88.

The optional `lzw` feature exposes a bounded, incremental decoder for Unix
`compress(1)` / `.Z` streams. It rejects reserved header bits, enforces the
fixed dictionary workspace before allocation, caps decoded output through
`libarchive_oxide-core::Limits`, and uses the safe Rust `compcol` state machine
for the LZW algorithm.

The optional `lzx` feature exposes a bounded, incremental regular-LZX decoder
used by the CAB reader. It is an audited fork of `lzxd` 0.2.7: allocation
failure, malformed bitstreams, invalid offsets, and arithmetic overflow are
returned as typed errors, while the caller controls CAB's per-CFDATA bitstream
boundaries. LZX DELTA reference data and extended match lengths are deliberately
outside this API. The exact upstream revision, source hashes, and local-change
record live in `src/lzx/UPSTREAM.md`.

Licensed under either MIT or Apache-2.0, at your option.
