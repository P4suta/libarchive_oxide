# libarchive_oxide-codecs

`no_std + alloc` portable compression state machines for [`libarchive_oxide`](https://github.com/P4suta/libarchive_oxide).

The crate exposes caller-driven codecs over `libarchive_oxide-protocol::Codec`.
It does not depend on archive format core;
`libarchive_oxide-core` re-exports the same protocol types for compatibility.
It intentionally contains no filesystem, blocking I/O, worker thread, async runtime, or native-library adapter.

MSRV: Rust 1.95.

The always-available Base64 and uuencode modules provide bounded, caller-driven ASCII armor.
Uuencode decodes one strictly framed POSIX member with compatible space/backtick zero symbols and LF/CRLF lines, and writes canonical libarchive-compatible 45-byte data lines.
Both directions enforce decoded or plaintext limits; uuencode also preflights its fixed line workspace.
The optional `lzo` feature adds strict lzop framing, a fuzz-hardened Safe Rust LZO1X decoder, and a deterministic stored-block writer.
The always-available RPM module removes the fixed lead and bounded signature and main headers without retaining header bodies, then emits the package payload for a following compression and cpio decoder.

The optional `lzw` feature exposes bounded, incremental decoding and encoding for Unix `compress(1)` / `.Z` streams.
It rejects reserved header bits,
enforces fixed decoder and encoder workspaces before allocation, caps decoded or plaintext input through `libarchive_oxide-protocol::Limits`, and uses the safe Rust `compcol` state machines for the LZW algorithm.

Format-specific RAR payload algorithms are intentionally isolated in the sibling `libarchive_oxide-rar` crate rather than exposed as a feature here.

The optional `lha` feature exposes bounded read-only `-lh2-` and `-lh3-` payload adapters.
LHA headers, metadata, CRC16, and source I/O remain in the flagship crate.
The codecs preflight their complete packed input and decoded output, the caller's fixed input window, 8 KiB dictionary, adaptive or canonical trees, and conservative vector growth before allocation.
The flagship dispatches these two built-ins through a private enum, so this hot path has no trait-object allocation or vtable.
There is no LHA writer; the checked-in LH2/LH3 vectors are explicitly not independent producer evidence.

The optional `lzx` feature exposes a bounded, incremental regular-LZX decoder used by the CAB reader.
It is an audited fork of `lzxd` 0.2.7: allocation failure, malformed bitstreams, invalid offsets, and arithmetic overflow are returned as typed errors, while the caller controls CAB's per-CFDATA bitstream boundaries.
LZX DELTA reference data and extended match lengths are deliberately outside this API.
The exact upstream revision, source hashes, and local-change record live in `src/lzx/UPSTREAM.md`.

Licensed under either MIT or Apache-2.0, at your option.
