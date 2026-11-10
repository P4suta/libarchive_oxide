# Vendored `deflate64`

- Upstream: <https://github.com/anatawa12/deflate64-rs>
- Crate: `deflate64` 0.1.12
- crates.io checksum: `ac6b926516df9c60bfa16e107b21086399f8285a44ca9711344b9e553c5146e2`
- License: MIT (see `LICENSE`)

The source is compiled as a private module of `libarchive_oxide`; it is not a public compatibility fork.
Relative imports were adapted for that nesting, the unused `Read` wrapper was excluded, and the upstream checkpoint machinery was made unconditional.
Two upstream spelling-only typos were corrected without changing behavior.
The local inflater accessor exposes only the byte-rounded latest safe checkpoint so the forward-only ZIP reader can leave Huffman look-ahead bytes uncommitted for a following data descriptor.
