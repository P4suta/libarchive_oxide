# libarchive_oxide-core

`no_std` + `alloc` sans-IO core for [`libarchive_oxide`](https://github.com/P4suta/libarchive_oxide):
the frozen trait algebra (`Transform` / `Filter` / `Format` / `EntryReader` / `EntryWriter`) and the
uncompressed archive formats. Zero external dependencies.

Most users want the std flagship crate [`libarchive_oxide`](https://crates.io/crates/libarchive_oxide)
instead; depend on this crate directly only for `no_std`/embedded targets or to build on the raw
algebra.

## License

Licensed under either of [MIT](../LICENSES/MIT.txt) or [Apache-2.0](../LICENSES/Apache-2.0.txt) at
your option.
