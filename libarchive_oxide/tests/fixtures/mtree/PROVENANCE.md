# mtree fixture provenance

The stable mtree integration fixtures are short textual manifests embedded in `libarchive_oxide/tests/mtree.rs`.
They are first-party conformance cases written from the public FreeBSD `mtree(5)` grammar and contain no third-party payload or copied implementation source.

The differential test also generates one manifest at test time with the system `bsdtar` when `tar --version` identifies libarchive's bsdtar.
It uses:

```text
tar --format=mtree -cf - -C <temporary-directory> "seed file.txt"
```

The same test sends a manifest produced by `MtreeEncoder` to `bsdtar -tf -`.
The test was established against bsdtar 3.8.4 (libarchive 3.8.4) on Windows.
Systems without bsdtar skip only this external interoperability check; all first-party parser, writer, boundary, and limit tests still run.

The fuzz seed `fuzz/corpus/read_tar/mtree-v2.txt` is a first-party minimal v2 manifest derived from the same public grammar.
It is covered by the repository `REUSE.toml` first-party corpus override (`MIT OR Apache-2.0`).

References:

- FreeBSD `mtree(5)`: <https://man.freebsd.org/cgi/man.cgi?query=mtree&sektion=5>
- libarchive: <https://github.com/libarchive/libarchive>
