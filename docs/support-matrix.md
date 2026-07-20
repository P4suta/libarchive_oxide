# Support matrix

This document describes the current implementation. “Planned” never means
“supported”, and a format name alone does not imply every method, encryption
scheme, metadata field, or producer quirk is accepted.

## Archive containers

| Container | Access | Read | Write | Metadata and method notes |
|---|---|---|---|---|
| tar | sequential | v7, ustar, pax, GNU | yes | pax extensions and GNU sparse; known-size entry creation |
| cpio | sequential | binary little/big endian, odc, newc, crc | yes | known-size entry creation |
| ar | sequential | GNU and BSD | yes | thin members are reported as external references and are never materialized automatically |
| ZIP/ZIP64 | seek or streaming | Store and Deflate | yes | descriptors, ZIP64, Unicode/timestamp extras, optional WinZip AES-256 AE-2; unknown extras are preserved |
| 7z | seek | LZMA/LZMA2, encoded headers, solid single-folder archives | yes | optional `sevenz`; multiple folders and general coder graphs are unsupported |
| ISO 9660 | seek | ISO 9660, Rock Ridge, Joliet | yes | UDF and continuation-area coverage are not complete |

ZIP compression methods Deflate64, BZip2, LZMA, and Zstandard are not yet
implemented. Traditional ZipCrypto is not enabled by default. 7z BCJ/Delta,
Deflate, BZip2, Zstandard, PPMd, AES, multi-folder, and arbitrary coder-graph
coverage remain roadmap work.

RAR5, CAB, XAR, and UDF are not currently implemented. They are read-only
targets for the Modern Archive Profile.

## Outer compression filters

| Filter | Decode | Encode | Dependency profile today |
|---|:---:|:---:|---|
| gzip/DEFLATE | yes | yes | portable `miniz_oxide`; native libz |
| bzip2 | yes | yes | portable `libbz2-rs-sys`; native libbz2 |
| zstd | yes | yes | portable `ruzstd`; native libzstd |
| xz/LZMA2 | yes | yes | portable `lzma-rust2`; native liblzma |
| LZ4 frame | yes | yes | portable `lz4_flex`; native liblz4 |

`portable-codecs` is the dependency-verified default. `native-codecs` is an
explicit `--no-default-features` profile, and selecting both fails compilation.
Profile-less individual codec features remain portable. Sync, Pipeline,
futures-io, Tokio, create, and CLI paths share the same conformance and
malformed corpus; see [codec profile evidence](codec-profiles.md).

## Filesystem restoration

Extraction is rooted in a `cap-std` directory capability. The default policy
rejects path traversal, pre-existing destinations, links, and special files,
and regular files are committed from a `create_new` temporary sibling.

Restoration fidelity varies by platform. Unix mode, ownership, timestamps,
xattrs, ACLs, sparse extents, symlinks, and hardlinks must be evaluated through
the extraction policy and report; unsupported restoration is reported rather
than counted as full format support. Linux is the planned reference adapter.

## Profiles

OCI layers, Debian packages, RPM payloads, and ZIP-based package families are
validation profiles built from the primitives above. A profile is only marked
supported when its container, codec, metadata, security, and interoperability
tests all pass. Registry communication and authentication are outside the OCI
layer-engine scope.
