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

## Compile-time providers

| Surface | Built-in compatibility | Downstream registration |
|---|---|---|
| format read | unchanged | sequential alternative `FormatProvider` |
| format write | unchanged | `ProviderArchiveWriter` / `create_registered` |
| outer codec read/write | unchanged | bounded alternative `CodecProvider` frames |
| engine events/inspect/plan/apply | unchanged | same concrete chain survives rewind |
| capability query | available/disabled/unknown | available/disabled/unknown |

Registration is static generic composition: there is no trait-object registry,
global mutable registration, dynamic library loading, or plugin ABI. Invalid
probe/progress contracts and ambiguous different-ID matches fail with typed
errors. External seek-native providers are not currently supported. See the
[provider contract and evidence](providers.md).

## Filesystem restoration

`ArchiveSession::apply_with_adapter` drives a compile-time `FilesystemAdapter`
after session identity, path normalization, policy, resource-limit, and
hardlink-order checks. Existing `apply(plan, cap_std::fs::Dir)` creates the
standard adapter. Every requested entry/metadata operation has an applied,
unsupported, refused, partial, or OS-error finding in `ApplyReport`; omitted
evidence is converted to `Partial`.

| Operation | Standard portable path | Linux reference path |
|---|---|---|
| regular file | temporary-sibling atomic publish | same, metadata applied by open descriptor |
| directory | no-follow creation/finalization | same |
| mode | Unix targets | yes |
| access/modification time | yes | yes, descriptor-based |
| numeric uid/gid | reported unsupported | yes; permission errors remain typed |
| xattr | reported unsupported | yes |
| POSIX ACL | reported unsupported | numeric access/default ACL text |
| sparse extents | Unix targets; Windows reported unsupported | logical and allocated-block evidence tested |
| symlink/hardlink | explicit policy only | explicit policy only |
| FIFO/socket/device | reported unsupported | explicit policy only |
| change/birth time, filesystem flags | reported unsupported | reported unsupported |

The default policy still rejects traversal, pre-existing destinations, links,
and special files. Commit failure removes the sibling without publishing an
invalid destination. See [the filesystem adapter contract](filesystem-adapters.md).

## Command-line surface

| Surface | Implemented contract | Bounded/atomic behavior |
|---|---|---|
| `oxarchive inspect` | human events or schema-versioned JSON Lines | streams `ReaderEvent`; no collected entry list; completion sentinel |
| `oxarchive plan` | human or advisory JSON | finite entry/metadata limits; never reusable apply input |
| `oxarchive apply` | human or JSON outcomes plus filesystem findings | same immutable session; per-file atomic commit |
| `oxarchive create` | tar/cpio/ar/zip; optional gzip/bzip2/xz/zstd/lz4 | common `CreateOptions`; 64 KiB copy buffer; file output staged and no-replace published |
| `oxarchive verify` | human or JSON digest/count result | streams payload events with checked counters |
| `oxtar`, `oxcpio`, `oxcat`, `oxunzip` | documented compatibility subsets | shared exit 0/1/2, stdout/stderr, limits, and safe extraction contracts |

`create ARCHIVE=-` reserves stdout for archive bytes and can leave a partial
prefix on a late exit-1 failure. JSON inspection records already flushed remain
valid after a late parser error, but only `inspect_complete` marks success. See
the [CLI and streaming-output contract](cli-contract.md) and
[ADR-0008](adr/0008-bounded-cli-streams.md).

## Profiles

OCI layers, Debian packages, RPM payloads, and ZIP-based package families are
validation profiles built from the primitives above. A profile is only marked
supported when its container, codec, metadata, security, and interoperability
tests all pass. Registry communication and authentication are outside the OCI
layer-engine scope.
