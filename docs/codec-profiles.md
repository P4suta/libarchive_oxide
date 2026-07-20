# Codec profiles

`libarchive_oxide` has two mutually exclusive compile-time backend profiles.

| Profile | Invocation | gzip | bzip2 | zstd | xz/LZMA2 | LZ4 frame |
|---|---|---|---|---|---|---|
| portable (default) | `cargo build` | `miniz_oxide` | `libbz2-rs-sys` | `ruzstd` | `lzma-rust2` | `lz4_flex` |
| native | `cargo build --no-default-features --features native-codecs` | `libz-sys` | `bzip2-sys` | `zstd-sys` | `xz2` / `lzma-sys` | `lz4` / `lz4-sys` |

The individual codec features remain available. For example,
`--no-default-features --features zstd` is a compatibility portable build.
`portable-codecs,native-codecs` is an intentional compile failure, so maximal
validation uses two commands rather than `--all-features`.

## Shared conformance

Both profiles run the same sync, Pipeline, futures-io, Tokio, create, CLI,
malformed-input, and fuzz-replay tests. The committed corpus covers all five
outer filters, including one-byte input boundaries, concatenated members,
trailing data, truncation, checksum failure, no-progress handling, decoded
output limits, XZ dictionary/index allocation limits, and independent producer
or consumer fixtures. Nightly CI builds and runs all 17 libFuzzer targets under
both profiles with overflow checks and panic-abort semantics.

The portable dependency gate inspects normal and build edges and rejects
`libz-sys`, `libz-ng-sys`, `bzip2-sys`, `zstd`, `zstd-safe`, `zstd-sys`,
`xz2`, `lzma-sys`, `lz4`, and `lz4-sys`. The native gate requires `libz-sys`,
`bzip2-sys`, `zstd-sys`, `lzma-sys`, and `lz4-sys`.

## Reproducible comparison

Run the bounded streaming probe with either profile:

```sh
cargo run --release -p libarchive_oxide --example codec_profile_probe \
  --no-default-features --features portable-codecs -- zstd 64
cargo run --release -p libarchive_oxide --example codec_profile_probe \
  --no-default-features --features native-codecs -- zstd 64
```

The probe creates and consumes a filtered tar without retaining the payload.
It reports wall time, compressed size, baseline RSS, peak sampled RSS, and
additional RSS as one JSON record. RSS is sampled every 8 MiB.

The following evidence was measured on 2026-07-20 from the RM-115 working tree
based on main `b7c3843`, Windows 10.0.26200 x86_64, AMD Family 25 Model 80,
Rust 1.97.1, release profile. The 16 MiB payload is a repeated byte stream;
times include periodic PowerShell RSS sampling and are comparison evidence,
not a general-purpose codec microbenchmark.

| Codec | Portable encode/decode ms | Native encode/decode ms | Portable/native bytes | Portable/native additional RSS MiB |
|---|---:|---:|---:|---:|
| gzip | 516 / 476 | 484 / 482 | 16,398 / 16,403 | 1.7 / 0.9 |
| bzip2 | 511 / 440 | 517 / 437 | 125 / 125 | 2.1 / 2.0 |
| zstd | 507 / 417 | 439 / 406 | 3,831 / 4,958 | 1.2 / 1.0 |
| xz | 1,496 / 916 | 1,229 / 450 | 35,976 / 35,976 | 9.7 / 1.0 |
| LZ4 | 423 / 439 | 427 / 408 | 76,672 / 74,359 | 1.2 / 1.0 |

A second 64 MiB run checked RSS scaling. Payload grew by 48 MiB, while the
largest sampled additional RSS remained 10.2 MiB, below the 64 MiB target.

| Codec | Portable additional RSS MiB | Native additional RSS MiB |
|---|---:|---:|
| gzip | 1.0 | 0.9 |
| bzip2 | 5.2 | 5.1 |
| zstd | 1.2 | 1.0 |
| xz | 10.2 | 1.1 |
| LZ4 | 1.7 | 1.3 |

Compressed sizes differ for gzip, zstd, and LZ4 because backend framing and
compression choices differ; bzip2 and xz happened to match for this input.
Cross-profile byte identity is not an API contract. Existing independent
Python bzip2, `zstd`, liblzma/xz2, and liblz4 fixtures and consumers verify the
interoperability contract in both directions where the project emits data.