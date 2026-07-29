# Fuzzing

This excluded Cargo workspace contains libFuzzer targets. It requires nightly
Rust and a sanitizer runtime.

## Layout

| Path | Purpose |
|---|---|
| `fuzz_lib` | portable invariant functions |
| `fuzz_targets` | `cargo-fuzz` entry points |
| `corpus` | committed seeds |

The 27 libFuzzer targets cover sequential and seek archive readers (including explicit
raw and malformed/valid synthesized WARC decoding in the reused `read_tar`
target and corpus, plus CAB, XAR, and UDF Metadata/Sparable/Virtual/VAT partitions), archive round trips,
outer/internal codecs (including bounded Unix `compress(1)` LZW), safe-extraction policy
planning, and bounded RPM, Alpine, ZIP-ecosystem, APK, IPA, and MSIX package
verification. The Alpine target supplies a fixed official public key so
mutations traverse exact compressed-member hashing and RSA verification rather
than stopping at signature detection. The app target recognizes direct ZIP
input by package metadata and includes official AOSP RSA v2/v3 plus Microsoft
MSIX SDK seeds. A dedicated selector applies bounded offset/XOR mutations to
the official CTS v4.0 APK/`.idsig` pair, while a length-prefixed envelope lets
libFuzzer vary both inputs independently. APK Signing Block parsing,
certificate and detached-sidecar signatures, v2/v3/v4 binding, chunked content
digests, the APK-wide Merkle tree, and bounded `AppxBlockMap.xml` 64-KiB block
hashing therefore remain mutation-reachable.

Stable corpus replay adds one portable LZIP decoder case (`codec_lzip`) without
adding a `cargo-fuzz` target. This keeps LZIP regression coverage available on
stable Rust while its worker bridge remains outside the libFuzzer campaign.

## Commands

```sh
cd fuzz
cargo +nightly-2026-07-29 fuzz build
cargo +nightly-2026-07-29 fuzz run read_tar
cargo +nightly-2026-07-29 fuzz run read_zip -- -max_total_time=30
cargo +nightly-2026-07-29 fuzz run read_udf -- -max_total_time=30
cargo +nightly-2026-07-29 fuzz run package_app -- -max_total_time=30
```

Portable replay:

```sh
cargo test -p libarchive_oxide --test fuzz_replay
```

CI builds every target, performs bounded fuzz runs, and replays corpus seeds and
deterministic mutations through `fuzz_lib`.

The existing `read_cab` target also recognizes a versioned multi-volume
envelope (`OXCV 01`, one-byte count, then repeated little-endian `u32` length
and volume bytes). Inputs without a complete envelope retain the ordinary
single-CAB path.

## Resource policy

The shared harness uses finite limits even when a malformed input declares huge
sizes: 128 MiB decoded data per archive/entry, 200,000 entries, 8 MiB metadata,
the default 64 MiB codec-memory ceiling, and 256 KiB in-flight buffering.
Round-trip synthesis is smaller still: at most 48 entries, 40-byte names, and
4 KiB bodies. The extraction target bounds names to 96 bytes, bodies to 512
bytes, memory spooling to 64 KiB, and total spooling to 2 MiB. Each input also
generates a bounded second spelling that exercises case, trailing-dot,
trailing-space, or NFC/NFD destination identity preflight.

OSS-Fuzz additionally caps generated inputs at 2 MiB, process RSS at 2 GiB
(allowing for AddressSanitizer overhead), and one input at 25 seconds. See
[`corpus/PROVENANCE.md`](corpus/PROVENANCE.md) for seed origin and licensing.

## OSS-Fuzz

The proposed upstream OSS-Fuzz project bundle lives in
[`../oss-fuzz`](../oss-fuzz/README.md). It builds all 27 targets with the
portable, self-contained codec profile under libFuzzer + AddressSanitizer and
packages every committed seed directory. It complements rather than replaces
the stable replay and the short portable/native GitHub nightly campaign.
