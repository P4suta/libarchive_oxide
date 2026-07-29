# Android APK Signature Scheme v4 fixture provenance

These files are byte-for-byte Android Open Source Project interoperability
fixtures. They are retained under the upstream Apache-2.0 license and contain
no private signing keys.

## CTS v4.0 pair

`v4-digest-v2v3.apk` and `v4-digest-v2v3.apk.idsig` come from
`platform/cts` commit
`79e7fb0fabd62276c5662b5000ac47ac18f2749f`, under:

`tests/tests/content/data/`

The CTS build file describes these as v4-signed
`android.appsecurity.cts.tinyapp` inputs. The APK carries v2 and v3 signing
blocks; its detached sidecar carries the legacy v4.0 signing-info layout and a
serialized Merkle tree.

## apksig v4.1 pairs

`v31-rsa-2048_2-tgt-10000-dev-release.apk` and its `.idsig` come from
`platform/tools/apksig` commit
`184702d9d18877edf9e5296c4e191cf0aa2b5fbb`, under:

`src/test/resources/com/android/apksig/`

They are a positive reference pair produced and consumed by Google's
`apksig`/`apksigner` implementation. The APK and sidecar exercise the primary
v2/v3 binding plus the v4.1 block bound specifically to the APK's v3.1 signer.

`v41-digest-mismatched-with-v31.apk` and its `.idsig` come from the same
upstream directory at commit
`3030f0111e5d100765efbdb7c7689e8f5b18e499`. AOSP's
`ApkVerifierTest.verify41_v41DigestMismatchedWithV31_reportsError` identifies
this pair as a required failure with
`V4_SIG_V2_V3_DIGESTS_MISMATCH`.

Canonical repositories:

- <https://android.googlesource.com/platform/cts/>
- <https://android.googlesource.com/platform/tools/apksig/>

## Local byte identities

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `v4-digest-v2v3.apk` | 8400 | `36e6594259ce226f1e4597e513e5985dbb94fde23f5aba6b3405656b435be8c4` |
| `v4-digest-v2v3.apk.idsig` | 5816 | `e444deb5b0a3bf6706c479d9d9f8bff7d87116d3391121561cda858e0ed64f0c` |
| `v31-rsa-2048_2-tgt-10000-dev-release.apk` | 16791 | `e9c2fbf63c9d362ca8a1bbcddb0efb40728a2a588fbf60a4e615d6c4bc75697e` |
| `v31-rsa-2048_2-tgt-10000-dev-release.apk.idsig` | 6909 | `ad4e6653171a3b0975ec21b3eabf02887427ab32ad8a16698da6a6bd8da3b769` |
| `v41-digest-mismatched-with-v31.apk` | 16791 | `405d5fbe8cb9778e79828fd25dd423f7bd8ee1865acc7bcb5428990778a7d229` |
| `v41-digest-mismatched-with-v31.apk.idsig` | 7931 | `5b65ca6f533c38609251121154a7f3579792556d01c9293235e434f0c73429f5` |
