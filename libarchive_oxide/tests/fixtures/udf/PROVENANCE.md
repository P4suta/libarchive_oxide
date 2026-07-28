<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# UDF fixture provenance

UDF Phase 1 conformance images are generated deterministically in
`tests/udf.rs`; no external UDF producer output is committed in this slice.

## First-party builder coverage

The in-code ECMA-167/UDF builder emits 2048-byte images for revisions 1.02,
1.50, and 2.01 with:

- primary and backup AVDPs plus Main/Reserve VDS with distinct descriptor
  sequence numbers;
- PVD, physical Partition Descriptor, LVD Type 1 map, FSD, and root ICB;
- FE/EFE strategy 4, short/long/embedded allocation descriptors,
  allocation-extent chains, block-aligned non-final multiple extents, and
  unrecorded sparse extents, with profile-correct Logical Blocks Recorded and
  root Unique ID fields;
- CS0 declarations, exactly one parent FID per directory, nested directories,
  binary-sorted FIDs, 8/16-bit OSTA Compressed Unicode, UDF timestamps,
  symlinks, repeated-ICB hardlinks, and a tag-262-framed Implementation Use
  extended attribute with a complete entity identifier.

The same builder produces `fuzz/corpus/read_udf/seed.udf` through the explicit
ignored generator test:

```powershell
$env:LIBARCHIVE_OXIDE_UDF_SEED = (Resolve-Path "fuzz/corpus/read_udf/seed.udf").Path
cargo test -p libarchive_oxide --test udf generate_udf_fuzz_seed -- --ignored
```

Seed SHA-256:
`676dff45d021162f2435285eee4301708409f83b661106d877149744bd20f527`
(1,433,600 bytes).

## External-producer evidence still required

`mkudffs` and two further independently verified UDF producers were not
available in the implementation environment. GNU
[xorriso](https://www.gnu.org/software/xorriso/) is not a candidate: its own
documentation states that it does not produce UDF filesystems. No unverifiable
blob was copied into the repository. The ≥3-producer evidence requirement
therefore remains explicitly open in RM-300/RM-400; this file records
implementation provenance, not a claim that the external interop gate is
complete.

## References and license

The builder is first-party MIT OR Apache-2.0 test code written from ECMA-167
and the OSTA UDF specifications referenced by ADR-0013. The generated seed
contains only synthetic first-party bytes and is covered by the repository's
fixture REUSE override.
