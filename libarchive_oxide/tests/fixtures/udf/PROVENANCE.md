<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# UDF fixture provenance

Most UDF conformance images are generated deterministically in `tests/udf.rs`.
One empty Sparable Partition image from the independent `mkudffs` producer is
also committed as byte-exact interoperability evidence.

## First-party builder coverage

The in-code ECMA-167/UDF builder emits 2048-byte images for revisions 1.02,
1.50, 2.00, 2.01, 2.50, and 2.60 with:

- primary and backup AVDPs plus Main/Reserve VDS with distinct descriptor
  sequence numbers;
- PVD, physical Partition Descriptor, LVD Type 1 map, continued File Set
  Descriptor sequences with default file-set-zero and prevailing-descriptor
  selection (including a distinct valid non-default file set), and root ICB;
- FE/EFE strategy 4, short/long/embedded allocation descriptors,
  allocation-extent chains, block-aligned non-final multiple extents, and
  unrecorded sparse extents, with profile-correct Logical Blocks Recorded and
  root Unique ID fields;
- CS0 declarations, exactly one parent FID per directory, nested directories,
  parent-first ordering, version-one FIDs, validated long-ad flags and UDF
  Unique IDs, binary-sorted FIDs, 8/16-bit OSTA Compressed Unicode, UDF
  timestamps, symlinks, repeated-ICB hardlinks, and a tag-262-framed
  Implementation Use extended attribute with a complete entity identifier;
- UDF 2.01 Extended File Entries for a System Stream Directory, a per-file
  Stream Directory, a conforming embedded `*UDF Backup` timestamp, all four
  Table 39 non-system streams, application and system stream FIDs, role-correct
  Stream bits, aggregate Object Size, inherited main-file UID/GID/permissions,
  stream-local timestamps, metadata characteristics, and streamed payloads
  exposed through collision-checked percent-encoded archive paths.
- UDF 2.50/2.60 Type-2 Metadata Partition Maps paired with the required
  physical Type-1 map; short-AD Metadata File allocation units; shared and
  duplicated Metadata Mirror File layouts; an optional Metadata Bitmap File;
  logical-to-physical translation across allocation-unit boundaries; and
  metadata ICB/FSD/FID descriptor locations expressed in metadata-partition
  logical blocks.
- UDF 1.50 and 2.00+ Type-2 Virtual Partition Maps paired with exactly one
  write-once physical Type-1 map; revision-specific VAT 1.50 trailers and
  2.00+ headers; reverse discovery of the latest VAT ICB; bounded Previous VAT
  ICB history; inline and split non-contiguous physical VAT data; direct
  short/long allocation descriptors and Allocation Extent continuation chains; and
  virtual FSD/ICB translation whose long allocation descriptors reference the
  underlying physical map.
- UDF 1.50 through 2.60 Type-2 Sparable Partition Maps with one or two
  redundant Sparing Tables, profile-valid 16- and 32-block packet translation,
  whole-packet remaps on both sides of an allocation-continuation boundary,
  highest sequence selection, corrupt-copy recovery, and same-sequence
  conflict rejection. UDF 2.50/2.60 fixtures additionally layer a Metadata
  Partition over a Sparable base and split Metadata File allocations at
  remapped packet boundaries.

The paired adversarial builders corrupt descriptor tag checksums, CRCs, and
locations; violate File Set/descriptor-number identity; form continuation and
stream-ICB cycles; point continuations and stream directories outside their
partitions; violate stream revision, type, Stream/metadata flag, parent order
and address, link-count, Object Size, FID version/long-ad flag, and Unique ID
rules; exceed the one-logical-block FID profile bound; and exercise nesting,
entry-count, path, and metadata/in-flight limits. Metadata-partition cases also
cover malformed or missing auxiliary ICBs, wrong file types, allocation-chain
cycles, physical overlap, allocation/alignment-unit violations, mapping
boundaries, primary-integrity mirror recovery, invalid revisions, and bounded
metadata accounting. Virtual-partition cases additionally cover missing,
wrong-type and truncated VAT ICBs, history cycles, duplicate/overlapping and
unallocated VAT entries, overlapping/truncated VAT extents, reserved/map
sequence/partition/access-type violations, allocation-chain cycles and back
pointers, non-physical file allocations, history/allocation depth limits, and
bounded VAT metadata accounting. Sparable-partition cases cover Type-2 map
length, revision, identifier, reserved bytes, volume/partition identity,
packet length restricted to the profile-valid 16/32-block values, table
count/size and packet-disjoint location invariants; rewritable access type and
partition packet alignment; Sparing Table tag, entity, reserved and sequence
fields plus body CRCs capped at 65,535 bytes; sorted and aligned original
locations; reserved entry values; image, table-overlap, and replacement-range
bounds; corrupt-copy fallback; conflicting prevailing copies; and exact
capacity-based cumulative-copy metadata plus in-flight resource limits.

The same builder produces `fuzz/corpus/read_udf/seed.udf` through the explicit
ignored generator test:

```powershell
$env:LIBARCHIVE_OXIDE_UDF_SEED = (Resolve-Path "fuzz/corpus/read_udf/seed.udf").Path
cargo test -p libarchive_oxide --test udf generate_udf_fuzz_seed -- --ignored
```

Seed SHA-256:
`1894a8f6cfa16dbc1e0474f11adb99d0a89a9031036cb64483a16a5e263c750a`
(1,433,600 bytes).

The UDF 2.60 Metadata Partition seed is generated separately so both the
Phase-1 graph-heavy image and the Type-2 map/mirror path remain stable corpus
entries:

```powershell
$env:LIBARCHIVE_OXIDE_UDF_METADATA_SEED = (Resolve-Path "fuzz/corpus/read_udf").Path + "\metadata-partition.udf"
cargo test -p libarchive_oxide --test udf generate_udf_metadata_fuzz_seed -- --ignored --exact
```

`metadata-partition.udf` SHA-256:
`92d29e6fa775626141c337120710366373c3f453d676c78b6829857004fd1c5b`
(1,433,600 bytes).

The UDF 2.60 Virtual Partition seed keeps a two-link split Allocation Extent
continuation chain and one-step VAT history mutation-reachable. The previous
VAT maps a separate, internally consistent empty filesystem, while only the
latest VAT maps `virtual.txt`; this makes reverse latest-generation selection
observable rather than duplicating the current table.

```powershell
$env:LIBARCHIVE_OXIDE_UDF_VIRTUAL_VAT_SEED = (Resolve-Path "fuzz/corpus/read_udf").Path + "\virtual-vat.udf"
cargo test -p libarchive_oxide --test udf --all-features generate_udf_virtual_vat_fuzz_seed -- --ignored --exact
```

`virtual-vat.udf` SHA-256:
`1424fcb3a1b6898c212c4b2f4a43fe8b90204e4b8f340f1cbedee333300f2696`
(1,433,600 bytes).

The UDF 2.60 Sparable Partition seed retains two Sparing Table generations.
Its prevailing generation remaps two adjacent packets, including the
Allocation Extent Descriptor/data packet reached by `chain.bin`; the original
packets are zeroed so a parser cannot pass by ignoring the map.

```powershell
$env:LIBARCHIVE_OXIDE_UDF_SPARABLE_SEED = (Resolve-Path "fuzz/corpus/read_udf").Path + "\sparable-partition.udf"
cargo test -p libarchive_oxide --test udf generate_udf_sparable_fuzz_seed -- --ignored --exact
```

`sparable-partition.udf` SHA-256:
`66f3406ed6f026bd950f9ce1f808b63007b0368775bdc29d5c3a9c6a380a8319`
(1,433,600 bytes).

## Independent `mkudffs` interoperability fixture

`mkudffs-sparable-2.01.udf` is an empty 2 MiB UDF 2.01 filesystem produced by
`mkudffs` from Fedora's `udftools` 2.3 package. It contains two Sparing Tables,
four spare entries, 16-block packets, and the producer's non-allocatable-space
system stream. The public Seek and Range readers parse the image and expose
that system stream.

The image was generated in an ephemeral `fedora:43` container with:

```sh
mkudffs --new-file --blocksize=2048 --media-type=cdrw --udfrev=2.01 \
  --spartable=2 --sparspace=4 --packetlen=16 \
  --uuid=0123456789abcdef --label=OXSPARABLE \
  /out/mkudffs-sparable.udf 1024
```

Committed artifact SHA-256:
`db0cda3e5f6a6ecbc9f24907aa12dfb1ab6424fa52037b7c9f019c11f3e1c0d5`
(2,097,152 bytes). The artifact is an empty generated filesystem and contains
no third-party payload. `udftools` itself is not redistributed.

This establishes one genuinely independent producer. The ≥3-producer evidence
requirement remains open for two further verified producers. GNU
[xorriso](https://www.gnu.org/software/xorriso/) remains ineligible because its
own documentation states that it does not produce UDF filesystems.

## References and license

The builder is first-party MIT OR Apache-2.0 test code written from ECMA-167
and the OSTA UDF specifications referenced by ADR-0013. The generated seeds
contain only synthetic first-party bytes. The empty `mkudffs` output and all
first-party images are covered by the repository's fixture REUSE override.
