# ADR-0013: RAR5 and UDF read-only feasibility, and the Deflate64 go/no-go

- Status: accepted
- Date: 2026-07-23
- Tracks: RM-306 / DEV-112 (epic RM-300)

## Context

The Modern Archive Profile (see [modern-replacement.md](../modern-replacement.md))
commits to "accurately scoped read-only RAR5, CAB, XAR, and UDF providers". RM-306
is the feasibility gate for the two hard cases — RAR5 and UDF — and also owns the
Deflate64 go/no-go that [ADR-0012](0012-codec-capability-contract.md) explicitly
delegated ("Feasibility decision … own read-only decoder, external decoder, or
leave unsupported"). This ADR resolves all three, records the fixture-provenance
approach that [ADR-0011](0011-interop-evidence-and-fixture-provenance.md)
anticipated ("the RAR5 and UDF specifics in particular will be appended to this
ADR by RM-306"), and does so without weakening any core invariant. It is a
*feasibility and scope* decision: it does not itself land a provider. Each cell
in the [support matrix](../support-matrix.md) still flips only when its provider
actually lands, so the matrix keeps describing implementation, not intention.

The load-bearing constraint frames every verdict below: the crate is
`#![forbid(unsafe_code)]`, statically dispatched, and ships a dependency-verified
**C/FFI-free portable profile** (RM-400). That constraint is not a preference —
it **disqualifies the obvious shortcuts**. FFI bindings to the C++ UnRAR library
(the `unrar`/`unrar-ng` crates compile the C++ source and inherit both `unsafe`
and the UnRAR license) and FFI to C UDF libraries (`libudfread`, `udftools`) are
ruled out at the profile level, independent of any licensing question. Any `go`
here therefore means an **independent, in-tree, pure-Rust, read-only** path, or it
means nothing.

### RAR5

Legally, an independent read-only RAR5 decoder is defensible. The RAR
*compression* method is a trade secret, not a patent — no patent held by Roshal /
win.rar GmbH covering RAR5 encode or decode was found
([RAR file format](https://en.wikipedia.org/wiki/RAR_(file_format))) — and a
trade secret does not bind someone who reads a lawfully obtained archive or the
published RAR5 technote. The UnRAR license is a copyright license on RARLAB's
*source*: it permits using that source "to handle RAR archives without
limitations", forbids only building a RAR-compatible **compressor**, and does not
reach code that is not derived from it
([UnRAR license](https://github.com/pmachapman/unrar/blob/master/license.txt),
[Fedora](https://fedoraproject.org/wiki/Licensing:Unrar)). Because forbid(unsafe)
+ C-free already forces an independent Rust implementation, we would land in the
legally safest posture by construction — the same model libarchive (BSD) uses for
its independent RAR5 reader (added in 3.4.0). The residual hazards are process,
not blockers: clean-room provenance (no line-porting from UnRAR or from
unRAR-restricted readers such as 7-Zip), nominative naming only ("reads RAR5",
never "a RAR archiver", respecting the trademark), and decode-only forever (a
compressor is the bright-line prohibition and the trade-secret danger zone).

Legality, however, is not feasibility. RAR5 payload decompression is a
proprietary LZSS-plus-context-modeling codec (PPMd-family) of substantial
complexity, and **no mature, vetted, `#![forbid(unsafe_code)]`, provenance-clean
pure-Rust RAR5 decompressor exists** to consume. The one native-Rust `rar` crate
that claims RAR5 extraction is unaudited for both `unsafe` and clean-room
provenance ([crates.io/unrar](https://crates.io/crates/unrar) and survey). Per
ADR-0012 the engine core does **not** absorb a codec; a decompressor of that
weight would belong behind the codec-provider boundary as a dedicated,
independently-provenanced crate the engine merely consumes — and that crate does
not exist under our constraints. Writing one clean-room is a large effort carrying
the trade-secret provenance hazard, so it cannot be hand-waved as in-scope.
Compounding this, `.rar` files in the wild are almost always compressed: a
metadata-plus-Stored-only provider would read almost nothing real, so its
maintenance cost is not justified by the coverage it would deliver today.

### UDF

UDF is a bounded, pure byte-structure read problem with clean spec access and no
FFI need. It layers on ECMA-167, a free public PDF
([ECMA-167 3rd ed.](https://www.ecma-international.org/wp-content/uploads/ECMA-167_3rd_edition_june_1997.pdf)),
and the OSTA UDF revisions 1.02–2.60 are free public PDFs
([UDF 2.60](http://www.osta.org/specs/pdf/udf260.pdf)). The only IP language is
generic SDO RAND boilerplate with no named essential patent — the same posture
under which the Linux kernel `udf` driver, `libudfread`, and `udftools` have
shipped for two decades. The read path is well understood: Anchor Volume
Descriptor Pointer at fixed logical sector 256 (mirrors at N and N−256) → Main /
Reserve Volume Descriptor Sequence (Primary VD, Partition Descriptor, Logical
Volume Descriptor with partition maps) → File Set Descriptor → root ICB /
(Extended) File Entry → File Identifier Descriptors and short/long allocation
descriptors resolving extents, with descriptor-tag CRC/checksum validation and
OSTA-compressed Unicode dstrings. Complexity is roughly 2–4× ISO 9660 but remains
bounded and `unsafe`-free. Crucially, UDF-bridge discs share the Volume
Recognition Sequence that arca's ISO 9660 detection already parses, so UDF
activates from the same entry point. Producer diversity is healthy — mkudffs /
udftools (GPL-2.0), `xorriso -as mkisofs -udf` (GPLv3+), plus ImgBurn / macOS
`hdiutil` / Windows `format /fs:UDF` — so the ≥3-producer rule is satisfiable with
genuinely independent producers. Pure-Rust prior art exists as oracles, not
dependencies: `hadris-udf` (MIT, read-only UDF 1.02, no_std) and bdinfo-rs's
read-only UDF 2.50 reader.

### Deflate64 (ZIP method 9)

A mature, pure-Rust, decode-only crate exists: `deflate64` (MIT, a port of .NET's
streaming inflater, no C/FFI, bounded 64 KiB window), already the backend the
`zip` crate uses for method 9 ([lib.rs/deflate64](https://lib.rs/crates/deflate64),
[docs.rs/zip](https://docs.rs/zip/latest/zip/)). Read demand is real: Windows
Explorer's built-in zipper emits method 9 for large archives (>~2 GB), so
in-the-wild `.zip` files require it. On the write side, **no pure-Rust (or
otherwise reusable) Deflate64 encoder exists anywhere** and demand is effectively
nil; libarchive itself has neither read nor write for method 9. This is exactly
the shape ADR-0012 sanctioned: read via a dedicated pure-Rust codec crate the
engine consumes, write as a typed `Unsupported`.

## Decision

1. **Deflate64 read: GO, via the external pure-Rust `deflate64` decoder — as a
   follow-on implementation unit.** ZIP method 9 read is resolved *in principle*
   by consuming the `deflate64` crate as a pinned dependency **behind the
   codec-provider boundary**, on both the `portable-codecs` and `native-codecs`
   profiles (the crate is pure Rust, so it satisfies the C-free portable profile).
   This is ADR-0012's sanctioned resolution path verbatim; the engine core keeps
   `#![forbid(unsafe_code)]`, static dispatch, and bounded-memory decode (64 KiB
   window). arca does **not** write its own Deflate64 decoder and does **not**
   shell out to a CLI. Because RM-306 is a feasibility ADR, the wiring lands as a
   separate implementation slice, at which point the support-matrix method-9 read
   cells flip to `✓`.

2. **Deflate64 write: NO-GO, retired as won't-do.** No pure-Rust encoder exists
   and write demand is nil. ZIP method 9 write remains a structured
   `ErrorKind::Unsupported` that still enumerates, matching libarchive. This
   **supersedes** the "Deflate64 (read + write)" deficit in ADR-0012's ledger: the
   read half has a decided resolution path (adopt the external decoder), and the
   write half is reclassified from "feasibility-pending" to a closed won't-do with
   no encoder planned.

3. **UDF: GO, scoped read-only, in-tree pure-Rust — as a follow-on implementation
   unit.** A read-only UDF provider is approved, to be activated from the existing
   Volume Recognition Sequence entry point that already serves ISO 9660 (so
   UDF-bridge discs need no new probe). **Phase 1 scope** (the primary read
   surface, covering DVD-ROM/Video and virtually all UDF-bridge optical images):
   revisions **1.02, 1.50, 2.01**; AVDP discovery at sector 256 with N and N−256
   fallbacks; Main/Reserve VDS walk (Primary VD, Partition Descriptor, Logical
   Volume Descriptor with Type 1 physical partition maps) with descriptor-tag CRC
   and checksum validation; File Set Descriptor → root ICB; File Entry and Extended
   File Entry (strategy type 4); short and long allocation descriptors including
   embedded/inline data; directory File Identifier Descriptors; OSTA-compressed
   Unicode (8/16-bit) dstrings and UDF timestamps. **Phase 2, deferred and gated on
   demand:** UDF 2.50/2.60 Metadata Partition Map (required for Blu-ray/BD-ROM) and
   named streams. **Explicitly out of scope:** all write support; Virtual
   Allocation Table / sequential CD-R; sparable partition maps; extended-attribute-
   heavy paths; any encryption (UDF defines none). `hadris-udf` and bdinfo-rs are
   interop oracles, **never dependencies** — the codec-purity / tracking-debt
   principle favors an in-tree implementation with its own bounded fixtures. The
   generic RAND patent caveat is recorded as a low-but-nonzero **tracked IP risk**,
   not asserted as zero exposure, consistent with two decades of Linux `udf` /
   `libudfread` / `udftools` shipping under the same posture.

4. **RAR5: read-only feasible in principle, but the RAR5 provider is DEFERRED in
   its entirety.** No RAR5 provider is implemented now. The blocker is not legal
   (an independent read-only decoder is defensible) but practical: no mature,
   `#![forbid(unsafe_code)]`, provenance-clean pure-Rust RAR5 decompressor exists,
   FFI to C UnRAR is disqualified by the portable profile, and a metadata-plus-
   Stored-only cut would read almost nothing real because `.rar` files in the wild
   are almost always compressed. RAR5 is therefore recorded as a **tracked
   deficit** whose resolution path is a dedicated, independently-provenanced,
   clean-room, pure-Rust RAR5 decompressor consumed behind the codec-provider
   boundary; only once that exists does a RAR5 provider become worth building. The
   constraints that will govern any future RAR5 work are fixed here so the decision
   need not be relitigated: **decode-only forever** (no compressor — the bright-line
   prohibition and trade-secret hazard), **clean-room provenance** (written from the
   RAR5 technote and analysis of lawfully obtained archives, never transcribed or
   line-ported from UnRAR or 7-Zip), and **nominative naming only** ("reads RAR5",
   not "a RAR archiver"). We do not ship an unaudited third-party RAR5 crate to
   shortcut this, and we do not commit RAR5 fixtures until a provider exists to read
   them.

5. **Fixture provenance for `go` items uses ADR-0011's on-disk escape hatch,
   because no pure-Rust producer dev-dependency exists for any of them.** ADR-0011's
   default (deterministic in-code generation from pinned dev-deps) is unattainable
   for UDF and Deflate64 producers, so each requires committed opaque fixtures under
   `libarchive_oxide/tests/fixtures/<format>/<producer>/<case>.<ext>` with a
   mandatory row per file in that format's `PROVENANCE.md` (producing tool, exact
   version, exact command line, capture date, SHA-256, upstream license and
   redistribution note), regenerable byte-for-byte. Fixtures are test **inputs**
   only, never linked into the shipped crate, and a tool's output bytes are not a
   derivative work of the tool, so committing GPL-tool output (mkudffs / xorriso) or
   7-Zip / Windows output to an MIT/Apache-2.0 repo is sound. Payload content is
   self-authored/synthetic to avoid third-party content copyright, and
   non-deterministic fields (timestamps, volume IDs/UUIDs) are pinned in every
   generation command (`mkudffs --uuid/--vid/--utf8`) so regeneration is
   byte-reproducible. These fixtures land with each provider's implementation slice,
   not with this ADR.
   - **UDF:** ≥3 genuinely independent producers — mkudffs / udftools (GPL-2.0),
     `xorriso -as mkisofs -udf` (GPLv3+), plus one of ImgBurn / macOS `hdiutil` /
     Windows `format /fs:UDF` — cleanly satisfying the ≥3-producer rule, with the
     crate's own reader as one consumer and `hadris-udf` / bdinfo-rs as cross-check
     oracles. The third producer choice is an implementation-time decision recorded
     in the UDF `PROVENANCE.md`.
   - **Deflate64:** committed method-9 `.zip` fixtures produced by 7-Zip and by
     Windows Explorer (large-archive path), with the `deflate64` crate serving as
     the decode cross-check.

6. **RM-305 (CAB and XAR) is unaffected and proceeds independently.** CAB and XAR
   remain pure-Rust, in-tree, read-only providers tracked by RM-305 / DEV-111. Their
   feasibility was never in question under these constraints; this ADR neither blocks
   nor gates them and is noted only to confirm the RAR5/UDF resolution does not
   disturb their scope.

## Consequences

**Support matrix** ([support-matrix.md](../support-matrix.md)) changes made now
(decision-only, since no provider lands with this ADR): the codec-deficit ledger's
"Deflate64 (read + write)" row is replaced by a write-only **won't-do** row that
also records the decided read resolution path (adopt the external `deflate64`
decoder in a follow-on slice); and the "RAR5, CAB, XAR, and UDF are not currently
implemented" prose is updated to record the resolved scope — UDF is a scoped
read-only go pending implementation, RAR5 is deferred in its entirety pending a
clean-room decompressor, and CAB/XAR remain under RM-305. The ZIP methods grid's
Deflate64 read cells stay `—` until the `deflate64` wiring actually lands, and the
UDF container row is added when the UDF provider lands; the matrix continues to
describe implementation, not intention.

**Tracked deficits.** *Reclassified:* ADR-0012's Deflate64 deficit — read has a
decided resolution path (external decoder, follow-on slice), write is a closed
won't-do. *Opened / carried:* (a) Deflate64 read implementation (adopt `deflate64`
behind the codec-provider boundary); (b) the UDF read-only provider (Phase 1
scope above); (c) RAR5 read-only support, resolution path = a clean-room,
forbid(unsafe), independently-provenanced pure-Rust RAR5 decompressor behind the
codec-provider boundary, with no provider built until it exists; (d) UDF Phase 2
(2.50/2.60 Metadata Partition, named streams), gated on demand; (e) the UDF
generic-RAND IP caveat as a low-but-nonzero tracked risk. Each carries a resolution
path per ADR-0012's model, so honest disclosure never becomes a resting state.

**Out of scope and staying so:** any RAR compressor or RAR5 *creation* path
(bright-line prohibition); any Deflate64 encoder; UDF write, VAT / sequential CD-R,
sparable partition maps, and encryption. These are typed `Unsupported`, never
silent gaps, and enumeration continues across them.

**Interop verification** for every `go` item, when implemented, runs through the
RM-301 harness with provenance recorded in each format's `PROVENANCE.md` per
ADR-0011: UDF against ≥3 independent producers; Deflate64 read against 7-Zip- and
Windows-produced fixtures with the `deflate64` crate as cross-check. Provenance for
these formats is hereby the appendix that ADR-0011 reserved for RM-306.

**Net.** RM-306 is resolved decisively and honestly: Deflate64 read gets a decided
external-decoder path and its write deficit is formally retired; UDF is a bounded
read-only go pending its implementation slice; and RAR5 is deferred in its entirety
— truthful about the one thing that is genuinely not feasible in-tree today,
proprietary RAR5 decompression — rather than shipping a metadata-only provider that
would read almost no real archive. The clean-room, decode-only, nominative-naming
constraints for any future RAR5 work are fixed so the decision need not be
relitigated.
