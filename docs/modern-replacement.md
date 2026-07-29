# Modern Replacement roadmap

## North star

`libarchive_oxide` aims to become a safe Rust-first artifact engine for OCI
layers, packages, and archive CLI workflows. Format interoperability follows
libarchive where practical, but C symbols and libarchive ABI compatibility are
not part of this project.

The preferred product surface is a high-level Rust engine with
`inspect -> plan -> apply/create`, finite resource limits, extraction policy,
capability-based filesystems, bounded streaming events, and range sources.
Low-level readers, writers, and sans-I/O state machines remain available for
specialized integrations.

## Modern Archive Profile

The project may call a future 1.0 a Modern Replacement only when all of these
gates pass:

- a dependency-verified, C/FFI-free portable codec profile for DEFLATE/gzip,
  zstd, xz/LZMA2, LZ4 frame, and bzip2;
- read/write tar (v7/ustar/pax/GNU), major cpio dialects, GNU/BSD ar,
  ZIP/ZIP64 with mainstream ZIPX methods, practical 7z, and ISO 9660 with Rock
  Ridge and Joliet;
- accurately scoped read-only RAR5, CAB, XAR, and UDF providers;
- OCI layer and package-profile conformance, including tar+gzip and tar+zstd,
  Debian/RPM payload codecs, and ZIP-based package families;
- a coherent Rust API and a versioned CLI JSON contract, without freezing
  SemVer while the design is still converging;
- bounded-memory, malformed-input, fuzz, interoperability, and performance
  gates described below.

The [support matrix](support-matrix.md) is authoritative for what works now.

## Campaigns

### Campaign 0: truthful public surface

- Keep README, security claims, crate metadata, and the support matrix aligned
  with the actual dependency graph and implementation.
- Enforce by static test that release automation remains manual, produces a
  draft, attaches assets before final publication, and cannot run on a release
  event.
- Test the packaged crates from an external consumer, not only the repository
  workspace.

### Campaign 1: measurable foundations

- Add ADRs for the engine, providers, codec profiles, range sources, and
  filesystem capabilities.
- Introduce `ArchiveEngine`, `ArchiveSession`, inspections, session-bound
  plans, apply reports, bounded events, and create options.
- Add object-safe format/codec providers with duplicate-safe explicit
  registration and built-in defaults.
- Add `ReadAt`/`AsyncRangeSource`, a Linux reference filesystem adapter,
  a unified `oxarchive` CLI, portable/native codec profiles, bzip2, and
  comparable benchmarks.

The original associated-type provider chains in
[ADR-0006](adr/0006-compile-time-providers.md) were superseded by the boxed,
object-safe registry in
[ADR-0015](adr/0015-object-safe-provider-registry.md). Pipeline,
reader, engine/session, and creation now share that extensible registry
contract.
Filesystem application is implemented as a shared policy/limit driver plus a
compile-time capability-reporting adapter. The Linux reference adapter and
atomicity/finding contract are specified by
[ADR-0007](adr/0007-capability-filesystem.md).
Unified creation and inspection use the shared engine/options/event paths.
Atomic file publication, JSON Lines completion records, standard streams, and
exit 0/1/2 are specified by
[ADR-0008](adr/0008-bounded-cli-streams.md).

### Campaign 2: OCI and packages

- Build an OCI layer engine for tar, tar+gzip, and tar+zstd without registry
  networking or authentication.
- Verify compressed digest and diffID in one pass; model whiteouts, opaque
  directories, mappings, hardlinks, xattrs, and path conflicts in the plan.
- Create deterministic layers with canonical order, time, ownership, pax, and
  padding.
- Validate Debian, RPM, APK/JAR/IPA/MSIX/NuGet/Wheel/EPUB structures.

### Campaign 3: mainstream depth

- Expand ZIP methods, AES, and extras; expand 7z folders, coder graphs, solid
  archives, filters, methods, and AES.
- Complete producer corpora and metadata round trips for tar/cpio/ar/ISO.
- Implement CAB and XAR read-only providers and settle legal/spec/fixture
  feasibility for RAR5 and UDF.
- Keep provider and sans-I/O seams sufficient for a separate future C-facing
  project without exposing a C ABI here.

### Campaign 4: replacement candidate

- Complete the read-only compatibility providers and continuous quality gates.
- Keep publishing, release candidates, version bumps, and compatibility
  freezes outside this implementation program.

No calendar date or version number overrides these completion gates.

## Acceptance gates

- Read each format/method from at least three independent producers and verify
  emitted archives with at least two independent consumers.
- Regress and fuzz malformed lengths, truncation, checksum/auth failures,
  overlaps, traversal, symlink races, decompression bombs, and huge entry
  counts.
- Keep a 10 GiB tar/gzip/xz/zstd streaming soak bounded at no more than
  128 MiB peak RSS and with no growth proportional to payload size.
- Target native performance within 20% of libarchive and portable performance
  within 2x on representative operations. A sustained regression over 10%
  requires explicit review.
- Verify protocol arithmetic, MSRV, 32-bit, big-endian, WASI inspection, and
  no_std core/codecs.

## Explicit non-goals

Registry clients, cloud SDK implementations, GUIs, dynamic plugin ABIs,
complete libarchive source compatibility, and silent OS-metadata loss are not
part of the engine. Historical long-tail formats can graduate as external
providers when they have real usage data, ownership, and conformance corpora.
