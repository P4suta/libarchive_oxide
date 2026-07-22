# ADR-0010: Bounded package-validation profiles, the Debian `.deb`, RPM, and ZIP-container validators

- Status: accepted
- Date: 2026-07-22
- Tracks: RM-211 / DEV-75, RM-212 / DEV-100, RM-213 / DEV-101, RM-214

## Context

A software package is an archive that carries a fixed internal contract: a
Debian `.deb`, per `deb(5)` and `dpkg-deb(1)`, is a Unix `ar` archive whose
members are, in order, the text stamp `debian-binary` holding a `2.x` version
line, a `control.tar.*`, and a `data.tar.*`, where each inner tarball is stored
plain or wrapped in a single outer gzip, xz, zstd, or bzip2 filter. RPM, Alpine
`apk`, and the ZIP-based families (JAR, IPA, MSIX, NuGet, Wheel, EPUB) impose
their own nested-container contracts.

Consumers frequently need to answer "is this untrusted package well formed and
safe?" without unpacking it. The general extraction path could parse a `.deb`,
but validating a package by extracting it defeats the purpose: a hostile package
could be a decompression bomb, could carry traversing member or entry names, or
could nest a member that is not the archive it claims to be. The two inner
tarballs are themselves compressed archives, so any approach that pulls a whole
member into memory to inspect it would buffer attacker-controlled, potentially
unbounded decompressed output. Nothing in the existing surface separated "the
container could be read" from "the package conforms to its profile", and there
was no typed vocabulary for package-level findings distinct from the filesystem
adapter's per-operation findings.

## Decision

- A new `package` module (`finding`, `deb`, `rpm`, `zip_profile`, `app_profile`,
  and the shared internal `zip_reader`) builds on the existing
  bounded primitives rather than adding a general new parser: the outer `ar`
  container, the `Pipeline` sans-io nested decoder, the compile-time provider
  capability query, the archive-path sanitizer, and the core `Limits`. The RPM
  lead and header structure — which is neither `ar`, `tar`, nor `zip` — is the
  one exception and adds a small bounded hand-written parser inside `rpm`.
- **Bounded, no-extract validation.** `DebValidator::validate` inspects an
  untrusted package without ever materializing it or buffering a whole member.
  Only bounded prefixes are retained — 64 bytes of the `debian-binary` body and
  six bytes to classify a member's outer filter signature — and nested decode
  output is capped by the configured `Limits`, so a decompression bomb is
  refused as a `DecompressionBomb` finding rather than expanded.
- **`ar` is read as events; inner `tar.*` is streamed through `Pipeline`.** The
  outer container is driven by the push/event `ArchiveReader` (`ReaderEvent`),
  and each `control.tar.*` / `data.tar.*` member is fed chunk by chunk into a
  per-member `Pipeline` (`feed` / `finish_input` / `poll_event`) that
  auto-detects the outer filter and the nested tar and decodes only enough to
  check structure. A pull-style `FilterReader` over a member was deliberately
  rejected because pulling would require the whole member in hand, violating the
  no-whole-buffer rule; the sans-io pipeline consumes exactly the bytes the
  event stream already hands out.
- **Typed `PackageFinding` and ordered `Severity`.** Every deviation is a typed
  `PackageFinding` carrying a stable `PackageFindingCode`, an ordered
  `Severity` (`Info < Warning < Error`), the producing profile name, the
  archive-native path bytes when applicable, and human detail. This mirrors the
  filesystem module's typed-finding pattern and carries no `serde` dependency,
  so a CLI or JSON front end renders it without lossy transcoding.
- **Unsupported methods are a capability finding, not a hard failure.** A
  member whose recognized outer filter cannot be decoded by the current build is
  reported as an `UnsupportedCompression` finding derived from the provider
  `ProviderCapability` query (a recognized frame with no `Available` capability),
  exactly as a build compiled without a given codec feature would report. This
  keeps "we do not support this method" distinct from "this package is
  malformed".
- **Container-readability and profile-conformance are separate verdicts.** The
  result exposes `SupportStatus { container_readable, profile_valid }` as two
  independent booleans. `container_readable` reports only whether the outer `ar`
  structure parsed; `profile_valid` additionally requires the ordered members,
  a valid version stamp, both required tarballs, and no blocking (`Warning` or
  `Error`) finding. A readable container can still fail its profile, and the two
  are never collapsed into one boolean.
- **Supported inputs, Debian unit (RM-211).** The Debian `.deb` profile only:
  member order, duplicate members, missing/unknown members, unsafe member and
  nested-entry paths, malformed or truncated nesting, duplicate nested paths,
  decompression bombs, and the four inner filters (gzip/xz/zstd/bzip2, plus
  plain tar).

### RPM profile (RM-212)

- **RPM is a bespoke binary stream, not a generic container.** Per the RPM v3/v4
  format, an `.rpm` is a fixed 96-byte *lead* (magic `ED AB EE DB`), a
  *signature header*, a *main header* (both using the same RPM header structure
  of magic `8E AD E8 01`, a big-endian index-entry count and data-store size, a
  run of 16-byte index entries, then the data store), and finally a *payload*
  that is a cpio archive wrapped in one outer filter named by the main header's
  `PAYLOADCOMPRESSOR` tag. `RpmValidator::validate` parses this with a small
  bounded, hand-written parser rather than the `ar` reader, but reuses every
  other primitive — the `Pipeline` nested decoder, the provider capability
  query, the path sanitizer, the `Limits`, and the whole `finding` vocabulary.
- **Header sizes are checked before they are allocated.** Each header's declared
  index length (`nindex × 16`) plus data-store length (`hsize`) is validated
  against `Limits::metadata_bytes` *before* any of those bytes are read, so a
  header claiming a huge store is refused as a `HeaderTooLarge` finding rather
  than allocated — the header-bomb budget. The lead is read as a fixed 96 bytes
  and each header section is consumed exactly; the signature header's data store
  is padded to the next eight-byte boundary, the main header is not.
- **Only the two payload tags are read, and only from within the store.** The
  main-header index is scanned for `PAYLOADFORMAT` (1124) and `PAYLOADCOMPRESSOR`
  (1125), each a NUL-terminated string read from the data store at a
  bounds-checked offset. A `PAYLOADFORMAT` that is absent or not `cpio` is a
  `PayloadFormatMismatch` finding.
- **The payload is streamed through one bounded `Pipeline`, never extracted.**
  The remaining bytes are fed chunk by chunk (`feed` / `poll_event` /
  `finish_input`) into a single pipeline that buffers only a six-byte prefix to
  classify the outer filter, then decodes only enough to walk the nested cpio.
  The detected filter is cross-checked against `PAYLOADCOMPRESSOR`; a
  disagreement is a `CompressorMismatch` finding. Unsafe or duplicate cpio entry
  paths, truncation, and a decode past the configured `Limits` become
  `UnsafeEntryPath`, `DuplicateEntryPath`, `TruncatedMember`, and
  `DecompressionBomb` findings, and a recognized filter this build cannot decode
  is the same `UnsupportedCompression` capability finding used by the Debian
  profile.
- **Same separated verdict, same shared vocabulary.** `RpmValidation` exposes the
  same `SupportStatus { container_readable, profile_valid }`: an invalid lead or
  header clears `container_readable`, while a readable container that carries the
  wrong payload format, a compressor mismatch, or any blocking payload finding
  reads but is not `profile_valid`. The RPM-specific codes (`InvalidLead`,
  `InvalidHeader`, `HeaderTooLarge`, `PayloadFormatMismatch`, `CompressorMismatch`)
  are additions to the shared `PackageFindingCode` enum; every other code is
  reused unchanged.
- **Supported inputs, RPM unit (RM-212).** Lead and header magic/version and
  size validation, header-bomb refusal, `PAYLOADFORMAT`/`PAYLOADCOMPRESSOR`
  extraction, detected-versus-declared compressor cross-check, unsafe/duplicate
  cpio entry paths, truncation, decompression bombs, and the payload filters
  gzip/xz/zstd/bzip2 (plus a plain `none` cpio). Signature and digest
  verification are explicitly out of scope for this unit.

### ZIP-container profiles (RM-213)

- **JAR, NuGet, Wheel, and EPUB are one ZIP validator with per-profile members.**
  All four are ordinary ZIP archives; they differ only in the members they must
  carry and, for EPUB, in a structural constraint on the first member.
  `ZipPackageValidator` takes a `ZipPackageProfile` and reuses the whole
  `finding` vocabulary, the path sanitizer, and the core `Limits`. Because ZIP
  stores its index (the central directory) at the end of the file, the validator
  requires `Read + Seek` rather than the streaming `Read` the `ar` and RPM
  profiles use.
- **Bounded, no-extract validation reads only the central directory.** A small
  bounded hand-written parser locates the end-of-central-directory record (with a
  ZIP64 fallback), then walks the central directory to collect each member's
  name, order, compression method, encryption flag, and declared uncompressed
  size. No entry payload is ever decompressed. Central-directory size,
  entry count, and per-entry path length are bounded by `Limits::metadata_bytes`,
  `Limits::entries`, and `Limits::path_bytes`, matching the seekable ZIP reader.
  The single exception is the EPUB `mimetype` body: only for that member, and
  only the exact media-type length, is a stored body read to confirm it is
  `application/epub+zip`.
- **The decompression-bomb budget is the summed declared size.** Because nothing
  is decompressed, the bomb defense compares the summed declared uncompressed
  size of every member against `Limits::decoded_total` and reports a
  `DecompressionBomb` finding when it is exceeded, rather than expanding output.
- **Per-profile required members.** JAR requires `META-INF/MANIFEST.MF`; NuGet
  requires `[Content_Types].xml` and exactly one root `*.nuspec` (a second root
  manifest is a `DuplicateMember` finding); Wheel requires `*.dist-info/METADATA`,
  `*.dist-info/RECORD`, and `*.dist-info/WHEEL`; EPUB requires a first, stored
  `mimetype` member with the exact `application/epub+zip` body plus
  `META-INF/container.xml`. A missing required member is a `MissingRequiredMember`
  finding.
- **Shared ZIP-structure defenses and additive codes.** Every profile refuses an
  unsafe (`UnsafeEntryPath`) or duplicate (`DuplicateEntryPath`) member name, an
  encrypted member (`UnexpectedEncryption`), and a compression method this build
  cannot decode (the same `UnsupportedCompression` capability finding used by the
  Debian and RPM profiles, classified from the central-directory method rather
  than a provider query because no decode is attempted). The EPUB-specific
  constraints add `MimetypeNotFirst`, `MimetypeNotStored`, and
  `MimetypeInvalidContent`; these three codes plus `UnexpectedEncryption` are
  additions to the shared `PackageFindingCode` enum and every other code is
  reused unchanged.
- **Same separated verdict.** `ZipPackageValidation` exposes the same
  `SupportStatus { container_readable, profile_valid }`: a ZIP whose central
  directory cannot be parsed clears `container_readable`, while a readable
  archive that is missing a required member, carries an encrypted or
  undecodable member, or violates the EPUB `mimetype` contract reads but is not
  `profile_valid`.
- **Supported inputs, ZIP-container unit (RM-213).** The JAR, NuGet, Wheel, and
  EPUB profiles: required-member presence, the single-root-`.nuspec` and
  first-stored-`mimetype` structural rules, unsafe/duplicate member paths,
  encryption, an undecodable method, and decompression-bomb refusal. Payload
  decompression, signature and digest verification, and the remaining ZIP
  families (IPA, MSIX/APPX) are out of scope for this unit.

### OS/app package profiles (RM-214)

- **APK, IPA, and MSIX reuse the ZIP central-directory reader, extracted to a
  shared module.** The RM-213 reader (end-of-central-directory location with a
  ZIP64 fallback, bounded member collection, and the shared ZIP-structure
  defenses) was moved verbatim into a crate-internal `zip_reader` module so both
  the `ZipPackageValidator` (JAR/NuGet/Wheel/EPUB) and the new
  `AppPackageValidator` (APK/IPA/MSIX) parse the container in exactly one place.
  The app validator adds no new container parser; it selects an
  `AppPackageProfile` and reuses the whole `finding` vocabulary, the path
  sanitizer, and the core `Limits`, and — like the ZIP-container validator — it
  requires `Read + Seek`.
- **Per-profile required members.** APK requires a root `AndroidManifest.xml`
  (a `classes.dex` is typical but not mandated); IPA requires a
  `Payload/<name>.app/Info.plist` bundle, checked structurally only because the
  iOS code signature lives inside the `.app`; MSIX requires `AppxManifest.xml`,
  `[Content_Types].xml`, and `AppxBlockMap.xml`. A missing required member is a
  `MissingRequiredMember` finding.
- **APK signing schemes are detected, bounded, and informational.** The v1
  scheme is detected from a `META-INF/*.SF` paired with a
  `META-INF/*.(RSA|DSA|EC)` signature file in the central directory. The v2/v3
  schemes live in the *APK Signing Block*, which sits between the last local
  entry and the central directory: the 24 bytes immediately before the
  central-directory start offset (which the reader now returns) are read and the
  trailing 16-byte `APK Sig Block 42` magic confirms the block's presence, then
  its id-value pairs are walked under a cap (`Limits::metadata_bytes`, with a
  fixed fallback) for the v2 id `0x7109871a` and v3 id `0xf05368c0`. The block is
  never read in full; an oversized block is scanned only up to the cap and the
  truncation is reported. Every signature observation is an informational
  `Severity::Info` finding — `SigningSchemeDetected` when a scheme is found or
  `UnsignedPackage` when none is — so signature state never on its own
  invalidates the profile. MSIX detects its `AppxSignature.p7x` member the same
  way. The detected schemes are also surfaced structurally on the result as an
  `AppSignatureReport`.
- **Same separated verdict, same shared defenses, additive codes.** Every app
  profile refuses an unsafe (`UnsafeEntryPath`) or duplicate
  (`DuplicateEntryPath`) member name, an encrypted member
  (`UnexpectedEncryption`), a compression method this build cannot decode
  (`UnsupportedCompression`), and a summed-declared-size decompression bomb
  (`DecompressionBomb`) — the identical `check_common_structure` shared with the
  ZIP-container profiles. `AppPackageValidation` exposes the same
  `SupportStatus { container_readable, profile_valid }`. The two informational
  codes `UnsignedPackage` and `SigningSchemeDetected` are additions to the shared
  `PackageFindingCode` enum; every other code is reused unchanged.
- **Supported inputs, OS/app unit (RM-214).** The APK, IPA, and MSIX profiles:
  required-member presence, APK v1/v2/v3 signing-scheme detection (with a bounded
  signing-block scan), MSIX `AppxSignature.p7x` detection, unsafe/duplicate
  member paths, encryption, an undecodable method, and decompression-bomb
  refusal. Cryptographic signature *verification* (validating the certificates
  and digests, as opposed to detecting the scheme) and a package-validation CLI
  surface are out of scope for this unit.

A package-validation CLI surface is deferred to a later Campaign 2 unit
(RM-215). This decision owns no rendering
or transport policy: any front end consumes the same `DebValidation`,
`RpmValidation`, `ZipPackageValidation`, `AppPackageValidation`, `PackageFinding`,
and `SupportStatus` types unchanged and re-implements no package policy of its own.

## Consequences

Validating a `.deb` no longer requires unpacking it or trusting its size:
memory stays bounded by the configured limits regardless of how large the
package or its decompressed payload claims to be, and a hostile package is
described by typed findings instead of an exception or a partial extraction.
Because container-readability is reported separately from profile-conformance,
a caller can distinguish "not even a readable `ar`" from "a readable container
that violates the Debian contract", which a single valid/invalid boolean cannot
express.

Because the validator is generic over `Read` and over the codec provider set,
the same call path serves an in-memory buffer, a file, or a range-backed source,
and swapping the provider set lets a caller detect exactly which members a
reduced build cannot decode without the validator conflating that with
corruption. The shared `finding` vocabulary is profile-agnostic: the RPM profile
reuses it directly and only adds a small bounded lead/header parser and five
RPM-specific codes, and the ZIP-container profiles (RM-213) do the same with only
a bounded central-directory reader and four additive codes. The OS/app profiles
(RM-214) extend that same reader — extracted to a shared `zip_reader` module — to
APK, IPA, and MSIX, adding APK signing-scheme detection and MSIX signature
detection as informational findings under two more additive codes. Cryptographic
signature *verification* and digest checking (as opposed to scheme detection) and
any package-validation CLI are outside these units and remain later Campaign 2
work.
