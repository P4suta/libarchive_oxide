# ADR-0010: Bounded package-validation profiles and the Debian `.deb` validator

- Status: accepted
- Date: 2026-07-22
- Tracks: RM-211 / DEV-75

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

- A new `package` module (`finding`, `deb`) builds on the existing bounded
  primitives rather than adding a new parser: the outer `ar` container, the
  `Pipeline` sans-io nested decoder, the compile-time provider capability query,
  the archive-path sanitizer, and the core `Limits`.
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
- **Supported inputs this unit.** The Debian `.deb` profile only: member order,
  duplicate members, missing/unknown members, unsafe member and nested-entry
  paths, malformed or truncated nesting, duplicate nested paths, decompression
  bombs, and the four inner filters (gzip/xz/zstd/bzip2, plus plain tar).

RPM, the ZIP-based package families, and a package-validation CLI surface are
deferred to later Campaign 2 units (RM-212 onward and RM-215 for the CLI). This
decision owns no rendering or transport policy: any front end consumes the same
`DebValidation`, `PackageFinding`, and `SupportStatus` types unchanged and
re-implements no package policy of its own.

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
corruption. The shared `finding` vocabulary is profile-agnostic, so RPM and the
ZIP-based families reuse it directly and only add their own container-reading
front end. Signature and cryptographic-integrity verification, digest checking,
and any package-validation CLI are outside this unit and remain later Campaign 2
work.
