# Security Policy

## Reporting

Do not report vulnerabilities in a public issue.

Use [GitHub private vulnerability reporting](https://github.com/P4suta/libarchive_oxide/security/advisories/new).
Include:

- affected crate and version or commit;
- minimal reproducer;
- observed impact.

## Scope

In scope:

- panics, crashes, hangs, or excessive resource use from crafted input;
- writes outside the extraction destination;
- output-limit bypasses;
- unchecked allocation or indexing from archive metadata;
- safety-relevant decoding errors.

Out of scope:

- documented limits selected by the caller;
- misuse confined to trusted inputs;
- weaknesses inherent to an archive format or cipher.

WinZip AES AE-2 requires PBKDF2-HMAC-SHA1 and HMAC-SHA1 for format
compatibility.

## Controls

- all project-owned published crates use `#![forbid(unsafe_code)]`;
- `libarchive_oxide-core` is zero-dependency safe Rust; the default
  `portable-codecs` normal/build graph excludes codec C/FFI packages, while
  additive `native-codecs` explicitly enables system backends. Portable,
  native, and combined builds run the same bounded conformance, malformed, and
  fuzz corpus;
- every decoder, encoder, filter pipeline, spool, and extractor receives
  finite-by-default resource limits;
- session planning validates every destination before apply starts; the shared
  driver binds replayed entries to that plan and passes only relative normalized
  operations to a compile-time filesystem adapter. Windows additionally rejects
  trailing-dot/space, reserved-device, ADS, case, and Unicode-normalization
  aliases while Unix retains byte-exact case-sensitive identity;
- the built-in `cap-std` adapter resolves every parent one component at a time
  without following links, then creates and atomically commits relative to that
  stable directory capability; replacing an ancestor after preparation cannot
  redirect a write, and commit failure leaves the destination unpublished;
- safe extraction rejects traversal, duplicate destination identities,
  pre-existing destinations, links, and special files; applied, unsupported,
  refused, partial, and OS-error filesystem outcomes remain typed in
  `ApplyReport`;
- `oxarchive create` rejects unsafe derived archive names and stages file
  output in a unique sibling; input or writer failure removes the sibling and
  existing destinations are never replaced;
- bounded inspection emits one flushed event record at a time and requires an
  explicit completion record; stdout archive creation is binary-only and its
  documented partial-stream risk is signaled by exit 1;
- decoded output and CLI processing are capped at 4 GiB by default;
- header-derived offsets and sizes use checked conversions and arithmetic;
- fuzz targets run in CI;
- CodeQL and dependency review run on repository changes.

## Supported versions

Before 1.0, security fixes target the latest `main`.

| Version | Supported |
|---|:---:|
| latest `main` | yes |
| older commits | no |
