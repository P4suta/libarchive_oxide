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
  `native-codecs` is an explicit mutually exclusive profile. Both run the same
  bounded conformance, malformed, and fuzz corpus;
- every decoder, encoder, filter pipeline, spool, and extractor receives
  finite-by-default resource limits;
- session apply keeps path normalization, limits, link order, and policy in a
  shared driver, then passes only relative normalized operations to a
  compile-time filesystem adapter;
- the built-in `cap-std` adapter commits regular files atomically from a
  `create_new` sibling, reopens parents/directories without following links,
  and leaves the destination unpublished on commit failure;
- safe extraction rejects traversal, pre-existing destinations, links, and
  special files; applied, unsupported, refused, partial, and OS-error
  filesystem outcomes remain typed in `ApplyReport`;
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
