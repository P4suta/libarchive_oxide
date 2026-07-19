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

- all published crates use `#![forbid(unsafe_code)]`;
- no FFI or C code is linked;
- extraction sanitizes paths;
- `decompress_capped` limits decompressed output;
- CLI decompression is capped at 4 GiB;
- header-derived offsets and sizes use checked conversions and arithmetic;
- fuzz targets run in CI;
- CodeQL and dependency review run on repository changes.

## Supported versions

Before 1.0, security fixes target the latest `main`.

| Version | Supported |
|---|:---:|
| latest `main` | yes |
| older commits | no |
