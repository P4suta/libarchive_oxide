# Security Policy

`libarchive_oxide` parses untrusted, attacker-controlled input: archive
containers (tar / cpio / ar / zip / 7z / iso9660) and compressed streams
(gzip / zstd / xz / lz4). Memory safety and robust bounds handling are core goals
— the whole tree is `#![forbid(unsafe_code)]` and continuously fuzzed — so we take
security reports seriously.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's [private vulnerability
reporting](https://github.com/P4suta/libarchive_oxide/security/advisories/new)
(Security → Advisories → *Report a vulnerability*). Include:

- the affected crate and version / commit,
- a minimal reproducer (a crashing input archive is ideal), and
- the observed impact (panic, hang, excessive memory, path escape, incorrect output).

We aim to acknowledge a report within a few days and will keep you updated as we
investigate. Once a fix is available we will coordinate a disclosure timeline with
you and credit you in the advisory unless you prefer otherwise.

## Threat model

The library is designed to consume **untrusted, attacker-controlled archives**.
The safe path is the default; the unsafe knob is explicit and documented.

In scope:

- **Memory safety and liveness on crafted input** — crashes, panics, unbounded
  memory or CPU on a malformed or hostile archive or compressed stream.
- **Extraction attacks** — any way an archive entry can write outside the
  destination directory (path traversal via `..`, absolute paths, Windows
  drive/UNC prefixes, device names) despite `libarchive_oxide::sanitize`.
- **Decompression bombs** — any way `decompress_capped` expands past its cap, or a
  format path allocates from an untrusted size field without a bound.
- **Correctness that affects safety** — a decode result that diverges from the
  format specification in a way that could mislead a security decision.

Out of scope:

- Denial-of-service that is a documented, tunable limit (for example, choosing the
  uncapped `decompress` for trusted input, or setting a very high cap).
- API misuse by trusted, developer-supplied code paths that cannot be reached from
  untrusted archive bytes.
- Weaknesses inherent to a format or cipher itself (e.g. ZipCrypto's known
  weakness) rather than to this implementation. WinZip AES-256 is implemented to
  the AE-2 spec; SHA-1 there is an interoperability requirement, not a strength
  claim.

## Hardening

- **No `unsafe`.** Every published crate is `#![forbid(unsafe_code)]`. There is no
  FFI and no C linked — this is a from-scratch reimplementation, not a binding.
- **Path sanitization.** Extraction refuses entries whose sanitized path escapes
  the destination, via `libarchive_oxide::sanitize` (`..`, absolute, drive/UNC,
  device names).
- **Decompression caps.** `decompress_capped(bytes, max)` fails with
  `LimitExceeded` before expanding past the cap; the CLI applies a 4 GiB cap by
  default. The uncapped `decompress` is opt-in for trusted input.
- **Checked arithmetic.** Buffer sizes and indices derived from untrusted headers
  use explicit `checked_*` / `saturating_*` arithmetic and are validated before
  allocation, so safety does not rely on the release-profile overflow trap.
- **Continuous fuzzing.** cargo-fuzz targets exercise the decode/extract paths;
  their invariant bodies are also replayed from the normal test suite.

## Supported versions

Pre-1.0: only the latest `main` receives security fixes.

| Version         | Supported |
| --------------- | --------- |
| `main` (latest) | ✅        |
| older commits   | ❌        |
