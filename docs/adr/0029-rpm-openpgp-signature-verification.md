# Bounded package public-key verification

## Status

Proposed

Date: 2026-11-11

## Context

`RPM` supports header-only and legacy header-plus-payload signatures.
Verification must preserve finite memory and separate authenticity from trust.

## Decision

Accept explicitly supplied public-key certificates and verify every applicable detached signature.
Bound keys, signature count, metadata, and streamed payload hashes.
Require explicit fingerprint pins for trust.
Expose no private-key import, generation, or signing operation.

## Alternatives

Presence-only reporting leaves validity unknown.
Ambient keyring discovery or buffering complete payloads would broaden authority and resource use.

## Consequences

The rPGP dependency still selects timing-affected arithmetic.
The narrow exceptions in `deny.toml` apply to public-key verification.
Remove them when compatible fixed dependencies exist.
Reconsider the dependency before adding any secret-key operation.

## Confirmation

[Signature tests](../../libarchive_oxide-package/tests/package_rpm_signature.rs) cover malformed keys, tampering, limits, and trust.
The [RSA advisory](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) and [integer advisory](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) identify secret-dependent timing concerns.
