---
date: 2026-11-23
status: accepted
---

# Read package certificates and signed data with RustCrypto

## Context

The Java, Android, and NuGet package verifiers share certificate parsing.
Their existing Cryptographic Message Syntax and X.509 libraries depend on the unmaintained Chrono crate.
Archive inspection must remain offline and preserve the bytes used for signature verification.

## Decision

Use the RustCrypto `cms` and `x509-cert` crates to decode signed data and certificates.
Keep the existing input limits, package-specific signer rules and `ring` verification algorithms.
Use the original encoded attributes to verify signatures.
Calculate certificate fingerprints from the received bytes.
Trust decisions remain with the caller.

## Alternatives

An advisory exception would keep the obsolete dependency.
Maintaining a private fork of the earlier codecs would add responsibility for their parser and certificate fixes.

## Consequences

Package verifiers share certificate decoding while each format retains its signer and content checks.
Changing the decoder may affect the classification of malformed input.

## Confirmation

Run the same Java, Android, and NuGet package fixtures before and after migration.
Compare accepted signers and fingerprints along with the classifications for malformed, mismatched, unsupported, and ambiguous signatures.
Confirm the package and fuzz dependency graphs both resolve without Chrono.
