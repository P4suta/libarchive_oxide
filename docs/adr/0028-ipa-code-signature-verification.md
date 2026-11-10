# Bounded app signature verification

## Status

Proposed

Date: 2026-11-11

## Context

`IPA` authenticity depends on executable pages, resource seals, signature bindings, and caller trust.
Retaining an entire executable as metadata would violate memory limits.

## Decision

Read Mach-O and signature ranges through bounded sparse passes.
Stream page and resource hashes, validate directory bindings, and verify every signer.
Keep explicit fingerprint trust separate from integrity and validity.

## Alternatives

Presence-only reporting misses tampering.
Extracting executable files or using platform trust adds storage and ambient-policy dependencies.

## Consequences

Large executables use bounded metadata and hash state rather than executable-sized memory.
Unsupported nested-code and resource rules fail explicitly.
Reconsider their support with normative rules and independent fixtures.

## Confirmation

[`IPA` signature tests](../../libarchive_oxide-package/tests/package_ipa_signature.rs) cover code pages, resources, alternate directories, signature tampering, limits, and trust pins.
