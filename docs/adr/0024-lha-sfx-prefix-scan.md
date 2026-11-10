# Bounded `LHA` executable-prefix scanning

## Status

Proposed

Date: 2026-08-14

## Context

`LHA` member signatures can follow an executable stub.
An unbounded executable scan would invite false positives and excessive work.

## Decision

Scan only `MZ` inputs and only through a 20 KiB prefix.
Use a fixed window, validate candidate headers through the ordinary parser, and report the discovered offset as metadata.
Keep explicit and automatic opens on the same bounded path.

## Alternatives

Rejecting executable wrappers preserves a smaller surface but loses common inputs.
Scanning arbitrary wrappers lacks a justified bound.

## Consequences

Non-MZ wrappers remain unsupported.
The payload parser and checksum rules remain unchanged.
Reconsider the prefix bound when an independently produced fixture requires a larger documented wrapper.

## Confirmation

[`LHA` integration tests](../../libarchive_oxide/tests/interop_lha.rs) cover valid prefixes, malformed headers, and limit refusals.
