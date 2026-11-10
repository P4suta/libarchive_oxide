---
date: 2026-11-11
---

# Declare the compiler version required by codecs

## Status

Proposed

## Context

The selected codec dependencies require Rust 1.95.
Workspace metadata and consumer documentation still declare Rust 1.88.
The workspace [manifest](../../libarchive_oxide-codecs/Cargo.toml) selects the newer codec versions.

## Decision

Support Rust 1.95 or later across the workspace.
Keep the development compiler pin separate from the supported version range.
Align documentation and compiler checks with the declared contract.

## Alternatives

Keeping Rust 1.88 would require older dependency forks and a separate compatibility program.
Independent minimums for primitive crates would preserve some older consumers but multiply supported configurations.

## Consequences

Consumers need Rust 1.95 or later for the recovered workspace.
Uniform metadata avoids advertising a configuration that dependencies reject.
Reconsider the policy when an identified consumer needs an older compiler.

## Confirmation

Check the workspace and vendored decoders with the declared compiler.
Keep the record proposed until owner acceptance.
