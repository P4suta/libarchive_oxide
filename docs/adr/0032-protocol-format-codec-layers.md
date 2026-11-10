# Separate protocol, formats, and codecs

## Status

Proposed

Date: 2026-08-16

## Context

Generic codecs need shared byte protocols without depending on archive-format state machines.

## Decision

Place common errors, limits, and codec protocols in dependency-free `libarchive_oxide-protocol`.
Keep format core, generic codecs, and `RAR` codecs as sibling consumers.
Compose them in the flagship crate and preserve existing core re-exports.
Make package and CLI layers consume public upper-layer APIs.

## Alternatives

Keeping protocol primitives in core forces generic codecs to depend on format code.
Splitting every format into a package would add release overhead without requiring a new extension boundary.

## Consequences

The workspace gains packages and explicit dependency direction.
The proposal amends [core architecture](0001-core-architecture.md) after owner acceptance.
Reconsider package boundaries when reuse or licensing needs differ.

## Confirmation

`just architecture` checks dependency direction and source imports.
Workspace tests check the composed adapters.
