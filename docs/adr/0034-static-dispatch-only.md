# Statically typed archive algorithm dispatch

## Status

Proposed

Date: 2026-08-16

## Context

Provider composition can use associated types and closed enums instead of a boxed runtime registry.

## Decision

Use generic provider chains and concrete associated state for archive formats, filters, and payload codecs.
Use closed enums for built-in choices.
Keep heterogeneous storage and caller policy at separate boundaries.

## Alternatives

Retaining the runtime registry preserves its API but keeps two composition models.
A dynamic plugin interface would need a reviewed process or serialization contract.

## Consequences

The recovered implementation breaks the pre-1.0 registry API and can increase monomorphized code size.
The proposal replaces [the registry decision](0015-object-safe-provider-registry.md) only after owner acceptance.
Reconsider dispatch when concrete consumer requirements justify dynamic loading.

## Confirmation

`just architecture` rejects boxed algorithm trait objects in project-owned Rust.
Provider tests check downstream composition and rewind behavior.
