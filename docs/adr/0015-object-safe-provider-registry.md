# ADR-0015: providers use an application-owned object-safe registry

- Status: accepted
- Date: 2026-07-28
- Supersedes: ADR-0006
- Amends: ADR-0012

## Context

Generic provider cons-lists made every provider combination a distinct public
type, increased monomorphization, and prevented applications from assembling a
provider set from runtime configuration. The old `no-dyn` gate also prohibited
the natural ownership boundary for incremental provider state.

A process-global mutable registry or a stable plugin ABI is still unnecessary.
Applications need an owned, immutable registry whose providers obey the same
bounded sans-I/O protocol as built-ins.

## Decision

- `IncrementalFormatProvider` and `IncrementalCodecProvider` are object-safe and
  create boxed incremental decoder/encoder states.
- `RegistryBuilder` owns provider objects, rejects duplicate IDs before I/O,
  and freezes them into a cheaply cloneable immutable `Registry`.
- A registry adapts to the common `ProviderSet`, so `Pipeline`,
  `ArchiveReader`, and provider-backed writers retain their existing progress,
  resource-limit, ambiguity, and error validation.
- Existing associated-type providers have an internal blanket adapter during
  migration and live only in the doc-hidden `advanced::legacy` namespace.
- The source-scanning `no-dyn` gate is removed. CI instead runs registry
  conformance tests covering boxed execution and duplicate rejection.
- Registration remains application-owned. There is no ambient global state,
  dynamic library loading, or C/plugin ABI.

## Consequences

- Downstream custom IDs can be selected without encoding a cons-list in the
  application type.
- One virtual call occurs at provider/state boundaries.
- Provider objects and their incremental states must be `Send`; provider
  factories must also be `Sync`.
- The legacy generic provider builders are not a second canonical downstream
  route. They remain only as doc-hidden workspace migration machinery under
  `advanced::legacy`.
