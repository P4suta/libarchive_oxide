# ADR-0006: compile-time provider chains

- Status: accepted
- Date: 2026-07-20
- Tracks: RM-103 / issue #46

## Context

Built-in static dispatch was safe and auditable but did not let a downstream
crate add a format or codec without forking the library. A process-global
registry, `dyn` dispatch, or a dynamic plugin ABI would add initialization
order, ownership, ABI, and policy boundaries that the current safe-Rust
architecture deliberately avoids.

The event API, collected inspection, extraction planning/application, and
creation must not select providers through separate registries. Rewind must
also retain the exact registered chain used by the first read.

## Decision

- `FormatProvider` and `CodecProvider` expose associated decoder/encoder types.
  Provider nodes form generic cons-lists; dispatch remains monomorphized.
- `ProviderSet::builtins()` preserves the default chain and
  `ProviderSet::empty()` creates an explicitly closed chain. Registration
  prepends a provider and changes the concrete set/engine type.
- Providers serve the stable `FormatId` / `FilterId` namespace. A prepended
  provider is an alternative implementation for that identifier; adding a new
  identifier remains a core API decision.
- Head registration order is the override rule for the same identifier.
  Simultaneous different-identifier matches, invalid `NeedMore`, and invalid
  progress are typed protocol failures.
- `Pipeline`, `ArchiveReader`, and `ArchiveEngine` use the same concrete chains.
  `ArchiveSession::rewind` moves those chains out of the prior reader and into
  the replacement reader, avoiding `Clone`, globals, and reconstruction.
- `ProviderArchiveWriter` and `ArchiveEngine::create_registered` use the same
  format/codec selection contract and enforce a combined in-flight budget.
- Capability queries distinguish available, compiled-but-disabled, and unknown
  identifiers. Errors retain the corresponding Capability, Unsupported,
  Malformed, Limit, or Protocol kind.
- RM-103 providers are sequential. The existing built-in seek-native path is
  retained; an external seek-provider protocol is a separate design problem.

## Consequences

- Provider composition is visible in concrete Rust types and can increase
  monomorphized code size as chains grow.
- A provider value may carry configuration, but it cannot be replaced through
  ambient mutable state. Rewind transfers rather than clones it.
- Downstream providers must obey caller-driven buffering and progress rules;
  the shared pipeline validates them at the trust boundary.
- Dynamic discovery and a stable plugin ABI remain out of scope.