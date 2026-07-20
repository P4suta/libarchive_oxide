# Compile-time providers

`libarchive_oxide` composes archive-format and outer-codec providers at compile
time. Registration changes the concrete Rust type; it does not create a global
registry, trait object, dynamic library boundary, or plugin ABI.

## Registration

Start from one of two provider sets:

- `ProviderSet::builtins()` retains the standard tar/cpio/ar/ZIP/7z/ISO and
  gzip/bzip2/zstd/xz/LZ4 behavior.
- `ProviderSet::empty()` creates a closed set for downstream-only formats and
  codecs.

Prepend implementations with `with_format_provider` and
`with_codec_provider`, or use the equivalent `ArchiveEngine` builders. A
provider serves an existing stable `FormatId` or `FilterId`; prepend order
selects an alternative implementation for that identifier. Adding a new
identifier remains a core API decision rather than a runtime registration side
effect. `name()` is diagnostic and should remain stable.

`FormatProvider` supplies associated caller-driven decoder and encoder state.
`CodecProvider` supplies associated decoder state and a bounded encoded
frame/member. Associated types keep every chain statically dispatched.
Downstream format providers are sequential in this contract and advertise
`FormatCapabilities::new(..., false)`; seek-native provider registration is not
part of RM-103.

## Shared paths

| Entry point | Registered state used |
|---|---|
| `Pipeline::with_providers` | codec probe/decode and format probe/decode |
| `ArchiveReader::with_providers` | the same caller-driven `Pipeline` |
| `ArchiveEngine::open` | events, inspection, rewind, planning, and apply |
| `ArchiveEngine::create_registered` | format encode and optional codec encode |
| `ProviderSet::{format,codec}_capability` | available, disabled, or unknown capability |

`ArchiveSession::rewind` recovers the concrete provider chains from the prior
reader and installs them over the same immutable input snapshot. It neither
reconstructs a default registry nor changes parser state models.

## Probe and protocol rules

A probe returns `Match`, `NoMatch`, or `NeedMore { minimum }`. `minimum` must be
strictly greater than the supplied prefix length; otherwise the pipeline
returns `ErrorKind::Protocol`. The prepended head provider is the explicit
override when it and a tail provider use the same identifier. Simultaneous
matches for different identifiers are an ambiguity and also fail with a typed
protocol error.

All provider codec and archive steps pass through the core progress validators.
Out-of-range counts, empty data events, and no-progress loops fail closed.
Truncation remains `Malformed`, unavailable registered capabilities are
`Capability`, and an identifier absent from the chain is `Unsupported`.

Registered codec encoding uses bounded frames and accounts the archive output
buffer, plaintext frame, and encoded frame against `Limits::in_flight_bytes`.
A frame cannot be emitted after `abort`.

## Compatibility

`ArchiveEngine::new`, `ProviderSet::builtins`, `ArchiveReader::new`,
`ArchiveWriter`, async/Tokio adapters, and seek-native readers keep their
existing built-in behavior. Registration is opt-in; no existing format or
individual codec feature is deprecated by this API.