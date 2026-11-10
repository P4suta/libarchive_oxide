# Static provider chains

`libarchive_oxide` composes archive-format and outer-codec providers in an
application-owned `ProviderSet`. The provider traits use associated concrete
decoder and encoder types; the resulting chain is a Rust type, not a runtime
registry or plugin ABI.

## Composition

```rust
use libarchive_oxide::advanced::{CodecProvider, FormatProvider, ProviderSet};

fn providers<F, C>(format: F, codec: C) -> impl Sized
where
    F: FormatProvider,
    C: CodecProvider,
{
    ProviderSet::empty()
        .with_format_provider(format)
        .with_codec_provider(codec)
}
```

- `FormatProvider` names `Decoder` and `Encoder` associated types.
- `CodecProvider` names its `Decoder` associated type and provides bounded frame encoding.
- `ProviderSet::builtins()` selects the built-in chain;
  `ProviderSet::empty()` starts an explicitly closed downstream chain.
- Prepending a provider changes the concrete set/reader/engine type.
  The head provider is the deterministic override when identifiers are equal.

Downstream identifiers use `FormatId::custom` or `FilterId::custom`; reserved built-in values cannot be created through those constructors.
A provider's `name()` is diagnostic and should remain stable.

## Shared paths

| Entry point | Concrete provider state used |
|---|---|
| `Pipeline::with_providers` | codec probe/decode and format probe/decode |
| `ArchiveReader::with_providers` | the same pipeline through a `Read` adapter |
| `ArchiveEngine::{with_format_provider,with_codec_provider}` | events, inspection, rewind, planning, apply, and creation |
| `ProviderSet::{format,codec}_capability` | available, disabled, or unknown capability |

`ArchiveSession::rewind` moves the original provider chains into the replacement reader over the same immutable input snapshot.
It neither reconstructs defaults nor changes parser state models.

## Probe and protocol rules

A probe returns `Match`, `NoMatch`, or `NeedMore { minimum }`. `minimum` must be
strictly greater than the supplied prefix length; otherwise the pipeline
returns `ErrorKind::Protocol`. Simultaneous matches for different identifiers
are an ambiguity and also fail with a typed protocol error. An equal-identifier
head match is an intentional implementation override.

Signatureless formats must not claim every input from `probe`; callers select them explicitly.
The pipeline detects and removes registered outer filters first, validates read/sequential capabilities before I/O, and constructs only the selected closed-enum decoder state.

Every codec and archive step passes through the core progress validators.
Out-of-range counts, empty data events, and no-progress loops fail closed.
Truncation remains `Malformed`, unavailable capabilities are `Capability`, and an identifier absent from the chain is `Unsupported`.

Codec encoding uses bounded frames and accounts the archive output buffer,
plaintext frame, and encoded frame against `Limits::in_flight_bytes`.
A frame cannot be emitted after `abort`.

## Compatibility and scope

`ArchiveEngine::new`, `ArchiveReader::new`, `ArchiveWriter`, async/Tokio
adapters, and seek-native readers keep their built-in behavior. Random-access
and multi-volume providers use their own associated-decoder trait because their
source contract is `VolumeSet`, not sequential bytes.

Provider, range-source, and caller-driven pipeline types live under `libarchive_oxide::advanced`; they are intentionally not duplicated at the crate root.
Dynamic discovery and a stable plugin ABI remain out of scope.
