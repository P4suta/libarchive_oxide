# Object-safe provider registry

`libarchive_oxide` composes archive-format and outer-codec providers in an
application-owned immutable `Registry`. It does not create global mutable
state, a dynamic-library boundary, or a plugin ABI.

## Registration

Build a registry with `Registry::builder()`:

```rust
use libarchive_oxide::advanced::{
    IncrementalCodecProvider, IncrementalFormatProvider, Registry,
};
# let _ = core::mem::size_of::<Option<Box<dyn IncrementalCodecProvider>>>();
# let _ = core::mem::size_of::<Option<Box<dyn IncrementalFormatProvider>>>();
let registry = Registry::builder().build();
# let _ = registry;
```

- `register_format(Box<dyn IncrementalFormatProvider>)` adds one object-safe
  archive provider.
- `register_codec(Box<dyn IncrementalCodecProvider>)` adds one object-safe
  outer-codec provider.
- `build()` freezes the lists into a cheaply cloneable `Registry`.

Duplicate identifiers are rejected during registration, before archive I/O.
Downstream identifiers must be created with `FormatId::custom` or
`FilterId::custom`; reserved built-in values cannot be constructed through
those APIs. `name()` is diagnostic and should remain stable.

Providers create boxed incremental sans-I/O states. Downstream format providers
in this contract are sequential and advertise
`FormatCapabilities::uniform(directions, AccessMode::Sequential)`;
asymmetric providers instead construct an `AccessProfile` and pass it to
`FormatCapabilities::new`;
seek-native registration remains a separate interface.

## Shared paths

| Entry point | Registered state used |
|---|---|
| `Registry::pipeline` | codec probe/decode and format probe/decode |
| `Registry::reader` | the same caller-driven pipeline through a `Read` adapter |
| `ArchiveEngine::from_registry` | events, inspection, rewind, planning, and apply |
| `ArchiveEngine::create_registered` | format encode and optional codec encode |
| `Registry::{format,codec}_capability` | available, disabled, or unknown capability |

`ArchiveSession::rewind` recovers the registry-backed provider set from the
prior reader and installs it over the same immutable input snapshot. It neither
reconstructs defaults nor changes parser state models.

## Probe and protocol rules

A probe returns `Match`, `NoMatch`, or `NeedMore { minimum }`. `minimum` must be
strictly greater than the supplied prefix length; otherwise the pipeline
returns `ErrorKind::Protocol`. Simultaneous matches for different identifiers
are an ambiguity and also fail with a typed protocol error.

Signatureless formats must never claim every input from `probe`. Callers opt
in through an explicit-format constructor instead. The pipeline still detects
and removes registered outer filters first, validates read/sequential
capabilities before I/O, and then creates only the selected decoder. Built-in
`FormatId::Raw` follows this contract.
Built-in `FormatId::Warc` instead auto-detects only the exact bounded
`WARC/1.0\r\n` and `WARC/1.1\r\n` signatures and advertises sequential read
capability only.

All provider codec and archive steps pass through the core progress validators.
Out-of-range counts, empty data events, and no-progress loops fail closed.
Truncation remains `Malformed`, unavailable registered capabilities are
`Capability`, and an identifier absent from the chain is `Unsupported`.

Registered codec encoding uses bounded frames and accounts the archive output
buffer, plaintext frame, and encoded frame against `Limits::in_flight_bytes`.
A frame cannot be emitted after `abort`.

## Compatibility

`ArchiveEngine::new`, `ArchiveReader::new`, `ArchiveWriter`, async/Tokio
adapters, and seek-native readers keep their built-in behavior. Generic static
provider chains remain only as doc-hidden workspace migration machinery in
`advanced::legacy`; applications use `Registry`.

All registry, provider, range-source, and caller-driven pipeline types live
under `libarchive_oxide::advanced`; they are intentionally not duplicated at
the crate root.
