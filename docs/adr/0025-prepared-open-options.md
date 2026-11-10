# Common options for prepared sessions

## Status

Proposed

Date: 2026-08-14

## Context

Prepared inspect, plan, and apply sessions need the same format, limits, and password choices as ordinary readers.

## Decision

Clone `OpenOptions` into prepared sessions and use the same options for rewinds.
Bound spooling and recheck caller-created snapshot length.
Keep volume and adjacent-discovery options on their explicit source APIs.

## Alternatives

Separate convenience methods fragment behavior and can lose password candidates or filter selection.
Implicitly spooling every unsupported combination hides resource costs.

## Consequences

One option model reaches every session stage.
Unsupported filter/container combinations fail explicitly.
Reconsider them when a second bounded seek snapshot has an explicit caller contract.

## Confirmation

[Engine tests](../../libarchive_oxide/tests/engine.rs) and CLI tests cover ordered candidates, explicit formats, rewinds, and source limits.
