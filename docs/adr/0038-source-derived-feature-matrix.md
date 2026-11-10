# Source-derived feature interaction checks

## Status

Proposed

Date: 2026-08-17

## Context

An exhaustive pair matrix repeats configurations whose features never interact in source.

## Decision

Keep isolated builds for every workspace feature.
Derive other flagship combinations from minimal positive source `cfg` conjunctions.
Remove manifest-implied duplicates and keep the maximal combined workspace build.

## Alternatives

An exhaustive pair matrix is simpler to describe but grows quadratically.
A handwritten interaction list can miss new source seams.

## Consequences

The parser must reject malformed expressions instead of dropping checks.
The matrix checks compile isolation.
Portable and native test profiles cover behavior at their assigned stages.
Reconsider parsing when source adds conditional syntax outside the supported grammar.

## Confirmation

Feature-seam unit tests cover conjunctions, implications, and invalid syntax.
`just feature-matrix` runs the generated configurations.
Saved timing figures require fresh measurements before any performance claim.
