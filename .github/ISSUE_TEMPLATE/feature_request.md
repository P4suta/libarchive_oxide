---
name: Feature request
about: Suggest a capability, API, or format-support addition
title: ""
labels: enhancement
assignees: ""
---

## Problem

What are you trying to do that libarchive_oxide does not support today?

## Proposed solution

The API, CLI flag, or behavior you would like. If it maps to a container/format specification (tar
POSIX/PAX, ZIP APPNOTE, 7z, ISO 9660 / Rock Ridge, a compression codec), link the relevant part of
the spec. New formats and directions must land under the frozen `libarchive_oxide-core` trait algebra
(`Format` / `Filter` / `EntryReader` / `EntryWriter`) — say how it fits.

## Alternatives considered

Other approaches, and why they fall short. If `libarchive` (the C library) or another tool handles
this, note how.

## Additional context

Anything else — sample files, links, the drop-in `bsdtar`/`bsdcpio`/`bsdcat`/`bsdunzip` behavior you
want the CLI to match, etc.
