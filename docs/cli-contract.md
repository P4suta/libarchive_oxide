# CLI and streaming-output contract

`oxarchive`, `oxtar`, `oxcpio`, `oxcat`, and `oxunzip` share this process
contract:

| Exit | Meaning | Standard output | Standard error |
|---:|---|---|---|
| 0 | operation completed | requested data or report | verbose diagnostics only |
| 1 | operational failure | may contain an explicitly documented partial stream | error diagnostic |
| 2 | usage or unsupported option | empty | usage diagnostic |

Help and version output use standard output and exit 0. Unsupported options are
never silently ignored.

## `oxarchive create`

```text
oxarchive [--json] create --format FORMAT [--filter FILTER] ARCHIVE INPUT...
```

Sequential formats are `tar`, `cpio`, `ar`, and `zip`. Outer filters are
`none`, `gzip`, `bzip2`, `xz`, `zstd`, and `lz4`. Creation uses
`ArchiveEngine`, `CreateOptions`, and `StreamingArchiveBuilder`, so the same
finite limits, writer state machines, and safe archive-name policy apply to the
Rust API and CLI.

For a file `ARCHIVE`, creation writes to a unique `create_new` sibling,
synchronizes it, and publishes it without replacing an existing destination.
Failure before publication removes the sibling. An archive path inside a
directory input is refused to prevent the output from becoming one of its own
members.

For `ARCHIVE` equal to `-`, archive bytes are the only standard output.
Streaming cannot retract bytes: if a later input fails, exit is 1 and the
already-written prefix remains partial. `--json create -` is therefore a usage
error instead of mixing JSON and archive bytes.

## Bounded inspection records

`oxarchive --json inspect ARCHIVE` is JSON Lines. Each line is a complete JSON
value and carries `schema_version: "oxarchive.output.v0alpha1"`.

1. `inspect_start` identifies the encoded-input digest.
2. Zero or more `inspect_entry` records carry one entry at a time.
3. `inspect_complete` carries the detected format, digest, entry count, and
   `complete: true`.

The implementation writes directly from `ReaderEvent` and does not retain the
entry list. Each record is flushed before the next event. A parser or output
failure returns exit 1; records already written remain valid, and the absence
of `inspect_complete` marks the stream incomplete.

Human inspection follows the same start/entry/complete sequence. `plan`,
`apply`, and `verify` remain complete reports. `apply` JSON also exposes all
filesystem capability findings instead of discarding unsupported, refused,
partial, or OS-error metadata outcomes.

## Standard streams and unsafe paths

- `inspect`, `plan`, `apply`, and `verify` accept archive input `-`.
- `create` accepts archive output `-`; inputs are filesystem paths.
- `oxtar`, `oxcpio`, and `oxcat` retain their documented stdin/stdout
  compatibility forms.
- Extraction traversal, absolute, drive/UNC, link-order, and destination
  policy failures remain visible and return exit 1.
- Creation rejects parent-directory archive names and derives relative names
  without lossy Unix path conversion.

The schema identifier, record types, command grammar, exit meanings, and
stdout/stderr split are compatibility surfaces.
