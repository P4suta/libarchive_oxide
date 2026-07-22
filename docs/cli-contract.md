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

## `oxarchive oci`

```text
oxarchive oci inspect LAYER
oxarchive oci verify LAYER --digest sha256:... --diff-id sha256:...
oxarchive oci apply [POLICY FLAGS] LAYER DEST --digest sha256:... --diff-id sha256:...
```

The `oci` subcommands read OCI image layers (tar, tar+gzip, tar+zstd) through
the layer engine, plan, and report types of `libarchive_oxide::oci`
(`OciLayerEngine`, `OciLayerApplier`, `LayerDigests`, `OciApplyReport`). The CLI
re-implements no OCI whiteout, opaque-directory, digest, ownership, or path
policy; it only renders the shared types. Every `oci` subcommand emits machine
JSON regardless of the top-level `--json` flag, and every record carries
`schema_version: "oxarchive.output.v0alpha1"`. A layer is named by two SHA-256
values: the compressed `digest` over the stored blob and the `diff_id` over the
decoded tar stream, both rendered as `sha256:<64 hex>` descriptors.

`oci inspect LAYER` is JSON Lines and streams one entry at a time, mirroring the
bounded `inspect` contract:

1. `oci_inspect_start` opens the stream.
2. Zero or more `oci_inspect_entry` records carry one entry each with `index`,
   `path`, `path_raw_hex`, `kind`, `size`, `link_target`, `link_target_raw_hex`,
   `mode`, `uid`, and `gid`.
3. `oci_inspect_complete` carries `entry_count`, the compressed `digest`, the
   `diff_id`, and `complete: true`.

Each record is flushed before the next entry, and the entry list is never
retained. A read or parse failure returns exit 1; the absence of
`oci_inspect_complete` marks the stream incomplete. `LAYER` may be `-` for
standard input.

`oci verify LAYER --digest ... --diff-id ...` emits one `oci_verify` object.
Both digest flags are required; a missing or malformed `sha256:<hex>` argument
is a usage error (exit 2). A match reports `verified: true` with the computed
`digest` and `diff_id` and exits 0. A mismatch reports `verified: false` and a
`mismatch` object (`kind`, `expected`, `computed`) and exits 1. `LAYER` may be
`-`.

`oci apply [POLICY FLAGS] LAYER DEST --digest ... --diff-id ...` emits one
`oci_apply` object. It plans and applies through `OciLayerApplier`, which
verifies both digests before touching `DEST`, so a mismatch reports
`applied: false` with a `mismatch` object, leaves the destination unchanged, and
exits 1. A successful apply reports `applied: true`, the verified `digest` and
`diff_id`, the `materialized`, `removed`, `cleared`, and `rejected` counts, and
a `findings` array of filesystem capability findings. Policy flags are
`--overwrite`, `--allow-symlinks`, `--allow-hardlinks`, and
`--allow-special-files`; a policy refusal keeps the entry visible in the report
and returns exit 1. `oci apply` requires a seekable `LAYER` file so it can rewind
between the verify and apply passes; `-` is a usage error (exit 2).

## Standard streams and unsafe paths

- `inspect`, `plan`, `apply`, and `verify` accept archive input `-`.
- `oci inspect` and `oci verify` accept layer input `-`; `oci apply` requires a
  seekable file and rejects `-`.
- `create` accepts archive output `-`; inputs are filesystem paths.
- `oxtar`, `oxcpio`, and `oxcat` retain their documented stdin/stdout
  compatibility forms.
- Extraction traversal, absolute, drive/UNC, link-order, and destination
  policy failures remain visible and return exit 1.
- Creation rejects parent-directory archive names and derives relative names
  without lossy Unix path conversion.

The schema identifier, record types, command grammar, exit meanings, and
stdout/stderr split are compatibility surfaces.
