# Filesystem adapter contract

`ArchiveSession::apply_with_adapter` is the capability-reporting application
boundary. The session verifies plan identity and replay state, rewinds the same
immutable input snapshot, and drives one concrete `FilesystemAdapter` value.
The existing `ArchiveSession::apply(plan, cap_std::fs::Dir)` API remains a
shortcut that constructs `CapStdFilesystemAdapter`.

## Division of responsibility

The shared engine driver retains the security-sensitive archive work:

- entry/path/nesting limits and checked entry accounting;
- archive-path normalization and traversal/absolute/drive rejection;
- policy gates for overwrite, links, and special files;
- session-local hardlink ordering;
- parser/codec state and bounded payload chunks; and
- required-operation accounting for every entry and restorable metadata field.

An adapter receives `FilesystemEntry` only after those checks. Its destination
and optional link target are normalized relative paths. The adapter still owns
filesystem resolution and must not follow untrusted intermediate links.
Adapters are compile-time values; the contract needs no global registry,
trait-object dispatch, ambient path, or dynamic plugin ABI.

The call order is:

```text
begin_session
  begin_entry
    write_data *
  finish_entry
  ...
finish_session
```

`abort_entry` removes in-flight state when archive processing fails. An adapter
that advertises a capability must return a `FilesystemFinding` for each
requested operation. If it does not, the driver adds a `Partial` finding rather
than silently treating the attribute as restored.

## Findings and failures

`ApplyReport::filesystem_findings` records an archive path,
`FilesystemOperation`, and one of:

- `Applied` — the requested semantics were completed;
- `Unsupported` — the adapter did not advertise the capability;
- `Refused` — extraction policy or a destination conflict refused it;
- `Partial` — only part was applied, or an adapter omitted its evidence; and
- `OsError` — with portable `io::ErrorKind` and raw OS code when available.

Expected permission, platform, metadata, and destination errors belong in the
report. `FilesystemAdapterError` is reserved for a broken adapter state or an
infrastructure failure that makes continued bounded streaming impossible.
`EntryOutcomeKind` remains the source-compatible materialization summary;
`RejectionReason::FilesystemError` links an entry-level adapter failure to its
detailed findings.

## Built-in `cap-std` adapter

`CapStdFilesystemAdapter` resolves beneath a caller-supplied `cap_std::fs::Dir`.
It creates regular files as unique `create_new` siblings, applies metadata to
the open handle where supported, synchronizes the handle, then publishes by
rename (overwrite) or hardlink (no-overwrite). Commit failure removes the
sibling and does not replace or create the destination. Parent directories and
previously created directories are reopened without following symlinks.

The Linux reference path implements:

- mode, numeric uid/gid, access time, and modification time through an open
  file or directory descriptor;
- `user.*` and other permitted extended attributes;
- numeric POSIX access/default ACL text through Linux ACL xattrs;
- sparse logical files by writing only declared data extents and setting the
  final logical length;
- explicitly policy-enabled symlinks, session-local hardlinks, FIFO/socket,
  and character/block device nodes; and
- temporary-sibling atomic regular-file publication.

Named owner lookup, metadata-change time, birth time, and filesystem flags are
not silently approximated. They produce `Unsupported`, `Partial`, `Refused`,
or `OsError` findings. Special files remain disabled unless policy explicitly
enables them, even when the adapter reports platform support.

## Evidence

The external adapter tests cover normalized paths, missing finding detection,
typed OS errors, identity mismatch before adapter dispatch, unsafe paths,
destination races, and atomic publication. Linux tests additionally verify
mode/time/xattr/ACL/numeric ownership, sparse logical bytes, and allocated block
usage. The published-package smoke consumer implements `FilesystemAdapter`
using only public APIs.

```sh
cargo test -p libarchive_oxide --test filesystem_adapter \
  --no-default-features --features portable-codecs,aes,sevenz,async,tokio
cargo run -p xtask -- package-smoke
```