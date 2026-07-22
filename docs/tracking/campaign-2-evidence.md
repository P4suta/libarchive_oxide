# Campaign 2 completion evidence

This snapshot records the technical evidence for the OCI layer engine slices of
RM-200: RM-201 (bounded layer read with one-pass compressed digest and diffID),
RM-202 (digest-verified layer application with overlay, ownership, link, and
conflict handling), RM-204 (byte/range source adapters that feed the engine with
no networking, authentication, or cloud SDK dependency), and RM-205 (the
`oxarchive oci` inspect/verify/apply CLI over the same engine, plan, and report
types). RM-201/202 (#52) and RM-205 (#53) have reached `main`; RM-204 is based on
the `feat/rm-204-oci-range-adapters` working tree. The parent epic closes only
after every slice has passed its required remote checks and reached `main`.

No tag, package publication, GitHub Release, release-workflow execution,
version change, or versioned release candidate is part of this snapshot.

## Implementation map

| Work | Unit | Source | Evidence |
|---|---|---|---|
| One-pass digest/diffID hashing | RM-201 | `libarchive_oxide/src/oci/digest.rs` | `HashingReader`, `SharedHasher`, `LayerDigests` |
| Bounded layer reader and verify | RM-201 | `libarchive_oxide/src/oci/layer.rs` | `OciLayerEngine`, `OciLayerSession`, `DigestMismatch` |
| Explicit overlay/ownership plan | RM-202 | `libarchive_oxide/src/oci/plan.rs` | `OciLayerPlanner`, `OciPlanOperation`, `OwnershipTable` |
| No-commit-on-mismatch apply | RM-202 | `libarchive_oxide/src/oci/apply.rs` | `OciLayerApplier`, `OciApplyReport` |
| Module surface and re-exports | RM-201/202 | `libarchive_oxide/src/oci/mod.rs`, `src/lib.rs` | public `oci` types re-exported from the crate root |
| Adapter removal/clear operations | RM-202 | `libarchive_oxide/src/filesystem.rs`, `src/filesystem_std.rs` | `FilesystemRemoval`, `remove_path`, `clear_directory` |
| Integration tests | RM-201/202 | `libarchive_oxide/tests/oci_layer.rs` | 20 tests, read and apply |
| SDK-free range adapters example | RM-204 | `libarchive_oxide/examples/oci_range_adapter.rs` | `FetchRange`, HTTP/S3/GCS/Azure adapters over one injected fetch seam |
| Range-backed layer read tests | RM-204 | `libarchive_oxide/tests/oci_range.rs` | 4 tests, `RangeReader` → `OciLayerEngine` parity and offset exactness |
| `oci` CLI subcommands | RM-205 | `libarchive_oxide-cli/src/oci.rs` | `run_oci`, `run_oci_inspect`, `run_oci_verify`, `run_oci_apply` over the shared engine |
| `oci` command dispatch | RM-205 | `libarchive_oxide-cli/src/oxarchive.rs` | `run_oxarchive` routes `oci` to `crate::oci::run_oci` |
| `oci` CLI contract tests | RM-205 | `libarchive_oxide-cli/tests/oci_cli.rs` | 8 tests: inspect, verify, apply, usage |

## RM-201

- ADR-0009 specifies the two-digest single-pass design: an `OciLayerEngine`
  nests one `HashingReader` under the raw source and one over the decoded tar
  bytes, so the compressed digest and diffID are computed during a single
  decompression without retaining the stream.
- `plain_tar_layer_digests_match_and_are_equal`, `gzip_layer_digests_match_reference`,
  and `zstd_layer_digests_match_reference` confirm the digests match an
  independent `sha2` reference for tar, tar+gzip, and tar+zstd, and that an
  uncompressed layer's two digests are equal while a compressed layer's differ.
- `verify_accepts_matching_digests`, `verify_rejects_wrong_compressed_digest`,
  and `verify_rejects_wrong_diff_id` cover `OciLayerSession::verify`, including
  which `DigestKind` failed and the reported expected/actual bytes.
- `large_layer_is_hashed_by_streaming` (4 MiB decoded body) and
  `decoded_total_limit_bounds_the_diff_id_pass` show the diffID pass is
  streamed and bounded by the decoded-output limit rather than buffered.

## RM-202

- ADR-0009 specifies overlay markers as explicit plan operations, planned
  ownership mapping, single-use session-bound plans, and no commit on digest
  mismatch. `OciLayerApplier::apply` verifies both digests in a first pass and
  only drives the `FilesystemAdapter` in a second pass on a full match.
- `apply_materializes_a_normal_layer`, `apply_hardlink_targets_a_committed_file`,
  and `apply_preserves_extended_attributes` cover file, hardlink, and xattr
  materialization; the Linux-gated assertions check applied ownership and
  extended-attribute findings.
- `apply_whiteout_removes_a_lower_file` and
  `apply_opaque_directory_clears_existing_contents` verify that `.wh.<name>`
  deletes a lower file without disturbing siblings and that `.wh..wh..opq`
  clears a directory's contents while preserving the directory itself.
- `apply_maps_ownership_into_the_plan` shows an `OwnershipTable` remap is
  recorded as a `MapOwnership` operation that preserves the original owner.
- `digest_mismatch_leaves_destination_untouched` and
  `digest_mismatch_never_executes_a_whiteout` prove a tampered digest aborts
  with `DigestMismatch` before any file is created or any whiteout runs.
- `plan_rejects_traversal_and_duplicate_paths`,
  `plan_rejects_entries_escaping_through_a_layer_symlink`,
  `applier_applies_at_most_one_plan`, and `plan_binds_to_its_originating_applier`
  cover path traversal, duplicate paths, symlink escape, single-apply, and
  cross-applier plan binding.

## RM-204

- ADR-0009 records that the layer engine and applier are generic over `Read`
  (and `Read + Seek`), so a `RangeReader` over any `RangeSource` feeds them with
  no new parser. RM-204 exercises exactly that path: a remote layer blob served
  through ranged fetches is read, digested, and planned with no registry
  networking, authentication, or cloud SDK dependency.
- `examples/oci_range_adapter.rs` defines one generic bridge, `FetchRange<F>`,
  parameterized over a `FnMut(offset, len) -> io::Result<Vec<u8>>` fetch closure
  (static dispatch, no trait objects). The transport is injected at that single
  seam, never depended upon: the HTTP/HTTPS, Amazon S3 `GetObject`, Google Cloud
  Storage media, and Azure Blob Storage adapters differ only in the identity
  source (`ETag`, `VersionId`, `generation`) and in which header carries the
  shared `bytes=<a>-<b>` value, which is documented rather than implemented.
- Running the example drives all four adapters against one in-memory blob through
  the same range interface a remote store exposes; the four report identical
  compressed/diffID digests, and the same S3-flavored source — being `Read +
  Seek` via `RangeReader` — also feeds `OciLayerApplier::plan`, which produces a
  3-operation plan without touching any filesystem.
- `tests/oci_range.rs` proves parity and boundary exactness with a recording
  `MemoryRange` source: `range_backed_digests_match_direct_read` and
  `range_backed_session_verifies_against_direct_digests` show a `RangeReader`-fed
  `OciLayerEngine` yields byte-identical paths and digests to a direct `Cursor`
  read; `range_reader_reproduces_bytes_across_chunk_boundaries` confirms the
  reader reassembles the blob across fetch boundaries with every fetch strictly
  inside the source; and `read_range_returns_exact_bytes_at_each_offset` checks
  start, mid-window, final-byte, and at-length (zero bytes) reads.
- No crate dependency is added: the adapters reuse the existing `RangeSource`,
  `RangeReader`, `SourceIdentity`, and `oci` surface only. The absence of any
  HTTP or cloud SDK is the point of the unit — the transport lives entirely in
  the caller-supplied closure.

## RM-205

- The unified `oxarchive` binary gains an `oci` subcommand group that shares the
  RM-201/202 `OciLayerEngine`, `OciLayerApplier`, `LayerDigests`, and
  `OciApplyReport` types directly; the CLI re-implements no whiteout,
  opaque-directory, digest, ownership, or path policy and only renders the shared
  plan/report values as machine JSON. `run_oxarchive` routes `oci` to
  `crate::oci::run_oci`, which statically dispatches to `inspect`, `verify`, and
  `apply` without a trait object (a `LayerSource` enum unifies stdin and a file),
  keeping the `no-dyn` gate green.
- `inspect_streams_bounded_json_lines_across_filters` confirms `oci inspect`
  emits JSON Lines — `oci_inspect_start`, one `oci_inspect_entry` per member with
  `path`/`kind`/`size`, then `oci_inspect_complete` carrying `entry_count`, the
  compressed `digest`, and the `diff_id` — for plain, gzip, and zstd layers, and
  that the reported digests equal an engine-computed reference.
  `inspect_reads_standard_input` covers the `-` layer operand.
- `verify_matches_and_reports_each_mismatch` covers `oci verify`: a matching
  `--digest`/`--diff-id` pair yields `verified: true` at exit 0, a wrong
  compressed digest yields `verified: false` with a `mismatch` object naming the
  `compressed digest` kind at exit 1, and a malformed `sha256:` argument is a
  usage error at exit 2.
- `apply_materializes_files_and_executes_whiteout` shows `oci apply` materializes
  a file and runs a `.wh.` whiteout through `OciLayerApplier`, reporting
  `applied: true` with `materialized`/`removed` counts.
  `apply_digest_mismatch_leaves_destination_unchanged` proves a tampered digest
  reports `applied: false` and leaves `DEST` untouched at exit 1.
  `apply_refuses_unsafe_paths_with_exit_one` shows a traversal entry is counted
  in `rejected` and produces exit 1 without escaping the destination.
- `apply_rejects_stdin_and_missing_digests_as_usage` confirms `oci apply` refuses
  the non-seekable `-` operand and a missing `--diff-id` as usage errors (exit
  2), and `unknown_oci_subcommand_is_usage_error` covers an unknown and a missing
  `oci` subcommand.

## Reproduced gates

- Working tree, Windows x86_64, default portable codec profile:
  `cargo test -p libarchive_oxide --test oci_layer` passed 20/20, and
  `cargo test -p libarchive_oxide --test oci_range` passed 4/4 (RM-204).
- `cargo build -p libarchive_oxide --example oci_range_adapter` builds and
  `cargo run` on it prints matching digests across all four adapters and a
  3-operation plan (RM-204).
- `cargo test -p libarchive_oxide-cli --test oci_cli` passed 8/8 (RM-205), and
  the full `cargo test -p libarchive_oxide` and `-p libarchive_oxide-cli` suites
  passed, including the existing engine, codec, zip, and CLI contract suites.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  the `no-dyn` gate, and `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` all
  pass; every public `oci` item carries rustdoc and the crate keeps
  `#![forbid(unsafe_code)]` with no new runtime dependency.

## Out of scope for this slice

Deterministic layer creation and a full 10 GiB soak are deferred to RM-203. The
`oxarchive oci` CLI subcommand landed as RM-205 and the SDK-free range adapter
example as RM-204. Remote matrix, nightly fuzz, big-endian, and CodeQL gates
remain required before the RM-200 epic can close.
