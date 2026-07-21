# Campaign 2 completion evidence

This snapshot records the technical evidence for the first slice of RM-200,
the OCI layer engine: RM-201 (bounded layer read with one-pass compressed
digest and diffID) and RM-202 (digest-verified layer application with overlay,
ownership, link, and conflict handling). It is based on the
`feat/rm-200-oci-layer` working tree. The parent epic closes only after every
slice has passed its required remote checks and reached `main`.

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

## Reproduced gates

- Working tree, Windows x86_64, default portable codec profile:
  `cargo test -p libarchive_oxide --test oci_layer` passed 20/20.
- The full `cargo test -p libarchive_oxide` suite passed, including the existing
  engine, codec, and zip suites.
- `cargo fmt --check`, `cargo clippy -p libarchive_oxide --all-targets
  -- -D warnings`, and `RUSTDOCFLAGS="-D warnings" cargo doc -p libarchive_oxide
  --no-deps` all pass; every public `oci` item carries rustdoc and the crate
  keeps `#![forbid(unsafe_code)]` with no new runtime dependency.

## Out of scope for this slice

Deterministic layer creation, a range-source adapter example, the
`oxarchive oci` CLI subcommand, and a full 10 GiB soak are deferred to RM-203,
RM-204, and RM-205. Remote matrix, nightly fuzz, big-endian, and CodeQL gates
remain required before the RM-200 epic can close.
