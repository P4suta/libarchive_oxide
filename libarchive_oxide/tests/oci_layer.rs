// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! OCI layer reading: one-pass compressed digest and diffID over tar,
//! tar+gzip, and tar+zstd, plus mismatch detection and bounded streaming.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{Cursor, Read};

use std::fs;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::libarchive_oxide_core::{
    ArchivePath, EntryKind, EntryMetadata, FilterId, FormatId, Limits, Owner,
};
use libarchive_oxide::{
    ArchiveEngine, CapStdFilesystemAdapter, CreateOptions, DigestKind, FilterReader,
    IdentityOwnership, LayerDigests, OciApplyReport, OciLayerApplier, OciLayerEngine,
    OciLayerError, OciPlanOperation, OciRejection, OwnershipTable, Policy,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use libarchive_oxide::{FilesystemFindingKind, FilesystemOperation};
use sha2::{Digest, Sha256};

/// The tar entries every fixture layer contains.
fn layer_entries() -> Vec<(&'static [u8], EntryKind, Vec<u8>)> {
    vec![
        (b"etc/".as_slice(), EntryKind::Dir, Vec::new()),
        (
            b"etc/hostname".as_slice(),
            EntryKind::File,
            b"oxide-node\n".to_vec(),
        ),
        (
            b"usr/bin/tool".as_slice(),
            EntryKind::File,
            vec![0x5a_u8; 9000],
        ),
    ]
}

/// Builds a tar layer blob, optionally wrapped in an outer filter.
fn build_layer(filter: Option<FilterId>, entries: &[(&[u8], EntryKind, Vec<u8>)]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new()
                .with_format(FormatId::Tar)
                .with_filter(filter),
        )
        .expect("create layer writer");
    for (path, kind, body) in entries {
        let metadata = EntryMetadata::builder(*kind, ArchivePath::from_bytes(*path))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start entry");
        if !body.is_empty() {
            writer.write_data(body).expect("write entry");
        }
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish layer")
}

/// Reference SHA-256 over a byte slice.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let output = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&output);
    digest
}

/// Computes the expected digests independently: the compressed digest over the
/// blob and the diffID over the blob decompressed with [`FilterReader`].
fn expected_digests(blob: &[u8]) -> LayerDigests {
    let compressed = sha256(blob);
    let mut filter = FilterReader::new(Cursor::new(blob.to_vec())).expect("filter reader");
    let mut plain = Vec::new();
    filter.read_to_end(&mut plain).expect("decompress blob");
    LayerDigests::from_bytes(compressed, sha256(&plain))
}

/// Reads every entry descriptor from a fresh session.
fn collect_paths(blob: &[u8]) -> (Vec<Vec<u8>>, LayerDigests) {
    let engine = OciLayerEngine::new();
    let mut session = engine.open(Cursor::new(blob.to_vec())).expect("open layer");
    let mut paths = Vec::new();
    while let Some(entry) = session.next_entry().expect("next entry") {
        paths.push(entry.path().to_vec());
    }
    let digests = session.digests().expect("digests");
    (paths, digests)
}

#[test]
fn plain_tar_layer_digests_match_and_are_equal() {
    let entries = layer_entries();
    let blob = build_layer(None, &entries);
    let expected = expected_digests(&blob);

    let (paths, digests) = collect_paths(&blob);
    assert_eq!(
        paths,
        vec![
            b"etc/".to_vec(),
            b"etc/hostname".to_vec(),
            b"usr/bin/tool".to_vec(),
        ]
    );
    assert_eq!(digests, expected);
    // An uncompressed layer's compressed digest and diffID are identical.
    assert_eq!(digests.compressed(), digests.diff_id());
}

#[test]
fn gzip_layer_digests_match_reference() {
    let entries = layer_entries();
    let blob = build_layer(Some(FilterId::Gzip), &entries);
    let expected = expected_digests(&blob);

    let (paths, digests) = collect_paths(&blob);
    assert_eq!(paths.len(), 3);
    assert_eq!(digests.compressed(), expected.compressed());
    assert_eq!(digests.diff_id(), expected.diff_id());
    // Compression changes the stored blob, so the two digests differ.
    assert_ne!(digests.compressed(), digests.diff_id());
}

#[test]
fn zstd_layer_digests_match_reference() {
    let entries = layer_entries();
    let blob = build_layer(Some(FilterId::Zstd), &entries);
    let expected = expected_digests(&blob);

    let (paths, digests) = collect_paths(&blob);
    assert_eq!(paths.len(), 3);
    assert_eq!(digests, expected);
    assert_ne!(digests.compressed(), digests.diff_id());
}

#[test]
fn verify_accepts_matching_digests() {
    let entries = layer_entries();
    let blob = build_layer(Some(FilterId::Gzip), &entries);
    let expected = expected_digests(&blob);

    let mut session = OciLayerEngine::new()
        .open(Cursor::new(blob))
        .expect("open layer");
    session.verify(expected).expect("verify matching digests");
}

#[test]
fn verify_rejects_wrong_compressed_digest() {
    let entries = layer_entries();
    let blob = build_layer(Some(FilterId::Gzip), &entries);
    let expected = expected_digests(&blob);

    let mut tampered_compressed = *expected.compressed();
    tampered_compressed[0] ^= 0xff;
    let wrong = LayerDigests::from_bytes(tampered_compressed, *expected.diff_id());

    let mut session = OciLayerEngine::new()
        .open(Cursor::new(blob))
        .expect("open layer");
    match session.verify(wrong) {
        Err(OciLayerError::DigestMismatch(mismatch)) => {
            assert_eq!(mismatch.kind(), DigestKind::Compressed);
            assert_eq!(mismatch.expected(), &tampered_compressed);
            assert_eq!(mismatch.actual(), expected.compressed());
        },
        other => panic!("expected compressed digest mismatch, got {other:?}"),
    }
}

#[test]
fn verify_rejects_wrong_diff_id() {
    let entries = layer_entries();
    let blob = build_layer(Some(FilterId::Zstd), &entries);
    let expected = expected_digests(&blob);

    let mut tampered_diff = *expected.diff_id();
    tampered_diff[31] ^= 0x01;
    let wrong = LayerDigests::from_bytes(*expected.compressed(), tampered_diff);

    let mut session = OciLayerEngine::new()
        .open(Cursor::new(blob))
        .expect("open layer");
    match session.verify(wrong) {
        Err(OciLayerError::DigestMismatch(mismatch)) => {
            assert_eq!(mismatch.kind(), DigestKind::DiffId);
        },
        other => panic!("expected diffID mismatch, got {other:?}"),
    }
}

#[test]
fn large_layer_is_hashed_by_streaming() {
    // A layer whose decoded tar far exceeds any single buffer, proving the
    // digests are computed without retaining the whole stream.
    let mut acc: u8 = 0;
    let body: Vec<u8> = (0..4 * 1024 * 1024)
        .map(|_| {
            acc = acc.wrapping_mul(31).wrapping_add(7);
            acc
        })
        .collect();
    let entries: Vec<(&[u8], EntryKind, Vec<u8>)> =
        vec![(b"var/data.bin".as_slice(), EntryKind::File, body)];
    let blob = build_layer(Some(FilterId::Gzip), &entries);
    let expected = expected_digests(&blob);

    let (paths, digests) = collect_paths(&blob);
    assert_eq!(paths, vec![b"var/data.bin".to_vec()]);
    assert_eq!(digests, expected);
}

#[test]
fn decoded_total_limit_bounds_the_diff_id_pass() {
    // The decoded (diffID) pass is bounded: a layer whose uncompressed tar
    // exceeds the configured decoded budget is rejected rather than buffered.
    let body: Vec<u8> = vec![0xa5_u8; 512 * 1024];
    let entries: Vec<(&[u8], EntryKind, Vec<u8>)> =
        vec![(b"big.bin".as_slice(), EntryKind::File, body)];
    let blob = build_layer(Some(FilterId::Gzip), &entries);

    let limits = Limits::safe().with_decoded_total(Some(64 * 1024));
    let engine = OciLayerEngine::with_limits(limits);
    let mut session = engine.open(Cursor::new(blob)).expect("open layer");

    let mut hit_error = false;
    loop {
        match session.next_entry() {
            Ok(Some(_)) => {},
            Ok(None) => break,
            Err(_) => {
                hit_error = true;
                break;
            },
        }
    }
    assert!(
        hit_error,
        "decoded-total limit should abort the diffID pass"
    );
}

// ---------------------------------------------------------------------------
// Stage 2: applying layers (RM-202)
// ---------------------------------------------------------------------------

/// Builds a tar layer blob from full entry metadata plus bodies.
fn build_meta_layer(filter: Option<FilterId>, entries: &[(EntryMetadata, Vec<u8>)]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new()
                .with_format(FormatId::Tar)
                .with_filter(filter),
        )
        .expect("create layer writer");
    for (metadata, body) in entries {
        writer.start_entry(metadata).expect("start entry");
        if !body.is_empty() {
            writer.write_data(body).expect("write entry");
        }
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish layer")
}

/// A regular-file entry with the given path, body, and owner ids.
fn file_entry(path: &[u8], body: &[u8], uid: Option<u64>, gid: Option<u64>) -> EntryMetadata {
    EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path.to_vec()))
        .size(Some(body.len() as u64))
        .mode(Some(0o644))
        .owner(Owner {
            uid,
            gid,
            user: None,
            group: None,
        })
        .build()
}

/// A zero-length overlay marker file (whiteout or opaque).
fn marker_entry(path: &[u8]) -> EntryMetadata {
    EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path.to_vec()))
        .size(Some(0))
        .build()
}

/// Applies `blob` to a fresh temporary root and returns the tempdir and report.
fn apply_layer<M: libarchive_oxide::OwnershipMapper>(
    blob: &[u8],
    expected: LayerDigests,
    policy: Policy,
    mapper: &M,
    prepare: impl FnOnce(&std::path::Path),
) -> (tempfile::TempDir, Result<OciApplyReport, OciLayerError>) {
    let destination = tempfile::tempdir().expect("tempdir");
    prepare(destination.path());
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).expect("open root");
    let mut applier = OciLayerApplier::new(Cursor::new(blob.to_vec()));
    let result = applier
        .plan(expected, policy, mapper)
        .and_then(|plan| applier.apply(plan, &mut CapStdFilesystemAdapter::new(root)));
    (destination, result)
}

#[test]
fn apply_materializes_a_normal_layer() {
    let entries = vec![
        (
            file_entry(b"etc/hostname", b"oxide\n", None, None),
            b"oxide\n".to_vec(),
        ),
        (
            file_entry(b"usr/bin/tool", b"ELF", None, None),
            b"ELF".to_vec(),
        ),
    ];
    let blob = build_meta_layer(Some(FilterId::Gzip), &entries);
    let expected = expected_digests(&blob);

    let (dir, result) = apply_layer(&blob, expected, Policy::safe(), &IdentityOwnership, |_| {});
    let report = result.expect("apply layer");
    assert_eq!(report.materialized(), 2);
    assert_eq!(report.verified(), expected);
    assert_eq!(
        fs::read(dir.path().join("etc/hostname")).unwrap(),
        b"oxide\n"
    );
    assert_eq!(fs::read(dir.path().join("usr/bin/tool")).unwrap(), b"ELF");
}

#[test]
fn apply_whiteout_removes_a_lower_file() {
    let blob = build_meta_layer(None, &[(marker_entry(b"etc/.wh.hostname"), Vec::new())]);
    let expected = expected_digests(&blob);

    let (dir, result) = apply_layer(
        &blob,
        expected,
        Policy::safe(),
        &IdentityOwnership,
        |root| {
            fs::create_dir(root.join("etc")).unwrap();
            fs::write(root.join("etc/hostname"), b"lower").unwrap();
            fs::write(root.join("etc/keep"), b"stay").unwrap();
        },
    );
    let report = result.expect("apply whiteout");
    assert_eq!(report.removed(), 1);
    assert!(!dir.path().join("etc/hostname").exists());
    // The whiteout must not disturb siblings.
    assert_eq!(fs::read(dir.path().join("etc/keep")).unwrap(), b"stay");
}

#[test]
fn apply_opaque_directory_clears_existing_contents() {
    let blob = build_meta_layer(None, &[(marker_entry(b"data/.wh..wh..opq"), Vec::new())]);
    let expected = expected_digests(&blob);

    let (dir, result) = apply_layer(
        &blob,
        expected,
        Policy::safe(),
        &IdentityOwnership,
        |root| {
            fs::create_dir(root.join("data")).unwrap();
            fs::write(root.join("data/a"), b"a").unwrap();
            fs::write(root.join("data/b"), b"b").unwrap();
            fs::create_dir(root.join("data/sub")).unwrap();
            fs::write(root.join("data/sub/c"), b"c").unwrap();
        },
    );
    let report = result.expect("apply opaque");
    assert_eq!(report.cleared(), 1);
    // The directory survives but is now empty.
    assert!(dir.path().join("data").is_dir());
    assert_eq!(fs::read_dir(dir.path().join("data")).unwrap().count(), 0);
}

#[test]
fn apply_maps_ownership_into_the_plan() {
    let entries = vec![(
        file_entry(b"srv/app", b"payload", Some(1000), Some(1000)),
        b"payload".to_vec(),
    )];
    let blob = build_meta_layer(None, &entries);
    let expected = expected_digests(&blob);

    let table = OwnershipTable::new().map_uid(1000, 0).map_gid(1000, 42);

    // The plan records the remap explicitly, regardless of platform.
    let mut applier = OciLayerApplier::new(Cursor::new(blob.clone()));
    let plan = applier
        .plan(expected, Policy::safe(), &table)
        .expect("plan layer");
    match &plan.operations()[0] {
        OciPlanOperation::MapOwnership(materialize) => {
            assert_eq!(materialize.metadata().owner().uid, Some(0));
            assert_eq!(materialize.metadata().owner().gid, Some(42));
            let original = materialize.original_owner().expect("original owner");
            assert_eq!(original.uid, Some(1000));
            assert_eq!(original.gid, Some(1000));
        },
        other => panic!("expected MapOwnership, got {other:?}"),
    }

    // Applying still materializes the file; ownership landing is platform-gated.
    let (dir, result) = apply_layer(&blob, expected, Policy::safe(), &table, |_| {});
    let report = result.expect("apply mapped layer");
    assert_eq!(report.materialized(), 1);
    assert_eq!(fs::read(dir.path().join("srv/app")).unwrap(), b"payload");
    // On Linux the adapter attempts and reports ownership rather than silently
    // dropping it. Mapping to uid 0 lands as `Applied` only when the process is
    // privileged; an unprivileged runner reports the refused chown as `OsError`.
    // Either way the ownership operation is surfaced, never discarded.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    assert!(report.findings().iter().any(|finding| {
        finding.operation() == &FilesystemOperation::Ownership
            && matches!(
                finding.kind(),
                FilesystemFindingKind::Applied | FilesystemFindingKind::OsError
            )
    }));
}

#[test]
fn apply_hardlink_targets_a_committed_file() {
    let target = file_entry(b"target.txt", b"payload", None, None);
    let hardlink = EntryMetadata::builder(
        EntryKind::Hardlink,
        ArchivePath::from_bytes(b"hard.txt".to_vec()),
    )
    .size(Some(0))
    .link_target(Some(ArchivePath::from_bytes(b"target.txt".to_vec())))
    .build();
    let blob = build_meta_layer(
        None,
        &[(target, b"payload".to_vec()), (hardlink, Vec::new())],
    );
    let expected = expected_digests(&blob);

    let policy = Policy::safe().allow_hardlinks(true);
    let (dir, result) = apply_layer(&blob, expected, policy, &IdentityOwnership, |_| {});
    let report = result.expect("apply hardlink");
    assert_eq!(report.materialized(), 2);
    assert_eq!(fs::read(dir.path().join("hard.txt")).unwrap(), b"payload");
    assert_eq!(fs::read(dir.path().join("target.txt")).unwrap(), b"payload");
}

#[test]
fn apply_preserves_extended_attributes() {
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"file.bin".to_vec()),
    )
    .size(Some(3))
    .mode(Some(0o644))
    .xattr(b"user.oxide".to_vec(), b"present".to_vec())
    .build();
    let blob = build_meta_layer(None, &[(metadata, b"abc".to_vec())]);
    let expected = expected_digests(&blob);

    let (dir, result) = apply_layer(&blob, expected, Policy::safe(), &IdentityOwnership, |_| {});
    let report = result.expect("apply xattr layer");
    assert_eq!(fs::read(dir.path().join("file.bin")).unwrap(), b"abc");
    #[cfg(any(target_os = "linux", target_os = "android"))]
    assert!(report.findings().iter().any(|finding| {
        matches!(finding.operation(), FilesystemOperation::ExtendedAttribute(name) if name == b"user.oxide")
            && finding.kind() == FilesystemFindingKind::Applied
    }));
    let _ = &report;
}

#[test]
fn digest_mismatch_leaves_destination_untouched() {
    let entries = vec![(
        file_entry(b"etc/hostname", b"oxide\n", None, None),
        b"oxide\n".to_vec(),
    )];
    let blob = build_meta_layer(Some(FilterId::Zstd), &entries);
    let expected = expected_digests(&blob);

    // Tamper the compressed digest the plan is bound to.
    let mut wrong = *expected.compressed();
    wrong[0] ^= 0xff;
    let tampered = LayerDigests::from_bytes(wrong, *expected.diff_id());

    let (dir, result) = apply_layer(&blob, tampered, Policy::safe(), &IdentityOwnership, |_| {});
    match result {
        Err(OciLayerError::DigestMismatch(mismatch)) => {
            assert_eq!(mismatch.kind(), DigestKind::Compressed);
        },
        other => panic!("expected digest mismatch, got {other:?}"),
    }
    // Nothing may have been created.
    assert!(!dir.path().join("etc").exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn digest_mismatch_never_executes_a_whiteout() {
    let blob = build_meta_layer(None, &[(marker_entry(b"etc/.wh.hostname"), Vec::new())]);
    let expected = expected_digests(&blob);
    let mut wrong = *expected.diff_id();
    wrong[31] ^= 0x01;
    let tampered = LayerDigests::from_bytes(*expected.compressed(), wrong);

    let (dir, result) = apply_layer(
        &blob,
        tampered,
        Policy::safe(),
        &IdentityOwnership,
        |root| {
            fs::create_dir(root.join("etc")).unwrap();
            fs::write(root.join("etc/hostname"), b"lower").unwrap();
        },
    );
    assert!(matches!(result, Err(OciLayerError::DigestMismatch(_))));
    // The existing file the whiteout targeted must remain.
    assert_eq!(fs::read(dir.path().join("etc/hostname")).unwrap(), b"lower");
}

#[test]
fn plan_rejects_traversal_and_duplicate_paths() {
    let entries = vec![
        (file_entry(b"../escape", b"x", None, None), b"x".to_vec()),
        (
            file_entry(b"dup.txt", b"first", None, None),
            b"first".to_vec(),
        ),
        (
            file_entry(b"dup.txt", b"second", None, None),
            b"second".to_vec(),
        ),
    ];
    let blob = build_meta_layer(None, &entries);
    let expected = expected_digests(&blob);

    let mut applier = OciLayerApplier::new(Cursor::new(blob));
    let plan = applier
        .plan(expected, Policy::safe(), &IdentityOwnership)
        .expect("plan");
    let operations = plan.operations();
    assert!(matches!(
        &operations[0],
        OciPlanOperation::Reject(reject) if reject.reason() == OciRejection::UnsafePath
    ));
    assert!(matches!(&operations[1], OciPlanOperation::Materialize(_)));
    assert!(matches!(
        &operations[2],
        OciPlanOperation::Reject(reject) if reject.reason() == OciRejection::Duplicate
    ));
}

#[test]
fn plan_rejects_entries_escaping_through_a_layer_symlink() {
    let symlink = EntryMetadata::builder(
        EntryKind::Symlink,
        ArchivePath::from_bytes(b"link".to_vec()),
    )
    .size(Some(0))
    .link_target(Some(ArchivePath::from_bytes(b"innocent".to_vec())))
    .build();
    let hostile = file_entry(b"link/evil", b"boom", None, None);
    let blob = build_meta_layer(None, &[(symlink, Vec::new()), (hostile, b"boom".to_vec())]);
    let expected = expected_digests(&blob);

    let policy = Policy::safe().allow_symlinks(true);
    let mut applier = OciLayerApplier::new(Cursor::new(blob));
    let plan = applier
        .plan(expected, policy, &IdentityOwnership)
        .expect("plan");
    let operations = plan.operations();
    assert!(matches!(&operations[0], OciPlanOperation::Materialize(_)));
    assert!(matches!(
        &operations[1],
        OciPlanOperation::Reject(reject) if reject.reason() == OciRejection::SymlinkEscape
    ));
}

#[test]
fn applier_applies_at_most_one_plan() {
    let entries = vec![(file_entry(b"a.txt", b"a", None, None), b"a".to_vec())];
    let blob = build_meta_layer(None, &entries);
    let expected = expected_digests(&blob);

    let destination = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let mut applier = OciLayerApplier::new(Cursor::new(blob));
    let first = applier
        .plan(expected, Policy::safe(), &IdentityOwnership)
        .unwrap();
    let second = applier
        .plan(expected, Policy::safe(), &IdentityOwnership)
        .unwrap();
    let mut adapter = CapStdFilesystemAdapter::new(root);
    applier.apply(first, &mut adapter).expect("first apply");
    assert!(matches!(
        applier.apply(second, &mut adapter),
        Err(OciLayerError::Session(_))
    ));
}

#[test]
fn plan_binds_to_its_originating_applier() {
    let entries = vec![(file_entry(b"a.txt", b"a", None, None), b"a".to_vec())];
    let blob = build_meta_layer(None, &entries);
    let expected = expected_digests(&blob);

    let mut planner = OciLayerApplier::new(Cursor::new(blob.clone()));
    let plan = planner
        .plan(expected, Policy::safe(), &IdentityOwnership)
        .unwrap();

    let destination = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority()).unwrap();
    let mut other = OciLayerApplier::new(Cursor::new(blob));
    assert!(matches!(
        other.apply(plan, &mut CapStdFilesystemAdapter::new(root)),
        Err(OciLayerError::Session(_))
    ));
}
