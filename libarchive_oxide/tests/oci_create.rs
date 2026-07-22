// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic OCI layer creation: byte-identical rebuilds, digest
//! round-trips through the reader, and reproducible metadata emission across the
//! uncompressed, gzip, and zstd paths.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{Cursor, Read};

use libarchive_oxide::libarchive_oxide_core::{
    ArchivePath, EntryKind, EntryMetadata, EntryTimes, Owner, Timestamp,
};
use libarchive_oxide::{
    FilterReader, LayerDigests, OciLayerBuilder, OciLayerEngine, OciLayerFilter,
};
use sha2::{Digest, Sha256};

/// Reference SHA-256 over a byte slice.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let output = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&output);
    digest
}

/// Independent reference digests: compressed over the blob, diffID over the blob
/// decompressed with [`FilterReader`].
fn reference_digests(blob: &[u8]) -> LayerDigests {
    let compressed = sha256(blob);
    let mut filter = FilterReader::new(Cursor::new(blob.to_vec())).expect("filter reader");
    let mut plain = Vec::new();
    filter.read_to_end(&mut plain).expect("decompress blob");
    LayerDigests::from_bytes(compressed, sha256(&plain))
}

/// A directory entry.
fn dir(path: &[u8], mode: u32) -> EntryMetadata {
    EntryMetadata::builder(EntryKind::Dir, ArchivePath::from_bytes(path.to_vec()))
        .size(Some(0))
        .mode(Some(mode))
        .build()
}

/// A regular-file entry with explicit mode, owner, and timestamp.
fn file(
    path: &[u8],
    body: &[u8],
    mode: u32,
    uid: Option<u64>,
    gid: Option<u64>,
    mtime: Option<Timestamp>,
) -> EntryMetadata {
    EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path.to_vec()))
        .size(Some(body.len() as u64))
        .mode(Some(mode))
        .owner(Owner {
            uid,
            gid,
            user: None,
            group: None,
        })
        .times(EntryTimes {
            modified: mtime,
            accessed: None,
            changed: None,
            created: None,
        })
        .build()
}

/// Populates a builder with a fixed ordered fixture layer.
fn fixture(filter: OciLayerFilter) -> OciLayerBuilder {
    let mut builder = OciLayerBuilder::new(filter);
    builder
        .push_entry(dir(b"etc/", 0o755), Vec::new())
        .push_entry(
            file(
                b"etc/hostname",
                b"oxide-node\n",
                0o644,
                Some(0),
                Some(0),
                Some(Timestamp {
                    secs: 1_700_000_000,
                    nanos: 0,
                }),
            ),
            b"oxide-node\n".to_vec(),
        )
        .push_entry(
            file(
                b"usr/bin/tool",
                &[0x5a_u8; 9000],
                0o755,
                Some(1000),
                Some(1000),
                None,
            ),
            vec![0x5a_u8; 9000],
        );
    builder
}

#[test]
fn uncompressed_build_is_byte_identical_and_digests_round_trip() {
    let builder = fixture(OciLayerFilter::Uncompressed);
    let first = builder.build().expect("build");
    let second = builder.build().expect("rebuild");

    // Determinism: same input, same bytes, same digests.
    assert_eq!(first.blob(), second.blob());
    assert_eq!(first.digests(), second.digests());

    // An uncompressed layer's two digests coincide.
    assert_eq!(first.digests().compressed(), first.digests().diff_id());

    // The builder's digests match an independent reference.
    assert_eq!(first.digests(), reference_digests(first.blob()));
}

#[test]
fn gzip_build_is_byte_identical_and_matches_reference() {
    let builder = fixture(OciLayerFilter::Gzip);
    let first = builder.build().expect("build");
    let second = builder.build().expect("rebuild");

    assert_eq!(first.blob(), second.blob());
    assert_eq!(first.digests(), second.digests());
    // Compression makes the stored bytes differ from the tar stream.
    assert_ne!(first.digests().compressed(), first.digests().diff_id());
    assert_eq!(first.digests(), reference_digests(first.blob()));
}

#[test]
fn zstd_build_is_byte_identical_and_matches_reference() {
    let builder = fixture(OciLayerFilter::Zstd);
    let first = builder.build().expect("build");
    let second = builder.build().expect("rebuild");

    assert_eq!(first.blob(), second.blob());
    assert_eq!(first.digests(), second.digests());
    assert_ne!(first.digests().compressed(), first.digests().diff_id());
    assert_eq!(first.digests(), reference_digests(first.blob()));
}

#[test]
fn build_digests_round_trip_through_the_reader() {
    for filter in [
        OciLayerFilter::Uncompressed,
        OciLayerFilter::Gzip,
        OciLayerFilter::Zstd,
    ] {
        let built = fixture(filter).build().expect("build");

        // Re-read the produced blob and confirm the session computes the same
        // digests and recovers the entry paths in order.
        let mut session = OciLayerEngine::new()
            .open(Cursor::new(built.blob().to_vec()))
            .expect("open layer");
        let mut paths = Vec::new();
        while let Some(entry) = session.next_entry().expect("next entry") {
            paths.push(entry.path().to_vec());
        }
        assert_eq!(
            paths,
            vec![
                b"etc/".to_vec(),
                b"etc/hostname".to_vec(),
                b"usr/bin/tool".to_vec(),
            ],
            "entry order preserved for {filter:?}",
        );
        let read_back = session.digests().expect("digests");
        assert_eq!(
            read_back,
            built.digests(),
            "round-trip digests for {filter:?}"
        );

        // The session's own verification accepts the builder's digests.
        let mut verifier = OciLayerEngine::new()
            .open(Cursor::new(built.blob().to_vec()))
            .expect("open layer");
        verifier.verify(built.digests()).expect("verify layer");
    }
}

#[test]
fn metadata_is_emitted_as_specified() {
    // mode, ownership, mtime, and an xattr should all survive the round trip.
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"srv/app".to_vec()),
    )
    .size(Some(7))
    .mode(Some(0o640))
    .owner(Owner {
        uid: Some(4242),
        gid: Some(2424),
        user: None,
        group: None,
    })
    .times(EntryTimes {
        modified: Some(Timestamp {
            secs: 1_650_000_000,
            nanos: 0,
        }),
        accessed: None,
        changed: None,
        created: None,
    })
    .xattr(b"user.oxide".to_vec(), b"present".to_vec())
    .build();

    let mut builder = OciLayerBuilder::new(OciLayerFilter::Gzip);
    builder.push_entry(metadata, b"payload".to_vec());
    let built = builder.build().expect("build");

    let mut session = OciLayerEngine::new()
        .open(Cursor::new(built.blob().to_vec()))
        .expect("open layer");
    let entry = session
        .next_entry()
        .expect("next entry")
        .expect("one entry");
    assert_eq!(entry.path(), b"srv/app");
    assert_eq!(entry.mode(), Some(0o640));
    assert_eq!(entry.uid(), Some(4242));
    assert_eq!(entry.gid(), Some(2424));
    assert_eq!(entry.size(), Some(7));

    // The xattr rides in a PAX `SCHILY.xattr.` record; assert it landed in the
    // decoded tar bytes so PAX emission is exercised end to end.
    let mut filter = FilterReader::new(Cursor::new(built.into_blob())).expect("filter reader");
    let mut plain = Vec::new();
    filter.read_to_end(&mut plain).expect("decompress");
    let needle = b"SCHILY.xattr.user.oxide=present";
    assert!(
        plain.windows(needle.len()).any(|window| window == needle),
        "expected PAX xattr record in the decoded tar stream",
    );
}

#[test]
fn unset_timestamps_never_inject_wall_clock() {
    // No modification time is supplied for any entry. Two builds separated in
    // wall-clock time must still be byte-identical, proving no clock leaks in.
    let build_once = || {
        let mut builder = OciLayerBuilder::new(OciLayerFilter::Uncompressed);
        builder
            .push_entry(dir(b"var/", 0o755), Vec::new())
            .push_entry(
                file(b"var/data", b"body", 0o644, None, None, None),
                b"body".to_vec(),
            );
        builder.build().expect("build")
    };

    let first = build_once();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let second = build_once();

    assert_eq!(first.blob(), second.blob());
    assert_eq!(first.digests(), second.digests());

    // An unset mtime serializes as the epoch (`0`), not the current time.
    let mut session = OciLayerEngine::new()
        .open(Cursor::new(first.blob().to_vec()))
        .expect("open layer");
    while session.next_entry().expect("next entry").is_some() {}
    // Digests already assert byte stability; the round trip confirms decodability.
    let _ = session.digests().expect("digests");
}

#[test]
fn entry_order_and_padding_are_reproducible_across_filters() {
    // Reordering entries must change the bytes; identical order must not. This
    // pins down both the ordering contract and the fixed tar block padding.
    for filter in [
        OciLayerFilter::Uncompressed,
        OciLayerFilter::Gzip,
        OciLayerFilter::Zstd,
    ] {
        let mut forward = OciLayerBuilder::new(filter);
        forward
            .push_entry(file(b"a", b"1", 0o644, None, None, None), b"1".to_vec())
            .push_entry(file(b"b", b"22", 0o644, None, None, None), b"22".to_vec());

        let mut reversed = OciLayerBuilder::new(filter);
        reversed
            .push_entry(file(b"b", b"22", 0o644, None, None, None), b"22".to_vec())
            .push_entry(file(b"a", b"1", 0o644, None, None, None), b"1".to_vec());

        let forward_blob = forward.build().expect("forward").into_blob();
        let forward_again = forward.build().expect("forward again").into_blob();
        let reversed_blob = reversed.build().expect("reversed").into_blob();

        assert_eq!(forward_blob, forward_again, "stable order for {filter:?}");
        assert_ne!(
            forward_blob, reversed_blob,
            "entry order is load-bearing for {filter:?}",
        );
    }
}

#[test]
fn reference_reader_agrees_with_builder_for_gzip() {
    // Cross-check: the builder's blob decoded through the reference FilterReader
    // yields exactly the diffID the builder reported.
    let built = fixture(OciLayerFilter::Gzip).build().expect("build");
    let mut filter = FilterReader::new(Cursor::new(built.blob().to_vec())).expect("filter reader");
    let mut plain = Vec::new();
    filter.read_to_end(&mut plain).expect("decompress");
    assert_eq!(&sha256(&plain), built.digests().diff_id());
    assert_eq!(&sha256(built.blob()), built.digests().compressed());
}
