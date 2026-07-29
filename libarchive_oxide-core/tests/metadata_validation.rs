// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Validated metadata value-type and cross-field contracts.

#![allow(clippy::expect_used)]

use libarchive_oxide_core::{
    ArchivePath, Checksum, ChecksumAlgorithm, EntryKind, EntryMetadata, ErrorKind, PathEncoding,
    SparseExtent, Timestamp,
};

#[test]
fn encoded_paths_reject_invalid_utf8_and_utf16() {
    let utf8 = ArchivePath::try_from_encoded([0xff], PathEncoding::Utf8)
        .expect_err("invalid UTF-8 must be rejected");
    assert_eq!(utf8.kind(), ErrorKind::Malformed);

    let odd = ArchivePath::try_from_encoded([0x61], PathEncoding::Utf16Le)
        .expect_err("odd UTF-16LE byte length must be rejected");
    assert_eq!(odd.kind(), ErrorKind::Malformed);

    let surrogate = ArchivePath::try_from_encoded([0x00, 0xd8], PathEncoding::Utf16Le)
        .expect_err("unpaired UTF-16 surrogate must be rejected");
    assert_eq!(surrogate.kind(), ErrorKind::Malformed);
}

#[test]
fn timestamp_and_checksum_lengths_are_validated_at_construction() {
    assert_eq!(
        Timestamp::new(0, 1_000_000_000)
            .expect_err("one billion nanoseconds is outside a second")
            .kind(),
        ErrorKind::Malformed
    );
    assert_eq!(
        Checksum::new(ChecksumAlgorithm::Sha256, [0_u8; 31])
            .expect_err("SHA-256 must contain 32 bytes")
            .kind(),
        ErrorKind::Malformed
    );

    let checksum =
        Checksum::new(ChecksumAlgorithm::Sha256, [7_u8; 32]).expect("valid SHA-256 checksum");
    assert_eq!(checksum.algorithm(), ChecksumAlgorithm::Sha256);
    assert_eq!(checksum.as_bytes(), &[7; 32]);
}

#[test]
fn sparse_extents_reject_empty_overflowing_and_cross_field_invalid_layouts() {
    assert_eq!(
        SparseExtent::new(0, 0).expect_err("empty extent").kind(),
        ErrorKind::Malformed
    );
    assert_eq!(
        SparseExtent::new(u64::MAX, 1)
            .expect_err("overflowing extent")
            .kind(),
        ErrorKind::Malformed
    );

    let overlap = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("sparse"))
        .size(Some(20))
        .sparse_extent(SparseExtent::new(4, 8).expect("valid extent"))
        .sparse_extent(SparseExtent::new(8, 2).expect("valid extent"))
        .try_build()
        .expect_err("overlap must be rejected");
    assert_eq!(overlap.kind(), ErrorKind::Malformed);

    let beyond_size = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("sparse"))
        .size(Some(5))
        .sparse_extent(SparseExtent::new(4, 2).expect("valid extent"))
        .try_build()
        .expect_err("extent beyond declared size must be rejected");
    assert_eq!(beyond_size.kind(), ErrorKind::Malformed);
}

#[test]
fn metadata_builder_rejects_empty_paths_and_mismatched_link_targets() {
    let empty = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes([]))
        .try_build()
        .expect_err("empty path must be rejected");
    assert_eq!(empty.kind(), ErrorKind::Malformed);

    let missing_target = EntryMetadata::builder(EntryKind::Symlink, ArchivePath::from_utf8("link"))
        .try_build()
        .expect_err("symlink without target must be rejected");
    assert_eq!(missing_target.kind(), ErrorKind::Malformed);

    let unexpected_target = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("file"))
        .link_target(Some(ArchivePath::from_utf8("target")))
        .try_build()
        .expect_err("regular file with a link target must be rejected");
    assert_eq!(unexpected_target.kind(), ErrorKind::Malformed);
}
