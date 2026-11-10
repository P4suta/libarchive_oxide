// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Archive transcoder public-contract tests.

#![allow(clippy::expect_used, clippy::panic)]

use std::io::{Cursor, Read};

use libarchive_oxide::{
    ArchivePath, ArchiveTranscoder, ArchiveWriter, CreateOptions, EntryKind, EntryMetadata,
    EntryTimes, Extension, FormatId, MetadataField, MetadataLossPolicy, OpenOptions, Owner,
    ReaderEvent, Timestamp,
};

fn rich_tar() -> Vec<u8> {
    let times = EntryTimes {
        modified: Some(
            Timestamp::new(1_700_000_000, 123_456_789).expect("valid modification timestamp"),
        ),
        accessed: Some(Timestamp::new(1_700_000_001, 0).expect("valid access timestamp")),
        changed: None,
        created: None,
    };
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("hello.txt"))
        .size(Some(11))
        .mode(Some(0o640))
        .owner(Owner {
            uid: Some(1000),
            gid: Some(1001),
            user: Some(b"alice".to_vec()),
            group: Some(b"staff".to_vec()),
        })
        .times(times)
        .xattr(b"user.color".to_vec(), b"blue".to_vec())
        .comment(Some(b"source comment".to_vec()))
        .try_build()
        .expect("valid rich metadata");
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Tar).expect("tar writer");
    writer.start_entry(&metadata).expect("start rich entry");
    writer.write_data(b"hello world").expect("write rich body");
    writer.end_entry().expect("end rich entry");
    writer.finish().expect("finish rich tar")
}

#[test]
fn seek_transcoder_streams_payload_and_reports_exact_xar_metadata_loss() {
    let outcome = ArchiveTranscoder::new()
        .transcode_to_seek(
            Cursor::new(rich_tar()),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Xar),
        )
        .expect("transcode tar to XAR");

    assert_eq!(outcome.report().entries(), 1);
    assert_eq!(outcome.report().payload_bytes(), 11);
    let fields: Vec<_> = outcome
        .report()
        .metadata_losses()
        .iter()
        .map(libarchive_oxide::MetadataLoss::field)
        .collect();
    assert_eq!(
        fields,
        [
            MetadataField::OwnerNames,
            MetadataField::AccessedTime,
            MetadataField::ExtendedAttributes,
            MetadataField::EntryComment,
            MetadataField::EntryExtensions,
        ]
    );
    assert!(outcome.report().metadata_losses().iter().all(|loss| {
        loss.entry_index() == Some(0)
            && loss
                .path()
                .is_some_and(|path| path.as_bytes() == b"hello.txt")
    }));

    let output = outcome.into_output();
    let mut reader = libarchive_oxide::SeekArchiveReader::with_options(
        output,
        &OpenOptions::new().with_format(Some(FormatId::Xar)),
    )
    .expect("open transcoded XAR");
    let metadata = loop {
        match reader.next_event().expect("read XAR entry event") {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => break metadata,
            event => panic!("unexpected event before XAR entry: {event:?}"),
        }
    };
    assert_eq!(metadata.path().as_bytes(), b"hello.txt");
    assert_eq!(metadata.mode(), Some(0o640));
    assert_eq!(metadata.owner().uid, Some(1000));
    assert_eq!(metadata.owner().gid, Some(1001));
    assert_eq!(
        metadata
            .times()
            .modified
            .expect("XAR modification time")
            .nanoseconds(),
        123_456_789
    );
    match reader.next_event().expect("read XAR payload") {
        ReaderEvent::Data(bytes) => assert_eq!(bytes, b"hello world"),
        event => panic!("expected data, got {event:?}"),
    }
    assert!(matches!(
        reader.next_event().expect("read XAR end-entry"),
        ReaderEvent::EndEntry
    ));
    assert!(matches!(
        reader.next_event().expect("read XAR completion"),
        ReaderEvent::Done
    ));
}

#[test]
fn metadata_loss_can_be_rejected_before_the_entry_is_started() {
    let error = ArchiveTranscoder::new()
        .with_metadata_loss_policy(MetadataLossPolicy::Reject)
        .transcode_to_seek(
            Cursor::new(rich_tar()),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Xar),
        )
        .expect_err("loss rejection must fail closed");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Unsupported);
    assert!(error.to_string().contains("metadata loss"));
}

#[test]
fn tar_symlink_transcodes_to_metadata_owned_zip_target() {
    let target = ArchivePath::from_utf8("../target.txt");
    let metadata = EntryMetadata::builder(EntryKind::Symlink, ArchivePath::from_utf8("link"))
        .size(Some(0))
        .link_target(Some(target.clone()))
        .build();
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Tar).unwrap();
    writer.start_entry(&metadata).unwrap();
    writer.end_entry().unwrap();
    let source = writer.finish().unwrap();

    let outcome = ArchiveTranscoder::new()
        .transcode_to_seek(
            Cursor::new(source),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Zip),
        )
        .expect("transcode Tar symlink to ZIP");
    assert_eq!(
        outcome.report().metadata_losses()[0].field(),
        MetadataField::DeclaredSize
    );
    let zip = outcome.into_output().into_inner();
    let mut reader =
        libarchive_oxide::SeekArchiveReader::new(Cursor::new(zip.clone())).expect("open ZIP");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(decoded) = reader.next_event().unwrap() else {
        panic!("ZIP symlink entry missing");
    };
    assert_eq!(decoded.kind(), EntryKind::Symlink);
    assert_eq!(decoded.link_target(), Some(&target));

    let reencoded = ArchiveTranscoder::new()
        .transcode_seek(
            Cursor::new(zip),
            &OpenOptions::new().with_format(Some(FormatId::Zip)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Zip),
        )
        .expect("re-encode ZIP symlink");
    assert_eq!(reencoded.report().metadata_losses(), []);
    let mut reader =
        libarchive_oxide::SeekArchiveReader::new(reencoded.into_output()).expect("open second ZIP");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(decoded) = reader.next_event().unwrap() else {
        panic!("re-encoded ZIP symlink entry missing");
    };
    assert_eq!(decoded.kind(), EntryKind::Symlink);
    assert_eq!(decoded.link_target(), Some(&target));
}

#[cfg(feature = "sevenz")]
#[test]
fn tar_symlink_transcodes_to_metadata_owned_sevenz_target() {
    let target = ArchivePath::from_utf8("../target.txt");
    let metadata = EntryMetadata::builder(EntryKind::Symlink, ArchivePath::from_utf8("link"))
        .size(Some(0))
        .link_target(Some(target.clone()))
        .build();
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Tar).unwrap();
    writer.start_entry(&metadata).unwrap();
    writer.end_entry().unwrap();
    let source = writer.finish().unwrap();

    let outcome = ArchiveTranscoder::new()
        .transcode_to_seek(
            Cursor::new(source),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::SevenZip),
        )
        .expect("transcode Tar symlink to 7z");
    assert!(
        outcome
            .report()
            .metadata_losses()
            .iter()
            .any(|loss| loss.field() == MetadataField::DeclaredSize)
    );
    let archive = outcome.into_output().into_inner();
    let mut reader =
        libarchive_oxide::SeekArchiveReader::new(Cursor::new(archive)).expect("open transcoded 7z");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(decoded) = reader.next_event().unwrap() else {
        panic!("7z symlink entry missing");
    };
    assert_eq!(decoded.kind(), EntryKind::Symlink);
    assert_eq!(decoded.link_target(), Some(&target));
}

#[test]
fn sequential_transcoder_copies_large_entry_without_whole_payload_buffering() {
    let payload = vec![0x5a; 3 * 64 * 1024 + 17];
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("large.bin"))
        .size(Some(payload.len() as u64))
        .try_build()
        .expect("valid large metadata");
    let mut source = ArchiveWriter::with_format(Vec::new(), FormatId::Tar).expect("tar writer");
    source.start_entry(&metadata).expect("start large entry");
    source.write_data(&payload).expect("write large entry");
    source.end_entry().expect("end large entry");
    let source = source.finish().expect("finish large tar");

    let outcome = ArchiveTranscoder::new()
        .transcode(
            Cursor::new(source),
            &OpenOptions::new(),
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Zip),
        )
        .expect("transcode tar to ZIP");
    assert_eq!(outcome.report().payload_bytes(), payload.len() as u64);
    assert_eq!(outcome.report().metadata_losses(), []);

    let mut reader = libarchive_oxide::SeekArchiveReader::with_options(
        Cursor::new(outcome.into_output()),
        &OpenOptions::new().with_format(Some(FormatId::Zip)),
    )
    .expect("open transcoded ZIP");
    loop {
        match reader.next_event().expect("read ZIP entry event") {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(_) => break,
            event => panic!("unexpected event before entry: {event:?}"),
        }
    }
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("read ZIP payload event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::EndEntry => break,
            event => panic!("unexpected event: {event:?}"),
        }
    }
    assert_eq!(decoded, payload);
}

#[test]
fn loss_report_limit_and_metadata_only_destination_fail_closed() {
    let error = ArchiveTranscoder::new()
        .with_maximum_metadata_losses(3)
        .transcode_to_seek(
            Cursor::new(rich_tar()),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Xar),
        )
        .expect_err("four losses must exceed a three-record report limit");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);

    let error = ArchiveTranscoder::new()
        .transcode(
            Cursor::new(rich_tar()),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Mtree),
        )
        .expect_err("mtree destination would discard entry bodies");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Unsupported);
    assert!(error.to_string().contains("metadata-only destination"));
}

#[test]
fn seek_source_supports_both_sequential_and_seek_destinations() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("tiny.txt"))
        .size(Some(4))
        .try_build()
        .expect("valid tiny metadata");
    let mut zip = ArchiveWriter::with_format(Vec::new(), FormatId::Zip).expect("ZIP writer");
    zip.start_entry(&metadata).expect("start ZIP entry");
    zip.write_data(b"tiny").expect("write ZIP body");
    zip.end_entry().expect("end ZIP entry");
    let zip = zip.finish().expect("finish ZIP");
    let source = OpenOptions::new().with_format(Some(FormatId::Zip));

    let tar = ArchiveTranscoder::new()
        .transcode_from_seek(
            Cursor::new(zip.clone()),
            &source,
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Tar),
        )
        .expect("transcode seek ZIP to sequential tar");
    assert_eq!(tar.report().payload_bytes(), 4);
    assert_eq!(tar.report().metadata_losses(), []);

    let xar = ArchiveTranscoder::new()
        .transcode_seek(
            Cursor::new(zip),
            &source,
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Xar),
        )
        .expect("transcode seek ZIP to seek XAR");
    assert_eq!(xar.report().entries(), 1);
    assert_eq!(xar.report().payload_bytes(), 4);
    assert_eq!(xar.report().metadata_losses(), []);
}

#[test]
fn destination_timestamp_quantization_is_reported() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("time.bin"))
        .size(Some(0))
        .times(EntryTimes {
            modified: Some(Timestamp::new(1_700_000_000, 123_456_789).expect("valid timestamp")),
            accessed: None,
            changed: None,
            created: None,
        })
        .try_build()
        .expect("valid timestamp metadata");
    let mut tar = ArchiveWriter::with_format(Vec::new(), FormatId::Tar).expect("tar writer");
    tar.start_entry(&metadata).expect("start timestamp entry");
    tar.end_entry().expect("end timestamp entry");
    let tar = tar.finish().expect("finish timestamp tar");

    let zip = ArchiveTranscoder::new()
        .transcode(
            Cursor::new(tar.clone()),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Zip),
        )
        .expect("transcode timestamp to ZIP");
    assert_eq!(
        zip.report().metadata_losses()[0].field(),
        MetadataField::ModifiedTime
    );

    for format in [FormatId::Cpio, FormatId::Ar] {
        let outcome = ArchiveTranscoder::new()
            .transcode(
                Cursor::new(tar.clone()),
                &OpenOptions::new().with_format(Some(FormatId::Tar)),
                Vec::new(),
                CreateOptions::new().with_format(format),
            )
            .expect("transcode fractional timestamp to whole-second format");
        assert_eq!(
            outcome.report().metadata_losses()[0].field(),
            MetadataField::ModifiedTime
        );
    }

    let iso = ArchiveTranscoder::new()
        .transcode_to_seek(
            Cursor::new(tar),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Iso9660),
        )
        .expect("transcode timestamp to ISO");
    assert_eq!(
        iso.report().metadata_losses()[0].field(),
        MetadataField::ModifiedTime
    );
}

#[test]
fn destination_timestamp_range_loss_is_reported() {
    let source = |timestamp| {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("range-time.bin"))
                .size(Some(0))
                .times(EntryTimes {
                    modified: Some(timestamp),
                    ..EntryTimes::default()
                })
                .try_build()
                .expect("valid source timestamp");
        let mut tar = ArchiveWriter::with_format(Vec::new(), FormatId::Tar).expect("tar writer");
        tar.start_entry(&metadata).expect("start timestamp entry");
        tar.end_entry().expect("end timestamp entry");
        tar.finish().expect("finish timestamp tar")
    };

    let iso = ArchiveTranscoder::new()
        .transcode_to_seek(
            Cursor::new(source(Timestamp::from_seconds(253_402_300_800))),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Iso9660),
        )
        .expect("out-of-range ISO time must be projected explicitly");
    assert!(
        iso.report()
            .metadata_losses()
            .iter()
            .any(|loss| loss.field() == MetadataField::ModifiedTime)
    );

    let sevenz = ArchiveTranscoder::new()
        .transcode_to_seek(
            Cursor::new(source(Timestamp::from_seconds(-11_644_473_601))),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::SevenZip),
        )
        .expect("out-of-range 7z time must be projected explicitly");
    assert!(
        sevenz
            .report()
            .metadata_losses()
            .iter()
            .any(|loss| loss.field() == MetadataField::ModifiedTime)
    );
}

#[test]
fn iso_entry_comment_is_reported_as_metadata_loss() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("comment.bin"))
        .size(Some(0))
        .comment(Some(b"not representable in ISO".to_vec()))
        .build();
    let mut tar = ArchiveWriter::with_format(Vec::new(), FormatId::Tar).unwrap();
    tar.start_entry(&metadata).unwrap();
    tar.end_entry().unwrap();
    let outcome = ArchiveTranscoder::new()
        .transcode_to_seek(
            Cursor::new(tar.finish().unwrap()),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Iso9660),
        )
        .expect("ISO transcoder must project unsupported entry comments");
    assert!(
        outcome
            .report()
            .metadata_losses()
            .iter()
            .any(|loss| loss.field() == MetadataField::EntryComment)
    );
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_structural_file_properties_are_reported_as_archive_metadata_loss() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("empty.bin"))
        .size(Some(0))
        .build();
    let mut source = libarchive_oxide::SeekArchiveWriter::with_format(
        Cursor::new(Vec::new()),
        FormatId::SevenZip,
        libarchive_oxide::Limits::default(),
    )
    .expect("7z source writer");
    source.start_entry(&metadata).expect("start 7z entry");
    source.end_entry().expect("end 7z entry");
    let source = source.finish().expect("finish 7z source").into_inner();

    let outcome = ArchiveTranscoder::new()
        .transcode_seek(
            Cursor::new(source),
            &OpenOptions::new().with_format(Some(FormatId::SevenZip)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::SevenZip),
        )
        .expect("7z transcoder must project structural raw properties");
    assert!(
        outcome
            .report()
            .metadata_losses()
            .iter()
            .any(|loss| loss.field() == MetadataField::ArchiveExtensions)
    );
}

#[test]
fn zip_empty_comments_are_reported_as_metadata_loss() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("empty.txt"))
        .size(Some(0))
        .comment(Some(Vec::new()))
        .build();
    let mut tar = ArchiveWriter::with_format(Vec::new(), FormatId::Tar).expect("tar writer");
    tar.set_archive_metadata(&libarchive_oxide::ArchiveMetadata::new().with_comment(Vec::new()))
        .expect("empty Tar global comment");
    tar.start_entry(&metadata).expect("empty Tar entry comment");
    tar.end_entry().expect("end Tar entry");

    let outcome = ArchiveTranscoder::new()
        .transcode_to_seek(
            Cursor::new(tar.finish().expect("finish Tar source")),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Zip),
        )
        .expect("ZIP transcoder must project empty comments");
    let losses = outcome.report().metadata_losses();
    assert!(
        losses
            .iter()
            .any(|loss| loss.field() == MetadataField::ArchiveComment)
    );
    assert!(
        losses
            .iter()
            .any(|loss| loss.field() == MetadataField::EntryComment)
    );
}

#[test]
fn cpio_inode_and_link_count_transcode_losslessly_to_iso() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("inode.bin"))
        .size(Some(0))
        .inode_and_links(Some(42), Some(1))
        .build();
    let mut cpio = ArchiveWriter::with_format(Vec::new(), FormatId::Cpio).expect("cpio writer");
    cpio.start_entry(&metadata).expect("cpio entry");
    cpio.end_entry().expect("end cpio entry");

    let outcome = ArchiveTranscoder::new()
        .transcode_to_seek(
            Cursor::new(cpio.finish().expect("finish cpio source")),
            &OpenOptions::new().with_format(Some(FormatId::Cpio)),
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Iso9660),
        )
        .expect("cpio inode metadata to ISO");
    assert!(
        !outcome
            .report()
            .metadata_losses()
            .iter()
            .any(|loss| loss.field() == MetadataField::InodeAndLinkCount)
    );

    let mut reader = libarchive_oxide::SeekArchiveReader::new(outcome.into_output())
        .expect("open transcoded ISO");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(decoded) = reader.next_event().unwrap() else {
        panic!("transcoded ISO entry missing");
    };
    assert_eq!(decoded.inode(), Some(42));
    assert_eq!(decoded.links(), Some(1));
}

#[test]
fn zip_owner_range_loss_is_reported_instead_of_silently_dropped() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("owner.bin"))
        .size(Some(0))
        .owner(Owner {
            uid: Some(70_000),
            gid: Some(1),
            user: None,
            group: None,
        })
        .try_build()
        .expect("valid owner metadata");
    let mut tar = ArchiveWriter::with_format(Vec::new(), FormatId::Tar).expect("tar writer");
    tar.start_entry(&metadata).expect("start owner entry");
    tar.end_entry().expect("end owner entry");
    let tar = tar.finish().expect("finish owner tar");

    let zip = ArchiveTranscoder::new()
        .transcode(
            Cursor::new(tar),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Zip),
        )
        .expect("transcode owner to ZIP");
    assert_eq!(
        zip.report().metadata_losses()[0].field(),
        MetadataField::OwnerIds
    );
}

#[test]
fn warc_transcode_reports_the_synthesized_entry_path() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("not-encoded"))
        .size(Some(4))
        .mode(Some(0o644))
        .extension(Extension::new(
            "warc",
            b"WARC-Type".to_vec(),
            b"resource".to_vec(),
        ))
        .extension(Extension::new(
            "warc",
            b"WARC-Record-ID".to_vec(),
            b"<urn:uuid:path-loss>".to_vec(),
        ))
        .extension(Extension::new(
            "warc",
            b"WARC-Date".to_vec(),
            b"2026-08-15T00:00:00Z".to_vec(),
        ))
        .build();
    let mut source = ArchiveWriter::with_format(Vec::new(), FormatId::Warc).unwrap();
    source.start_entry(&metadata).unwrap();
    source.write_data(b"body").unwrap();
    source.end_entry().unwrap();

    let outcome = ArchiveTranscoder::new()
        .transcode(
            Cursor::new(source.finish().unwrap()),
            &OpenOptions::new().with_format(Some(FormatId::Warc)),
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Warc),
        )
        .expect("WARC re-encoding must preserve record data");
    assert_eq!(
        outcome
            .report()
            .metadata_losses()
            .iter()
            .map(libarchive_oxide::MetadataLoss::field)
            .collect::<Vec<_>>(),
        [MetadataField::EntryPath]
    );

    let mut reader = libarchive_oxide::ArchiveReader::with_options(
        Cursor::new(outcome.into_output()),
        &OpenOptions::new().with_format(Some(FormatId::Warc)),
    )
    .expect("open transcoded WARC");
    let mut entry = reader
        .next_entry()
        .unwrap()
        .expect("transcoded WARC record");
    let mut body = Vec::new();
    entry.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"body");
}
