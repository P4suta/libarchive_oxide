// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Split 7z volume reconstruction over the common bounded source model.

#![cfg(feature = "sevenz")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use libarchive_oxide::advanced::{
    MemoryReadAt, RangeReadError, RangeReadErrorKind, ReadAt, SevenZipVolumeProvider,
    SourceIdentity, SourceLimits, VolumeId, VolumeResolver, VolumeSet,
};
use libarchive_oxide::{
    ArchiveEngine, CreateOptions, EntryKind, EntryMetadata, Error, FormatId, FormatWriteOptions,
    OpenOptions, PasswordCandidates, Policy, ReaderEvent, SecretBytes, SevenZipCompression,
    SevenZipEncryption, SevenZipWriteOptions, VolumeArchiveReader,
};

struct Resolver {
    volumes: BTreeMap<VolumeId, Arc<dyn ReadAt>>,
    requests: AtomicU64,
}

impl VolumeResolver for Resolver {
    fn resolve(&self, volume: VolumeId) -> std::io::Result<Option<Arc<dyn ReadAt>>> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        Ok(self.volumes.get(&volume).cloned())
    }
}

fn source(index: usize, bytes: Vec<u8>) -> Arc<dyn ReadAt> {
    Arc::new(MemoryReadAt::new(
        bytes,
        SourceIdentity::try_new(format!("split-7z-volume-{index}-v1").into_bytes())
            .expect("valid source identity"),
    ))
}

fn volume_set(parts: Vec<Vec<u8>>, limits: SourceLimits) -> (Arc<VolumeSet>, Arc<Resolver>) {
    let mut parts = parts.into_iter().enumerate();
    let (_, primary) = parts.next().expect("split archive has a primary volume");
    let resolver = Arc::new(Resolver {
        volumes: parts
            .map(|(index, bytes)| {
                (
                    VolumeId::new(u32::try_from(index).expect("small volume index")),
                    source(index, bytes),
                )
            })
            .collect(),
        requests: AtomicU64::new(0),
    });
    let volumes = Arc::new(
        VolumeSet::new(source(0, primary), resolver.clone(), limits)
            .expect("create bounded volume set"),
    );
    (volumes, resolver)
}

fn write_archive(encryption: SevenZipEncryption, password: Option<&[u8]>) -> Vec<u8> {
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new()
                .with_compression(SevenZipCompression::Lzma2)
                .with_solid(false)
                .with_encryption(encryption),
        )));
    let output = Cursor::new(Vec::new());
    let mut writer = match password {
        Some(password) => ArchiveEngine::new()
            .create_seek_with_password(output, options, SecretBytes::new(password.to_vec()))
            .expect("create encrypted 7z writer"),
        None => ArchiveEngine::new()
            .create_seek(output, options)
            .expect("create 7z writer"),
    };
    for (path, payload) in [
        ("first.bin", b"first split-volume payload".repeat(17)),
        (
            "nested/second.bin",
            b"second split-volume payload".repeat(23),
        ),
    ] {
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            libarchive_oxide::ArchivePath::from_utf8(path),
        )
        .size(Some(u64::try_from(payload.len()).expect("payload length")))
        .build();
        writer.start_entry(&metadata).expect("start 7z entry");
        for chunk in payload.chunks(13) {
            writer.write_data(chunk).expect("write 7z payload");
        }
        writer.end_entry().expect("end 7z entry");
    }
    writer.finish().expect("finish 7z archive").into_inner()
}

fn split(bytes: &[u8], part_size: usize) -> Vec<Vec<u8>> {
    bytes.chunks(part_size).map(<[u8]>::to_vec).collect()
}

fn write_adjacent_parts(directory: &Path, parts: &[Vec<u8>]) -> PathBuf {
    let primary = directory.join("bundle.7z.001");
    for (index, bytes) in parts.iter().enumerate() {
        let physical = index + 1;
        fs::write(directory.join(format!("bundle.7z.{physical:03}")), bytes)
            .expect("write adjacent 7z volume");
    }
    primary
}

fn read_all(mut reader: VolumeArchiveReader) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut paths = Vec::new();
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("read split 7z event") {
            ReaderEvent::Entry(entry) => paths.push(entry.path().as_bytes().to_vec()),
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => return (paths, payload),
            _ => {},
        }
    }
}

fn typed_range(error: &Error) -> Option<RangeReadErrorKind> {
    error
        .io_error()
        .and_then(|io| io.get_ref())
        .and_then(|source| source.downcast_ref::<RangeReadError>())
        .copied()
        .map(RangeReadError::kind)
}

#[test]
fn common_volume_reader_detects_and_streams_split_sevenz() {
    let archive = write_archive(SevenZipEncryption::None, None);
    let parts = split(&archive, 29);
    assert!(
        parts.len() > 3,
        "fixture must cross several physical volumes"
    );
    let (volumes, resolver) = volume_set(parts.clone(), SourceLimits::safe());

    let reader = VolumeArchiveReader::new(volumes).expect("open split 7z");
    assert_eq!(reader.format(), FormatId::SevenZip);
    let (paths, payload) = read_all(reader);
    assert_eq!(
        paths,
        [b"first.bin".as_slice(), b"nested/second.bin".as_slice()]
    );
    let mut expected = b"first split-volume payload".repeat(17);
    expected.extend_from_slice(&b"second split-volume payload".repeat(23));
    assert_eq!(payload, expected);
    assert_eq!(
        resolver.requests.load(Ordering::Relaxed),
        u64::try_from(parts.len()).expect("part count"),
        "every additional volume and one terminating absence are resolved once"
    );

    let _provider = SevenZipVolumeProvider::new();
}

#[test]
fn archive_engine_inspects_plans_applies_and_rewinds_split_sevenz() {
    let archive = write_archive(SevenZipEncryption::None, None);
    let (volumes, resolver) = volume_set(split(&archive, 31), SourceLimits::safe());
    let options = OpenOptions::new().with_volumes(volumes);
    let mut session = ArchiveEngine::new()
        .open_volumes(&options)
        .expect("open split 7z engine session");

    let inspection = session.inspect().expect("inspect split 7z");
    assert_eq!(inspection.format(), FormatId::SevenZip);
    assert_eq!(inspection.entries().len(), 2);
    let plan = session.plan(Policy::safe()).expect("plan split 7z");
    let destination = tempfile::tempdir().expect("extraction directory");
    let root = Dir::open_ambient_dir(destination.path(), ambient_authority())
        .expect("open extraction capability");
    let report = session.apply(plan, root).expect("apply split 7z plan");
    assert!(!report.extraction().has_rejections());
    assert_eq!(
        std::fs::read(destination.path().join("first.bin")).expect("read first payload"),
        b"first split-volume payload".repeat(17)
    );
    assert_eq!(
        std::fs::read(destination.path().join("nested/second.bin")).expect("read second payload"),
        b"second split-volume payload".repeat(23)
    );
    session.rewind().expect("rewind split 7z session");
    assert_eq!(
        session.inspect().expect("reinspect split 7z").format(),
        FormatId::SevenZip
    );
    assert!(resolver.requests.load(Ordering::Relaxed) > 1);
}

#[test]
#[cfg(feature = "aes")]
fn split_sevenz_uses_common_password_candidates() {
    let password = b"split-7z-secret";
    let archive = write_archive(SevenZipEncryption::Aes256, Some(password));
    let (volumes, _) = volume_set(split(&archive, 37), SourceLimits::safe());
    let options = OpenOptions::new()
        .with_volumes(volumes)
        .with_password_provider(Arc::new(PasswordCandidates::new([
            SecretBytes::new(b"wrong first".to_vec()),
            SecretBytes::new(password.to_vec()),
        ])));
    let reader = VolumeArchiveReader::with_options(&options)
        .expect("open encrypted split 7z with ordered candidates");
    let (_, payload) = read_all(reader);
    let mut expected = b"first split-volume payload".repeat(17);
    expected.extend_from_slice(&b"second split-volume payload".repeat(23));
    assert_eq!(payload, expected);
}

#[test]
#[cfg(feature = "aes")]
fn split_sevenz_rejects_all_wrong_candidates_before_plaintext() {
    let archive = write_archive(SevenZipEncryption::Aes256, Some(b"correct-secret"));
    let (volumes, _) = volume_set(split(&archive, 43), SourceLimits::safe());
    let options = OpenOptions::new()
        .with_volumes(volumes)
        .with_password_provider(Arc::new(PasswordCandidates::new([
            SecretBytes::new(b"wrong one".to_vec()),
            SecretBytes::new(b"wrong two".to_vec()),
        ])));
    let mut reader = VolumeArchiveReader::with_options(&options)
        .expect("plaintext 7z header opens before folder authentication");
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::ArchiveMetadata(_)) => {},
            Ok(ReaderEvent::Data(_)) => panic!("wrong password exposed unauthenticated data"),
            Ok(event) => panic!("wrong password exposed event before authentication: {event:?}"),
            Err(error) => {
                assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Integrity);
                break;
            },
        }
    }
}

#[test]
#[cfg(feature = "aes")]
fn split_sevenz_rejects_one_wrong_candidate_before_plaintext() {
    let archive = write_archive(SevenZipEncryption::Aes256, Some(b"correct-secret"));
    let (volumes, _) = volume_set(split(&archive, 47), SourceLimits::safe());
    let options = OpenOptions::new()
        .with_volumes(volumes)
        .with_password_provider(Arc::new(PasswordCandidates::new([SecretBytes::new(
            b"only wrong candidate".to_vec(),
        )])));
    let mut reader = VolumeArchiveReader::with_options(&options)
        .expect("plaintext 7z header opens before folder authentication");
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::ArchiveMetadata(_)) => {},
            Ok(ReaderEvent::Data(_)) => panic!("wrong password exposed unauthenticated data"),
            Ok(event) => panic!("wrong password exposed event before authentication: {event:?}"),
            Err(error) => {
                assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Integrity);
                break;
            },
        }
    }
}

#[test]
fn split_sevenz_enforces_exact_volume_count_and_aggregate_bytes() {
    let archive = write_archive(SevenZipEncryption::None, None);
    let parts = split(&archive, 41);
    let count = u32::try_from(parts.len()).expect("part count");
    let total = u64::try_from(archive.len()).expect("archive length");

    let (volumes, _) = volume_set(
        parts.clone(),
        SourceLimits::safe().with_volumes(Some(count)),
    );
    VolumeArchiveReader::new(volumes).expect("exact physical volume count is accepted");

    let (volumes, _) = volume_set(
        parts.clone(),
        SourceLimits::safe().with_volumes(Some(count - 1)),
    );
    let error = VolumeArchiveReader::new(volumes).expect_err("volume count must be bounded");
    assert_eq!(
        typed_range(&error),
        Some(RangeReadErrorKind::VolumeCountExceeded)
    );

    let (volumes, _) = volume_set(
        parts,
        SourceLimits::safe().with_volume_bytes(Some(total - 1)),
    );
    let error = VolumeArchiveReader::new(volumes).expect_err("aggregate bytes must be bounded");
    assert_eq!(
        typed_range(&error),
        Some(RangeReadErrorKind::VolumeBytesExceeded)
    );
}

#[test]
fn format_specific_reader_rejects_incoherent_common_options() {
    let archive = write_archive(SevenZipEncryption::None, None);
    let (volumes, _) = volume_set(split(&archive, 53), SourceLimits::safe());
    for options in [
        OpenOptions::new()
            .with_volumes(Arc::clone(&volumes))
            .with_source_limits(SourceLimits::unlimited()),
        OpenOptions::new()
            .with_volumes(Arc::clone(&volumes))
            .with_adjacent_volume_discovery(true),
        OpenOptions::new()
            .with_volumes(Arc::clone(&volumes))
            .with_filter(Some(libarchive_oxide::FilterId::Base64)),
    ] {
        let error = libarchive_oxide::advanced::SevenZipVolumeReader::with_options(&options)
            .expect_err("incoherent split 7z options must fail before decode");
        assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Capability);
    }
}

#[test]
fn path_open_discovers_adjacent_sevenz_only_after_explicit_opt_in() {
    let archive = write_archive(SevenZipEncryption::None, None);
    let parts = split(&archive, 31);
    let directory = tempfile::tempdir().expect("volume directory");
    let primary = write_adjacent_parts(directory.path(), &parts);

    let disabled = ArchiveEngine::new()
        .open_path_with_options(&primary, &OpenOptions::new())
        .expect_err("path discovery must require explicit opt-in");
    assert_eq!(disabled.kind(), libarchive_oxide::ErrorKind::Capability);

    let mut session = ArchiveEngine::new()
        .open_path_with_options(
            &primary,
            &OpenOptions::new().with_adjacent_volume_discovery(true),
        )
        .expect("open adjacent split 7z");
    let inspection = session.inspect().expect("inspect adjacent split 7z");
    assert_eq!(inspection.format(), FormatId::SevenZip);
    assert_eq!(inspection.entries().len(), 2);
}

#[test]
#[cfg(feature = "aes")]
fn path_open_preserves_ordered_password_candidates() {
    let password = b"adjacent-volume-secret";
    let archive = write_archive(SevenZipEncryption::Aes256, Some(password));
    let parts = split(&archive, 37);
    let directory = tempfile::tempdir().expect("volume directory");
    let primary = write_adjacent_parts(directory.path(), &parts);
    let options = OpenOptions::new()
        .with_adjacent_volume_discovery(true)
        .with_password_provider(Arc::new(PasswordCandidates::new([
            SecretBytes::new(b"wrong first".to_vec()),
            SecretBytes::new(password.to_vec()),
        ])));

    let mut session = ArchiveEngine::new()
        .open_path_with_options(&primary, &options)
        .expect("open encrypted adjacent split 7z");
    assert_eq!(
        session
            .inspect()
            .expect("authenticate and inspect")
            .format(),
        FormatId::SevenZip
    );
}

#[test]
fn path_open_rejects_ambiguous_volume_names_and_prebuilt_sets() {
    let archive = write_archive(SevenZipEncryption::None, None);
    let directory = tempfile::tempdir().expect("volume directory");
    let malformed = directory.path().join("bundle.7z");
    fs::write(&malformed, &archive).expect("write unsuffixed archive");
    let not_primary = directory.path().join("bundle.7z.002");
    fs::write(&not_primary, &archive).expect("write non-primary volume");
    let discover = OpenOptions::new().with_adjacent_volume_discovery(true);

    for path in [&malformed, &not_primary] {
        let error = ArchiveEngine::new()
            .open_path_with_options(path, &discover)
            .expect_err("ambiguous adjacent-volume name must fail closed");
        assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Capability);
    }

    let (volumes, _) = volume_set(split(&archive, 31), SourceLimits::safe());
    let error = ArchiveEngine::new()
        .open_path_with_options(
            directory.path().join("bundle.7z.001"),
            &discover.with_volumes(volumes),
        )
        .expect_err("path discovery and caller-owned volumes are mutually exclusive");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Capability);
}

#[test]
fn path_open_fails_closed_on_missing_volume_and_source_limits() {
    let archive = write_archive(SevenZipEncryption::None, None);
    let parts = split(&archive, 31);
    assert!(parts.len() > 2, "fixture must have an interior volume");
    let directory = tempfile::tempdir().expect("volume directory");
    let primary = write_adjacent_parts(directory.path(), &parts);
    fs::remove_file(directory.path().join("bundle.7z.002")).expect("remove interior volume");
    let discover = OpenOptions::new().with_adjacent_volume_discovery(true);

    ArchiveEngine::new()
        .open_path_with_options(&primary, &discover)
        .expect_err("missing interior volume must not be skipped");

    fs::write(directory.path().join("bundle.7z.002"), &parts[1]).expect("restore interior volume");
    let error = ArchiveEngine::new()
        .open_path_with_options(
            &primary,
            &discover.with_source_limits(SourceLimits::safe().with_volumes(Some(1))),
        )
        .expect_err("adjacent discovery must enforce the source count limit");
    assert_eq!(
        typed_range(&error),
        Some(RangeReadErrorKind::VolumeCountExceeded)
    );
}
