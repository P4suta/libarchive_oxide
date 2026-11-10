// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed high-level writer-option contracts.

#![allow(clippy::expect_used)]

use std::io::Cursor;

use libarchive_oxide::{
    AesStrength, ArchiveEngine, CreateOptions, EntryKind, EntryMetadata, FormatId,
    FormatWriteOptions, Limits, ReaderEvent, SeekArchiveReader, SevenZipCompression,
    SevenZipEncryption, SevenZipFilter, SevenZipWriteOptions, XarCompression, XarWriteOptions,
    ZipCompression, ZipEncryption, ZipWriteOptions,
};

fn file() -> libarchive_oxide::EntryMetadata {
    EntryMetadata::builder(
        EntryKind::File,
        libarchive_oxide::ArchivePath::from_utf8("payload.bin"),
    )
    .size(Some(3))
    .build()
}

#[test]
fn xar_options_are_typed_and_container_scoped() {
    let xar = XarWriteOptions::new().with_compression(XarCompression::Zlib);
    assert_eq!(xar.compression(), XarCompression::Zlib);
    let format_options = FormatWriteOptions::Xar(xar);
    let options = CreateOptions::new()
        .with_format(FormatId::Xar)
        .with_format_options(Some(format_options));
    assert_eq!(options.format_options(), Some(format_options));

    let mismatch = CreateOptions::new()
        .with_format(FormatId::Zip)
        .with_format_options(Some(format_options));
    let error = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), mismatch)
        .expect_err("XAR options must not configure ZIP");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Capability);
}

#[test]
fn zip_store_is_selected_through_create_options() {
    let format_options =
        FormatWriteOptions::Zip(ZipWriteOptions::new().with_compression(ZipCompression::Store));
    let options = CreateOptions::new()
        .with_format(FormatId::Zip)
        .with_format_options(Some(format_options));
    assert_eq!(options.format_options(), Some(format_options));

    let mut writer = ArchiveEngine::new()
        .create(Vec::new(), options)
        .expect("ZIP Store writer");
    writer.start_entry(&file()).expect("start entry");
    writer.write_data(b"abc").expect("write entry");
    writer.end_entry().expect("end entry");
    let archive = writer.finish().expect("finish ZIP");
    assert_eq!(&archive[..4], b"PK\x03\x04");
    assert_eq!(u16::from_le_bytes([archive[8], archive[9]]), 0);
}

#[test]
fn encryption_without_a_password_fails_before_output_is_returned() {
    let options = CreateOptions::new()
        .with_format(FormatId::Zip)
        .with_format_options(Some(FormatWriteOptions::Zip(
            ZipWriteOptions::new().with_encryption(ZipEncryption::Aes(AesStrength::Bits256)),
        )));
    let error = ArchiveEngine::new()
        .create(Vec::new(), options)
        .expect_err("encrypted ZIP needs an explicit secret");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Capability);
}

#[test]
#[cfg(feature = "sevenz")]
fn sevenz_encryption_without_a_password_fails_before_output_is_returned() {
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_encryption(SevenZipEncryption::Aes256),
        )));
    let error = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect_err("encrypted 7z needs an explicit secret");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Capability);
}

#[test]
#[cfg(feature = "aes")]
fn zip_aes_all_strengths_roundtrip_and_record_their_strength() {
    for (strength, expected_code) in [
        (AesStrength::Bits128, 1),
        (AesStrength::Bits192, 2),
        (AesStrength::Bits256, 3),
    ] {
        let options = CreateOptions::new()
            .with_format(FormatId::Zip)
            .with_format_options(Some(FormatWriteOptions::Zip(
                ZipWriteOptions::new()
                    .with_compression(ZipCompression::Store)
                    .with_encryption(ZipEncryption::Aes(strength)),
            )));
        let password = b"strength-specific secret";
        let mut writer = ArchiveEngine::new()
            .create_with_password(
                Vec::new(),
                options,
                libarchive_oxide::SecretBytes::new(password.to_vec()),
            )
            .expect("WinZip AES writer");
        writer.start_entry(&file()).expect("start entry");
        writer.write_data(b"abc").expect("write entry");
        writer.end_entry().expect("end entry");
        let archive = writer.finish().expect("finish encrypted ZIP");

        let extra_start = 30 + "payload.bin".len();
        assert_eq!(
            &archive[extra_start..extra_start + 2],
            &0x9901_u16.to_le_bytes()
        );
        assert_eq!(archive[extra_start + 8], expected_code);

        let mut reader = SeekArchiveReader::with_password(
            Cursor::new(archive),
            libarchive_oxide::SecretBytes::new(password.to_vec()),
        )
        .expect("open encrypted ZIP");
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().expect("encrypted ZIP event") {
                ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, b"abc");
    }
}

#[test]
#[cfg(feature = "aes")]
fn zip_aes_256_store_profile_roundtrips() {
    let options = CreateOptions::new()
        .with_format(FormatId::Zip)
        .with_format_options(Some(FormatWriteOptions::Zip(
            ZipWriteOptions::new()
                .with_compression(ZipCompression::Store)
                .with_encryption(ZipEncryption::Aes(AesStrength::Bits256)),
        )));
    let password = b"format options secret";
    let mut writer = ArchiveEngine::new()
        .create_with_password(
            Vec::new(),
            options,
            libarchive_oxide::SecretBytes::new(password.to_vec()),
        )
        .expect("AES-256 Store writer");
    writer.start_entry(&file()).expect("start entry");
    writer.write_data(b"abc").expect("write entry");
    writer.end_entry().expect("end entry");
    let archive = writer.finish().expect("finish encrypted ZIP");
    assert_eq!(u16::from_le_bytes([archive[8], archive[9]]), 99);

    let mut reader = libarchive_oxide::SeekArchiveReader::with_password(
        Cursor::new(archive),
        libarchive_oxide::SecretBytes::new(password.to_vec()),
    )
    .expect("open encrypted ZIP");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("encrypted ZIP event") {
            libarchive_oxide::ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            libarchive_oxide::ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, b"abc");
}

#[test]
#[cfg(all(feature = "aes", feature = "sevenz"))]
fn sevenz_aes_256_writer_roundtrips_and_authenticates() {
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new()
                .with_compression(SevenZipCompression::Lzma2)
                .with_filter(Some(SevenZipFilter::Delta(3)))
                .with_encryption(SevenZipEncryption::Aes256),
        )));
    let password = b"7z format options secret";
    let payload = b"encrypted solid payload".repeat(257);
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        libarchive_oxide::ArchivePath::from_utf8("secret.bin"),
    )
    .size(Some(payload.len() as u64))
    .build();
    let mut writer = ArchiveEngine::new()
        .create_seek_with_password(
            Cursor::new(Vec::new()),
            options,
            libarchive_oxide::SecretBytes::new(password.to_vec()),
        )
        .expect("7z AES-256 writer");
    writer.start_entry(&metadata).expect("start AES entry");
    for chunk in payload.chunks(73) {
        writer.write_data(chunk).expect("stream AES payload");
    }
    writer.end_entry().expect("end AES entry");
    let archive = writer.finish().expect("finish encrypted 7z").into_inner();

    let mut reader = SeekArchiveReader::with_password(
        Cursor::new(archive.clone()),
        libarchive_oxide::SecretBytes::new(password.to_vec()),
    )
    .expect("open encrypted 7z");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("encrypted 7z event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);

    let mut wrong = SeekArchiveReader::with_password(
        Cursor::new(archive),
        libarchive_oxide::SecretBytes::new(b"wrong password".to_vec()),
    )
    .expect("plain header lists with a wrong password");
    let error = loop {
        match wrong.next_event() {
            Ok(ReaderEvent::Done) => panic!("wrong 7z password unexpectedly succeeded"),
            Ok(_) => {},
            Err(error) => break error,
        }
    };
    assert_eq!(
        error.kind(),
        libarchive_oxide::ErrorKind::Integrity,
        "{error:?}"
    );
}

#[test]
#[cfg(feature = "sevenz")]
fn sevenz_writer_options_accept_the_implemented_profile() {
    let format_options = FormatWriteOptions::SevenZip(
        SevenZipWriteOptions::new()
            .with_compression(SevenZipCompression::Lzma2)
            .with_solid(true)
            .with_encryption(SevenZipEncryption::None),
    );
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(format_options));
    let writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("implemented solid LZMA2 profile");
    assert_eq!(writer.format(), FormatId::SevenZip);
}

#[test]
#[cfg(feature = "sevenz")]
fn sevenz_store_writer_streams_and_roundtrips() {
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_compression(SevenZipCompression::Store),
        )));
    let mut writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("7z Store writer");
    writer.start_entry(&file()).expect("start Store entry");
    writer.write_data(b"abc").expect("stream Store payload");
    writer.end_entry().expect("end Store entry");
    let output = writer.finish().expect("finish Store archive").into_inner();
    assert_eq!(&output[32..35], b"abc");

    let mut reader = SeekArchiveReader::new(Cursor::new(output)).expect("open Store archive");
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("read Store event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"abc");

    let zero_workspace = Limits::safe().with_codec_memory(Some(0));
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_compression(SevenZipCompression::Store),
        )));
    ArchiveEngine::new()
        .with_limits(zero_workspace)
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("Store has no compression dictionary allocation");
}

#[test]
#[cfg(feature = "sevenz")]
fn sevenz_non_solid_store_writer_emits_one_folder_per_stream() {
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new()
                .with_compression(SevenZipCompression::Store)
                .with_solid(false),
        )));
    let mut writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("non-solid 7z Store writer");
    for (name, payload) in [
        ("first.bin", b"first payload".as_slice()),
        ("second.bin", b"second payload is different".as_slice()),
    ] {
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            libarchive_oxide::ArchivePath::from_utf8(name),
        )
        .size(Some(payload.len() as u64))
        .build();
        writer.start_entry(&metadata).expect("start folder entry");
        for chunk in payload.chunks(3) {
            writer.write_data(chunk).expect("stream folder payload");
        }
        writer.end_entry().expect("end folder entry");
    }
    for (kind, name) in [
        (EntryKind::File, "empty.bin"),
        (EntryKind::Dir, "empty-dir"),
    ] {
        let metadata = EntryMetadata::builder(kind, libarchive_oxide::ArchivePath::from_utf8(name))
            .size(Some(0))
            .build();
        writer.start_entry(&metadata).expect("start empty entry");
        writer.end_entry().expect("end empty entry");
    }
    let archive = writer.finish().expect("finish non-solid 7z").into_inner();
    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).expect("open non-solid 7z");
    let mut entries = Vec::<Vec<u8>>::new();
    loop {
        match reader.next_event().expect("non-solid event") {
            ReaderEvent::Entry(_) => entries.push(Vec::new()),
            ReaderEvent::Data(bytes) => entries.last_mut().expect("active entry").extend(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(
        entries,
        [
            b"first payload".to_vec(),
            b"second payload is different".to_vec(),
            Vec::new(),
            Vec::new(),
        ]
    );
}

#[test]
#[cfg(feature = "sevenz")]
fn sevenz_deflate_writer_streams_and_roundtrips_with_bounded_workspace() {
    let payload = b"bounded raw deflate payload\n".repeat(4096);
    let metadata = libarchive_oxide::EntryMetadata::builder(
        EntryKind::File,
        libarchive_oxide::ArchivePath::from_utf8("deflate/payload.bin"),
    )
    .size(Some(payload.len() as u64))
    .try_build()
    .expect("Deflate metadata");
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_compression(SevenZipCompression::Deflate),
        )));
    let mut writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("7z Deflate writer");
    writer.start_entry(&metadata).expect("start Deflate entry");
    for chunk in payload.chunks(37) {
        writer.write_data(chunk).expect("stream Deflate payload");
    }
    writer.end_entry().expect("end Deflate entry");
    let output = writer
        .finish()
        .expect("finish Deflate archive")
        .into_inner();
    let packed_size = u64::from_le_bytes(output[12..20].try_into().expect("packed size"));
    assert!(packed_size < payload.len() as u64);

    let mut reader = SeekArchiveReader::new(Cursor::new(output)).expect("open Deflate archive");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("read Deflate event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);

    let below_workspace = Limits::safe().with_codec_memory(Some(512 * 1024 - 1));
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_compression(SevenZipCompression::Deflate),
        )));
    let error = ArchiveEngine::new()
        .with_limits(below_workspace)
        .create_seek(Cursor::new(Vec::new()), options)
        .expect_err("Deflate workspace must be checked before creation");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);
}

#[test]
#[cfg(feature = "sevenz")]
fn sevenz_lzma_writer_streams_and_roundtrips_with_bounded_dictionary() {
    let payload = b"bounded LZMA1 payload\n".repeat(4096);
    let metadata = libarchive_oxide::EntryMetadata::builder(
        EntryKind::File,
        libarchive_oxide::ArchivePath::from_utf8("lzma/payload.bin"),
    )
    .size(Some(payload.len() as u64))
    .try_build()
    .expect("LZMA metadata");
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_compression(SevenZipCompression::Lzma),
        )));
    let mut writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("7z LZMA writer");
    writer.start_entry(&metadata).expect("start LZMA entry");
    for chunk in payload.chunks(41) {
        writer.write_data(chunk).expect("stream LZMA payload");
    }
    writer.end_entry().expect("end LZMA entry");
    let output = writer.finish().expect("finish LZMA archive").into_inner();
    let packed_size = u64::from_le_bytes(output[12..20].try_into().expect("packed size"));
    assert!(packed_size < payload.len() as u64);

    let mut reader = SeekArchiveReader::new(Cursor::new(output)).expect("open LZMA archive");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("read LZMA event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);

    let below_dictionary = Limits::safe().with_codec_memory(Some((1 << 23) - 1));
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_compression(SevenZipCompression::Lzma),
        )));
    let error = ArchiveEngine::new()
        .with_limits(below_dictionary)
        .create_seek(Cursor::new(Vec::new()), options)
        .expect_err("LZMA dictionary must be checked before creation");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);
}

#[test]
#[cfg(all(feature = "sevenz", feature = "bzip2"))]
fn sevenz_bzip2_writer_streams_and_roundtrips_with_bounded_workspace() {
    let payload = b"bounded BZip2 payload\n".repeat(4096);
    let metadata = libarchive_oxide::EntryMetadata::builder(
        EntryKind::File,
        libarchive_oxide::ArchivePath::from_utf8("bzip2/payload.bin"),
    )
    .size(Some(payload.len() as u64))
    .try_build()
    .expect("BZip2 metadata");
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_compression(SevenZipCompression::Bzip2),
        )));
    let mut writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("7z BZip2 writer");
    writer.start_entry(&metadata).expect("start BZip2 entry");
    for chunk in payload.chunks(43) {
        writer.write_data(chunk).expect("stream BZip2 payload");
    }
    writer.end_entry().expect("end BZip2 entry");
    let output = writer.finish().expect("finish BZip2 archive").into_inner();
    let packed_size = u64::from_le_bytes(output[12..20].try_into().expect("packed size"));
    assert!(packed_size < payload.len() as u64);

    let mut reader = SeekArchiveReader::new(Cursor::new(output)).expect("open BZip2 archive");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("read BZip2 event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);

    let below_workspace = Limits::safe().with_codec_memory(Some(8 * 1024 * 1024 - 1));
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_compression(SevenZipCompression::Bzip2),
        )));
    let error = ArchiveEngine::new()
        .with_limits(below_workspace)
        .create_seek(Cursor::new(Vec::new()), options)
        .expect_err("BZip2 workspace must be checked before creation");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);
}

#[test]
#[cfg(all(feature = "sevenz", feature = "zstd"))]
fn sevenz_zstd_writer_streams_and_roundtrips_with_bounded_workspace() {
    let payload = b"bounded Zstandard payload\n".repeat(4096);
    let metadata = libarchive_oxide::EntryMetadata::builder(
        EntryKind::File,
        libarchive_oxide::ArchivePath::from_utf8("zstd/payload.bin"),
    )
    .size(Some(payload.len() as u64))
    .try_build()
    .expect("Zstandard metadata");
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_compression(SevenZipCompression::Zstd),
        )));
    let mut writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("7z Zstandard writer");
    writer
        .start_entry(&metadata)
        .expect("start Zstandard entry");
    for chunk in payload.chunks(47) {
        writer.write_data(chunk).expect("stream Zstandard payload");
    }
    writer.end_entry().expect("end Zstandard entry");
    let output = writer
        .finish()
        .expect("finish Zstandard archive")
        .into_inner();
    assert_eq!(&output[32..36], &[0x28, 0xb5, 0x2f, 0xfd]);

    let mut reader = SeekArchiveReader::new(Cursor::new(output)).expect("open Zstandard archive");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("read Zstandard event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);

    let zero_workspace = Limits::safe().with_codec_memory(Some(0));
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_compression(SevenZipCompression::Zstd),
        )));
    let error = ArchiveEngine::new()
        .with_limits(zero_workspace)
        .create_seek(Cursor::new(Vec::new()), options)
        .expect_err("Zstandard workspace must be checked before creation");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);
}

#[test]
#[cfg(feature = "sevenz")]
fn sevenz_ppmd7_writer_streams_and_roundtrips_with_bounded_model() {
    let payload = b"bounded PPMd7 payload\n".repeat(4096);
    let metadata = libarchive_oxide::EntryMetadata::builder(
        EntryKind::File,
        libarchive_oxide::ArchivePath::from_utf8("ppmd7/payload.bin"),
    )
    .size(Some(payload.len() as u64))
    .try_build()
    .expect("PPMd7 metadata");
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_compression(SevenZipCompression::Ppmd7),
        )));
    let mut writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("7z PPMd7 writer");
    writer.start_entry(&metadata).expect("start PPMd7 entry");
    for chunk in payload.chunks(53) {
        writer.write_data(chunk).expect("stream PPMd7 payload");
    }
    writer.end_entry().expect("end PPMd7 entry");
    let output = writer.finish().expect("finish PPMd7 archive").into_inner();
    let packed_size = u64::from_le_bytes(output[12..20].try_into().expect("packed size"));
    assert!(packed_size < payload.len() as u64);

    let mut reader = SeekArchiveReader::new(Cursor::new(output)).expect("open PPMd7 archive");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("read PPMd7 event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);

    let below_model = Limits::safe().with_codec_memory(Some((1 << 20) - 1));
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_compression(SevenZipCompression::Ppmd7),
        )));
    let error = ArchiveEngine::new()
        .with_limits(below_model)
        .create_seek(Cursor::new(Vec::new()), options)
        .expect_err("PPMd7 model must be checked before creation");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Limit);
}

#[test]
#[cfg(feature = "sevenz")]
fn sevenz_delta_filter_writer_streams_and_roundtrips() {
    let payload: Vec<u8> = (0_u8..=255).cycle().take(96 * 1024).collect();
    let metadata = libarchive_oxide::EntryMetadata::builder(
        EntryKind::File,
        libarchive_oxide::ArchivePath::from_utf8("delta/payload.bin"),
    )
    .size(Some(payload.len() as u64))
    .try_build()
    .expect("Delta metadata");
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new().with_filter(Some(SevenZipFilter::Delta(4))),
        )));
    let mut writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("7z Delta writer");
    writer.start_entry(&metadata).expect("start Delta entry");
    for chunk in payload.chunks(59) {
        writer.write_data(chunk).expect("stream Delta payload");
    }
    writer.end_entry().expect("end Delta entry");
    let output = writer.finish().expect("finish Delta archive").into_inner();

    let mut reader = SeekArchiveReader::new(Cursor::new(output)).expect("open Delta archive");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("read Delta event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, payload);

    for invalid in [0, 257] {
        let options = CreateOptions::new()
            .with_format(FormatId::SevenZip)
            .with_format_options(Some(FormatWriteOptions::SevenZip(
                SevenZipWriteOptions::new().with_filter(Some(SevenZipFilter::Delta(invalid))),
            )));
        let error = ArchiveEngine::new()
            .create_seek(Cursor::new(Vec::new()), options)
            .expect_err("invalid Delta distance must fail before creation");
        assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Malformed);
    }
}

#[test]
#[cfg(feature = "sevenz")]
fn sevenz_bcj_filter_writers_stream_and_roundtrip() {
    let mut payload = Vec::new();
    for index in 0_u32..4096 {
        payload.push(0xe8);
        payload.extend_from_slice(&index.wrapping_mul(17).to_le_bytes());
        payload.extend_from_slice(&[0x00, 0x00, 0x00]);
    }
    let filters = [
        SevenZipFilter::BcjX86,
        SevenZipFilter::BcjPowerPc,
        SevenZipFilter::BcjIa64,
        SevenZipFilter::BcjArm,
        SevenZipFilter::BcjArmThumb,
        SevenZipFilter::BcjArm64,
        SevenZipFilter::BcjSparc,
        SevenZipFilter::BcjRiscV,
    ];
    for filter in filters {
        let metadata = libarchive_oxide::EntryMetadata::builder(
            EntryKind::File,
            libarchive_oxide::ArchivePath::from_utf8("bcj/payload.bin"),
        )
        .size(Some(payload.len() as u64))
        .try_build()
        .expect("BCJ metadata");
        let options = CreateOptions::new()
            .with_format(FormatId::SevenZip)
            .with_format_options(Some(FormatWriteOptions::SevenZip(
                SevenZipWriteOptions::new().with_filter(Some(filter)),
            )));
        let mut writer = ArchiveEngine::new()
            .create_seek(Cursor::new(Vec::new()), options)
            .expect("7z BCJ writer");
        writer.start_entry(&metadata).expect("start BCJ entry");
        for chunk in payload.chunks(67) {
            writer.write_data(chunk).expect("stream BCJ payload");
        }
        writer.end_entry().expect("end BCJ entry");
        let output = writer.finish().expect("finish BCJ archive").into_inner();

        let mut reader = SeekArchiveReader::new(Cursor::new(output)).expect("open BCJ archive");
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().expect("read BCJ event") {
                ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, payload, "BCJ round-trip failed for {filter:?}");
    }
}

#[test]
fn sevenz_non_solid_lzma2_profile_is_accepted() {
    let options = CreateOptions::new()
        .with_format(FormatId::SevenZip)
        .with_format_options(Some(FormatWriteOptions::SevenZip(
            SevenZipWriteOptions::new()
                .with_filter(Some(SevenZipFilter::BcjX86))
                .with_solid(false),
        )));
    let mut writer = ArchiveEngine::new()
        .create_seek(Cursor::new(Vec::new()), options)
        .expect("7z non-solid LZMA2 writer");
    let payloads = [
        b"first x86 payload".repeat(300),
        b"second x86 payload".repeat(170),
    ];
    for (index, payload) in payloads.iter().enumerate() {
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            libarchive_oxide::ArchivePath::from_utf8(format!("{index}.bin")),
        )
        .size(Some(payload.len() as u64))
        .build();
        writer
            .start_entry(&metadata)
            .expect("start non-solid entry");
        for chunk in payload.chunks(61) {
            writer.write_data(chunk).expect("write non-solid entry");
        }
        writer.end_entry().expect("end non-solid entry");
    }
    let bytes = writer
        .finish()
        .expect("finish non-solid LZMA2")
        .into_inner();
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes)).expect("open non-solid LZMA2");
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("non-solid LZMA2 event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(
        decoded,
        [payloads[0].as_slice(), payloads[1].as_slice()].concat()
    );
}

#[test]
#[cfg(all(feature = "sevenz", feature = "bzip2", feature = "zstd"))]
fn sevenz_non_solid_compressors_roundtrip_multiple_folders() {
    let compressions = [
        SevenZipCompression::Store,
        SevenZipCompression::Lzma,
        SevenZipCompression::Lzma2,
        SevenZipCompression::Ppmd7,
        SevenZipCompression::Deflate,
        SevenZipCompression::Bzip2,
        SevenZipCompression::Zstd,
    ];
    let payloads = [
        b"alpha non-solid payload".repeat(97),
        b"bravo folder".repeat(181),
    ];
    for compression in compressions {
        let options = CreateOptions::new()
            .with_format(FormatId::SevenZip)
            .with_format_options(Some(FormatWriteOptions::SevenZip(
                SevenZipWriteOptions::new()
                    .with_compression(compression)
                    .with_filter(Some(SevenZipFilter::Delta(2)))
                    .with_solid(false),
            )));
        let mut writer = ArchiveEngine::new()
            .create_seek(Cursor::new(Vec::new()), options)
            .expect("non-solid compressor writer");
        for (index, payload) in payloads.iter().enumerate() {
            let metadata = EntryMetadata::builder(
                EntryKind::File,
                libarchive_oxide::ArchivePath::from_utf8(format!("{index}.bin")),
            )
            .size(Some(payload.len() as u64))
            .build();
            writer
                .start_entry(&metadata)
                .expect("start compressed folder");
            for chunk in payload.chunks(47) {
                writer.write_data(chunk).expect("write compressed folder");
            }
            writer.end_entry().expect("finish compressed folder");
        }
        let bytes = writer
            .finish()
            .expect("finish non-solid archive")
            .into_inner();
        let mut reader =
            SeekArchiveReader::new(Cursor::new(bytes)).expect("open non-solid archive");
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().expect("non-solid compressor event") {
                ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(
            decoded,
            [payloads[0].as_slice(), payloads[1].as_slice()].concat(),
            "non-solid round-trip failed for {compression:?}"
        );
    }
}

#[test]
fn format_specific_options_cannot_target_another_container() {
    let options = CreateOptions::new()
        .with_format(FormatId::Tar)
        .with_format_options(Some(FormatWriteOptions::Zip(ZipWriteOptions::new())));
    let error = ArchiveEngine::new()
        .create(Vec::new(), options)
        .expect_err("ZIP options on tar must fail closed");
    assert_eq!(error.kind(), libarchive_oxide::ErrorKind::Capability);
}
