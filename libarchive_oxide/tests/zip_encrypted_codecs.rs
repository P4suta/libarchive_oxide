// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encrypted ZIP wrappers combined with non-Deflate streaming codecs.

#![cfg(feature = "aes")]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::io::{Cursor, Read, Write};

#[cfg(feature = "async")]
use libarchive_oxide::AsyncArchiveWriter;
#[cfg(feature = "tokio")]
use libarchive_oxide::TokioArchiveWriter;
#[cfg(any(feature = "async", feature = "tokio"))]
use libarchive_oxide::ZipMethod;
use libarchive_oxide::{
    AesStrength, ArchiveEngine, ArchivePath, CreateOptions, EntryKind, EntryMetadata, Error,
    FormatId, FormatWriteOptions, Limits, ReaderEvent, SecretBytes, SeekArchiveReader,
    ZipCompression, ZipEncryption, ZipWriteOptions,
};
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;

const PASSWORD: &[u8] = b"combined codec password";
const PAYLOAD: &[u8] = b"encrypted codec combinations must authenticate after decompression\n";

fn compressions() -> Vec<(ZipCompression, zip::CompressionMethod, bool)> {
    vec![
        #[cfg(feature = "bzip2")]
        (ZipCompression::Bzip2, zip::CompressionMethod::Bzip2, true),
        #[cfg(feature = "zstd")]
        (ZipCompression::Zstd, zip::CompressionMethod::Zstd, true),
        #[cfg(feature = "xz")]
        (ZipCompression::Xz, zip::CompressionMethod::XZ, true),
        #[cfg(feature = "xz")]
        (ZipCompression::Lzma, zip::CompressionMethod::Lzma, false),
        #[cfg(feature = "ppmd")]
        (ZipCompression::Ppmd8, zip::CompressionMethod::Ppmd, true),
    ]
}

#[derive(Clone, Copy)]
enum IndependentEncryption {
    Aes256,
    ZipCrypto,
}

#[cfg(any(feature = "async", feature = "tokio"))]
fn owned_streaming_methods() -> Vec<ZipMethod> {
    vec![
        #[cfg(feature = "xz")]
        ZipMethod::Lzma,
        #[cfg(feature = "ppmd")]
        ZipMethod::Ppmd8,
    ]
}

fn create_with_arca(
    compression: ZipCompression,
    encryption: ZipEncryption,
    payload: &[u8],
) -> Vec<u8> {
    let options = CreateOptions::new()
        .with_format(FormatId::Zip)
        .with_format_options(Some(FormatWriteOptions::Zip(
            ZipWriteOptions::new()
                .with_compression(compression)
                .with_encryption(encryption),
        )));
    let mut writer = ArchiveEngine::new()
        .create_with_password(Vec::new(), options, SecretBytes::from(PASSWORD))
        .expect("combined encrypted ZIP writer");
    let metadata =
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("payload.bin")).build();
    writer.start_entry(&metadata).unwrap();
    for chunk in payload.chunks(31) {
        writer.write_data(chunk).unwrap();
    }
    writer.end_entry().unwrap();
    writer.finish().unwrap()
}

fn read_result_with_arca(
    archive: Vec<u8>,
    password: &[u8],
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    let mut reader = SeekArchiveReader::with_limits_and_password(
        Cursor::new(archive),
        limits,
        SecretBytes::from(password),
    )?;
    let mut output = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Data(bytes) => output.extend_from_slice(bytes),
            ReaderEvent::Done => return Ok(output),
            _ => {},
        }
    }
}

fn read_with_arca(archive: Vec<u8>) -> Vec<u8> {
    read_result_with_arca(archive, PASSWORD, Limits::default()).unwrap()
}

fn read_with_zip_crate(archive: Vec<u8>) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(archive)).unwrap();
    let mut member = archive.by_index_decrypt(0, PASSWORD).unwrap();
    let mut output = Vec::new();
    member.read_to_end(&mut output).unwrap();
    output
}

fn create_with_zip_crate(
    method: zip::CompressionMethod,
    encryption: IndependentEncryption,
    payload: &[u8],
) -> Vec<u8> {
    let mut output = Cursor::new(Vec::new());
    {
        let mut writer = zip::write::ZipWriter::new(&mut output);
        let options = match encryption {
            IndependentEncryption::Aes256 => SimpleFileOptions::default()
                .compression_method(method)
                .with_aes_encryption(zip::AesMode::Aes256, std::str::from_utf8(PASSWORD).unwrap()),
            IndependentEncryption::ZipCrypto => SimpleFileOptions::default()
                .compression_method(method)
                .with_deprecated_encryption(PASSWORD)
                .unwrap(),
        };
        writer.start_file("payload.bin", options).unwrap();
        writer.write_all(payload).unwrap();
        writer.finish().unwrap();
    }
    output.into_inner()
}

#[test]
fn aes_combines_with_every_streaming_zip_codec_both_directions() {
    let payload = PAYLOAD.repeat(512);
    for (compression, method, independent_writer) in compressions() {
        let arca = create_with_arca(
            compression,
            ZipEncryption::Aes(AesStrength::Bits256),
            &payload,
        );
        assert_eq!(read_with_zip_crate(arca.clone()), payload);
        assert_eq!(read_with_arca(arca), payload);

        if independent_writer {
            let independent =
                create_with_zip_crate(method, IndependentEncryption::Aes256, &payload);
            assert_eq!(read_with_arca(independent), payload);
        }
    }
}

#[test]
fn zipcrypto_combines_with_every_streaming_zip_codec_both_directions() {
    let payload = PAYLOAD.repeat(512);
    for (compression, method, independent_writer) in compressions() {
        let arca = create_with_arca(compression, ZipEncryption::ZipCrypto, &payload);
        assert_eq!(read_with_zip_crate(arca.clone()), payload);
        assert_eq!(read_with_arca(arca), payload);

        if independent_writer {
            let independent =
                create_with_zip_crate(method, IndependentEncryption::ZipCrypto, &payload);
            assert_eq!(read_with_arca(independent), payload);
        }
    }
}

#[test]
fn encrypted_codec_combinations_reject_wrong_passwords_and_aes_tampering() {
    let payload = PAYLOAD.repeat(128);
    for (compression, _, _) in compressions() {
        let aes = create_with_arca(
            compression,
            ZipEncryption::Aes(AesStrength::Bits256),
            &payload,
        );
        assert!(read_result_with_arca(aes.clone(), b"incorrect", Limits::default()).is_err());
        let mut tampered = aes;
        let central = tampered
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .expect("central directory");
        let descriptor = tampered[..central]
            .windows(4)
            .rposition(|window| window == b"PK\x07\x08")
            .expect("data descriptor");
        tampered[descriptor - 1] ^= 0x80;
        assert!(read_result_with_arca(tampered, PASSWORD, Limits::default()).is_err());

        let zipcrypto = create_with_arca(compression, ZipEncryption::ZipCrypto, &payload);
        let error = read_result_with_arca(zipcrypto, b"incorrect", Limits::default())
            .expect_err("ZipCrypto password verifier must reject a wrong password");
        assert_eq!(
            error.archive_error().expect("archive error").kind(),
            libarchive_oxide::ErrorKind::Integrity,
            "{compression:?}"
        );
    }
}

#[test]
fn encrypted_codec_combinations_honor_decoded_total_limit() {
    let payload = vec![0x5a; 128 * 1024];
    let limits = Limits::default().with_decoded_total(Some(4096));
    for (compression, _, _) in compressions() {
        for encryption in [
            ZipEncryption::Aes(AesStrength::Bits256),
            ZipEncryption::ZipCrypto,
        ] {
            let archive = create_with_arca(compression, encryption, &payload);
            let error = read_result_with_arca(archive, PASSWORD, limits)
                .expect_err("decoded-total limit must reject the payload");
            assert_eq!(
                error.archive_error().expect("archive error").kind(),
                libarchive_oxide::ErrorKind::Limit
            );
        }
    }
}

#[cfg(feature = "async")]
#[test]
fn futures_writer_streams_encrypted_lzma_and_ppmd8() {
    futures_lite::future::block_on(async {
        let payload = PAYLOAD.repeat(128);
        for method in owned_streaming_methods() {
            let output = futures_lite::io::Cursor::new(Vec::new());
            let mut writer = AsyncArchiveWriter::with_zip_password(
                output,
                method,
                SecretBytes::from(PASSWORD),
                Limits::default(),
            );
            let metadata =
                EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("payload.bin"))
                    .build();
            writer.start_entry(&metadata).await.unwrap();
            for chunk in payload.chunks(31) {
                writer.write_data(chunk).await.unwrap();
            }
            writer.end_entry().await.unwrap();
            let archive = writer.finish().await.unwrap().into_inner();
            assert_eq!(read_with_arca(archive), payload);
        }
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_writer_streams_zipcrypto_lzma_and_ppmd8() {
    let payload = PAYLOAD.repeat(128);
    for method in owned_streaming_methods() {
        let mut writer = TokioArchiveWriter::with_zipcrypto_password(
            Vec::new(),
            method,
            SecretBytes::from(PASSWORD),
            Limits::default(),
        );
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("payload.bin")).build();
        writer.start_entry(&metadata).await.unwrap();
        for chunk in payload.chunks(31) {
            writer.write_data(chunk).await.unwrap();
        }
        writer.end_entry().await.unwrap();
        let archive = writer.finish().await.unwrap();
        assert_eq!(read_with_arca(archive), payload);
    }
}
