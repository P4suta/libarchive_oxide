// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Common archive-opening option contracts.

#![allow(clippy::expect_used, clippy::panic)]

use std::io::Cursor;
#[cfg(feature = "async")]
use std::pin::Pin;
use std::sync::Arc;
#[cfg(feature = "async")]
use std::task::{Context, Poll};

use libarchive_oxide::advanced::{MemoryReadAt, SourceIdentity};
use libarchive_oxide::{
    ArchivePath, ArchiveReader, ArchiveWriter, EntryKind, EntryMetadata, ErrorKind, FilterId,
    FormatId, Limits, OpenOptions, PasswordCandidates, RangeArchiveReader, ReaderEvent,
    SecretBytes, SeekArchiveReader, SourceLimits,
};

#[cfg(feature = "async")]
#[derive(Debug)]
struct AsyncOneByte {
    bytes: Vec<u8>,
    position: usize,
}

#[cfg(feature = "async")]
impl futures_io::AsyncRead for AsyncOneByte {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        if output.is_empty() || self.position == self.bytes.len() {
            return Poll::Ready(Ok(0));
        }
        output[0] = self.bytes[self.position];
        self.position += 1;
        Poll::Ready(Ok(1))
    }
}

#[cfg(feature = "async")]
#[test]
fn async_stream_reader_uses_the_same_options() {
    futures_lite::future::block_on(async {
        let options = OpenOptions::new().with_format(Some(FormatId::Raw));
        let input = futures_lite::io::Cursor::new(b"async payload".to_vec());
        let mut reader = libarchive_oxide::AsyncArchiveReader::with_options(input, &options)
            .expect("explicit async raw reader");
        let mut payload = Vec::new();
        loop {
            match reader.next_event().await.expect("async raw event") {
                ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(payload, b"async payload");
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_stream_reader_uses_the_same_options() {
    let options = OpenOptions::new().with_format(Some(FormatId::Raw));
    let input = Cursor::new(b"tokio payload".to_vec());
    let mut reader = libarchive_oxide::TokioArchiveReader::with_options(input, &options)
        .expect("explicit Tokio raw reader");
    let mut payload = Vec::new();
    loop {
        match reader.next_event().await.expect("Tokio raw event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"tokio payload");
}

#[cfg(feature = "async")]
#[test]
fn async_seek_reader_uses_the_same_options() {
    futures_lite::future::block_on(async {
        let options = OpenOptions::new().with_format(Some(FormatId::Zip));
        let input = futures_lite::io::Cursor::new(empty_zip());
        let reader = libarchive_oxide::AsyncSeekArchiveReader::with_options(input, &options)
            .await
            .expect("explicit async ZIP reader");
        assert_eq!(reader.format(), FormatId::Zip);
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_seek_reader_uses_the_same_options() {
    let options = OpenOptions::new().with_format(Some(FormatId::Zip));
    let reader =
        libarchive_oxide::TokioSeekArchiveReader::with_options(Cursor::new(empty_zip()), &options)
            .await
            .expect("explicit Tokio ZIP reader");
    assert_eq!(reader.format(), FormatId::Zip);
}

fn empty_zip() -> Vec<u8> {
    b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec()
}

#[test]
fn open_options_defaults_are_finite_and_debug_is_secret_safe() {
    let options = OpenOptions::new().with_password_provider(Arc::new(PasswordCandidates::new([
        SecretBytes::new(b"first".to_vec()),
        SecretBytes::new(b"second".to_vec()),
    ])));

    assert_eq!(options.limits(), Limits::safe());
    assert_eq!(options.source_limits(), SourceLimits::safe());
    assert_eq!(options.format(), None);
    assert_eq!(options.filter(), None);
    assert_eq!(options.maximum_password_candidates(), 16);
    let debug = format!("{options:?}");
    assert!(debug.contains("password_provider: true"));
    assert!(!debug.contains("first"));
    assert!(!debug.contains("second"));
}

#[test]
fn explicit_format_is_shared_by_the_sync_stream_reader() {
    let options = OpenOptions::new().with_format(Some(FormatId::Raw));
    let mut reader = ArchiveReader::with_options(Cursor::new(b"payload"), &options)
        .expect("explicit raw reader");

    assert!(matches!(
        reader.next_event(),
        Ok(ReaderEvent::ArchiveMetadata(_))
    ));
    assert!(matches!(reader.next_event(), Ok(ReaderEvent::Entry(_))));
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("raw payload event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::EndEntry => break,
            event => panic!("unexpected raw payload event: {event:?}"),
        }
    }
    assert_eq!(payload, b"payload");
    assert!(matches!(reader.next_event(), Ok(ReaderEvent::Done)));
}

#[test]
fn explicit_outer_filter_is_shared_by_the_sync_stream_reader() {
    let encoded = lzma_tar();
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Tar))
        .with_filter(Some(FilterId::Lzma));
    assert_eq!(options.filter(), Some(FilterId::Lzma));
    let mut reader = ArchiveReader::with_options(Cursor::new(encoded), &options)
        .expect("explicit LZMA options reader");
    assert_eq!(collect_payload_sync(&mut reader), b"payload");
}

#[test]
fn explicit_base64_filter_uses_the_common_options() {
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Tar))
        .with_filter(Some(FilterId::Base64));
    let mut reader = ArchiveReader::with_options(Cursor::new(base64_tar()), &options)
        .expect("explicit Base64 options reader");
    assert_eq!(collect_payload_sync(&mut reader), b"payload");
}

#[test]
fn explicit_framed_filter_uses_the_common_options() {
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Tar))
        .with_filter(Some(FilterId::Gzip));
    let mut reader =
        ArchiveReader::with_options(Cursor::new(filtered_tar(FilterId::Gzip)), &options)
            .expect("explicit gzip options reader");
    assert_eq!(collect_payload_sync(&mut reader), b"payload");
}

#[cfg(feature = "async")]
#[test]
fn explicit_framed_filter_uses_the_async_common_options() {
    futures_lite::future::block_on(async {
        let options = OpenOptions::new()
            .with_format(Some(FormatId::Tar))
            .with_filter(Some(FilterId::Gzip));
        let input = futures_lite::io::Cursor::new(filtered_tar(FilterId::Gzip));
        let mut reader = libarchive_oxide::AsyncArchiveReader::with_options(input, &options)
            .expect("explicit async gzip options reader");
        let mut payload = Vec::new();
        loop {
            match reader.next_event().await.expect("async gzip event") {
                ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(payload, b"payload");
    });
}

#[test]
fn seek_reader_requires_a_format_with_an_explicit_outer_filter() {
    let options = OpenOptions::new().with_filter(Some(FilterId::Base64));
    let error = SeekArchiveReader::with_options(Cursor::new(base64_tar()), &options)
        .expect_err("filtered seek input cannot auto-detect through random access");
    assert_eq!(error.kind(), ErrorKind::Capability);
}

#[test]
fn explicit_uuencode_filter_uses_the_common_options() {
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Tar))
        .with_filter(Some(FilterId::Uuencode));
    let mut reader = ArchiveReader::with_options(Cursor::new(uuencode_tar()), &options)
        .expect("explicit uuencode options reader");
    assert_eq!(collect_payload_sync(&mut reader), b"payload");

    #[cfg(feature = "async")]
    {
        futures_lite::future::block_on(async {
            let input = futures_lite::io::Cursor::new(uuencode_tar());
            let mut reader = libarchive_oxide::AsyncArchiveReader::with_options(input, &options)
                .expect("explicit async uuencode options reader");
            let mut payload = Vec::new();
            loop {
                match reader.next_event().await.expect("async uuencode event") {
                    ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
                    ReaderEvent::Done => break,
                    _ => {},
                }
            }
            assert_eq!(payload, b"payload");
        });
    }
}

#[test]
fn sync_options_preserve_lzma_limit_and_malformed_error_kinds() {
    let limits = Limits::safe().with_decoded_total(Some(1024));
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Tar))
        .with_filter(Some(FilterId::Lzma))
        .with_limits(limits);
    let error = ArchiveReader::with_options(Cursor::new(lzma_declared_size_bomb()), &options)
        .expect_err("declared-size bomb");
    assert_eq!(error.kind(), ErrorKind::Limit);

    let error = ArchiveReader::with_options(Cursor::new(vec![0; 12]), &options)
        .expect_err("truncated LZMA header");
    assert_eq!(error.kind(), ErrorKind::Malformed);
}

#[cfg(feature = "async")]
#[test]
fn async_options_preserve_lzma_limit_error_kind() {
    futures_lite::future::block_on(async {
        let options = OpenOptions::new()
            .with_format(Some(FormatId::Tar))
            .with_filter(Some(FilterId::Lzma))
            .with_limits(Limits::safe().with_decoded_total(Some(1024)));
        let input = futures_lite::io::Cursor::new(lzma_declared_size_bomb());
        let mut reader = libarchive_oxide::AsyncArchiveReader::with_options(input, &options)
            .expect("construct async bomb reader");
        let error = loop {
            match reader.next_event().await {
                Ok(ReaderEvent::Done) => panic!("LZMA bomb was accepted"),
                Ok(_) => {},
                Err(error) => break error,
            }
        };
        assert_eq!(error.kind(), ErrorKind::Limit, "{error:?}");

        let input = futures_lite::io::Cursor::new(vec![0; 12]);
        let mut reader = libarchive_oxide::AsyncArchiveReader::with_options(input, &options)
            .expect("construct truncated async reader");
        let error = loop {
            match reader.next_event().await {
                Ok(ReaderEvent::Done) => panic!("truncated LZMA header was accepted"),
                Ok(_) => {},
                Err(error) => break error,
            }
        };
        assert_eq!(error.kind(), ErrorKind::Malformed, "{error:?}");
    });
}

#[test]
fn explicit_outer_filter_is_shared_by_the_seek_reader() {
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Tar))
        .with_filter(Some(FilterId::Lzma));
    let mut reader = SeekArchiveReader::with_options(Cursor::new(lzma_tar()), &options)
        .expect("explicit seek LZMA reader");
    assert_eq!(reader.format(), FormatId::Tar);
    assert_eq!(collect_payload_seek(&mut reader), b"payload");
}

#[test]
fn explicit_outer_filter_is_shared_by_the_range_reader() {
    let source = MemoryReadAt::new(
        lzma_tar(),
        SourceIdentity::try_new(b"lzma-tar".to_vec()).expect("identity"),
    );
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Tar))
        .with_filter(Some(FilterId::Lzma));
    let mut reader =
        RangeArchiveReader::with_options(source, &options).expect("explicit range LZMA reader");
    assert_eq!(reader.format(), FormatId::Tar);
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("range LZMA event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"payload");
}

#[test]
fn explicit_uuencode_filter_is_shared_by_seek_and_range_readers() {
    let encoded = uuencode_tar();
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Tar))
        .with_filter(Some(FilterId::Uuencode));
    let mut seek = SeekArchiveReader::with_options(Cursor::new(encoded.clone()), &options)
        .expect("explicit seek uuencode reader");
    assert_eq!(collect_payload_seek(&mut seek), b"payload");

    let source = MemoryReadAt::new(
        encoded,
        SourceIdentity::try_new(b"uuencode-tar".to_vec()).expect("identity"),
    );
    let mut range =
        RangeArchiveReader::with_options(source, &options).expect("explicit range uuencode reader");
    let mut payload = Vec::new();
    loop {
        match range.next_event().expect("range uuencode event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"payload");
}

#[cfg(feature = "async")]
#[test]
fn explicit_uuencode_filter_is_shared_by_the_async_seek_reader() {
    futures_lite::future::block_on(async {
        let options = OpenOptions::new()
            .with_format(Some(FormatId::Tar))
            .with_filter(Some(FilterId::Uuencode));
        let input = futures_lite::io::Cursor::new(uuencode_tar());
        let mut reader = libarchive_oxide::AsyncSeekArchiveReader::with_options(input, &options)
            .await
            .expect("explicit async seek uuencode reader");
        let mut payload = Vec::new();
        loop {
            match reader
                .next_event()
                .await
                .expect("async seek uuencode event")
            {
                ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(payload, b"payload");
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn explicit_uuencode_filter_is_shared_by_tokio_stream_and_seek_readers() {
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Tar))
        .with_filter(Some(FilterId::Uuencode));
    let mut stream =
        libarchive_oxide::TokioArchiveReader::with_options(Cursor::new(uuencode_tar()), &options)
            .expect("explicit Tokio uuencode reader");
    let mut payload = Vec::new();
    loop {
        match stream.next_event().await.expect("Tokio uuencode event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"payload");

    let mut seek = libarchive_oxide::TokioSeekArchiveReader::with_options(
        Cursor::new(uuencode_tar()),
        &options,
    )
    .await
    .expect("explicit Tokio seek uuencode reader");
    let mut payload = Vec::new();
    loop {
        match seek.next_event().await.expect("Tokio seek uuencode event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"payload");
}

fn lzma_tar() -> Vec<u8> {
    filtered_tar(FilterId::Lzma)
}

fn lzma_declared_size_bomb() -> Vec<u8> {
    let mut encoded = lzma_tar();
    encoded[5..13].copy_from_slice(&1_000_000_u64.to_le_bytes());
    encoded
}

fn base64_tar() -> Vec<u8> {
    filtered_tar(FilterId::Base64)
}

fn uuencode_tar() -> Vec<u8> {
    filtered_tar(FilterId::Uuencode)
}

fn filtered_tar(filter: FilterId) -> Vec<u8> {
    let mut writer =
        ArchiveWriter::with_filter(Vec::new(), FormatId::Tar, Some(filter), Limits::safe())
            .expect("filtered tar writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"options.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    writer.start_entry(&metadata).expect("start entry");
    writer.write_data(b"payload").expect("write entry");
    writer.end_entry().expect("end entry");
    writer.finish().expect("finish filtered tar")
}

fn collect_payload_sync<R: std::io::Read>(reader: &mut ArchiveReader<R>) -> Vec<u8> {
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("LZMA tar event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    payload
}

fn collect_payload_seek<R: std::io::Read + std::io::Seek>(
    reader: &mut SeekArchiveReader<R>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("seek LZMA tar event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    payload
}

#[cfg(feature = "async")]
#[test]
fn explicit_outer_filter_is_shared_by_the_async_stream_reader() {
    futures_lite::future::block_on(async {
        let options = OpenOptions::new()
            .with_format(Some(FormatId::Tar))
            .with_filter(Some(FilterId::Lzma));
        let input = AsyncOneByte {
            bytes: lzma_tar(),
            position: 0,
        };
        let mut reader = libarchive_oxide::AsyncArchiveReader::with_options(input, &options)
            .expect("explicit async LZMA reader");
        let mut payload = Vec::new();
        loop {
            match reader.next_event().await.expect("async LZMA event") {
                ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(payload, b"payload");
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn explicit_outer_filter_is_shared_by_the_tokio_stream_reader() {
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Tar))
        .with_filter(Some(FilterId::Lzma));
    let mut reader =
        libarchive_oxide::TokioArchiveReader::with_options(Cursor::new(lzma_tar()), &options)
            .expect("explicit Tokio LZMA reader");
    let mut payload = Vec::new();
    loop {
        match reader.next_event().await.expect("Tokio LZMA event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"payload");
}

#[cfg(feature = "async")]
#[test]
fn explicit_outer_filter_is_shared_by_the_async_seek_reader() {
    futures_lite::future::block_on(async {
        let options = OpenOptions::new()
            .with_format(Some(FormatId::Tar))
            .with_filter(Some(FilterId::Lzma));
        let input = futures_lite::io::Cursor::new(lzma_tar());
        let mut reader = libarchive_oxide::AsyncSeekArchiveReader::with_options(input, &options)
            .await
            .expect("explicit async seek LZMA reader");
        assert_eq!(reader.format(), FormatId::Tar);
        let mut payload = Vec::new();
        loop {
            match reader.next_event().await.expect("async seek LZMA event") {
                ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(payload, b"payload");
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn explicit_outer_filter_is_shared_by_the_tokio_seek_reader() {
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Tar))
        .with_filter(Some(FilterId::Lzma));
    let mut reader =
        libarchive_oxide::TokioSeekArchiveReader::with_options(Cursor::new(lzma_tar()), &options)
            .await
            .expect("explicit Tokio seek LZMA reader");
    assert_eq!(reader.format(), FormatId::Tar);
    let mut payload = Vec::new();
    loop {
        match reader.next_event().await.expect("Tokio seek LZMA event") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload, b"payload");
}

#[test]
fn streaming_reader_accepts_password_provider_for_unencrypted_formats() {
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Raw))
        .with_password_provider(Arc::new(PasswordCandidates::new([SecretBytes::new(
            b"secret".to_vec(),
        )])));
    let mut reader = ArchiveReader::with_options(Cursor::new(b"payload"), &options)
        .expect("password provider is harmless for plaintext formats");
    assert!(matches!(
        reader.next_event(),
        Ok(ReaderEvent::ArchiveMetadata(_))
    ));
}

#[test]
fn range_reader_uses_open_options_source_limits() {
    let source = MemoryReadAt::new(
        empty_zip(),
        SourceIdentity::try_new(b"tiny-zip".to_vec()).expect("identity"),
    );
    let options =
        OpenOptions::new().with_source_limits(SourceLimits::safe().with_source_bytes(Some(8)));
    let error = RangeArchiveReader::with_options(source, &options)
        .expect_err("encoded source budget must be enforced");
    assert_eq!(error.kind(), ErrorKind::Io);
}
