// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-adapter v0.2 streaming contracts.
#![cfg(feature = "async")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{Cursor, Write};
use std::panic::RefUnwindSafe;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_io::AsyncRead;
use futures_lite::future::block_on;
use libarchive_oxide::filter::gzip::GzipEncoder;
use libarchive_oxide::{
    ArchiveReader, ArchiveWriter, AsyncArchiveReader, AsyncArchiveWriter, FilterReader, Pipeline,
    ReaderEvent,
};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{
    ArchivePath, Codec, CodecStatus, EndOfInput, EntryKind, EntryMetadata, FormatId, Limits,
};

fn assert_reader_auto_traits<T: Sync + RefUnwindSafe>() {}

#[test]
fn xz_backend_preserves_public_reader_auto_traits() {
    assert_reader_auto_traits::<FilterReader<Cursor<Vec<u8>>>>();
    assert_reader_auto_traits::<Pipeline>();
    assert_reader_auto_traits::<ArchiveReader<Cursor<Vec<u8>>>>();
    assert_reader_auto_traits::<AsyncArchiveReader<Cursor<Vec<u8>>>>();
    #[cfg(feature = "tokio")]
    assert_reader_auto_traits::<libarchive_oxide::TokioArchiveReader<Cursor<Vec<u8>>>>();
}

fn compress(plain: &[u8], filter: FilterId) -> std::io::Result<Vec<u8>> {
    match filter {
        FilterId::Gzip => {
            let mut codec = GzipEncoder::new(Limits::default());
            let mut input = plain;
            let mut buffer = [0_u8; 257];
            let mut output = Vec::new();
            loop {
                let step = codec
                    .process(input, &mut buffer, EndOfInput::End)
                    .map_err(std::io::Error::other)?;
                input = &input[step.consumed..];
                output.extend_from_slice(&buffer[..step.produced]);
                if matches!(step.status, CodecStatus::Done) {
                    return Ok(output);
                }
            }
        },
        FilterId::Bzip2 => {
            let mut writer =
                bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            writer.write_all(plain)?;
            writer.finish()
        },
        FilterId::Zstd => zstd_codec::stream::encode_all(Cursor::new(plain), 3),
        FilterId::Xz => {
            let mut writer =
                lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6))?;
            writer.write_all(plain)?;
            writer.finish()
        },
        FilterId::Lz4 => {
            let mut writer = lz4_flex::frame::FrameEncoder::new(Vec::new());
            writer.write_all(plain)?;
            writer
                .finish()
                .map_err(|error| std::io::Error::other(error.to_string()))
        },
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unknown filter",
        )),
    }
}

fn metadata() -> EntryMetadata {
    EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"adapter.txt".to_vec()),
    )
    .size(Some(12))
    .mode(Some(0o640))
    .build()
}

fn fixture() -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Vec::new());
    writer.start_entry(&metadata()).unwrap();
    writer.write_data(b"same payload").unwrap();
    writer.end_entry().unwrap();
    writer.finish().unwrap()
}

fn collect_sync(bytes: Vec<u8>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut reader = ArchiveReader::new(Cursor::new(bytes));
    let mut entries = Vec::new();
    let mut current: Option<(Vec<u8>, Vec<u8>)> = None;
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(meta) => {
                current = Some((meta.path().as_bytes().to_vec(), Vec::new()));
            },
            ReaderEvent::Data(data) => current.as_mut().unwrap().1.extend_from_slice(data),
            ReaderEvent::EndEntry => entries.push(current.take().unwrap()),
            ReaderEvent::Done => return entries,
            _ => panic!("unknown synchronous event"),
        }
    }
}

async fn collect_futures(bytes: Vec<u8>) -> Vec<(Vec<u8>, Vec<u8>)> {
    collect_futures_with_limits(bytes, Limits::default()).await
}

async fn collect_futures_with_limits(bytes: Vec<u8>, limits: Limits) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut reader = AsyncArchiveReader::with_limits(AsyncOneByte { bytes, position: 0 }, limits);
    let mut entries = Vec::new();
    let mut current: Option<(Vec<u8>, Vec<u8>)> = None;
    loop {
        match reader.next_event().await.unwrap() {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(meta) => {
                current = Some((meta.path().as_bytes().to_vec(), Vec::new()));
            },
            ReaderEvent::Data(data) => current.as_mut().unwrap().1.extend_from_slice(data),
            ReaderEvent::EndEntry => entries.push(current.take().unwrap()),
            ReaderEvent::Done => return entries,
            _ => panic!("unknown futures event"),
        }
    }
}

#[derive(Debug)]
struct AsyncOneByte {
    bytes: Vec<u8>,
    position: usize,
}

impl AsyncRead for AsyncOneByte {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
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

fn sync_filtered_fixture(filter: FilterId) -> Vec<u8> {
    let mut writer =
        ArchiveWriter::with_filter(Vec::new(), FormatId::Tar, Some(filter), Limits::default())
            .unwrap();
    writer.start_entry(&metadata()).unwrap();
    writer.write_data(b"same payload").unwrap();
    writer.end_entry().unwrap();
    writer.finish().unwrap()
}

#[test]
fn futures_reader_and_writer_match_sync_contract() {
    block_on(async {
        let expected = collect_sync(fixture());
        assert_eq!(collect_futures(fixture()).await, expected);

        let mut writer = AsyncArchiveWriter::new(futures_lite::io::Cursor::new(Vec::new()));
        writer.start_entry(&metadata()).await.unwrap();
        writer.write_data(b"same ").await.unwrap();
        writer.write_data(b"payload").await.unwrap();
        writer.end_entry().await.unwrap();
        let archive = writer.finish().await.unwrap().into_inner();
        assert_eq!(collect_sync(archive), expected);

        let mut gzip_writer = AsyncArchiveWriter::with_filter(
            futures_lite::io::Cursor::new(Vec::new()),
            FormatId::Tar,
            Some(FilterId::Gzip),
            Limits::default(),
        )
        .unwrap();
        gzip_writer.start_entry(&metadata()).await.unwrap();
        gzip_writer.write_data(b"same payload").await.unwrap();
        gzip_writer.end_entry().await.unwrap();
        let gzip_archive = gzip_writer.finish().await.unwrap().into_inner();
        assert_eq!(collect_sync(gzip_archive), expected);

        for filter in [
            FilterId::Gzip,
            FilterId::Bzip2,
            FilterId::Zstd,
            FilterId::Xz,
            FilterId::Lz4,
        ] {
            let sync_archive = sync_filtered_fixture(filter);
            assert_eq!(collect_sync(sync_archive.clone()), expected, "{filter:?}");
            assert_eq!(collect_futures(sync_archive).await, expected, "{filter:?}");

            let mut writer = AsyncArchiveWriter::with_filter(
                futures_lite::io::Cursor::new(Vec::new()),
                FormatId::Tar,
                Some(filter),
                Limits::default(),
            )
            .unwrap();
            writer.start_entry(&metadata()).await.unwrap();
            writer.write_data(b"same ").await.unwrap();
            writer.write_data(b"payload").await.unwrap();
            writer.end_entry().await.unwrap();
            let archive = writer.finish().await.unwrap().into_inner();
            assert_eq!(collect_sync(archive.clone()), expected, "{filter:?}");
            assert_eq!(collect_futures(archive).await, expected, "{filter:?}");
        }
    });
}

#[test]
fn async_reader_concatenates_every_filter_and_rejects_trailing_data() {
    block_on(async {
        let plain = fixture();
        let expected = collect_sync(plain.clone());
        let split = plain.len() / 2;
        for filter in [
            FilterId::Gzip,
            FilterId::Bzip2,
            FilterId::Zstd,
            FilterId::Xz,
            FilterId::Lz4,
        ] {
            let mut members = compress(&plain[..split], filter).unwrap();
            members.extend_from_slice(&compress(&plain[split..], filter).unwrap());
            assert_eq!(collect_futures(members).await, expected, "{filter:?}");

            let mut trailing = compress(&plain, filter).unwrap();
            trailing.push(0);
            let mut reader = AsyncArchiveReader::new(AsyncOneByte {
                bytes: trailing,
                position: 0,
            });
            loop {
                match reader.next_event().await {
                    Ok(ReaderEvent::Done) => panic!("{filter:?} accepted trailing data"),
                    Ok(_) => {},
                    Err(error) => {
                        assert_eq!(
                            error.io_error().map(std::io::Error::kind),
                            Some(std::io::ErrorKind::InvalidData),
                            "{filter:?}: {error}"
                        );
                        break;
                    },
                }
            }
        }
    });
}

#[test]
fn async_reader_composes_four_nested_filters() {
    block_on(async {
        let plain = fixture();
        let expected = collect_sync(plain.clone());
        let mut nested = plain;
        for filter in [
            FilterId::Gzip,
            FilterId::Bzip2,
            FilterId::Zstd,
            FilterId::Xz,
        ] {
            nested = compress(&nested, filter).unwrap();
        }
        assert_eq!(collect_futures(nested.clone()).await, expected);

        let limits = Limits::default().with_filter_depth(Some(3));
        let mut reader = AsyncArchiveReader::with_limits(
            AsyncOneByte {
                bytes: nested,
                position: 0,
            },
            limits,
        );
        loop {
            match reader.next_event().await {
                Ok(ReaderEvent::Done) => panic!("nested filter limit was bypassed"),
                Ok(_) => {},
                Err(error) => {
                    assert_eq!(
                        error
                            .archive_error()
                            .map(libarchive_oxide_core::ArchiveError::kind),
                        Some(libarchive_oxide_core::ErrorKind::Limit),
                        "{error:?}"
                    );
                    break;
                },
            }
        }
    });
}

#[test]
fn async_xz_dictionary_limit_prevents_oversized_allocation() {
    block_on(async {
        let bytes = vec![
            253, 55, 122, 88, 90, 0, 0, 4, 230, 214, 180, 70, 0, 208, 208, 208, 208, 1, 32, 208,
            208, 208, 208, 58, 26, 8, 206, 118, 199, 229, 233, 111, 229, 163, 224, 0, 175, 0, 49,
            0, 58, 26, 8, 93, 206, 118, 199, 214, 233, 229, 7, 52, 195, 209, 14, 191, 206, 85, 103,
            251, 2, 0, 0, 0, 0, 4, 89, 90,
        ];
        let mut reader =
            AsyncArchiveReader::with_limits(AsyncOneByte { bytes, position: 0 }, Limits::default());
        let error = loop {
            match reader.next_event().await {
                Ok(ReaderEvent::Done) => panic!("oversized XZ dictionary was accepted"),
                Ok(_) => {},
                Err(error) => break error,
            }
        };
        assert_eq!(
            error.io_error().map(std::io::Error::kind),
            Some(std::io::ErrorKind::OutOfMemory)
        );
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_reader_and_writer_match_sync_contract() {
    use std::future::poll_fn;
    use std::io::SeekFrom;

    use futures_io::AsyncSeek;
    use libarchive_oxide::{TokioArchiveReader, TokioArchiveWriter, TokioIo};

    let expected = collect_sync(fixture());
    let input = fixture();
    let mut reader = TokioArchiveReader::new(&input[..]);
    let mut entries = Vec::new();
    let mut current: Option<(Vec<u8>, Vec<u8>)> = None;
    loop {
        match reader.next_event().await.unwrap() {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(meta) => {
                current = Some((meta.path().as_bytes().to_vec(), Vec::new()));
            },
            ReaderEvent::Data(data) => current.as_mut().unwrap().1.extend_from_slice(data),
            ReaderEvent::EndEntry => entries.push(current.take().unwrap()),
            ReaderEvent::Done => break,
            _ => panic!("unknown Tokio event"),
        }
    }
    assert_eq!(entries, expected);

    let mut writer = TokioArchiveWriter::new(Vec::new());
    writer.start_entry(&metadata()).await.unwrap();
    writer.write_data(b"same payload").await.unwrap();
    writer.end_entry().await.unwrap();
    let archive = writer.finish().await.unwrap();
    assert_eq!(collect_sync(archive), expected);

    let bzip2_input = sync_filtered_fixture(FilterId::Bzip2);
    let mut bzip2_reader = TokioArchiveReader::new(bzip2_input.as_slice());
    let mut bzip2_entries = Vec::new();
    let mut bzip2_current: Option<(Vec<u8>, Vec<u8>)> = None;
    loop {
        match bzip2_reader.next_event().await.unwrap() {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(meta) => {
                bzip2_current = Some((meta.path().as_bytes().to_vec(), Vec::new()));
            },
            ReaderEvent::Data(data) => bzip2_current.as_mut().unwrap().1.extend_from_slice(data),
            ReaderEvent::EndEntry => bzip2_entries.push(bzip2_current.take().unwrap()),
            ReaderEvent::Done => break,
            _ => panic!("unknown Tokio bzip2 event"),
        }
    }
    assert_eq!(bzip2_entries, expected);

    let mut bzip2_writer = TokioArchiveWriter::with_filter(
        Vec::new(),
        FormatId::Tar,
        Some(FilterId::Bzip2),
        Limits::default(),
    )
    .unwrap();
    bzip2_writer.start_entry(&metadata()).await.unwrap();
    bzip2_writer.write_data(b"same payload").await.unwrap();
    bzip2_writer.end_entry().await.unwrap();
    let bzip2_archive = bzip2_writer.finish().await.unwrap();
    assert_eq!(collect_sync(bzip2_archive), expected);

    let mut seek = TokioIo::new(Cursor::new(vec![0_u8; 8]));
    let position = poll_fn(|context| Pin::new(&mut seek).poll_seek(context, SeekFrom::Start(5)))
        .await
        .unwrap();
    assert_eq!(position, 5);
    assert_eq!(seek.into_inner().position(), 5);
}
