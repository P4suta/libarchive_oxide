// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unix `compress(1)` / `.Z` interoperability through the public archive readers.

#![cfg(feature = "compress")]
#![allow(clippy::expect_used, clippy::panic)]

use std::io::{Cursor, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use libarchive_oxide::capability::{Backend, CapabilityState, capability_state};
use libarchive_oxide::{
    ArchivePath, ArchiveReader, ArchiveWriter, EntryKind, EntryMetadata, ErrorKind, FilterId,
    FormatId, Limits, ReaderEvent,
};
use libarchive_oxide_core::{AccessMode, CAPABILITY_LEDGER, DirectionSet};

fn bsdtar_fixture() -> Vec<u8> {
    let record = include_str!("../../fuzz/corpus/codec_lzw/bsdtar-seed-tar.hex")
        .trim()
        .strip_prefix("hex:")
        .expect("text fixture prefix");
    assert_eq!(record.len() % 2, 0);
    record
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(text, 16).expect("valid hex byte")
        })
        .collect()
}

#[test]
fn bsdtar_compress_fixture_streams_through_archive_reader() {
    // Produced by bsdtar 3.8.4:
    // `tar -acf seed.tar.Z -C fuzz/corpus/extraction_plan seed.txt`.
    let mut reader = ArchiveReader::new(Cursor::new(bsdtar_fixture()));
    let mut entry = reader
        .next_entry()
        .expect("read compressed tar")
        .expect("one tar entry");
    assert_eq!(entry.metadata().path().as_bytes(), b"seed.txt");
    let mut body = Vec::new();
    entry.read_to_end(&mut body).expect("stream entry payload");
    assert_eq!(body, b"safe/subdirectory/file.txt\n");
    drop(entry);
    assert!(reader.next_entry().expect("archive end").is_none());
}

#[derive(Debug, Clone)]
struct CountingSink(Arc<AtomicUsize>);

impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.fetch_add(bytes.len(), Ordering::SeqCst);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_preflights_compress_memory_before_io() {
    let written = Arc::new(AtomicUsize::new(0));
    let result = ArchiveWriter::with_filter(
        CountingSink(Arc::clone(&written)),
        FormatId::Tar,
        Some(FilterId::Compress),
        Limits::safe().with_codec_memory(Some(1)),
    );
    let Err(error) = result else {
        panic!("compress writer must enforce its encoder memory limit");
    };
    assert_eq!(error.kind(), ErrorKind::Limit);
    assert_eq!(error.format(), Some("compress"));
    assert_eq!(written.load(Ordering::SeqCst), 0);
}

fn write_compress_tar() -> Vec<u8> {
    let mut writer = ArchiveWriter::with_filter(
        Vec::new(),
        FormatId::Tar,
        Some(FilterId::Compress),
        Limits::safe(),
    )
    .expect("compress tar writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"compress.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    writer.start_entry(&metadata).expect("start entry");
    writer.write_data(b"pay").expect("first body chunk");
    writer.write_data(b"load").expect("second body chunk");
    writer.end_entry().expect("end entry");
    writer.finish().expect("finish compress tar")
}

#[test]
fn writer_output_round_trips_through_public_reader() {
    let encoded = write_compress_tar();
    assert_eq!(&encoded[..3], &[0x1f, 0x9d, 0x90]);
    let mut reader = ArchiveReader::new(encoded.as_slice());
    let mut body = Vec::new();
    loop {
        match reader.next_event().expect("read compress writer output") {
            ReaderEvent::Entry(entry) => {
                assert_eq!(entry.path().as_bytes(), b"compress.txt");
            },
            ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unexpected compress archive event"),
        }
    }
    assert_eq!(body, b"payload");
}

#[test]
fn capability_ledger_reports_portable_compress_read_write() {
    let record = CAPABILITY_LEDGER
        .iter()
        .find(|record| record.key() == "filter.compress")
        .expect("compress capability record");
    assert_eq!(record.access().read(), Some(AccessMode::Filter));
    assert_eq!(record.access().write(), Some(AccessMode::Filter));
    assert_eq!(record.portable(), DirectionSet::READ_WRITE);
    assert_eq!(record.native(), DirectionSet::NONE);
    let portable_state = if cfg!(feature = "portable-codecs") || !cfg!(feature = "native-codecs") {
        CapabilityState::Available(DirectionSet::READ_WRITE)
    } else {
        CapabilityState::Disabled
    };
    assert_eq!(capability_state(*record, Backend::Portable), portable_state);
}

#[test]
fn writer_abort_does_not_finalize_the_compress_stream() {
    let mut writer = ArchiveWriter::with_filter(
        Vec::new(),
        FormatId::Tar,
        Some(FilterId::Compress),
        Limits::safe(),
    )
    .expect("compress tar writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"aborted.txt".to_vec()),
    )
    .size(Some(7))
    .build();
    writer.start_entry(&metadata).expect("start entry");
    writer.write_data(b"payload").expect("write body");
    let incomplete = writer.abort().expect("recover incomplete output");
    assert!(incomplete.starts_with(&[0x1f, 0x9d, 0x90]));
    assert_ne!(incomplete, write_compress_tar());
}

#[cfg(feature = "async")]
mod asynchronous {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures_io::{AsyncRead, AsyncWrite};
    use futures_lite::future::block_on;
    use libarchive_oxide::{AsyncArchiveReader, AsyncArchiveWriter};

    use super::*;

    #[derive(Debug)]
    struct OneByte {
        bytes: Vec<u8>,
        position: usize,
    }

    impl AsyncRead for OneByte {
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

    #[derive(Debug)]
    struct AsyncCountingSink(Arc<AtomicUsize>);

    impl AsyncWrite for AsyncCountingSink {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0.fetch_add(bytes.len(), Ordering::SeqCst);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn async_writer_preflights_compress_memory_before_io() {
        let written = Arc::new(AtomicUsize::new(0));
        let result = AsyncArchiveWriter::with_filter(
            AsyncCountingSink(Arc::clone(&written)),
            FormatId::Tar,
            Some(FilterId::Compress),
            Limits::safe().with_codec_memory(Some(1)),
        );
        let Err(error) = result else {
            panic!("async compress writer must enforce its memory limit");
        };
        assert_eq!(error.kind(), ErrorKind::Limit);
        assert_eq!(error.format(), Some("compress"));
        assert_eq!(written.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn async_writer_streams_compress_for_the_public_reader() {
        block_on(async {
            let output = futures_lite::io::Cursor::new(Vec::new());
            let mut writer = AsyncArchiveWriter::with_filter(
                output,
                FormatId::Tar,
                Some(FilterId::Compress),
                Limits::safe(),
            )
            .expect("async compress writer");
            let metadata = EntryMetadata::builder(
                EntryKind::File,
                ArchivePath::from_bytes(b"async-compress.txt".to_vec()),
            )
            .size(Some(7))
            .build();
            writer.start_entry(&metadata).await.expect("start entry");
            writer.write_data(b"pay").await.expect("first chunk");
            writer.write_data(b"load").await.expect("second chunk");
            writer.end_entry().await.expect("end entry");
            let encoded = writer.finish().await.expect("finish writer").into_inner();

            let mut reader = ArchiveReader::new(encoded.as_slice());
            let mut payload = Vec::new();
            loop {
                match reader.next_event().expect("read async compress output") {
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
    async fn tokio_writer_streams_compress_for_the_public_reader() {
        use libarchive_oxide::TokioArchiveWriter;

        let mut writer = TokioArchiveWriter::with_filter(
            Vec::new(),
            FormatId::Tar,
            Some(FilterId::Compress),
            Limits::safe(),
        )
        .expect("Tokio compress writer");
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_bytes(b"tokio-compress.txt".to_vec()),
        )
        .size(Some(7))
        .build();
        writer.start_entry(&metadata).await.expect("start entry");
        writer.write_data(b"payload").await.expect("body");
        writer.end_entry().await.expect("end entry");
        let encoded = writer.finish().await.expect("finish writer");

        let mut reader = ArchiveReader::new(encoded.as_slice());
        let mut payload = Vec::new();
        loop {
            match reader.next_event().expect("read Tokio compress output") {
                ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(payload, b"payload");
    }

    #[test]
    fn bsdtar_compress_fixture_streams_through_async_reader() {
        block_on(async {
            let mut reader = AsyncArchiveReader::new(OneByte {
                bytes: bsdtar_fixture(),
                position: 0,
            });
            let mut path = None;
            let mut body = Vec::new();
            loop {
                match reader.next_event().await.expect("async archive event") {
                    ReaderEvent::Entry(metadata) => {
                        path = Some(metadata.path().as_bytes().to_vec());
                    },
                    ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
                    ReaderEvent::Done => break,
                    ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
                    _ => panic!("unexpected future reader event"),
                }
            }
            assert_eq!(path.as_deref(), Some(b"seed.txt".as_slice()));
            assert_eq!(body, b"safe/subdirectory/file.txt\n");
        });
    }
}
