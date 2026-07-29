// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict lzip interoperability through the public sync and async readers.

#![cfg(feature = "lzip")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::{self, Cursor, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(all(feature = "portable-codecs", feature = "native-codecs"))]
use libarchive_oxide::BackendPreference;
use libarchive_oxide::advanced::{CapabilityState, Pipeline, PipelineEvent, capability_state};
use libarchive_oxide::{
    ArchiveReader, ArchiveWriter, Backend, ErrorKind, FilterId, FilterReader, FormatId, Limits,
    filter_for_name,
};
use libarchive_oxide_core::{AccessMode, CAPABILITY_LEDGER, Direction, DirectionSet, ProbeResult};

const FIXTURE_HEX: &str = include_str!("fixtures/lzip/bsdtar-3.8.4-seed.tar.lz.hex");
const LZIP_TRAILER_SIZE: usize = 20;

fn fixture() -> Vec<u8> {
    decode_hex(FIXTURE_HEX)
}

fn decode_hex(record: &str) -> Vec<u8> {
    let hex = record
        .trim()
        .strip_prefix("hex:")
        .expect("fixture has a hex prefix");
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("fixture is ASCII");
            u8::from_str_radix(text, 16).expect("fixture contains valid hexadecimal")
        })
        .collect()
}

fn lzip_member(plain: &[u8]) -> Vec<u8> {
    let mut writer =
        lzma_rust2::LzipWriter::new(Vec::new(), lzma_rust2::LzipOptions::with_preset(1));
    writer.write_all(plain).expect("write dev-only lzip member");
    writer.finish().expect("finish dev-only lzip member")
}

#[derive(Debug)]
struct Chunked {
    bytes: Vec<u8>,
    position: usize,
    chunk: usize,
}

impl Chunked {
    fn new(bytes: Vec<u8>, chunk: usize) -> Self {
        Self {
            bytes,
            position: 0,
            chunk,
        }
    }
}

impl Read for Chunked {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.bytes.len() {
            return Ok(0);
        }
        let read = output
            .len()
            .min(self.chunk)
            .min(self.bytes.len() - self.position);
        output[..read].copy_from_slice(&self.bytes[self.position..self.position + read]);
        self.position += read;
        Ok(read)
    }
}

fn decode_filter(bytes: Vec<u8>, input_chunk: usize, output_chunk: usize) -> io::Result<Vec<u8>> {
    let mut reader = FilterReader::new(Chunked::new(bytes, input_chunk))?;
    let mut decoded = Vec::new();
    let mut output = vec![0_u8; output_chunk];
    loop {
        let read = reader.read(&mut output)?;
        if read == 0 {
            return Ok(decoded);
        }
        decoded.extend_from_slice(&output[..read]);
    }
}

#[test]
fn bsdtar_fixture_streams_through_archive_reader() {
    let mut reader = ArchiveReader::new(Chunked::new(fixture(), 1));
    let mut entry = reader
        .next_entry()
        .expect("read bsdtar lzip fixture")
        .expect("fixture has one tar entry");
    assert_eq!(entry.metadata().path().as_bytes(), b"seed.txt");
    let mut body = Vec::new();
    entry
        .read_to_end(&mut body)
        .expect("stream fixture payload");
    assert_eq!(body, b"safe/subdirectory/file.txt\n");
    drop(entry);
    assert!(reader.next_entry().expect("finish fixture").is_none());
}

#[test]
fn decode_is_invariant_across_input_and_output_chunks() {
    let encoded = lzip_member(&(0_u8..=251).cycle().take(300_000).collect::<Vec<u8>>());
    let expected = decode_filter(encoded.clone(), encoded.len(), 64 * 1024).unwrap();
    for input_chunk in [1, 2, 5, 31, 4096, 64 * 1024] {
        for output_chunk in [1, 3, 257, 64 * 1024] {
            assert_eq!(
                decode_filter(encoded.clone(), input_chunk, output_chunk).unwrap(),
                expected,
                "input={input_chunk}, output={output_chunk}"
            );
        }
    }
}

#[test]
fn concatenated_members_decode_and_trailing_data_is_rejected() {
    let first = lzip_member(b"first");
    let second = lzip_member(b"second");
    let mut members = first.clone();
    members.extend_from_slice(&second);
    assert_eq!(decode_filter(members, 1, 2).unwrap(), b"firstsecond");

    let mut trailing = first.clone();
    trailing.push(0);
    assert_eq!(
        decode_filter(trailing, 3, 7).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );

    let mut corrupt_second = first;
    let second_offset = corrupt_second.len();
    corrupt_second.extend_from_slice(&second);
    corrupt_second[second_offset] = b'X';
    assert_eq!(
        decode_filter(corrupt_second, 11, 13).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

fn strict_member() -> Vec<u8> {
    lzip_member(b"strict-envelope")
}

fn truncate_raw_payload(member: &[u8]) -> Vec<u8> {
    let payload_end = member
        .len()
        .checked_sub(LZIP_TRAILER_SIZE)
        .expect("lzip member includes its trailer");
    assert!(payload_end > 6, "lzip member has a non-empty raw payload");
    member[..payload_end - 1].to_vec()
}

fn assert_strict_member_error(bytes: Vec<u8>, input_chunk: usize, output_chunk: usize) {
    assert!(decode_filter(bytes, input_chunk, output_chunk).is_err());
}

#[test]
fn wrong_version_fails_closed() {
    let mut wrong_version = strict_member();
    wrong_version[4] = 2;
    assert_strict_member_error(wrong_version, 1, 5);
}

#[test]
fn bad_dictionary_fails_closed() {
    let mut bad_dictionary = strict_member();
    bad_dictionary[5] = 0x0b;
    assert_strict_member_error(bad_dictionary, 2, 5);
}

fn corrupt_trailer(relative_offset: usize) -> Vec<u8> {
    let mut corrupt = strict_member();
    let trailer = corrupt.len() - 20;
    corrupt[trailer + relative_offset] ^= 1;
    corrupt
}

#[test]
fn trailer_crc_corruption_fails_closed() {
    assert_strict_member_error(corrupt_trailer(0), 3, 7);
}

#[test]
fn trailer_data_size_corruption_fails_closed() {
    assert_strict_member_error(corrupt_trailer(4), 3, 7);
}

#[test]
fn trailer_member_size_corruption_fails_closed() {
    assert_strict_member_error(corrupt_trailer(12), 3, 7);
}

#[test]
fn payload_corruption_fails_closed() {
    let mut corrupt_payload = strict_member();
    corrupt_payload[10] ^= 0x40;
    assert_strict_member_error(corrupt_payload, 5, 11);
}

fn truncated_member(cut: impl FnOnce(&[u8]) -> usize) -> Vec<u8> {
    let valid = strict_member();
    let cut = cut(&valid);
    valid[..cut].to_vec()
}

#[test]
fn truncation_inside_magic_fails_closed() {
    assert_strict_member_error(truncated_member(|_| 4), 1, 17);
}

#[test]
fn truncation_before_dictionary_fails_closed() {
    assert_strict_member_error(truncated_member(|_| 5), 1, 17);
}

#[test]
fn truncation_after_header_fails_closed() {
    assert_strict_member_error(truncated_member(|_| 6), 1, 17);
}

#[test]
fn truncation_inside_payload_fails_closed() {
    assert_strict_member_error(truncated_member(|_| 7), 1, 17);
}

#[test]
fn raw_lzma_payload_truncation_is_reported_before_synthetic_output() {
    let error = decode_filter(truncate_raw_payload(&strict_member()), 1, 17).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        error.to_string().contains("truncated lzip LZMA payload"),
        "unexpected lzip error: {error}"
    );
}

#[test]
fn truncation_before_trailer_fails_closed() {
    assert_strict_member_error(truncated_member(|valid| valid.len() - 20), 1, 17);
}

#[test]
fn truncation_inside_trailer_fails_closed() {
    assert_strict_member_error(truncated_member(|valid| valid.len() - 1), 1, 17);
}

#[test]
fn every_truncation_boundary_fails_closed() {
    let valid = strict_member();
    for cut in 4..valid.len() {
        assert_strict_member_error(valid[..cut].to_vec(), 1, 17);
    }
}

#[test]
fn bsdtar_fixture_every_truncation_boundary_fails_closed() {
    let valid = fixture();
    for cut in 4..valid.len() {
        assert_strict_member_error(valid[..cut].to_vec(), 1, 17);
    }
}

#[test]
fn bsdtar_fixture_cut_122_fails_closed() {
    let valid = fixture();
    assert_strict_member_error(valid[..122].to_vec(), 1, 17);
}

#[test]
fn pipeline_rejects_raw_lzma_payload_truncation() {
    let truncated = truncate_raw_payload(&fixture());
    let mut pipeline = Pipeline::new(Limits::default());
    assert_eq!(pipeline.feed(&truncated).unwrap(), truncated.len());
    pipeline.finish_input().unwrap();

    let error = loop {
        match pipeline.poll_event() {
            Err(error) => break error,
            Ok(PipelineEvent::NeedInput) => panic!("finished lzip input requested more bytes"),
            Ok(PipelineEvent::Done) => panic!("truncated lzip payload unexpectedly decoded"),
            Ok(_) => {},
        }
    };
    assert_eq!(error.kind(), ErrorKind::Malformed);
    assert_eq!(error.format(), Some("lzip"));
    assert!(
        error.to_string().contains("truncated lzip LZMA payload"),
        "unexpected lzip error: {error}"
    );
}

#[test]
fn dropping_pipeline_with_partial_lzip_input_joins_worker() {
    let encoded = fixture();
    let partial = &encoded[..10];
    let mut pipeline = Pipeline::new(Limits::default());
    assert_eq!(pipeline.feed(partial).unwrap(), partial.len());
    assert!(matches!(
        pipeline.poll_event().unwrap(),
        PipelineEvent::NeedInput
    ));
    drop(pipeline);
}

#[test]
fn dictionary_and_decoded_total_limits_are_enforced() {
    // A complete header advertising 512 MiB is enough to prove the workspace
    // budget is checked before the raw LZMA decoder tries to read or allocate.
    let oversized_header = vec![b'L', b'Z', b'I', b'P', 1, 0x1d];
    let mut reader = FilterReader::with_limits(
        Cursor::new(oversized_header),
        Limits::default().with_codec_memory(Some(64 * 1024 * 1024)),
    )
    .expect("magic detection itself performs no dictionary allocation");
    let mut byte = [0_u8; 1];
    assert_eq!(
        reader.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );

    let mut reader = FilterReader::with_limits(
        Chunked::new(lzip_member(b"12345"), 1),
        Limits::default().with_decoded_total(Some(4)),
    )
    .unwrap();
    let mut decoded = Vec::new();
    assert_eq!(
        reader.read_to_end(&mut decoded).unwrap_err().kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(decoded, b"1234");
}

#[test]
fn probe_filename_and_capability_ledger_are_consistent() {
    assert_eq!(
        FilterId::probe(b"LZI"),
        ProbeResult::NeedMore { minimum: 4 }
    );
    assert_eq!(FilterId::probe(b"LZIP"), ProbeResult::Match(FilterId::Lzip));
    assert_eq!(filter_for_name("archive.tar.lz"), Some(FilterId::Lzip));
    assert_eq!(filter_for_name("ARCHIVE.LZ"), Some(FilterId::Lzip));

    let record = CAPABILITY_LEDGER
        .iter()
        .find(|record| record.key() == "filter.lzip")
        .expect("canonical lzip capability record");
    assert_eq!(record.access().read(), Some(AccessMode::Filter));
    assert_eq!(record.access().write(), None);
    assert_eq!(record.portable(), DirectionSet::READ);
    assert_eq!(record.native(), DirectionSet::NONE);
    assert!(record.portable().contains(Direction::Read));
    assert_eq!(
        capability_state(*record, Backend::Portable),
        CapabilityState::Available(DirectionSet::READ)
    );
}

#[derive(Debug, Clone)]
struct CountingSink(Arc<AtomicUsize>);

impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.fetch_add(bytes.len(), Ordering::SeqCst);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_rejects_lzip_with_capability_before_io() {
    let written = Arc::new(AtomicUsize::new(0));
    let result = ArchiveWriter::with_filter(
        CountingSink(Arc::clone(&written)),
        FormatId::Tar,
        Some(FilterId::Lzip),
        Limits::default(),
    );
    let Err(error) = result else {
        panic!("lzip writer must not be constructible");
    };
    assert_eq!(error.kind(), ErrorKind::Capability);
    assert_eq!(error.format(), Some("lzip"));
    assert_eq!(written.load(Ordering::SeqCst), 0);
}

#[test]
#[cfg(all(feature = "portable-codecs", feature = "native-codecs"))]
fn auto_uses_portable_and_explicit_native_is_typed_capability() {
    assert!(
        decode_filter(fixture(), 1, 19).is_ok(),
        "Auto must select the lzip portable backend"
    );
    let mut portable = FilterReader::with_backend(
        Cursor::new(fixture()),
        Limits::default(),
        BackendPreference::Portable,
    )
    .unwrap();
    let mut decoded = Vec::new();
    portable.read_to_end(&mut decoded).unwrap();
    assert!(!decoded.is_empty());

    let bytes = fixture();
    let mut pipeline = Pipeline::with_backend(Limits::default(), BackendPreference::Native);
    assert_eq!(pipeline.feed(&bytes).unwrap(), bytes.len());
    pipeline.finish_input().unwrap();
    let error = loop {
        match pipeline.poll_event() {
            Err(error) => break error,
            Ok(PipelineEvent::NeedInput) => panic!("all lzip bytes were already supplied"),
            Ok(PipelineEvent::Done) => panic!("native lzip unexpectedly decoded"),
            Ok(_) => {},
        }
    };
    assert_eq!(error.kind(), ErrorKind::Capability);
    assert_eq!(error.format(), Some("lzip"));
}

#[cfg(feature = "async")]
mod asynchronous {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures_io::{AsyncRead, AsyncWrite};
    use futures_lite::future::block_on;
    use libarchive_oxide::{AsyncArchiveReader, AsyncArchiveWriter, ReaderEvent};

    use super::*;

    #[derive(Debug)]
    struct AsyncOneByte {
        bytes: Vec<u8>,
        position: usize,
    }

    impl AsyncRead for AsyncOneByte {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            output: &mut [u8],
        ) -> Poll<io::Result<usize>> {
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
        ) -> Poll<io::Result<usize>> {
            self.0.fetch_add(bytes.len(), Ordering::SeqCst);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn async_writer_rejects_lzip_with_capability_before_io() {
        let written = Arc::new(AtomicUsize::new(0));
        let result = AsyncArchiveWriter::with_filter(
            AsyncCountingSink(Arc::clone(&written)),
            FormatId::Tar,
            Some(FilterId::Lzip),
            Limits::default(),
        );
        let Err(error) = result else {
            panic!("async lzip writer must not be constructible");
        };
        assert_eq!(error.kind(), ErrorKind::Capability);
        assert_eq!(error.format(), Some("lzip"));
        assert_eq!(written.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn bsdtar_fixture_streams_through_async_archive_reader() {
        block_on(async {
            let mut reader = AsyncArchiveReader::new(AsyncOneByte {
                bytes: fixture(),
                position: 0,
            });
            let mut path = None;
            let mut body = Vec::new();
            loop {
                match reader.next_event().await.expect("async lzip event") {
                    ReaderEvent::Entry(metadata) => {
                        path = Some(metadata.path().as_bytes().to_vec());
                    },
                    ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
                    ReaderEvent::Done => break,
                    ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
                    _ => panic!("unexpected async reader event"),
                }
            }
            assert_eq!(path.as_deref(), Some(b"seed.txt".as_slice()));
            assert_eq!(body, b"safe/subdirectory/file.txt\n");
        });
    }

    #[test]
    fn async_reader_rejects_raw_lzma_payload_truncation() {
        block_on(async {
            let mut reader = AsyncArchiveReader::new(AsyncOneByte {
                bytes: truncate_raw_payload(&fixture()),
                position: 0,
            });
            let error = loop {
                match reader.next_event().await {
                    Err(error) => break error,
                    Ok(ReaderEvent::Done) => {
                        panic!("truncated lzip payload unexpectedly decoded")
                    },
                    Ok(_) => {},
                }
            };
            assert!(
                error.to_string().contains("truncated lzip LZMA payload"),
                "unexpected lzip error: {error}"
            );
        });
    }

    #[cfg(feature = "tokio")]
    #[tokio::test(flavor = "current_thread")]
    async fn bsdtar_fixture_streams_through_tokio_archive_reader() {
        use libarchive_oxide::TokioArchiveReader;

        let input = fixture();
        let mut reader = TokioArchiveReader::new(input.as_slice());
        let mut path = None;
        let mut body = Vec::new();
        loop {
            match reader.next_event().await.expect("Tokio lzip event") {
                ReaderEvent::Entry(metadata) => {
                    path = Some(metadata.path().as_bytes().to_vec());
                },
                ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
                _ => panic!("unexpected Tokio reader event"),
            }
        }
        assert_eq!(path.as_deref(), Some(b"seed.txt".as_slice()));
        assert_eq!(body, b"safe/subdirectory/file.txt\n");
    }

    #[cfg(feature = "tokio")]
    #[tokio::test(flavor = "current_thread")]
    async fn tokio_reader_rejects_raw_lzma_payload_truncation() {
        use libarchive_oxide::TokioArchiveReader;

        let input = truncate_raw_payload(&fixture());
        let mut reader = TokioArchiveReader::new(input.as_slice());
        let error = loop {
            match reader.next_event().await {
                Err(error) => break error,
                Ok(ReaderEvent::Done) => panic!("truncated lzip payload unexpectedly decoded"),
                Ok(_) => {},
            }
        };
        assert!(
            error.to_string().contains("truncated lzip LZMA payload"),
            "unexpected lzip error: {error}"
        );
    }
}
