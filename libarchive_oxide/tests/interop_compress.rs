// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unix `compress(1)` / `.Z` interoperability through the public archive readers.

#![cfg(feature = "compress")]
#![allow(clippy::expect_used, clippy::panic)]

use std::io::{Cursor, Read};

use libarchive_oxide::ArchiveReader;

fn bsdtar_fixture() -> Vec<u8> {
    let record = include_str!("../../fuzz/corpus/codec_lzw/bsdtar-seed-tar.hex")
        .trim()
        .strip_prefix("hex:")
        .expect("text fixture prefix");
    assert_eq!(record.len() % 2, 0);
    record
        .as_bytes()
        .chunks_exact(2)
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

#[cfg(feature = "async")]
mod asynchronous {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use futures_io::AsyncRead;
    use futures_lite::future::block_on;
    use libarchive_oxide::{AsyncArchiveReader, ReaderEvent};

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
