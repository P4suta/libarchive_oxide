// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Immutable sync and runtime-neutral async range-source contracts.

#![allow(clippy::expect_used)]

use std::io::{self, Cursor, Seek, SeekFrom};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use libarchive_oxide::libarchive_oxide_core::{
    ArchivePath, EntryKind, EntryMetadata, FormatId, Limits,
};
use libarchive_oxide::{
    RangeArchiveReader, RangeReadError, RangeReader, RangeSource, ReaderEvent, SeekArchiveWriter,
    SourceIdentity, StreamError,
};

const PAYLOAD: &[u8] = b"immutable range source payload";
type SourceConfiguration = fn(&mut MemoryRange);

#[derive(Debug)]
struct MemoryRange {
    bytes: Vec<u8>,
    identity: SourceIdentity,
    max_chunk: usize,
    requests: u64,
    transferred: u64,
    max_request: usize,
    mutate_on_request: Option<u64>,
    grow_on_request: Option<u64>,
    fail_short: bool,
    no_progress: bool,
    invalid_count: bool,
}

impl MemoryRange {
    fn new(bytes: Vec<u8>, max_chunk: usize) -> Self {
        Self {
            bytes,
            identity: SourceIdentity::new(b"memory-generation-1".to_vec()),
            max_chunk,
            requests: 0,
            transferred: 0,
            max_request: 0,
            mutate_on_request: None,
            grow_on_request: None,
            fail_short: false,
            no_progress: false,
            invalid_count: false,
        }
    }
}

impl RangeSource for MemoryRange {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    fn read_range(&mut self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        self.requests += 1;
        self.max_request = self.max_request.max(output.len());
        if self.mutate_on_request == Some(self.requests) {
            self.identity = SourceIdentity::new(b"memory-generation-2".to_vec());
        }
        if self.grow_on_request == Some(self.requests) {
            self.bytes.push(0);
        }
        if self.fail_short {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "simulated truncated object",
            ));
        }
        if self.no_progress {
            return Ok(0);
        }
        if self.invalid_count {
            return Ok(output.len() + 1);
        }
        let start = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset exceeds usize"))?;
        let available = self
            .bytes
            .get(start..)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset exceeds object"))?;
        let count = available.len().min(output.len()).min(self.max_chunk);
        output[..count].copy_from_slice(&available[..count]);
        self.transferred += count as u64;
        Ok(count)
    }
}

#[derive(Debug)]
struct ExternallyMutableRange {
    bytes: Vec<u8>,
    identities: [SourceIdentity; 2],
    mutated: Arc<AtomicBool>,
}

impl RangeSource for ExternallyMutableRange {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn identity(&self) -> &SourceIdentity {
        if self.mutated.load(Ordering::Relaxed) {
            &self.identities[1]
        } else {
            &self.identities[0]
        }
    }

    fn read_range(&mut self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        let start = usize::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset exceeds usize"))?;
        let available = self
            .bytes
            .get(start..)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset exceeds object"))?;
        let count = available.len().min(output.len());
        output[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

fn archive(format: FormatId) -> Vec<u8> {
    let output = Cursor::new(Vec::new());
    let mut writer = SeekArchiveWriter::with_format(output, format, Limits::default())
        .expect("create seek writer");
    let metadata =
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("range/payload.txt"))
            .size(Some(PAYLOAD.len() as u64))
            .build();
    writer.start_entry(&metadata).expect("start file");
    writer.write_data(PAYLOAD).expect("write file");
    writer.end_entry().expect("end file");
    writer.finish().expect("finish seek archive").into_inner()
}

fn read_all(reader: &mut RangeArchiveReader<MemoryRange>) -> Vec<u8> {
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("range event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    decoded
}

fn typed_range_error(error: &StreamError) -> Option<RangeReadError> {
    error
        .io_error()?
        .get_ref()?
        .downcast_ref::<RangeReadError>()
        .copied()
}

#[test]
fn zip_and_iso_use_the_existing_seek_parser_with_exact_metrics() {
    for format in [FormatId::Zip, FormatId::Iso9660] {
        let source = MemoryRange::new(archive(format), 11);
        let mut reader = RangeArchiveReader::new(source).expect("open range archive");
        assert_eq!(reader.format(), format);
        assert_eq!(reader.identity().as_bytes(), b"memory-generation-1");
        assert_eq!(read_all(&mut reader), PAYLOAD);

        let metrics = reader.metrics();
        assert!(metrics.requests() > 1);
        assert!(metrics.transferred_bytes() > 0);
        let source = reader.into_inner();
        assert_eq!(metrics.requests(), source.requests);
        assert_eq!(metrics.transferred_bytes(), source.transferred);
    }
}

#[cfg(feature = "sevenz")]
#[test]
fn sevenz_uses_the_existing_seek_parser() {
    let source = MemoryRange::new(archive(FormatId::SevenZip), 13);
    let mut reader = RangeArchiveReader::new(source).expect("open range 7z");
    assert_eq!(reader.format(), FormatId::SevenZip);
    assert_eq!(read_all(&mut reader), PAYLOAD);
    assert!(reader.metrics().requests() > 1);
}

#[test]
fn identity_changes_fail_closed_during_a_request() {
    let mut source = MemoryRange::new(archive(FormatId::Zip), 64);
    source.mutate_on_request = Some(1);
    let error = RangeArchiveReader::new(source).expect_err("mutation must fail");
    assert_eq!(
        typed_range_error(&error),
        Some(RangeReadError::IdentityChanged)
    );
}

#[test]
fn length_changes_fail_closed_during_a_request() {
    let mut source = MemoryRange::new(archive(FormatId::Zip), 64);
    source.grow_on_request = Some(1);
    let error = RangeArchiveReader::new(source).expect_err("length mutation must fail");
    assert_eq!(
        typed_range_error(&error),
        Some(RangeReadError::LengthChanged)
    );
}

#[test]
fn identity_is_revalidated_between_public_commands() {
    let mutated = Arc::new(AtomicBool::new(false));
    let source = ExternallyMutableRange {
        bytes: archive(FormatId::Zip),
        identities: [
            SourceIdentity::new(b"external-generation-1".to_vec()),
            SourceIdentity::new(b"external-generation-2".to_vec()),
        ],
        mutated: Arc::clone(&mutated),
    };
    let mut reader = RangeArchiveReader::new(source).expect("open stable range");
    mutated.store(true, Ordering::Relaxed);
    let error = reader
        .next_event()
        .expect_err("external mutation must fail");
    assert_eq!(
        typed_range_error(&error),
        Some(RangeReadError::IdentityChanged)
    );
}

#[test]
fn cache_and_read_ahead_obey_limits() {
    let source = MemoryRange::new(vec![7; 100], 100);
    let limits = Limits::safe()
        .with_metadata_bytes(Some(32))
        .with_in_flight_bytes(Some(16));
    let mut reader = RangeReader::with_limits(source, limits);
    let mut bytes = [0; 2];
    assert_eq!(
        std::io::Read::read(&mut reader, &mut bytes).expect("first cached read"),
        2
    );
    assert_eq!(
        std::io::Read::read(&mut reader, &mut bytes).expect("second cached read"),
        2
    );
    assert_eq!(reader.metrics().requests(), 1);
    assert_eq!(reader.metrics().transferred_bytes(), 16);
    let source = reader.into_inner();
    assert_eq!(source.max_request, 16);

    let source = MemoryRange::new(vec![7; 100], 100);
    let mut reader = RangeReader::with_limits(source, Limits::safe().with_metadata_bytes(Some(1)));
    let error =
        std::io::Read::read(&mut reader, &mut bytes).expect_err("cache budget must be enforced");
    assert_eq!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<RangeReadError>())
            .copied(),
        Some(RangeReadError::CacheBudgetExceeded)
    );
}

#[test]
fn range_protocol_failures_remain_typed() {
    let cases: [(SourceConfiguration, RangeReadError); 3] = [
        (
            |source: &mut MemoryRange| source.fail_short = true,
            RangeReadError::ShortRead,
        ),
        (
            |source: &mut MemoryRange| source.no_progress = true,
            RangeReadError::NoProgress,
        ),
        (
            |source: &mut MemoryRange| source.invalid_count = true,
            RangeReadError::InvalidReadCount,
        ),
    ];
    for (configure, expected) in cases {
        let mut source = MemoryRange::new(vec![1, 2, 3], 3);
        configure(&mut source);
        let mut reader = RangeReader::new(source);
        let mut byte = [0];
        let error = std::io::Read::read(&mut reader, &mut byte).expect_err("typed range failure");
        assert_eq!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<RangeReadError>())
                .copied(),
            Some(expected)
        );
    }

    let source = MemoryRange::new(vec![1, 2, 3], 3);
    let mut reader = RangeReader::new(source);
    let error = reader
        .seek(SeekFrom::Start(4))
        .expect_err("out-of-bounds seek");
    assert_eq!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<RangeReadError>())
            .copied(),
        Some(RangeReadError::OffsetOutOfBounds)
    );
}

#[cfg(feature = "async")]
mod asynchronous {
    use futures_lite::future::block_on;
    use libarchive_oxide::{AsyncRangeArchiveReader, AsyncRangeSource};

    use super::*;

    impl AsyncRangeSource for MemoryRange {
        fn len(&self) -> u64 {
            RangeSource::len(self)
        }

        fn identity(&self) -> &SourceIdentity {
            RangeSource::identity(self)
        }

        async fn read_range(&mut self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
            RangeSource::read_range(self, offset, output)
        }
    }

    #[test]
    fn short_async_chunks_use_the_same_zip_parser_and_exact_metrics() {
        block_on(async {
            let source = MemoryRange::new(archive(FormatId::Zip), 3);
            let mut reader = AsyncRangeArchiveReader::new(source)
                .await
                .expect("open async range ZIP");
            assert_eq!(reader.format(), FormatId::Zip);
            let mut decoded = Vec::new();
            loop {
                match reader.next_event().await.expect("async range event") {
                    ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
                    ReaderEvent::Done => break,
                    _ => {},
                }
            }
            assert_eq!(decoded, PAYLOAD);
            let metrics = reader.metrics();
            assert!(metrics.requests() > 1);
            let source = reader.into_inner();
            assert_eq!(metrics.requests(), source.requests);
            assert_eq!(metrics.transferred_bytes(), source.transferred);
        });
    }

    #[test]
    fn async_identity_mutation_is_rejected() {
        block_on(async {
            let mut source = MemoryRange::new(archive(FormatId::Zip), 64);
            source.mutate_on_request = Some(1);
            let error = AsyncRangeArchiveReader::new(source)
                .await
                .expect_err("async mutation must fail");
            assert_eq!(
                typed_range_error(&error),
                Some(RangeReadError::IdentityChanged)
            );
        });
    }
}
