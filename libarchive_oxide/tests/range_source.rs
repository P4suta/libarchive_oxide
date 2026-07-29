// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Immutable sync and runtime-neutral async range-source contracts.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::{self, Cursor, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use libarchive_oxide::advanced::{
    FileReadAt, FormatCapabilities, MemoryReadAt, RandomAccessArchiveDecoder,
    RandomAccessFormatProvider, RangeArchiveReader, RangeReadError, RangeReadErrorKind,
    RangeReader, ReadAt, Registry, SeekReadAt, SourceIdentity, SourceIdentityError, SourceLimits,
    VolumeId, VolumeResolver, VolumeSet,
};
use libarchive_oxide::{Error, ReaderEvent, SeekArchiveWriter};
use libarchive_oxide_core::{
    AccessMode, ArchivePath, DirectionSet, EntryKind, EntryMetadata, FormatId, Limits,
};

const PAYLOAD: &[u8] = b"immutable range source payload";
type SourceConfiguration = fn(&mut MemoryRange);

#[derive(Debug)]
struct MemoryRange {
    bytes: Vec<u8>,
    identities: [SourceIdentity; 2],
    max_chunk: usize,
    requests: AtomicU64,
    transferred: AtomicU64,
    max_request: AtomicUsize,
    mutated: AtomicBool,
    grown: AtomicBool,
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
            identities: [
                SourceIdentity::try_new(b"memory-generation-1".to_vec())
                    .expect("valid source identity"),
                SourceIdentity::try_new(b"memory-generation-2".to_vec())
                    .expect("valid source identity"),
            ],
            max_chunk,
            requests: AtomicU64::new(0),
            transferred: AtomicU64::new(0),
            max_request: AtomicUsize::new(0),
            mutated: AtomicBool::new(false),
            grown: AtomicBool::new(false),
            mutate_on_request: None,
            grow_on_request: None,
            fail_short: false,
            no_progress: false,
            invalid_count: false,
        }
    }
}

impl ReadAt for MemoryRange {
    fn len(&self) -> u64 {
        self.bytes.len() as u64 + u64::from(self.grown.load(Ordering::Relaxed))
    }

    fn identity(&self) -> &SourceIdentity {
        if self.mutated.load(Ordering::Relaxed) {
            &self.identities[1]
        } else {
            &self.identities[0]
        }
    }

    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        let request = self.requests.fetch_add(1, Ordering::Relaxed) + 1;
        self.max_request.fetch_max(output.len(), Ordering::Relaxed);
        if self.mutate_on_request == Some(request) {
            self.mutated.store(true, Ordering::Relaxed);
        }
        if self.grow_on_request == Some(request) {
            self.grown.store(true, Ordering::Relaxed);
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
        self.transferred.fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
    }
}

#[derive(Debug)]
struct ExternallyMutableRange {
    bytes: Vec<u8>,
    identities: [SourceIdentity; 2],
    mutated: Arc<AtomicBool>,
}

impl ReadAt for ExternallyMutableRange {
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

    fn read_at(&self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
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

fn typed_range_error(error: &Error) -> Option<RangeReadErrorKind> {
    error
        .io_error()?
        .get_ref()?
        .downcast_ref::<RangeReadError>()
        .copied()
        .map(RangeReadError::kind)
}

fn typed_io_error(error: &io::Error) -> Option<&RangeReadError> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<RangeReadError>())
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
        let source = reader.into_inner().expect("recover range source");
        assert_eq!(metrics.requests(), source.requests.load(Ordering::Relaxed));
        assert_eq!(
            metrics.transferred_bytes(),
            source.transferred.load(Ordering::Relaxed)
        );
    }
}

#[test]
fn downstream_trait_object_opens_a_real_zip_without_spooling() {
    let source: Arc<dyn ReadAt> = Arc::new(MemoryRange::new(archive(FormatId::Zip), 9));
    let mut reader = RangeArchiveReader::new(source).expect("open object-safe ZIP source");
    assert_eq!(reader.format(), FormatId::Zip);

    let mut decoded = Vec::new();
    loop {
        match reader.next_event().expect("object-safe source event") {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, PAYLOAD);
    assert!(reader.metrics().transferred_bytes() < archive(FormatId::Zip).len() as u64 * 4);
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
        Some(RangeReadErrorKind::IdentityChanged)
    );
}

#[test]
fn length_changes_fail_closed_during_a_request() {
    let mut source = MemoryRange::new(archive(FormatId::Zip), 64);
    source.grow_on_request = Some(1);
    let error = RangeArchiveReader::new(source).expect_err("length mutation must fail");
    assert_eq!(
        typed_range_error(&error),
        Some(RangeReadErrorKind::LengthChanged)
    );
}

#[test]
fn identity_is_revalidated_between_public_commands() {
    let mutated = Arc::new(AtomicBool::new(false));
    let source = ExternallyMutableRange {
        bytes: archive(FormatId::Zip),
        identities: [
            SourceIdentity::try_new(b"external-generation-1".to_vec())
                .expect("valid source identity"),
            SourceIdentity::try_new(b"external-generation-2".to_vec())
                .expect("valid source identity"),
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
        Some(RangeReadErrorKind::IdentityChanged)
    );
}

#[test]
fn cache_and_read_ahead_obey_limits() {
    let source = MemoryRange::new(vec![7; 100], 100);
    let limits = Limits::safe()
        .with_metadata_bytes(Some(32))
        .with_in_flight_bytes(Some(16));
    let mut reader = RangeReader::with_limits(source, limits).expect("bounded range reader");
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
    assert_eq!(source.max_request.load(Ordering::Relaxed), 16);

    let source = MemoryRange::new(vec![7; 100], 100);
    let mut reader = RangeReader::with_limits(source, Limits::safe().with_metadata_bytes(Some(1)))
        .expect("small-cache range reader");
    let error =
        std::io::Read::read(&mut reader, &mut bytes).expect_err("cache budget must be enforced");
    assert_eq!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<RangeReadError>())
            .copied()
            .map(RangeReadError::kind),
        Some(RangeReadErrorKind::CacheBudgetExceeded)
    );
}

#[test]
fn range_protocol_failures_remain_typed() {
    let cases: [(SourceConfiguration, RangeReadErrorKind); 3] = [
        (
            |source: &mut MemoryRange| source.fail_short = true,
            RangeReadErrorKind::ShortRead,
        ),
        (
            |source: &mut MemoryRange| source.no_progress = true,
            RangeReadErrorKind::NoProgress,
        ),
        (
            |source: &mut MemoryRange| source.invalid_count = true,
            RangeReadErrorKind::InvalidReadCount,
        ),
    ];
    for (configure, expected) in cases {
        let mut source = MemoryRange::new(vec![1, 2, 3], 3);
        configure(&mut source);
        let mut reader = RangeReader::new(source).expect("range reader");
        let mut byte = [0];
        let error = std::io::Read::read(&mut reader, &mut byte).expect_err("typed range failure");
        assert_eq!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<RangeReadError>())
                .copied()
                .map(RangeReadError::kind),
            Some(expected)
        );
    }

    let source = MemoryRange::new(vec![1, 2, 3], 3);
    let mut reader = RangeReader::new(source).expect("range reader");
    let error = reader
        .seek(SeekFrom::Start(4))
        .expect_err("out-of-bounds seek");
    assert_eq!(
        error
            .get_ref()
            .and_then(|source| source.downcast_ref::<RangeReadError>())
            .copied()
            .map(RangeReadError::kind),
        Some(RangeReadErrorKind::OffsetOutOfBounds)
    );
}

#[test]
fn exact_reads_validate_overflow_bounds_and_progress() {
    let source = MemoryReadAt::new(
        b"0123456789".to_vec(),
        SourceIdentity::try_new(b"exact-memory-v1".to_vec()).expect("valid source identity"),
    );
    let mut middle = [0_u8; 4];
    source
        .read_exact_at(3, &mut middle)
        .expect("exact middle range");
    assert_eq!(&middle, b"3456");

    let mut beyond = [0_u8; 2];
    let error = source
        .read_exact_at(9, &mut beyond)
        .expect_err("declared range must be enforced");
    let error = typed_io_error(&error).expect("typed out-of-bounds error");
    assert_eq!(error.kind(), RangeReadErrorKind::OffsetOutOfBounds);
    assert_eq!(error.range(), Some((9, 2)));

    let error = source
        .read_exact_at(u64::MAX, &mut beyond)
        .expect_err("offset addition must not wrap");
    let error = typed_io_error(&error).expect("typed overflow error");
    assert_eq!(error.kind(), RangeReadErrorKind::OffsetOverflow);
    assert_eq!(error.range(), Some((u64::MAX, 2)));

    let mut stalled = MemoryRange::new(vec![1, 2, 3], 3);
    stalled.no_progress = true;
    let error = stalled
        .read_exact_at(0, &mut [0_u8; 1])
        .expect_err("zero progress must fail");
    assert_eq!(
        typed_io_error(&error).copied().map(RangeReadError::kind),
        Some(RangeReadErrorKind::NoProgress)
    );
}

#[test]
fn source_identity_rejects_empty_and_attacker_sized_values() {
    assert_eq!(
        SourceIdentity::try_new(Vec::new()).expect_err("empty identity"),
        SourceIdentityError::Empty
    );
    assert_eq!(
        SourceIdentity::try_new(vec![0_u8; 1025]).expect_err("oversized identity"),
        SourceIdentityError::TooLong {
            length: 1025,
            maximum: 1024,
        }
    );
}

#[test]
fn memory_seek_and_file_adapters_obey_the_same_contract() {
    let identity =
        SourceIdentity::try_new(b"seek-cursor-v1".to_vec()).expect("valid source identity");
    let seek = SeekReadAt::new(Cursor::new(b"seek-adapter".to_vec()), identity)
        .expect("construct seek adapter");
    let mut bytes = [0_u8; 4];
    seek.read_exact_at(5, &mut bytes).expect("seek exact read");
    assert_eq!(&bytes, b"adap");

    let mut file = tempfile::NamedTempFile::new().expect("temporary source");
    file.write_all(b"file-adapter").expect("write source");
    file.flush().expect("flush source");
    let file_source = FileReadAt::open(file.path()).expect("open file adapter");
    file_source
        .read_exact_at(5, &mut bytes)
        .expect("file exact read");
    assert_eq!(&bytes, b"adap");
}

#[test]
fn source_size_limit_is_checked_before_parser_io() {
    let source = MemoryReadAt::new(
        vec![0_u8; 9],
        SourceIdentity::try_new(b"oversized-source".to_vec()).expect("valid source identity"),
    );
    let error = RangeReader::with_source_limits(
        source,
        Limits::safe(),
        SourceLimits::safe().with_source_bytes(Some(8)),
    )
    .expect_err("oversized encoded source must fail at construction");
    let error = typed_io_error(&error).expect("typed source-size error");
    assert_eq!(error.kind(), RangeReadErrorKind::SourceSizeExceeded);
    assert_eq!(error.budget(), Some((9, 8)));
}

struct ExternalVolumeResolver {
    volumes: BTreeMap<VolumeId, Arc<dyn ReadAt>>,
    requests: AtomicU64,
}

impl VolumeResolver for ExternalVolumeResolver {
    fn resolve(&self, volume: VolumeId) -> io::Result<Option<Arc<dyn ReadAt>>> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        Ok(self.volumes.get(&volume).cloned())
    }
}

fn volume_source(index: u32, bytes: &[u8]) -> Arc<dyn ReadAt> {
    Arc::new(MemoryReadAt::new(
        bytes.to_vec(),
        SourceIdentity::try_new(format!("volume-{index}-v1").into_bytes())
            .expect("valid source identity"),
    ))
}

#[test]
fn downstream_volume_resolver_is_cached_bounded_and_contextual() {
    let primary = volume_source(0, b"primary");
    let secondary = volume_source(1, b"secondary");
    let resolver = Arc::new(ExternalVolumeResolver {
        volumes: BTreeMap::from([(VolumeId::new(1), Arc::clone(&secondary))]),
        requests: AtomicU64::new(0),
    });
    let volumes = VolumeSet::new(
        primary,
        resolver.clone(),
        SourceLimits::safe()
            .with_volumes(Some(2))
            .with_volume_bytes(Some(32)),
    )
    .expect("bounded volume set");

    let secondary_source = volumes
        .resolve_required(VolumeId::new(1))
        .expect("resolve second volume");
    let mut bytes = [0_u8; 9];
    secondary_source
        .read_exact_at(0, &mut bytes)
        .expect("read resolved volume");
    assert_eq!(&bytes, b"secondary");
    volumes
        .resolve_required(VolumeId::new(1))
        .expect("reuse cached volume");
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);

    let error = volumes
        .resolve_required(VolumeId::new(2))
        .err()
        .expect("third distinct volume exceeds count limit");
    let error = typed_io_error(&error).expect("typed count failure");
    assert_eq!(error.kind(), RangeReadErrorKind::VolumeCountExceeded);
    assert_eq!(error.volume(), Some(VolumeId::new(2)));
    assert_eq!(error.budget(), Some((3, 2)));
}

#[test]
fn volume_total_and_missing_fail_before_provider_decode() {
    let primary = volume_source(0, b"1234");
    let secondary = volume_source(1, b"56789");
    let resolver = Arc::new(ExternalVolumeResolver {
        volumes: BTreeMap::from([(VolumeId::new(1), secondary)]),
        requests: AtomicU64::new(0),
    });
    let volumes = VolumeSet::new(
        primary,
        resolver,
        SourceLimits::safe()
            .with_volumes(Some(3))
            .with_volume_bytes(Some(8)),
    )
    .expect("primary fits total budget");
    let error = volumes
        .resolve_required(VolumeId::new(1))
        .err()
        .expect("resolved total must remain bounded");
    let error = typed_io_error(&error).expect("typed total-byte error");
    assert_eq!(error.kind(), RangeReadErrorKind::VolumeBytesExceeded);
    assert_eq!(error.budget(), Some((9, 8)));

    let empty = Arc::new(ExternalVolumeResolver {
        volumes: BTreeMap::new(),
        requests: AtomicU64::new(0),
    });
    let volumes = VolumeSet::new(
        volume_source(0, b"0"),
        empty,
        SourceLimits::safe().with_volumes(Some(2)),
    )
    .expect("missing-volume set");
    let error = volumes
        .resolve_required(VolumeId::new(1))
        .err()
        .expect("missing volume must remain explicit");
    let error = typed_io_error(&error).expect("typed missing-volume error");
    assert_eq!(error.kind(), RangeReadErrorKind::MissingVolume);
    assert_eq!(error.volume(), Some(VolumeId::new(1)));
}

struct RacingResolver {
    barrier: Barrier,
}

impl VolumeResolver for RacingResolver {
    fn resolve(&self, volume: VolumeId) -> io::Result<Option<Arc<dyn ReadAt>>> {
        self.barrier.wait();
        Ok(Some(volume_source(
            volume.get(),
            &[u8::try_from(volume.get()).unwrap_or(u8::MAX)],
        )))
    }
}

#[test]
fn concurrent_volume_commit_rechecks_the_count_budget() {
    let volumes = Arc::new(
        VolumeSet::new(
            volume_source(0, b"0"),
            Arc::new(RacingResolver {
                barrier: Barrier::new(2),
            }),
            SourceLimits::safe().with_volumes(Some(2)),
        )
        .expect("concurrent volume set"),
    );

    let handles: Vec<_> = [VolumeId::new(1), VolumeId::new(2)]
        .into_iter()
        .map(|volume| {
            let volumes = Arc::clone(&volumes);
            std::thread::spawn(move || volumes.resolve_required(volume))
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("resolver thread"))
        .collect();

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let failure = results
        .iter()
        .find_map(|result| result.as_ref().err())
        .and_then(typed_io_error)
        .expect("one typed concurrent count failure");
    assert_eq!(failure.kind(), RangeReadErrorKind::VolumeCountExceeded);
}

const MULTI_VOLUME_FORMAT: FormatId = match FormatId::custom(0x8000_0042) {
    Some(format) => format,
    None => panic!("custom format identifier"),
};

struct ExternalMultiVolumeFormat;

impl RandomAccessFormatProvider for ExternalMultiVolumeFormat {
    fn format(&self) -> FormatId {
        MULTI_VOLUME_FORMAT
    }

    fn name(&self) -> &'static str {
        "external-multi-volume"
    }

    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities::uniform(DirectionSet::READ, AccessMode::Seek)
    }

    fn probe(&self, source: &VolumeSet, _limits: Limits) -> Result<bool, Error> {
        let mut magic = [0_u8; 4];
        source.primary().read_exact_at(0, &mut magic)?;
        Ok(&magic == b"MV01")
    }

    fn open(
        &self,
        source: Arc<VolumeSet>,
        _limits: Limits,
    ) -> Result<Box<dyn RandomAccessArchiveDecoder>, Error> {
        let mut payload = vec![0_u8; 9];
        source
            .resolve_required(VolumeId::new(1))?
            .read_exact_at(0, &mut payload)?;
        Ok(Box::new(ExternalMultiVolumeDecoder { payload, state: 0 }))
    }
}

struct ExternalMultiVolumeDecoder {
    payload: Vec<u8>,
    state: u8,
}

impl RandomAccessArchiveDecoder for ExternalMultiVolumeDecoder {
    fn next_event(&mut self) -> Result<ReaderEvent<'_>, Error> {
        let event = match self.state {
            0 => ReaderEvent::Entry(
                EntryMetadata::builder(
                    EntryKind::File,
                    ArchivePath::from_utf8("external-volume.bin"),
                )
                .size(Some(u64::try_from(self.payload.len()).unwrap_or(u64::MAX)))
                .build(),
            ),
            1 => ReaderEvent::Data(&self.payload),
            2 => ReaderEvent::EndEntry,
            _ => ReaderEvent::Done,
        };
        self.state = self.state.saturating_add(1);
        Ok(event)
    }

    fn skip_entry(&mut self) -> Result<(), Error> {
        self.state = 3;
        Ok(())
    }
}

#[test]
fn registry_random_access_provider_consumes_the_bounded_volume_seam() {
    let resolver = Arc::new(ExternalVolumeResolver {
        volumes: BTreeMap::from([(VolumeId::new(1), volume_source(1, b"secondary"))]),
        requests: AtomicU64::new(0),
    });
    let volumes = Arc::new(
        VolumeSet::new(
            volume_source(0, b"MV01"),
            resolver.clone(),
            SourceLimits::safe().with_volumes(Some(2)),
        )
        .expect("external provider volumes"),
    );
    let mut builder = Registry::builder();
    builder
        .register_random_access_format(Box::new(ExternalMultiVolumeFormat))
        .expect("register external random-access provider");
    let registry = builder.build();
    assert_eq!(registry.random_access_format_count(), 1);
    assert_eq!(
        registry
            .detect_random_access(&volumes, Limits::safe())
            .expect("detect external format"),
        Some(MULTI_VOLUME_FORMAT)
    );

    let mut decoder = registry
        .open_random_access(MULTI_VOLUME_FORMAT, volumes, Limits::safe())
        .expect("open external multi-volume provider");
    let mut payload_bytes = Vec::new();
    loop {
        match decoder.next_event().expect("external provider event") {
            ReaderEvent::Data(bytes) => payload_bytes.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(payload_bytes, b"secondary");
    assert_eq!(resolver.requests.load(Ordering::Relaxed), 1);
}

#[test]
fn registry_random_access_provider_preserves_missing_volume_error() {
    let volumes = Arc::new(
        VolumeSet::new(
            volume_source(0, b"MV01"),
            Arc::new(ExternalVolumeResolver {
                volumes: BTreeMap::new(),
                requests: AtomicU64::new(0),
            }),
            SourceLimits::safe().with_volumes(Some(2)),
        )
        .expect("missing external volume set"),
    );
    let mut builder = Registry::builder();
    builder
        .register_random_access_format(Box::new(ExternalMultiVolumeFormat))
        .expect("register external random-access provider");
    let error = builder
        .build()
        .open_random_access(MULTI_VOLUME_FORMAT, volumes, Limits::safe())
        .err()
        .expect("missing volume must prevent provider open");
    assert_eq!(
        error
            .io_error()
            .and_then(typed_io_error)
            .copied()
            .map(RangeReadError::kind),
        Some(RangeReadErrorKind::MissingVolume)
    );
}

#[cfg(feature = "async")]
mod asynchronous {
    use futures_lite::future::block_on;
    use libarchive_oxide::advanced::{AsyncRangeArchiveReader, AsyncRangeSource};

    use super::*;

    impl AsyncRangeSource for MemoryRange {
        fn len(&self) -> u64 {
            ReadAt::len(self)
        }

        fn identity(&self) -> &SourceIdentity {
            ReadAt::identity(self)
        }

        async fn read_range(&mut self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
            ReadAt::read_at(self, offset, output)
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
            assert_eq!(metrics.requests(), source.requests.load(Ordering::Relaxed));
            assert_eq!(
                metrics.transferred_bytes(),
                source.transferred.load(Ordering::Relaxed)
            );
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
                Some(RangeReadErrorKind::IdentityChanged)
            );
        });
    }

    #[test]
    fn async_source_size_limit_matches_the_sync_boundary() {
        block_on(async {
            let source = MemoryRange::new(vec![0_u8; 9], 9);
            let error = AsyncRangeArchiveReader::with_source_limits(
                source,
                Limits::safe(),
                SourceLimits::safe().with_source_bytes(Some(8)),
            )
            .await
            .expect_err("async encoded source must be bounded before parser I/O");
            assert_eq!(
                typed_range_error(&error),
                Some(RangeReadErrorKind::SourceSizeExceeded)
            );
        });
    }
}
