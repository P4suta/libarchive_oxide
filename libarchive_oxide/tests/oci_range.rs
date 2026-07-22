// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Range-backed OCI layer reading: an in-memory `RangeSource` fed through
//! `RangeReader` into `OciLayerEngine` must produce byte-identical digests to a
//! direct `Read`, and its `read_range` offsets and boundaries must be exact.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::cell::RefCell;
use std::io::{self, Cursor, Read};
use std::rc::Rc;

use libarchive_oxide::libarchive_oxide_core::{
    ArchivePath, EntryKind, EntryMetadata, FilterId, FormatId,
};
use libarchive_oxide::{
    ArchiveEngine, CreateOptions, LayerDigests, OciLayerEngine, RangeReader, RangeSource,
    SourceIdentity,
};

/// A log of every `(offset, buffer_len)` pair passed to `read_range`.
type CallLog = Rc<RefCell<Vec<(u64, usize)>>>;

/// An immutable in-memory range source that records each fetch it serves.
struct MemoryRange {
    bytes: Vec<u8>,
    identity: SourceIdentity,
    calls: CallLog,
}

impl RangeSource for MemoryRange {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    fn read_range(&mut self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        // The adapter must never address bytes beyond the declared length.
        assert!(
            offset <= self.len(),
            "read_range offset {offset} exceeds declared len {}",
            self.len(),
        );
        self.calls.borrow_mut().push((offset, output.len()));
        let start = usize::try_from(offset).unwrap();
        let available = &self.bytes[start..];
        let count = available.len().min(output.len());
        output[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

/// Builds a `MemoryRange` over `blob` plus a handle to its fetch log.
fn memory_source(blob: &[u8]) -> (MemoryRange, CallLog) {
    let calls: CallLog = Rc::new(RefCell::new(Vec::new()));
    let source = MemoryRange {
        bytes: blob.to_vec(),
        identity: SourceIdentity::new(b"oci-range-test-v1".to_vec()),
        calls: calls.clone(),
    };
    (source, calls)
}

/// Builds a small tar+gzip layer blob spanning several tar blocks.
fn build_layer() -> Vec<u8> {
    let entries: [(&[u8], EntryKind, &[u8]); 3] = [
        (b"etc/", EntryKind::Dir, b""),
        (b"etc/hostname", EntryKind::File, b"oxide-node\n"),
        (b"usr/bin/tool", EntryKind::File, &[0x5a_u8; 4096]),
    ];
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new()
                .with_format(FormatId::Tar)
                .with_filter(Some(FilterId::Gzip)),
        )
        .expect("create layer writer");
    for (path, kind, body) in entries {
        let metadata = EntryMetadata::builder(kind, ArchivePath::from_bytes(path.to_vec()))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start entry");
        if !body.is_empty() {
            writer.write_data(body).expect("write entry");
        }
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish layer")
}

/// Reads all entry paths and the digests from a direct `Read` over `blob`.
fn direct_digests(blob: &[u8]) -> (Vec<Vec<u8>>, LayerDigests) {
    let mut session = OciLayerEngine::new()
        .open(Cursor::new(blob.to_vec()))
        .expect("open direct");
    let mut paths = Vec::new();
    while let Some(entry) = session.next_entry().expect("direct next entry") {
        paths.push(entry.path().to_vec());
    }
    (paths, session.digests().expect("direct digests"))
}

#[test]
fn range_backed_digests_match_direct_read() {
    let blob = build_layer();
    let (direct_paths, direct) = direct_digests(&blob);

    let (source, calls) = memory_source(&blob);
    let mut session = OciLayerEngine::new()
        .open(RangeReader::new(source))
        .expect("open range");
    let mut paths = Vec::new();
    while let Some(entry) = session.next_entry().expect("range next entry") {
        paths.push(entry.path().to_vec());
    }
    let range = session.digests().expect("range digests");

    assert_eq!(paths, direct_paths);
    assert_eq!(range, direct);
    assert!(
        !calls.borrow().is_empty(),
        "the range source must have been read"
    );
}

#[test]
fn range_backed_session_verifies_against_direct_digests() {
    let blob = build_layer();
    let (_, direct) = direct_digests(&blob);

    let (source, _calls) = memory_source(&blob);
    let mut session = OciLayerEngine::new()
        .open(RangeReader::new(source))
        .expect("open range");
    session.verify(direct).expect("verify range-backed layer");
}

#[test]
fn range_reader_reproduces_bytes_across_chunk_boundaries() {
    let blob = build_layer();
    let (source, calls) = memory_source(&blob);

    let mut reader = RangeReader::new(source);
    let mut readback = Vec::new();
    reader.read_to_end(&mut readback).expect("read to end");
    assert_eq!(
        readback, blob,
        "range reader must reproduce the blob exactly"
    );

    let log = calls.borrow();
    assert!(!log.is_empty(), "at least one fetch is required");
    for (offset, len) in log.iter().copied() {
        // Every fetch starts strictly inside the source and requests bytes.
        assert!(
            offset < blob.len() as u64,
            "fetch offset {offset} must be within the source"
        );
        assert!(len > 0, "fetch length must be positive");
    }
}

#[test]
fn read_range_returns_exact_bytes_at_each_offset() {
    let blob = build_layer();
    let len = blob.len();
    let (mut source, _calls) = memory_source(&blob);

    // Full read from the start returns a prefix of the blob.
    let mut whole = vec![0u8; len];
    let read = source.read_range(0, &mut whole).expect("read from start");
    assert_eq!(&whole[..read], &blob[..read]);

    // A window read from the middle into a smaller buffer.
    let mid = len / 2;
    let mut window = [0u8; 7];
    let read = source
        .read_range(mid as u64, &mut window)
        .expect("read middle");
    assert_eq!(read, window.len().min(len - mid));
    assert_eq!(&window[..read], &blob[mid..mid + read]);

    // The final byte is reachable and returns exactly one byte.
    let mut last = [0u8; 4];
    let read = source
        .read_range((len - 1) as u64, &mut last)
        .expect("read last byte");
    assert_eq!(read, 1);
    assert_eq!(last[0], blob[len - 1]);

    // An offset exactly at the length yields zero bytes without error.
    let mut past = [0u8; 4];
    let read = source
        .read_range(len as u64, &mut past)
        .expect("read at end");
    assert_eq!(read, 0);
}
