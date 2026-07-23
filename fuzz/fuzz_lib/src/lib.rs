// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable fuzz invariants for the v0.2 streaming protocols.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};

use arbitrary::Arbitrary;
use libarchive_oxide::filter::crc32;
use libarchive_oxide::filter::gzip::{GzipDecoder, GzipEncoder};
use libarchive_oxide::{
    ArchiveReader, ArchiveWriter, FilterReader, ReaderEvent, SeekArchiveReader, SeekArchiveWriter,
    StreamError,
};
use libarchive_oxide_core::{
    ArchiveError, ArchivePath, Codec, CodecStatus, EndOfInput, EntryKind, EntryMetadata, ErrorKind,
    FormatId, Limits,
};

const MAX_ENTRIES: usize = 200_000;
const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const CODEC_CAP: usize = 64 * 1024 * 1024;
const CODEC_ROUNDTRIP_MAX: usize = 256 * 1024;
const LZMA2_DICT: u32 = 8 * 1024 * 1024;
const MAX_ROUNDTRIP_ENTRIES: usize = 48;
const MAX_NAME_LEN: usize = 40;
const MAX_ROUNDTRIP_DATA: usize = 4096;

fn fuzz_limits() -> Limits {
    Limits::default()
        .with_decoded_total(Some(MAX_TOTAL_BYTES))
        .with_entry_bytes(Some(MAX_TOTAL_BYTES))
        .with_entries(Some(MAX_ENTRIES as u64))
        .with_metadata_bytes(Some(8 * 1024 * 1024))
        .with_in_flight_bytes(Some(256 * 1024))
}

fn drive_sequential(data: &[u8]) {
    let mut reader = ArchiveReader::with_limits(Cursor::new(data), fuzz_limits());
    let mut events = 0usize;
    let mut payload = 0u64;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Entry(metadata)) => {
                let _ = metadata.path().as_bytes();
                let _ = metadata.link_target().map(|path| path.as_bytes());
                events = events.saturating_add(1);
            },
            Ok(ReaderEvent::Data(bytes)) => {
                payload = payload.saturating_add(bytes.len() as u64);
            },
            Ok(ReaderEvent::Done) | Err(_) => return,
            Ok(ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry) => {},
            Ok(_) => return,
        }
        if events > MAX_ENTRIES || payload > MAX_TOTAL_BYTES {
            return;
        }
    }
}

fn drive_seek(data: &[u8]) {
    let Ok(mut reader) = SeekArchiveReader::with_limits(Cursor::new(data), fuzz_limits()) else {
        return;
    };
    let mut events = 0usize;
    let mut payload = 0u64;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Entry(metadata)) => {
                let _ = metadata.path().as_bytes();
                let _ = metadata.link_target().map(|path| path.as_bytes());
                events = events.saturating_add(1);
            },
            Ok(ReaderEvent::Data(bytes)) => {
                payload = payload.saturating_add(bytes.len() as u64);
            },
            Ok(ReaderEvent::Done) | Err(_) => return,
            Ok(ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry) => {},
            Ok(_) => return,
        }
        if events > MAX_ENTRIES || payload > MAX_TOTAL_BYTES {
            return;
        }
    }
}

/// tar decoder: arbitrary bytes and chunk boundaries must not panic.
pub fn read_tar(data: &[u8]) {
    drive_sequential(data);
}

/// cpio decoder: arbitrary bytes and chunk boundaries must not panic.
pub fn read_cpio(data: &[u8]) {
    drive_sequential(data);
}

/// ar decoder: arbitrary bytes and chunk boundaries must not panic.
pub fn read_ar(data: &[u8]) {
    drive_sequential(data);
}

/// ZIP seek decoder: arbitrary indexes and payloads must not panic.
pub fn read_zip(data: &[u8]) {
    drive_seek(data);
}

/// 7z seek decoder: arbitrary indexes and coder metadata must not panic.
pub fn read_7z(data: &[u8]) {
    drive_seek(data);
}

/// ISO seek decoder: arbitrary volume and directory records must not panic.
pub fn read_iso(data: &[u8]) {
    drive_seek(data);
}

/// Synthesized archive member.
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzEntry {
    /// Raw candidate name (normalized before use).
    pub name: Vec<u8>,
    /// Raw candidate payload (bounded before use).
    pub data: Vec<u8>,
}

fn normalize_files(entries: &[FuzzEntry]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for (index, entry) in entries.iter().take(MAX_ROUNDTRIP_ENTRIES).enumerate() {
        let mut name: Vec<u8> = entry
            .name
            .iter()
            .copied()
            .filter(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            .take(MAX_NAME_LEN)
            .collect();
        while matches!(name.first(), Some(b'.' | b'-')) {
            name.remove(0);
        }
        if name.is_empty() {
            name = format!("f{index}").into_bytes();
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            let mut unique = format!("{index}_").into_bytes();
            unique.extend_from_slice(&name);
            if !seen.insert(unique.to_ascii_lowercase()) {
                continue;
            }
            name = unique;
        }
        output.push((
            name,
            entry
                .data
                .iter()
                .copied()
                .take(MAX_ROUNDTRIP_DATA)
                .collect(),
        ));
    }
    output
}

fn metadata(name: &[u8], size: usize) -> EntryMetadata {
    EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(name.to_vec()))
        .size(Some(size as u64))
        .mode(Some(0o644))
        .build()
}

fn expected_map(files: &[(Vec<u8>, Vec<u8>)]) -> BTreeMap<Vec<u8>, Vec<u8>> {
    files.iter().cloned().collect()
}

macro_rules! collect_events {
    ($reader:expr) => {{
        let reader = &mut $reader;
        let mut files = BTreeMap::new();
        let mut current: Option<(Vec<u8>, Vec<u8>)> = None;
        loop {
            match reader.next_event() {
                Ok(ReaderEvent::Entry(metadata)) => {
                    current = (metadata.kind() == EntryKind::File)
                        .then(|| (metadata.path().as_bytes().to_vec(), Vec::new()));
                },
                Ok(ReaderEvent::Data(bytes)) => match current.as_mut() {
                    Some((_, body)) => body.extend_from_slice(bytes),
                    None => break None,
                },
                Ok(ReaderEvent::EndEntry) => {
                    if let Some((name, body)) = current.take() {
                        files.insert(name, body);
                    }
                },
                Ok(ReaderEvent::ArchiveMetadata(_)) => {},
                Ok(ReaderEvent::Done) => break Some(files),
                Ok(_) | Err(_) => break None,
            }
        }
    }};
}

fn collect_sequential(bytes: Vec<u8>) -> Option<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut reader = ArchiveReader::with_limits(Cursor::new(bytes), fuzz_limits());
    collect_events!(reader)
}

fn collect_seek(bytes: Vec<u8>) -> Option<BTreeMap<Vec<u8>, Vec<u8>>> {
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(bytes), fuzz_limits()).ok()?;
    collect_events!(reader)
}

fn roundtrip_sequential(entries: &[FuzzEntry], format: FormatId) {
    let files = normalize_files(entries);
    let Ok(mut writer) = ArchiveWriter::with_format_and_limits(Vec::new(), format, fuzz_limits())
    else {
        return;
    };
    for (name, body) in &files {
        writer
            .start_entry(&metadata(name, body.len()))
            .expect("normalized v0.2 metadata must be accepted");
        for chunk in body.chunks(17) {
            writer
                .write_data(chunk)
                .expect("bounded data command must be accepted");
        }
        writer
            .end_entry()
            .expect("declared size must close exactly");
    }
    let archive = writer.finish().expect("streaming writer must finish");
    assert_eq!(
        collect_sequential(archive),
        Some(expected_map(&files)),
        "{format:?} streaming read/write"
    );
}

fn roundtrip_seek(entries: &[FuzzEntry], format: FormatId) {
    let files = normalize_files(entries);
    let destination = Cursor::new(Vec::new());
    let Ok(mut writer) = SeekArchiveWriter::with_format(destination, format, fuzz_limits()) else {
        return;
    };
    for (name, body) in &files {
        writer
            .start_entry(&metadata(name, body.len()))
            .expect("normalized seek metadata must be accepted");
        for chunk in body.chunks(17) {
            writer
                .write_data(chunk)
                .expect("seek writer data command must be accepted");
        }
        writer.end_entry().expect("seek entry must close");
    }
    let archive = writer
        .finish()
        .expect("seek writer must finish")
        .into_inner();
    assert_eq!(
        collect_seek(archive),
        Some(expected_map(&files)),
        "{format:?} seek read/write"
    );
}

/// tar streaming round trip.
pub fn roundtrip_tar(entries: &[FuzzEntry]) {
    roundtrip_sequential(entries, FormatId::Tar);
}

/// cpio streaming round trip.
pub fn roundtrip_cpio(entries: &[FuzzEntry]) {
    roundtrip_sequential(entries, FormatId::Cpio);
}

/// ar streaming round trip.
pub fn roundtrip_ar(entries: &[FuzzEntry]) {
    roundtrip_sequential(entries, FormatId::Ar);
}

/// 7z seek-back writer and streaming reader round trip.
pub fn roundtrip_7z(entries: &[FuzzEntry]) {
    roundtrip_seek(entries, FormatId::SevenZip);
}

/// ISO seek-back writer and streaming reader round trip.
pub fn roundtrip_iso(entries: &[FuzzEntry]) {
    roundtrip_seek(entries, FormatId::Iso9660);
}

fn codec_decode_no_panic<C: Codec>(mut codec: C, data: &[u8]) {
    let mut input = data;
    let mut output = [0_u8; 257];
    let mut total = 0usize;
    loop {
        let Ok(step) = codec.process(input, &mut output, EndOfInput::End) else {
            return;
        };
        if step.consumed > input.len() || step.produced > output.len() {
            panic!("codec reported out-of-range progress");
        }
        input = &input[step.consumed..];
        total = total.saturating_add(step.produced);
        if total > CODEC_CAP || matches!(step.status, CodecStatus::Done) {
            return;
        }
        if step.consumed == 0 && step.produced == 0 {
            return;
        }
    }
}

fn gzip_encode(data: &[u8]) -> Option<Vec<u8>> {
    let mut codec = GzipEncoder::new(fuzz_limits());
    let mut input = data;
    let mut output = [0_u8; 257];
    let mut encoded = Vec::new();
    loop {
        let step = codec.process(input, &mut output, EndOfInput::End).ok()?;
        input = input.get(step.consumed..)?;
        encoded.extend_from_slice(output.get(..step.produced)?);
        if matches!(step.status, CodecStatus::Done) {
            return Some(encoded);
        }
        if step.consumed == 0 && step.produced == 0 {
            return None;
        }
    }
}

fn gzip_decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut codec = GzipDecoder::new(fuzz_limits());
    let mut input = data;
    let mut output = [0_u8; 257];
    let mut decoded = Vec::new();
    loop {
        let step = codec.process(input, &mut output, EndOfInput::End).ok()?;
        input = input.get(step.consumed..)?;
        decoded.extend_from_slice(output.get(..step.produced)?);
        if decoded.len() > CODEC_CAP {
            return None;
        }
        if matches!(step.status, CodecStatus::Done) {
            return Some(decoded);
        }
        if step.consumed == 0 && step.produced == 0 {
            return None;
        }
    }
}

/// gzip codec protocol and round-trip target.
pub fn codec_gzip(data: &[u8]) {
    filtered_decode_no_panic(data);
    codec_decode_no_panic(GzipDecoder::new(fuzz_limits()), data);
    let plain: Vec<u8> = data.iter().copied().take(CODEC_ROUNDTRIP_MAX).collect();
    if let Some(encoded) = gzip_encode(&plain) {
        assert_eq!(gzip_decode(&encoded), Some(plain));
    }
}

fn filtered_decode_no_panic(data: &[u8]) {
    let Ok(reader) = FilterReader::with_limits(Cursor::new(data), fuzz_limits()) else {
        return;
    };
    let _ = read_capped(reader, CODEC_CAP);
}

/// bzip2 incremental filter target.
pub fn codec_bzip2(data: &[u8]) {
    filtered_decode_no_panic(data);
}

/// zstd incremental filter target.
pub fn codec_zstd(data: &[u8]) {
    filtered_decode_no_panic(data);
}

/// XZ incremental filter target.
pub fn codec_xz(data: &[u8]) {
    filtered_decode_no_panic(data);
}

/// LZ4 incremental filter target.
pub fn codec_lz4(data: &[u8]) {
    filtered_decode_no_panic(data);
}

fn read_capped<R: Read>(mut reader: R, cap: usize) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Some(output),
            Ok(read) if output.len().saturating_add(read) <= cap => {
                output.extend_from_slice(&buffer[..read]);
            },
            Ok(_) | Err(_) => return None,
        }
    }
}

fn lzma2_decode_capped(data: &[u8], cap: usize) -> Option<Vec<u8>> {
    let reader = lzma_rust2::Lzma2Reader::new(Cursor::new(data.to_vec()), LZMA2_DICT, None);
    read_capped(reader, cap)
}

fn lzma2_encode(plain: &[u8]) -> Option<Vec<u8>> {
    let options = lzma_rust2::Lzma2Options::with_preset(6);
    let mut writer = lzma_rust2::Lzma2Writer::new(Vec::new(), options);
    writer.write_all(plain).ok()?;
    writer.finish().ok()
}

/// LZMA2 codec target used by 7z.
pub fn codec_lzma2(data: &[u8]) {
    let _ = lzma2_decode_capped(data, CODEC_CAP);
    let plain: Vec<u8> = data.iter().copied().take(CODEC_ROUNDTRIP_MAX).collect();
    if let Some(encoded) = lzma2_encode(&plain) {
        assert_eq!(lzma2_decode_capped(&encoded, CODEC_CAP), Some(plain));
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Structured 7z coder-graph fuzz (read_7z_graph)
// ════════════════════════════════════════════════════════════════════════════════════════════════
//
// Rather than mutate raw bytes, this target *synthesizes* a 7z `StreamsInfo` from an `arbitrary`
// spec — number of folders, per-coder method / arity / properties, bind pairs, packed indices, and
// coder/substream sizes — then frames it in a valid signature header (correct start- and
// next-header CRCs) so the reader's checksum gate is passed and the coder-graph parser is reached on
// every input. It then drives the seek reader and asserts the RM-303 invariant: no panic, bounded
// work, and every failure is a *typed* archive error (`Malformed` / `Unsupported` / `Integrity` /
// `Limit`) — never an untyped I/O error, a wrong answer, or an unbounded allocation. Cycles, stream
// overlaps, and truncation (via the `truncate` knob, recomputed under the header CRC) are the
// stressors the graph resolver and length arithmetic must survive.

/// Upper bounds keeping a synthesized archive small regardless of input size.
const GRAPH_MAX_FOLDERS: usize = 6;
const GRAPH_MAX_CODERS: usize = 6;
const GRAPH_MAX_ARITY: usize = 6;
const GRAPH_MAX_PROPS: usize = 8;
const GRAPH_MAX_UNPACK: usize = 24;
const GRAPH_MAX_SUBSTREAMS: usize = 6;
const GRAPH_MAX_PACKDATA: usize = 4096;

/// 7z signature magic (`'7' 'z' 0xBC 0xAF 0x27 0x1C`).
const GRAPH_SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

// 7z next-header property ids used by the synthesizer.
const G_K_END: u8 = 0x00;
const G_K_HEADER: u8 = 0x01;
const G_K_MAIN_STREAMS_INFO: u8 = 0x04;
const G_K_FILES_INFO: u8 = 0x05;
const G_K_PACK_INFO: u8 = 0x06;
const G_K_UNPACK_INFO: u8 = 0x07;
const G_K_SUBSTREAMS_INFO: u8 = 0x08;
const G_K_SIZE: u8 = 0x09;
const G_K_CRC: u8 = 0x0A;
const G_K_FOLDER: u8 = 0x0B;
const G_K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const G_K_NUM_UNPACK_STREAM: u8 = 0x0D;
const G_K_NAME: u8 = 0x11;

/// Candidate coder method ids: decodable coders, filters, and the two deferred/unsupported ids
/// (PPMd, BCJ2) plus an unknown id — so the synthesizer builds graphs arca decodes *and* graphs it
/// must type as `Unsupported`.
const GRAPH_METHOD_IDS: &[&[u8]] = &[
    &[0x21],                   // LZMA2
    &[0x03, 0x01, 0x01],       // LZMA
    &[0x03],                   // Delta filter
    &[0x03, 0x03, 0x01, 0x03], // BCJ x86
    &[0x0A],                   // BCJ ARM64
    &[0x04, 0x01, 0x08],       // Deflate (raw)
    &[0x04, 0x02, 0x02],       // BZip2
    &[0x04, 0xF7, 0x11, 0x01], // Zstd
    &[0x06, 0xF1, 0x07, 0x01], // AES-256
    &[0x03, 0x04, 0x01],       // PPMd (deferred → Unsupported)
    &[0x03, 0x03, 0x01, 0x1B], // BCJ2 (multi-stream, deferred → Unsupported)
    &[0x00],                   // Copy / unknown
];

/// One coder in a synthesized folder.
#[derive(Debug, Arbitrary)]
struct GraphCoder {
    method: u8,
    complex: bool,
    alt: u8,
    num_in: u8,
    num_out: u8,
    props: Vec<u8>,
}

/// One synthesized folder: its coders plus the bind-pair / packed-stream index pools the encoder
/// draws from (cycled to the arity the emitted coders imply).
#[derive(Debug, Arbitrary)]
struct GraphFolder {
    coders: Vec<GraphCoder>,
    bind_in: Vec<u8>,
    bind_out: Vec<u8>,
    packed: Vec<u8>,
}

/// A full `StreamsInfo` skeleton.
#[derive(Debug, Arbitrary)]
struct GraphSpec {
    pack_pos: u8,
    pack_sizes: Vec<u16>,
    folders: Vec<GraphFolder>,
    unpack_sizes: Vec<u16>,
    include_folder_crc: bool,
    include_substreams: bool,
    num_unpack_streams: Vec<u8>,
    substream_sizes: Vec<u16>,
    include_substream_crc: bool,
    include_files_info: bool,
    truncate: u16,
    pack_data: Vec<u8>,
}

/// Writes a 7z variable-length number (`WriteNumber`), mirroring the reader's `ReadNumber`.
#[allow(clippy::cast_possible_truncation)]
fn graph_number(out: &mut Vec<u8>, value: u64) {
    let mut first = 0u8;
    let mut mask = 0x80u8;
    let mut i = 0u32;
    while i < 8 {
        if value < (1u64 << (7 * (i + 1))) {
            first |= (value >> (8 * i)) as u8;
            break;
        }
        first |= mask;
        mask >>= 1;
        i += 1;
    }
    out.push(first);
    let mut v = value;
    for _ in 0..i {
        out.push(v as u8);
        v >>= 8;
    }
}

impl GraphCoder {
    /// Emits this coder and returns the `(num_in, num_out)` arca will parse from the emitted bytes.
    fn emit(&self, out: &mut Vec<u8>) -> (usize, usize) {
        let id = GRAPH_METHOD_IDS[self.method as usize % GRAPH_METHOD_IDS.len()];
        let id_size = id.len() as u8; // every candidate id is <= 4 bytes
        let has_props = !self.props.is_empty();
        let mut flags = id_size & 0x0F;
        if self.complex {
            flags |= 0x10;
        }
        if has_props {
            flags |= 0x20;
        }
        // Rarely set the "alternative methods" bit (~6%), which the reader must type as Unsupported.
        if self.alt < 16 {
            flags |= 0x80;
        }
        out.push(flags);
        out.extend_from_slice(id);
        let (num_in, num_out) = if self.complex {
            let ni = (self.num_in as usize % GRAPH_MAX_ARITY) + 1;
            let no = (self.num_out as usize % GRAPH_MAX_ARITY) + 1;
            graph_number(out, ni as u64);
            graph_number(out, no as u64);
            (ni, no)
        } else {
            (1, 1)
        };
        if has_props {
            let props: Vec<u8> = self.props.iter().copied().take(GRAPH_MAX_PROPS).collect();
            graph_number(out, props.len() as u64);
            out.extend_from_slice(&props);
        }
        (num_in, num_out)
    }
}

impl GraphSpec {
    /// Serializes the spec into a framed 7z archive image.
    #[allow(clippy::cast_possible_truncation)]
    fn encode(&self) -> Vec<u8> {
        let folders: Vec<&GraphFolder> = self.folders.iter().take(GRAPH_MAX_FOLDERS).collect();

        let mut streams = Vec::new();
        // ── PackInfo ──
        streams.push(G_K_PACK_INFO);
        graph_number(&mut streams, u64::from(self.pack_pos));
        let pack_sizes: Vec<u64> = self
            .pack_sizes
            .iter()
            .take(GRAPH_MAX_UNPACK)
            .map(|&s| u64::from(s))
            .collect();
        graph_number(&mut streams, pack_sizes.len() as u64);
        streams.push(G_K_SIZE);
        for &size in &pack_sizes {
            graph_number(&mut streams, size);
        }
        streams.push(G_K_END);

        // ── UnpackInfo ──
        streams.push(G_K_UNPACK_INFO);
        streams.push(G_K_FOLDER);
        graph_number(&mut streams, folders.len() as u64);
        streams.push(0x00); // folder definitions are inline (external == 0)
        let mut total_outputs = 0usize;
        for folder in &folders {
            let coders: Vec<&GraphCoder> = folder.coders.iter().take(GRAPH_MAX_CODERS).collect();
            let num_coders = coders.len().max(1);
            graph_number(&mut streams, num_coders as u64);
            let mut total_in = 0usize;
            let mut total_out = 0usize;
            for i in 0..num_coders {
                // At least one coder even if the pool is empty (an LZMA2 stand-in).
                let (ni, no) = match coders.get(i) {
                    Some(coder) => coder.emit(&mut streams),
                    None => {
                        streams.push(0x01); // id_size 1, simple coder
                        streams.push(0x21); // LZMA2
                        (1, 1)
                    },
                };
                total_in += ni;
                total_out += no;
            }
            total_outputs += total_out;
            // (numOut - 1) bind pairs, drawn from the folder's index pools (cycled), kept roughly
            // in range so some resolve cleanly and some overlap / cycle.
            let num_bind = total_out.saturating_sub(1);
            for k in 0..num_bind {
                let in_index = pool_index(&folder.bind_in, k, total_in);
                let out_index = pool_index(&folder.bind_out, k, total_out);
                graph_number(&mut streams, in_index as u64);
                graph_number(&mut streams, out_index as u64);
            }
            // Packed inputs = total_in - num_bind; >1 are listed explicitly, 1 is implicit.
            let num_packed = total_in.saturating_sub(num_bind);
            if num_packed > 1 {
                for k in 0..num_packed {
                    let idx = pool_index(&folder.packed, k, total_in.max(1));
                    graph_number(&mut streams, idx as u64);
                }
            }
        }
        streams.push(G_K_CODERS_UNPACK_SIZE);
        for i in 0..total_outputs {
            let size = self
                .unpack_sizes
                .get(i % self.unpack_sizes.len().max(1))
                .map_or(0, |&s| u64::from(s));
            graph_number(&mut streams, size);
        }
        if self.include_folder_crc {
            streams.push(G_K_CRC);
            streams.push(0x00); // not all defined
            let bytes = folders.len().div_ceil(8);
            streams.extend(std::iter::repeat_n(0u8, bytes)); // none defined
        }
        streams.push(G_K_END);

        // ── SubStreamsInfo (optional) ──
        if self.include_substreams && !folders.is_empty() {
            streams.push(G_K_SUBSTREAMS_INFO);
            let counts: Vec<usize> = (0..folders.len())
                .map(|f| {
                    self.num_unpack_streams
                        .get(f % self.num_unpack_streams.len().max(1))
                        .map_or(1, |&n| usize::from(n) % GRAPH_MAX_SUBSTREAMS)
                })
                .collect();
            streams.push(G_K_NUM_UNPACK_STREAM);
            for &c in &counts {
                graph_number(&mut streams, c as u64);
            }
            streams.push(G_K_SIZE);
            let mut si = 0usize;
            for &c in &counts {
                for _ in 0..c.saturating_sub(1) {
                    let size = self
                        .substream_sizes
                        .get(si % self.substream_sizes.len().max(1))
                        .map_or(0, |&s| u64::from(s));
                    graph_number(&mut streams, size);
                    si += 1;
                }
            }
            if self.include_substream_crc {
                streams.push(G_K_CRC);
                let total: usize = counts.iter().sum();
                streams.push(0x01); // all defined
                for _ in 0..total {
                    // Deliberately (almost certainly) wrong CRCs: a reached decode must surface a
                    // typed `Integrity` error, never a silent wrong answer.
                    streams.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
                }
            }
            streams.push(G_K_END);
        }
        streams.push(G_K_END); // end StreamsInfo

        // ── Assemble the plain kHeader body ──
        let mut next = vec![G_K_HEADER, G_K_MAIN_STREAMS_INFO];
        next.extend_from_slice(&streams);
        // Optional minimal FilesInfo (empty names) so a consistent graph reaches the decode path.
        if self.include_files_info && !folders.is_empty() {
            next.push(G_K_FILES_INFO);
            let num_files = folders.len();
            graph_number(&mut next, num_files as u64);
            graph_number(&mut next, u64::from(G_K_NAME));
            let mut name_body = vec![0x00u8]; // names are inline (external == 0)
            for _ in 0..num_files {
                name_body.extend_from_slice(&[0x00, 0x00]); // empty UTF-16 name (terminator only)
            }
            graph_number(&mut next, name_body.len() as u64);
            next.extend_from_slice(&name_body);
            graph_number(&mut next, u64::from(G_K_END));
        }
        next.push(G_K_END); // end kHeader

        // Truncation knob: cut the header short *before* computing its CRC, so the outer checksum
        // gate still passes and the reader hits the truncation inside the graph parser.
        if self.truncate != 0 && !next.is_empty() {
            let keep = (self.truncate as usize) % next.len();
            next.truncate(keep);
        }

        // ── Frame it: signature header + pack region + next header ──
        let pack: Vec<u8> = self
            .pack_data
            .iter()
            .copied()
            .take(GRAPH_MAX_PACKDATA)
            .collect();
        let mut file = vec![0u8; 32];
        file[..6].copy_from_slice(&GRAPH_SIGNATURE);
        file[6] = 0; // format version major
        file[7] = 4; // format version minor
        file.extend_from_slice(&pack);
        let header_offset = pack.len() as u64;
        let header_size = next.len() as u64;
        let header_crc = crc32(&next);
        file.extend_from_slice(&next);
        file[12..20].copy_from_slice(&header_offset.to_le_bytes());
        file[20..28].copy_from_slice(&header_size.to_le_bytes());
        file[28..32].copy_from_slice(&header_crc.to_le_bytes());
        let start_crc = crc32(&file[12..32]);
        file[8..12].copy_from_slice(&start_crc.to_le_bytes());
        file
    }
}

/// Picks an index from a pool (cycled), kept within `[0, modulus)` so it lands near the real stream
/// range — some in-range (resolvable), some colliding (overlap/cycle the resolver must reject).
fn pool_index(pool: &[u8], k: usize, modulus: usize) -> usize {
    let modulus = modulus.max(1);
    match pool.get(k % pool.len().max(1)) {
        Some(&raw) => usize::from(raw) % modulus,
        None => k % modulus,
    }
}

/// Asserts a 7z read failure is a *typed* archive error of an expected kind — the RM-303 contract
/// that a hostile coder graph never panics, never leaks an untyped error, and never silently lies.
fn assert_graph_typed(error: &StreamError) {
    match error.archive_error().map(ArchiveError::kind) {
        Some(
            ErrorKind::Malformed | ErrorKind::Unsupported | ErrorKind::Integrity | ErrorKind::Limit,
        ) => {},
        other => panic!("7z coder-graph fuzz surfaced a non-typed / unexpected error: {other:?}"),
    }
}

/// Structured 7z coder-graph target: synthesize a `StreamsInfo`, frame it, and drive the reader.
pub fn read_7z_graph(data: &[u8]) {
    let mut input = arbitrary::Unstructured::new(data);
    let Ok(spec) = GraphSpec::arbitrary(&mut input) else {
        return;
    };
    let archive = spec.encode();
    let mut reader = match SeekArchiveReader::with_limits(Cursor::new(archive), fuzz_limits()) {
        Ok(reader) => reader,
        Err(error) => {
            assert_graph_typed(&error);
            return;
        },
    };
    let mut events = 0usize;
    let mut payload = 0u64;
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Entry(metadata)) => {
                let _ = metadata.path().as_bytes();
                events = events.saturating_add(1);
            },
            Ok(ReaderEvent::Data(bytes)) => {
                payload = payload.saturating_add(bytes.len() as u64);
            },
            Ok(ReaderEvent::Done) => return,
            Ok(ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry) => {},
            Ok(_) => return,
            Err(error) => {
                assert_graph_typed(&error);
                return;
            },
        }
        if events > MAX_ENTRIES || payload > MAX_TOTAL_BYTES {
            return;
        }
    }
}

/// All portable fuzz targets.
pub const TARGETS: &[&str] = &[
    "read_tar",
    "read_cpio",
    "read_ar",
    "read_zip",
    "read_7z",
    "read_7z_graph",
    "read_iso",
    "roundtrip_tar",
    "roundtrip_cpio",
    "roundtrip_ar",
    "roundtrip_7z",
    "roundtrip_iso",
    "codec_gzip",
    "codec_bzip2",
    "codec_zstd",
    "codec_xz",
    "codec_lz4",
    "codec_lzma2",
];

/// Runs a portable fuzz target.
pub fn run_target(name: &str, data: &[u8]) {
    match name {
        "read_tar" => read_tar(data),
        "read_cpio" => read_cpio(data),
        "read_ar" => read_ar(data),
        "read_zip" => read_zip(data),
        "read_7z" => read_7z(data),
        "read_7z_graph" => read_7z_graph(data),
        "read_iso" => read_iso(data),
        "roundtrip_tar" => roundtrip_tar(&entries_from_bytes(data)),
        "roundtrip_cpio" => roundtrip_cpio(&entries_from_bytes(data)),
        "roundtrip_ar" => roundtrip_ar(&entries_from_bytes(data)),
        "roundtrip_7z" => roundtrip_7z(&entries_from_bytes(data)),
        "roundtrip_iso" => roundtrip_iso(&entries_from_bytes(data)),
        "codec_gzip" => codec_gzip(data),
        "codec_bzip2" => codec_bzip2(data),
        "codec_zstd" => codec_zstd(data),
        "codec_xz" => codec_xz(data),
        "codec_lz4" => codec_lz4(data),
        "codec_lzma2" => codec_lzma2(data),
        _ => {},
    }
}

fn entries_from_bytes(data: &[u8]) -> Vec<FuzzEntry> {
    let mut input = arbitrary::Unstructured::new(data);
    Vec::<FuzzEntry>::arbitrary(&mut input).unwrap_or_default()
}
