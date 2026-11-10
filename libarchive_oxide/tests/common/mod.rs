// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reusable interoperability-evidence harness (RM-301).
//!
//! This module is the single foundation that later format slices (ZIP/7z/tar/cpio/ar/ISO/CAB/XAR)
//! sit on to produce two kinds of evidence:
//!
//! * *"≥3 producers can be read"* — [`assert_producers_agree`] feeds the SAME logical entry set to
//!   N independent encoders and asserts arca reads every encoding back to identical shapes+content.
//! * *"≥2 consumers accept"* — [`assert_consumers_accept`] hands arca's writer output to M
//!   independent decoders and asserts every one reconstructs identical shapes+content.
//!
//! Heterogeneous producers/consumers are carried as bare `fn` pointers inside concrete
//! non-generic case structs. A `fn` pointer is a `Copy` scalar, so fixtures remain static data and
//! RM-302/303/304 can add cases with a free function and a `&[]` array without editing this file.
//!
//! Files under `tests/common/` are NOT compiled as their own test binary; a test binary pulls this
//! in with `mod common;`. `dead_code` is allowed because not every including binary uses every
//! helper.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    dead_code,
    unreachable_pub
)]

use std::io::Cursor;

use libarchive_oxide::{ArchiveReader, ReaderEvent, SeekArchiveReader, SeekArchiveWriter};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, FormatId, Limits};

const ISO_SECTOR: usize = 2048;

fn iso_both_u16(value: u16) -> [u8; 4] {
    let little = value.to_le_bytes();
    let big = value.to_be_bytes();
    [little[0], little[1], big[0], big[1]]
}

fn iso_both_u32(value: u32) -> [u8; 8] {
    let little = value.to_le_bytes();
    let big = value.to_be_bytes();
    [
        little[0], little[1], little[2], little[3], big[0], big[1], big[2], big[3],
    ]
}

fn iso_le_u32(bytes: &[u8], position: usize) -> u32 {
    u32::from_le_bytes(bytes[position..position + 4].try_into().unwrap())
}

fn patch_iso_tree(image: &mut [u8], descriptor_sector: usize, identifier: &[u8], second_lba: u32) {
    let record_start = iso_tree_record_start(image, descriptor_sector, identifier);
    let length = usize::from(image[record_start]);
    let root_record = descriptor_sector * ISO_SECTOR + 156;
    let root_lba = usize::try_from(iso_le_u32(image, root_record + 2)).unwrap();
    let root_size = usize::try_from(iso_le_u32(image, root_record + 10)).unwrap();
    let base = root_lba * ISO_SECTOR;
    let second_start = record_start + length;
    assert!(second_start + length <= base + root_size);
    assert_eq!(second_start / ISO_SECTOR, record_start / ISO_SECTOR);
    let mut final_record = image[record_start..record_start + length].to_vec();
    image[record_start + 10..record_start + 18].copy_from_slice(&iso_both_u32(5));
    image[record_start + 25] |= 0x80;
    final_record[2..10].copy_from_slice(&iso_both_u32(second_lba));
    final_record[10..18].copy_from_slice(&iso_both_u32(6));
    final_record[25] &= !0x80;
    image[second_start..second_start + length].copy_from_slice(&final_record);
}

fn iso_tree_record_start(image: &[u8], descriptor_sector: usize, identifier: &[u8]) -> usize {
    let root_record = descriptor_sector * ISO_SECTOR + 156;
    let root_lba = usize::try_from(iso_le_u32(image, root_record + 2)).unwrap();
    let root_size = usize::try_from(iso_le_u32(image, root_record + 10)).unwrap();
    let base = root_lba * ISO_SECTOR;
    let mut position = 0;
    while position < root_size {
        let record_start = base + position;
        let length = usize::from(image[record_start]);
        if length == 0 {
            position = (position / ISO_SECTOR + 1) * ISO_SECTOR;
            continue;
        }
        let identifier_length = usize::from(image[record_start + 32]);
        let identifier_start = record_start + 33;
        if image[identifier_start..identifier_start + identifier_length] == *identifier {
            return record_start;
        }
        position += length;
    }
    panic!("ISO writer omitted the expected directory record");
}

fn update_iso_volume_sectors(image: &mut [u8], volume_sectors: u32) {
    for descriptor_sector in [16, 17] {
        let start = descriptor_sector * ISO_SECTOR + 80;
        image[start..start + 8].copy_from_slice(&iso_both_u32(volume_sectors));
    }
}

/// First-party ISO with one logical file split over two noncontiguous file sections.
pub fn multi_extent_iso_fixture() -> Vec<u8> {
    let output = Cursor::new(Vec::new());
    let mut writer =
        SeekArchiveWriter::with_format(output, FormatId::Iso9660, Limits::default()).unwrap();
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("SPLIT.BIN"))
        .size(Some(11))
        .build();
    writer.start_entry(&metadata).unwrap();
    writer.write_data(b"firstsecond").unwrap();
    writer.end_entry().unwrap();
    let mut image = writer.finish().unwrap().into_inner();

    let original_sectors = image.len().div_ceil(ISO_SECTOR);
    let second_lba = u32::try_from(original_sectors + 1).unwrap();
    let volume_sectors = second_lba + 1;
    image.resize(usize::try_from(volume_sectors).unwrap() * ISO_SECTOR, 0);
    image[original_sectors * ISO_SECTOR..(original_sectors + 1) * ISO_SECTOR].fill(0xa5);
    let second_start = usize::try_from(second_lba).unwrap() * ISO_SECTOR;
    image[second_start..second_start + 6].copy_from_slice(b"second");
    update_iso_volume_sectors(&mut image, volume_sectors);
    patch_iso_tree(&mut image, 16, b"SPLIT.BIN;1", second_lba);
    let joliet_identifier = "SPLIT.BIN"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect::<Vec<_>>();
    patch_iso_tree(&mut image, 17, &joliet_identifier, second_lba);
    image
}

/// Fully mastered ISO with a 5,000-byte file recorded as 1-block units separated by 1-block gaps.
pub fn interleaved_iso_fixture() -> (Vec<u8>, Vec<u8>) {
    let payload = (0_u8..=250).cycle().take(5000).collect::<Vec<_>>();
    let output = Cursor::new(Vec::new());
    let mut writer =
        SeekArchiveWriter::with_format(output, FormatId::Iso9660, Limits::default()).unwrap();
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("STRIPED.BIN"))
        .size(Some(payload.len() as u64))
        .build();
    writer.start_entry(&metadata).unwrap();
    writer.write_data(&payload).unwrap();
    writer.end_entry().unwrap();
    let mut image = writer.finish().unwrap().into_inner();

    let original_sectors = image.len().div_ceil(ISO_SECTOR);
    let first_lba = original_sectors + 1;
    let volume_sectors = u32::try_from(first_lba + 5).unwrap();
    image.resize(usize::try_from(volume_sectors).unwrap() * ISO_SECTOR, 0);
    image[first_lba * ISO_SECTOR..(first_lba + 5) * ISO_SECTOR].fill(0);
    image[first_lba * ISO_SECTOR..(first_lba + 1) * ISO_SECTOR]
        .copy_from_slice(&payload[..ISO_SECTOR]);
    image[(first_lba + 1) * ISO_SECTOR..(first_lba + 2) * ISO_SECTOR].fill(0xa5);
    image[(first_lba + 2) * ISO_SECTOR..(first_lba + 3) * ISO_SECTOR]
        .copy_from_slice(&payload[ISO_SECTOR..2 * ISO_SECTOR]);
    image[(first_lba + 3) * ISO_SECTOR..(first_lba + 4) * ISO_SECTOR].fill(0x5a);
    let final_start = (first_lba + 4) * ISO_SECTOR;
    image[final_start..final_start + payload.len() - 2 * ISO_SECTOR]
        .copy_from_slice(&payload[2 * ISO_SECTOR..]);
    update_iso_volume_sectors(&mut image, volume_sectors);

    let primary_record = iso_tree_record_start(&image, 16, b"STRIPED.BIN;1");
    image[primary_record + 2..primary_record + 10]
        .copy_from_slice(&iso_both_u32(u32::try_from(first_lba).unwrap()));
    image[primary_record + 26] = 1;
    image[primary_record + 27] = 1;
    let joliet_identifier = "STRIPED.BIN"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect::<Vec<_>>();
    let joliet_record = iso_tree_record_start(&image, 17, &joliet_identifier);
    image[joliet_record + 2..joliet_record + 10]
        .copy_from_slice(&iso_both_u32(u32::try_from(first_lba).unwrap()));
    image[joliet_record + 26] = 1;
    image[joliet_record + 27] = 1;
    (image, payload)
}

fn extended_attribute_iso_fixture_inner(select_joliet: bool) -> (Vec<u8>, Vec<u8>) {
    let (mut image, payload) = interleaved_iso_fixture();
    let primary_record = iso_tree_record_start(&image, 16, b"STRIPED.BIN;1");
    let first_lba = usize::try_from(iso_le_u32(&image, primary_record + 2)).unwrap();
    let joliet_identifier = "STRIPED.BIN"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect::<Vec<_>>();
    let joliet_record = iso_tree_record_start(&image, 17, &joliet_identifier);
    for record in [primary_record, joliet_record] {
        image[record + 1] = 1;
        image[record + 25] |= 0x10;
        image[record + 26] = 0;
        image[record + 27] = 0;
    }

    let mut attributes = [0_u8; ISO_SECTOR];
    attributes[0..4].copy_from_slice(&iso_both_u16(1000));
    attributes[4..8].copy_from_slice(&iso_both_u16(1001));
    attributes[8..10].copy_from_slice(&0xfeaa_u16.to_be_bytes());
    attributes[10..27].copy_from_slice(b"2026081501020300\0");
    attributes[27..44].copy_from_slice(b"2026081602030400\x04");
    attributes[84..116].fill(b' ');
    attributes[180] = 1;
    attributes[246..250].copy_from_slice(&iso_both_u16(4));
    attributes[250..254].copy_from_slice(b"meta");
    image[first_lba * ISO_SECTOR..(first_lba + 1) * ISO_SECTOR].copy_from_slice(&attributes);
    let data_start = (first_lba + 1) * ISO_SECTOR;
    image[data_start..data_start + payload.len()].copy_from_slice(&payload);

    if select_joliet {
        // Select the Joliet tree so the writer-generated Rock Ridge PX field in the primary tree does not intentionally override EA.
        let primary_root = 16 * ISO_SECTOR + 156;
        let primary_root_lba = usize::try_from(iso_le_u32(&image, primary_root + 2)).unwrap();
        let dot = primary_root_lba * ISO_SECTOR;
        let dot_end = dot + usize::from(image[dot]);
        image[dot + 35..dot_end].fill(0);
    }
    (image, payload)
}

/// Fully mastered primary/Joliet ISO with one ECMA-119 extended-attribute block.
pub fn extended_attribute_iso_fixture() -> (Vec<u8>, Vec<u8>) {
    extended_attribute_iso_fixture_inner(true)
}

/// The same fixture with Rock Ridge enabled to exercise metadata precedence.
pub fn extended_attribute_iso_with_rock_ridge_fixture() -> (Vec<u8>, Vec<u8>) {
    extended_attribute_iso_fixture_inner(false)
}

/// Compression method WHERE OBSERVABLE. arca's reader decodes transparently and exposes no
/// per-entry codec, so [`read_with_arca`] always yields `None`. `Some(..)` is set only by
/// consumers/producers that expose their own codec view. Kept OUTSIDE content-equality so a Store
/// producer and a Deflate producer of the same logical set still compare equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionMethod {
    Store,
    Deflate,
    Lzma,
    Lzma2,
    Bzip2,
    Zstd,
    Other(u16),
}

/// The SAME logical entry every producer must encode. RAW path bytes only; content is the full
/// uncompressed payload (empty for `Dir`). This is the harness's single source of truth:
/// [`assert_producers_agree`] feeds the identical slice to every producer.
#[derive(Clone, Debug)]
pub struct LogicalEntry {
    pub path: Vec<u8>,
    pub kind: EntryKind,
    pub content: Vec<u8>,
}

impl LogicalEntry {
    /// A regular file with the given raw path bytes and full payload.
    pub fn file(path: impl Into<Vec<u8>>, content: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            kind: EntryKind::File,
            content: content.into(),
        }
    }

    /// A directory with the given raw path bytes; content is always empty.
    pub fn dir(path: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            kind: EntryKind::Dir,
            content: Vec::new(),
        }
    }
}

/// Normalized, content-comparable entry read back out of an archive.
#[derive(Clone, Debug)]
pub struct EntryShape {
    path: Vec<u8>,
    kind: EntryKind,
    content: Vec<u8>,
    method: Option<CompressionMethod>,
}

impl EntryShape {
    /// The ONLY constructor. Centralizes dir-slash normalization so every shape (arca-read and
    /// consumer-decoded) is canonical and comparisons are honest: when `kind == Dir` exactly ONE
    /// trailing `b'/'` is stripped, matching real producer behavior (arca writes `b"sub"`, the
    /// `zip` crate and any spec-conformant raw ZIP store `b"sub/"`).
    pub fn new(path: impl Into<Vec<u8>>, kind: EntryKind, content: impl Into<Vec<u8>>) -> Self {
        let kind = shape_kind(kind);
        let mut p = path.into();
        if kind == EntryKind::Dir && p.last() == Some(&b'/') {
            p.pop();
        }
        Self {
            path: p,
            kind,
            content: content.into(),
            method: None,
        }
    }

    /// Attach an observed compression method (excluded from equality).
    #[must_use]
    pub fn with_method(mut self, m: CompressionMethod) -> Self {
        self.method = Some(m);
        self
    }

    pub fn path(&self) -> &[u8] {
        &self.path
    }

    pub fn kind(&self) -> EntryKind {
        self.kind
    }

    /// DERIVED from content, never stored — so a `size = None` vs `Some` mismatch can't diverge.
    pub fn size(&self) -> u64 {
        self.content.len() as u64
    }

    pub fn content(&self) -> &[u8] {
        &self.content
    }

    pub fn method(&self) -> Option<CompressionMethod> {
        self.method
    }

    /// Panics if this shape carries a method that disagrees with `expected`; a no-op when the
    /// method is `None` (arca-read shapes expose no codec).
    #[track_caller]
    pub fn assert_method(&self, expected: CompressionMethod) {
        if let Some(actual) = self.method {
            assert_eq!(
                actual, expected,
                "compression method mismatch for {:?}",
                self.path
            );
        }
    }

    /// Module-private: append a streamed `Data` chunk to the current entry's content.
    pub(crate) fn push_data(&mut self, bytes: &[u8]) {
        self.content.extend_from_slice(bytes);
    }
}

// EQUALITY = CONTENT equality over (path, kind, content) ONLY. `method` and the derived `size` are
// excluded. A field-subset projection is a valid equivalence relation, so the Eq contract holds; no
// Hash is derived or needed.
impl PartialEq for EntryShape {
    fn eq(&self, o: &Self) -> bool {
        self.path == o.path && self.kind == o.kind && self.content == o.content
    }
}
impl Eq for EntryShape {}

/// `EntryKind` is `#[non_exhaustive]` → the mapping MUST have a wildcard arm. Symlink/device kinds
/// (out of scope this slice) fold to `File` deterministically.
fn shape_kind(k: EntryKind) -> EntryKind {
    match k {
        EntryKind::Dir => EntryKind::Dir,
        _ => EntryKind::File,
    }
}

/// Canonical order: paths are unique within one archive, so sorting by path makes
/// central-directory order vs stream order compare equal (robust + documented).
fn sorted_by_path(mut v: Vec<EntryShape>) -> Vec<EntryShape> {
    v.sort_by(|a, b| a.path().cmp(b.path()));
    v
}

/// Independent encoder: turns the shared logical set into archive bytes. `name` = `"crate@version"`
/// provenance (e.g. `"zip@8.6.0"`); flows into panic messages.
pub struct ProducerCase {
    pub name: &'static str,
    pub encode: fn(&[LogicalEntry]) -> Vec<u8>,
}

/// Independent decoder: reconstructs shapes (WITH content) from archive bytes.
pub struct ConsumerCase {
    pub name: &'static str,
    pub decode: fn(&[u8]) -> Vec<EntryShape>,
}

/// (2) Read ANY arca-readable bytes through the seek reader into shapes with real content. `method`
/// left `None` (arca abstracts compression). Panics on arca error (test-only).
///
/// `ReaderEvent` is `#[non_exhaustive]` in the arca crate, so from this external test binary the
/// match needs a wildcard arm (mirrors `sevenz_differential.rs`).
#[track_caller]
pub fn read_with_arca(bytes: &[u8]) -> Vec<EntryShape> {
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes.to_vec())).unwrap();
    let mut out: Vec<EntryShape> = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(meta) => out.push(EntryShape::new(
                meta.path().as_bytes().to_vec(),
                meta.kind(),
                Vec::new(),
            )),
            ReaderEvent::Data(d) => out.last_mut().unwrap().push_data(d),
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Done => return out,
            _ => panic!("unexpected future reader event"),
        }
    }
}

/// (2b) Read a SEQUENTIAL archive (tar / cpio / ar) into content shapes via the
/// non-seek [`ArchiveReader`]. `SeekArchiveReader` only indexes ZIP and ISO, so
/// tar-family bytes need this reader. Usable directly as a [`ConsumerCase::decode`]
/// field. `method` stays `None` (arca abstracts compression). Panics on arca error
/// (test-only).
#[track_caller]
pub fn read_seq_with_arca(bytes: &[u8]) -> Vec<EntryShape> {
    let mut reader = ArchiveReader::new(Cursor::new(bytes.to_vec()));
    let mut out: Vec<EntryShape> = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(meta) => out.push(EntryShape::new(
                meta.path().as_bytes().to_vec(),
                meta.kind(),
                Vec::new(),
            )),
            ReaderEvent::Data(d) => out.last_mut().unwrap().push_data(d),
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Done => return out,
            _ => panic!("unexpected future reader event"),
        }
    }
}

/// A metadata projection read back from an archive for fidelity comparison
/// (RM-304). Unlike [`EntryShape`] — which folds every non-directory kind to
/// `File` and drops mode/owner/time/link metadata — this preserves the REAL entry
/// kind and the typed metadata a format round-trips, so per-format tests can
/// assert that mode, uid/gid, mtime, and symlink/hardlink targets survive a
/// producer. Content is NOT carried here; content interop is [`EntryShape`]'s job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaShape {
    pub path: Vec<u8>,
    pub kind: EntryKind,
    pub mode: Option<u32>,
    pub uid: Option<u64>,
    pub gid: Option<u64>,
    pub mtime: Option<i64>,
    pub link_target: Option<Vec<u8>>,
}

impl MetaShape {
    /// Projects an arca `EntryMetadata` into the comparable subset, applying the
    /// same one-trailing-slash directory normalization as [`EntryShape::new`].
    pub fn from_metadata(meta: &EntryMetadata) -> Self {
        let kind = meta.kind();
        let mut path = meta.path().as_bytes().to_vec();
        if kind == EntryKind::Dir && path.last() == Some(&b'/') {
            path.pop();
        }
        Self {
            path,
            kind,
            mode: meta.mode(),
            uid: meta.owner().uid,
            gid: meta.owner().gid,
            mtime: meta
                .times()
                .modified
                .map(libarchive_oxide_core::Timestamp::seconds),
            link_target: meta.link_target().map(|target| target.as_bytes().to_vec()),
        }
    }

    /// The uid/gid pair, for terse assertions.
    #[must_use]
    pub fn owner(&self) -> (Option<u64>, Option<u64>) {
        (self.uid, self.gid)
    }
}

fn sorted_meta_by_path(mut v: Vec<MetaShape>) -> Vec<MetaShape> {
    v.sort_by(|a, b| a.path.cmp(&b.path));
    v
}

/// Reads metadata shapes from a SEQUENTIAL archive (tar / cpio / ar), path-sorted.
#[track_caller]
pub fn read_meta_seq_with_arca(bytes: &[u8]) -> Vec<MetaShape> {
    let mut reader = ArchiveReader::new(Cursor::new(bytes.to_vec()));
    let mut out = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(meta) => out.push(MetaShape::from_metadata(&meta)),
            ReaderEvent::Data(_) | ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Done => return sorted_meta_by_path(out),
            _ => panic!("unexpected future reader event"),
        }
    }
}

/// Reads metadata shapes from a SEEK archive (ISO / ZIP), path-sorted.
#[track_caller]
pub fn read_meta_seek_with_arca(bytes: &[u8]) -> Vec<MetaShape> {
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes.to_vec())).unwrap();
    let mut out = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Entry(meta) => out.push(MetaShape::from_metadata(&meta)),
            ReaderEvent::Data(_) | ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Done => return sorted_meta_by_path(out),
            _ => panic!("unexpected future reader event"),
        }
    }
}

/// (3) N-producer evidence (*"≥3 producers can be read"*, applied repeatedly). Every producer
/// encodes the SAME `entries`; arca reads each output back and each read-back must equal the
/// canonical shapes DERIVED from `entries` (source of truth → a shared bug in all producers cannot
/// pass). Returns the agreed, path-sorted shapes for downstream [`assert_consumers_accept`].
#[track_caller]
pub fn assert_producers_agree(
    entries: &[LogicalEntry],
    producers: &[ProducerCase],
) -> Vec<EntryShape> {
    let expected = sorted_by_path(
        entries
            .iter()
            .map(|e| EntryShape::new(e.path.clone(), e.kind, e.content.clone()))
            .collect(),
    );
    for p in producers {
        let got = sorted_by_path(read_with_arca(&(p.encode)(entries)));
        assert_eq!(got, expected, "producer {} disagreed", p.name);
    }
    expected
}

/// Sequential-format variant of [`assert_producers_agree`]: reads each producer's
/// output back through the non-seek [`read_seq_with_arca`] (tar / cpio / ar).
#[track_caller]
pub fn assert_producers_agree_seq(
    entries: &[LogicalEntry],
    producers: &[ProducerCase],
) -> Vec<EntryShape> {
    let expected = sorted_by_path(
        entries
            .iter()
            .map(|e| EntryShape::new(e.path.clone(), e.kind, e.content.clone()))
            .collect(),
    );
    for p in producers {
        let got = sorted_by_path(read_seq_with_arca(&(p.encode)(entries)));
        assert_eq!(got, expected, "producer {} disagreed", p.name);
    }
    expected
}

/// (4) M-consumer evidence (*"≥2 consumers accept"*). arca's writer output `archive` is handed to
/// each independent consumer; each must reconstruct `expected` exactly (method excluded from Eq, so
/// a Deflate-reporting consumer still matches).
#[track_caller]
pub fn assert_consumers_accept(
    archive: &[u8],
    expected: &[EntryShape],
    consumers: &[ConsumerCase],
) {
    let expected = sorted_by_path(expected.to_vec());
    for c in consumers {
        let got = sorted_by_path((c.decode)(archive));
        assert_eq!(
            got, expected,
            "consumer {} rejected/misread arca output",
            c.name
        );
    }
}

/// Independent ZIP decoder built on the `zip` crate: `by_index` over every member, raw name bytes,
/// `.is_dir()` → `Dir`, `.compression()` → `.with_method(..)`, `read_to_end` into content. Usable
/// directly as a [`ConsumerCase::decode`] field.
pub fn zip_crate_decode(bytes: &[u8]) -> Vec<EntryShape> {
    use std::io::Read;

    let mut archive = zip::ZipArchive::new(Cursor::new(bytes.to_vec())).unwrap();
    let mut out = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let mut f = archive.by_index(i).unwrap();
        let raw = f.name_raw().to_vec();
        let kind = if f.is_dir() {
            EntryKind::Dir
        } else {
            EntryKind::File
        };
        let method = match f.compression() {
            zip::CompressionMethod::Stored => CompressionMethod::Store,
            zip::CompressionMethod::Deflated => CompressionMethod::Deflate,
            zip::CompressionMethod::Bzip2 => CompressionMethod::Bzip2,
            zip::CompressionMethod::Zstd => CompressionMethod::Zstd,
            zip::CompressionMethod::Lzma => CompressionMethod::Lzma,
            _ => CompressionMethod::Other(0),
        };
        let mut content = Vec::new();
        if !f.is_dir() {
            f.read_to_end(&mut content).unwrap();
        }
        out.push(EntryShape::new(raw, kind, content).with_method(method));
    }
    out
}

/// Independent 7z decoder built on `sevenz-rust2`: `SevenReader::new` + `Password::empty()`,
/// `archive().files` for name/`is_directory`, `read_file(name)` for content, `.with_method(Lzma2)`.
/// Usable directly as a [`ConsumerCase::decode`] field.
#[cfg(feature = "sevenz")]
pub fn sevenz_rust2_decode(bytes: &[u8]) -> Vec<EntryShape> {
    use sevenz_rust2::{ArchiveReader as SevenReader, Password};

    let mut reader = SevenReader::new(Cursor::new(bytes.to_vec()), Password::empty()).unwrap();
    // Snapshot names/kinds under the immutable borrow first, then read contents.
    let meta: Vec<(String, bool)> = reader
        .archive()
        .files
        .iter()
        .map(|e| (e.name().to_string(), e.is_directory()))
        .collect();

    let mut out = Vec::with_capacity(meta.len());
    for (name, is_dir) in meta {
        let (kind, content) = if is_dir {
            (EntryKind::Dir, Vec::new())
        } else {
            (EntryKind::File, reader.read_file(&name).unwrap())
        };
        out.push(
            EntryShape::new(name.into_bytes(), kind, content).with_method(CompressionMethod::Lzma2),
        );
    }
    out
}
