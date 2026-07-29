// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded MSIX/APPX package-block-map integrity verification.
//!
//! `AppxBlockMap.xml` hashes each package file in uncompressed 64-KiB blocks.
//! This adapter parses the Microsoft 2010 block-map vocabulary without building
//! an XML DOM, streams every ZIP member through the existing bounded seek
//! reader, and compares the declared names, sizes, local-header sizes,
//! compressed block sizes, and SHA-256 hashes. Package signature parsing is
//! intentionally outside this module: the presence of `AppxSignature.p7x`
//! never implies cryptographic validity.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use libarchive_oxide::{ErrorKind, ReaderEvent, SeekArchiveReader};
use libarchive_oxide_core::Limits;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use sha2::{Digest, Sha256};

use crate::verification::VerificationDimension;
use crate::zip_reader::{
    LOCAL_HEADER_LEN, METHOD_DEFLATE, METHOD_STORE, ZipEntry, le_u16, read_central_directory,
    read_exact_at,
};
use crate::{PackageFinding, PackageFindingCode};

const PROFILE: &str = "msix";
const BLOCK_SIZE: u64 = 64 * 1024;
const BLOCK_MAP_NAME: &[u8] = b"AppxBlockMap.xml";
const MANIFEST_NAME: &[u8] = b"AppxManifest.xml";
const CONTENT_TYPES_NAME: &[u8] = b"[Content_Types].xml";
const SIGNATURE_NAME: &[u8] = b"AppxSignature.p7x";
const CODE_INTEGRITY_NAME: &[u8] = b"AppxMetadata/CodeIntegrity.cat";
const BLOCK_MAP_NAMESPACE: &str = "http://schemas.microsoft.com/appx/2010/blockmap";
const BLOCK_MAP_NAMESPACE_2015: &str = "http://schemas.microsoft.com/appx/2015/blockmap";
const BLOCK_MAP_NAMESPACE_2017: &str = "http://schemas.microsoft.com/appx/2017/blockmap";
const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const MAX_APPX_NAME_CHARS: usize = 32_767;

#[derive(Debug)]
pub(crate) struct MsixVerification {
    pub(crate) integrity: VerificationDimension,
    pub(crate) findings: Vec<PackageFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    InvalidMetadata,
    Read,
    Resource,
    UnsupportedAlgorithm,
    UnsupportedScope,
}

#[derive(Debug)]
struct Failure {
    kind: FailureKind,
    path: Option<Vec<u8>>,
    detail: String,
}

impl Failure {
    fn invalid(path: Option<Vec<u8>>, detail: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::InvalidMetadata,
            path,
            detail: detail.into(),
        }
    }

    fn read(path: Option<Vec<u8>>, detail: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Read,
            path,
            detail: detail.into(),
        }
    }

    fn resource(path: Option<Vec<u8>>, detail: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Resource,
            path,
            detail: detail.into(),
        }
    }

    fn unsupported_algorithm(detail: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::UnsupportedAlgorithm,
            path: Some(BLOCK_MAP_NAME.to_vec()),
            detail: detail.into(),
        }
    }

    fn unsupported_scope(detail: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::UnsupportedScope,
            path: Some(BLOCK_MAP_NAME.to_vec()),
            detail: detail.into(),
        }
    }

    fn archive(error: &libarchive_oxide::Error) -> Self {
        if error.kind() == ErrorKind::Limit {
            Self::resource(None, error.to_string())
        } else {
            Self::read(None, error.to_string())
        }
    }

    fn finding(self) -> PackageFinding {
        let code = match self.kind {
            FailureKind::InvalidMetadata => PackageFindingCode::InvalidIntegrityMetadata,
            FailureKind::Read => PackageFindingCode::IntegrityReadFailure,
            FailureKind::Resource => PackageFindingCode::IntegrityResourceLimit,
            FailureKind::UnsupportedAlgorithm => PackageFindingCode::UnsupportedIntegrityAlgorithm,
            FailureKind::UnsupportedScope => PackageFindingCode::UnsupportedIntegrityScope,
        };
        PackageFinding::new(PROFILE, self.path, code, self.detail)
    }
}

#[derive(Debug)]
struct MetadataBudget {
    used: usize,
    limit: Option<usize>,
}

impl MetadataBudget {
    fn new(limit: Option<usize>) -> Self {
        Self { used: 0, limit }
    }

    fn charge(&mut self, bytes: usize, detail: &'static str) -> Result<(), Failure> {
        self.used = self
            .used
            .checked_add(bytes)
            .ok_or_else(|| Failure::resource(None, "MSIX metadata accounting overflow"))?;
        if self.limit.is_some_and(|limit| self.used > limit) {
            return Err(Failure::resource(None, detail));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct CentralEntry {
    uncompressed_size: u64,
    compressed_size: u64,
    method: u16,
    local_header_size: u32,
}

#[derive(Debug)]
struct ActualEntry {
    size: u64,
    block_hashes: Vec<[u8; 32]>,
}

#[derive(Debug)]
struct CollectedArchive {
    entries: BTreeMap<Vec<u8>, ActualEntry>,
    block_map_xml: Vec<u8>,
}

struct CurrentEntry {
    name: Vec<u8>,
    excluded: bool,
    is_block_map: bool,
    size: u64,
    bytes_in_block: u64,
    hasher: Sha256,
    block_hashes: Vec<[u8; 32]>,
    body: Vec<u8>,
}

impl CurrentEntry {
    fn new(
        name: Vec<u8>,
        declared_size: u64,
        budget: &mut MetadataBudget,
    ) -> Result<Self, Failure> {
        let excluded = is_excluded_footprint(&name);
        let is_block_map = name == BLOCK_MAP_NAME;
        let block_count = if excluded {
            0
        } else {
            block_count(declared_size)?
        };
        let block_capacity = usize::try_from(block_count).map_err(|_| {
            Failure::resource(
                Some(name.clone()),
                "MSIX block count exceeds this platform's address space",
            )
        })?;
        budget.charge(
            name.len()
                .checked_add(size_of::<ActualEntry>())
                .and_then(|value| {
                    value.checked_add(block_capacity.saturating_mul(size_of::<[u8; 32]>()))
                })
                .ok_or_else(|| {
                    Failure::resource(
                        Some(name.clone()),
                        "MSIX block-hash allocation accounting overflow",
                    )
                })?,
            "MSIX entry and block-hash metadata exceeds configured budget",
        )?;
        let mut block_hashes = Vec::new();
        block_hashes
            .try_reserve_exact(block_capacity)
            .map_err(|error| {
                Failure::resource(
                    Some(name.clone()),
                    format!("cannot allocate MSIX block-hash table: {error}"),
                )
            })?;
        Ok(Self {
            name,
            excluded,
            is_block_map,
            size: 0,
            bytes_in_block: 0,
            hasher: Sha256::new(),
            block_hashes,
            body: Vec::new(),
        })
    }

    fn feed(&mut self, mut bytes: &[u8], budget: &mut MetadataBudget) -> Result<(), Failure> {
        self.size = self
            .size
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| Failure::read(Some(self.name.clone()), "MSIX entry size overflow"))?;
        if self.is_block_map {
            budget.charge(
                bytes.len(),
                "AppxBlockMap.xml exceeds configured metadata budget",
            )?;
            self.body.try_reserve(bytes.len()).map_err(|error| {
                Failure::resource(
                    Some(self.name.clone()),
                    format!("cannot allocate AppxBlockMap.xml buffer: {error}"),
                )
            })?;
            self.body.extend_from_slice(bytes);
        }
        if self.excluded {
            return Ok(());
        }
        while !bytes.is_empty() {
            let remaining = usize::try_from(BLOCK_SIZE - self.bytes_in_block)
                .map_err(|_| Failure::resource(Some(self.name.clone()), "block size overflow"))?;
            let take = remaining.min(bytes.len());
            self.hasher.update(&bytes[..take]);
            self.bytes_in_block += take as u64;
            bytes = &bytes[take..];
            if self.bytes_in_block == BLOCK_SIZE {
                self.finish_block();
            }
        }
        Ok(())
    }

    fn finish_block(&mut self) {
        let digest = self.hasher.finalize_reset();
        self.block_hashes.push(digest.into());
        self.bytes_in_block = 0;
    }

    fn finish(mut self) -> ActualEntry {
        if !self.excluded && self.bytes_in_block != 0 {
            self.finish_block();
        }
        ActualEntry {
            size: self.size,
            block_hashes: self.block_hashes,
        }
    }
}

#[derive(Debug)]
struct BlockMap {
    files: Vec<BlockMapFile>,
}

#[derive(Debug)]
struct BlockMapFile {
    name: Vec<u8>,
    size: u64,
    local_header_size: u32,
    blocks: Vec<Block>,
}

#[derive(Debug)]
struct Block {
    hash: [u8; 32],
    compressed_size: Option<u64>,
}

/// Verifies the uncompressed-file block hashes and exact file coverage declared
/// by an MSIX/APPX `AppxBlockMap.xml`.
pub(crate) fn verify_msix_block_map<R: Read + Seek>(
    mut reader: R,
    limits: Limits,
) -> MsixVerification {
    let mut budget = MetadataBudget::new(limits.metadata_bytes());
    let central = match collect_central_entries(&mut reader, limits, &mut budget) {
        Ok(entries) => entries,
        Err(error) => return failure_verification(error),
    };
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return failure_verification(Failure::read(None, "cannot rewind MSIX package"));
    }
    let collected = match collect_archive(reader, limits, &central, &mut budget) {
        Ok(collected) => collected,
        Err(error) => return failure_verification(error),
    };
    let block_map = match parse_block_map(&collected.block_map_xml, limits, &mut budget) {
        Ok(block_map) => block_map,
        Err(error) => return failure_verification(error),
    };
    compare_block_map(&block_map, &central, &collected.entries)
}

fn failure_verification(error: Failure) -> MsixVerification {
    let integrity = match error.kind {
        FailureKind::UnsupportedAlgorithm | FailureKind::UnsupportedScope => {
            VerificationDimension::Unsupported
        },
        FailureKind::InvalidMetadata | FailureKind::Read | FailureKind::Resource => {
            VerificationDimension::Invalid
        },
    };
    MsixVerification {
        integrity,
        findings: vec![error.finding()],
    }
}

fn collect_central_entries<R: Read + Seek>(
    reader: &mut R,
    limits: Limits,
    budget: &mut MetadataBudget,
) -> Result<BTreeMap<Vec<u8>, CentralEntry>, Failure> {
    let entries = read_central_directory(reader, limits)
        .map_err(|detail| Failure::read(None, format!("cannot read MSIX ZIP index: {detail}")))?;
    budget.charge(
        entries
            .len()
            .checked_mul(size_of::<ZipEntry>() + size_of::<CentralEntry>())
            .and_then(|value| {
                entries
                    .iter()
                    .try_fold(value, |used, entry| used.checked_add(entry.name.len()))
            })
            .ok_or_else(|| Failure::resource(None, "MSIX ZIP metadata accounting overflow"))?,
        "MSIX ZIP metadata exceeds configured budget",
    )?;
    let mut central = BTreeMap::new();
    let mut case_folded = BTreeSet::new();
    for entry in entries {
        let name = normalize_archive_name(&entry.name, limits)?;
        if !case_folded.insert(ascii_case_fold(&name)) {
            return Err(Failure::invalid(
                Some(name),
                "MSIX ZIP contains a duplicate or ASCII-case-colliding path",
            ));
        }
        let local_header_size = read_local_header_size(reader, &entry)?;
        if central
            .insert(
                name.clone(),
                CentralEntry {
                    uncompressed_size: entry.uncompressed_size,
                    compressed_size: entry.compressed_size,
                    method: entry.method,
                    local_header_size,
                },
            )
            .is_some()
        {
            return Err(Failure::invalid(
                Some(name),
                "MSIX ZIP contains a duplicate normalized path",
            ));
        }
    }
    Ok(central)
}

fn read_local_header_size<R: Read + Seek>(
    reader: &mut R,
    entry: &ZipEntry,
) -> Result<u32, Failure> {
    let mut fixed = [0_u8; LOCAL_HEADER_LEN];
    read_exact_at(reader, entry.local_offset, &mut fixed).map_err(|error| {
        Failure::read(
            Some(entry.name.clone()),
            format!("cannot read ZIP local header: {error}"),
        )
    })?;
    if &fixed[..4] != b"PK\x03\x04" {
        return Err(Failure::invalid(
            Some(entry.name.clone()),
            "ZIP local header has an invalid signature",
        ));
    }
    if le_u16(&fixed, 8) != entry.method {
        return Err(Failure::invalid(
            Some(entry.name.clone()),
            "ZIP local and central headers disagree on compression method",
        ));
    }
    let name_length = usize::from(le_u16(&fixed, 26));
    let extra_length = usize::from(le_u16(&fixed, 28));
    let local_header_size = LOCAL_HEADER_LEN
        .checked_add(name_length)
        .and_then(|value| value.checked_add(extra_length))
        .ok_or_else(|| {
            Failure::invalid(
                Some(entry.name.clone()),
                "ZIP local-header length overflows",
            )
        })?;
    if !(LOCAL_HEADER_LEN..=usize::from(u16::MAX) + 1).contains(&local_header_size) {
        return Err(Failure::invalid(
            Some(entry.name.clone()),
            "ZIP local-header size is outside the APPX schema range",
        ));
    }
    let mut local_name = vec![0_u8; name_length];
    read_exact_at(
        reader,
        entry.local_offset + LOCAL_HEADER_LEN as u64,
        &mut local_name,
    )
    .map_err(|error| {
        Failure::read(
            Some(entry.name.clone()),
            format!("cannot read ZIP local-header name: {error}"),
        )
    })?;
    if local_name != entry.name {
        return Err(Failure::invalid(
            Some(entry.name.clone()),
            "ZIP local and central headers disagree on member name",
        ));
    }
    u32::try_from(local_header_size).map_err(|_| {
        Failure::invalid(
            Some(entry.name.clone()),
            "ZIP local-header size does not fit the APPX field",
        )
    })
}

fn collect_archive<R: Read + Seek>(
    reader: R,
    limits: Limits,
    central: &BTreeMap<Vec<u8>, CentralEntry>,
    budget: &mut MetadataBudget,
) -> Result<CollectedArchive, Failure> {
    let mut archive =
        SeekArchiveReader::with_limits(reader, limits).map_err(|error| Failure::archive(&error))?;
    let mut current: Option<CurrentEntry> = None;
    let mut entries = BTreeMap::new();
    let mut block_map_xml: Option<Vec<u8>> = None;
    loop {
        match archive
            .next_event()
            .map_err(|error| Failure::archive(&error))?
        {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => {
                if current.is_some() {
                    return Err(Failure::read(
                        None,
                        "MSIX ZIP started an entry before ending the previous entry",
                    ));
                }
                let name = normalize_archive_name(metadata.path().as_bytes(), limits)?;
                let central_entry = central.get(&name).ok_or_else(|| {
                    Failure::read(
                        Some(name.clone()),
                        "decoded MSIX entry is absent from the central directory",
                    )
                })?;
                let declared_size = metadata.size().unwrap_or(central_entry.uncompressed_size);
                current = Some(CurrentEntry::new(name, declared_size, budget)?);
            },
            ReaderEvent::Data(bytes) => {
                let entry = current.as_mut().ok_or_else(|| {
                    Failure::read(None, "MSIX ZIP produced data outside an entry")
                })?;
                entry.feed(bytes, budget)?;
            },
            ReaderEvent::EndEntry => {
                let mut entry = current.take().ok_or_else(|| {
                    Failure::read(None, "MSIX ZIP ended an entry that was not open")
                })?;
                let name = entry.name.clone();
                let is_block_map = entry.is_block_map;
                let body = std::mem::take(&mut entry.body);
                let actual = entry.finish();
                if entries.insert(name.clone(), actual).is_some() {
                    return Err(Failure::invalid(
                        Some(name),
                        "MSIX decoder produced a duplicate normalized path",
                    ));
                }
                if is_block_map && block_map_xml.replace(body).is_some() {
                    return Err(Failure::invalid(
                        Some(BLOCK_MAP_NAME.to_vec()),
                        "MSIX ZIP contains more than one AppxBlockMap.xml",
                    ));
                }
            },
            ReaderEvent::Done => {
                if current.is_some() {
                    return Err(Failure::read(
                        None,
                        "MSIX ZIP ended before the current entry",
                    ));
                }
                break;
            },
            _ => {
                return Err(Failure::read(
                    None,
                    "MSIX ZIP reader returned an unknown event",
                ));
            },
        }
    }
    let block_map_xml = block_map_xml.ok_or_else(|| {
        Failure::invalid(
            Some(BLOCK_MAP_NAME.to_vec()),
            "MSIX ZIP has no AppxBlockMap.xml body",
        )
    })?;
    if entries.len() != central.len() || entries.keys().ne(central.keys()) {
        return Err(Failure::read(
            None,
            "MSIX decoded-entry set disagrees with the ZIP central directory",
        ));
    }
    Ok(CollectedArchive {
        entries,
        block_map_xml,
    })
}

fn parse_block_map(
    xml: &[u8],
    limits: Limits,
    budget: &mut MetadataBudget,
) -> Result<BlockMap, Failure> {
    if xml.is_empty() {
        return Err(Failure::invalid(
            Some(BLOCK_MAP_NAME.to_vec()),
            "AppxBlockMap.xml is empty",
        ));
    }
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = true;
    let mut parser = BlockMapParser::new(limits, budget);
    let mut buffer = Vec::new();
    loop {
        let event = reader.read_event_into(&mut buffer).map_err(|error| {
            Failure::invalid(
                Some(BLOCK_MAP_NAME.to_vec()),
                format!("AppxBlockMap.xml is not well-formed XML: {error}"),
            )
        })?;
        let done = parser.event(&reader, event)?;
        buffer.clear();
        if done {
            return parser.finish();
        }
    }
}

struct BlockMapParser<'a> {
    limits: Limits,
    budget: &'a mut MetadataBudget,
    depth: usize,
    document: DocumentState,
    xml_version: XmlVersion,
    declaration_seen: bool,
    current: Option<BlockMapFile>,
    block_open: bool,
    files: Vec<BlockMapFile>,
    folded_names: BTreeSet<Vec<u8>>,
    ignorable_prefixes: BTreeSet<Vec<u8>>,
    declared_prefixes: BTreeMap<Vec<u8>, Vec<u8>>,
    skip_depth: Option<usize>,
    total_declared_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocumentState {
    BeforeRoot,
    InRoot,
    Closed,
}

impl<'a> BlockMapParser<'a> {
    fn new(limits: Limits, budget: &'a mut MetadataBudget) -> Self {
        Self {
            limits,
            budget,
            depth: 0,
            document: DocumentState::BeforeRoot,
            xml_version: XmlVersion::Implicit1_0,
            declaration_seen: false,
            current: None,
            block_open: false,
            files: Vec::new(),
            folded_names: BTreeSet::new(),
            ignorable_prefixes: BTreeSet::new(),
            declared_prefixes: BTreeMap::new(),
            skip_depth: None,
            total_declared_size: 0,
        }
    }

    fn event(&mut self, reader: &Reader<&[u8]>, event: Event<'_>) -> Result<bool, Failure> {
        match event {
            Event::Decl(declaration) => {
                if self.document != DocumentState::BeforeRoot || self.declaration_seen {
                    return Err(Self::invalid("XML declaration is duplicated or misplaced"));
                }
                self.xml_version = match declaration.version().map_err(|error| {
                    Self::invalid(format!("XML declaration has an invalid version: {error}"))
                })? {
                    version if version.as_ref() == b"1.0" => XmlVersion::Explicit1_0,
                    version if version.as_ref() == b"1.1" => XmlVersion::Explicit1_1,
                    _ => return Err(Self::invalid("XML declaration uses an unknown version")),
                };
                self.declaration_seen = true;
            },
            Event::Start(element) => self.start(reader, &element, false)?,
            Event::Empty(element) => self.start(reader, &element, true)?,
            Event::End(element) => self.end(element.name().as_ref())?,
            Event::Text(text) => {
                if !text.as_ref().iter().all(u8::is_ascii_whitespace) {
                    return Err(Self::invalid("block-map elements may not contain text"));
                }
            },
            Event::Comment(_) => {},
            Event::Eof => return Ok(true),
            Event::CData(_) | Event::PI(_) | Event::DocType(_) | Event::GeneralRef(_) => {
                return Err(Self::invalid(
                    "AppxBlockMap.xml contains an XML construct outside the schema",
                ));
            },
        }
        Ok(false)
    }

    fn start(
        &mut self,
        reader: &Reader<&[u8]>,
        element: &BytesStart<'_>,
        empty: bool,
    ) -> Result<(), Failure> {
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or_else(|| Self::resource("XML nesting depth overflow"))?;
        if self
            .limits
            .nesting()
            .is_some_and(|limit| self.depth > limit)
        {
            return Err(Self::resource(
                "AppxBlockMap.xml nesting exceeds configured limit",
            ));
        }
        if self.document == DocumentState::Closed {
            return Err(Self::invalid(
                "AppxBlockMap.xml has content after the root element",
            ));
        }
        if self.skip_depth.is_some() {
            if empty {
                self.depth -= 1;
            }
            return Ok(());
        }

        let qualified = element.name();
        let name = qualified.as_ref();
        if let Some(prefix) = element_prefix(name) {
            if self.depth > 1 && self.ignorable_prefixes.contains(prefix) {
                if empty {
                    self.depth -= 1;
                } else {
                    self.skip_depth = Some(self.depth);
                }
                return Ok(());
            }
            return Err(Self::invalid(
                "block map uses an undeclared or non-ignorable namespace",
            ));
        }

        match self.depth {
            1 if name == b"BlockMap" => {
                if self.document != DocumentState::BeforeRoot || empty {
                    return Err(Self::invalid(
                        "BlockMap root must occur exactly once and contain files",
                    ));
                }
                self.parse_root_attributes(reader, element)?;
                self.document = DocumentState::InRoot;
            },
            2 if name == b"File" && self.document == DocumentState::InRoot => {
                if self.current.is_some() || self.block_open {
                    return Err(Self::invalid("File elements overlap"));
                }
                let file = self.parse_file_attributes(reader, element)?;
                self.current = Some(file);
                if empty {
                    self.close_file()?;
                    self.depth -= 1;
                }
            },
            3 if name == b"Block" && self.current.is_some() => {
                if self.block_open {
                    return Err(Self::invalid("Block elements may not nest"));
                }
                let block = Self::parse_block_attributes(reader, element, self.xml_version)?;
                let Some(file) = self.current.as_mut() else {
                    return Err(Failure::invalid(
                        Some(BLOCK_MAP_NAME.to_vec()),
                        "Block appears outside File",
                    ));
                };
                let expected = block_count(file.size)?;
                if file.blocks.len() as u64 >= expected {
                    return Err(Self::invalid(
                        "File contains more Block elements than its Size permits",
                    ));
                }
                file.blocks.push(block);
                if empty {
                    self.depth -= 1;
                } else {
                    self.block_open = true;
                }
            },
            _ => {
                return Err(Self::invalid(
                    "block map violates BlockMap/File/Block nesting",
                ));
            },
        }
        Ok(())
    }

    fn end(&mut self, name: &[u8]) -> Result<(), Failure> {
        if self.depth == 0 {
            return Err(Self::invalid("XML close element underflows parser state"));
        }
        if let Some(skip_depth) = self.skip_depth {
            if self.depth == skip_depth {
                self.skip_depth = None;
            }
            self.depth -= 1;
            return Ok(());
        }
        match self.depth {
            3 if name == b"Block" && self.block_open => {
                self.block_open = false;
            },
            2 if name == b"File" && self.current.is_some() && !self.block_open => {
                self.close_file()?;
            },
            1 if name == b"BlockMap"
                && self.document == DocumentState::InRoot
                && self.current.is_none() =>
            {
                self.document = DocumentState::Closed;
            },
            _ => {
                return Err(Self::invalid(
                    "block-map close element violates schema nesting",
                ));
            },
        }
        self.depth -= 1;
        Ok(())
    }

    fn parse_root_attributes(
        &mut self,
        reader: &Reader<&[u8]>,
        element: &BytesStart<'_>,
    ) -> Result<(), Failure> {
        let attributes = decoded_attributes(reader, element, 35, self.xml_version)?;
        let mut namespace: Option<String> = None;
        let mut hash_method: Option<String> = None;
        let mut ignorable: Option<String> = None;
        for (name, value) in attributes {
            if name == b"xmlns" {
                set_once(&mut namespace, value, "duplicate default XML namespace")?;
            } else if let Some(prefix) = name.strip_prefix(b"xmlns:") {
                if prefix.is_empty()
                    || self
                        .declared_prefixes
                        .insert(prefix.to_vec(), value.into_bytes())
                        .is_some()
                {
                    return Err(Self::invalid("duplicate or empty XML namespace prefix"));
                }
            } else if name == b"HashMethod" {
                set_once(&mut hash_method, value, "duplicate HashMethod attribute")?;
            } else if name == b"IgnorableNamespaces" {
                set_once(
                    &mut ignorable,
                    value,
                    "duplicate IgnorableNamespaces attribute",
                )?;
            } else {
                return Err(Self::invalid("BlockMap root contains an unknown attribute"));
            }
        }
        match namespace.as_deref() {
            Some(BLOCK_MAP_NAMESPACE) => {},
            Some(BLOCK_MAP_NAMESPACE_2015 | BLOCK_MAP_NAMESPACE_2017) => {
                return Err(Failure::unsupported_scope(
                    "encrypted/delta BlockMap 2015/2017 vocabulary is not verified",
                ));
            },
            _ => {
                return Err(Self::invalid(
                    "BlockMap has the wrong or missing default namespace",
                ));
            },
        }
        let hash_method =
            hash_method.ok_or_else(|| Self::invalid("BlockMap has no HashMethod attribute"))?;
        if hash_method != SHA256_URI {
            return Err(Failure::unsupported_algorithm(format!(
                "MSIX BlockMap requests unsupported hash method {hash_method}"
            )));
        }
        if let Some(prefixes) = ignorable {
            for prefix in prefixes.split_ascii_whitespace() {
                let prefix = prefix.as_bytes();
                let namespace = self.declared_prefixes.get(prefix).ok_or_else(|| {
                    Self::invalid("IgnorableNamespaces names an undeclared prefix")
                })?;
                if namespace.as_slice() == BLOCK_MAP_NAMESPACE.as_bytes() {
                    return Err(Self::invalid("core BlockMap namespace cannot be ignorable"));
                }
                self.ignorable_prefixes.insert(prefix.to_vec());
            }
            if self.ignorable_prefixes.is_empty() {
                return Err(Self::invalid(
                    "IgnorableNamespaces must name at least one prefix",
                ));
            }
        }
        Ok(())
    }

    fn parse_file_attributes(
        &mut self,
        reader: &Reader<&[u8]>,
        element: &BytesStart<'_>,
    ) -> Result<BlockMapFile, Failure> {
        if self
            .limits
            .entries()
            .is_some_and(|limit| self.files.len() as u64 >= limit)
        {
            return Err(Self::resource(
                "AppxBlockMap.xml file count exceeds configured limit",
            ));
        }
        let (raw_name, raw_size, raw_local_header_size) =
            Self::file_attribute_values(reader, element, self.xml_version)?;
        let name = normalize_block_map_name(&raw_name, self.limits)?;
        if is_excluded_footprint(&name) {
            return Err(Failure::invalid(
                Some(name),
                "excluded MSIX footprint file must not appear in AppxBlockMap.xml",
            ));
        }
        if !self.folded_names.insert(ascii_case_fold(&name)) {
            return Err(Failure::invalid(
                Some(name),
                "AppxBlockMap.xml repeats or case-collides a File name",
            ));
        }
        let size = self.validate_file_size(&name, &raw_size)?;
        let local_header_size = Self::validate_local_header_size(&name, &raw_local_header_size)?;
        self.allocate_file(name, size, local_header_size)
    }

    fn file_attribute_values(
        reader: &Reader<&[u8]>,
        element: &BytesStart<'_>,
        xml_version: XmlVersion,
    ) -> Result<(String, String, String), Failure> {
        let attributes = decoded_attributes(reader, element, 3, xml_version)?;
        let mut name: Option<String> = None;
        let mut size: Option<String> = None;
        let mut local_header_size: Option<String> = None;
        for (key, value) in attributes {
            match key.as_slice() {
                b"Name" => set_once(&mut name, value, "File repeats Name")?,
                b"Size" => set_once(&mut size, value, "File repeats Size")?,
                b"LfhSize" => {
                    set_once(&mut local_header_size, value, "File repeats LfhSize")?;
                },
                _ => return Err(Self::invalid("File contains an unknown attribute")),
            }
        }
        Ok((
            name.ok_or_else(|| Self::invalid("File has no Name attribute"))?,
            size.ok_or_else(|| Self::invalid("File has no Size attribute"))?,
            local_header_size.ok_or_else(|| Self::invalid("File has no LfhSize attribute"))?,
        ))
    }

    fn validate_file_size(&mut self, name: &[u8], raw_size: &str) -> Result<u64, Failure> {
        let size = parse_decimal_u64(raw_size, "File Size")?;
        if self.limits.entry_bytes().is_some_and(|limit| size > limit) {
            return Err(Failure::resource(
                Some(name.to_vec()),
                "BlockMap File Size exceeds configured per-entry limit",
            ));
        }
        self.total_declared_size = self
            .total_declared_size
            .checked_add(size)
            .ok_or_else(|| Self::resource("AppxBlockMap.xml declared-size accounting overflow"))?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|limit| self.total_declared_size > limit)
        {
            return Err(Self::resource(
                "BlockMap declared file sizes exceed configured decoded-total limit",
            ));
        }
        Ok(size)
    }

    fn validate_local_header_size(name: &[u8], raw_size: &str) -> Result<u32, Failure> {
        let local_header_size = parse_decimal_u64(raw_size, "File LfhSize")?;
        if !(LOCAL_HEADER_LEN as u64..=65_536).contains(&local_header_size) {
            return Err(Failure::invalid(
                Some(name.to_vec()),
                "File LfhSize is outside the 30..=65536 schema range",
            ));
        }
        u32::try_from(local_header_size).map_err(|_| Self::invalid("File LfhSize does not fit u32"))
    }

    fn allocate_file(
        &mut self,
        name: Vec<u8>,
        size: u64,
        local_header_size: u32,
    ) -> Result<BlockMapFile, Failure> {
        let blocks = block_count(size)?;
        let blocks = usize::try_from(blocks).map_err(|_| {
            Failure::resource(
                Some(name.clone()),
                "BlockMap File block count exceeds this platform's address space",
            )
        })?;
        self.budget.charge(
            name.len()
                .checked_add(size_of::<BlockMapFile>())
                .and_then(|value| value.checked_add(blocks.saturating_mul(size_of::<Block>())))
                .ok_or_else(|| {
                    Failure::resource(
                        Some(name.clone()),
                        "BlockMap parsed metadata accounting overflow",
                    )
                })?,
            "parsed AppxBlockMap.xml metadata exceeds configured budget",
        )?;
        let mut parsed_blocks = Vec::new();
        parsed_blocks.try_reserve_exact(blocks).map_err(|error| {
            Failure::resource(
                Some(name.clone()),
                format!("cannot allocate parsed BlockMap blocks: {error}"),
            )
        })?;
        Ok(BlockMapFile {
            name,
            size,
            local_header_size,
            blocks: parsed_blocks,
        })
    }

    fn parse_block_attributes(
        reader: &Reader<&[u8]>,
        element: &BytesStart<'_>,
        xml_version: XmlVersion,
    ) -> Result<Block, Failure> {
        let attributes = decoded_attributes(reader, element, 2, xml_version)?;
        let mut hash: Option<String> = None;
        let mut compressed_size: Option<String> = None;
        for (key, value) in attributes {
            match key.as_slice() {
                b"Hash" => set_once(&mut hash, value, "Block repeats Hash")?,
                b"Size" => set_once(&mut compressed_size, value, "Block repeats Size")?,
                _ => return Err(Self::invalid("Block contains an unknown attribute")),
            }
        }
        let encoded = hash.ok_or_else(|| Self::invalid("Block has no Hash attribute"))?;
        let decoded = STANDARD.decode(encoded.as_bytes()).map_err(|error| {
            Self::invalid(format!("Block Hash is not canonical base64: {error}"))
        })?;
        let hash: [u8; 32] = decoded
            .try_into()
            .map_err(|_| Self::invalid("SHA-256 Block Hash must decode to exactly 32 bytes"))?;
        let compressed_size = compressed_size
            .map(|value| {
                let value = parse_decimal_u64(&value, "Block Size")?;
                if value == 0 {
                    return Err(Self::invalid("Block Size must be a positive integer"));
                }
                Ok(value)
            })
            .transpose()?;
        Ok(Block {
            hash,
            compressed_size,
        })
    }

    fn close_file(&mut self) -> Result<(), Failure> {
        let file = self
            .current
            .take()
            .ok_or_else(|| Self::invalid("File close has no active File"))?;
        let expected = block_count(file.size)?;
        if file.blocks.len() as u64 != expected {
            return Err(Failure::invalid(
                Some(file.name),
                format!(
                    "File Size requires {expected} Block elements, found {}",
                    file.blocks.len()
                ),
            ));
        }
        self.files.push(file);
        Ok(())
    }

    fn finish(self) -> Result<BlockMap, Failure> {
        if self.document != DocumentState::Closed || self.depth != 0 || self.skip_depth.is_some() {
            return Err(Self::invalid(
                "AppxBlockMap.xml ended before the root element closed",
            ));
        }
        if self.files.is_empty() {
            return Err(Self::invalid("BlockMap must contain at least one File"));
        }
        if !self.files.iter().any(|file| file.name == MANIFEST_NAME) {
            return Err(Failure::invalid(
                Some(MANIFEST_NAME.to_vec()),
                "AppxManifest.xml must be listed in AppxBlockMap.xml",
            ));
        }
        Ok(BlockMap { files: self.files })
    }

    fn invalid(detail: impl Into<String>) -> Failure {
        Failure::invalid(Some(BLOCK_MAP_NAME.to_vec()), detail)
    }

    fn resource(detail: impl Into<String>) -> Failure {
        Failure::resource(Some(BLOCK_MAP_NAME.to_vec()), detail)
    }
}

fn decoded_attributes(
    reader: &Reader<&[u8]>,
    element: &BytesStart<'_>,
    maximum: usize,
    xml_version: XmlVersion,
) -> Result<Vec<(Vec<u8>, String)>, Failure> {
    let mut attributes = Vec::new();
    let mut seen = BTreeSet::new();
    for attribute in element.attributes() {
        if attributes.len() >= maximum {
            return Err(Failure::resource(
                Some(BLOCK_MAP_NAME.to_vec()),
                "XML element attribute count exceeds the block-map schema limit",
            ));
        }
        let attribute = attribute.map_err(|error| {
            Failure::invalid(
                Some(BLOCK_MAP_NAME.to_vec()),
                format!("invalid or duplicate XML attribute: {error}"),
            )
        })?;
        let name = attribute.key.as_ref().to_vec();
        if !seen.insert(name.clone()) {
            return Err(Failure::invalid(
                Some(BLOCK_MAP_NAME.to_vec()),
                "XML element repeats an attribute",
            ));
        }
        let value = attribute
            .decoded_and_normalized_value(xml_version, reader.decoder())
            .map_err(|error| {
                Failure::invalid(
                    Some(BLOCK_MAP_NAME.to_vec()),
                    format!("invalid XML attribute value: {error}"),
                )
            })?
            .into_owned();
        attributes.push((name, value));
    }
    Ok(attributes)
}

fn set_once(
    target: &mut Option<String>,
    value: String,
    detail: &'static str,
) -> Result<(), Failure> {
    if target.replace(value).is_some() {
        return Err(Failure::invalid(Some(BLOCK_MAP_NAME.to_vec()), detail));
    }
    Ok(())
}

fn compare_block_map(
    block_map: &BlockMap,
    central: &BTreeMap<Vec<u8>, CentralEntry>,
    actual: &BTreeMap<Vec<u8>, ActualEntry>,
) -> MsixVerification {
    let mut findings = Vec::new();
    let mut covered = BTreeSet::new();
    let mut unsupported = false;
    for declared in &block_map.files {
        if !covered.insert(declared.name.clone()) {
            findings.push(integrity_finding(
                Some(declared.name.clone()),
                PackageFindingCode::InvalidIntegrityMetadata,
                "AppxBlockMap.xml repeats a normalized File name",
            ));
            continue;
        }
        unsupported |= compare_declared_file(declared, central, actual, &mut findings);
    }

    for name in central.keys() {
        if !is_excluded_footprint(name) && !covered.contains(name) {
            findings.push(integrity_finding(
                Some(name.clone()),
                PackageFindingCode::MissingIntegrityRecord,
                "package file is absent from AppxBlockMap.xml",
            ));
        }
    }

    let invalid = findings.iter().any(|finding| {
        !matches!(
            finding.code(),
            PackageFindingCode::UnsupportedIntegrityScope
        )
    });
    let integrity = if invalid {
        VerificationDimension::Invalid
    } else if unsupported {
        VerificationDimension::Unsupported
    } else {
        VerificationDimension::Verified
    };
    MsixVerification {
        integrity,
        findings,
    }
}

fn compare_declared_file(
    declared: &BlockMapFile,
    central: &BTreeMap<Vec<u8>, CentralEntry>,
    actual: &BTreeMap<Vec<u8>, ActualEntry>,
    findings: &mut Vec<PackageFinding>,
) -> bool {
    let Some(central_entry) = central.get(&declared.name) else {
        findings.push(integrity_finding(
            Some(declared.name.clone()),
            PackageFindingCode::MissingIntegrityRecord,
            "AppxBlockMap.xml names a file absent from the package",
        ));
        return false;
    };
    let Some(actual_entry) = actual.get(&declared.name) else {
        findings.push(integrity_finding(
            Some(declared.name.clone()),
            PackageFindingCode::IntegrityReadFailure,
            "package file was not delivered by the bounded ZIP reader",
        ));
        return false;
    };
    compare_file_sizes(declared, central_entry, actual_entry, findings);
    let unsupported = compare_compression(declared, central_entry, findings);
    compare_block_hashes(declared, actual_entry, findings);
    unsupported
}

fn compare_file_sizes(
    declared: &BlockMapFile,
    central: &CentralEntry,
    actual: &ActualEntry,
    findings: &mut Vec<PackageFinding>,
) {
    if declared.size != central.uncompressed_size || declared.size != actual.size {
        findings.push(integrity_finding(
            Some(declared.name.clone()),
            PackageFindingCode::IntegrityMismatch,
            format!(
                "BlockMap Size {} disagrees with ZIP/decoded size {}/{}",
                declared.size, central.uncompressed_size, actual.size
            ),
        ));
    }
    if declared.local_header_size != central.local_header_size {
        findings.push(integrity_finding(
            Some(declared.name.clone()),
            PackageFindingCode::IntegrityMismatch,
            format!(
                "BlockMap LfhSize {} disagrees with ZIP local-header size {}",
                declared.local_header_size, central.local_header_size
            ),
        ));
    }
}

fn compare_compression(
    declared: &BlockMapFile,
    central: &CentralEntry,
    findings: &mut Vec<PackageFinding>,
) -> bool {
    match central.method {
        METHOD_STORE => {
            if declared
                .blocks
                .iter()
                .any(|block| block.compressed_size.is_some())
            {
                findings.push(integrity_finding(
                    Some(declared.name.clone()),
                    PackageFindingCode::InvalidIntegrityMetadata,
                    "stored MSIX file must omit every Block Size attribute",
                ));
            }
            false
        },
        METHOD_DEFLATE => {
            compare_deflated_block_sizes(declared, central.compressed_size, findings);
            false
        },
        method => {
            findings.push(integrity_finding(
                Some(declared.name.clone()),
                PackageFindingCode::UnsupportedIntegrityScope,
                format!(
                    "MSIX file uses ZIP method {method}; compressed Block Size cannot be verified"
                ),
            ));
            true
        },
    }
}

fn compare_deflated_block_sizes(
    declared: &BlockMapFile,
    compressed_size: u64,
    findings: &mut Vec<PackageFinding>,
) {
    let compressed_total = declared.blocks.iter().try_fold(0_u64, |total, block| {
        block
            .compressed_size
            .and_then(|size| total.checked_add(size))
    });
    match compressed_total {
        // Microsoft emits every 64-KiB sequence with Z_FULL_FLUSH and records
        // those sequence lengths. The raw ZIP stream then ends with a two-byte
        // empty Z_FINISH block which is outside the final Block Size.
        Some(total)
            if total
                .checked_add(2)
                .is_some_and(|size| size == compressed_size) => {},
        Some(total) => findings.push(integrity_finding(
            Some(declared.name.clone()),
            PackageFindingCode::IntegrityMismatch,
            format!(
                "Block Size total {total} plus Deflate terminator disagrees with ZIP compressed size {compressed_size}"
            ),
        )),
        None => findings.push(integrity_finding(
            Some(declared.name.clone()),
            PackageFindingCode::InvalidIntegrityMetadata,
            "deflated MSIX file requires a positive Size on every Block",
        )),
    }
}

fn compare_block_hashes(
    declared: &BlockMapFile,
    actual: &ActualEntry,
    findings: &mut Vec<PackageFinding>,
) {
    if declared.blocks.len() != actual.block_hashes.len() {
        findings.push(integrity_finding(
            Some(declared.name.clone()),
            PackageFindingCode::IntegrityMismatch,
            format!(
                "BlockMap declares {} hashes but decoded file has {} 64-KiB blocks",
                declared.blocks.len(),
                actual.block_hashes.len()
            ),
        ));
    }
    for (index, (declared_block, actual_hash)) in
        declared.blocks.iter().zip(&actual.block_hashes).enumerate()
    {
        if &declared_block.hash != actual_hash {
            findings.push(integrity_finding(
                Some(declared.name.clone()),
                PackageFindingCode::IntegrityMismatch,
                format!("Block {} SHA-256 hash does not match", index + 1),
            ));
        }
    }
}

fn integrity_finding(
    path: Option<Vec<u8>>,
    code: PackageFindingCode,
    detail: impl Into<String>,
) -> PackageFinding {
    PackageFinding::new(PROFILE, path, code, detail)
}

fn parse_decimal_u64(value: &str, field: &'static str) -> Result<u64, Failure> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Failure::invalid(
            Some(BLOCK_MAP_NAME.to_vec()),
            format!("{field} is not a non-negative decimal integer"),
        ));
    }
    value.parse::<u64>().map_err(|error| {
        Failure::invalid(
            Some(BLOCK_MAP_NAME.to_vec()),
            format!("{field} overflows u64: {error}"),
        )
    })
}

fn block_count(size: u64) -> Result<u64, Failure> {
    size.checked_add(BLOCK_SIZE - 1)
        .map(|value| value / BLOCK_SIZE)
        .ok_or_else(|| {
            Failure::resource(
                Some(BLOCK_MAP_NAME.to_vec()),
                "MSIX block-count arithmetic overflow",
            )
        })
}

fn normalize_archive_name(raw: &[u8], limits: Limits) -> Result<Vec<u8>, Failure> {
    let name = std::str::from_utf8(raw).map_err(|error| {
        Failure::invalid(
            Some(raw.to_vec()),
            format!("MSIX member name is not UTF-8: {error}"),
        )
    })?;
    normalize_name(name, limits, Some(raw.to_vec()))
}

fn normalize_block_map_name(name: &str, limits: Limits) -> Result<Vec<u8>, Failure> {
    normalize_name(name, limits, Some(name.as_bytes().to_vec()))
}

fn normalize_name(
    name: &str,
    limits: Limits,
    original: Option<Vec<u8>>,
) -> Result<Vec<u8>, Failure> {
    if name.is_empty() || name.chars().count() > MAX_APPX_NAME_CHARS {
        return Err(Failure::invalid(
            original,
            "MSIX path is empty or exceeds the APPX character limit",
        ));
    }
    if limits.path_bytes().is_some_and(|limit| name.len() > limit) {
        return Err(Failure::resource(
            original,
            "MSIX path exceeds configured path-byte limit",
        ));
    }
    let normalized: Vec<u8> = name
        .as_bytes()
        .iter()
        .map(|byte| if *byte == b'\\' { b'/' } else { *byte })
        .collect();
    if normalized.starts_with(b"/")
        || normalized.ends_with(b"/")
        || normalized.contains(&b'\0')
        || normalized.contains(&b':')
        || normalized
            .split(|byte| *byte == b'/')
            .any(|segment| segment.is_empty() || segment == b"." || segment == b"..")
    {
        return Err(Failure::invalid(
            Some(normalized),
            "MSIX path is absolute, traversing, empty-segmented, or device-qualified",
        ));
    }
    Ok(normalized)
}

fn ascii_case_fold(name: &[u8]) -> Vec<u8> {
    name.iter().map(u8::to_ascii_lowercase).collect()
}

fn is_excluded_footprint(name: &[u8]) -> bool {
    name == BLOCK_MAP_NAME
        || name == CONTENT_TYPES_NAME
        || name == SIGNATURE_NAME
        || name == CODE_INTEGRITY_NAME
}

fn element_prefix(name: &[u8]) -> Option<&[u8]> {
    name.iter()
        .position(|byte| *byte == b':')
        .map(|separator| &name[..separator])
}
