// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded Android binary XML SDK declaration parser.

use std::io::{Read, Seek};

use libarchive_oxide::Limits;
use libarchive_oxide::{ErrorKind, ReaderEvent, SeekArchiveReader};

use crate::{PackageFinding, PackageFindingCode, VerificationDimension};

const MANIFEST_PATH: &[u8] = b"AndroidManifest.xml";

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_TYPE: u16 = 0x0003;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;
const UTF8_FLAG: u32 = 0x0000_0100;
const NO_INDEX: u32 = u32::MAX;
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const MIN_SDK_ID: u32 = 0x0101_020c;
const TARGET_SDK_ID: u32 = 0x0101_0270;
const MAX_CHUNKS: usize = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AndroidManifestSdk {
    pub(crate) minimum_sdk: u32,
    pub(crate) target_sdk: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Failure {
    Invalid(String),
    Unsupported(String),
    Resource(String),
}

/// Bounded binary `AndroidManifest.xml` SDK inspection result.
///
/// The manifest syntax verdict is independent from APK signature validity and issuer trust.
/// SDK values are present only after a complete binary XML parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndroidApkManifestReport {
    validity: VerificationDimension,
    minimum_sdk: Option<u32>,
    target_sdk: Option<u32>,
    findings: Vec<PackageFinding>,
}

impl AndroidApkManifestReport {
    pub(crate) fn not_evaluated() -> Self {
        Self {
            validity: VerificationDimension::NotEvaluated,
            minimum_sdk: None,
            target_sdk: None,
            findings: Vec::new(),
        }
    }

    /// Binary XML syntax and stable SDK-value verdict.
    #[must_use]
    pub const fn validity(&self) -> VerificationDimension {
        self.validity
    }

    /// Effective minimum platform SDK, including Android's default of API 1.
    #[must_use]
    pub const fn minimum_sdk(&self) -> Option<u32> {
        self.minimum_sdk
    }

    /// Effective target platform SDK, defaulted to the effective minimum SDK.
    #[must_use]
    pub const fn target_sdk(&self) -> Option<u32> {
        self.target_sdk
    }

    /// Manifest-specific typed findings.
    #[must_use]
    pub fn findings(&self) -> &[PackageFinding] {
        &self.findings
    }

    fn missing() -> Self {
        Self {
            validity: VerificationDimension::NotPresent,
            minimum_sdk: None,
            target_sdk: None,
            findings: Vec::new(),
        }
    }

    fn verified(sdk: AndroidManifestSdk) -> Self {
        Self {
            validity: VerificationDimension::Verified,
            minimum_sdk: Some(sdk.minimum_sdk),
            target_sdk: Some(sdk.target_sdk),
            findings: Vec::new(),
        }
    }

    fn failed(failure: Failure) -> Self {
        let (validity, code, detail) = match failure {
            Failure::Invalid(detail) => (
                VerificationDimension::Invalid,
                PackageFindingCode::InvalidAndroidManifest,
                detail,
            ),
            Failure::Unsupported(detail) => (
                VerificationDimension::Unsupported,
                PackageFindingCode::UnsupportedAndroidManifestSdk,
                detail,
            ),
            Failure::Resource(detail) => (
                VerificationDimension::Invalid,
                PackageFindingCode::AndroidManifestResourceLimit,
                detail,
            ),
        };
        Self {
            validity,
            minimum_sdk: None,
            target_sdk: None,
            findings: vec![PackageFinding::new(
                "android-apk",
                Some(MANIFEST_PATH.to_vec()),
                code,
                detail,
            )],
        }
    }
}

/// Locates and decodes only the root Android manifest entry.
/// Other ZIP members are skipped through the seek reader without buffering their payloads.
pub(crate) fn inspect_android_manifest<R: Read + Seek>(
    reader: R,
    limits: Limits,
) -> AndroidApkManifestReport {
    match read_android_manifest(reader, limits) {
        Ok(Some(bytes)) => match parse_android_manifest(&bytes, limits) {
            Ok(sdk) => AndroidApkManifestReport::verified(sdk),
            Err(failure) => AndroidApkManifestReport::failed(failure),
        },
        Ok(None) => AndroidApkManifestReport::missing(),
        Err(failure) => AndroidApkManifestReport::failed(failure),
    }
}

fn read_android_manifest<R: Read + Seek>(
    reader: R,
    limits: Limits,
) -> Result<Option<Vec<u8>>, Failure> {
    let mut archive =
        SeekArchiveReader::with_limits(reader, limits).map_err(|error| archive_failure(&error))?;
    let maximum = limits.metadata_bytes().unwrap_or(64 * 1024 * 1024);
    let mut found = false;
    let mut collecting = false;
    let mut skipping = false;
    let mut body = Vec::new();

    loop {
        match archive
            .next_event()
            .map_err(|error| archive_failure(&error))?
        {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => {
                if collecting || skipping {
                    return Err(Failure::Invalid(
                        "APK decoder started an entry before ending the previous entry".to_string(),
                    ));
                }
                let is_manifest = metadata.path().as_bytes() == MANIFEST_PATH;
                if !is_manifest {
                    archive
                        .skip_entry()
                        .map_err(|error| archive_failure(&error))?;
                    skipping = true;
                    continue;
                }
                if found {
                    return Err(Failure::Invalid(
                        "APK contains more than one AndroidManifest.xml entry".to_string(),
                    ));
                }
                found = true;
                collecting = true;
                if metadata.size().is_some_and(|size| size > maximum as u64) {
                    return Err(Failure::Resource(
                        "AndroidManifest.xml exceeds the configured metadata limit".to_string(),
                    ));
                }
            },
            ReaderEvent::Data(bytes) => {
                if !collecting {
                    return Err(Failure::Invalid(
                        "APK decoder produced data outside the selected manifest entry".to_string(),
                    ));
                }
                let length = body
                    .len()
                    .checked_add(bytes.len())
                    .ok_or_else(|| Failure::Resource("manifest size overflow".to_string()))?;
                if length > maximum {
                    return Err(Failure::Resource(
                        "AndroidManifest.xml exceeds the configured metadata limit".to_string(),
                    ));
                }
                body.extend_from_slice(bytes);
            },
            ReaderEvent::EndEntry => {
                if collecting {
                    collecting = false;
                } else if skipping {
                    skipping = false;
                } else {
                    return Err(Failure::Invalid(
                        "APK decoder ended an entry that was not selected".to_string(),
                    ));
                }
            },
            ReaderEvent::Done => {
                if collecting || skipping {
                    return Err(Failure::Invalid(
                        "APK ended before AndroidManifest.xml was complete".to_string(),
                    ));
                }
                return Ok(found.then_some(body));
            },
            _ => {
                return Err(Failure::Invalid(
                    "APK reader returned an unknown event".to_string(),
                ));
            },
        }
    }
}

fn archive_failure(error: &libarchive_oxide::Error) -> Failure {
    match error.kind() {
        ErrorKind::Limit => Failure::Resource(error.to_string()),
        ErrorKind::Unsupported | ErrorKind::Capability => Failure::Unsupported(error.to_string()),
        _ => Failure::Invalid(error.to_string()),
    }
}

#[allow(clippy::too_many_lines)] // One pass keeps XML nesting and document framing atomic.
pub(crate) fn parse_android_manifest(
    bytes: &[u8],
    limits: Limits,
) -> Result<AndroidManifestSdk, Failure> {
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| bytes.len() > maximum)
    {
        return Err(Failure::Resource(
            "AndroidManifest.xml exceeds the configured metadata limit".to_string(),
        ));
    }
    let document = Chunk::read(bytes, 0)?;
    if document.kind != RES_XML_TYPE || document.header_size != 8 {
        return Err(Failure::Invalid(
            "AndroidManifest.xml has no binary XML document header".to_string(),
        ));
    }
    if document.end != bytes.len() {
        return Err(Failure::Invalid(
            "AndroidManifest.xml document size does not consume the entry".to_string(),
        ));
    }

    let mut offset = document.header_size;
    let mut chunks = 0_usize;
    let mut strings: Option<StringPool<'_>> = None;
    let mut resource_map: Option<ResourceMap<'_>> = None;
    let mut stack = Vec::<(u32, u32)>::new();
    let mut saw_manifest = false;
    let mut closed_manifest = false;
    let mut minimum_sdk = 1_u32;
    let mut target_sdk = None;

    while offset < document.end {
        chunks = chunks
            .checked_add(1)
            .ok_or_else(|| Failure::Resource("binary XML chunk count overflow".to_string()))?;
        if chunks > MAX_CHUNKS {
            return Err(Failure::Resource(format!(
                "AndroidManifest.xml exceeds the {MAX_CHUNKS}-chunk limit"
            )));
        }
        let chunk = Chunk::read(bytes, offset)?;
        if chunk.end > document.end {
            return Err(Failure::Invalid(
                "binary XML child chunk exceeds its document".to_string(),
            ));
        }
        match chunk.kind {
            RES_STRING_POOL_TYPE => {
                if strings.is_some() || saw_manifest {
                    return Err(Failure::Invalid(
                        "binary XML has a misplaced or duplicate string pool".to_string(),
                    ));
                }
                strings = Some(StringPool::parse(bytes, chunk)?);
            },
            RES_XML_RESOURCE_MAP_TYPE => {
                if resource_map.is_some() || saw_manifest {
                    return Err(Failure::Invalid(
                        "binary XML has a misplaced or duplicate resource map".to_string(),
                    ));
                }
                resource_map = Some(ResourceMap::parse(bytes, chunk)?);
            },
            RES_XML_START_ELEMENT_TYPE => {
                let pool = strings.as_ref().ok_or_else(|| {
                    Failure::Invalid("element precedes the binary XML string pool".to_string())
                })?;
                let element = Element::parse(bytes, chunk)?;
                let name = pool.string(element.name)?;
                if stack.is_empty() {
                    if saw_manifest
                        || closed_manifest
                        || element.namespace != NO_INDEX
                        || name != "manifest"
                    {
                        return Err(Failure::Invalid(
                            "binary XML root element is not an unnamespaced manifest".to_string(),
                        ));
                    }
                    saw_manifest = true;
                } else if closed_manifest {
                    return Err(Failure::Invalid(
                        "binary XML contains an element after the manifest root".to_string(),
                    ));
                }

                if stack.len() == 1 && element.namespace == NO_INDEX && name == "uses-sdk" {
                    let map = resource_map.as_ref().ok_or_else(|| {
                        Failure::Invalid(
                            "uses-sdk attributes require a binary XML resource map".to_string(),
                        )
                    })?;
                    let sdk = element.sdk_attributes(bytes, pool, map)?;
                    minimum_sdk = minimum_sdk.max(sdk.minimum_sdk.unwrap_or(1));
                    if target_sdk.is_none() {
                        target_sdk = sdk.target_sdk;
                    }
                }

                if limits
                    .nesting()
                    .is_some_and(|maximum| stack.len() >= maximum)
                {
                    return Err(Failure::Resource(
                        "AndroidManifest.xml nesting exceeds the configured limit".to_string(),
                    ));
                }
                stack.push((element.namespace, element.name));
            },
            RES_XML_END_ELEMENT_TYPE => {
                let element = EndElement::parse(bytes, chunk)?;
                let expected = stack.pop().ok_or_else(|| {
                    Failure::Invalid("binary XML end element underflows nesting".to_string())
                })?;
                if expected != (element.namespace, element.name) {
                    return Err(Failure::Invalid(
                        "binary XML start/end element names or namespaces disagree".to_string(),
                    ));
                }
                if stack.is_empty() {
                    closed_manifest = true;
                }
            },
            RES_XML_START_NAMESPACE_TYPE | RES_XML_END_NAMESPACE_TYPE | RES_XML_CDATA_TYPE => {
                validate_node_chunk(chunk)?;
            },
            _ => {
                return Err(Failure::Unsupported(format!(
                    "AndroidManifest.xml contains unsupported binary XML chunk {:#06x}",
                    chunk.kind
                )));
            },
        }
        offset = chunk.end;
    }

    if !saw_manifest || !closed_manifest || !stack.is_empty() {
        return Err(Failure::Invalid(
            "binary XML manifest root is missing or unclosed".to_string(),
        ));
    }
    Ok(AndroidManifestSdk {
        minimum_sdk,
        target_sdk: target_sdk.unwrap_or(minimum_sdk),
    })
}

#[derive(Debug, Clone, Copy)]
struct Chunk {
    kind: u16,
    header_size: usize,
    end: usize,
    start: usize,
}

impl Chunk {
    fn read(bytes: &[u8], start: usize) -> Result<Self, Failure> {
        let header = bytes
            .get(start..start.saturating_add(8))
            .ok_or_else(|| Failure::Invalid("binary XML chunk header is truncated".to_string()))?;
        let kind = u16::from_le_bytes([header[0], header[1]]);
        let header_size = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let size = usize::try_from(u32::from_le_bytes([
            header[4], header[5], header[6], header[7],
        ]))
        .map_err(|_| {
            Failure::Resource("binary XML chunk size exceeds address space".to_string())
        })?;
        if header_size < 8 || size < header_size {
            return Err(Failure::Invalid(
                "binary XML chunk has an invalid header or total size".to_string(),
            ));
        }
        let end = start
            .checked_add(size)
            .ok_or_else(|| Failure::Resource("binary XML chunk end overflow".to_string()))?;
        if end > bytes.len() {
            return Err(Failure::Invalid(
                "binary XML chunk is truncated".to_string(),
            ));
        }
        Ok(Self {
            kind,
            header_size,
            end,
            start,
        })
    }
}

#[derive(Debug)]
struct StringPool<'a> {
    offsets: &'a [u8],
    strings: &'a [u8],
    count: usize,
    utf8: bool,
}

impl<'a> StringPool<'a> {
    fn parse(bytes: &'a [u8], chunk: Chunk) -> Result<Self, Failure> {
        if chunk.header_size < 28 {
            return Err(Failure::Invalid(
                "binary XML string-pool header is too short".to_string(),
            ));
        }
        let count = usize::try_from(read_u32(bytes, chunk.start + 8)?).map_err(|_| {
            Failure::Resource("binary XML string count exceeds address space".to_string())
        })?;
        let style_count = usize::try_from(read_u32(bytes, chunk.start + 12)?).map_err(|_| {
            Failure::Resource("binary XML style count exceeds address space".to_string())
        })?;
        let flags = read_u32(bytes, chunk.start + 16)?;
        let strings_start = usize::try_from(read_u32(bytes, chunk.start + 20)?).map_err(|_| {
            Failure::Resource("binary XML strings offset exceeds address space".to_string())
        })?;
        let styles_start = usize::try_from(read_u32(bytes, chunk.start + 24)?).map_err(|_| {
            Failure::Resource("binary XML styles offset exceeds address space".to_string())
        })?;
        let offset_bytes = count
            .checked_add(style_count)
            .and_then(|value| value.checked_mul(4))
            .ok_or_else(|| Failure::Resource("binary XML offset table overflow".to_string()))?;
        let offsets_start = chunk.start + chunk.header_size;
        let offsets_end = offsets_start
            .checked_add(offset_bytes)
            .ok_or_else(|| Failure::Resource("binary XML offset table end overflow".to_string()))?;
        let string_data_start = chunk.start.checked_add(strings_start).ok_or_else(|| {
            Failure::Resource("binary XML string data offset overflow".to_string())
        })?;
        if offsets_end > chunk.end
            || string_data_start < offsets_end
            || string_data_start > chunk.end
        {
            return Err(Failure::Invalid(
                "binary XML string-pool offsets are invalid".to_string(),
            ));
        }
        if style_count == 0 && styles_start != 0 {
            return Err(Failure::Invalid(
                "binary XML empty style pool has a nonzero offset".to_string(),
            ));
        }
        if style_count != 0
            && (styles_start == 0
                || chunk
                    .start
                    .checked_add(styles_start)
                    .is_none_or(|value| value > chunk.end))
        {
            return Err(Failure::Invalid(
                "binary XML style-pool offset is invalid".to_string(),
            ));
        }
        Ok(Self {
            offsets: &bytes[offsets_start..offsets_start + count * 4],
            strings: &bytes[string_data_start..chunk.end],
            count,
            utf8: flags & UTF8_FLAG != 0,
        })
    }

    fn string(&self, index: u32) -> Result<String, Failure> {
        let index = usize::try_from(index).map_err(|_| {
            Failure::Resource("binary XML string index exceeds address space".to_string())
        })?;
        if index >= self.count {
            return Err(Failure::Invalid(
                "binary XML string index is out of bounds".to_string(),
            ));
        }
        let table = index * 4;
        let offset = usize::try_from(u32::from_le_bytes([
            self.offsets[table],
            self.offsets[table + 1],
            self.offsets[table + 2],
            self.offsets[table + 3],
        ]))
        .map_err(|_| {
            Failure::Resource("binary XML string offset exceeds address space".to_string())
        })?;
        let value = self.strings.get(offset..).ok_or_else(|| {
            Failure::Invalid("binary XML string offset is out of bounds".to_string())
        })?;
        if self.utf8 {
            decode_utf8_string(value)
        } else {
            decode_utf16_string(value)
        }
    }
}

#[derive(Debug)]
struct ResourceMap<'a> {
    ids: &'a [u8],
}

impl<'a> ResourceMap<'a> {
    fn parse(bytes: &'a [u8], chunk: Chunk) -> Result<Self, Failure> {
        if chunk.header_size != 8 || !(chunk.end - chunk.start - 8).is_multiple_of(4) {
            return Err(Failure::Invalid(
                "binary XML resource map has invalid framing".to_string(),
            ));
        }
        Ok(Self {
            ids: &bytes[chunk.start + 8..chunk.end],
        })
    }

    fn id(&self, string_index: u32) -> Result<u32, Failure> {
        let index = usize::try_from(string_index).map_err(|_| {
            Failure::Resource("resource-map index exceeds address space".to_string())
        })?;
        let start = index
            .checked_mul(4)
            .ok_or_else(|| Failure::Resource("resource-map offset overflow".to_string()))?;
        let end = start
            .checked_add(4)
            .ok_or_else(|| Failure::Resource("resource-map field end overflow".to_string()))?;
        let Some(value) = self.ids.get(start..end) else {
            return Ok(0);
        };
        Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
    }
}

#[derive(Debug, Clone, Copy)]
struct Element {
    namespace: u32,
    name: u32,
    attributes_start: usize,
    attribute_size: usize,
    attribute_count: usize,
}

#[derive(Debug, Default)]
struct SdkAttributes {
    minimum_sdk: Option<u32>,
    target_sdk: Option<u32>,
}

impl Element {
    fn parse(bytes: &[u8], chunk: Chunk) -> Result<Self, Failure> {
        if chunk.header_size < 16 || chunk.end - chunk.start < chunk.header_size + 20 {
            return Err(Failure::Invalid(
                "binary XML start element is truncated".to_string(),
            ));
        }
        let extension = chunk.start + chunk.header_size;
        let namespace = read_u32(bytes, extension)?;
        let name = read_u32(bytes, extension + 4)?;
        let attribute_table_offset = usize::from(read_u16(bytes, extension + 8)?);
        let attribute_size = usize::from(read_u16(bytes, extension + 10)?);
        let attribute_count = usize::from(read_u16(bytes, extension + 12)?);
        if attribute_table_offset < 20 || attribute_size < 20 {
            return Err(Failure::Invalid(
                "binary XML attribute table has invalid strides".to_string(),
            ));
        }
        let attributes_start = extension
            .checked_add(attribute_table_offset)
            .ok_or_else(|| Failure::Resource("attribute table offset overflow".to_string()))?;
        let attributes_end = attribute_count
            .checked_mul(attribute_size)
            .and_then(|length| attributes_start.checked_add(length))
            .ok_or_else(|| Failure::Resource("attribute table size overflow".to_string()))?;
        if attributes_end > chunk.end {
            return Err(Failure::Invalid(
                "binary XML attribute table is truncated".to_string(),
            ));
        }
        Ok(Self {
            namespace,
            name,
            attributes_start,
            attribute_size,
            attribute_count,
        })
    }

    fn sdk_attributes(
        self,
        bytes: &[u8],
        strings: &StringPool<'_>,
        resources: &ResourceMap<'_>,
    ) -> Result<SdkAttributes, Failure> {
        let mut sdk = SdkAttributes::default();
        for index in 0..self.attribute_count {
            let start = self.attributes_start + index * self.attribute_size;
            let name = read_u32(bytes, start + 4)?;
            let resource_id = resources.id(name)?;
            if !matches!(resource_id, MIN_SDK_ID | TARGET_SDK_ID) {
                continue;
            }
            let value_size = read_u16(bytes, start + 12)?;
            let reserved = *bytes.get(start + 14).ok_or_else(|| {
                Failure::Invalid("binary XML typed value is truncated".to_string())
            })?;
            let value_type = *bytes.get(start + 15).ok_or_else(|| {
                Failure::Invalid("binary XML typed value is truncated".to_string())
            })?;
            if value_size != 8 || reserved != 0 {
                return Err(Failure::Invalid(
                    "binary XML SDK typed value has invalid framing".to_string(),
                ));
            }
            let data = read_u32(bytes, start + 16)?;
            let value = match value_type {
                TYPE_INT_DEC | TYPE_INT_HEX => data,
                TYPE_STRING => {
                    let codename = strings.string(data)?;
                    return Err(Failure::Unsupported(format!(
                        "Android SDK codename {codename:?} cannot be mapped offline to a stable API level"
                    )));
                },
                _ => {
                    return Err(Failure::Unsupported(format!(
                        "Android SDK attribute uses unsupported binary value type {value_type:#04x}"
                    )));
                },
            };
            let slot = if resource_id == MIN_SDK_ID {
                &mut sdk.minimum_sdk
            } else {
                &mut sdk.target_sdk
            };
            if slot.replace(value).is_some() {
                return Err(Failure::Invalid(
                    "uses-sdk repeats an Android SDK attribute".to_string(),
                ));
            }
        }
        Ok(sdk)
    }
}

#[derive(Debug, Clone, Copy)]
struct EndElement {
    namespace: u32,
    name: u32,
}

impl EndElement {
    fn parse(bytes: &[u8], chunk: Chunk) -> Result<Self, Failure> {
        if chunk.header_size < 16 || chunk.end - chunk.start < chunk.header_size + 8 {
            return Err(Failure::Invalid(
                "binary XML end element is truncated".to_string(),
            ));
        }
        Ok(Self {
            namespace: read_u32(bytes, chunk.start + chunk.header_size)?,
            name: read_u32(bytes, chunk.start + chunk.header_size + 4)?,
        })
    }
}

fn validate_node_chunk(chunk: Chunk) -> Result<(), Failure> {
    if chunk.header_size < 16 {
        Err(Failure::Invalid(
            "binary XML node header is too short".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn decode_utf8_string(bytes: &[u8]) -> Result<String, Failure> {
    let (_, after_utf16) = utf8_length(bytes, 0)?;
    let (byte_length, start) = utf8_length(bytes, after_utf16)?;
    let end = start
        .checked_add(byte_length)
        .ok_or_else(|| Failure::Resource("UTF-8 string end overflow".to_string()))?;
    let value = bytes
        .get(start..end)
        .ok_or_else(|| Failure::Invalid("binary XML UTF-8 string is truncated".to_string()))?;
    if bytes.get(end) != Some(&0) {
        return Err(Failure::Invalid(
            "binary XML UTF-8 string has no terminator".to_string(),
        ));
    }
    core::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| Failure::Invalid("binary XML string is not valid UTF-8".to_string()))
}

fn utf8_length(bytes: &[u8], offset: usize) -> Result<(usize, usize), Failure> {
    let first = *bytes
        .get(offset)
        .ok_or_else(|| Failure::Invalid("binary XML UTF-8 length is truncated".to_string()))?;
    if first & 0x80 == 0 {
        Ok((usize::from(first), offset + 1))
    } else {
        let second = *bytes
            .get(offset + 1)
            .ok_or_else(|| Failure::Invalid("binary XML UTF-8 length is truncated".to_string()))?;
        Ok((
            (usize::from(first & 0x7f) << 8) | usize::from(second),
            offset + 2,
        ))
    }
}

fn decode_utf16_string(bytes: &[u8]) -> Result<String, Failure> {
    let (units, start) = utf16_length(bytes)?;
    let byte_length = units
        .checked_mul(2)
        .ok_or_else(|| Failure::Resource("UTF-16 string size overflow".to_string()))?;
    let end = start
        .checked_add(byte_length)
        .ok_or_else(|| Failure::Resource("UTF-16 string end overflow".to_string()))?;
    let raw = bytes
        .get(start..end)
        .ok_or_else(|| Failure::Invalid("binary XML UTF-16 string is truncated".to_string()))?;
    let terminator_end = end
        .checked_add(2)
        .ok_or_else(|| Failure::Resource("UTF-16 terminator end overflow".to_string()))?;
    if bytes.get(end..terminator_end) != Some(&[0, 0]) {
        return Err(Failure::Invalid(
            "binary XML UTF-16 string has no terminator".to_string(),
        ));
    }
    let decoded = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&decoded)
        .map_err(|_| Failure::Invalid("binary XML string is not valid UTF-16".to_string()))
}

fn utf16_length(bytes: &[u8]) -> Result<(usize, usize), Failure> {
    let first = read_u16(bytes, 0)?;
    if first & 0x8000 == 0 {
        Ok((usize::from(first), 2))
    } else {
        let second = read_u16(bytes, 2)?;
        Ok((
            ((usize::from(first & 0x7fff)) << 16) | usize::from(second),
            4,
        ))
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Failure> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| Failure::Invalid("binary XML 16-bit field is truncated".to_string()))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Failure> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| Failure::Invalid("binary XML 32-bit field is truncated".to_string()))?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(test)]
mod tests {
    use super::{AndroidManifestSdk, Failure, TYPE_STRING, parse_android_manifest};
    use libarchive_oxide::Limits;

    const MIN_SDK_ID: u32 = 0x0101_020c;
    const TARGET_SDK_ID: u32 = 0x0101_0270;

    fn push_u16(output: &mut Vec<u8>, value: u16) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn chunk(kind: u16, header_size: u16, mut body: Vec<u8>) -> Vec<u8> {
        let mut output = Vec::new();
        push_u16(&mut output, kind);
        push_u16(&mut output, header_size);
        push_u32(
            &mut output,
            u32::try_from(8 + body.len()).expect("chunk size"),
        );
        output.append(&mut body);
        output
    }

    fn string_pool(strings: &[&str]) -> Vec<u8> {
        let mut offsets = Vec::new();
        let mut encoded = Vec::new();
        for value in strings {
            offsets.push(u32::try_from(encoded.len()).expect("string offset"));
            encoded.push(u8::try_from(value.len()).expect("UTF-16 length"));
            encoded.push(u8::try_from(value.len()).expect("UTF-8 length"));
            encoded.extend_from_slice(value.as_bytes());
            encoded.push(0);
        }
        while encoded.len() % 4 != 0 {
            encoded.push(0);
        }
        let strings_start = 28 + offsets.len() * 4;
        let mut body = Vec::new();
        push_u32(
            &mut body,
            u32::try_from(strings.len()).expect("string count"),
        );
        push_u32(&mut body, 0);
        push_u32(&mut body, 0x100);
        push_u32(
            &mut body,
            u32::try_from(strings_start).expect("strings start"),
        );
        push_u32(&mut body, 0);
        for offset in offsets {
            push_u32(&mut body, offset);
        }
        body.extend_from_slice(&encoded);
        chunk(0x0001, 28, body)
    }

    fn resource_map(ids: &[u32]) -> Vec<u8> {
        let mut body = Vec::new();
        for id in ids {
            push_u32(&mut body, *id);
        }
        chunk(0x0180, 8, body)
    }

    fn start_element(name: u32, attributes: &[(u32, u32)]) -> Vec<u8> {
        let mut body = Vec::new();
        push_u32(&mut body, 1);
        push_u32(&mut body, u32::MAX);
        push_u32(&mut body, u32::MAX);
        push_u32(&mut body, name);
        push_u16(&mut body, 20);
        push_u16(&mut body, 20);
        push_u16(
            &mut body,
            u16::try_from(attributes.len()).expect("attribute count"),
        );
        push_u16(&mut body, 0);
        push_u16(&mut body, 0);
        push_u16(&mut body, 0);
        for (name, value) in attributes {
            push_u32(&mut body, u32::MAX);
            push_u32(&mut body, *name);
            push_u32(&mut body, u32::MAX);
            push_u16(&mut body, 8);
            body.push(0);
            body.push(0x10);
            push_u32(&mut body, *value);
        }
        chunk(0x0102, 16, body)
    }

    fn end_element(name: u32) -> Vec<u8> {
        let mut body = Vec::new();
        push_u32(&mut body, 1);
        push_u32(&mut body, u32::MAX);
        push_u32(&mut body, u32::MAX);
        push_u32(&mut body, name);
        chunk(0x0103, 16, body)
    }

    fn manifest(uses_sdk: &[&[(u32, u32)]]) -> Vec<u8> {
        let strings = ["manifest", "uses-sdk", "minSdkVersion", "targetSdkVersion"];
        let mut chunks = string_pool(&strings);
        chunks.extend_from_slice(&resource_map(&[0, 0, MIN_SDK_ID, TARGET_SDK_ID]));
        chunks.extend_from_slice(&start_element(0, &[]));
        for attributes in uses_sdk {
            chunks.extend_from_slice(&start_element(1, attributes));
            chunks.extend_from_slice(&end_element(1));
        }
        chunks.extend_from_slice(&end_element(0));
        chunk(0x0003, 8, chunks)
    }

    #[test]
    fn parses_numeric_sdk_values_and_android_defaults() {
        let explicit = manifest(&[&[(2, 21), (3, 34)]]);
        assert_eq!(
            parse_android_manifest(&explicit, Limits::safe()),
            Ok(AndroidManifestSdk {
                minimum_sdk: 21,
                target_sdk: 34,
            })
        );

        let defaulted = manifest(&[]);
        assert_eq!(
            parse_android_manifest(&defaulted, Limits::safe()),
            Ok(AndroidManifestSdk {
                minimum_sdk: 1,
                target_sdk: 1,
            })
        );
    }

    #[test]
    fn uses_maximum_minimum_across_multiple_uses_sdk_elements() {
        let bytes = manifest(&[&[(2, 19)], &[(2, 28)]]);
        assert_eq!(
            parse_android_manifest(&bytes, Limits::safe()),
            Ok(AndroidManifestSdk {
                minimum_sdk: 28,
                target_sdk: 28,
            })
        );
    }

    #[test]
    fn rejects_truncation_and_metadata_exhaustion() {
        let bytes = manifest(&[&[(2, 24)]]);
        for length in 0..bytes.len() {
            assert!(
                matches!(
                    parse_android_manifest(&bytes[..length], Limits::safe()),
                    Err(Failure::Invalid(_))
                ),
                "truncation {length}"
            );
        }
        assert!(matches!(
            parse_android_manifest(
                &bytes,
                Limits::safe().with_metadata_bytes(Some(bytes.len() - 1)),
            ),
            Err(Failure::Resource(_))
        ));
    }

    #[test]
    fn rejects_sdk_codenames_without_an_explicit_offline_mapping() {
        let mut bytes = manifest(&[&[(2, 24)]]);
        let typed_value = bytes
            .windows(8)
            .position(|window| window == [8, 0, 0, 0x10, 24, 0, 0, 0])
            .expect("numeric SDK typed value");
        bytes[typed_value + 3] = TYPE_STRING;
        bytes[typed_value + 4..typed_value + 8].copy_from_slice(&0_u32.to_le_bytes());

        assert!(matches!(
            parse_android_manifest(&bytes, Limits::safe()),
            Err(Failure::Unsupported(detail)) if detail.contains("codename")
        ));
    }
}
