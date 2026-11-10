// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded offline verification of IPA Mach-O `CodeDirectory` and CMS signatures.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::panic::{AssertUnwindSafe, catch_unwind};

use bcder::{ConstOid, Oid};
use cryptographic_message_syntax::SignedData;
use libarchive_oxide::Limits;
use libarchive_oxide::{ReaderEvent, SeekArchiveReader};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};
use subtle::ConstantTimeEq;

use crate::PackageFinding;
use crate::integrity::{EntryDigest, collect_entries};
use crate::jar_signature::{SignatureFailure, verify_cms};
use crate::verification::VerificationDimension;

const PROFILE: &str = "ipa";
const INFO_PLIST: &[u8] = b"Info.plist";
const CODE_RESOURCES: &[u8] = b"_CodeSignature/CodeResources";
const METADATA_FALLBACK: usize = 64 * 1024 * 1024;
const MAX_MACH_ARCHITECTURES: usize = 32;
const MAX_LOAD_COMMANDS: usize = 65_536;
const MAX_SIGNATURE_BLOBS: usize = 256;
const MAX_SPECIAL_SLOTS: usize = 65_536;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_INFOSLOT: u32 = 1;
const CSSLOT_REQUIREMENTS: u32 = 2;
const CSSLOT_RESOURCEDIR: u32 = 3;
const CSSLOT_ENTITLEMENTS: u32 = 5;
const CSSLOT_DER_ENTITLEMENTS: u32 = 7;
const CSSLOT_ALTERNATE_CODEDIRECTORIES: u32 = 0x1000;
const CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT: u32 = 0x1005;
const CSSLOT_SIGNATURE: u32 = 0x1_0000;
const OID_APPLE_HASH_AGILITY_V1: ConstOid = Oid(&[42, 134, 72, 134, 247, 99, 100, 9, 1]);
const OID_APPLE_HASH_AGILITY_V2: ConstOid = Oid(&[42, 134, 72, 134, 247, 99, 100, 9, 2]);
const OID_SHA1: &[u8] = &[43, 14, 3, 2, 26];
const OID_SHA256: &[u8] = &[96, 134, 72, 1, 101, 3, 4, 2, 1];
const OID_SHA384: &[u8] = &[96, 134, 72, 1, 101, 3, 4, 2, 2];

#[derive(Debug)]
pub(crate) struct IpaSignatureVerification {
    pub(crate) integrity: VerificationDimension,
    pub(crate) validity: VerificationDimension,
    pub(crate) signer_fingerprints: Vec<[u8; 32]>,
    pub(crate) findings: Vec<PackageFinding>,
}

#[derive(Debug)]
struct IpaVerificationOutcome {
    fingerprints: Vec<[u8; 32]>,
    present: bool,
    signature_failure: Option<SignatureFailure>,
}

#[derive(Debug)]
struct BundleDescriptor {
    base: Vec<u8>,
    info_path: Vec<u8>,
    executable_path: Vec<u8>,
    resources_path: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum Endian {
    Little,
    Big,
}

#[derive(Debug)]
struct MachSlice {
    offset: usize,
    size: usize,
    signature_offset: usize,
    signature_size: usize,
}

#[derive(Debug)]
struct MachLayout {
    slices: Vec<MachSlice>,
    signatures: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct CodePagePlan {
    start: usize,
    end: usize,
    page_size: usize,
    hash: CodeHash,
    expected: Vec<Vec<u8>>,
}

#[derive(Debug)]
struct CodePageState {
    plan: CodePagePlan,
    slot: usize,
    bytes_in_page: usize,
    processed: usize,
    hasher: PageHasher,
}

#[derive(Debug)]
enum PageHasher {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
}

#[derive(Debug)]
struct EmbeddedSignature<'a> {
    blobs: BTreeMap<u32, &'a [u8]>,
    code_directories: Vec<CodeDirectory<'a>>,
    primary: &'a [u8],
    cms: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CodeHash {
    Sha1,
    Sha256,
    Sha256Truncated,
    Sha384,
}

impl CodeHash {
    const fn size(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha256Truncated => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(bytes).to_vec(),
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha256Truncated => Sha256::digest(bytes)[..20].to_vec(),
            Self::Sha384 => Sha384::digest(bytes).to_vec(),
        }
    }
}

#[derive(Debug)]
struct CodeDirectory<'a> {
    raw: &'a [u8],
    hash_offset: usize,
    special_slots: usize,
    code_slots: usize,
    code_limit: usize,
    hash_size: usize,
    hash: CodeHash,
    page_exponent: u8,
}

pub(crate) fn verify_ipa_signature<R: Read + Seek>(
    mut reader: R,
    limits: Limits,
) -> IpaSignatureVerification {
    match verify_ipa_signature_inner(&mut reader, limits) {
        Ok(IpaVerificationOutcome {
            fingerprints,
            present: true,
            signature_failure: None,
        }) => IpaSignatureVerification {
            integrity: VerificationDimension::Verified,
            validity: VerificationDimension::Verified,
            signer_fingerprints: fingerprints,
            findings: Vec::new(),
        },
        Ok(IpaVerificationOutcome {
            fingerprints,
            present: true,
            signature_failure: Some(failure),
        }) => {
            let validity = if matches!(failure, SignatureFailure::Unsupported(_)) {
                VerificationDimension::Unsupported
            } else {
                VerificationDimension::Invalid
            };
            let code = failure.code();
            IpaSignatureVerification {
                integrity: VerificationDimension::Verified,
                validity,
                signer_fingerprints: fingerprints,
                findings: vec![PackageFinding::new(PROFILE, None, code, failure.detail())],
            }
        },
        Ok(IpaVerificationOutcome { present: false, .. }) => IpaSignatureVerification {
            integrity: VerificationDimension::NotEvaluated,
            validity: VerificationDimension::NotPresent,
            signer_fingerprints: Vec::new(),
            findings: Vec::new(),
        },
        Err(failure) => {
            let validity = if matches!(failure, SignatureFailure::Unsupported(_)) {
                VerificationDimension::Unsupported
            } else {
                VerificationDimension::Invalid
            };
            let code = failure.code();
            IpaSignatureVerification {
                integrity: validity,
                validity,
                signer_fingerprints: Vec::new(),
                findings: vec![PackageFinding::new(PROFILE, None, code, failure.detail())],
            }
        },
    }
}

fn verify_ipa_signature_inner<R: Read + Seek>(
    reader: &mut R,
    limits: Limits,
) -> Result<IpaVerificationOutcome, SignatureFailure> {
    let entries = collect_entries(&mut *reader, limits, |name| {
        ipa_info_path(name).is_some() || ipa_code_resources_path(name).is_some()
    })
    .map_err(collect_failure)?;
    let bundles = discover_bundles(&entries, limits)?;
    if bundles.is_empty() {
        return Ok(IpaVerificationOutcome {
            fingerprints: Vec::new(),
            present: false,
            signature_failure: None,
        });
    }

    let mut fingerprints = BTreeSet::new();
    let mut signature_failure = None;
    for bundle in &bundles {
        let info = unique_entry(&entries, &bundle.info_path, "Info.plist")?;
        let info_body = retained_body(info, "IPA Info.plist")?;
        let resources = optional_unique_entry(&entries, &bundle.resources_path)?;
        let resources_body = resources
            .map(|entry| retained_body(entry, "IPA CodeResources"))
            .transpose()?;

        let layout = read_mach_layout(reader, &bundle.executable_path, limits)?;
        let mut page_plans = Vec::new();
        for (slice, signature_bytes) in layout.slices.iter().zip(&layout.signatures) {
            if signature_bytes.len() != slice.signature_size {
                return Err(SignatureFailure::InvalidMetadata(
                    "captured Mach-O signature length is inconsistent".to_string(),
                ));
            }
            let embedded = parse_embedded_signature(signature_bytes, limits)?;
            for directory in &embedded.code_directories {
                page_plans.push(verify_code_directory_metadata(
                    slice,
                    directory,
                    &embedded.blobs,
                    info_body,
                    resources_body,
                )?);
            }
            match verify_cms(embedded.cms, embedded.primary, limits) {
                Ok(verified) => {
                    fingerprints.extend(verified);
                    if let Err(failure) =
                        verify_code_directory_hash_agility(embedded.cms, &embedded.code_directories)
                    {
                        signature_failure.get_or_insert(failure);
                    }
                },
                Err(failure) => {
                    signature_failure.get_or_insert(failure);
                },
            }
        }
        verify_code_pages(reader, &bundle.executable_path, page_plans, limits)?;

        let resources_body = resources_body.ok_or_else(|| {
            SignatureFailure::Mismatch(format!(
                "signed IPA bundle {} has no _CodeSignature/CodeResources resource envelope",
                String::from_utf8_lossy(&bundle.base)
            ))
        })?;
        verify_code_resources(bundle, resources_body, &entries)?;
    }

    Ok(IpaVerificationOutcome {
        fingerprints: fingerprints.into_iter().collect(),
        present: true,
        signature_failure,
    })
}

fn collect_failure(error: crate::integrity::CollectError) -> SignatureFailure {
    if error.resource_limit {
        SignatureFailure::ResourceLimit(error.detail)
    } else {
        SignatureFailure::InvalidMetadata(error.detail)
    }
}

fn discover_bundles(
    entries: &[EntryDigest],
    limits: Limits,
) -> Result<Vec<BundleDescriptor>, SignatureFailure> {
    let mut bundles = Vec::new();
    for entry in entries {
        let Some(base) = ipa_info_path(&entry.name) else {
            continue;
        };
        let body = retained_body(entry, "IPA Info.plist")?;
        let value = plist::Value::from_reader(Cursor::new(body)).map_err(|error| {
            SignatureFailure::InvalidMetadata(format!(
                "IPA {} is not a valid XML or binary property list: {error}",
                String::from_utf8_lossy(&entry.name)
            ))
        })?;
        let dictionary = value.as_dictionary().ok_or_else(|| {
            SignatureFailure::InvalidMetadata(format!(
                "IPA {} root is not a property-list dictionary",
                String::from_utf8_lossy(&entry.name)
            ))
        })?;
        let executable = dictionary
            .get("CFBundleExecutable")
            .and_then(plist::Value::as_string)
            .ok_or_else(|| {
                SignatureFailure::InvalidMetadata(format!(
                    "IPA {} has no string CFBundleExecutable",
                    String::from_utf8_lossy(&entry.name)
                ))
            })?
            .as_bytes();
        let path_limit = limits.path_bytes().unwrap_or(64 * 1024);
        if executable.is_empty()
            || executable.len() > path_limit
            || executable.contains(&b'/')
            || executable.contains(&b'\\')
            || executable.contains(&0)
            || executable == b"."
            || executable == b".."
        {
            return Err(SignatureFailure::InvalidMetadata(format!(
                "IPA {} has an unsafe CFBundleExecutable",
                String::from_utf8_lossy(&entry.name)
            )));
        }
        let mut executable_path = base.clone();
        executable_path.extend_from_slice(executable);
        let mut resources_path = base.clone();
        resources_path.extend_from_slice(CODE_RESOURCES);
        bundles.push(BundleDescriptor {
            base,
            info_path: entry.name.clone(),
            executable_path,
            resources_path,
        });
    }
    if bundles.len() > 1 {
        return Err(SignatureFailure::InvalidMetadata(format!(
            "IPA contains {} top-level application bundles; exactly one is supported",
            bundles.len()
        )));
    }
    Ok(bundles)
}

fn ipa_info_path(name: &[u8]) -> Option<Vec<u8>> {
    let rest = name.strip_prefix(b"Payload/")?;
    let split = rest.iter().position(|byte| *byte == b'/')?;
    let app = rest.get(..split)?;
    let tail = rest.get(split + 1..)?;
    if app.is_empty() || !app.ends_with(b".app") || tail != INFO_PLIST {
        return None;
    }
    Some(
        name.get(..name.len().checked_sub(INFO_PLIST.len())?)?
            .to_vec(),
    )
}

fn ipa_code_resources_path(name: &[u8]) -> Option<Vec<u8>> {
    let prefix_length = name.len().checked_sub(CODE_RESOURCES.len())?;
    let base = name.get(..prefix_length)?;
    let rest = base.strip_prefix(b"Payload/")?;
    let app = rest.strip_suffix(b"/")?;
    if app.is_empty() || app.contains(&b'/') || !app.ends_with(b".app") {
        return None;
    }
    Some(base.to_vec())
}

fn retained_body<'a>(entry: &'a EntryDigest, label: &str) -> Result<&'a [u8], SignatureFailure> {
    entry.metadata_body.as_deref().ok_or_else(|| {
        SignatureFailure::ResourceLimit(format!(
            "{label} {} was not retained inside the metadata budget",
            String::from_utf8_lossy(&entry.name)
        ))
    })
}

fn unique_entry<'a>(
    entries: &'a [EntryDigest],
    name: &[u8],
    label: &str,
) -> Result<&'a EntryDigest, SignatureFailure> {
    optional_unique_entry(entries, name)?.ok_or_else(|| {
        SignatureFailure::InvalidMetadata(format!(
            "IPA has no {label} {}",
            String::from_utf8_lossy(name)
        ))
    })
}

fn optional_unique_entry<'a>(
    entries: &'a [EntryDigest],
    name: &[u8],
) -> Result<Option<&'a EntryDigest>, SignatureFailure> {
    let mut matching = entries.iter().filter(|entry| entry.name == name);
    let first = matching.next();
    if matching.next().is_some() {
        return Err(SignatureFailure::InvalidMetadata(format!(
            "IPA repeats member {}",
            String::from_utf8_lossy(name)
        )));
    }
    Ok(first)
}

fn capture_entry_ranges<R: Read + Seek>(
    reader: &mut R,
    path: &[u8],
    ranges: &[(usize, usize)],
    limits: Limits,
) -> Result<(usize, Vec<Vec<u8>>), SignatureFailure> {
    let requested = ranges.iter().try_fold(0_usize, |total, (_, length)| {
        total.checked_add(*length).ok_or_else(|| {
            SignatureFailure::ResourceLimit("Mach-O capture size overflow".to_string())
        })
    })?;
    let metadata_limit = limits.metadata_bytes().unwrap_or(METADATA_FALLBACK);
    if requested > metadata_limit {
        return Err(SignatureFailure::ResourceLimit(format!(
            "Mach-O sparse metadata capture requires {requested} bytes, exceeding limit {metadata_limit}"
        )));
    }
    for (start, length) in ranges {
        start.checked_add(*length).ok_or_else(|| {
            SignatureFailure::ResourceLimit("Mach-O capture range overflow".to_string())
        })?;
    }

    reader.seek(SeekFrom::Start(0)).map_err(|error| {
        SignatureFailure::InvalidMetadata(format!(
            "cannot seek to re-read IPA executable metadata: {error}"
        ))
    })?;
    let mut archive = SeekArchiveReader::with_limits(&mut *reader, limits)
        .map_err(|error| SignatureFailure::InvalidMetadata(error.to_string()))?;
    let mut captured = ranges
        .iter()
        .map(|(_, length)| Vec::with_capacity(*length))
        .collect::<Vec<_>>();
    let mut current_target = false;
    let mut position = 0_usize;
    let mut target_length = None;
    loop {
        match archive
            .next_event()
            .map_err(|error| SignatureFailure::InvalidMetadata(error.to_string()))?
        {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => {
                current_target = metadata.path().as_bytes() == path;
                position = 0;
                if current_target && target_length.is_some() {
                    return Err(SignatureFailure::InvalidMetadata(format!(
                        "IPA repeats main executable {}",
                        String::from_utf8_lossy(path)
                    )));
                }
            },
            ReaderEvent::Data(bytes) => {
                if current_target {
                    let chunk_end = position.checked_add(bytes.len()).ok_or_else(|| {
                        SignatureFailure::ResourceLimit(
                            "IPA executable stream position overflow".to_string(),
                        )
                    })?;
                    for ((start, length), destination) in ranges.iter().zip(&mut captured) {
                        let range_end = start.checked_add(*length).ok_or_else(|| {
                            SignatureFailure::ResourceLimit(
                                "Mach-O capture range overflow".to_string(),
                            )
                        })?;
                        let overlap_start = position.max(*start);
                        let overlap_end = chunk_end.min(range_end);
                        if overlap_start < overlap_end {
                            destination.extend_from_slice(
                                &bytes[overlap_start - position..overlap_end - position],
                            );
                        }
                    }
                    position = chunk_end;
                }
            },
            ReaderEvent::EndEntry => {
                if current_target {
                    target_length = Some(position);
                    current_target = false;
                }
            },
            ReaderEvent::Done => break,
            _ => {
                return Err(SignatureFailure::InvalidMetadata(
                    "ZIP reader returned an unknown event while reading IPA executable".to_string(),
                ));
            },
        }
    }
    let target_length = target_length.ok_or_else(|| {
        SignatureFailure::InvalidMetadata(format!(
            "IPA has no main executable {}",
            String::from_utf8_lossy(path)
        ))
    })?;
    for ((start, length), body) in ranges.iter().zip(&captured) {
        if body.len() != *length {
            return Err(SignatureFailure::InvalidMetadata(format!(
                "Mach-O capture range {start}..{} exceeds executable length {target_length}",
                start.saturating_add(*length)
            )));
        }
    }
    Ok((target_length, captured))
}

#[allow(clippy::too_many_lines)] // Sparse passes keep attacker-controlled ranges validated in wire order.
fn read_mach_layout<R: Read + Seek>(
    reader: &mut R,
    path: &[u8],
    limits: Limits,
) -> Result<MachLayout, SignatureFailure> {
    let (executable_size, initial) = capture_entry_ranges(reader, path, &[(0, 8)], limits)?;
    let initial = &initial[0];
    let magic = initial.get(..4).ok_or_else(|| {
        SignatureFailure::InvalidMetadata("IPA executable has a truncated Mach-O magic".to_string())
    })?;

    let mut slice_ranges: Vec<(usize, usize)> = Vec::new();
    match magic {
        [0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe] => {
            slice_ranges.push((0, executable_size));
        },
        [0xca, 0xfe, 0xba, 0xbe | 0xbf] | [0xbe | 0xbf, 0xba, 0xfe, 0xca] => {
            let endian = if matches!(magic, [0xca, 0xfe, 0xba, 0xbe | 0xbf]) {
                Endian::Big
            } else {
                Endian::Little
            };
            let is_64 = matches!(magic, [0xca, 0xfe, 0xba, 0xbf] | [0xbf, 0xba, 0xfe, 0xca]);
            let count = usize::try_from(read_u32(initial, 4, endian)?).map_err(|_| {
                SignatureFailure::ResourceLimit(
                    "Mach-O architecture count does not fit usize".to_string(),
                )
            })?;
            let configured = limits.entries().unwrap_or(MAX_MACH_ARCHITECTURES as u64);
            if count == 0 || count > MAX_MACH_ARCHITECTURES || (count as u64) > configured {
                return Err(SignatureFailure::ResourceLimit(format!(
                    "universal Mach-O architecture count {count} exceeds the configured/fixed limit"
                )));
            }
            let record_size = if is_64 { 32 } else { 20 };
            let table_end = 8_usize
                .checked_add(count.checked_mul(record_size).ok_or_else(|| {
                    SignatureFailure::ResourceLimit(
                        "Mach-O architecture table size overflow".to_string(),
                    )
                })?)
                .ok_or_else(|| {
                    SignatureFailure::ResourceLimit(
                        "Mach-O architecture table offset overflow".to_string(),
                    )
                })?;
            let (_, table) = capture_entry_ranges(reader, path, &[(0, table_end)], limits)?;
            let table = &table[0];
            for index in 0..count {
                let record = 8 + index * record_size;
                let (offset, size) = if is_64 {
                    (
                        read_u64(table, record + 8, endian)?,
                        read_u64(table, record + 16, endian)?,
                    )
                } else {
                    (
                        u64::from(read_u32(table, record + 8, endian)?),
                        u64::from(read_u32(table, record + 12, endian)?),
                    )
                };
                let offset = usize::try_from(offset).map_err(|_| {
                    SignatureFailure::ResourceLimit(
                        "Mach-O slice offset does not fit usize".to_string(),
                    )
                })?;
                let size = usize::try_from(size).map_err(|_| {
                    SignatureFailure::ResourceLimit(
                        "Mach-O slice size does not fit usize".to_string(),
                    )
                })?;
                let end = offset.checked_add(size).ok_or_else(|| {
                    SignatureFailure::ResourceLimit("Mach-O slice range overflow".to_string())
                })?;
                if offset < table_end || size == 0 || end > executable_size {
                    return Err(SignatureFailure::InvalidMetadata(
                        "universal Mach-O architecture points outside the executable".to_string(),
                    ));
                }
                if slice_ranges.iter().any(|(start, previous_size)| {
                    let previous_end = start.saturating_add(*previous_size);
                    offset < previous_end && *start < end
                }) {
                    return Err(SignatureFailure::InvalidMetadata(
                        "universal Mach-O architecture ranges overlap".to_string(),
                    ));
                }
                slice_ranges.push((offset, size));
            }
        },
        _ => {
            return Err(SignatureFailure::InvalidMetadata(
                "IPA CFBundleExecutable is not a supported thin or universal Mach-O".to_string(),
            ));
        },
    }

    let header_ranges = slice_ranges
        .iter()
        .map(|(offset, _)| (*offset, 32))
        .collect::<Vec<_>>();
    let (_, headers) = capture_entry_ranges(reader, path, &header_ranges, limits)?;
    let mut command_ranges = Vec::with_capacity(headers.len());
    let mut slice_headers = Vec::with_capacity(headers.len());
    for ((offset, size), header) in slice_ranges.iter().zip(&headers) {
        let (endian, is_64) = thin_magic(header)?;
        let header_size: usize = if is_64 { 32 } else { 28 };
        let command_count = usize::try_from(read_u32(header, 16, endian)?).map_err(|_| {
            SignatureFailure::ResourceLimit("Mach-O command count does not fit usize".to_string())
        })?;
        let configured = limits.entries().unwrap_or(MAX_LOAD_COMMANDS as u64);
        if command_count > MAX_LOAD_COMMANDS || (command_count as u64) > configured {
            return Err(SignatureFailure::ResourceLimit(format!(
                "Mach-O load-command count {command_count} exceeds the configured/fixed limit"
            )));
        }
        let command_bytes = usize::try_from(read_u32(header, 20, endian)?).map_err(|_| {
            SignatureFailure::ResourceLimit(
                "Mach-O load-command size does not fit usize".to_string(),
            )
        })?;
        let commands_end = header_size.checked_add(command_bytes).ok_or_else(|| {
            SignatureFailure::ResourceLimit("Mach-O load-command range overflow".to_string())
        })?;
        if commands_end > *size {
            return Err(SignatureFailure::InvalidMetadata(
                "Mach-O load commands are truncated".to_string(),
            ));
        }
        command_ranges.push((
            offset.checked_add(header_size).ok_or_else(|| {
                SignatureFailure::ResourceLimit("Mach-O load-command offset overflow".to_string())
            })?,
            command_bytes,
        ));
        slice_headers.push((endian, header_size, command_count, command_bytes));
    }
    let (_, commands) = capture_entry_ranges(reader, path, &command_ranges, limits)?;

    let mut slices = Vec::with_capacity(slice_ranges.len());
    let mut signature_ranges = Vec::with_capacity(slice_ranges.len());
    for (((offset, size), (endian, header_size, command_count, command_bytes)), commands) in
        slice_ranges.iter().zip(&slice_headers).zip(&commands)
    {
        let mut cursor = 0_usize;
        let mut code_signature = None;
        for _ in 0..*command_count {
            let cmd = read_u32(commands, cursor, *endian)?;
            let cmd_size =
                usize::try_from(read_u32(commands, cursor + 4, *endian)?).map_err(|_| {
                    SignatureFailure::ResourceLimit(
                        "Mach-O command size does not fit usize".to_string(),
                    )
                })?;
            let command_end = cursor.checked_add(cmd_size).ok_or_else(|| {
                SignatureFailure::ResourceLimit("Mach-O command range overflow".to_string())
            })?;
            if cmd_size < 8 || command_end > *command_bytes {
                return Err(SignatureFailure::InvalidMetadata(
                    "Mach-O load command has an invalid size".to_string(),
                ));
            }
            if cmd == LC_CODE_SIGNATURE {
                if code_signature.is_some() || cmd_size < 16 {
                    return Err(SignatureFailure::InvalidMetadata(
                        "Mach-O must contain exactly one well-formed LC_CODE_SIGNATURE".to_string(),
                    ));
                }
                code_signature = Some((
                    usize::try_from(read_u32(commands, cursor + 8, *endian)?).map_err(|_| {
                        SignatureFailure::ResourceLimit(
                            "Mach-O signature offset does not fit usize".to_string(),
                        )
                    })?,
                    usize::try_from(read_u32(commands, cursor + 12, *endian)?).map_err(|_| {
                        SignatureFailure::ResourceLimit(
                            "Mach-O signature size does not fit usize".to_string(),
                        )
                    })?,
                ));
            }
            cursor = command_end;
        }
        if cursor != *command_bytes {
            return Err(SignatureFailure::InvalidMetadata(
                "Mach-O load-command count does not consume sizeofcmds".to_string(),
            ));
        }
        let (signature_offset, signature_size) = code_signature.ok_or_else(|| {
            SignatureFailure::InvalidMetadata("Mach-O has no LC_CODE_SIGNATURE".to_string())
        })?;
        let signature_end = signature_offset
            .checked_add(signature_size)
            .ok_or_else(|| {
                SignatureFailure::ResourceLimit("Mach-O signature range overflow".to_string())
            })?;
        if signature_size == 0
            || signature_offset < header_size.saturating_add(*command_bytes)
            || signature_end > *size
        {
            return Err(SignatureFailure::InvalidMetadata(
                "LC_CODE_SIGNATURE range is outside the Mach-O slice".to_string(),
            ));
        }
        let absolute = offset.checked_add(signature_offset).ok_or_else(|| {
            SignatureFailure::ResourceLimit("Mach-O signature offset overflow".to_string())
        })?;
        signature_ranges.push((absolute, signature_size));
        slices.push(MachSlice {
            offset: *offset,
            size: *size,
            signature_offset,
            signature_size,
        });
    }
    let (_, signatures) = capture_entry_ranges(reader, path, &signature_ranges, limits)?;
    Ok(MachLayout { slices, signatures })
}

fn thin_magic(data: &[u8]) -> Result<(Endian, bool), SignatureFailure> {
    match data.get(..4) {
        Some([0xfe, 0xed, 0xfa, 0xce]) => Ok((Endian::Big, false)),
        Some([0xce, 0xfa, 0xed, 0xfe]) => Ok((Endian::Little, false)),
        Some([0xfe, 0xed, 0xfa, 0xcf]) => Ok((Endian::Big, true)),
        Some([0xcf, 0xfa, 0xed, 0xfe]) => Ok((Endian::Little, true)),
        _ => Err(SignatureFailure::InvalidMetadata(
            "universal Mach-O contains a slice with an invalid magic".to_string(),
        )),
    }
}

#[allow(clippy::too_many_lines)] // One bounded SuperBlob walk keeps slot and range invariants adjacent.
fn parse_embedded_signature(
    data: &[u8],
    limits: Limits,
) -> Result<EmbeddedSignature<'_>, SignatureFailure> {
    if be_u32(data, 0)? != CSMAGIC_EMBEDDED_SIGNATURE {
        return Err(SignatureFailure::InvalidMetadata(
            "Mach-O signature is not an embedded-signature SuperBlob".to_string(),
        ));
    }
    let length = usize::try_from(be_u32(data, 4)?).map_err(|_| {
        SignatureFailure::ResourceLimit("Mach-O SuperBlob length does not fit usize".to_string())
    })?;
    if length < 12 || length > data.len() {
        return Err(SignatureFailure::InvalidMetadata(
            "Mach-O SuperBlob length is invalid".to_string(),
        ));
    }
    if data[length..].iter().any(|byte| *byte != 0) {
        return Err(SignatureFailure::InvalidMetadata(
            "Mach-O signature padding contains non-zero bytes".to_string(),
        ));
    }
    let superblob = &data[..length];
    let count = usize::try_from(be_u32(superblob, 8)?).map_err(|_| {
        SignatureFailure::ResourceLimit("Mach-O SuperBlob count does not fit usize".to_string())
    })?;
    let configured = limits.entries().unwrap_or(MAX_SIGNATURE_BLOBS as u64);
    if count == 0 || count > MAX_SIGNATURE_BLOBS || (count as u64) > configured {
        return Err(SignatureFailure::ResourceLimit(format!(
            "Mach-O signature blob count {count} exceeds the configured/fixed limit"
        )));
    }
    let index_end = 12_usize
        .checked_add(count.checked_mul(8).ok_or_else(|| {
            SignatureFailure::ResourceLimit("Mach-O SuperBlob index size overflow".to_string())
        })?)
        .ok_or_else(|| {
            SignatureFailure::ResourceLimit("Mach-O SuperBlob index offset overflow".to_string())
        })?;
    if index_end > length {
        return Err(SignatureFailure::InvalidMetadata(
            "Mach-O SuperBlob index is truncated".to_string(),
        ));
    }
    let mut blobs = BTreeMap::new();
    let mut ranges = Vec::with_capacity(count);
    for index in 0..count {
        let entry = 12 + index * 8;
        let slot = be_u32(superblob, entry)?;
        let offset = usize::try_from(be_u32(superblob, entry + 4)?).map_err(|_| {
            SignatureFailure::ResourceLimit("Mach-O blob offset does not fit usize".to_string())
        })?;
        if offset < index_end {
            return Err(SignatureFailure::InvalidMetadata(
                "Mach-O signature blob overlaps the SuperBlob index".to_string(),
            ));
        }
        let blob_length = usize::try_from(be_u32(superblob, offset + 4)?).map_err(|_| {
            SignatureFailure::ResourceLimit("Mach-O blob length does not fit usize".to_string())
        })?;
        let end = offset.checked_add(blob_length).ok_or_else(|| {
            SignatureFailure::ResourceLimit("Mach-O blob range overflow".to_string())
        })?;
        if blob_length < 8
            || end > length
            || ranges
                .iter()
                .any(|(start, previous_end)| offset < *previous_end && *start < end)
        {
            return Err(SignatureFailure::InvalidMetadata(
                "Mach-O signature blob has an invalid or overlapping range".to_string(),
            ));
        }
        let blob = &superblob[offset..end];
        if blobs.insert(slot, blob).is_some() {
            return Err(SignatureFailure::InvalidMetadata(format!(
                "Mach-O SuperBlob repeats slot {slot:#x}"
            )));
        }
        ranges.push((offset, end));
    }

    let primary = *blobs.get(&CSSLOT_CODEDIRECTORY).ok_or_else(|| {
        SignatureFailure::InvalidMetadata(
            "Mach-O signature has no primary CodeDirectory".to_string(),
        )
    })?;
    let signature_blob = *blobs.get(&CSSLOT_SIGNATURE).ok_or_else(|| {
        SignatureFailure::InvalidMetadata("Mach-O signature has no CMS signature slot".to_string())
    })?;
    if be_u32(signature_blob, 0)? != CSMAGIC_BLOBWRAPPER {
        return Err(SignatureFailure::InvalidMetadata(
            "Mach-O CMS slot is not a BlobWrapper".to_string(),
        ));
    }
    let cms = signature_blob.get(8..).ok_or_else(|| {
        SignatureFailure::InvalidMetadata("Mach-O CMS BlobWrapper is truncated".to_string())
    })?;

    let mut code_directories = Vec::new();
    code_directories.push(parse_code_directory(primary)?);
    let mut expected_slot = CSSLOT_ALTERNATE_CODEDIRECTORIES;
    while expected_slot < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT {
        let Some(blob) = blobs.get(&expected_slot) else {
            if blobs
                .range(expected_slot + 1..CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT)
                .next()
                .is_some()
            {
                return Err(SignatureFailure::InvalidMetadata(
                    "Mach-O alternate CodeDirectory slots are not contiguous".to_string(),
                ));
            }
            break;
        };
        code_directories.push(parse_code_directory(blob)?);
        expected_slot += 1;
    }
    let distinct = code_directories
        .iter()
        .map(|directory| directory.hash)
        .collect::<BTreeSet<_>>();
    if distinct.len() != code_directories.len() {
        return Err(SignatureFailure::InvalidMetadata(
            "Mach-O repeats a CodeDirectory hash algorithm".to_string(),
        ));
    }
    Ok(EmbeddedSignature {
        blobs,
        code_directories,
        primary,
        cms,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmsDigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
}

fn verify_code_directory_hash_agility(
    cms: &[u8],
    directories: &[CodeDirectory<'_>],
) -> Result<(), SignatureFailure> {
    let signed = catch_unwind(AssertUnwindSafe(|| SignedData::parse_ber(cms)))
        .map_err(|_| {
            SignatureFailure::InvalidMetadata(
                "Apple CMS parser panicked while reading hash-agility attributes".to_string(),
            )
        })?
        .map_err(|error| {
            SignatureFailure::InvalidMetadata(format!(
                "Apple CMS hash-agility attributes cannot be parsed: {error}"
            ))
        })?;
    let expected_v1 = directories
        .iter()
        .map(|directory| {
            let digest = directory.hash.digest(directory.raw);
            digest[..digest.len().min(20)].to_vec()
        })
        .collect::<Vec<_>>();
    let expected_v2 = directories
        .iter()
        .map(|directory| {
            let algorithm = match directory.hash {
                CodeHash::Sha1 => CmsDigestAlgorithm::Sha1,
                CodeHash::Sha256 | CodeHash::Sha256Truncated => CmsDigestAlgorithm::Sha256,
                CodeHash::Sha384 => CmsDigestAlgorithm::Sha384,
            };
            (algorithm, directory.hash.digest(directory.raw))
        })
        .collect::<Vec<_>>();

    for signer in signed.signers() {
        let attributes = signer.signed_attributes().ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "Apple CMS signer has no signed attributes".to_string(),
            )
        })?;
        let v1 = attributes
            .attributes()
            .iter()
            .filter(|attribute| attribute.typ == OID_APPLE_HASH_AGILITY_V1)
            .collect::<Vec<_>>();
        let v2 = attributes
            .attributes()
            .iter()
            .filter(|attribute| attribute.typ == OID_APPLE_HASH_AGILITY_V2)
            .collect::<Vec<_>>();
        if v1.len() > 1 || v2.len() > 1 {
            return Err(SignatureFailure::InvalidMetadata(
                "Apple CMS repeats a CodeDirectory hash-agility attribute".to_string(),
            ));
        }
        if directories.len() > 1 && v1.is_empty() && v2.is_empty() {
            return Err(SignatureFailure::Mismatch(
                "alternate CodeDirectories are not bound by a signed CMS hash-agility attribute"
                    .to_string(),
            ));
        }
        if let Some(attribute) = v1.first() {
            verify_hash_agility_v1(attribute.values.as_slice(), &expected_v1)?;
        }
        if let Some(attribute) = v2.first() {
            verify_hash_agility_v2(attribute.values.as_slice(), &expected_v2)?;
        }
    }
    Ok(())
}

fn verify_hash_agility_v1(
    values: &[x509_certificate::rfc5652::AttributeValue],
    expected: &[Vec<u8>],
) -> Result<(), SignatureFailure> {
    let [value] = values else {
        return Err(SignatureFailure::InvalidMetadata(
            "Apple CMS hash-agility v1 must contain exactly one value".to_string(),
        ));
    };
    let (tag, plist_bytes, end) = der_element(value.as_slice(), 0)?;
    if tag != 0x04 || end != value.as_slice().len() {
        return Err(SignatureFailure::InvalidMetadata(
            "Apple CMS hash-agility v1 value is not one DER octet string".to_string(),
        ));
    }
    let plist = plist::Value::from_reader(Cursor::new(plist_bytes)).map_err(|error| {
        SignatureFailure::InvalidMetadata(format!(
            "Apple CMS hash-agility v1 plist is invalid: {error}"
        ))
    })?;
    let hashes = plist
        .as_dictionary()
        .and_then(|dictionary| dictionary.get("cdhashes"))
        .and_then(plist::Value::as_array)
        .ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "Apple CMS hash-agility v1 plist has no cdhashes array".to_string(),
            )
        })?;
    if hashes.len() != expected.len() {
        return Err(SignatureFailure::Mismatch(format!(
            "Apple CMS hash-agility v1 seals {} CodeDirectories but {} are present",
            hashes.len(),
            expected.len()
        )));
    }
    for (actual, expected) in hashes.iter().zip(expected) {
        let actual = actual.as_data().ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "Apple CMS hash-agility v1 cdhash is not plist data".to_string(),
            )
        })?;
        compare_hash("Apple CMS hash-agility v1 CodeDirectory", actual, expected)?;
    }
    Ok(())
}

fn verify_hash_agility_v2(
    values: &[x509_certificate::rfc5652::AttributeValue],
    expected: &[(CmsDigestAlgorithm, Vec<u8>)],
) -> Result<(), SignatureFailure> {
    let mut actual = Vec::new();
    for value in values {
        let mut cursor = 0_usize;
        while cursor < value.as_slice().len() {
            let (algorithm, digest, end) = parse_hash_agility_v2_value(value.as_slice(), cursor)?;
            actual.push((algorithm, digest));
            cursor = end;
        }
    }
    if actual.len() != expected.len() {
        return Err(SignatureFailure::Mismatch(format!(
            "Apple CMS hash-agility v2 seals {} CodeDirectories but {} are present",
            actual.len(),
            expected.len()
        )));
    }
    let mut remaining = expected.to_vec();
    for (algorithm, digest) in actual {
        let Some(index) = remaining
            .iter()
            .position(|(expected_algorithm, expected_digest)| {
                *expected_algorithm == algorithm
                    && expected_digest.len() == digest.len()
                    && bool::from(expected_digest.as_slice().ct_eq(digest))
            })
        else {
            return Err(SignatureFailure::Mismatch(
                "Apple CMS hash-agility v2 CodeDirectory digest does not match".to_string(),
            ));
        };
        remaining.remove(index);
    }
    Ok(())
}

fn parse_hash_agility_v2_value(
    value: &[u8],
    offset: usize,
) -> Result<(CmsDigestAlgorithm, &[u8], usize), SignatureFailure> {
    let (outer_tag, outer, outer_end) = der_element(value, offset)?;
    if outer_tag != 0x30 {
        return Err(SignatureFailure::InvalidMetadata(
            "Apple CMS hash-agility v2 value contains a non-sequence".to_string(),
        ));
    }
    let (oid_tag, oid, algorithm_end) = der_element(outer, 0)?;
    if oid_tag != 0x06 {
        return Err(SignatureFailure::InvalidMetadata(
            "Apple CMS hash-agility v2 sequence has no digest OID".to_string(),
        ));
    }
    let algorithm = match oid {
        OID_SHA1 => CmsDigestAlgorithm::Sha1,
        OID_SHA256 => CmsDigestAlgorithm::Sha256,
        OID_SHA384 => CmsDigestAlgorithm::Sha384,
        _ => {
            return Err(SignatureFailure::Unsupported(
                "Apple CMS hash-agility v2 uses an unsupported digest algorithm".to_string(),
            ));
        },
    };
    let (digest_tag, digest, digest_end) = der_element(outer, algorithm_end)?;
    if digest_tag != 0x04 || digest_end != outer.len() {
        return Err(SignatureFailure::InvalidMetadata(
            "Apple CMS hash-agility v2 digest is not one DER octet string".to_string(),
        ));
    }
    Ok((algorithm, digest, outer_end))
}

fn der_element(data: &[u8], offset: usize) -> Result<(u8, &[u8], usize), SignatureFailure> {
    let tag = *data.get(offset).ok_or_else(|| {
        SignatureFailure::InvalidMetadata(
            "Apple CMS hash-agility DER element is truncated".to_string(),
        )
    })?;
    let first_length = *data.get(offset + 1).ok_or_else(|| {
        SignatureFailure::InvalidMetadata(
            "Apple CMS hash-agility DER length is truncated".to_string(),
        )
    })?;
    let (header, length) = if first_length & 0x80 == 0 {
        (2_usize, usize::from(first_length))
    } else {
        let count = usize::from(first_length & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err(SignatureFailure::InvalidMetadata(
                "Apple CMS hash-agility DER uses an invalid length".to_string(),
            ));
        }
        let length_bytes = data.get(offset + 2..offset + 2 + count).ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "Apple CMS hash-agility DER long length is truncated".to_string(),
            )
        })?;
        if length_bytes[0] == 0 {
            return Err(SignatureFailure::InvalidMetadata(
                "Apple CMS hash-agility DER length is not minimal".to_string(),
            ));
        }
        let mut length = 0_usize;
        for byte in length_bytes {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| {
                    SignatureFailure::ResourceLimit(
                        "Apple CMS hash-agility DER length overflows".to_string(),
                    )
                })?;
        }
        if length < 128 {
            return Err(SignatureFailure::InvalidMetadata(
                "Apple CMS hash-agility DER length is not minimal".to_string(),
            ));
        }
        (2 + count, length)
    };
    let content_start = offset.checked_add(header).ok_or_else(|| {
        SignatureFailure::ResourceLimit(
            "Apple CMS hash-agility DER content offset overflows".to_string(),
        )
    })?;
    let end = content_start.checked_add(length).ok_or_else(|| {
        SignatureFailure::ResourceLimit(
            "Apple CMS hash-agility DER element length overflows".to_string(),
        )
    })?;
    let content = data.get(content_start..end).ok_or_else(|| {
        SignatureFailure::InvalidMetadata(
            "Apple CMS hash-agility DER element exceeds its value".to_string(),
        )
    })?;
    Ok((tag, content, end))
}

#[allow(clippy::too_many_lines)] // Fixed versioned fields and hash-array bounds are validated together.
fn parse_code_directory(blob: &[u8]) -> Result<CodeDirectory<'_>, SignatureFailure> {
    if be_u32(blob, 0)? != CSMAGIC_CODEDIRECTORY {
        return Err(SignatureFailure::InvalidMetadata(
            "CodeDirectory slot has the wrong blob magic".to_string(),
        ));
    }
    let length = usize::try_from(be_u32(blob, 4)?).map_err(|_| {
        SignatureFailure::ResourceLimit("CodeDirectory length does not fit usize".to_string())
    })?;
    if length != blob.len() || length < 44 {
        return Err(SignatureFailure::InvalidMetadata(
            "CodeDirectory length is inconsistent".to_string(),
        ));
    }
    let version = be_u32(blob, 8)?;
    if !(0x0002_0001..0x0002_f000).contains(&version) {
        return Err(SignatureFailure::Unsupported(format!(
            "CodeDirectory version {version:#x} is outside the supported compatibility range"
        )));
    }
    let fixed = if version >= 0x20600 {
        108
    } else if version >= 0x20500 {
        96
    } else if version >= 0x20400 {
        88
    } else if version >= 0x20300 {
        64
    } else if version >= 0x20200 {
        52
    } else if version >= 0x20100 {
        48
    } else {
        44
    };
    if length < fixed {
        return Err(SignatureFailure::InvalidMetadata(
            "CodeDirectory is truncated for its declared version".to_string(),
        ));
    }
    let hash_offset = usize::try_from(be_u32(blob, 16)?).map_err(|_| {
        SignatureFailure::ResourceLimit("CodeDirectory hash offset does not fit usize".to_string())
    })?;
    let identifier_offset = usize::try_from(be_u32(blob, 20)?).map_err(|_| {
        SignatureFailure::ResourceLimit(
            "CodeDirectory identifier offset does not fit usize".to_string(),
        )
    })?;
    let special_slots = usize::try_from(be_u32(blob, 24)?).map_err(|_| {
        SignatureFailure::ResourceLimit(
            "CodeDirectory special-slot count does not fit usize".to_string(),
        )
    })?;
    let code_slots = usize::try_from(be_u32(blob, 28)?).map_err(|_| {
        SignatureFailure::ResourceLimit(
            "CodeDirectory code-slot count does not fit usize".to_string(),
        )
    })?;
    let mut code_limit = u64::from(be_u32(blob, 32)?);
    let hash_size = usize::from(*blob.get(36).ok_or_else(|| {
        SignatureFailure::InvalidMetadata("CodeDirectory hash size is truncated".to_string())
    })?);
    let hash_type = *blob.get(37).ok_or_else(|| {
        SignatureFailure::InvalidMetadata("CodeDirectory hash type is truncated".to_string())
    })?;
    let page_exponent = *blob.get(39).ok_or_else(|| {
        SignatureFailure::InvalidMetadata("CodeDirectory page size is truncated".to_string())
    })?;
    if version >= 0x20300 {
        let code_limit64 = be_u64(blob, 56)?;
        if code_limit64 != 0 {
            code_limit = code_limit64;
        }
    }
    let code_limit = usize::try_from(code_limit).map_err(|_| {
        SignatureFailure::ResourceLimit(
            "CodeDirectory signing limit does not fit usize".to_string(),
        )
    })?;
    let hash = match hash_type {
        1 => CodeHash::Sha1,
        2 => CodeHash::Sha256,
        3 => CodeHash::Sha256Truncated,
        4 => CodeHash::Sha384,
        _ => {
            return Err(SignatureFailure::Unsupported(format!(
                "CodeDirectory hash type {hash_type} is unsupported"
            )));
        },
    };
    if hash_size != hash.size() {
        return Err(SignatureFailure::InvalidMetadata(
            "CodeDirectory hash size disagrees with its hash type".to_string(),
        ));
    }
    if special_slots > MAX_SPECIAL_SLOTS {
        return Err(SignatureFailure::ResourceLimit(format!(
            "CodeDirectory special-slot count {special_slots} exceeds fixed limit {MAX_SPECIAL_SLOTS}"
        )));
    }
    let hashes_before = special_slots.checked_mul(hash_size).ok_or_else(|| {
        SignatureFailure::ResourceLimit("CodeDirectory special hash bytes overflow".to_string())
    })?;
    let hashes_after = code_slots.checked_mul(hash_size).ok_or_else(|| {
        SignatureFailure::ResourceLimit("CodeDirectory code hash bytes overflow".to_string())
    })?;
    let hash_start = hash_offset.checked_sub(hashes_before).ok_or_else(|| {
        SignatureFailure::InvalidMetadata(
            "CodeDirectory special hashes begin before the blob".to_string(),
        )
    })?;
    let hash_end = hash_offset.checked_add(hashes_after).ok_or_else(|| {
        SignatureFailure::ResourceLimit("CodeDirectory hash range overflow".to_string())
    })?;
    if hash_start < fixed || hash_end > length {
        return Err(SignatureFailure::InvalidMetadata(
            "CodeDirectory hash array lies outside the blob".to_string(),
        ));
    }
    if identifier_offset < fixed
        || identifier_offset >= length
        || !blob[identifier_offset..].contains(&0)
    {
        return Err(SignatureFailure::InvalidMetadata(
            "CodeDirectory identifier string lies outside the blob".to_string(),
        ));
    }
    if version >= 0x20100 && be_u32(blob, 44)? != 0 {
        return Err(SignatureFailure::Unsupported(
            "CodeDirectory scatter vectors are not supported by the IPA verifier".to_string(),
        ));
    }
    let expected_slots = if code_limit == 0 {
        0
    } else if page_exponent == 0 {
        1
    } else {
        if u32::from(page_exponent) >= usize::BITS {
            return Err(SignatureFailure::ResourceLimit(
                "CodeDirectory page exponent does not fit address space".to_string(),
            ));
        }
        let page_size = 1_usize << page_exponent;
        code_limit.checked_add(page_size - 1).ok_or_else(|| {
            SignatureFailure::ResourceLimit("CodeDirectory page count overflow".to_string())
        })? / page_size
    };
    if expected_slots != code_slots {
        return Err(SignatureFailure::InvalidMetadata(format!(
            "CodeDirectory declares {code_slots} code slots but signing limit requires {expected_slots}"
        )));
    }
    Ok(CodeDirectory {
        raw: blob,
        hash_offset,
        special_slots,
        code_slots,
        code_limit,
        hash_size,
        hash,
        page_exponent,
    })
}

fn verify_code_directory_metadata(
    slice: &MachSlice,
    directory: &CodeDirectory<'_>,
    blobs: &BTreeMap<u32, &[u8]>,
    info: &[u8],
    resources: Option<&[u8]>,
) -> Result<CodePagePlan, SignatureFailure> {
    if directory.code_limit != slice.signature_offset {
        return Err(SignatureFailure::Mismatch(format!(
            "CodeDirectory signing limit {} does not end at LC_CODE_SIGNATURE offset {}",
            directory.code_limit, slice.signature_offset
        )));
    }
    if directory.code_limit > slice.size {
        return Err(SignatureFailure::InvalidMetadata(
            "CodeDirectory signing limit exceeds its Mach-O architecture".to_string(),
        ));
    }
    let start = slice.offset;
    let end = start.checked_add(directory.code_limit).ok_or_else(|| {
        SignatureFailure::ResourceLimit("CodeDirectory signed range overflow".to_string())
    })?;
    let page_size = if directory.page_exponent == 0 {
        directory.code_limit.max(1)
    } else {
        1_usize << directory.page_exponent
    };
    let expected = (0..directory.code_slots)
        .map(|slot| directory.code_slot(slot).map(<[u8]>::to_vec))
        .collect::<Result<Vec<_>, _>>()?;

    for slot in 1..=directory.special_slots {
        let expected = directory.special_slot(slot)?;
        let present = expected.iter().any(|byte| *byte != 0);
        let slot_number = u32::try_from(slot).map_err(|_| {
            SignatureFailure::ResourceLimit(
                "CodeDirectory special-slot number does not fit u32".to_string(),
            )
        })?;
        let component = match Some(slot_number) {
            Some(CSSLOT_INFOSLOT) => Some(info),
            Some(CSSLOT_RESOURCEDIR) => resources,
            Some(CSSLOT_REQUIREMENTS | CSSLOT_ENTITLEMENTS | CSSLOT_DER_ENTITLEMENTS) => {
                blobs.get(&slot_number).copied()
            },
            Some(4 | 8 | 9 | 10 | 11) => blobs.get(&slot_number).copied(),
            _ => None,
        };
        match (present, component) {
            (true, Some(bytes)) => compare_hash(
                "Mach-O special slot",
                expected,
                &directory.hash.digest(bytes),
            )?,
            (true, None) => {
                return Err(SignatureFailure::Mismatch(format!(
                    "CodeDirectory special slot {slot} is sealed but its component is absent or unsupported"
                )));
            },
            (false, Some(_)) => {
                return Err(SignatureFailure::Mismatch(format!(
                    "Mach-O signature carries unsealed component slot {slot}"
                )));
            },
            (false, None) => {},
        }
    }
    for (slot, blob) in blobs {
        if (1..32).contains(slot)
            && !matches!(
                *slot,
                CSSLOT_CODEDIRECTORY | CSSLOT_INFOSLOT | CSSLOT_RESOURCEDIR
            )
        {
            let slot_index = usize::try_from(*slot).map_err(|_| {
                SignatureFailure::ResourceLimit("Mach-O blob slot does not fit usize".to_string())
            })?;
            if slot_index > directory.special_slots
                || !directory
                    .special_slot(slot_index)?
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return Err(SignatureFailure::Mismatch(format!(
                    "Mach-O signature component slot {slot:#x} is not sealed by every CodeDirectory ({} bytes)",
                    blob.len()
                )));
            }
        }
    }
    Ok(CodePagePlan {
        start,
        end,
        page_size,
        hash: directory.hash,
        expected,
    })
}

impl PageHasher {
    fn new(hash: CodeHash) -> Self {
        match hash {
            CodeHash::Sha1 => Self::Sha1(Sha1::new()),
            CodeHash::Sha256 | CodeHash::Sha256Truncated => Self::Sha256(Sha256::new()),
            CodeHash::Sha384 => Self::Sha384(Sha384::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(hasher) => hasher.update(bytes),
            Self::Sha256(hasher) => hasher.update(bytes),
            Self::Sha384(hasher) => hasher.update(bytes),
        }
    }

    fn finish_reset(&mut self, hash: CodeHash) -> Vec<u8> {
        let previous = std::mem::replace(self, Self::new(hash));
        match previous {
            Self::Sha1(hasher) => hasher.finalize().to_vec(),
            Self::Sha256(hasher) => {
                let digest = hasher.finalize();
                if hash == CodeHash::Sha256Truncated {
                    digest[..20].to_vec()
                } else {
                    digest.to_vec()
                }
            },
            Self::Sha384(hasher) => hasher.finalize().to_vec(),
        }
    }
}

impl CodePageState {
    fn new(plan: CodePagePlan) -> Self {
        let hasher = PageHasher::new(plan.hash);
        Self {
            plan,
            slot: 0,
            bytes_in_page: 0,
            processed: 0,
            hasher,
        }
    }

    fn feed(&mut self, chunk_start: usize, bytes: &[u8]) -> Result<(), SignatureFailure> {
        let chunk_end = chunk_start.checked_add(bytes.len()).ok_or_else(|| {
            SignatureFailure::ResourceLimit("Mach-O stream chunk range overflow".to_string())
        })?;
        let overlap_start = chunk_start.max(self.plan.start);
        let overlap_end = chunk_end.min(self.plan.end);
        if overlap_start >= overlap_end {
            return Ok(());
        }
        let mut remaining = &bytes[overlap_start - chunk_start..overlap_end - chunk_start];
        while !remaining.is_empty() {
            let page_remaining = self
                .plan
                .page_size
                .checked_sub(self.bytes_in_page)
                .ok_or_else(|| {
                    SignatureFailure::InvalidMetadata(
                        "Mach-O code page accounting is inconsistent".to_string(),
                    )
                })?;
            let take = page_remaining.min(remaining.len());
            self.hasher.update(&remaining[..take]);
            self.bytes_in_page += take;
            self.processed = self.processed.checked_add(take).ok_or_else(|| {
                SignatureFailure::ResourceLimit("Mach-O hashed byte count overflow".to_string())
            })?;
            remaining = &remaining[take..];
            if self.bytes_in_page == self.plan.page_size
                || self.plan.start.saturating_add(self.processed) == self.plan.end
            {
                let expected = self.plan.expected.get(self.slot).ok_or_else(|| {
                    SignatureFailure::InvalidMetadata(
                        "CodeDirectory has too few code-slot hashes".to_string(),
                    )
                })?;
                let actual = self.hasher.finish_reset(self.plan.hash);
                compare_hash("Mach-O code page", expected, &actual)?;
                self.slot += 1;
                self.bytes_in_page = 0;
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<(), SignatureFailure> {
        let required = self.plan.end.checked_sub(self.plan.start).ok_or_else(|| {
            SignatureFailure::InvalidMetadata("Mach-O signed range is inverted".to_string())
        })?;
        if self.processed != required
            || self.bytes_in_page != 0
            || self.slot != self.plan.expected.len()
        {
            return Err(SignatureFailure::InvalidMetadata(
                "CodeDirectory signed bytes are truncated or its page hashes are incomplete"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

fn verify_code_pages<R: Read + Seek>(
    reader: &mut R,
    path: &[u8],
    plans: Vec<CodePagePlan>,
    limits: Limits,
) -> Result<(), SignatureFailure> {
    let mut states = plans
        .into_iter()
        .map(CodePageState::new)
        .collect::<Vec<_>>();
    reader.seek(SeekFrom::Start(0)).map_err(|error| {
        SignatureFailure::InvalidMetadata(format!(
            "cannot seek to stream IPA executable code pages: {error}"
        ))
    })?;
    let mut archive = SeekArchiveReader::with_limits(&mut *reader, limits)
        .map_err(|error| SignatureFailure::InvalidMetadata(error.to_string()))?;
    let mut current_target = false;
    let mut seen = false;
    let mut position = 0_usize;
    loop {
        match archive
            .next_event()
            .map_err(|error| SignatureFailure::InvalidMetadata(error.to_string()))?
        {
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Entry(metadata) => {
                current_target = metadata.path().as_bytes() == path;
                position = 0;
                if current_target {
                    if seen {
                        return Err(SignatureFailure::InvalidMetadata(format!(
                            "IPA repeats main executable {}",
                            String::from_utf8_lossy(path)
                        )));
                    }
                    seen = true;
                }
            },
            ReaderEvent::Data(bytes) => {
                if current_target {
                    for state in &mut states {
                        state.feed(position, bytes)?;
                    }
                    position = position.checked_add(bytes.len()).ok_or_else(|| {
                        SignatureFailure::ResourceLimit(
                            "IPA executable stream position overflow".to_string(),
                        )
                    })?;
                }
            },
            ReaderEvent::EndEntry => current_target = false,
            ReaderEvent::Done => break,
            _ => {
                return Err(SignatureFailure::InvalidMetadata(
                    "ZIP reader returned an unknown event while hashing IPA executable".to_string(),
                ));
            },
        }
    }
    if !seen {
        return Err(SignatureFailure::InvalidMetadata(format!(
            "IPA has no main executable {}",
            String::from_utf8_lossy(path)
        )));
    }
    for state in states {
        state.finish()?;
    }
    Ok(())
}

impl CodeDirectory<'_> {
    fn code_slot(&self, slot: usize) -> Result<&[u8], SignatureFailure> {
        if slot >= self.code_slots {
            return Err(SignatureFailure::InvalidMetadata(
                "CodeDirectory code-slot index is out of bounds".to_string(),
            ));
        }
        let start = self
            .hash_offset
            .checked_add(slot.checked_mul(self.hash_size).ok_or_else(|| {
                SignatureFailure::ResourceLimit(
                    "CodeDirectory code-slot offset overflow".to_string(),
                )
            })?)
            .ok_or_else(|| {
                SignatureFailure::ResourceLimit(
                    "CodeDirectory code-slot offset overflow".to_string(),
                )
            })?;
        self.raw.get(start..start + self.hash_size).ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "CodeDirectory code-slot bytes are truncated".to_string(),
            )
        })
    }

    fn special_slot(&self, slot: usize) -> Result<&[u8], SignatureFailure> {
        if slot == 0 || slot > self.special_slots {
            return Err(SignatureFailure::InvalidMetadata(
                "CodeDirectory special-slot index is out of bounds".to_string(),
            ));
        }
        let distance = slot.checked_mul(self.hash_size).ok_or_else(|| {
            SignatureFailure::ResourceLimit(
                "CodeDirectory special-slot offset overflow".to_string(),
            )
        })?;
        let start = self.hash_offset.checked_sub(distance).ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "CodeDirectory special-slot begins before the blob".to_string(),
            )
        })?;
        self.raw.get(start..start + self.hash_size).ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "CodeDirectory special-slot bytes are truncated".to_string(),
            )
        })
    }
}

fn verify_code_resources(
    bundle: &BundleDescriptor,
    body: &[u8],
    entries: &[EntryDigest],
) -> Result<(), SignatureFailure> {
    let value = plist::Value::from_reader(Cursor::new(body)).map_err(|error| {
        SignatureFailure::InvalidMetadata(format!(
            "IPA CodeResources is not a valid XML or binary property list: {error}"
        ))
    })?;
    let root = value.as_dictionary().ok_or_else(|| {
        SignatureFailure::InvalidMetadata("IPA CodeResources root is not a dictionary".to_string())
    })?;
    let files2 = root
        .get("files2")
        .and_then(plist::Value::as_dictionary)
        .ok_or_else(|| {
            SignatureFailure::InvalidMetadata(
                "IPA CodeResources has no files2 dictionary".to_string(),
            )
        })?;
    let mut covered = BTreeSet::new();
    for (relative, value) in files2 {
        let relative_bytes = relative.as_bytes();
        if !safe_relative_resource(relative_bytes) {
            return Err(SignatureFailure::InvalidMetadata(format!(
                "IPA CodeResources contains unsafe path {relative:?}"
            )));
        }
        let record = value.as_dictionary().ok_or_else(|| {
            SignatureFailure::InvalidMetadata(format!(
                "IPA CodeResources files2 entry {relative:?} is not a dictionary"
            ))
        })?;
        let optional = record
            .get("optional")
            .and_then(plist::Value::as_boolean)
            .unwrap_or(false);
        if record.contains_key("symlink")
            || record.contains_key("cdhash")
            || record.contains_key("requirement")
        {
            return Err(SignatureFailure::Unsupported(format!(
                "IPA CodeResources entry {relative:?} uses nested-code or symlink sealing that is not yet supported"
            )));
        }
        let mut full = bundle.base.clone();
        full.extend_from_slice(relative_bytes);
        let Some(entry) = optional_unique_entry(entries, &full)? else {
            if optional {
                continue;
            }
            return Err(SignatureFailure::Mismatch(format!(
                "IPA CodeResources requires missing member {}",
                String::from_utf8_lossy(&full)
            )));
        };
        let mut checked = false;
        if let Some(expected) = record.get("hash2").and_then(plist::Value::as_data) {
            compare_hash("IPA CodeResources SHA-256", expected, &entry.sha256)?;
            checked = true;
        }
        if let Some(expected) = record.get("hash").and_then(plist::Value::as_data) {
            compare_hash("IPA CodeResources SHA-1", expected, &entry.sha1)?;
            checked = true;
        }
        if !checked {
            return Err(SignatureFailure::InvalidMetadata(format!(
                "IPA CodeResources entry {relative:?} contains no supported digest"
            )));
        }
        covered.insert(relative_bytes.to_vec());
    }
    for entry in entries {
        let Some(relative) = entry.name.strip_prefix(bundle.base.as_slice()) else {
            continue;
        };
        if relative.is_empty()
            || relative.ends_with(b"/")
            || entry.name == bundle.info_path
            || entry.name == bundle.executable_path
            || entry.name == bundle.resources_path
            || relative == b"PkgInfo"
            || relative.starts_with(b"_CodeSignature/")
        {
            continue;
        }
        if !covered.contains(relative) {
            return Err(SignatureFailure::Mismatch(format!(
                "IPA resource {} is not sealed by CodeResources",
                String::from_utf8_lossy(&entry.name)
            )));
        }
    }
    Ok(())
}

fn safe_relative_resource(path: &[u8]) -> bool {
    !path.is_empty()
        && !path.starts_with(b"/")
        && !path.contains(&b'\\')
        && !path.contains(&0)
        && path
            .split(|byte| *byte == b'/')
            .all(|part| !matches!(part, b"" | b"." | b".."))
}

fn compare_hash(label: &str, expected: &[u8], actual: &[u8]) -> Result<(), SignatureFailure> {
    if expected.len() != actual.len() || !bool::from(expected.ct_eq(actual)) {
        return Err(SignatureFailure::Mismatch(format!(
            "{label} digest does not match"
        )));
    }
    Ok(())
}

fn read_u32(data: &[u8], offset: usize, endian: Endian) -> Result<u32, SignatureFailure> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or_else(|| {
            SignatureFailure::InvalidMetadata("Mach-O integer field is truncated".to_string())
        })?
        .try_into()
        .map_err(|_| {
            SignatureFailure::InvalidMetadata("Mach-O integer field is truncated".to_string())
        })?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(bytes),
        Endian::Big => u32::from_be_bytes(bytes),
    })
}

fn read_u64(data: &[u8], offset: usize, endian: Endian) -> Result<u64, SignatureFailure> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .ok_or_else(|| {
            SignatureFailure::InvalidMetadata("Mach-O integer field is truncated".to_string())
        })?
        .try_into()
        .map_err(|_| {
            SignatureFailure::InvalidMetadata("Mach-O integer field is truncated".to_string())
        })?;
    Ok(match endian {
        Endian::Little => u64::from_le_bytes(bytes),
        Endian::Big => u64::from_be_bytes(bytes),
    })
}

fn be_u32(data: &[u8], offset: usize) -> Result<u32, SignatureFailure> {
    read_u32(data, offset, Endian::Big)
}

fn be_u64(data: &[u8], offset: usize) -> Result<u64, SignatureFailure> {
    read_u64(data, offset, Endian::Big)
}
