// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded OS/app package validation: happy-path member and signature checks for
//! the Android APK, iOS IPA, and Windows MSIX profiles, plus adversarial archives
//! (traversal, duplicate paths, encryption, unsupported method, decompression
//! bomb) that must be refused without extraction. APK Signing Blocks are built by
//! hand and spliced in front of a hand-assembled central directory.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::io::Cursor;

use libarchive_oxide::libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, Limits};
use libarchive_oxide::{
    AppPackageProfile, AppPackageValidation, AppPackageValidator, ArchiveWriter,
    PackageFindingCode, ZipMethod,
};

/// APK Signature Scheme v2 block id.
const APK_V2_ID: u32 = 0x7109_871a;

/// APK Signature Scheme v3 block id.
const APK_V3_ID: u32 = 0xf053_68c0;

/// A single raw ZIP member: name, compression method, general-purpose flags,
/// and a stored body. The body is written uncompressed regardless of `method`,
/// so structural (no-extract) checks see the declared method.
struct RawEntry {
    name: &'static [u8],
    method: u16,
    flags: u16,
    body: Vec<u8>,
}

impl RawEntry {
    fn stored(name: &'static [u8], body: &[u8]) -> Self {
        Self {
            name,
            method: 0,
            flags: 0,
            body: body.to_vec(),
        }
    }
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

/// Assembles a minimal but standard ZIP file from raw members, optionally
/// splicing `extra_before_cd` (an APK Signing Block) between the last local entry
/// and the central directory. The central-directory offset in the EOCD is bumped
/// past the spliced bytes; local-header offsets in the CD records are unaffected
/// because they point at headers preceding the splice point.
fn build_zip(entries: &[RawEntry], extra_before_cd: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for entry in entries {
        offsets.push(out.len() as u32);
        out.extend_from_slice(b"PK\x03\x04");
        push_u16(&mut out, 20);
        push_u16(&mut out, entry.flags);
        push_u16(&mut out, entry.method);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0x21);
        push_u32(&mut out, 0);
        push_u32(&mut out, entry.body.len() as u32);
        push_u32(&mut out, entry.body.len() as u32);
        push_u16(&mut out, entry.name.len() as u16);
        push_u16(&mut out, 0);
        out.extend_from_slice(entry.name);
        out.extend_from_slice(&entry.body);
    }
    out.extend_from_slice(extra_before_cd);
    let central_offset = out.len() as u32;
    let mut central = Vec::new();
    for (entry, offset) in entries.iter().zip(offsets.iter()) {
        central.extend_from_slice(b"PK\x01\x02");
        push_u16(&mut central, 0x031e);
        push_u16(&mut central, 20);
        push_u16(&mut central, entry.flags);
        push_u16(&mut central, entry.method);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0x21);
        push_u32(&mut central, 0);
        push_u32(&mut central, entry.body.len() as u32);
        push_u32(&mut central, entry.body.len() as u32);
        push_u16(&mut central, entry.name.len() as u16);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u16(&mut central, 0);
        push_u32(&mut central, 0);
        push_u32(&mut central, *offset);
        central.extend_from_slice(entry.name);
    }
    let central_size = central.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    push_u16(&mut out, 0);
    push_u16(&mut out, 0);
    push_u16(&mut out, entries.len() as u16);
    push_u16(&mut out, entries.len() as u16);
    push_u32(&mut out, central_size);
    push_u32(&mut out, central_offset);
    push_u16(&mut out, 0);
    out
}

/// Builds an APK Signing Block from id-value pairs.
///
/// Layout: `[u64 block_size][pairs...][u64 block_size][magic]`, where each pair is
/// `[u64 pair_len][u32 id][value]` and `block_size` counts every byte after the
/// leading size field through the trailing 16-byte magic.
fn apk_sig_block(pairs: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut region = Vec::new();
    for (id, value) in pairs {
        let pair_len = (4 + value.len()) as u64;
        region.extend_from_slice(&pair_len.to_le_bytes());
        region.extend_from_slice(&id.to_le_bytes());
        region.extend_from_slice(value);
    }
    let block_size = (region.len() + 8 + 16) as u64;
    let mut block = Vec::new();
    block.extend_from_slice(&block_size.to_le_bytes());
    block.extend_from_slice(&region);
    block.extend_from_slice(&block_size.to_le_bytes());
    block.extend_from_slice(b"APK Sig Block 42");
    block
}

/// Builds a real deflate ZIP through the crate's own sequential writer, used to
/// confirm the validator interoperates with genuine central-directory output.
fn build_real_zip(members: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Deflate, Limits::safe());
    for (name, body) in members {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(*name))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start entry");
        if !body.is_empty() {
            writer.write_data(body).expect("write entry");
        }
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish zip")
}

fn validate(profile: AppPackageProfile, bytes: &[u8]) -> AppPackageValidation {
    AppPackageValidator::new(profile).validate(Cursor::new(bytes.to_vec()))
}

// ---------------------------------------------------------------------------
// APK: required member and signing-scheme detection.
// ---------------------------------------------------------------------------

#[test]
fn apk_v1_signed_reports_scheme_and_is_valid() {
    let bytes = build_zip(
        &[
            RawEntry::stored(b"AndroidManifest.xml", b"\x03\x00\x08\x00"),
            RawEntry::stored(b"classes.dex", b"dex\n035\x00"),
            RawEntry::stored(b"META-INF/CERT.SF", b"Signature-Version: 1.0\n"),
            RawEntry::stored(b"META-INF/CERT.RSA", b"\x30\x82"),
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Apk, &bytes);
    assert!(result.container_readable());
    assert!(result.profile_valid(), "{:?}", result.findings());
    assert!(result.signatures().apk_v1());
    assert!(!result.signatures().apk_v2());
    assert!(result.has_code(PackageFindingCode::SigningSchemeDetected));
}

#[test]
fn apk_v2_signing_block_is_detected() {
    let block = apk_sig_block(&[(APK_V2_ID, vec![0xAB; 32])]);
    let bytes = build_zip(
        &[
            RawEntry::stored(b"AndroidManifest.xml", b"\x03\x00\x08\x00"),
            RawEntry::stored(b"classes.dex", b"dex\n035\x00"),
        ],
        &block,
    );
    let result = validate(AppPackageProfile::Apk, &bytes);
    assert!(result.profile_valid(), "{:?}", result.findings());
    assert!(result.signatures().apk_signing_block());
    assert!(result.signatures().apk_v2());
    assert!(!result.signatures().apk_v3());
    assert!(result.has_code(PackageFindingCode::SigningSchemeDetected));
}

#[test]
fn apk_v3_signing_block_is_detected() {
    let block = apk_sig_block(&[(APK_V3_ID, vec![0xCD; 48])]);
    let bytes = build_zip(
        &[RawEntry::stored(
            b"AndroidManifest.xml",
            b"\x03\x00\x08\x00",
        )],
        &block,
    );
    let result = validate(AppPackageProfile::Apk, &bytes);
    assert!(result.profile_valid(), "{:?}", result.findings());
    assert!(result.signatures().apk_signing_block());
    assert!(result.signatures().apk_v3());
    assert!(!result.signatures().apk_v2());
}

#[test]
fn apk_v2_and_v3_both_detected() {
    let block = apk_sig_block(&[
        (APK_V2_ID, vec![0x01; 16]),
        (APK_V3_ID, vec![0x02; 16]),
        (0x1234_5678, vec![0x03; 8]),
    ]);
    let bytes = build_zip(
        &[RawEntry::stored(
            b"AndroidManifest.xml",
            b"\x03\x00\x08\x00",
        )],
        &block,
    );
    let result = validate(AppPackageProfile::Apk, &bytes);
    let signatures = result.signatures();
    assert!(signatures.apk_v2());
    assert!(signatures.apk_v3());
    assert!(signatures.any());
}

#[test]
fn apk_unsigned_reports_unsigned_but_stays_valid() {
    let bytes = build_zip(
        &[
            RawEntry::stored(b"AndroidManifest.xml", b"\x03\x00\x08\x00"),
            RawEntry::stored(b"classes.dex", b"dex\n035\x00"),
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Apk, &bytes);
    // No signature is informational: the profile is still structurally valid.
    assert!(result.profile_valid(), "{:?}", result.findings());
    assert!(!result.signatures().any());
    assert!(result.has_code(PackageFindingCode::UnsignedPackage));
}

#[test]
fn apk_without_manifest_is_rejected() {
    let bytes = build_zip(&[RawEntry::stored(b"classes.dex", b"dex\n035\x00")], &[]);
    let result = validate(AppPackageProfile::Apk, &bytes);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MissingRequiredMember));
}

#[test]
fn apk_v1_requires_both_sf_and_signature_file() {
    // A lone `.SF` with no `.RSA`/`.DSA`/`.EC` is not a complete v1 signature.
    let bytes = build_zip(
        &[
            RawEntry::stored(b"AndroidManifest.xml", b"\x03\x00\x08\x00"),
            RawEntry::stored(b"META-INF/CERT.SF", b"Signature-Version: 1.0\n"),
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Apk, &bytes);
    assert!(!result.signatures().apk_v1());
    assert!(result.has_code(PackageFindingCode::UnsignedPackage));
}

#[test]
fn apk_from_real_deflate_writer_is_valid() {
    let bytes = build_real_zip(&[
        (b"AndroidManifest.xml", b"binary xml here"),
        (b"classes.dex", b"dex payload"),
    ]);
    let result = validate(AppPackageProfile::Apk, &bytes);
    assert!(result.container_readable());
    assert!(result.profile_valid(), "{:?}", result.findings());
}

// ---------------------------------------------------------------------------
// IPA: Payload/<name>.app/Info.plist bundle.
// ---------------------------------------------------------------------------

#[test]
fn ipa_with_app_bundle_is_valid() {
    let bytes = build_zip(
        &[
            RawEntry::stored(b"Payload/Demo.app/Info.plist", b"<plist/>"),
            RawEntry::stored(b"Payload/Demo.app/Demo", b"\xca\xfe\xba\xbe"),
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Ipa, &bytes);
    assert!(result.profile_valid(), "{:?}", result.findings());
    // IPA carries no ZIP-level signature scheme.
    assert!(!result.signatures().any());
}

#[test]
fn ipa_without_app_bundle_is_rejected() {
    let bytes = build_zip(
        &[
            RawEntry::stored(b"Payload/Demo.app/Demo", b"\xca\xfe"),
            RawEntry::stored(b"README.txt", b"no plist here"),
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Ipa, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MissingRequiredMember));
}

#[test]
fn ipa_info_plist_outside_app_is_rejected() {
    // An `Info.plist` not directly inside a `Payload/<name>.app/` does not count.
    let bytes = build_zip(&[RawEntry::stored(b"Payload/Info.plist", b"<plist/>")], &[]);
    let result = validate(AppPackageProfile::Ipa, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MissingRequiredMember));
}

// ---------------------------------------------------------------------------
// MSIX: required members and AppxSignature.p7x.
// ---------------------------------------------------------------------------

#[test]
fn msix_signed_is_valid_and_reports_signature() {
    let bytes = build_zip(
        &[
            RawEntry::stored(b"AppxManifest.xml", b"<Package/>"),
            RawEntry::stored(b"[Content_Types].xml", b"<Types/>"),
            RawEntry::stored(b"AppxBlockMap.xml", b"<BlockMap/>"),
            RawEntry::stored(b"AppxSignature.p7x", b"PKCS7\x00"),
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Msix, &bytes);
    assert!(result.profile_valid(), "{:?}", result.findings());
    assert!(result.signatures().embedded_signature());
    assert!(result.has_code(PackageFindingCode::SigningSchemeDetected));
}

#[test]
fn msix_unsigned_is_valid_but_reports_unsigned() {
    let bytes = build_zip(
        &[
            RawEntry::stored(b"AppxManifest.xml", b"<Package/>"),
            RawEntry::stored(b"[Content_Types].xml", b"<Types/>"),
            RawEntry::stored(b"AppxBlockMap.xml", b"<BlockMap/>"),
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Msix, &bytes);
    assert!(result.profile_valid(), "{:?}", result.findings());
    assert!(!result.signatures().embedded_signature());
    assert!(result.has_code(PackageFindingCode::UnsignedPackage));
}

#[test]
fn msix_without_manifest_is_rejected() {
    let bytes = build_zip(
        &[
            RawEntry::stored(b"[Content_Types].xml", b"<Types/>"),
            RawEntry::stored(b"AppxBlockMap.xml", b"<BlockMap/>"),
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Msix, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MissingRequiredMember));
}

#[test]
fn msix_without_block_map_is_rejected() {
    let bytes = build_zip(
        &[
            RawEntry::stored(b"AppxManifest.xml", b"<Package/>"),
            RawEntry::stored(b"[Content_Types].xml", b"<Types/>"),
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Msix, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MissingRequiredMember));
}

// ---------------------------------------------------------------------------
// Shared ZIP-structure defenses (reused across every app profile).
// ---------------------------------------------------------------------------

#[test]
fn traversing_member_name_is_rejected() {
    let bytes = build_zip(
        &[
            RawEntry::stored(b"AndroidManifest.xml", b"\x03\x00\x08\x00"),
            RawEntry::stored(b"../escape.txt", b"nope"),
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Apk, &bytes);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::UnsafeEntryPath));
}

#[test]
fn duplicate_member_path_is_rejected() {
    let bytes = build_zip(
        &[
            RawEntry::stored(b"AndroidManifest.xml", b"\x03\x00\x08\x00"),
            RawEntry::stored(b"res/x", b"one"),
            RawEntry::stored(b"res/x", b"two"),
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Apk, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::DuplicateEntryPath));
}

#[test]
fn unsupported_method_is_reported() {
    let mut odd = RawEntry::stored(b"res/blob", b"body");
    odd.method = 14; // LZMA, which the no-extract validator cannot decode.
    let bytes = build_zip(
        &[
            RawEntry::stored(b"AndroidManifest.xml", b"\x03\x00\x08\x00"),
            odd,
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Apk, &bytes);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::UnsupportedCompression));
}

#[test]
fn encrypted_member_is_reported() {
    let mut secret = RawEntry::stored(b"res/secret", b"cipher");
    secret.flags = 0x0001; // traditional encryption bit.
    let bytes = build_zip(
        &[
            RawEntry::stored(b"AndroidManifest.xml", b"\x03\x00\x08\x00"),
            secret,
        ],
        &[],
    );
    let result = validate(AppPackageProfile::Apk, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::UnexpectedEncryption));
}

#[test]
fn decompression_bomb_is_refused_by_budget() {
    let bytes = build_zip(
        &[
            RawEntry::stored(b"AndroidManifest.xml", b"\x03\x00\x08\x00"),
            RawEntry::stored(b"assets/large", &vec![b'a'; 4096]),
        ],
        &[],
    );
    let validator =
        AppPackageValidator::apk().with_limits(Limits::safe().with_decoded_total(Some(64)));
    let result = validator.validate(Cursor::new(bytes));
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::DecompressionBomb));
}

#[test]
fn garbage_container_is_unreadable() {
    let bytes = vec![b'X'; 128];
    let result = validate(AppPackageProfile::Apk, &bytes);
    assert!(!result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::ContainerUnreadable));
}

#[test]
fn apk_signing_block_scan_is_bounded_by_metadata_budget() {
    // A signing block larger than the metadata budget is scanned only up to the
    // cap; the block is still detected via its magic, but a v2/v3 id sitting past
    // the cap is not reached. A large filler pair pushes the v2 id beyond a
    // 256-byte scan window (which still comfortably holds the tiny CD).
    let block = apk_sig_block(&[(0x1234_5678, vec![0x00; 4096]), (APK_V2_ID, vec![0xEE; 16])]);
    let bytes = build_zip(
        &[RawEntry::stored(
            b"AndroidManifest.xml",
            b"\x03\x00\x08\x00",
        )],
        &block,
    );
    let validator =
        AppPackageValidator::apk().with_limits(Limits::safe().with_metadata_bytes(Some(256)));
    let result = validator.validate(Cursor::new(bytes));
    assert!(result.container_readable(), "{:?}", result.findings());
    assert!(result.signatures().apk_signing_block());
    // The block is present and reported, but the v2 id is beyond the scan cap.
    assert!(!result.signatures().apk_v2());
    assert!(result.has_code(PackageFindingCode::SigningSchemeDetected));
}
