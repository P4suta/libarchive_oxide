// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded ZIP-container package validation: happy-path member checks for the
//! JAR, `NuGet`, wheel, and EPUB profiles plus a battery of adversarial archives
//! that must be refused without extraction.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use std::io::Cursor;

use libarchive_oxide::libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, Limits};
use libarchive_oxide::{
    ArchiveWriter, PackageFindingCode, ZipMethod, ZipPackageProfile, ZipPackageValidator,
};

/// A single raw ZIP member: name, compression method, general-purpose flags,
/// and a stored body. The body is written uncompressed regardless of `method`,
/// so structural (no-extract) checks see the declared method while EPUB body
/// reads still find the raw bytes for stored members.
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

/// Assembles a minimal but standard ZIP file from raw members, giving each test
/// exact control over names, order, methods, flags, and bodies.
fn build_zip(entries: &[RawEntry]) -> Vec<u8> {
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

fn validate(profile: ZipPackageProfile, bytes: &[u8]) -> libarchive_oxide::ZipPackageValidation {
    ZipPackageValidator::new(profile).validate(Cursor::new(bytes.to_vec()))
}

// ---------------------------------------------------------------------------
// Happy paths.
// ---------------------------------------------------------------------------

#[test]
fn jar_with_manifest_is_valid() {
    let bytes = build_zip(&[
        RawEntry::stored(b"META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        RawEntry::stored(b"com/example/Main.class", b"\xca\xfe\xba\xbe"),
    ]);
    let result = validate(ZipPackageProfile::Jar, &bytes);
    assert!(result.container_readable());
    assert!(result.profile_valid());
    assert!(result.findings().is_empty(), "{:?}", result.findings());
}

#[test]
fn jar_from_real_deflate_writer_is_valid() {
    let bytes = build_real_zip(&[
        (b"META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        (b"com/example/Main.class", b"payload bytes here"),
    ]);
    let result = validate(ZipPackageProfile::Jar, &bytes);
    assert!(result.container_readable());
    assert!(result.profile_valid(), "{:?}", result.findings());
}

#[test]
fn nuget_with_content_types_and_single_nuspec_is_valid() {
    let bytes = build_zip(&[
        RawEntry::stored(b"[Content_Types].xml", b"<Types/>"),
        RawEntry::stored(b"demo.nuspec", b"<package/>"),
        RawEntry::stored(b"lib/net8.0/demo.dll", b"MZ"),
    ]);
    let result = validate(ZipPackageProfile::NuGet, &bytes);
    assert!(result.profile_valid(), "{:?}", result.findings());
}

#[test]
fn wheel_with_dist_info_members_is_valid() {
    let bytes = build_zip(&[
        RawEntry::stored(b"demo-1.0.dist-info/METADATA", b"Name: demo\n"),
        RawEntry::stored(b"demo-1.0.dist-info/RECORD", b""),
        RawEntry::stored(b"demo-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
        RawEntry::stored(b"demo/__init__.py", b""),
    ]);
    let result = validate(ZipPackageProfile::Wheel, &bytes);
    assert!(result.profile_valid(), "{:?}", result.findings());
}

#[test]
fn epub_with_stored_first_mimetype_is_valid() {
    let bytes = build_zip(&[
        RawEntry::stored(b"mimetype", b"application/epub+zip"),
        RawEntry::stored(b"META-INF/container.xml", b"<container/>"),
        RawEntry::stored(b"OEBPS/content.opf", b"<package/>"),
    ]);
    let result = validate(ZipPackageProfile::Epub, &bytes);
    assert!(result.profile_valid(), "{:?}", result.findings());
    assert!(result.findings().is_empty(), "{:?}", result.findings());
}

// ---------------------------------------------------------------------------
// Missing required members.
// ---------------------------------------------------------------------------

#[test]
fn jar_without_manifest_is_rejected() {
    let bytes = build_zip(&[RawEntry::stored(b"com/example/Main.class", b"\xca\xfe")]);
    let result = validate(ZipPackageProfile::Jar, &bytes);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MissingRequiredMember));
}

#[test]
fn nuget_without_content_types_is_rejected() {
    let bytes = build_zip(&[RawEntry::stored(b"demo.nuspec", b"<package/>")]);
    let result = validate(ZipPackageProfile::NuGet, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MissingRequiredMember));
}

#[test]
fn nuget_with_two_root_nuspecs_is_rejected() {
    let bytes = build_zip(&[
        RawEntry::stored(b"[Content_Types].xml", b"<Types/>"),
        RawEntry::stored(b"first.nuspec", b"<package/>"),
        RawEntry::stored(b"second.nuspec", b"<package/>"),
    ]);
    let result = validate(ZipPackageProfile::NuGet, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::DuplicateMember));
}

#[test]
fn wheel_without_wheel_member_is_rejected() {
    let bytes = build_zip(&[
        RawEntry::stored(b"demo-1.0.dist-info/METADATA", b"Name: demo\n"),
        RawEntry::stored(b"demo-1.0.dist-info/RECORD", b""),
    ]);
    let result = validate(ZipPackageProfile::Wheel, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MissingRequiredMember));
}

#[test]
fn epub_without_container_is_rejected() {
    let bytes = build_zip(&[RawEntry::stored(b"mimetype", b"application/epub+zip")]);
    let result = validate(ZipPackageProfile::Epub, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MissingRequiredMember));
}

// ---------------------------------------------------------------------------
// EPUB structural constraints on the mimetype member.
// ---------------------------------------------------------------------------

#[test]
fn epub_mimetype_not_first_is_rejected() {
    let bytes = build_zip(&[
        RawEntry::stored(b"META-INF/container.xml", b"<container/>"),
        RawEntry::stored(b"mimetype", b"application/epub+zip"),
    ]);
    let result = validate(ZipPackageProfile::Epub, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MimetypeNotFirst));
}

#[test]
fn epub_mimetype_not_stored_is_rejected() {
    let mut mimetype = RawEntry::stored(b"mimetype", b"application/epub+zip");
    mimetype.method = 8; // deflate
    let bytes = build_zip(&[
        mimetype,
        RawEntry::stored(b"META-INF/container.xml", b"<container/>"),
    ]);
    let result = validate(ZipPackageProfile::Epub, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MimetypeNotStored));
}

#[test]
fn epub_mimetype_bad_body_is_rejected() {
    let bytes = build_zip(&[
        RawEntry::stored(b"mimetype", b"application/zip"),
        RawEntry::stored(b"META-INF/container.xml", b"<container/>"),
    ]);
    let result = validate(ZipPackageProfile::Epub, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::MimetypeInvalidContent));
}

// ---------------------------------------------------------------------------
// Shared ZIP-structure defenses.
// ---------------------------------------------------------------------------

#[test]
fn traversing_member_name_is_rejected() {
    let bytes = build_zip(&[
        RawEntry::stored(b"META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        RawEntry::stored(b"../escape.txt", b"nope"),
    ]);
    let result = validate(ZipPackageProfile::Jar, &bytes);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::UnsafeEntryPath));
}

#[test]
fn duplicate_member_path_is_rejected() {
    let bytes = build_zip(&[
        RawEntry::stored(b"META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        RawEntry::stored(b"data/x", b"one"),
        RawEntry::stored(b"data/x", b"two"),
    ]);
    let result = validate(ZipPackageProfile::Jar, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::DuplicateEntryPath));
}

#[test]
fn unsupported_method_is_reported() {
    let mut odd = RawEntry::stored(b"data/blob", b"body");
    odd.method = 14; // LZMA, which the no-extract validator cannot decode.
    let bytes = build_zip(&[
        RawEntry::stored(b"META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        odd,
    ]);
    let result = validate(ZipPackageProfile::Jar, &bytes);
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::UnsupportedCompression));
}

#[test]
fn encrypted_member_is_reported() {
    let mut secret = RawEntry::stored(b"data/secret", b"cipher");
    secret.flags = 0x0001; // traditional encryption bit.
    let bytes = build_zip(&[
        RawEntry::stored(b"META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        secret,
    ]);
    let result = validate(ZipPackageProfile::Jar, &bytes);
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::UnexpectedEncryption));
}

#[test]
fn decompression_bomb_is_refused_by_budget() {
    let bytes = build_zip(&[
        RawEntry::stored(b"META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        RawEntry::stored(b"data/large", &vec![b'a'; 4096]),
    ]);
    let validator =
        ZipPackageValidator::jar().with_limits(Limits::safe().with_decoded_total(Some(64)));
    let result = validator.validate(Cursor::new(bytes));
    assert!(result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::DecompressionBomb));
}

#[test]
fn garbage_container_is_unreadable() {
    let bytes = vec![b'X'; 128];
    let result = validate(ZipPackageProfile::Jar, &bytes);
    assert!(!result.container_readable());
    assert!(!result.profile_valid());
    assert!(result.has_code(PackageFindingCode::ContainerUnreadable));
}
