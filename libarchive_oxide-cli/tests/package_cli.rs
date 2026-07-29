// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `oxarchive package validate` contract: structure, integrity,
//! signature-validity, and issuer trust remain separate JSON dimensions.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
#![allow(clippy::cast_possible_truncation)]

mod common;

use libarchive_oxide::{ArchiveEngine, ArchiveWriter, CreateOptions, ZipMethod};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, FilterId, FormatId, Limits};
use serde_json::Value;

use common::{TempDir, code, run_in, run_stdin};

const SIGNED_JAR_APK: &[u8] = include_bytes!("fixtures/package/jar-apk-v1-signed.apk");
const SIGNER_SHA256_HEX: &str = "06f73dd845505562148c9b2d658ce359a3f6e86bdc096960826ba04d0b2e4182";
const ANDROID_APK_V2: &[u8] = include_bytes!("fixtures/package/android-apk-v2-aosp.apk");
const ANDROID_V2_SIGNER_SHA256_HEX: &str =
    "fb5dbd3c669af9fc236c6991e6387b7f11ff0590997f22d0f5c74ff40e04fca8";
const ANDROID_APK_V31_ROTATION: &[u8] =
    include_bytes!("fixtures/package/android-apk-v31-rotation-aosp.apk");
const ANDROID_APK_STANDARD_AND_VERITY: &[u8] =
    include_bytes!("fixtures/package/android-apk-standard-verity-aosp.apk");
const ANDROID_APK_V4_CTS: &[u8] = include_bytes!("fixtures/package/android-apk-v4-cts.apk");
const ANDROID_APK_V4_CTS_IDSIG: &[u8] =
    include_bytes!("fixtures/package/android-apk-v4-cts.apk.idsig");
const ANDROID_V4_SIGNER_SHA256_HEX: &str =
    "4180a9a0b1a55ef62ab56c8a630b061179cc32dc9896012135fe5d2c4bd04e6d";
const ALPINE_KEYS_APK: &[u8] = include_bytes!("fixtures/package/alpine-keys-2.5-r0.apk");
const ALPINE_KEY: &[u8] =
    include_bytes!("fixtures/package/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub");
const ALPINE_KEY_ID: &str = "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub";
const ALPINE_SIGNER_SHA256_HEX: &str =
    "5e03bee6b12094ef8e01323d8efa0d5929487c781def110fb2e8d09fc446f899";
const MICROSOFT_MSIX: &[u8] = include_bytes!("fixtures/package/msix-blockmap-microsoft.msix");

// --- Fixture builders (mirroring the library validator test suites) --------

/// A single tar/cpio entry: archive-native path, kind, and body bytes.
type Entry = (&'static [u8], EntryKind, Vec<u8>);

/// Builds an outer `ar` archive from named member bodies.
fn build_ar(members: &[(&[u8], Vec<u8>)]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(Vec::new(), CreateOptions::new().with_format(FormatId::Ar))
        .expect("create ar writer");
    for (name, body) in members {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(*name))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start member");
        if !body.is_empty() {
            writer.write_data(body).expect("write member");
        }
        writer.end_entry().expect("end member");
    }
    writer.finish().expect("finish ar")
}

/// Builds a tar member, optionally wrapped in a single outer filter.
fn build_tar(filter: Option<FilterId>, entries: &[Entry]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new()
                .with_format(FormatId::Tar)
                .with_filter(filter),
        )
        .expect("create tar writer");
    for (path, kind, body) in entries {
        let metadata = EntryMetadata::builder(*kind, ArchivePath::from_bytes(*path))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start entry");
        if !body.is_empty() {
            writer.write_data(body).expect("write entry");
        }
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish tar")
}

/// A well-formed `.deb`: `debian-binary`, a gzip `control.tar.gz`, and a gzip
/// `data.tar.gz`.
fn build_deb() -> Vec<u8> {
    let control = vec![(
        b"control".as_slice(),
        EntryKind::File,
        b"Package: demo\n".to_vec(),
    )];
    let data = vec![(
        b"usr/bin/demo".as_slice(),
        EntryKind::File,
        b"#!/bin/sh\n".to_vec(),
    )];
    build_ar(&[
        (b"debian-binary", b"2.0\n".to_vec()),
        (b"control.tar.gz", build_tar(Some(FilterId::Gzip), &control)),
        (b"data.tar.gz", build_tar(Some(FilterId::Gzip), &data)),
    ])
}

const HEADER_MAGIC: [u8; 3] = [0x8E, 0xAD, 0xE8];
const LEAD_MAGIC: [u8; 4] = [0xED, 0xAB, 0xEE, 0xDB];
const TAG_PAYLOADFORMAT: u32 = 1124;
const TAG_PAYLOADCOMPRESSOR: u32 = 1125;
const TYPE_STRING: u32 = 6;

/// Builds a gzip cpio payload from named file entries.
fn build_cpio(entries: &[Entry]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new()
                .with_format(FormatId::Cpio)
                .with_filter(Some(FilterId::Gzip)),
        )
        .expect("create cpio writer");
    for (path, kind, body) in entries {
        let metadata = EntryMetadata::builder(*kind, ArchivePath::from_bytes(*path))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata).expect("start entry");
        if !body.is_empty() {
            writer.write_data(body).expect("write entry");
        }
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish cpio")
}

/// One 16-byte RPM header index entry.
fn index_entry(tag: u32, kind: u32, offset: u32, count: u32) -> Vec<u8> {
    let mut entry = Vec::with_capacity(16);
    entry.extend_from_slice(&tag.to_be_bytes());
    entry.extend_from_slice(&kind.to_be_bytes());
    entry.extend_from_slice(&offset.to_be_bytes());
    entry.extend_from_slice(&count.to_be_bytes());
    entry
}

/// Assembles one RPM header structure from a raw index and data store.
fn header_bytes(index: &[u8], store: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&HEADER_MAGIC);
    out.push(0x01); // version
    out.extend_from_slice(&[0, 0, 0, 0]); // reserved
    out.extend_from_slice(&u32::try_from(index.len() / 16).unwrap().to_be_bytes());
    out.extend_from_slice(&u32::try_from(store.len()).unwrap().to_be_bytes());
    out.extend_from_slice(index);
    out.extend_from_slice(store);
    out
}

/// A well-formed RPM: 96-byte lead, empty signature header, a main header with
/// the `cpio`/`gzip` payload tags, and a gzip cpio payload.
fn build_rpm() -> Vec<u8> {
    let mut lead = vec![0u8; 96];
    lead[..4].copy_from_slice(&LEAD_MAGIC);
    lead[4] = 3; // major

    let mut store = Vec::new();
    let format_offset = u32::try_from(store.len()).unwrap();
    store.extend_from_slice(b"cpio");
    store.push(0);
    let compressor_offset = u32::try_from(store.len()).unwrap();
    store.extend_from_slice(b"gzip");
    store.push(0);
    let mut index = Vec::new();
    index.extend_from_slice(&index_entry(
        TAG_PAYLOADFORMAT,
        TYPE_STRING,
        format_offset,
        1,
    ));
    index.extend_from_slice(&index_entry(
        TAG_PAYLOADCOMPRESSOR,
        TYPE_STRING,
        compressor_offset,
        1,
    ));

    let payload = build_cpio(&[(
        b"usr/bin/demo".as_slice(),
        EntryKind::File,
        b"#!/bin/sh\n".to_vec(),
    )]);

    let mut rpm = lead;
    rpm.extend_from_slice(&header_bytes(&[], &[])); // signature header
    rpm.extend_from_slice(&header_bytes(&index, &store)); // main header
    rpm.extend_from_slice(&payload);
    rpm
}

/// Builds a genuine stored (uncompressed) ZIP through the crate's own writer,
/// preserving member order so EPUB `mimetype`-first checks pass.
fn build_zip_store(members: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut writer = ArchiveWriter::with_zip_method(Vec::new(), ZipMethod::Store, Limits::safe());
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

/// A valid JAR: requires `META-INF/MANIFEST.MF`.
fn build_jar() -> Vec<u8> {
    build_zip_store(&[
        (
            b"META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\r\n\r\n\
              Name: com/example/Main.class\r\n\
              SHA-256-Digest: I59Z7VXnN8dxR89VrQwbAwttfudIp0JpUvm4UtWpNeU=\r\n\r\n",
        ),
        (b"com/example/Main.class", b"payload"),
    ])
}

/// A structurally valid JAR whose manifest digest does not match the class.
fn build_tampered_jar() -> Vec<u8> {
    build_zip_store(&[
        (
            b"META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\r\n\r\nName: com/example/Main.class\r\nSHA-256-Digest: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n",
        ),
        (b"com/example/Main.class", b"payload"),
    ])
}

/// A valid EPUB: a first, stored `mimetype` member plus `META-INF/container.xml`.
fn build_epub() -> Vec<u8> {
    build_zip_store(&[
        (b"mimetype", b"application/epub+zip"),
        (b"META-INF/container.xml", b"<container/>"),
        (b"OEBPS/content.opf", b"<package/>"),
    ])
}

/// A structurally valid, unsigned Android APK.
fn build_android_apk() -> Vec<u8> {
    build_zip_store(&[
        (b"AndroidManifest.xml", b"manifest"),
        (b"classes.dex", b"dex\n035\0"),
    ])
}

/// A structurally valid, unsigned Alpine APK v2. The dedicated package-crate
/// suite covers the canonical concatenated-gzip layout; a single gzip member is
/// also a valid logical gzip/tar stream for CLI dispatch.
fn build_alpine_apk() -> Vec<u8> {
    build_tar(
        Some(FilterId::Gzip),
        &[
            (
                b".PKGINFO".as_slice(),
                EntryKind::File,
                b"pkgname = demo\npkgver = 1.0-r0\narch = x86_64\n".to_vec(),
            ),
            (
                b"usr/bin/demo".as_slice(),
                EntryKind::File,
                b"demo".to_vec(),
            ),
        ],
    )
}

// --- Output helpers --------------------------------------------------------

fn object(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "json object: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Returns whether the record carries a finding with the given code.
fn has_code(value: &Value, wanted: &str) -> bool {
    value["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .any(|finding| finding["code"] == wanted)
}

// --- Happy paths -----------------------------------------------------------

#[test]
fn valid_packages_report_exit_zero_and_profile_valid() {
    let dir = TempDir::new("package_valid");
    for (kind, name, blob, expected_finding) in [
        ("deb", "demo.deb", build_deb(), None),
        ("rpm", "demo.rpm", build_rpm(), None),
        ("jar", "demo.jar", build_jar(), None),
        ("epub", "demo.epub", build_epub(), None),
        (
            "alpine-apk",
            "demo-alpine.apk",
            build_alpine_apk(),
            Some("unsigned-package"),
        ),
        (
            "android-apk",
            "demo.apk",
            build_android_apk(),
            Some("unsigned-package"),
        ),
    ] {
        let path = dir.write(name, &blob);
        let output = run_in(
            "oxarchive",
            &[
                "package",
                "validate",
                path.to_str().expect("utf8"),
                "--type",
                kind,
            ],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{kind}: {output:?}");
        let value = object(&output);
        assert_eq!(value["schema_version"], "oxarchive.output.v0alpha1");
        assert_eq!(value["type"], "package_validation");
        assert_eq!(value["profile"], kind);
        assert_eq!(value["container_readable"], true, "{kind}: {value:?}");
        assert_eq!(value["profile_valid"], true, "{kind}: {value:?}");
        assert_eq!(
            value["integrity"],
            match kind {
                "jar" => "verified",
                "rpm" | "epub" | "alpine-apk" => "not-present",
                _ => "not-evaluated",
            },
            "{kind}: {value:?}"
        );
        assert_eq!(
            value["signature_validity"],
            if matches!(kind, "jar" | "epub" | "android-apk" | "alpine-apk") {
                "not-present"
            } else {
                "not-evaluated"
            },
            "{kind}: {value:?}"
        );
        assert_eq!(value["trust"], "not-evaluated", "{kind}: {value:?}");
        if let Some(code) = expected_finding {
            assert!(has_code(&value, code), "{kind}: {value:?}");
        } else {
            assert!(
                value["findings"].as_array().expect("findings").is_empty(),
                "{kind} should have no findings: {value:?}"
            );
        }
    }
}

#[test]
fn microsoft_msix_reports_verified_block_map_without_claiming_signature_validity() {
    let dir = TempDir::new("package_msix_blockmap");
    let path = dir.write("microsoft.msix", MICROSOFT_MSIX);
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8 path"),
            "--type",
            "msix",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let value = object(&output);
    assert_eq!(value["profile"], "msix");
    assert_eq!(value["container_readable"], true);
    assert_eq!(value["profile_valid"], true);
    assert_eq!(value["integrity"], "verified");
    assert_eq!(value["signature_validity"], "not-present");
    assert_eq!(value["trust"], "not-evaluated");
}

#[test]
fn type_flag_accepts_equals_form() {
    let dir = TempDir::new("package_equals");
    let path = dir.write("demo.jar", &build_jar());
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8"),
            "--type=jar",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert_eq!(object(&output)["profile"], "jar");
}

#[test]
fn signed_package_reports_verified_signer_and_requires_an_explicit_offline_pin() {
    let dir = TempDir::new("package_signer_pin");
    let path = dir.write("signed.jar", SIGNED_JAR_APK);
    let package = path.to_str().expect("utf8");

    let output = run_in(
        "oxarchive",
        &["package", "validate", package, "--type", "jar"],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let value = object(&output);
    assert_eq!(value["integrity"], "verified");
    assert_eq!(value["signature_validity"], "verified");
    assert_eq!(value["trust"], "invalid");
    assert_eq!(
        value["signer_fingerprints_sha256"],
        serde_json::json!([SIGNER_SHA256_HEX])
    );

    let trusted = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            package,
            "--type=jar",
            &format!(
                "--trusted-signer-sha256={}",
                SIGNER_SHA256_HEX.to_ascii_uppercase()
            ),
        ],
        dir.path(),
    );
    assert_eq!(code(&trusted), 0, "{trusted:?}");
    let value = object(&trusted);
    assert_eq!(value["signature_validity"], "verified");
    assert_eq!(value["trust"], "verified");
    assert_eq!(
        value["signer_fingerprints_sha256"],
        serde_json::json!([SIGNER_SHA256_HEX])
    );
}

#[test]
fn android_v2_verifies_content_and_requires_a_separate_trust_pin() {
    let dir = TempDir::new("package_android_v2");
    let path = dir.write("signed-v2.apk", ANDROID_APK_V2);
    let package = path.to_str().expect("utf8");

    let untrusted = run_in(
        "oxarchive",
        &["package", "validate", package, "--type", "android-apk"],
        dir.path(),
    );
    assert_eq!(code(&untrusted), 1, "{untrusted:?}");
    let value = object(&untrusted);
    assert_eq!(value["integrity"], "verified");
    assert_eq!(value["signature_validity"], "verified");
    assert_eq!(value["trust"], "invalid");
    assert_eq!(
        value["signer_fingerprints_sha256"],
        serde_json::json!([ANDROID_V2_SIGNER_SHA256_HEX])
    );

    let trusted = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            package,
            "--type=android-apk",
            "--trusted-signer-sha256",
            ANDROID_V2_SIGNER_SHA256_HEX,
        ],
        dir.path(),
    );
    assert_eq!(code(&trusted), 0, "{trusted:?}");
    let value = object(&trusted);
    assert_eq!(value["integrity"], "verified");
    assert_eq!(value["signature_validity"], "verified");
    assert_eq!(value["trust"], "verified");
}

#[test]
fn android_v31_rotation_is_reported_without_collapsing_trust_or_v4() {
    let dir = TempDir::new("package_android_v31_rotation");
    let path = dir.write("signed-v31.apk", ANDROID_APK_V31_ROTATION);
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8"),
            "--type",
            "android-apk",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");

    let value = object(&output);
    assert_eq!(value["schema_version"], "oxarchive.output.v0alpha1");
    assert_eq!(value["integrity"], "verified");
    assert_eq!(value["signature_validity"], "verified");
    assert_eq!(value["trust"], "invalid");
    assert_eq!(value["android_apk_v4"]["revision"], Value::Null);
    assert_eq!(value["android_apk_v4"]["integrity"], "not-evaluated");
    assert_eq!(
        value["android_apk_v4"]["signature_validity"],
        "not-evaluated"
    );
    assert_eq!(value["android_apk_v4"]["trust"], "not-evaluated");

    let rotation = &value["android_apk_rotation"];
    assert_eq!(rotation["v3_1_present"], true);
    assert_eq!(rotation["rotation_min_sdk"], 34);
    assert_eq!(rotation["targets_dev_release"], false);
    assert_eq!(rotation["signers"].as_array().expect("signers").len(), 2);
    assert_eq!(rotation["signers"][0]["scheme"], "v3");
    assert_eq!(rotation["signers"][0]["minimum_sdk"], 24);
    assert_eq!(rotation["signers"][0]["maximum_sdk"], 33);
    assert_eq!(rotation["signers"][1]["scheme"], "v3.1");
    assert_eq!(rotation["signers"][1]["minimum_sdk"], 34);
    assert_eq!(rotation["signers"][1]["maximum_sdk"], i32::MAX);
    assert_eq!(rotation["lineage"].as_array().expect("lineage").len(), 2);
    assert_eq!(rotation["lineage"][0]["flags"], 0x17);
    assert_eq!(
        rotation["lineage"][0]["next_signature_algorithm_id"],
        0x0103
    );
    assert_eq!(
        rotation["lineage"][1]["signed_signature_algorithm_id"],
        0x0103
    );
    assert_eq!(rotation["lineage"][1]["next_signature_algorithm_id"], 0);
}

#[test]
fn android_platform_selected_signature_failure_is_versioned_json_and_exit_one() {
    const STANDARD_SIGNATURE_OFFSET: usize = 9133;

    let dir = TempDir::new("package_android_sdk_signature");
    let mut tampered = ANDROID_APK_STANDARD_AND_VERITY.to_vec();
    // In this immutable AOSP fixture, offset 9133 starts the v2 RSA PKCS#1
    // SHA-256 signature selected on Android N/O. Leave the later fs-verity
    // signature valid to ensure it cannot hide this platform-range failure.
    assert_eq!(
        &tampered[STANDARD_SIGNATURE_OFFSET - 8..STANDARD_SIGNATURE_OFFSET - 4],
        &0x0103_u32.to_le_bytes()
    );
    tampered[STANDARD_SIGNATURE_OFFSET] ^= 1;
    let path = dir.write("standard-signature-tampered.apk", &tampered);
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8"),
            "--type",
            "android-apk",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");

    let value = object(&output);
    assert_eq!(value["schema_version"], "oxarchive.output.v0alpha1");
    assert_eq!(value["integrity"], "not-evaluated");
    assert_eq!(value["signature_validity"], "invalid");
    assert_eq!(value["trust"], "not-evaluated");
    assert!(has_code(&value, "signature-mismatch"), "{value:?}");
    assert_eq!(value["android_apk_rotation"], Value::Null);
}

#[test]
fn android_v4_sidecar_is_explicit_verified_and_reported_as_versioned_json() {
    let dir = TempDir::new("package_android_v4");
    let package_path = dir.write("signed-v4.apk", ANDROID_APK_V4_CTS);
    let idsig_path = dir.write("detached.idsig", ANDROID_APK_V4_CTS_IDSIG);
    let package = package_path.to_str().expect("utf8");
    let idsig = idsig_path.to_str().expect("utf8");

    let untrusted = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            package,
            "--type=android-apk",
            &format!("--idsig-file={idsig}"),
        ],
        dir.path(),
    );
    assert_eq!(code(&untrusted), 1, "{untrusted:?}");
    let value = object(&untrusted);
    assert_eq!(value["schema_version"], "oxarchive.output.v0alpha1");
    assert_eq!(value["integrity"], "verified");
    assert_eq!(value["signature_validity"], "verified");
    assert_eq!(value["trust"], "invalid");
    assert_eq!(value["android_apk_v4"]["revision"], "v4.0");
    assert_eq!(value["android_apk_v4"]["integrity"], "verified");
    assert_eq!(value["android_apk_v4"]["signature_validity"], "verified");
    assert_eq!(value["android_apk_v4"]["trust"], "invalid");
    assert_eq!(
        value["android_apk_v4"]["signer_fingerprints_sha256"],
        serde_json::json!([ANDROID_V4_SIGNER_SHA256_HEX])
    );
    assert!(
        value["android_apk_v4"]["findings"]
            .as_array()
            .expect("v4 findings")
            .is_empty(),
        "{value:?}"
    );

    let trusted = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            package,
            "--type",
            "android-apk",
            "--idsig-file",
            idsig,
            "--trusted-signer-sha256",
            ANDROID_V4_SIGNER_SHA256_HEX,
        ],
        dir.path(),
    );
    assert_eq!(code(&trusted), 0, "{trusted:?}");
    let value = object(&trusted);
    assert_eq!(value["android_apk_v4"]["trust"], "verified");
    assert_eq!(value["trust"], "verified");
}

#[test]
fn android_v4_sidecar_is_never_discovered_from_a_sibling_path() {
    let dir = TempDir::new("package_android_v4_no_guess");
    let package_path = dir.write("signed-v4.apk", ANDROID_APK_V4_CTS);
    let _conventional_sidecar = dir.write("signed-v4.apk.idsig", ANDROID_APK_V4_CTS_IDSIG);
    let package = package_path.to_str().expect("utf8");

    let output = run_in(
        "oxarchive",
        &["package", "validate", package, "--type", "android-apk"],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let value = object(&output);
    assert_eq!(value["android_apk_v4"]["revision"], Value::Null);
    assert_eq!(value["android_apk_v4"]["integrity"], "not-evaluated");
    assert_eq!(
        value["android_apk_v4"]["signature_validity"],
        "not-evaluated"
    );
    assert_eq!(value["android_apk_v4"]["trust"], "not-evaluated");
    assert_eq!(
        value["android_apk_v4"]["findings"][0]["code"],
        "signature-sidecar-not-provided"
    );
}

#[test]
fn idsig_file_flag_is_android_only_single_and_path_backed() {
    let dir = TempDir::new("package_idsig_flag");
    let package_path = dir.write("signed-v4.apk", ANDROID_APK_V4_CTS);
    let idsig_path = dir.write("detached.idsig", ANDROID_APK_V4_CTS_IDSIG);
    let package = package_path.to_str().expect("utf8");
    let idsig = idsig_path.to_str().expect("utf8");

    for args in [
        vec![
            "package",
            "validate",
            package,
            "--type",
            "jar",
            "--idsig-file",
            idsig,
        ],
        vec![
            "package",
            "validate",
            package,
            "--type",
            "android-apk",
            "--idsig-file",
            idsig,
            "--idsig-file",
            idsig,
        ],
        vec![
            "package",
            "validate",
            package,
            "--type",
            "android-apk",
            "--idsig-file=-",
        ],
        vec![
            "package",
            "validate",
            package,
            "--type",
            "android-apk",
            "--idsig-file=",
        ],
    ] {
        let output = run_in("oxarchive", &args, dir.path());
        assert_eq!(code(&output), 2, "{args:?}: {output:?}");
    }

    let missing = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            package,
            "--type",
            "android-apk",
            "--idsig-file",
            "does-not-exist.idsig",
        ],
        dir.path(),
    );
    assert_eq!(code(&missing), 1, "{missing:?}");
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("cannot open APK v4 sidecar"),
        "{missing:?}"
    );
}

#[test]
fn alpine_rsa_key_verifies_validity_but_requires_a_separate_trust_pin() {
    let dir = TempDir::new("package_alpine_rsa");
    let package_path = dir.write("alpine-keys-2.5-r0.apk", ALPINE_KEYS_APK);
    let key_path = dir.write(ALPINE_KEY_ID, ALPINE_KEY);
    let package = package_path.to_str().expect("utf8");
    let key = key_path.to_str().expect("utf8");

    let no_key = run_in(
        "oxarchive",
        &["package", "validate", package, "--type", "alpine-apk"],
        dir.path(),
    );
    assert_eq!(code(&no_key), 0, "{no_key:?}");
    let value = object(&no_key);
    assert_eq!(value["integrity"], "verified");
    assert_eq!(value["signature_validity"], "not-evaluated");
    assert_eq!(value["trust"], "not-evaluated");

    let untrusted = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            package,
            "--type=alpine-apk",
            &format!("--alpine-rsa-key-file={key}"),
        ],
        dir.path(),
    );
    assert_eq!(code(&untrusted), 1, "{untrusted:?}");
    let value = object(&untrusted);
    assert_eq!(value["integrity"], "verified");
    assert_eq!(value["signature_validity"], "verified");
    assert_eq!(value["trust"], "invalid");
    assert_eq!(
        value["signer_fingerprints_sha256"],
        serde_json::json!([ALPINE_SIGNER_SHA256_HEX])
    );

    let trusted = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            package,
            "--type",
            "alpine-apk",
            "--alpine-rsa-key-file",
            key,
            "--trusted-signer-sha256",
            ALPINE_SIGNER_SHA256_HEX,
        ],
        dir.path(),
    );
    assert_eq!(code(&trusted), 0, "{trusted:?}");
    let value = object(&trusted);
    assert_eq!(value["signature_validity"], "verified");
    assert_eq!(value["trust"], "verified");
}

#[test]
fn alpine_key_file_flags_are_scoped_bounded_and_non_duplicated() {
    let dir = TempDir::new("package_alpine_key_flags");
    let package_path = dir.write("alpine-keys-2.5-r0.apk", ALPINE_KEYS_APK);
    let key_path = dir.write(ALPINE_KEY_ID, ALPINE_KEY);
    let package = package_path.to_str().expect("utf8");
    let key = key_path.to_str().expect("utf8");

    for args in [
        vec![
            "package",
            "validate",
            package,
            "--type",
            "jar",
            "--alpine-rsa-key-file",
            key,
        ],
        vec![
            "package",
            "validate",
            package,
            "--type",
            "alpine-apk",
            "--alpine-rsa-key-file",
            key,
            "--alpine-rsa-key-file",
            key,
        ],
    ] {
        let output = run_in("oxarchive", &args, dir.path());
        assert_eq!(code(&output), 2, "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
    }

    let oversized_path = dir.write(ALPINE_KEY_ID, &vec![b'A'; 64 * 1024 + 1]);
    let oversized = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            package,
            "--type",
            "alpine-apk",
            "--alpine-rsa-key-file",
            oversized_path.to_str().expect("utf8"),
        ],
        dir.path(),
    );
    assert_eq!(code(&oversized), 2, "{oversized:?}");
    assert!(oversized.stdout.is_empty(), "{oversized:?}");
}

#[test]
fn trust_policy_flags_are_strict_and_allow_unsigned_is_explicit() {
    let dir = TempDir::new("package_trust_flags");
    let path = dir.write("demo.jar", &build_jar());
    let package = path.to_str().expect("utf8");

    let allowed = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            package,
            "--type",
            "jar",
            "--allow-unsigned",
        ],
        dir.path(),
    );
    assert_eq!(code(&allowed), 0, "{allowed:?}");
    assert_eq!(object(&allowed)["trust"], "verified");

    for args in [
        vec![
            "package",
            "validate",
            package,
            "--type",
            "jar",
            "--trusted-signer-sha256",
            "00",
        ],
        vec![
            "package",
            "validate",
            package,
            "--type",
            "jar",
            "--trusted-signer-sha256",
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
        ],
        vec![
            "package",
            "validate",
            package,
            "--type",
            "jar",
            "--allow-unsigned",
            "--allow-unsigned",
        ],
    ] {
        let output = run_in("oxarchive", &args, dir.path());
        assert_eq!(code(&output), 2, "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
    }
}

#[test]
fn deb_validates_from_standard_input() {
    let dir = TempDir::new("package_stdin_deb");
    let output = run_stdin(
        "oxarchive",
        &["package", "validate", "-", "--type", "deb"],
        dir.path(),
        &build_deb(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let value = object(&output);
    assert_eq!(value["profile"], "deb");
    assert_eq!(value["profile_valid"], true);
}

#[test]
fn alpine_apk_validates_from_standard_input() {
    let dir = TempDir::new("package_stdin_alpine");
    let output = run_stdin(
        "oxarchive",
        &["package", "validate", "-", "--type", "alpine-apk"],
        dir.path(),
        &build_alpine_apk(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let value = object(&output);
    assert_eq!(value["profile"], "alpine-apk");
    assert_eq!(value["profile_valid"], true);
    assert_eq!(value["signature_validity"], "not-present");
}

// --- Invalid packages (container read, profile not satisfied) --------------

#[test]
fn missing_debian_binary_reports_exit_one_with_typed_finding() {
    let dir = TempDir::new("package_bad_deb");
    let blob = build_ar(&[
        (
            b"control.tar.gz",
            build_tar(
                Some(FilterId::Gzip),
                &[(
                    b"control".as_slice(),
                    EntryKind::File,
                    b"Package: demo\n".to_vec(),
                )],
            ),
        ),
        (
            b"data.tar.gz",
            build_tar(
                Some(FilterId::Gzip),
                &[(b"usr/bin/demo".as_slice(), EntryKind::File, b"x".to_vec())],
            ),
        ),
    ]);
    let path = dir.write("bad.deb", &blob);
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8"),
            "--type",
            "deb",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let value = object(&output);
    assert_eq!(value["type"], "package_validation");
    assert_eq!(value["container_readable"], true);
    assert_eq!(value["profile_valid"], false);
    assert!(
        has_code(&value, "missing-debian-binary"),
        "expected missing-debian-binary: {value:?}"
    );
    // The shared severity is rendered by its stable label, not re-derived.
    let finding = value["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|finding| finding["code"] == "missing-debian-binary")
        .expect("the finding");
    assert_eq!(finding["severity"], "error");
}

#[test]
fn jar_without_manifest_reports_exit_one_with_typed_finding() {
    let dir = TempDir::new("package_bad_jar");
    let blob = build_zip_store(&[(b"com/example/Main.class", b"payload")]);
    let path = dir.write("bad.jar", &blob);
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8"),
            "--type",
            "jar",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let value = object(&output);
    assert_eq!(value["container_readable"], true);
    assert_eq!(value["profile_valid"], false);
    assert!(
        has_code(&value, "missing-required-member"),
        "expected missing-required-member: {value:?}"
    );
}

#[test]
fn jar_integrity_mismatch_reports_exit_one_without_changing_structure_verdict() {
    let dir = TempDir::new("package_tampered_jar");
    let path = dir.write("tampered.jar", &build_tampered_jar());
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8"),
            "--type",
            "jar",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let value = object(&output);
    assert_eq!(value["container_readable"], true);
    assert_eq!(value["profile_valid"], true);
    assert_eq!(value["integrity"], "invalid");
    assert!(has_code(&value, "integrity-mismatch"), "{value:?}");
}

// --- Usage errors ----------------------------------------------------------

#[test]
fn unknown_type_is_usage_error() {
    let dir = TempDir::new("package_unknown_type");
    let path = dir.write("demo.jar", &build_jar());
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8"),
            "--type",
            "frob",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(!output.stderr.is_empty(), "{output:?}");
}

#[test]
fn ambiguous_apk_type_is_rejected_with_explicit_names() {
    let dir = TempDir::new("package_ambiguous_apk_type");
    let path = dir.write("demo.apk", &build_android_apk());
    let output = run_in(
        "oxarchive",
        &[
            "package",
            "validate",
            path.to_str().expect("utf8"),
            "--type",
            "apk",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("android-apk"), "{output:?}");
    assert!(stderr.contains("alpine-apk"), "{output:?}");
}

#[test]
fn missing_type_is_usage_error() {
    let dir = TempDir::new("package_missing_type");
    let path = dir.write("demo.jar", &build_jar());
    let output = run_in(
        "oxarchive",
        &["package", "validate", path.to_str().expect("utf8")],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
}

#[test]
fn unknown_subcommand_is_usage_error() {
    let dir = TempDir::new("package_unknown_sub");
    let output = run_in("oxarchive", &["package", "frobnicate"], dir.path());
    assert_eq!(code(&output), 2, "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");

    let output = run_in("oxarchive", &["package"], dir.path());
    assert_eq!(code(&output), 2, "{output:?}");
}

#[test]
fn zip_profile_rejects_standard_input_as_usage() {
    let dir = TempDir::new("package_stdin_zip");
    let output = run_stdin(
        "oxarchive",
        &["package", "validate", "-", "--type", "jar"],
        dir.path(),
        &build_jar(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(!output.stderr.is_empty(), "{output:?}");
}
