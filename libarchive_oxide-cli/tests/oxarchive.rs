// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unified `oxarchive` command contract.

#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::process::{Command, Stdio};

use libarchive_oxide::{
    ArchiveEngine, ArchivePath, ArchiveReader, CreateOptions, EntryKind, EntryMetadata, Extension,
    FilterId, FilterReader, FormatId, Limits, ReaderEvent,
};
use serde_json::Value;

use common::{TempDir, bin, code, run_in, run_stdin};

fn archive(format: FormatId, filter: Option<FilterId>, path: &[u8], body: &[u8]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new().with_format(format).with_filter(filter),
        )
        .expect("create archive");
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path))
        .size(Some(body.len() as u64))
        .build();
    writer.start_entry(&metadata).expect("start entry");
    writer.write_data(body).expect("write entry");
    writer.end_entry().expect("end entry");
    writer.finish().expect("finish archive")
}

fn archive_many(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut writer = ArchiveEngine::new()
        .create(Vec::new(), CreateOptions::new().with_format(FormatId::Tar))
        .expect("create archive");
    for (path, body) in entries {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path.to_vec()))
                .size(Some(body.len() as u64))
                .build();
        writer.start_entry(&metadata).expect("start entry");
        writer.write_data(body).expect("write entry");
        writer.end_entry().expect("end entry");
    }
    writer.finish().expect("finish archive")
}

fn rpm_wrapper(payload: &[u8]) -> Vec<u8> {
    fn header(store: &[u8], signature: bool) -> Vec<u8> {
        let mut bytes = vec![0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(
            &u32::try_from(store.len())
                .expect("store length")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(store);
        if signature {
            bytes.resize((bytes.len() + 7) & !7, 0);
        }
        bytes
    }

    let mut bytes = vec![0_u8; 96];
    bytes[..4].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
    bytes.extend_from_slice(&header(b"sig", true));
    bytes.extend_from_slice(&header(b"main", false));
    bytes.extend_from_slice(payload);
    bytes
}

fn lha_sfx_store(name: &[u8], body: &[u8]) -> Vec<u8> {
    let crc16 = |bytes: &[u8]| {
        let mut crc = 0_u16;
        for &byte in bytes {
            crc ^= u16::from(byte);
            for _ in 0..8 {
                crc = if crc & 1 == 0 {
                    crc >> 1
                } else {
                    (crc >> 1) ^ 0xa001
                };
            }
        }
        crc
    };
    let size = u32::try_from(body.len()).expect("LHA fixture body");
    let mut archive = vec![
        u8::try_from(22 + name.len()).expect("LHA fixture header"),
        0,
    ];
    archive.extend_from_slice(b"-lh0-");
    archive.extend_from_slice(&size.to_le_bytes());
    archive.extend_from_slice(&size.to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.extend_from_slice(&[0x20, 0, u8::try_from(name.len()).expect("LHA fixture name")]);
    archive.extend_from_slice(name);
    archive.extend_from_slice(&crc16(body).to_le_bytes());
    archive[1] = archive[2..]
        .iter()
        .fold(0_u8, |sum, &byte| sum.wrapping_add(byte));
    archive.extend_from_slice(body);
    archive.push(0);

    let mut sfx = vec![0x90; 123];
    sfx[..2].copy_from_slice(b"MZ");
    sfx.extend_from_slice(&archive);
    sfx
}

fn rar5_vint(mut value: u64) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

fn rar5_block(header_type: u64, flags: u64, data_size: Option<u64>, fields: &[u8]) -> Vec<u8> {
    let mut body = rar5_vint(header_type);
    body.extend_from_slice(&rar5_vint(flags));
    if flags & 0x02 != 0 {
        body.extend_from_slice(&rar5_vint(data_size.expect("RAR5 data size")));
    }
    body.extend_from_slice(fields);
    let size = rar5_vint(body.len() as u64);
    let mut checked = size.clone();
    checked.extend_from_slice(&body);
    let mut block = libarchive_oxide::filter::crc32(&checked)
        .to_le_bytes()
        .to_vec();
    block.extend_from_slice(&checked);
    block
}

fn rar5_store(name: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut archive = b"Rar!\x1a\x07\x01\x00".to_vec();
    archive.extend_from_slice(&rar5_block(1, 0, None, &rar5_vint(0)));
    let mut fields = rar5_vint(0x04);
    fields.extend_from_slice(&rar5_vint(payload.len() as u64));
    fields.extend_from_slice(&rar5_vint(0o100_644));
    fields.extend_from_slice(&libarchive_oxide::filter::crc32(payload).to_le_bytes());
    fields.extend_from_slice(&rar5_vint(0));
    fields.extend_from_slice(&rar5_vint(1));
    fields.extend_from_slice(&rar5_vint(name.len() as u64));
    fields.extend_from_slice(name);
    archive.extend_from_slice(&rar5_block(2, 0x02, Some(payload.len() as u64), &fields));
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&rar5_block(5, 0, None, &rar5_vint(0)));
    archive
}

fn rar5_volume(index: u64, next: bool, name: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut archive = b"Rar!\x1a\x07\x01\x00".to_vec();
    let mut main = rar5_vint(0x03);
    main.extend_from_slice(&rar5_vint(index));
    archive.extend_from_slice(&rar5_block(1, 0, None, &main));
    let mut fields = rar5_vint(0x04);
    fields.extend_from_slice(&rar5_vint(payload.len() as u64));
    fields.extend_from_slice(&rar5_vint(0o100_644));
    fields.extend_from_slice(&libarchive_oxide::filter::crc32(payload).to_le_bytes());
    fields.extend_from_slice(&rar5_vint(0));
    fields.extend_from_slice(&rar5_vint(1));
    fields.extend_from_slice(&rar5_vint(name.len() as u64));
    fields.extend_from_slice(name);
    archive.extend_from_slice(&rar5_block(2, 0x02, Some(payload.len() as u64), &fields));
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&rar5_block(5, 0, None, &rar5_vint(u64::from(next))));
    archive
}

fn split_zip_store(name: &[u8], payload: &[u8]) -> [Vec<u8>; 2] {
    let size = u32::try_from(payload.len()).expect("split ZIP payload size");
    let name_len = u16::try_from(name.len()).expect("split ZIP name size");
    let crc = libarchive_oxide::filter::crc32(payload);
    let mut first = b"PK\x07\x08PK\x03\x04".to_vec();
    first.extend_from_slice(&20_u16.to_le_bytes());
    first.extend_from_slice(&0_u16.to_le_bytes());
    first.extend_from_slice(&0_u16.to_le_bytes());
    first.extend_from_slice(&0_u16.to_le_bytes());
    first.extend_from_slice(&0_u16.to_le_bytes());
    first.extend_from_slice(&crc.to_le_bytes());
    first.extend_from_slice(&size.to_le_bytes());
    first.extend_from_slice(&size.to_le_bytes());
    first.extend_from_slice(&name_len.to_le_bytes());
    first.extend_from_slice(&0_u16.to_le_bytes());
    first.extend_from_slice(name);
    first.extend_from_slice(payload);

    let mut central = b"PK\x01\x02".to_vec();
    central.extend_from_slice(&20_u16.to_le_bytes());
    central.extend_from_slice(&20_u16.to_le_bytes());
    central.extend_from_slice(&0_u16.to_le_bytes());
    central.extend_from_slice(&0_u16.to_le_bytes());
    central.extend_from_slice(&0_u16.to_le_bytes());
    central.extend_from_slice(&0_u16.to_le_bytes());
    central.extend_from_slice(&crc.to_le_bytes());
    central.extend_from_slice(&size.to_le_bytes());
    central.extend_from_slice(&size.to_le_bytes());
    central.extend_from_slice(&name_len.to_le_bytes());
    central.extend_from_slice(&0_u16.to_le_bytes());
    central.extend_from_slice(&0_u16.to_le_bytes());
    central.extend_from_slice(&0_u16.to_le_bytes());
    central.extend_from_slice(&0_u16.to_le_bytes());
    central.extend_from_slice(&0_u32.to_le_bytes());
    central.extend_from_slice(&4_u32.to_le_bytes());
    central.extend_from_slice(name);
    let central_size = u32::try_from(central.len()).expect("split ZIP central size");
    let mut terminal = central;
    terminal.extend_from_slice(b"PK\x05\x06");
    terminal.extend_from_slice(&1_u16.to_le_bytes());
    terminal.extend_from_slice(&1_u16.to_le_bytes());
    terminal.extend_from_slice(&1_u16.to_le_bytes());
    terminal.extend_from_slice(&1_u16.to_le_bytes());
    terminal.extend_from_slice(&central_size.to_le_bytes());
    terminal.extend_from_slice(&0_u32.to_le_bytes());
    terminal.extend_from_slice(&0_u16.to_le_bytes());
    [first, terminal]
}

fn rar_legacy_store(name: &[u8], payload: &[u8]) -> Vec<u8> {
    fn block(kind: u8, flags: u16, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0, 0, kind];
        bytes.extend_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(7 + body.len())
                .expect("RAR4 block size")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(body);
        let crc = u16::try_from(libarchive_oxide::filter::crc32(&bytes[2..]) & u32::from(u16::MAX))
            .expect("low RAR header CRC16");
        bytes[..2].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    let mut archive = b"Rar!\x1a\x07\x00".to_vec();
    archive.extend_from_slice(&block(0x73, 0, &[0; 6]));
    let mut body = Vec::new();
    let size = u32::try_from(payload.len()).expect("RAR4 payload size");
    body.extend_from_slice(&size.to_le_bytes());
    body.extend_from_slice(&size.to_le_bytes());
    body.push(3);
    body.extend_from_slice(&libarchive_oxide::filter::crc32(payload).to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.push(29);
    body.push(0x30);
    body.extend_from_slice(
        &u16::try_from(name.len())
            .expect("RAR4 path size")
            .to_le_bytes(),
    );
    body.extend_from_slice(&0o100_644_u32.to_le_bytes());
    body.extend_from_slice(name);
    archive.extend_from_slice(&block(0x74, 0x8000, &body));
    archive.extend_from_slice(payload);
    archive.extend_from_slice(&block(0x7b, 0, &[]));
    archive
}

fn password_file(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.write(name, bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("protect password file");
    }
    path
}

fn run_without_tty(args: &[&str], cwd: &std::path::Path) -> std::process::Output {
    Command::new(bin("oxarchive"))
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .expect("spawn oxarchive without a TTY")
}

const PROCESS_SECRET: &str = "process-secret-never-print-this";
const WRONG_PROCESS_SECRET: &str = "wrong-secret-never-print-this";

fn create_protected_zip(dir: &TempDir) -> std::process::Output {
    dir.write("input.txt", b"authenticated payload");
    password_file(
        dir,
        "archive-password.txt",
        format!("{PROCESS_SECRET}\r\n").as_bytes(),
    );
    run_in(
        "oxarchive",
        &[
            "--json",
            "create",
            "--password-file",
            "archive-password.txt",
            "protected.zip",
            "input.txt",
        ],
        dir.path(),
    )
}

fn assert_secret_absent(output: &std::process::Output, secret: &str) {
    assert!(
        !output
            .stdout
            .windows(secret.len())
            .any(|bytes| bytes == secret.as_bytes()),
        "secret exposed on stdout"
    );
    assert!(
        !output
            .stderr
            .windows(secret.len())
            .any(|bytes| bytes == secret.as_bytes()),
        "secret exposed on stderr"
    );
}
fn json_output(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "JSON output: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn json_records(output: &std::process::Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| {
                panic!(
                    "JSON record: {error}; line={line}; stderr={}",
                    String::from_utf8_lossy(&output.stderr)
                )
            })
        })
        .collect()
}

#[test]
fn capabilities_json_is_versioned_and_preserves_known_deficits() {
    let dir = TempDir::new("oxarchive_capabilities");
    let output = run_in("oxarchive", &["capabilities", "--json"], dir.path());
    assert_eq!(code(&output), 0, "{output:?}");
    let value = json_output(&output);
    assert_eq!(value["schema"], "oxarchive.output.v0alpha1");
    assert_eq!(value["type"], "capability-ledger");
    let entries = value["entries"].as_array().expect("capability entries");
    let zip_zstd = entries
        .iter()
        .find(|entry| entry["key"] == "method.zip.zstd")
        .expect("ZIP Zstandard capability");
    assert_eq!(zip_zstd["format"], "zip");
    assert_eq!(zip_zstd["method_id"]["kind"], "numeric");
    assert_eq!(zip_zstd["method_id"]["value"], 93);
    assert_eq!(zip_zstd["access"]["read"], "sequential");
    assert_eq!(zip_zstd["access"]["write"], "sequential");
    if cfg!(feature = "portable-codecs") {
        assert_eq!(zip_zstd["portable"]["read"], true);
        assert_eq!(zip_zstd["portable"]["write"], true);
    } else {
        assert_eq!(zip_zstd["portable"]["state"], "disabled");
    }
    if cfg!(feature = "native-codecs") {
        assert_eq!(zip_zstd["native"]["read"], true);
        assert_eq!(zip_zstd["native"]["write"], true);
    } else {
        assert_eq!(zip_zstd["native"]["state"], "disabled");
    }

    let lzip = entries
        .iter()
        .find(|entry| entry["key"] == "filter.lzip")
        .expect("lzip filter capability");
    assert_eq!(lzip["kind"], "filter");
    assert_eq!(lzip["filter"], "lzip");
    assert_eq!(lzip["access"]["read"], "filter");
    assert_eq!(lzip["access"]["write"], "filter");
    let lzip_portable_state = lzip["portable"]["state"]
        .as_str()
        .expect("lzip portable state");
    let lzip_native_state = lzip["native"]["state"].as_str().expect("lzip native state");
    // Workspace feature unification is additive: another selected member (the
    // stable fuzz replay crate, for example) may enable the individual `lzip`
    // feature even when this CLI package's portable umbrella is disabled.
    // Validate the canonical ledger's coherent states instead of assuming a
    // package-local feature can subtract a dependency feature.
    assert!(
        matches!(
            (lzip_portable_state, lzip_native_state),
            ("disabled" | "available", "disabled") | ("available", "unsupported")
        ),
        "unexpected lzip backend states: portable={lzip_portable_state}, native={lzip_native_state}"
    );
    if cfg!(feature = "portable-codecs") {
        assert_eq!(lzip_portable_state, "available");
    }
    assert_eq!(lzip["portable"]["read"], lzip_portable_state == "available");
    assert_eq!(
        lzip["portable"]["write"],
        lzip_portable_state == "available"
    );
    assert_eq!(lzip["native"]["read"], false);
    assert_eq!(lzip["native"]["write"], false);

    let bcj2 = entries
        .iter()
        .find(|entry| entry["key"] == "method.7z.bcj2")
        .expect("7z BCJ2 capability");
    assert_eq!(bcj2["format"], "7z");
    assert_eq!(bcj2["method_id"]["kind"], "bytes");
    assert_eq!(bcj2["method_id"]["hex"], "0303011b");
    assert_eq!(bcj2["access"]["read"], "seek");
    assert!(bcj2["access"]["write"].is_null());
    assert_eq!(
        bcj2["portable"]["read"],
        cfg!(feature = "portable-codecs") || !cfg!(feature = "native-codecs")
    );
    assert_eq!(bcj2["native"]["read"], cfg!(feature = "native-codecs"));

    for key in ["method.cab.lzx", "method.cab.quantum"] {
        let method = entries
            .iter()
            .find(|entry| entry["key"] == key)
            .unwrap_or_else(|| panic!("{key} capability"));
        assert_eq!(
            method["portable"]["state"],
            if cfg!(feature = "portable-codecs") {
                "available"
            } else {
                "disabled"
            },
            "{key}"
        );
        assert_eq!(
            method["native"]["state"],
            if cfg!(feature = "native-codecs") {
                "available"
            } else {
                "disabled"
            },
            "{key}"
        );
    }
}

#[test]
fn completion_and_man_are_generated_without_extra_binaries() {
    let dir = TempDir::new("oxarchive_completion");
    for shell in ["bash", "zsh", "fish", "powershell"] {
        let output = run_in("oxarchive", &["completion", shell], dir.path());
        assert_eq!(code(&output), 0, "{shell}: {output:?}");
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("oxarchive"), "{shell}: {text}");
        assert!(text.contains("package"), "{shell}: {text}");
        assert!(text.contains("password-file"), "{shell}: {text}");
        assert!(text.contains("password-prompt"), "{shell}: {text}");
        assert!(text.contains("discover-volumes"), "{shell}: {text}");
        assert!(text.contains("zip-compression"), "{shell}: {text}");
        assert!(text.contains("zip-encryption"), "{shell}: {text}");
        assert!(text.contains("7z-compression"), "{shell}: {text}");
        assert!(text.contains("7z-filter"), "{shell}: {text}");
        assert!(text.contains("7z-encryption"), "{shell}: {text}");
        assert!(text.contains("xar-compression"), "{shell}: {text}");
        assert!(text.contains("idsig-file"), "{shell}: {text}");
    }

    let output = run_in("oxarchive", &["man"], dir.path());
    assert_eq!(code(&output), 0, "{output:?}");
    let man = String::from_utf8_lossy(&output.stdout);
    assert!(man.starts_with(".TH OXARCHIVE 1"));
    assert!(man.contains("--password-file FILE"));
    assert!(man.contains("--password-prompt"));
    assert!(man.contains("--discover-volumes"));
    assert!(man.contains("--zip-compression METHOD"));
    assert!(man.contains("--zip-encryption METHOD"));
    assert!(man.contains("--7z-compression METHOD"));
    assert!(man.contains("--7z-filter FILTER"));
    assert!(man.contains("--7z-encryption METHOD"));
    assert!(man.contains("--xar-compression METHOD"));
    assert!(man.contains("--password=VALUE"));
    assert!(man.contains("--idsig-file PATH"));

    for args in [
        &["completion", "cmd"][..],
        &["completion"][..],
        &["--json", "man"][..],
    ] {
        let output = run_in("oxarchive", args, dir.path());
        assert_eq!(code(&output), 2, "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
    }
}

#[test]
fn password_file_is_wired_to_create_and_every_archive_read_command() {
    let dir = TempDir::new("oxarchive_password");
    let created = create_protected_zip(&dir);
    assert_eq!(code(&created), 0, "{created:?}");
    assert_eq!(json_output(&created)["format"], "zip");
    assert_secret_absent(&created, PROCESS_SECRET);

    for command in ["list", "inspect", "plan", "verify"] {
        let output = run_in(
            "oxarchive",
            &[
                "--json",
                command,
                "--password-file=archive-password.txt",
                "protected.zip",
            ],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{command}: {output:?}");
        assert_secret_absent(&output, PROCESS_SECRET);
    }

    let explicit = run_in(
        "oxarchive",
        &[
            "--json",
            "inspect",
            "--format",
            "zip",
            "--password-file",
            "archive-password.txt",
            "protected.zip",
        ],
        dir.path(),
    );
    assert_eq!(code(&explicit), 0, "{explicit:?}");
    assert_eq!(
        json_records(&explicit).last().expect("complete")["format"],
        "zip"
    );
    assert_secret_absent(&explicit, PROCESS_SECRET);

    for (command, destination) in [("apply", "applied"), ("extract", "extracted")] {
        let output = run_in(
            "oxarchive",
            &[
                command,
                "--password-file",
                "archive-password.txt",
                "protected.zip",
                destination,
            ],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{command}: {output:?}");
        assert_eq!(
            std::fs::read(dir.join(&format!("{destination}/input.txt")))
                .expect("read protected extraction"),
            b"authenticated payload"
        );
        assert_secret_absent(&output, PROCESS_SECRET);
    }
}

#[test]
fn password_file_is_wired_to_rar3_read_convert_and_edit() {
    let dir = TempDir::new("oxarchive_rar3_password");
    dir.write(
        "encrypted.rar",
        include_bytes!(
            "../../libarchive_oxide/tests/fixtures/rar-legacy/rarfile-rar3-data-password.rar"
        ),
    );
    password_file(&dir, "archive-password.txt", b"password");

    let listed = run_in(
        "oxarchive",
        &[
            "--json",
            "list",
            "--format",
            "rar-legacy",
            "--password-file",
            "archive-password.txt",
            "encrypted.rar",
        ],
        dir.path(),
    );
    assert_eq!(code(&listed), 0, "{listed:?}");
    let records = json_records(&listed);
    assert_eq!(records[1]["path"], "file1.txt");
    assert_eq!(records[2]["path"], "file2.txt");

    let converted = run_in(
        "oxarchive",
        &[
            "convert",
            "--from-format",
            "rar-legacy",
            "--password-file",
            "archive-password.txt",
            "encrypted.rar",
            "converted.tar",
        ],
        dir.path(),
    );
    assert_eq!(code(&converted), 0, "{converted:?}");

    let edited = run_in(
        "oxarchive",
        &[
            "edit",
            "--from-format",
            "rar-legacy",
            "--password-file",
            "archive-password.txt",
            "--rename",
            "file1.txt=renamed.txt",
            "encrypted.rar",
            "edited.tar",
        ],
        dir.path(),
    );
    assert_eq!(code(&edited), 0, "{edited:?}");

    for (archive, paths) in [
        ("converted.tar", ["file1.txt", "file2.txt"]),
        ("edited.tar", ["renamed.txt", "file2.txt"]),
    ] {
        let output = run_in("oxarchive", &["--json", "list", archive], dir.path());
        assert_eq!(code(&output), 0, "{archive}: {output:?}");
        let records = json_records(&output);
        assert_eq!(records[1]["path"], paths[0]);
        assert_eq!(records[2]["path"], paths[1]);
    }
}

#[test]
fn password_file_is_wired_to_rar5_read_extract_convert_and_edit() {
    let dir = TempDir::new("oxarchive_rar5_password");
    dir.write(
        "encrypted.rar",
        include_bytes!("../../libarchive_oxide/tests/fixtures/rar5/rarfile-rar5-data-password.rar"),
    );
    password_file(&dir, "archive-password.txt", b"password");

    let listed = run_in(
        "oxarchive",
        &[
            "--json",
            "list",
            "--format",
            "rar5",
            "--password-file",
            "archive-password.txt",
            "encrypted.rar",
        ],
        dir.path(),
    );
    assert_eq!(code(&listed), 0, "{listed:?}");
    let records = json_records(&listed);
    assert_eq!(records[1]["path"], "stest1.txt");
    assert_eq!(records[2]["path"], "stest2.txt");

    let extracted = run_in(
        "oxarchive",
        &[
            "extract",
            "--format",
            "rar5",
            "--password-file",
            "archive-password.txt",
            "encrypted.rar",
            "extracted",
        ],
        dir.path(),
    );
    assert_eq!(code(&extracted), 0, "{extracted:?}");
    let expected: Vec<u8> = (0..512)
        .flat_map(|value| format!("{value:03}\n").into_bytes())
        .collect();
    assert_eq!(
        std::fs::read(dir.join("extracted/stest1.txt")).expect("read decrypted RAR5 file"),
        expected
    );

    let converted = run_in(
        "oxarchive",
        &[
            "convert",
            "--from-format",
            "rar5",
            "--password-file",
            "archive-password.txt",
            "encrypted.rar",
            "converted.tar",
        ],
        dir.path(),
    );
    assert_eq!(code(&converted), 0, "{converted:?}");

    let edited = run_in(
        "oxarchive",
        &[
            "edit",
            "--from-format",
            "rar5",
            "--password-file",
            "archive-password.txt",
            "--rename",
            "stest1.txt=renamed.txt",
            "encrypted.rar",
            "edited.tar",
        ],
        dir.path(),
    );
    assert_eq!(code(&edited), 0, "{edited:?}");

    for (archive, paths) in [
        ("converted.tar", ["stest1.txt", "stest2.txt"]),
        ("edited.tar", ["renamed.txt", "stest2.txt"]),
    ] {
        let output = run_in("oxarchive", &["--json", "list", archive], dir.path());
        assert_eq!(code(&output), 0, "{archive}: {output:?}");
        let records = json_records(&output);
        assert_eq!(records[1]["path"], paths[0]);
        assert_eq!(records[2]["path"], paths[1]);
    }
}

#[test]
fn create_exposes_zip_compression_and_encryption_profiles() {
    let dir = TempDir::new("oxarchive_zip_profiles");
    dir.write("input.txt", b"selected ZIP profile payload");
    password_file(&dir, "archive-password.txt", PROCESS_SECRET.as_bytes());

    for (compression, encryption, archive, destination) in [
        ("ppmd8", "aes192", "aes-ppmd.zip", "aes-ppmd"),
        ("lzma", "zipcrypto", "legacy-lzma.zip", "legacy-lzma"),
    ] {
        let created = run_in(
            "oxarchive",
            &[
                "--json",
                "create",
                "--zip-compression",
                compression,
                "--zip-encryption",
                encryption,
                "--password-file",
                "archive-password.txt",
                archive,
                "input.txt",
            ],
            dir.path(),
        );
        assert_eq!(code(&created), 0, "{compression}/{encryption}: {created:?}");
        let record = json_output(&created);
        assert_eq!(record["zip_compression"], compression);
        assert_eq!(record["zip_encryption"], encryption);
        assert_secret_absent(&created, PROCESS_SECRET);

        let extracted = run_in(
            "oxarchive",
            &[
                "extract",
                "--password-file",
                "archive-password.txt",
                archive,
                destination,
            ],
            dir.path(),
        );
        assert_eq!(
            code(&extracted),
            0,
            "{compression}/{encryption}: {extracted:?}"
        );
        assert_eq!(
            std::fs::read(dir.join(&format!("{destination}/input.txt"))).unwrap(),
            b"selected ZIP profile payload"
        );
    }
}

#[test]
fn create_rejects_incoherent_zip_profile_options_before_io() {
    let dir = TempDir::new("oxarchive_zip_profile_errors");
    dir.write("input.txt", b"must not be archived");
    password_file(&dir, "archive-password.txt", PROCESS_SECRET.as_bytes());

    for args in [
        vec![
            "create",
            "--zip-encryption",
            "aes256",
            "missing-password.zip",
            "input.txt",
        ],
        vec![
            "create",
            "--zip-encryption",
            "none",
            "--password-file",
            "archive-password.txt",
            "plain.zip",
            "input.txt",
        ],
        vec![
            "create",
            "--format",
            "tar",
            "--zip-compression",
            "store",
            "wrong-format.tar",
            "input.txt",
        ],
    ] {
        let output = run_in("oxarchive", &args, dir.path());
        assert_eq!(code(&output), 2, "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert_secret_absent(&output, PROCESS_SECRET);
    }
    for path in ["missing-password.zip", "plain.zip", "wrong-format.tar"] {
        assert!(!dir.join(path).exists(), "{path} must not be created");
    }
}

#[test]
fn create_exposes_sevenz_coder_filter_solid_and_encryption_profiles() {
    let dir = TempDir::new("oxarchive_sevenz_profiles");
    dir.write("input.txt", b"selected 7z profile payload");
    password_file(&dir, "archive-password.txt", PROCESS_SECRET.as_bytes());

    let created = run_in(
        "oxarchive",
        &[
            "--json",
            "create",
            "--7z-compression",
            "deflate",
            "--7z-filter",
            "delta:3",
            "--7z-non-solid",
            "--7z-encryption",
            "aes256",
            "--password-file",
            "archive-password.txt",
            "selected.7z",
            "input.txt",
        ],
        dir.path(),
    );
    assert_eq!(code(&created), 0, "{created:?}");
    let record = json_output(&created);
    assert_eq!(record["sevenz_compression"], "deflate");
    assert_eq!(record["sevenz_filter"], "delta:3");
    assert_eq!(record["sevenz_solid"], false);
    assert_eq!(record["sevenz_encryption"], "aes256");
    assert_secret_absent(&created, PROCESS_SECRET);

    let extracted = run_in(
        "oxarchive",
        &[
            "extract",
            "--password-file",
            "archive-password.txt",
            "selected.7z",
            "out",
        ],
        dir.path(),
    );
    assert_eq!(code(&extracted), 0, "{extracted:?}");
    assert_eq!(
        std::fs::read(dir.join("out/input.txt")).unwrap(),
        b"selected 7z profile payload"
    );
}

#[test]
fn read_commands_explicitly_discover_adjacent_sevenz_volumes() {
    let dir = TempDir::new("oxarchive_sevenz_adjacent_volumes");
    dir.write("input.txt", b"bounded adjacent-volume payload");
    let created = run_in(
        "oxarchive",
        &["create", "--7z-non-solid", "complete.7z", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&created), 0, "{created:?}");
    let archive = std::fs::read(dir.join("complete.7z")).expect("read complete 7z");
    assert!(archive.chunks(31).count() > 2, "fixture must span volumes");
    for (index, part) in archive.chunks(31).enumerate() {
        dir.write(&format!("bundle.7z.{:03}", index + 1), part);
    }
    std::fs::remove_file(dir.join("complete.7z")).expect("remove complete archive");

    let implicit = run_in("oxarchive", &["verify", "bundle.7z.001"], dir.path());
    assert_eq!(
        code(&implicit),
        1,
        "discovery must not be implicit: {implicit:?}"
    );

    for command in ["list", "inspect", "plan", "verify"] {
        let output = run_in(
            "oxarchive",
            &[command, "--discover-volumes", "bundle.7z.001"],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{command}: {output:?}");
    }
    let explicit = run_in(
        "oxarchive",
        &[
            "verify",
            "--format",
            "7z",
            "--discover-volumes",
            "bundle.7z.001",
        ],
        dir.path(),
    );
    assert_eq!(code(&explicit), 0, "{explicit:?}");
    for (command, destination) in [("apply", "applied"), ("extract", "extracted")] {
        let output = run_in(
            "oxarchive",
            &[command, "--discover-volumes", "bundle.7z.001", destination],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{command}: {output:?}");
        assert_eq!(
            std::fs::read(dir.join(&format!("{destination}/input.txt")))
                .expect("read extracted split payload"),
            b"bounded adjacent-volume payload"
        );
    }

    for args in [
        &["verify", "--discover-volumes", "-"][..],
        &[
            "verify",
            "--discover-volumes",
            "--discover-volumes",
            "bundle.7z.001",
        ][..],
        &[
            "verify",
            "--format",
            "tar",
            "--discover-volumes",
            "bundle.7z.001",
        ][..],
    ] {
        let output = run_in("oxarchive", args, dir.path());
        assert_eq!(code(&output), 2, "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
    }
}

#[test]
fn read_commands_explicitly_discover_adjacent_rar_volumes() {
    let dir = TempDir::new("oxarchive_rar_adjacent_volumes");
    dir.write(
        "bundle.part001.rar",
        &rar5_volume(0, true, b"first.txt", b"first RAR volume"),
    );
    dir.write(
        "bundle.part002.rar",
        &rar5_volume(1, false, b"second.txt", b"second RAR volume"),
    );

    for command in ["list", "inspect", "plan", "verify"] {
        let output = run_in(
            "oxarchive",
            &[
                command,
                "--discover-volumes",
                "--format",
                "rar5",
                "bundle.part001.rar",
            ],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{command}: {output:?}");
    }
    let extracted = run_in(
        "oxarchive",
        &[
            "extract",
            "--discover-volumes",
            "bundle.part001.rar",
            "rar-out",
        ],
        dir.path(),
    );
    assert_eq!(code(&extracted), 0, "{extracted:?}");
    assert_eq!(
        std::fs::read(dir.join("rar-out/first.txt")).expect("read first RAR payload"),
        b"first RAR volume"
    );
    assert_eq!(
        std::fs::read(dir.join("rar-out/second.txt")).expect("read second RAR payload"),
        b"second RAR volume"
    );
}

#[test]
fn read_commands_explicitly_discover_standard_split_zip_volumes() {
    let dir = TempDir::new("oxarchive_zip_adjacent_volumes");
    let [first, terminal] = split_zip_store(b"split.txt", b"standard split ZIP payload");
    dir.write("bundle.z01", &first);
    dir.write("bundle.zip", &terminal);

    for command in ["list", "inspect", "plan", "verify"] {
        let output = run_in(
            "oxarchive",
            &[command, "--discover-volumes", "bundle.zip"],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{command}: {output:?}");
    }
    let extracted = run_in(
        "oxarchive",
        &[
            "extract",
            "--discover-volumes",
            "--format",
            "zip",
            "bundle.zip",
            "zip-out",
        ],
        dir.path(),
    );
    assert_eq!(code(&extracted), 0, "{extracted:?}");
    assert_eq!(
        std::fs::read(dir.join("zip-out/split.txt")).expect("read split ZIP payload"),
        b"standard split ZIP payload"
    );
}

#[test]
fn create_rejects_incoherent_sevenz_profile_options_before_io() {
    let dir = TempDir::new("oxarchive_sevenz_profile_errors");
    dir.write("input.txt", b"must not be archived");
    password_file(&dir, "archive-password.txt", PROCESS_SECRET.as_bytes());

    for args in [
        vec![
            "create",
            "--7z-encryption",
            "aes256",
            "missing-password.7z",
            "input.txt",
        ],
        vec![
            "create",
            "--7z-encryption",
            "none",
            "--password-file",
            "archive-password.txt",
            "plain.7z",
            "input.txt",
        ],
        vec![
            "create",
            "--format",
            "tar",
            "--7z-compression",
            "lzma2",
            "wrong-format.tar",
            "input.txt",
        ],
        vec![
            "create",
            "--7z-solid",
            "--7z-non-solid",
            "contradictory.7z",
            "input.txt",
        ],
        vec![
            "create",
            "--7z-filter",
            "delta:257",
            "bad-delta.7z",
            "input.txt",
        ],
    ] {
        let output = run_in("oxarchive", &args, dir.path());
        assert_eq!(code(&output), 2, "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert_secret_absent(&output, PROCESS_SECRET);
    }
    for path in [
        "missing-password.7z",
        "plain.7z",
        "wrong-format.tar",
        "contradictory.7z",
        "bad-delta.7z",
    ] {
        assert!(!dir.join(path).exists(), "{path} must not be created");
    }
}

#[test]
fn wrong_and_argv_passwords_are_never_exposed() {
    let dir = TempDir::new("oxarchive_password_redaction");
    let created = create_protected_zip(&dir);
    assert_eq!(code(&created), 0, "{created:?}");
    password_file(&dir, "wrong-password.txt", WRONG_PROCESS_SECRET.as_bytes());
    let wrong = run_in(
        "oxarchive",
        &[
            "--json",
            "verify",
            "--password-file",
            "wrong-password.txt",
            "protected.zip",
        ],
        dir.path(),
    );
    assert_eq!(code(&wrong), 1, "{wrong:?}");
    for secret in [PROCESS_SECRET, WRONG_PROCESS_SECRET] {
        assert_secret_absent(&wrong, secret);
    }

    for args in [
        vec!["verify", "--password", PROCESS_SECRET, "missing.zip"],
        vec![
            "verify",
            "--password=process-secret-never-print-this",
            "missing.zip",
        ],
        vec!["verify", "-Pprocess-secret-never-print-this", "missing.zip"],
        vec!["--help", "-P", PROCESS_SECRET],
    ] {
        let output = run_in("oxarchive", &args, dir.path());
        assert_eq!(code(&output), 2, "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert_secret_absent(&output, PROCESS_SECRET);
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("password values in command-line arguments are refused")
        );
    }
}

#[test]
fn password_prompt_refuses_non_tty_and_archive_stdin_conflicts() {
    let dir = TempDir::new("oxarchive_password_prompt");
    let created = create_protected_zip(&dir);
    assert_eq!(code(&created), 0, "{created:?}");
    let no_tty = run_without_tty(
        &["verify", "--password-prompt", "protected.zip"],
        dir.path(),
    );
    assert_eq!(code(&no_tty), 2, "{no_tty:?}");
    assert!(String::from_utf8_lossy(&no_tty.stderr).contains("requires an interactive TTY"));

    let stdin_conflict = run_stdin(
        "oxarchive",
        &["verify", "--password-prompt", "-"],
        dir.path(),
        b"not consumed",
    );
    assert_eq!(code(&stdin_conflict), 2, "{stdin_conflict:?}");
    assert!(
        String::from_utf8_lossy(&stdin_conflict.stderr)
            .contains("cannot be combined with archive input")
    );
}

#[test]
fn password_files_reject_empty_oversized_and_non_regular_inputs() {
    let dir = TempDir::new("oxarchive_password_limits");
    password_file(&dir, "empty.secret", b"");
    password_file(&dir, "newline.secret", b"\r\n");
    password_file(&dir, "oversized.secret", &vec![b'x'; 64 * 1024 + 1]);
    std::fs::create_dir_all(dir.join("directory.secret")).expect("password directory");

    for (path, expected) in [
        ("empty.secret", "must not be empty"),
        ("newline.secret", "must not be empty"),
        ("oversized.secret", "exceeds the 64 KiB safety limit"),
        ("directory.secret", "must be a regular file"),
        ("-", "--password-file - is refused"),
    ] {
        let output = run_in(
            "oxarchive",
            &["verify", "--password-file", path, "missing.zip"],
            dir.path(),
        );
        assert_eq!(code(&output), 2, "{path}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "{path}: {output:?}"
        );
    }

    let duplicate = run_in(
        "oxarchive",
        &[
            "verify",
            "--password-file",
            "empty.secret",
            "--password-prompt",
            "missing.zip",
        ],
        dir.path(),
    );
    assert_eq!(code(&duplicate), 2, "{duplicate:?}");
    assert!(
        String::from_utf8_lossy(&duplicate.stderr).contains("choose exactly one password source")
    );
}

#[cfg(unix)]
#[test]
fn password_file_refuses_group_or_other_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new("oxarchive_password_permissions");
    let path = password_file(&dir, "readable.secret", b"not-exposed");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
        .expect("make password file insecure");
    let output = run_in(
        "oxarchive",
        &[
            "verify",
            "--password-file",
            "readable.secret",
            "missing.zip",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("permissions must deny all group"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("not-exposed"));
}

#[test]
fn inspect_and_verify_cover_stream_and_seek_formats() {
    let dir = TempDir::new("oxarchive_inspect");
    let gzip = archive(
        FormatId::Tar,
        Some(FilterId::Gzip),
        b"stream.txt",
        b"stream",
    );
    let gzip_path = dir.write("stream.tar.gz", &gzip);
    let output = run_in(
        "oxarchive",
        &[
            "--json",
            "inspect",
            gzip_path.to_str().expect("UTF-8 test path"),
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let records = json_records(&output);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["schema_version"], "oxarchive.output.v0alpha1");
    assert_eq!(records[0]["type"], "inspect_start");
    assert_eq!(records[1]["type"], "inspect_entry");
    assert_eq!(records[1]["path"], "stream.txt");
    assert_eq!(records[2]["type"], "inspect_complete");
    assert_eq!(records[2]["format"], "tar");
    assert_eq!(records[2]["entry_count"], 1);
    assert_eq!(records[2]["complete"], true);

    let zip = archive(FormatId::Zip, None, b"seek.txt", b"seek-body");
    let output = run_stdin("oxarchive", &["verify", "--json", "-"], dir.path(), &zip);
    assert_eq!(code(&output), 0, "{output:?}");
    let value = json_output(&output);
    assert_eq!(value["type"], "verify");
    assert_eq!(value["format"], "zip");
    assert_eq!(value["entries"], 1);
    assert_eq!(value["payload_bytes"], 9);
    assert_eq!(value["verified"], true);
}

#[test]
fn explicit_rar5_inspects_sfx_store_archive() {
    let dir = TempDir::new("oxarchive_rar5");
    let mut sfx = vec![0x90; 4097];
    sfx.extend_from_slice(&rar5_store(b"cli.txt", b"rar payload"));
    let output = run_stdin(
        "oxarchive",
        &["--json", "inspect", "--format", "rar5", "-"],
        dir.path(),
        &sfx,
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let records = json_records(&output);
    assert_eq!(records.len(), 3);
    assert_eq!(records[1]["path"], "cli.txt");
    assert_eq!(records[1]["size"], 11);
    assert_eq!(records[2]["format"], "rar5");
    assert_eq!(records[2]["entry_count"], 1);
}

#[test]
fn explicit_rar_legacy_inspects_sfx_store_archive() {
    let dir = TempDir::new("oxarchive_rar_legacy");
    let mut sfx = vec![0x90; 4097];
    sfx.extend_from_slice(&rar_legacy_store(b"legacy.txt", b"rar4 payload"));
    let output = run_stdin(
        "oxarchive",
        &["--json", "inspect", "--format", "rar-legacy", "-"],
        dir.path(),
        &sfx,
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let records = json_records(&output);
    assert_eq!(records.len(), 3);
    assert_eq!(records[1]["path"], "legacy.txt");
    assert_eq!(records[1]["size"], 12);
    assert_eq!(records[2]["format"], "rar-legacy");
    assert_eq!(records[2]["entry_count"], 1);
}

#[test]
fn signatureless_raw_requires_explicit_selection_across_read_commands() {
    let dir = TempDir::new("oxarchive_raw");
    let payload = b"plain bytes without an archive signature";
    let raw_path = dir.write("payload.bin", payload);
    let raw_arg = raw_path.to_str().expect("UTF-8 test path");

    let output = run_in(
        "oxarchive",
        &["--json", "inspect", "--format", "raw", raw_arg],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let records = json_records(&output);
    assert_eq!(records.len(), 3);
    assert_eq!(records[1]["type"], "inspect_entry");
    assert_eq!(records[1]["path"], "data");
    assert_eq!(records[1]["size"], Value::Null);
    assert_eq!(records[2]["type"], "inspect_complete");
    assert_eq!(records[2]["format"], "raw");
    assert_eq!(records[2]["entry_count"], 1);

    let output = run_stdin(
        "oxarchive",
        &["verify", "--json", "--format=raw", "-"],
        dir.path(),
        payload,
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let value = json_output(&output);
    assert_eq!(value["format"], "raw");
    assert_eq!(value["entries"], 1);
    assert_eq!(value["payload_bytes"], payload.len());
    assert_eq!(value["verified"], true);

    let output = run_in(
        "oxarchive",
        &["plan", "--json", "--format", "raw", raw_arg],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    let value = json_output(&output);
    assert_eq!(value["format"], "raw");
    assert_eq!(value["entries"][0]["path"], "data");

    let output = run_in(
        "oxarchive",
        &["extract", "--format", "raw", raw_arg, "destination"],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert_eq!(
        std::fs::read(dir.join("destination/data")).expect("extracted raw payload"),
        payload
    );

    let output = run_in("oxarchive", &["--json", "inspect", raw_arg], dir.path());
    assert_eq!(code(&output), 1, "{output:?}");
    let records = json_records(&output);
    assert_eq!(records.len(), 1, "{output:?}");
    assert_eq!(records[0]["type"], "inspect_start");

    let mismatch = run_in(
        "oxarchive",
        &["inspect", "--format", "zip", raw_arg],
        dir.path(),
    );
    assert_eq!(code(&mismatch), 1, "{mismatch:?}");
    assert!(
        mismatch.stdout.starts_with(b"inspect-start\t"),
        "{mismatch:?}"
    );
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("Malformed archive error in zip"));

    for args in [
        &["verify", "--format=unknown", raw_arg][..],
        &["plan", "--format", "raw", "--format=raw", raw_arg][..],
    ] {
        let output = run_in("oxarchive", args, dir.path());
        assert_eq!(code(&output), 2, "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
    }
}

#[test]
fn advisory_plan_and_apply_keep_rejections_visible() {
    let dir = TempDir::new("oxarchive_reject");
    let archive = archive(FormatId::Tar, None, b"../escape", b"blocked");
    let archive_path = dir.write("unsafe.tar", &archive);
    let archive_arg = archive_path.to_str().expect("UTF-8 test path");

    let output = run_in("oxarchive", &["plan", "--json", archive_arg], dir.path());
    assert_eq!(code(&output), 0, "{output:?}");
    let value = json_output(&output);
    assert_eq!(value["type"], "plan");
    assert_eq!(value["reusable"], false);
    assert_eq!(value["policy"]["symlinks"], false);
    assert_eq!(value["entries"][0]["disposition"], "reject:unsafepath");

    let output = run_in(
        "oxarchive",
        &["apply", "--json", archive_arg, "destination"],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let value = json_output(&output);
    assert_eq!(value["type"], "apply");
    assert_eq!(value["rejected"], true);
    assert!(!dir.join("escape").exists());
}

#[test]
fn safe_apply_materializes_through_the_engine() {
    let dir = TempDir::new("oxarchive_apply");
    let archive = archive(FormatId::Tar, None, b"nested/file.txt", b"payload");
    let archive_path = dir.write("safe.tar", &archive);
    let output = run_in(
        "oxarchive",
        &[
            "apply",
            archive_path.to_str().expect("UTF-8 test path"),
            "destination",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert_eq!(
        std::fs::read(dir.join("destination/nested/file.txt")).expect("read applied file"),
        b"payload"
    );
}

#[test]
fn malformed_and_duplicate_json_flags_have_stable_exit_codes() {
    let dir = TempDir::new("oxarchive_errors");
    dir.write("bad.bin", b"not an archive");

    let output = run_in("oxarchive", &["verify", "bad.bin"], dir.path());
    assert_eq!(code(&output), 1, "{output:?}");

    let output = run_in(
        "oxarchive",
        &["--json", "inspect", "--json", "bad.bin"],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
}

#[test]
fn create_streams_through_common_options_to_file_and_stdout() {
    let dir = TempDir::new("oxarchive_create");
    dir.write("input.txt", b"created payload");
    let output = run_in(
        "oxarchive",
        &[
            "create",
            "--json",
            "--format",
            "tar",
            "--filter",
            "gzip",
            "bundle.tar.gz",
            "input.txt",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let status = json_output(&output);
    assert_eq!(status["type"], "create");
    assert_eq!(status["format"], "tar");
    assert_eq!(status["filter"], "gzip");
    assert_eq!(status["complete"], true);
    assert_eq!(
        &std::fs::read(dir.join("bundle.tar.gz")).expect("created archive")[..2],
        &[0x1f, 0x8b]
    );

    let inspected = run_in(
        "oxarchive",
        &["--json", "inspect", "bundle.tar.gz"],
        dir.path(),
    );
    assert_eq!(code(&inspected), 0, "{inspected:?}");
    let records = json_records(&inspected);
    assert_eq!(records[1]["path"], "input.txt");
    assert_eq!(records.last().expect("complete")["complete"], true);

    let output = run_in(
        "oxarchive",
        &["create", "--format", "zip", "-", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert!(output.stdout.starts_with(b"PK"));
    dir.write("stdout.zip", &output.stdout);
    let inspected = run_in(
        "oxarchive",
        &["--json", "inspect", "stdout.zip"],
        dir.path(),
    );
    assert_eq!(code(&inspected), 0, "{inspected:?}");
    assert_eq!(json_records(&inspected)[1]["path"], "input.txt");

    dir.write("--help", b"dash operand");
    let output = run_in(
        "oxarchive",
        &["create", "--format", "tar", "dash-name.tar", "--", "--help"],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "dash-prefixed input: {output:?}");
    for (format, archive_name) in [("cpio", "created.cpio"), ("ar", "created.a")] {
        let output = run_in(
            "oxarchive",
            &["create", "--format", format, archive_name, "input.txt"],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{format}: {output:?}");
        let inspected = run_in(
            "oxarchive",
            &["--json", "inspect", archive_name],
            dir.path(),
        );
        assert_eq!(code(&inspected), 0, "{format}: {inspected:?}");
        let records = json_records(&inspected);
        assert_eq!(records[1]["path"], "input.txt");
        assert_eq!(records.last().expect("complete")["format"], format);
    }
}

#[test]
fn create_seek_formats_use_atomic_files_and_shared_inspection() {
    let dir = TempDir::new("oxarchive_create_seek");
    dir.write("input.txt", b"seek CLI payload");

    for (format, archive_name) in [
        ("xar", "created.xar"),
        ("7z", "created.7z"),
        ("iso9660", "created.iso"),
    ] {
        let output = run_in(
            "oxarchive",
            &["--json", "create", archive_name, "input.txt"],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{format}: {output:?}");
        assert_eq!(json_output(&output)["format"], format);

        let inspected = run_in(
            "oxarchive",
            &["--json", "inspect", archive_name],
            dir.path(),
        );
        assert_eq!(code(&inspected), 0, "{format}: {inspected:?}");
        let records = json_records(&inspected);
        assert_eq!(records[1]["path"], "input.txt");
        assert_eq!(records.last().expect("complete")["format"], format);
    }

    let stdout = run_in(
        "oxarchive",
        &["create", "--format", "xar", "-", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&stdout), 2, "{stdout:?}");
    assert_eq!(stdout.stdout, [] as [u8; 0]);

    let filtered = run_in(
        "oxarchive",
        &[
            "create",
            "--format",
            "xar",
            "--filter",
            "gzip",
            "filtered.xar",
            "input.txt",
        ],
        dir.path(),
    );
    assert_eq!(code(&filtered), 2, "{filtered:?}");
    assert!(!dir.join("filtered.xar").exists());
}

#[test]
fn create_exposes_xar_compression_profiles() {
    let dir = TempDir::new("oxarchive_xar_profiles");
    dir.write(
        "input.txt",
        &b"selected XAR compression profile\n".repeat(2048),
    );

    for (compression, archive) in [("zlib", "zlib.xar"), ("bzip2", "bzip2.xar")] {
        let created = run_in(
            "oxarchive",
            &[
                "--json",
                "create",
                "--xar-compression",
                compression,
                archive,
                "input.txt",
            ],
            dir.path(),
        );
        assert_eq!(code(&created), 0, "{compression}: {created:?}");
        assert_eq!(json_output(&created)["xar_compression"], compression);

        let verified = run_in("oxarchive", &["verify", archive], dir.path());
        assert_eq!(code(&verified), 0, "{compression}: {verified:?}");
    }

    let wrong_format = run_in(
        "oxarchive",
        &[
            "create",
            "--format",
            "tar",
            "--xar-compression",
            "zlib",
            "wrong.tar",
            "input.txt",
        ],
        dir.path(),
    );
    assert_eq!(code(&wrong_format), 2, "{wrong_format:?}");
    assert!(!dir.join("wrong.tar").exists());
}

#[test]
fn create_base64_filter_is_a_thin_library_wrapper() {
    let dir = TempDir::new("oxarchive_create_base64");
    dir.write("input.txt", b"created payload");
    let output = run_in(
        "oxarchive",
        &[
            "create",
            "--json",
            "--format",
            "tar",
            "--filter",
            "base64",
            "bundle.tar.b64",
            "input.txt",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert_eq!(json_output(&output)["filter"], "base64");

    let encoded = std::fs::read(dir.join("bundle.tar.b64")).expect("Base64 archive");
    let filtered = FilterReader::with_filter(encoded.as_slice(), FilterId::Base64, Limits::safe())
        .expect("explicit Base64 filter");
    let mut reader = ArchiveReader::new(filtered);
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("read Base64 CLI archive") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unexpected CLI Base64 archive event"),
        }
    }
    assert_eq!(payload, b"created payload");
}

#[test]
fn create_uuencode_filter_is_inferred_and_is_a_thin_library_wrapper() {
    let dir = TempDir::new("oxarchive_create_uuencode");
    dir.write("input.txt", b"created payload");
    let output = run_in(
        "oxarchive",
        &["create", "--json", "bundle.tar.uue", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert_eq!(json_output(&output)["filter"], "uuencode");

    let encoded = std::fs::read(dir.join("bundle.tar.uue")).expect("uuencode archive");
    assert!(encoded.starts_with(b"begin 644 -\n"));
    let filtered = FilterReader::new(encoded.as_slice()).expect("auto-detected uuencode filter");
    let mut reader = ArchiveReader::new(filtered);
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("read uuencode CLI archive") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unexpected CLI uuencode archive event"),
        }
    }
    assert_eq!(payload, b"created payload");
}

#[test]
fn create_lzma_filter_is_inferred_and_is_a_thin_library_wrapper() {
    let dir = TempDir::new("oxarchive_create_lzma");
    dir.write("input.txt", b"created payload");
    let output = run_in(
        "oxarchive",
        &["create", "--json", "bundle.tar.lzma", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert_eq!(json_output(&output)["filter"], "lzma-alone");

    let encoded = std::fs::read(dir.join("bundle.tar.lzma")).expect("LZMA archive");
    let filtered = FilterReader::with_filter(encoded.as_slice(), FilterId::Lzma, Limits::safe())
        .expect("explicit LZMA filter");
    let mut reader = ArchiveReader::new(filtered);
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("read LZMA CLI archive") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unexpected CLI LZMA archive event"),
        }
    }
    assert_eq!(payload, b"created payload");
}

#[test]
fn create_lzip_filter_is_inferred_and_is_a_thin_library_wrapper() {
    let dir = TempDir::new("oxarchive_create_lzip");
    dir.write("input.txt", b"created payload");
    let output = run_in(
        "oxarchive",
        &["create", "--json", "bundle.tar.lz", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert_eq!(json_output(&output)["filter"], "lzip");

    let encoded = std::fs::read(dir.join("bundle.tar.lz")).expect("lzip archive");
    let filtered = FilterReader::new(encoded.as_slice()).expect("auto-detected lzip filter");
    let mut reader = ArchiveReader::new(filtered);
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("read lzip CLI archive") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unexpected CLI lzip archive event"),
        }
    }
    assert_eq!(payload, b"created payload");
}

#[test]
fn create_lzop_filter_is_inferred_and_is_a_thin_library_wrapper() {
    let dir = TempDir::new("oxarchive_create_lzop");
    dir.write("input.txt", b"created payload");
    let output = run_in(
        "oxarchive",
        &["create", "--json", "bundle.tar.lzo", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert_eq!(json_output(&output)["filter"], "lzop");

    let encoded = std::fs::read(dir.join("bundle.tar.lzo")).expect("lzop archive");
    assert!(encoded.starts_with(b"\x89LZO\0\r\n\x1a\n"));
    let filtered = FilterReader::new(encoded.as_slice()).expect("auto-detected lzop filter");
    let mut reader = ArchiveReader::new(filtered);
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("read lzop CLI archive") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unexpected CLI lzop archive event"),
        }
    }
    assert_eq!(payload, b"created payload");
}

#[test]
fn create_compress_filter_is_inferred_and_is_a_thin_library_wrapper() {
    let dir = TempDir::new("oxarchive_create_compress");
    dir.write("input.txt", b"created payload");
    let output = run_in(
        "oxarchive",
        &["create", "--json", "bundle.tar.Z", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 0, "{output:?}");
    assert_eq!(json_output(&output)["filter"], "compress");

    let encoded = std::fs::read(dir.join("bundle.tar.Z")).expect("compress archive");
    assert!(encoded.starts_with(&[0x1f, 0x9d, 0x90]));
    let mut reader = ArchiveReader::new(encoded.as_slice());
    let mut payload = Vec::new();
    loop {
        match reader.next_event().expect("read compress CLI archive") {
            ReaderEvent::Data(bytes) => payload.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unexpected CLI compress archive event"),
        }
    }
    assert_eq!(payload, b"created payload");
}

#[test]
fn create_and_read_mtree_through_explicit_and_inferred_cli_formats() {
    let dir = TempDir::new("oxarchive_mtree");
    dir.write("input.txt", b"described payload");

    let explicit = run_in(
        "oxarchive",
        &[
            "--json",
            "create",
            "--format",
            "mtree",
            "explicit.mtree",
            "input.txt",
        ],
        dir.path(),
    );
    assert_eq!(code(&explicit), 0, "{explicit:?}");
    assert_eq!(json_output(&explicit)["format"], "mtree");
    let manifest = std::fs::read(dir.join("explicit.mtree")).expect("created mtree");
    assert!(manifest.starts_with(b"#mtree v2.0\n"));
    assert!(
        !manifest
            .windows(17)
            .any(|window| window == b"described payload")
    );

    let inspected = run_in(
        "oxarchive",
        &["--json", "inspect", "--format", "mtree", "explicit.mtree"],
        dir.path(),
    );
    assert_eq!(code(&inspected), 0, "{inspected:?}");
    let records = json_records(&inspected);
    assert_eq!(records[1]["path"], "input.txt");
    assert_eq!(records.last().expect("complete")["format"], "mtree");

    let inferred = run_in(
        "oxarchive",
        &["create", "inferred.mtree", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&inferred), 0, "{inferred:?}");
    assert!(dir.join("inferred.mtree").exists());
}

#[test]
fn inspects_lha_sfx_through_auto_and_explicit_cli_formats() {
    let dir = TempDir::new("oxarchive_lha_sfx");
    dir.write(
        "fixture.exe",
        &lha_sfx_store(b"nested/file.txt", b"LHA CLI payload"),
    );

    for arguments in [
        vec!["--json", "inspect", "fixture.exe"],
        vec!["--json", "inspect", "--format", "lha", "fixture.exe"],
    ] {
        let output = run_in("oxarchive", &arguments, dir.path());
        assert_eq!(code(&output), 0, "{output:?}");
        let records = json_records(&output);
        assert_eq!(records[1]["path"], "nested/file.txt");
        assert_eq!(records.last().expect("complete")["format"], "lha");
    }
}

#[test]
fn create_infers_extension_and_list_extract_aliases_use_the_unified_engine() {
    let dir = TempDir::new("oxarchive_inference");
    dir.write("input.txt", b"inferred payload");
    let created = run_in(
        "oxarchive",
        &["create", "inferred.tar.gz", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&created), 0, "{created:?}");
    assert_eq!(
        &std::fs::read(dir.join("inferred.tar.gz")).expect("created archive")[..2],
        &[0x1f, 0x8b]
    );

    let listed = run_in(
        "oxarchive",
        &["--json", "list", "inferred.tar.gz"],
        dir.path(),
    );
    assert_eq!(code(&listed), 0, "{listed:?}");
    assert_eq!(json_records(&listed)[1]["path"], "input.txt");

    let extracted = run_in(
        "oxarchive",
        &["extract", "inferred.tar.gz", "destination"],
        dir.path(),
    );
    assert_eq!(code(&extracted), 0, "{extracted:?}");
    assert_eq!(
        std::fs::read(dir.join("destination/input.txt")).expect("extracted file"),
        b"inferred payload"
    );

    let stdout_without_format = run_in("oxarchive", &["create", "-", "input.txt"], dir.path());
    assert_eq!(code(&stdout_without_format), 2, "{stdout_without_format:?}");
    assert_eq!(stdout_without_format.stdout.len(), 0);
}

#[test]
fn list_and_extract_unwrap_rpm_payload_through_the_library_engine() {
    let dir = TempDir::new("oxarchive_rpm_filter");
    let payload = archive(FormatId::Cpio, Some(FilterId::Gzip), b"rpm.txt", b"payload");
    dir.write("sample.rpm", &rpm_wrapper(&payload));

    let listed = run_in("oxarchive", &["--json", "list", "sample.rpm"], dir.path());
    assert_eq!(code(&listed), 0, "{listed:?}");
    assert_eq!(json_records(&listed)[1]["path"], "rpm.txt");

    let extracted = run_in(
        "oxarchive",
        &["extract", "sample.rpm", "destination"],
        dir.path(),
    );
    assert_eq!(code(&extracted), 0, "{extracted:?}");
    assert_eq!(
        std::fs::read(dir.join("destination/rpm.txt")).expect("RPM extracted file"),
        b"payload"
    );
}

#[test]
fn create_reproducible_is_byte_stable_and_rejects_duplicate_inputs() {
    let dir = TempDir::new("oxarchive_reproducible");
    dir.write("tree/z.txt", b"z");
    dir.write("tree/a.txt", b"a");

    for archive in ["first.tar", "second.tar"] {
        let output = run_in(
            "oxarchive",
            &["--json", "create", "--reproducible", archive, "tree"],
            dir.path(),
        );
        assert_eq!(code(&output), 0, "{output:?}");
        assert_eq!(json_output(&output)["metadata_profile"], "reproducible");
        // Rewriting the same bytes changes host metadata but not the archive.
        dir.write("tree/a.txt", b"a");
    }
    assert_eq!(
        std::fs::read(dir.join("first.tar")).expect("first archive"),
        std::fs::read(dir.join("second.tar")).expect("second archive")
    );

    let duplicate = run_in(
        "oxarchive",
        &[
            "create",
            "--reproducible",
            "duplicate.tar",
            "tree/a.txt",
            "tree/a.txt",
        ],
        dir.path(),
    );
    assert_eq!(code(&duplicate), 1, "{duplicate:?}");
    assert!(!dir.join("duplicate.tar").exists());
}

#[test]
fn create_file_failures_never_publish_or_replace_a_destination() {
    let dir = TempDir::new("oxarchive_create_atomic");
    dir.write("input.txt", b"payload");
    dir.write("existing.tar", b"external");

    let output = run_in(
        "oxarchive",
        &["create", "--format", "tar", "existing.tar", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    assert_eq!(
        std::fs::read(dir.join("existing.tar")).expect("existing destination"),
        b"external"
    );

    let output = run_in(
        "oxarchive",
        &[
            "create",
            "--format",
            "tar",
            "failed.tar",
            "input.txt",
            "missing.txt",
        ],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    assert!(!dir.join("failed.tar").exists());
    assert!(
        std::fs::read_dir(dir.path())
            .expect("directory")
            .all(|entry| !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".oxarchive-"))
    );

    dir.write("tree/member.txt", b"tree");
    let output = run_in(
        "oxarchive",
        &["create", "--format", "tar", "tree/archive.tar", "tree"],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    assert!(!dir.join("tree/archive.tar").exists());
}

#[test]
fn create_stdout_and_unsafe_path_failures_follow_the_partial_output_contract() {
    let dir = TempDir::new("oxarchive_create_partial");
    dir.write("input.txt", b"payload");
    let output = run_in(
        "oxarchive",
        &["create", "--format", "tar", "-", "input.txt", "missing.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    assert!(
        !output.stdout.is_empty(),
        "first entry should already be streamed"
    );
    assert_ne!(output.stderr.len(), 0);

    let output = run_in(
        "oxarchive",
        &["--json", "create", "--format", "tar", "-", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
    assert_eq!(output.stdout.len(), 0);

    dir.write("outside.txt", b"outside");
    std::fs::create_dir_all(dir.join("work")).expect("work directory");
    let output = run_in(
        "oxarchive",
        &["create", "--format", "tar", "unsafe.tar", "../outside.txt"],
        &dir.join("work"),
    );
    assert_eq!(code(&output), 1, "{output:?}");
    assert!(!dir.join("work/unsafe.tar").exists());
}

#[test]
fn inspect_json_stream_omits_completion_after_a_late_parser_error() {
    let dir = TempDir::new("oxarchive_inspect_partial");
    let mut malformed = archive_many(&[(b"first.txt", b"first"), (b"second.txt", b"second")]);
    malformed[1024] ^= 0xff;
    let output = run_stdin(
        "oxarchive",
        &["--json", "inspect", "-"],
        dir.path(),
        &malformed,
    );
    assert_eq!(code(&output), 1, "{output:?}");
    let records = json_records(&output);
    assert_eq!(records[0]["type"], "inspect_start");
    assert!(records.iter().any(|record| record["path"] == "first.txt"));
    assert!(
        records
            .iter()
            .all(|record| record["type"] != "inspect_complete")
    );
    assert_ne!(output.stderr.len(), 0);
}

#[test]
fn convert_uses_atomic_access_aware_transcoding_and_reports_metadata_loss() {
    let dir = TempDir::new("oxarchive_convert");
    dir.write(
        "source.tar",
        &archive(FormatId::Tar, None, b"payload.txt", b"converted"),
    );

    let converted = run_in(
        "oxarchive",
        &["--json", "convert", "source.tar", "output.xar"],
        dir.path(),
    );
    assert_eq!(code(&converted), 0, "{converted:?}");
    let record = json_output(&converted);
    assert_eq!(record["type"], "convert");
    assert_eq!(record["source_format"], "tar");
    assert_eq!(record["destination_format"], "xar");
    assert_eq!(record["entries"], 1);
    assert_eq!(record["payload_bytes"], 9);
    assert_eq!(record["metadata_losses"], serde_json::json!([]));

    let listed = run_in("oxarchive", &["--json", "list", "output.xar"], dir.path());
    assert_eq!(code(&listed), 0, "{listed:?}");
    assert_eq!(json_records(&listed)[1]["path"], "payload.txt");

    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("mode.txt"))
        .size(Some(0))
        .mode(Some(0o600))
        .owner(libarchive_oxide::Owner {
            uid: None,
            gid: None,
            user: Some(b"alice".to_vec()),
            group: None,
        })
        .try_build()
        .expect("valid mode metadata");
    let mut writer = ArchiveEngine::new()
        .create(Vec::new(), CreateOptions::new().with_format(FormatId::Tar))
        .expect("tar writer");
    writer.start_entry(&metadata).expect("start mode entry");
    writer.end_entry().expect("end mode entry");
    dir.write("mode.tar", &writer.finish().expect("finish mode tar"));

    let reported = run_in(
        "oxarchive",
        &["--json", "convert", "mode.tar", "reported.xar"],
        dir.path(),
    );
    assert_eq!(code(&reported), 0, "{reported:?}");
    assert_eq!(
        json_output(&reported)["metadata_losses"][0]["field"],
        "owner_names"
    );

    let rejected = run_in(
        "oxarchive",
        &[
            "convert",
            "--reject-metadata-loss",
            "mode.tar",
            "rejected.xar",
        ],
        dir.path(),
    );
    assert_eq!(code(&rejected), 1, "{rejected:?}");
    assert!(!dir.join("rejected.xar").exists());

    dir.write("existing.xar", b"external");
    let existing = run_in(
        "oxarchive",
        &["convert", "source.tar", "existing.xar"],
        dir.path(),
    );
    assert_eq!(code(&existing), 1, "{existing:?}");
    assert_eq!(
        std::fs::read(dir.join("existing.xar")).expect("existing output"),
        b"external"
    );
}

#[test]
fn convert_json_names_warc_synthesized_path_loss() {
    let dir = TempDir::new("oxarchive_convert_warc_path");
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("not-encoded"))
        .size(Some(0))
        .mode(Some(0o644))
        .extension(Extension::new(
            "warc",
            b"WARC-Type".to_vec(),
            b"resource".to_vec(),
        ))
        .extension(Extension::new(
            "warc",
            b"WARC-Record-ID".to_vec(),
            b"<urn:uuid:cli-path-loss>".to_vec(),
        ))
        .extension(Extension::new(
            "warc",
            b"WARC-Date".to_vec(),
            b"2026-08-15T00:00:00Z".to_vec(),
        ))
        .build();
    let mut writer = ArchiveEngine::new()
        .create(Vec::new(), CreateOptions::new().with_format(FormatId::Warc))
        .unwrap();
    writer.start_entry(&metadata).unwrap();
    writer.end_entry().unwrap();
    dir.write("source.warc", &writer.finish().unwrap());

    let converted = run_in(
        "oxarchive",
        &["--json", "convert", "source.warc", "output.warc"],
        dir.path(),
    );
    assert_eq!(code(&converted), 0, "{converted:?}");
    assert_eq!(
        json_output(&converted)["metadata_losses"][0]["field"],
        "entry_path"
    );
}

#[test]
fn edit_rewrites_atomically_and_fails_closed_on_bad_plans() {
    let dir = TempDir::new("oxarchive_edit");
    dir.write(
        "source.tar",
        &archive_many(&[(b"keep.txt", b"keep"), (b"drop.txt", b"drop")]),
    );

    let no_operations = run_in(
        "oxarchive",
        &["edit", "source.tar", "no-operations.tar"],
        dir.path(),
    );
    assert_eq!(code(&no_operations), 2, "{no_operations:?}");
    assert!(!dir.join("no-operations.tar").exists());

    let malformed = run_in(
        "oxarchive",
        &[
            "edit",
            "--rename",
            "missing-separator",
            "source.tar",
            "malformed.tar",
        ],
        dir.path(),
    );
    assert_eq!(code(&malformed), 2, "{malformed:?}");
    assert!(!dir.join("malformed.tar").exists());

    let edited = run_in(
        "oxarchive",
        &[
            "--json",
            "edit",
            "--rename",
            "keep.txt=renamed.txt",
            "--remove",
            "drop.txt",
            "source.tar",
            "edited.tar",
        ],
        dir.path(),
    );
    assert_eq!(code(&edited), 0, "{edited:?}");
    let record = json_output(&edited);
    assert_eq!(record["type"], "edit");
    assert_eq!(record["source_format"], "tar");
    assert_eq!(record["destination_format"], "tar");
    assert_eq!(record["source_entries"], 2);
    assert_eq!(record["entries"], 1);
    assert_eq!(record["removed_entries"], 1);
    assert_eq!(record["renamed_entries"], 1);
    assert_eq!(record["payload_bytes"], 4);
    assert_eq!(record["metadata_losses"], serde_json::json!([]));

    let listed = run_in("oxarchive", &["--json", "list", "edited.tar"], dir.path());
    assert_eq!(code(&listed), 0, "{listed:?}");
    let records = json_records(&listed);
    assert_eq!(records.len(), 3);
    assert_eq!(records[1]["path"], "renamed.txt");

    let missing = run_in(
        "oxarchive",
        &[
            "edit",
            "--remove",
            "missing.txt",
            "source.tar",
            "missing.tar",
        ],
        dir.path(),
    );
    assert_eq!(code(&missing), 1, "{missing:?}");
    assert!(!dir.join("missing.tar").exists());

    let unsafe_path = run_in(
        "oxarchive",
        &[
            "edit",
            "--rename=keep.txt=../escape.txt",
            "source.tar",
            "unsafe.tar",
        ],
        dir.path(),
    );
    assert_eq!(code(&unsafe_path), 1, "{unsafe_path:?}");
    assert!(!dir.join("unsafe.tar").exists());

    dir.write("existing.tar", b"external");
    let existing = run_in(
        "oxarchive",
        &["edit", "--remove", "drop.txt", "source.tar", "existing.tar"],
        dir.path(),
    );
    assert_eq!(code(&existing), 1, "{existing:?}");
    assert_eq!(
        std::fs::read(dir.join("existing.tar")).expect("existing output"),
        b"external"
    );
}
