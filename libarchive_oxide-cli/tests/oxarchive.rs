// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unified `oxarchive` command contract.

#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::process::{Command, Stdio};

use libarchive_oxide::{ArchiveEngine, CreateOptions};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, FilterId, FormatId};
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
    assert_eq!(zip_zstd["access"]["read"], "seek");
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
    assert!(lzip["access"]["write"].is_null());
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
    assert_eq!(lzip["portable"]["write"], false);
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
        assert!(text.contains("idsig-file"), "{shell}: {text}");
    }

    let output = run_in("oxarchive", &["man"], dir.path());
    assert_eq!(code(&output), 0, "{output:?}");
    let man = String::from_utf8_lossy(&output.stdout);
    assert!(man.starts_with(".TH OXARCHIVE 1"));
    assert!(man.contains("--password-file FILE"));
    assert!(man.contains("--password-prompt"));
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

    for args in [
        &["inspect", "--format", "zip", raw_arg][..],
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
    assert!(stdout_without_format.stdout.is_empty());
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
    assert!(!output.stderr.is_empty());

    let output = run_in(
        "oxarchive",
        &["--json", "create", "--format", "tar", "-", "input.txt"],
        dir.path(),
    );
    assert_eq!(code(&output), 2, "{output:?}");
    assert!(output.stdout.is_empty());

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
    assert!(!output.stderr.is_empty());
}
