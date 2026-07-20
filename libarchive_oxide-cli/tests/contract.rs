// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI-contract regression: the supported-flag surface and the unified exit-code contract
//! (0 success / 1 runtime failure / 2 usage-or-unsupported-flag). This is the machine-checkable
//! form of the `SemVer` interface promise in the README, and the guard that unsupported classic flags
//! fail loudly (exit 2) rather than silently no-op.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{TempDir, code, run, run_in};

/// `--help` / `--version` succeed for every tool (exit 0).
#[test]
fn help_and_version_succeed() {
    for tool in ["oxarchive", "oxtar", "oxcpio", "oxcat", "oxunzip"] {
        for argument in ["--help", "--version"] {
            let output = run(tool, &[argument]);
            assert_eq!(code(&output), 0, "{tool} {argument}");
            assert!(!output.stdout.is_empty(), "{tool} {argument} stdout");
            assert!(output.stderr.is_empty(), "{tool} {argument}: {output:?}");
        }
    }
}

/// Classic flags the library cannot honor faithfully must fail with a usage error (exit 2) and a
/// message carrying the greppable `unsupported:` prefix — never a silent no-op.
#[test]
fn unsupported_flags_exit_2() {
    let cases: &[(&str, &[&str])] = &[
        ("oxtar", &["-rf", "x.tar", "src"]), // -r append
        ("oxtar", &["-uf", "x.tar", "src"]), // -u update
        ("oxtar", &["-c", "--format", "zip", "-f", "x.tar", "s"]), // unsupported format
        ("oxcpio", &["-p"]),                 // pass-through
        ("oxcpio", &["-iC"]),                // block size
        ("oxunzip", &["-n", "a.zip"]),       // never-overwrite
        ("oxunzip", &["-x", "a.zip"]),       // exclude
    ];
    for (tool, args) in cases {
        let out = run(tool, args);
        assert_eq!(code(&out), 2, "{tool} {args:?} should be exit 2: {out:?}");
        let msg = String::from_utf8_lossy(&out.stderr);
        assert!(
            msg.contains("unsupported:"),
            "{tool} {args:?} missing 'unsupported:' prefix: {msg}"
        );
    }
}

/// Unknown flags and missing operands are usage errors (exit 2).
#[test]
fn usage_errors_exit_2() {
    let cases: &[(&str, &[&str])] = &[
        ("oxtar", &["--strip-components", "1", "-tf", "x.tar"]), // unknown long
        ("oxtar", &["-f", "x.tar"]),                             // no mode
        ("oxtar", &["-cf", "x.tar"]),                            // create with no inputs
        ("oxcpio", &["-v"]),                                     // no mode
        ("oxcat", &["--nope"]),                                  // unknown flag
        ("oxunzip", &["-l"]),                                    // missing archive operand
        ("oxunzip", &["--nope", "a.zip"]),                       // unknown long
        ("oxarchive", &["unknown"]),                             // unknown command
        ("oxarchive", &["inspect"]),                             // missing archive
        ("oxarchive", &["plan", "--unsafe", "a.tar"]),           // unknown policy
        ("oxarchive", &["create", "out.tar", "input"]),          // missing --format
        ("oxarchive", &["create", "--format", "rar", "out", "in"]),
        ("oxarchive", &["create", "--format", "tar", "out.tar"]),
    ];
    for (tool, args) in cases {
        let out = run(tool, args);
        assert_eq!(code(&out), 2, "{tool} {args:?} should be exit 2: {out:?}");
        assert!(
            out.stdout.is_empty(),
            "usage output leaked to stdout: {out:?}"
        );
        assert!(
            !out.stderr.is_empty(),
            "usage error missing stderr: {out:?}"
        );
    }
}

/// A valid invocation whose work fails (missing input file) is a runtime error (exit 1).
#[test]
fn runtime_errors_exit_1() {
    let dir = TempDir::new("contract_rt");
    let cases: &[(&str, &[&str])] = &[
        ("oxtar", &["-x", "-f", "nope.tar"]),
        ("oxtar", &["-t", "-f", "nope.tar"]),
        ("oxcpio", &["-i", "-F", "nope.cpio"]),
        ("oxcat", &["nope.gz"]),
        ("oxunzip", &["nope.zip"]),
        ("oxunzip", &["-l", "nope.zip"]),
        ("oxarchive", &["inspect", "nope.tar"]),
        (
            "oxarchive",
            &["create", "--format", "tar", "out.tar", "nope"],
        ),
    ];
    for (tool, args) in cases {
        let out = run_in(tool, args, dir.path());
        assert_eq!(code(&out), 1, "{tool} {args:?} should be exit 1: {out:?}");
        assert!(
            out.stdout.is_empty(),
            "runtime error leaked status to stdout: {out:?}"
        );
        assert!(
            !out.stderr.is_empty(),
            "runtime error missing stderr: {out:?}"
        );
    }
}

/// Every supported oxtar mode letter and compression selector parses to a successful create/read.
#[test]
fn supported_oxtar_flags_succeed() {
    let dir = TempDir::new("contract_ok");
    dir.write("src/f.txt", b"payload\n");
    for sel in [
        &["-c", "-f", "o.tar"][..],
        &["-c", "-z", "-f", "o.tgz"][..],
        &["-c", "-j", "-f", "o.tbz2"][..],
        &["-c", "-J", "-f", "o.tar.xz"][..],
        &["-c", "--zstd", "-f", "o.tar.zst"][..],
        &["-c", "--lz4", "-f", "o.tar.lz4"][..],
    ] {
        let mut args = sel.to_vec();
        args.extend_from_slice(&["-C", "src", "."]);
        let out = run_in("oxtar", &args, dir.path());
        assert_eq!(code(&out), 0, "create {sel:?}: {out:?}");
        let archive = sel[sel.len() - 1];
        let out = run_in("oxtar", &["-tf", archive], dir.path());
        assert_eq!(code(&out), 0, "list {archive}: {out:?}");
    }
}
