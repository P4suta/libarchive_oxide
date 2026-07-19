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
    for tool in ["oxtar", "oxcpio", "oxcat", "oxunzip"] {
        assert_eq!(code(&run(tool, &["--help"])), 0, "{tool} --help");
        assert_eq!(code(&run(tool, &["--version"])), 0, "{tool} --version");
    }
}

/// Classic flags the library cannot honor faithfully must fail with a usage error (exit 2) and a
/// message carrying the greppable `unsupported:` prefix — never a silent no-op.
#[test]
fn unsupported_flags_exit_2() {
    let cases: &[(&str, &[&str])] = &[
        ("oxtar", &["-cjf", "x.tar", "src"]),    // -j bzip2 removed
        ("oxtar", &["--bzip2", "-cf", "x.tar"]), // long bzip2
        ("oxtar", &["-rf", "x.tar", "src"]),     // -r append
        ("oxtar", &["-uf", "x.tar", "src"]),     // -u update
        ("oxtar", &["-c", "--format", "zip", "-f", "x.tar", "s"]), // unsupported format
        ("oxcpio", &["-p"]),                     // pass-through
        ("oxcpio", &["-iC"]),                    // block size
        ("oxunzip", &["-n", "a.zip"]),           // never-overwrite
        ("oxunzip", &["-x", "a.zip"]),           // exclude
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
    ];
    for (tool, args) in cases {
        let out = run(tool, args);
        assert_eq!(code(&out), 2, "{tool} {args:?} should be exit 2: {out:?}");
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
    ];
    for (tool, args) in cases {
        let out = run_in(tool, args, dir.path());
        assert_eq!(code(&out), 1, "{tool} {args:?} should be exit 1: {out:?}");
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
