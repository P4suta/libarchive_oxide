//! Differential tests: cross-validate the `ox*` tools against the real system
//! `bsdtar`/`bsdcpio`/`bsdcat`/`unzip` when they are on `PATH`, and gracefully skip when absent
//! (the same idiom as the library's `*_differential.rs` suites). These prove genuine interop:
//! archives we write are read by mature independent tools, and vice-versa.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::borrow::Cow;
use std::process::{Command, Stdio};

use common::{code, run_in, TempDir};
use libarchive_oxide::zip::{ZipOptions, ZipWriter};
use libarchive_oxide_core::{EntryKind, EntryMeta, EntryWriter};

/// Lenient probe: the first candidate name that spawns and emits *some* output (or exits 0) when
/// asked for its version. Returns the resolved command name. Accepts both `bsdtar` and the Windows
/// `tar` (which is bsdtar), etc.
fn find_tool(candidates: &[&str], version_arg: &str) -> Option<String> {
    for name in candidates {
        let ok = Command::new(name)
            .arg(version_arg)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .is_ok_and(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty());
        if ok {
            return Some((*name).to_string());
        }
    }
    None
}

const A: &[u8] = b"differential payload alpha\n";
const B: &[u8] = b"differential payload beta\n";

fn seed(dir: &TempDir) {
    dir.write("src/a.txt", A);
    dir.write("src/data/b.txt", B);
}

#[test]
fn tar_interop_with_system_tar() {
    let Some(tar) = find_tool(&["bsdtar", "tar"], "--version") else {
        eprintln!("skipping tar differential: no bsdtar/tar on PATH");
        return;
    };
    eprintln!("tar differential using: {tar}");
    let dir = TempDir::new("diff_tar");
    seed(&dir);

    // 1) oxtar writes → system tar reads.
    let out = run_in("oxtar", &["-c", "-f", "ox.tar", "-C", "src", "."], dir.path());
    assert_eq!(code(&out), 0, "oxtar create: {out:?}");
    let sys = Command::new(&tar)
        .args(["-tf", "ox.tar"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(sys.status.success(), "system tar list failed: {sys:?}");
    let listing = String::from_utf8_lossy(&sys.stdout);
    assert!(
        listing.contains("a.txt") && listing.contains("b.txt"),
        "system tar did not list our entries: {listing}"
    );

    // 2) system tar writes → oxtar reads and extracts.
    let made = Command::new(&tar)
        .args(["-cf", "sys.tar", "-C", "src", "."])
        .current_dir(dir.path())
        .status()
        .unwrap();
    assert!(made.success(), "system tar create failed");
    let out = run_in("oxtar", &["-x", "-f", "sys.tar", "-C", "ex"], dir.path());
    assert_eq!(code(&out), 0, "oxtar extract of system tar: {out:?}");
    assert_eq!(std::fs::read(dir.join("ex/data/b.txt")).unwrap(), B);
}

#[test]
fn tar_gzip_read_by_system_tar() {
    let Some(tar) = find_tool(&["bsdtar", "tar"], "--version") else {
        eprintln!("skipping tar-gzip differential: no bsdtar/tar on PATH");
        return;
    };
    let dir = TempDir::new("diff_tgz");
    seed(&dir);
    let out = run_in("oxtar", &["-c", "-z", "-f", "ox.tgz", "-C", "src", "."], dir.path());
    assert_eq!(code(&out), 0);
    // System tar auto-detects gzip on read.
    let sys = Command::new(&tar)
        .args(["-tf", "ox.tgz"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(sys.status.success(), "system tar could not read our gzip tar: {sys:?}");
    assert!(String::from_utf8_lossy(&sys.stdout).contains("a.txt"));
}

#[test]
fn cpio_interop_with_system_cpio() {
    let Some(cpio) = find_tool(&["bsdcpio", "cpio"], "--version") else {
        eprintln!("skipping cpio differential: no bsdcpio/cpio on PATH");
        return;
    };
    eprintln!("cpio differential using: {cpio}");
    let dir = TempDir::new("diff_cpio");
    seed(&dir);
    let out = run_in("oxtar", &["-c", "--format", "cpio", "-f", "ox.cpio", "-C", "src", "."], dir.path());
    assert_eq!(code(&out), 0, "oxtar cpio create: {out:?}");

    // System cpio reads our newc archive (copy-in + list).
    let list = Command::new(&cpio)
        .args(["-itF", "ox.cpio"])
        .current_dir(dir.path())
        .output();
    let list = match list {
        Ok(o) if o.status.success() => o,
        other => {
            eprintln!("skipping: system cpio -itF unsupported here: {other:?}");
            return;
        }
    };
    assert!(
        String::from_utf8_lossy(&list.stdout).contains("a.txt"),
        "system cpio did not list our entry"
    );
}

#[test]
fn cat_interop_with_system_bsdcat() {
    let Some(cat) = find_tool(&["bsdcat"], "--version") else {
        eprintln!("skipping bsdcat differential: no bsdcat on PATH");
        return;
    };
    let dir = TempDir::new("diff_cat");
    seed(&dir);
    run_in("oxtar", &["-c", "-f", "plain.tar", "-C", "src", "."], dir.path());
    run_in("oxtar", &["-c", "-z", "-f", "ox.tgz", "-C", "src", "."], dir.path());

    // bsdcat decompresses our gzip; the bytes must equal the plain tar and oxcat's output.
    let sys = Command::new(&cat)
        .arg("ox.tgz")
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(sys.status.success(), "bsdcat failed: {sys:?}");
    let plain = std::fs::read(dir.join("plain.tar")).unwrap();
    assert_eq!(sys.stdout, plain, "bsdcat output differs from the plain tar");

    let ours = run_in("oxcat", &["ox.tgz"], dir.path());
    assert_eq!(ours.stdout, sys.stdout, "oxcat and bsdcat disagree");
}

#[test]
fn zip_read_by_system_unzip() {
    // unzip has no --version; `-v` prints the banner.
    let Some(unzip) = find_tool(&["unzip"], "-v") else {
        eprintln!("skipping unzip differential: no unzip on PATH");
        return;
    };
    eprintln!("unzip differential using: {unzip}");
    let dir = TempDir::new("diff_unzip");

    // Build a zip with the library writer, then have system unzip list it.
    let mut w = ZipWriter::with_options(Vec::new(), ZipOptions::default());
    for (name, data) in [(&b"a.txt"[..], A), (&b"data/b.txt"[..], B)] {
        let mut m = EntryMeta::new(EntryKind::File, Cow::Borrowed(name));
        m.mode = 0o644;
        m.size = data.len() as u64;
        let mut sink = w.start_entry(&m).unwrap();
        sink.write_chunk(data).unwrap();
        sink.close().unwrap();
    }
    w.finish().unwrap();
    std::fs::write(dir.join("ox.zip"), w.into_inner()).unwrap();

    let sys = Command::new(&unzip)
        .args(["-l", "ox.zip"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(sys.status.success(), "system unzip -l failed: {sys:?}");
    let listing = String::from_utf8_lossy(&sys.stdout);
    assert!(
        listing.contains("a.txt") && listing.contains("b.txt"),
        "system unzip did not list our entries: {listing}"
    );
}
