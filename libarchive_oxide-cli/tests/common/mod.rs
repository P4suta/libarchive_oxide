//! Shared helpers for the `ox*` CLI integration tests: locating the built binaries, running them,
//! and managing throwaway working directories. No external test crates are used (keeping the
//! dependency footprint minimal); the bins are invoked through the `CARGO_BIN_EXE_*` paths Cargo
//! exports to integration tests, and asserted on via `std::process`.
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

/// Absolute path to a built `ox*` binary (`oxtar`/`oxcpio`/`oxcat`/`oxunzip`).
#[must_use]
pub(crate) fn bin(name: &str) -> PathBuf {
    // Cargo exposes each bin's path to its own package's integration tests.
    let var = match name {
        "oxtar" => env!("CARGO_BIN_EXE_oxtar"),
        "oxcpio" => env!("CARGO_BIN_EXE_oxcpio"),
        "oxcat" => env!("CARGO_BIN_EXE_oxcat"),
        "oxunzip" => env!("CARGO_BIN_EXE_oxunzip"),
        other => panic!("unknown bin {other}"),
    };
    PathBuf::from(var)
}

/// A throwaway working directory, removed on drop.
pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Creates a uniquely-named directory under the system temp dir.
    #[must_use]
    pub(crate) fn new(tag: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "oxcli_{tag}_{}_{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    /// The directory path.
    #[must_use]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Joins a relative path under this directory.
    #[must_use]
    pub(crate) fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }

    /// Writes a file (creating parent dirs) under this directory and returns its path.
    pub(crate) fn write(&self, rel: &str, contents: &[u8]) -> PathBuf {
        let p = self.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("create parents");
        }
        std::fs::write(&p, contents).expect("write file");
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Runs `bin` with `args` in `cwd`, returning the captured [`Output`].
pub(crate) fn run_in(bin_name: &str, args: &[&str], cwd: &Path) -> Output {
    Command::new(bin(bin_name))
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn bin")
}

/// Runs `bin` with `args` (no explicit cwd), returning the captured [`Output`].
pub(crate) fn run(bin_name: &str, args: &[&str]) -> Output {
    Command::new(bin(bin_name))
        .args(args)
        .output()
        .expect("spawn bin")
}

/// Runs `bin` in `cwd`, feeding `stdin_bytes` to stdin, returning the captured [`Output`].
pub(crate) fn run_stdin(bin_name: &str, args: &[&str], cwd: &Path, stdin_bytes: &[u8]) -> Output {
    use std::io::Write;
    let mut child = Command::new(bin(bin_name))
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn bin");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(stdin_bytes)
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

/// The process exit code, or `-1` if the process was signalled.
#[must_use]
pub(crate) fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

/// Whether an external tool is on `PATH` (probed via `--version`), for graceful-skip differential
/// tests. Mirrors the skip idiom used by the library's `*_differential.rs` suites.
#[must_use]
pub(crate) fn tool_present(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}
