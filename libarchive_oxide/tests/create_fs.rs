//! Round-trip test for `build_tar`: create a tar from a real directory tree, then read it back.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use libarchive_oxide::{build_tar, reader};
use libarchive_oxide_core::{EntryData, EntryReader};

fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("arca-create-{}-{tag}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    p
}

#[test]
fn build_tar_from_directory_round_trips() {
    let root = temp_dir("root");
    let proj = root.join("proj");
    fs::create_dir_all(proj.join("src")).unwrap();
    fs::write(proj.join("README.md"), b"# demo\n").unwrap();
    fs::write(proj.join("src/main.rs"), b"fn main() {}\n").unwrap();

    // An absolute input path keeps the test independent of the process cwd (which is shared
    // across parallel tests). Entry names then carry that prefix; we check the tail structure.
    let bytes = build_tar(&[proj.to_string_lossy().into_owned()]).unwrap();

    let mut r = reader(&bytes).unwrap();
    let mut names = Vec::new();
    while let Some(mut e) = r.next_entry().unwrap() {
        names.push(String::from_utf8(e.meta().path.to_vec()).unwrap());
        let mut buf = [0u8; 64];
        while e.data().read_chunk(&mut buf).unwrap() != 0 {}
    }

    assert_eq!(names.len(), 4);
    for tail in ["proj/", "proj/README.md", "proj/src/", "proj/src/main.rs"] {
        assert!(
            names.iter().any(|n| n.ends_with(tail)),
            "missing entry ending in {tail:?}; got {names:?}"
        );
    }

    let _ = fs::remove_dir_all(&root);
}
