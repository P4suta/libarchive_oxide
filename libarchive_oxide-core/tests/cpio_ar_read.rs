//! Integration tests for the cpio (newc/odc) and ar readers, using hand-built archives.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use libarchive_oxide_core::format::ar::ArReader;
use libarchive_oxide_core::format::cpio::CpioReader;
use libarchive_oxide_core::{Entry, EntryData, EntryKind, EntryReader};

const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;

fn drain<D: EntryData>(entry: &mut Entry<'_, D>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 8];
    loop {
        let n = entry.data().read_chunk(&mut tmp).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    out
}

/// Builds one SVR4 "newc" cpio entry (header + name + data, both 4-byte aligned).
fn newc(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
    let namesize = name.len() + 1;
    let mut h = Vec::new();
    h.extend_from_slice(b"070701");
    // ino, mode, uid, gid, nlink, mtime, filesize, devmaj, devmin, rdevmaj, rdevmin, namesize, check
    let filesize = u32::try_from(data.len()).unwrap();
    let namesize = u32::try_from(namesize).unwrap();
    for v in [0, mode, 0, 0, 1, 0, filesize, 0, 0, 0, 0, namesize, 0] {
        h.extend_from_slice(format!("{v:08x}").as_bytes());
    }
    h.extend_from_slice(name.as_bytes());
    h.push(0);
    while h.len() % 4 != 0 {
        h.push(0);
    }
    h.extend_from_slice(data);
    while h.len() % 4 != 0 {
        h.push(0);
    }
    h
}

/// Builds one POSIX "odc" cpio entry (octal fields, no padding).
fn odc(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
    let namesize = name.len() + 1;
    let mut h = Vec::new();
    h.extend_from_slice(b"070707");
    for v in [0, 0, mode, 0, 0, 1, 0] {
        h.extend_from_slice(format!("{v:06o}").as_bytes());
    }
    h.extend_from_slice(format!("{:011o}", 0).as_bytes()); // mtime
    h.extend_from_slice(format!("{namesize:06o}").as_bytes());
    h.extend_from_slice(format!("{:011o}", data.len()).as_bytes());
    h.extend_from_slice(name.as_bytes());
    h.push(0);
    h.extend_from_slice(data);
    h
}

/// Builds one ar member. `name_field` is the raw 16-byte name field content (caller includes
/// any trailing `/` or GNU `/N` reference).
fn ar_member(name_field: &str, data: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    let pad = |s: String, w: usize| {
        let mut b = s.into_bytes();
        b.resize(w, b' ');
        b
    };
    h.extend_from_slice(&pad(name_field.to_string(), 16));
    h.extend_from_slice(&pad("0".into(), 12)); // mtime
    h.extend_from_slice(&pad("0".into(), 6)); // uid
    h.extend_from_slice(&pad("0".into(), 6)); // gid
    h.extend_from_slice(&pad("100644".into(), 8)); // mode (octal)
    h.extend_from_slice(&pad(format!("{}", data.len()), 10)); // size (decimal)
    h.extend_from_slice(b"`\n");
    h.extend_from_slice(data);
    if data.len() % 2 == 1 {
        h.push(b'\n');
    }
    h
}

#[test]
fn cpio_newc_file_and_dir() {
    let mut ar = Vec::new();
    ar.extend(newc("hello.txt", S_IFREG | 0o644, b"cpio newc\n"));
    ar.extend(newc("adir", S_IFDIR | 0o755, b""));
    ar.extend(newc("TRAILER!!!", 0, b""));

    let mut r = CpioReader::new(&ar);
    {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"hello.txt");
        assert_eq!(e.meta().kind, EntryKind::File);
        assert_eq!(e.meta().mode, 0o644);
        assert_eq!(drain(&mut e), b"cpio newc\n");
    }
    {
        let e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"adir");
        assert_eq!(e.meta().kind, EntryKind::Dir);
    }
    assert!(r.next_entry().unwrap().is_none());
}

#[test]
fn cpio_odc_file() {
    let mut ar = Vec::new();
    ar.extend(odc("note.md", S_IFREG | 0o600, b"# odc"));
    ar.extend(odc("TRAILER!!!", 0, b""));

    let mut r = CpioReader::new(&ar);
    let mut e = r.next_entry().unwrap().unwrap();
    assert_eq!(e.meta().path.as_ref(), b"note.md");
    assert_eq!(e.meta().mode, 0o600);
    assert_eq!(drain(&mut e), b"# odc");
    assert!(r.next_entry().unwrap().is_none());
}

#[test]
fn ar_plain_members() {
    // Mimics the shape of a .deb: short GNU names with a trailing slash.
    let mut a = b"!<arch>\n".to_vec();
    a.extend(ar_member("debian-binary/", b"2.0\n"));
    a.extend(ar_member("control.tar/", b"CTRL")); // odd length -> padded
    a.extend(ar_member("data.tar/", b"DATA"));

    let mut r = ArReader::new(&a);
    let mut names = Vec::new();
    while let Some(mut e) = r.next_entry().unwrap() {
        names.push(String::from_utf8(e.meta().path.to_vec()).unwrap());
        let _ = drain(&mut e);
    }
    assert_eq!(names, ["debian-binary", "control.tar", "data.tar"]);
}

#[test]
fn ar_skips_symbol_tables() {
    // GNU 32-bit ("/") and 64-bit ("/SYM64/") symbol tables must not surface as file entries.
    let mut a = b"!<arch>\n".to_vec();
    a.extend(ar_member("/", b"\x00\x00\x00\x00"));
    a.extend(ar_member("/SYM64/", b"\x00\x00\x00\x00"));
    a.extend(ar_member("real.o/", b"OBJ"));

    let mut r = ArReader::new(&a);
    let mut names = Vec::new();
    while let Some(mut e) = r.next_entry().unwrap() {
        names.push(String::from_utf8(e.meta().path.to_vec()).unwrap());
        let _ = drain(&mut e);
    }
    assert_eq!(names, ["real.o"]);
}

#[test]
fn ar_gnu_long_name() {
    let long = "a_very_long_member_name_exceeding_sixteen_bytes.bin";
    let table = format!("{long}/\n"); // GNU string table entry
    let mut a = b"!<arch>\n".to_vec();
    a.extend(ar_member("//", table.as_bytes())); // string table member
    a.extend(ar_member("/0", b"payload")); // reference to offset 0

    let mut r = ArReader::new(&a);
    let mut e = r.next_entry().unwrap().unwrap();
    assert_eq!(e.meta().path.as_ref(), long.as_bytes());
    assert_eq!(drain(&mut e), b"payload");
    assert!(r.next_entry().unwrap().is_none());
}
