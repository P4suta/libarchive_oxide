//! Integration tests for the tar reader. Without depending on external tools, it assembles a
//! ustar archive in memory and reads it back, verifying path, kind, size, contents, and PAX/GNU overrides.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use libarchive_oxide_core::format::tar::TarReader;
use libarchive_oxide_core::{Entry, EntryData, EntryKind, EntryReader};

/// Write an octal numeric field as width-1 zero-padded digits + NUL.
fn put_octal(hdr: &mut [u8; 512], start: usize, width: usize, val: u64) {
    let digits = format!("{val:0w$o}", w = width - 1);
    hdr[start..start + width - 1].copy_from_slice(digits.as_bytes());
    hdr[start + width - 1] = 0;
}

/// Assemble a single ustar entry (header + data + block padding).
fn ustar(name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    let nb = name.as_bytes();
    h[..nb.len()].copy_from_slice(nb);
    put_octal(&mut h, 100, 8, 0o644); // mode
    put_octal(&mut h, 108, 8, 0); // uid
    put_octal(&mut h, 116, 8, 0); // gid
    put_octal(&mut h, 124, 12, data.len() as u64); // size
    put_octal(&mut h, 136, 12, 0); // mtime
    h[156] = typeflag;
    h[257..262].copy_from_slice(b"ustar");
    // The magic NUL (262) is already zero-initialized. version:
    h[263] = b'0';
    h[264] = b'0';

    // Checksum: blank out the field with spaces, take the unsigned sum, and write it as 6 octal digits + NUL + space.
    for b in &mut h[148..156] {
        *b = b' ';
    }
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    let cs = format!("{sum:06o}");
    h[148..154].copy_from_slice(cs.as_bytes());
    h[154] = 0;
    h[155] = b' ';

    let mut out = h.to_vec();
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.resize(out.len() + pad, 0);
    out
}

/// Assemble a PAX record `"LEN KEY=VALUE\n"` (LEN is the total length including itself).
fn pax_record(keyval: &str) -> Vec<u8> {
    let tail = format!(" {keyval}\n");
    let mut n = tail.len() + 1;
    loop {
        let s = format!("{n}{tail}");
        if s.len() == n {
            return s.into_bytes();
        }
        n += 1;
    }
}

/// Two zero blocks (the archive terminator).
fn trailer() -> Vec<u8> {
    vec![0u8; 1024]
}

/// Read an entry's body to completion in small buffers, a little at a time (verifies chunk splitting).
fn drain<D: EntryData>(entry: &mut Entry<'_, D>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 7];
    loop {
        let n = entry.data().read_chunk(&mut tmp).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    out
}

#[test]
fn reads_plain_ustar_file_and_dir() {
    let mut ar = Vec::new();
    ar.extend(ustar("hello.txt", b'0', b"Hello, arca!\n"));
    ar.extend(ustar("stuff/", b'5', b""));
    ar.extend(trailer());

    let mut r = TarReader::new(&ar);

    {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"hello.txt");
        assert_eq!(e.meta().kind, EntryKind::File);
        assert_eq!(e.meta().size, 13);
        assert_eq!(e.meta().mode, 0o644);
        assert_eq!(drain(&mut e), b"Hello, arca!\n");
    }
    {
        let e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"stuff/");
        assert_eq!(e.meta().kind, EntryKind::Dir);
        assert_eq!(e.meta().size, 0);
    }
    assert!(r.next_entry().unwrap().is_none());
    // After reaching the terminator, it keeps returning None.
    assert!(r.next_entry().unwrap().is_none());
}

#[test]
fn skips_unread_payload_between_entries() {
    // Advancing to the second entry without reading the first body must not misalign the position.
    let mut ar = Vec::new();
    ar.extend(ustar("a", b'0', &vec![b'x'; 1000]));
    ar.extend(ustar("b", b'0', b"bee"));
    ar.extend(trailer());

    let mut r = TarReader::new(&ar);
    assert_eq!(r.next_entry().unwrap().unwrap().meta().path.as_ref(), b"a");
    {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"b");
        assert_eq!(drain(&mut e), b"bee");
    }
    assert!(r.next_entry().unwrap().is_none());
}

#[test]
fn pax_path_override() {
    let long = "a/very/long/path/that/exceeds/the/ustar/limit/but/fits/in/pax.txt";
    let mut ar = Vec::new();
    ar.extend(ustar(
        "././@PaxHeader",
        b'x',
        &pax_record(&format!("path={long}")),
    ));
    ar.extend(ustar("short", b'0', b"payload"));
    ar.extend(trailer());

    let mut r = TarReader::new(&ar);
    let mut e = r.next_entry().unwrap().unwrap();
    assert_eq!(e.meta().path.as_ref(), long.as_bytes());
    assert_eq!(drain(&mut e), b"payload");
}

#[test]
fn pax_size_override_controls_payload() {
    // PAX size overrides the body length (essential for representing large files).
    let mut ar = Vec::new();
    ar.extend(ustar("big", b'x', &pax_record("size=5")));
    // The header size is 5, and the actual data is matched to 5 bytes.
    ar.extend(ustar("big", b'0', b"12345"));
    ar.extend(trailer());

    let mut r = TarReader::new(&ar);
    let mut e = r.next_entry().unwrap().unwrap();
    assert_eq!(e.meta().size, 5);
    assert_eq!(drain(&mut e), b"12345");
}

#[test]
fn gnu_longname() {
    let long = "this/is/a/gnu/longname/entry/exceeding/one/hundred/bytes/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/file";
    let mut name_block = long.as_bytes().to_vec();
    name_block.push(0); // NUL terminator
    let mut ar = Vec::new();
    ar.extend(ustar("././@LongLink", b'L', &name_block));
    ar.extend(ustar("truncated", b'0', b"data"));
    ar.extend(trailer());

    let mut r = TarReader::new(&ar);
    let mut e = r.next_entry().unwrap().unwrap();
    assert_eq!(e.meta().path.as_ref(), long.as_bytes());
    assert_eq!(drain(&mut e), b"data");
}

#[test]
fn symlink_target() {
    let mut h = ustar("link", b'2', b"");
    // Write the target into the linkname field (157..257).
    let target = b"/etc/target";
    h[157..157 + target.len()].copy_from_slice(target);
    // Recompute the checksum.
    for b in &mut h[148..156] {
        *b = b' ';
    }
    let sum: u64 = h[..512].iter().map(|&b| u64::from(b)).sum();
    let cs = format!("{sum:06o}");
    h[148..154].copy_from_slice(cs.as_bytes());
    h[154] = 0;
    h[155] = b' ';

    let mut ar = h;
    ar.extend(trailer());

    let mut r = TarReader::new(&ar);
    let e = r.next_entry().unwrap().unwrap();
    assert_eq!(e.meta().kind, EntryKind::Symlink);
    assert_eq!(e.meta().link_target.as_deref(), Some(&b"/etc/target"[..]));
}

#[test]
fn rejects_bad_checksum() {
    let mut ar = ustar("x", b'0', b"y");
    ar[149] ^= 0xff; // Corrupt a checksum digit.
    ar.extend(trailer());
    let mut r = TarReader::new(&ar);
    assert!(r.next_entry().is_err());
}
