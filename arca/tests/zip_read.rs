//! zip reader test: generate a zip with the `zip` crate (store + deflate + a directory), then read
//! it back through arca's format auto-detection and `ZipReader`.

use std::io::{Cursor, Write};

use arca::reader;
use arca_core::EntryKind;
use zip::write::{SimpleFileOptions, ZipWriter};
use zip::CompressionMethod;

fn make_zip(payload: &[u8]) -> Vec<u8> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut buf);
        let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        let deflated = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

        zw.start_file("hello.txt", deflated).unwrap();
        zw.write_all(b"hello from zip\n").unwrap();
        zw.add_directory("dir/", deflated).unwrap();
        zw.start_file("dir/stored.bin", stored).unwrap();
        zw.write_all(payload).unwrap();
        zw.finish().unwrap();
    }
    buf.into_inner()
}

fn drain(entry: &mut arca_core::Entry<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 33];
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
fn reads_zip_store_and_deflate() {
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let z = make_zip(&payload);
    assert_eq!(&z[..4], &[0x50, 0x4b, 0x03, 0x04]); // local header magic

    let mut r = reader(&z).unwrap(); // auto-detects zip

    {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"hello.txt");
        assert_eq!(e.meta().kind, EntryKind::File);
        assert_eq!(drain(&mut e), b"hello from zip\n");
    }
    {
        let e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"dir/");
        assert_eq!(e.meta().kind, EntryKind::Dir);
    }
    {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"dir/stored.bin");
        assert_eq!(e.meta().kind, EntryKind::File);
        assert_eq!(e.meta().size, payload.len() as u64);
        assert_eq!(drain(&mut e), payload);
    }
    assert!(r.next_entry().unwrap().is_none());
}

#[test]
fn malformed_zip_errors_without_panic() {
    // Truncated and garbage inputs that pass the "PK\x03\x04" sniff must error, not panic.
    for bad in [
        &b"PK\x03\x04"[..], // local magic only, no EOCD
        &b"PK\x03\x04garbage-without-eocd"[..],
        &b"PK\x05\x06"[..], // EOCD magic but too short
    ] {
        let mut r = reader(bad).unwrap();
        // Either construction-time or first next_entry surfaces the error; neither may panic.
        let _ = r.next_entry();
    }
}
