//! zip writer tests: store/deflate/dir/symlink/empty/incompressible-fallback/mode preservation,
//! all read back through arca's own zip reader (arca-internal round-trip).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;

use arca::reader;
use arca::zip::{ZipMethod, ZipOptions, ZipWriter};
use arca_core::{EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter};

/// A minimal entry description for building test archives.
struct Spec {
    kind: EntryKind,
    name: &'static [u8],
    mode: u32,
    data: Vec<u8>,
    link: Option<&'static [u8]>,
}

fn build(specs: &[Spec], options: ZipOptions) -> Vec<u8> {
    let mut w = ZipWriter::with_options(Vec::new(), options);
    for s in specs {
        let mut m = EntryMeta::new(s.kind, Cow::Borrowed(s.name));
        m.mode = s.mode;
        m.size = s.data.len() as u64;
        m.link_target = s.link.map(Cow::Borrowed);
        let mut sink = w.start_entry(&m).unwrap();
        if !s.data.is_empty() {
            sink.write_chunk(&s.data).unwrap();
        }
        sink.close().unwrap();
    }
    w.finish().unwrap();
    w.into_inner()
}

fn drain<D: EntryData>(entry: &mut arca_core::Entry<'_, D>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 37];
    loop {
        let n = entry.data().read_chunk(&mut tmp).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    out
}

/// The compression method recorded in the first local file header (offset 8, u16 LE).
fn first_lfh_method(bytes: &[u8]) -> u16 {
    assert_eq!(&bytes[..4], &[0x50, 0x4b, 0x03, 0x04]);
    u16::from_le_bytes([bytes[8], bytes[9]])
}

#[test]
fn round_trips_store_deflate_dir_symlink_empty() {
    let text = b"the quick brown fox ".repeat(50); // very compressible
    let specs = vec![
        Spec {
            kind: EntryKind::File,
            name: b"hello.txt",
            mode: 0o644,
            data: text.clone(),
            link: None,
        },
        Spec {
            kind: EntryKind::Dir,
            name: b"dir",
            mode: 0o755,
            data: Vec::new(),
            link: None,
        },
        Spec {
            kind: EntryKind::File,
            name: b"dir/empty.bin",
            mode: 0o600,
            data: Vec::new(),
            link: None,
        },
        Spec {
            kind: EntryKind::Symlink,
            name: b"link",
            mode: 0o777,
            data: Vec::new(),
            link: Some(b"hello.txt"),
        },
    ];
    let z = build(&specs, ZipOptions::default());

    let mut r = reader(&z).unwrap();

    {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"hello.txt");
        assert_eq!(e.meta().kind, EntryKind::File);
        assert_eq!(e.meta().mode, 0o644);
        assert_eq!(drain(&mut e), text);
    }
    {
        let e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"dir/");
        assert_eq!(e.meta().kind, EntryKind::Dir);
    }
    {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"dir/empty.bin");
        assert_eq!(e.meta().kind, EntryKind::File);
        assert_eq!(e.meta().mode, 0o600);
        assert_eq!(drain(&mut e), Vec::<u8>::new());
    }
    {
        let mut e = r.next_entry().unwrap().unwrap();
        assert_eq!(e.meta().path.as_ref(), b"link");
        assert_eq!(e.meta().kind, EntryKind::Symlink);
        assert_eq!(e.meta().link_target.as_deref(), Some(&b"hello.txt"[..]));
        assert_eq!(drain(&mut e), b"hello.txt");
    }
    assert!(r.next_entry().unwrap().is_none());
}

#[test]
fn compressible_data_uses_deflate() {
    let text = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".repeat(100);
    let z = build(
        &[Spec {
            kind: EntryKind::File,
            name: b"a.txt",
            mode: 0o644,
            data: text.clone(),
            link: None,
        }],
        ZipOptions::default(),
    );
    assert_eq!(first_lfh_method(&z), 8, "compressible data should deflate");
    // Round-trips.
    let mut r = reader(&z).unwrap();
    let mut e = r.next_entry().unwrap().unwrap();
    assert_eq!(drain(&mut e), text);
}

#[test]
fn incompressible_data_falls_back_to_store() {
    // Pseudo-random, incompressible bytes (xorshift64): deflate cannot shrink it below store.
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let data: Vec<u8> = (0..8192)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            u8::try_from((state >> 33) & 0xFF).unwrap_or(0)
        })
        .collect();
    let z = build(
        &[Spec {
            kind: EntryKind::File,
            name: b"rand.bin",
            mode: 0o644,
            data: data.clone(),
            link: None,
        }],
        ZipOptions::default(),
    );
    assert_eq!(
        first_lfh_method(&z),
        0,
        "incompressible data should store, not grow"
    );
    let mut r = reader(&z).unwrap();
    let mut e = r.next_entry().unwrap().unwrap();
    assert_eq!(drain(&mut e), data);
}

#[test]
fn store_method_option_forces_store() {
    let text = b"compressible ".repeat(100);
    let opts = ZipOptions {
        method: ZipMethod::Store,
        ..ZipOptions::default()
    };
    let z = build(
        &[Spec {
            kind: EntryKind::File,
            name: b"s.txt",
            mode: 0o644,
            data: text.clone(),
            link: None,
        }],
        opts,
    );
    assert_eq!(first_lfh_method(&z), 0, "Store option must force method 0");
    let mut r = reader(&z).unwrap();
    let mut e = r.next_entry().unwrap().unwrap();
    assert_eq!(drain(&mut e), text);
}
