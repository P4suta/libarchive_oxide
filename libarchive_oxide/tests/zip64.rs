//! zip64 tests: a test-only low threshold forces zip64 emission without multi-gigabyte data. We
//! assert the on-disk sentinels / 0x0001 extra / EOCD64 record, then round-trip through both arca's
//! own reader and the external `zip` crate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;
use std::io::{Cursor, Read};

use libarchive_oxide::reader;
use libarchive_oxide::zip::{ZipOptions, ZipWriter};
use libarchive_oxide_core::{EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter};
use zip::ZipArchive;

fn build_forced_zip64() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let a = b"first entry payload, non-empty so uncomp/comp overflow the (0) threshold\n".to_vec();
    let b = b"second entry payload, also non-empty; its offset overflows too\n".to_vec();

    let opts = ZipOptions {
        zip64_threshold: 0, // any value > 0 becomes a zip64 sentinel
        ..ZipOptions::default()
    };
    let mut w = ZipWriter::with_options(Vec::new(), opts);
    for (name, data) in [(&b"a.txt"[..], &a), (&b"b.txt"[..], &b)] {
        let mut m = EntryMeta::new(EntryKind::File, Cow::Borrowed(name));
        m.size = data.len() as u64;
        m.mode = 0o644;
        let mut sink = w.start_entry(&m).unwrap();
        sink.write_chunk(data).unwrap();
        sink.close().unwrap();
    }
    w.finish().unwrap();
    (w.into_inner(), a, b)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn emits_zip64_structures() {
    let (bytes, _, _) = build_forced_zip64();

    // zip64 EOCD record and locator must be present.
    assert!(
        contains(&bytes, &[0x50, 0x4b, 0x06, 0x06]),
        "missing EOCD64 record"
    );
    assert!(
        contains(&bytes, &[0x50, 0x4b, 0x06, 0x07]),
        "missing EOCD64 locator"
    );
    // A zip64 extra field (id 0x0001) must appear.
    assert!(
        contains(&bytes, &[0x01, 0x00, 0x10, 0x00]),
        "missing 0x0001 LFH extra (16B)"
    );
    // A 32-bit sentinel (0xFFFFFFFF) must appear (sizes/offset replaced).
    assert!(
        contains(&bytes, &[0xFF, 0xFF, 0xFF, 0xFF]),
        "missing 32-bit sentinel"
    );
}

#[test]
fn arca_reads_back_forced_zip64() {
    let (bytes, a, b) = build_forced_zip64();
    let mut r = reader(&bytes).unwrap();

    let mut got = Vec::new();
    while let Some(mut e) = r.next_entry().unwrap() {
        let name = e.meta().path.to_vec();
        let mut content = Vec::new();
        let mut tmp = [0u8; 16];
        loop {
            let n = e.data().read_chunk(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            content.extend_from_slice(&tmp[..n]);
        }
        got.push((name, content));
    }
    assert_eq!(got.len(), 2);
    assert_eq!(got[0], (b"a.txt".to_vec(), a));
    assert_eq!(got[1], (b"b.txt".to_vec(), b));
}

/// Builds `count` empty-file entries with default options (no forced threshold), so the *only*
/// zip64 trigger is the entry count crossing the 16-bit sentinel.
fn build_n_entries(count: usize) -> Vec<u8> {
    let mut w = ZipWriter::with_options(Vec::new(), ZipOptions::default());
    for i in 0..count {
        let name = format!("e{i}.txt").into_bytes();
        let m = EntryMeta::new(EntryKind::File, Cow::Owned(name));
        let mut sink = w.start_entry(&m).unwrap();
        sink.close().unwrap();
    }
    w.finish().unwrap();
    w.into_inner()
}

/// Regression: at *exactly* 65535 entries the classic EOCD count16 field is the 0xFFFF sentinel,
/// so a zip64 EOCD record + locator must be emitted. The off-by-one (`>` instead of `>=`) stamped
/// the sentinel with no zip64 record, which arca's own strict reader then rejected. Assert the
/// exact boundary plus its neighbours: 65534 stays classic, 65535 and 65536 go zip64, and all
/// three round-trip through arca's reader and the external `zip` crate.
#[test]
fn count_sentinel_boundary_round_trips() {
    for count in [65534usize, 65535, 65536] {
        let bytes = build_n_entries(count);

        // arca reads back every entry.
        let mut r = reader(&bytes).unwrap();
        let mut n = 0usize;
        while let Some(e) = r.next_entry().unwrap() {
            assert_eq!(e.meta().path.as_ref(), format!("e{n}.txt").as_bytes());
            n += 1;
        }
        assert_eq!(n, count, "arca must read back all {count} entries");

        // At/above the sentinel a zip64 EOCD record must be present; below it, absent.
        let has_eocd64 = contains(&bytes, &[0x50, 0x4b, 0x06, 0x06]);
        assert_eq!(
            has_eocd64,
            count >= 65535,
            "EOCD64 presence wrong at count {count}",
        );

        // The independent `zip` crate agrees on the entry count.
        let archive =
            ZipArchive::new(Cursor::new(bytes)).expect("zip crate opens boundary archive");
        assert_eq!(archive.len(), count);
    }
}

#[test]
fn zip_crate_reads_forced_zip64() {
    let (bytes, a, b) = build_forced_zip64();
    let mut archive = ZipArchive::new(Cursor::new(bytes)).expect("zip crate opens forced-zip64");
    assert_eq!(archive.len(), 2);

    let mut fa = archive.by_name("a.txt").unwrap();
    let mut va = Vec::new();
    fa.read_to_end(&mut va).unwrap();
    assert_eq!(va, a);
    drop(fa);

    let mut fb = archive.by_name("b.txt").unwrap();
    let mut vb = Vec::new();
    fb.read_to_end(&mut vb).unwrap();
    assert_eq!(vb, b);
}
