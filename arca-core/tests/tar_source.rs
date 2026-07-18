//! Tests for the incremental sans-IO tar source ([`TarSource`]).
//!
//! The invariant under test: feeding a tar archive through [`EntrySource`] in *any* chunking — one
//! byte at a time, odd splits, or whole-slice — yields exactly the same entries, paths, kinds,
//! sizes, link targets, and payload bytes as the slice-based [`TarReader`]. A PAX extended header
//! and its entry that straddle a feed boundary must still reassemble correctly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use arca_core::format::tar::{TarReader, TarSource};
use arca_core::{EntryData, EntryKind, EntryReader, EntrySource, SourceEvent};

// ── Archive builders (mirrors of the ones in tar_read.rs) ───────────────────────────────────────

fn put_octal(hdr: &mut [u8; 512], start: usize, width: usize, val: u64) {
    let digits = format!("{val:0w$o}", w = width - 1);
    hdr[start..start + width - 1].copy_from_slice(digits.as_bytes());
    hdr[start + width - 1] = 0;
}

fn ustar(name: &str, typeflag: u8, data: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    let nb = name.as_bytes();
    h[..nb.len()].copy_from_slice(nb);
    put_octal(&mut h, 100, 8, 0o644);
    put_octal(&mut h, 108, 8, 0);
    put_octal(&mut h, 116, 8, 0);
    put_octal(&mut h, 124, 12, data.len() as u64);
    put_octal(&mut h, 136, 12, 0);
    h[156] = typeflag;
    h[257..262].copy_from_slice(b"ustar");
    h[263] = b'0';
    h[264] = b'0';
    for b in &mut h[148..156] {
        *b = b' ';
    }
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    h[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
    h[154] = 0;
    h[155] = b' ';
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    let pad = (512 - data.len() % 512) % 512;
    out.resize(out.len() + pad, 0);
    out
}

/// A ustar entry with a symlink target written into the linkname field.
fn ustar_symlink(name: &str, target: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    let nb = name.as_bytes();
    h[..nb.len()].copy_from_slice(nb);
    put_octal(&mut h, 100, 8, 0o777);
    put_octal(&mut h, 124, 12, 0);
    h[156] = b'2';
    h[157..157 + target.len()].copy_from_slice(target);
    h[257..262].copy_from_slice(b"ustar");
    h[263] = b'0';
    h[264] = b'0';
    for b in &mut h[148..156] {
        *b = b' ';
    }
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    h[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
    h[154] = 0;
    h[155] = b' ';
    h.to_vec()
}

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

fn trailer() -> Vec<u8> {
    vec![0u8; 1024]
}

// ── Reference reader and the source under test, reduced to a common shape ────────────────────────

#[derive(Debug, PartialEq, Eq)]
struct Ent {
    path: Vec<u8>,
    kind: EntryKind,
    size: u64,
    link: Option<Vec<u8>>,
    data: Vec<u8>,
}

/// Read every entry with the slice-based reference reader.
fn read_reference(archive: &[u8]) -> Vec<Ent> {
    let mut r = TarReader::new(archive);
    let mut out = Vec::new();
    while let Some(mut e) = r.next_entry().unwrap() {
        let meta = e.meta().clone();
        let mut data = Vec::new();
        let mut tmp = [0u8; 13];
        loop {
            let n = e.data().read_chunk(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&tmp[..n]);
        }
        out.push(Ent {
            path: meta.path.to_vec(),
            kind: meta.kind,
            size: meta.size,
            link: meta.link_target.map(|c| c.to_vec()),
            data,
        });
    }
    out
}

/// Read every entry with the incremental source, feeding `archive` in `chunk`-sized pushes.
fn read_source(archive: &[u8], chunk: usize) -> Vec<Ent> {
    // An owned classification of the borrowed event, so the event borrow ends before we `feed`.
    enum Act {
        Need,
        Entry(Vec<u8>, EntryKind, u64, Option<Vec<u8>>),
        Data(Vec<u8>),
        End,
        Done,
    }

    let mut src = TarSource::new();
    let mut fed = 0usize;
    let mut out: Vec<Ent> = Vec::new();
    let mut cur: Option<Ent> = None;

    loop {
        let act = match src.pull().unwrap() {
            SourceEvent::NeedInput => Act::Need,
            SourceEvent::Entry(m) => Act::Entry(
                m.path.to_vec(),
                m.kind,
                m.size,
                m.link_target.map(|c| c.to_vec()),
            ),
            SourceEvent::Data(d) => Act::Data(d.to_vec()),
            SourceEvent::EndEntry => Act::End,
            SourceEvent::Done => Act::Done,
        };
        match act {
            Act::Need => {
                if fed < archive.len() {
                    let end = (fed + chunk).min(archive.len());
                    src.feed(&archive[fed..end]).unwrap();
                    fed = end;
                    if fed == archive.len() {
                        src.finish_input();
                    }
                } else {
                    src.finish_input();
                }
            }
            Act::Entry(path, kind, size, link) => {
                cur = Some(Ent {
                    path,
                    kind,
                    size,
                    link,
                    data: Vec::new(),
                });
            }
            Act::Data(d) => cur.as_mut().unwrap().data.extend_from_slice(&d),
            Act::End => out.push(cur.take().unwrap()),
            Act::Done => break,
        }
    }
    out
}

/// A representative archive exercising files, dirs, a multi-block payload, PAX path/size, GNU
/// longname, and a symlink.
fn sample_archive() -> Vec<u8> {
    let long = "a/very/long/path/that/exceeds/the/ustar/one/hundred/byte/limit/but/fits/in/pax/extended/header.txt";
    let gnu_long =
        "gnu/longname/entry/exceeding/one/hundred/bytes/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/file";
    let big: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();

    let mut ar = Vec::new();
    ar.extend(ustar("hello.txt", b'0', b"Hello, arca!\n"));
    ar.extend(ustar("stuff/", b'5', b""));
    ar.extend(ustar("big.bin", b'0', &big));
    ar.extend(ustar("empty.txt", b'0', b""));
    // PAX path override for the following entry.
    ar.extend(ustar(
        "././@PaxHeader",
        b'x',
        &pax_record(&format!("path={long}")),
    ));
    ar.extend(ustar("short", b'0', b"payload-under-pax"));
    // GNU longname for the following entry.
    let mut name_block = gnu_long.as_bytes().to_vec();
    name_block.push(0);
    ar.extend(ustar("././@LongLink", b'L', &name_block));
    ar.extend(ustar("truncated", b'0', b"gnu-data"));
    ar.extend(ustar_symlink("link", b"/etc/target"));
    ar.extend(trailer());
    ar
}

#[test]
fn source_matches_reader_across_chunk_sizes() {
    let ar = sample_archive();
    let reference = read_reference(&ar);
    // Seven real entries: the PAX `x` and GNU `L` headers are consumed as overrides, not entries.
    assert_eq!(reference.len(), 7);
    assert_eq!(reference[0].path, b"hello.txt");
    assert_eq!(reference[2].data.len(), 1500);
    assert_eq!(reference[6].kind, EntryKind::Symlink);

    for chunk in [1usize, 2, 3, 7, 13, 100, 511, 512, 513, 1000, ar.len()] {
        let got = read_source(&ar, chunk);
        assert_eq!(got, reference, "mismatch at chunk size {chunk}");
    }
}

#[test]
fn source_one_byte_at_a_time_equals_whole_slice() {
    let ar = sample_archive();
    assert_eq!(read_source(&ar, 1), read_source(&ar, ar.len()));
}

#[test]
fn pax_header_and_entry_straddling_feed_boundary() {
    // A PAX `path` header immediately followed by its entry. We split the feed at every possible
    // boundary and require the reassembled path/data to be correct each time — in particular when
    // the boundary lands inside the PAX record or between the record and the entry header.
    let long = "deeply/nested/pax/overridden/path/that/is/definitely/longer/than/one/hundred/ustar/bytes/for/sure.dat";
    let mut ar = Vec::new();
    ar.extend(ustar(
        "././@PaxHeader",
        b'x',
        &pax_record(&format!("path={long}")),
    ));
    ar.extend(ustar("placeholder", b'0', b"the-body"));
    ar.extend(trailer());

    for split in 1..ar.len() {
        let mut src = TarSource::new();
        src.feed(&ar[..split]).unwrap();
        src.feed(&ar[split..]).unwrap();
        src.finish_input();

        let mut path = None;
        let mut data = Vec::new();
        loop {
            let ev = src.pull().unwrap();
            match ev {
                SourceEvent::Entry(m) => path = Some(m.path.to_vec()),
                SourceEvent::Data(d) => data.extend_from_slice(d),
                SourceEvent::Done => break,
                SourceEvent::EndEntry | SourceEvent::NeedInput => {}
            }
        }
        assert_eq!(path.as_deref(), Some(long.as_bytes()), "split at {split}");
        assert_eq!(data, b"the-body", "split at {split}");
    }
}

#[test]
fn empty_archive_terminator_only() {
    let ar = trailer();
    assert!(read_source(&ar, 1).is_empty());
    assert!(read_source(&ar, ar.len()).is_empty());
}

#[test]
fn done_is_idempotent_after_finish() {
    let ar = sample_archive();
    let mut src = TarSource::new();
    src.feed(&ar).unwrap();
    src.finish_input();
    // Drive to completion.
    let _ = read_source(&ar, ar.len());
    // A freshly finished-and-drained source keeps reporting Done.
    while !matches!(src.pull().unwrap(), SourceEvent::Done) {}
    assert!(matches!(src.pull().unwrap(), SourceEvent::Done));
    assert!(matches!(src.pull().unwrap(), SourceEvent::Done));
}

#[test]
fn buffer_stays_bounded_for_a_large_entry_fed_in_small_chunks() {
    // The core sans-IO promise: a single huge entry, fed in small chunks and consumed window by
    // window, must never accumulate its whole payload in the internal buffer. We build a ~4 MiB
    // regular file, feed it in 64 KiB pushes, pull after each feed, and drop every event borrow
    // promptly — then assert peak residency stays near one chunk, not O(payload).
    const CHUNK: usize = 64 * 1024;
    let payload: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let mut ar = ustar("big.bin", b'0', &payload);
    ar.extend(trailer());

    let mut src = TarSource::new();
    let mut fed = 0usize;
    let mut peak = 0usize;
    let mut got = Vec::new();
    let mut done = false;
    while !done {
        // Classify then drop the event borrow before touching `src` again.
        enum Act {
            Need,
            Other,
            Done,
        }
        let act = match src.pull().unwrap() {
            SourceEvent::NeedInput => Act::Need,
            SourceEvent::Data(d) => {
                got.extend_from_slice(d);
                Act::Other
            }
            SourceEvent::Done => Act::Done,
            SourceEvent::Entry(_) | SourceEvent::EndEntry => Act::Other,
        };
        peak = peak.max(src.buffered_len());
        match act {
            Act::Need => {
                if fed < ar.len() {
                    let end = (fed + CHUNK).min(ar.len());
                    src.feed(&ar[fed..end]).unwrap();
                    fed = end;
                    if fed == ar.len() {
                        src.finish_input();
                    }
                } else {
                    src.finish_input();
                }
            }
            Act::Other => {}
            Act::Done => done = true,
        }
    }

    // Correctness: the whole payload round-trips.
    assert_eq!(got, payload);
    // Boundedness: never more than a couple of chunks plus a header block resident, and in
    // particular far below the ~4 MiB payload the pre-fix code would have accumulated.
    let bound = 2 * CHUNK + 512;
    assert!(
        peak <= bound,
        "peak residency {peak} exceeded bound {bound} (payload was {} bytes)",
        payload.len(),
    );
}
