// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end incremental pipeline: the byte-axis filter [`libarchive_oxide::filter::AnyDecoder`] (gzip) feeding
//! the format-axis [`TarSource`], both caller-driven and free of any type erasure.
//!
//! This is the incremental analogue of the whole-slice `.tar.gz` test in `targz.rs`: a `.tar.gz` is
//! fed in small compressed chunks, the decoder's plaintext output is streamed into the source, and
//! the entries/paths/data that emerge must equal what the slice `TarReader` reads from the fully
//! decompressed archive.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{trailer, ustar};
use flate2::write::GzEncoder;
use flate2::Compression;
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::format::tar::{TarReader, TarSource};
use libarchive_oxide_core::{
    EntryData, EntryKind, EntryReader, EntrySource, SourceEvent, Status, Transform,
};
use std::io::Write;

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

#[derive(Debug, PartialEq, Eq)]
struct Ent {
    path: Vec<u8>,
    kind: EntryKind,
    data: Vec<u8>,
}

/// Reference: fully decompress, then read with the slice reader.
fn read_reference(plain: &[u8]) -> Vec<Ent> {
    let mut r = TarReader::new(plain);
    let mut out = Vec::new();
    while let Some(mut e) = r.next_entry().unwrap() {
        let meta = e.meta().clone();
        let mut data = Vec::new();
        let mut tmp = [0u8; 11];
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
            data,
        });
    }
    out
}

/// An owned classification of a borrowed [`SourceEvent`], so the borrow ends before we mutate the
/// source (feed / finish).
enum Act {
    Need,
    Entry(Vec<u8>, EntryKind),
    Data(Vec<u8>),
    End,
    Done,
}

/// Drive gzip decode → tar source, feeding the compressed `gz` `chunk` bytes at a time. The two
/// stages compose by pushing the decoder's plaintext output straight into the source's `feed`.
fn pipeline(gz: &[u8], chunk: usize) -> Vec<Ent> {
    let mut dec = libarchive_oxide::filter::decoder(FilterId::Gzip).unwrap();
    let mut src = TarSource::new();
    let mut obuf = [0u8; 256];
    let mut pending: Vec<u8> = Vec::new(); // compressed bytes awaiting the decoder
    let mut pos = 0usize;
    let mut dec_done = false;
    let mut src_finished = false;

    let mut out: Vec<Ent> = Vec::new();
    let mut cur: Option<Ent> = None;

    loop {
        let act = match src.pull().unwrap() {
            SourceEvent::NeedInput => Act::Need,
            SourceEvent::Entry(m) => Act::Entry(m.path.to_vec(), m.kind),
            SourceEvent::Data(d) => Act::Data(d.to_vec()),
            SourceEvent::EndEntry => Act::End,
            SourceEvent::Done => Act::Done,
        };
        match act {
            Act::Entry(path, kind) => {
                cur = Some(Ent {
                    path,
                    kind,
                    data: Vec::new(),
                });
                continue;
            },
            Act::Data(d) => {
                cur.as_mut().unwrap().data.extend_from_slice(&d);
                continue;
            },
            Act::End => {
                out.push(cur.take().unwrap());
                continue;
            },
            Act::Done => break,
            Act::Need => {},
        }

        // The source is starved: produce more plaintext by advancing the decoder one unit.
        if !dec_done {
            let step = dec.step(&pending, &mut obuf).unwrap();
            src.feed(&obuf[..step.produced]).unwrap();
            pending.drain(..step.consumed);
            if step.status == Status::Done {
                dec_done = true;
                continue;
            }
            let progressed = step.consumed != 0 || step.produced != 0;
            if !progressed {
                if pos < gz.len() {
                    let end = (pos + chunk).min(gz.len());
                    pending.extend_from_slice(&gz[pos..end]);
                    pos = end;
                } else {
                    // Compressed input exhausted: flush the decoder's tail into the source.
                    loop {
                        let s = dec.finish(&mut obuf).unwrap();
                        src.feed(&obuf[..s.produced]).unwrap();
                        if s.status == Status::Done || s.produced == 0 {
                            break;
                        }
                    }
                    dec_done = true;
                }
            }
        } else if !src_finished {
            src.finish_input();
            src_finished = true;
        } else {
            // Decoder finished and source finished, yet still starved: truncated input.
            break;
        }
    }
    out
}

fn sample_tar() -> Vec<u8> {
    let blob: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    let mut tar = Vec::new();
    tar.extend(ustar("readme.txt", b'0', b"arca via gzip, incrementally\n"));
    tar.extend(ustar("dir/", b'5', b""));
    tar.extend(ustar("blob.bin", b'0', &blob));
    tar.extend(ustar("nested/deep/file.txt", b'0', b"leaf contents"));
    tar.extend(trailer());
    tar
}

#[test]
fn gzip_into_tar_source_end_to_end_chunked() {
    let tar = sample_tar();
    let gz = gzip(&tar);
    assert_eq!(&gz[..2], &[0x1f, 0x8b]);

    let reference = read_reference(&tar);
    assert_eq!(reference.len(), 4);
    assert_eq!(reference[2].data.len(), 40_000);

    // Every chunking of the compressed stream — including one byte at a time — must reconstruct the
    // identical entries as the slice reader over the fully decompressed archive.
    for chunk in [1usize, 2, 5, 17, 64, 500, 4096, gz.len()] {
        let got = pipeline(&gz, chunk);
        assert_eq!(got, reference, "mismatch at compressed chunk size {chunk}");
    }
}
