//! Full-stack write capstone: assemble a `.deb` with arca's own ar writer, tar writer, and gzip
//! encoder, then read it back down through ar -> gzip -> tar. The write-direction dual of `deb.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;

use libarchive_oxide::{compress, decompress};
use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::format::ar::{ArReader, ArWriter};
use libarchive_oxide_core::format::tar::{TarReader, TarWriter};
use libarchive_oxide_core::{Entry, EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter};

fn drain<D: EntryData>(entry: &mut Entry<'_, D>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut tmp = [0u8; 32];
    loop {
        let n = entry.data().read_chunk(&mut tmp).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    out
}

/// Builds a plain tar (via `TarWriter`) from `(name, data)` file entries.
fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = TarWriter::new(Vec::new());
    for (name, data) in entries {
        let mut m = EntryMeta::new(EntryKind::File, Cow::Borrowed(name.as_bytes()));
        m.mode = 0o644;
        m.size = data.len() as u64;
        let mut sink = w.start_entry(&m).unwrap();
        if !data.is_empty() {
            sink.write_chunk(data).unwrap();
        }
        sink.close().unwrap();
    }
    w.finish().unwrap();
    w.into_inner()
}

fn ar_member(w: &mut ArWriter<Vec<u8>>, name: &[u8], data: &[u8]) {
    let mut m = EntryMeta::new(EntryKind::File, Cow::Borrowed(name));
    m.mode = 0o644;
    m.size = data.len() as u64;
    let mut sink = w.start_entry(&m).unwrap();
    if !data.is_empty() {
        sink.write_chunk(data).unwrap();
    }
    sink.close().unwrap();
}

#[test]
fn assemble_and_read_back_a_deb() {
    let control = compress(
        &tar_of(&[("./control", b"Package: arca\n")]),
        FilterId::Gzip,
    )
    .unwrap();
    let data = compress(
        &tar_of(&[("./usr/bin/app", b"#!/bin/sh\necho hi\n")]),
        FilterId::Gzip,
    )
    .unwrap();

    // Assemble the .deb (ar) with arca's own writer.
    let mut w = ArWriter::new(Vec::new());
    ar_member(&mut w, b"debian-binary", b"2.0\n");
    ar_member(&mut w, b"control.tar.gz", &control);
    ar_member(&mut w, b"data.tar.gz", &data);
    w.finish().unwrap();
    let deb = w.into_inner();

    // Read it back: ar layer -> collect members.
    let mut r = ArReader::new(&deb);
    let mut version = None;
    let mut data_member = None;
    while let Some(mut e) = r.next_entry().unwrap() {
        let name = e.meta().path.to_vec();
        let body = drain(&mut e);
        match name.as_slice() {
            b"debian-binary" => version = Some(body),
            b"data.tar.gz" => data_member = Some(body),
            _ => {},
        }
    }
    assert_eq!(version.as_deref(), Some(&b"2.0\n"[..]));

    // gzip filter -> inner tar.
    let data_bytes = data_member.unwrap();
    let plain = decompress(&data_bytes).unwrap();
    let mut tr = TarReader::new(&plain);
    let mut e = tr.next_entry().unwrap().unwrap();
    assert_eq!(e.meta().path.as_ref(), b"./usr/bin/app");
    assert_eq!(drain(&mut e), b"#!/bin/sh\necho hi\n");
    assert!(tr.next_entry().unwrap().is_none());
}
