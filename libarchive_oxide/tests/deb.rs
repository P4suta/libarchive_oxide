// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `.deb`-style end-to-end test: an `ar` archive whose members are gzip-compressed tarballs.
//!
//! This exercises all three layers composing at once: ar (outer format) -> gzip (filter) ->
//! tar (inner format), which is exactly how a Debian package is structured.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::Write;

use common::{drain, trailer, ustar};
use flate2::write::GzEncoder;
use flate2::Compression;
use libarchive_oxide::decompress;
use libarchive_oxide_core::format::ar::ArReader;
use libarchive_oxide_core::format::tar::TarReader;
use libarchive_oxide_core::{EntryReader, Result};

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

/// Builds one ar member; `name_field` is the raw 16-byte name field (with any trailing `/`).
fn ar_member(name_field: &str, data: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    let pad = |s: String, w: usize| {
        let mut b = s.into_bytes();
        b.resize(w, b' ');
        b
    };
    h.extend_from_slice(&pad(name_field.to_string(), 16));
    h.extend_from_slice(&pad("0".into(), 12));
    h.extend_from_slice(&pad("0".into(), 6));
    h.extend_from_slice(&pad("0".into(), 6));
    h.extend_from_slice(&pad("100644".into(), 8));
    h.extend_from_slice(&pad(format!("{}", data.len()), 10));
    h.extend_from_slice(b"`\n");
    h.extend_from_slice(data);
    if data.len() % 2 == 1 {
        h.push(b'\n');
    }
    h
}

/// Wraps entries into a plain tarball.
fn tarball(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
    let mut t = Vec::new();
    for &(name, typeflag, data) in entries {
        t.extend(ustar(name, typeflag, data));
    }
    t.extend(trailer());
    t
}

#[test]
fn extracts_deb_like_archive() -> Result<()> {
    let control_tar_gz = gzip(&tarball(&[("./control", b'0', b"Package: arca\n")]));
    let data_tar_gz = gzip(&tarball(&[
        ("./usr/bin/app", b'0', b"#!/bin/sh\necho hi\n"),
        ("./usr/share/", b'5', b""),
    ]));

    let mut deb = b"!<arch>\n".to_vec();
    deb.extend(ar_member("debian-binary/", b"2.0\n"));
    deb.extend(ar_member("control.tar.gz/", &control_tar_gz));
    deb.extend(ar_member("data.tar.gz/", &data_tar_gz));

    // Layer 1: walk the ar container and collect members by name.
    let mut r = ArReader::new(&deb);
    let mut version = None;
    let mut data_member = None;
    while let Some(mut e) = r.next_entry()? {
        let name = e.meta().path.to_vec();
        let body = drain(&mut e);
        match name.as_slice() {
            b"debian-binary" => version = Some(body),
            b"data.tar.gz" => data_member = Some(body),
            _ => {},
        }
    }
    assert_eq!(version.as_deref(), Some(&b"2.0\n"[..]));

    // Layer 2: decompress the gzip filter. Layer 3: read the inner tar.
    let data_member = data_member.expect("data.tar.gz present");
    let plain = decompress(&data_member).unwrap();
    let mut tr = TarReader::new(&plain);

    let mut e = tr.next_entry()?.unwrap();
    assert_eq!(e.meta().path.as_ref(), b"./usr/bin/app");
    assert_eq!(drain(&mut e), b"#!/bin/sh\necho hi\n");

    let e = tr.next_entry()?.unwrap();
    assert_eq!(e.meta().path.as_ref(), b"./usr/share/");
    assert!(tr.next_entry()?.is_none());
    Ok(())
}
