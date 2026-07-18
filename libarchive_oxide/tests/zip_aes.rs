//! `WinZip` AES-256 (AE-2) tests. Requires the `aes` feature.
//!
//! Coverage:
//!
//! * arca -> arca round-trip (encrypt then decrypt).
//! * wrong password errors without panicking.
//! * differential BOTH directions against the `zip` crate's independent `aes-crypto`:
//!   arca-encrypted archive decrypted by the `zip` crate, and a `zip`-crate-encrypted fixture
//!   decrypted by arca.
//!
//! The cross-implementation decrypt is the strongest correctness signal for the crypto layer.
#![cfg(feature = "aes")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;
use std::io::{Cursor, Read, Write};

use libarchive_oxide::reader_with_password;
use libarchive_oxide::zip::{SaltSource, ZipMethod, ZipOptions, ZipWriter};
use libarchive_oxide_core::{EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter};
use zip::write::SimpleFileOptions;
use zip::{AesMode, ZipArchive};

const PASSWORD: &[u8] = b"correct horse battery staple";

/// Builds a single-file arca archive encrypted with AES-256 AE-2 (deterministic fixed salt).
fn arca_aes(name: &[u8], data: &[u8], method: ZipMethod) -> Vec<u8> {
    let opts = ZipOptions {
        method,
        password: Some(PASSWORD.to_vec()),
        salt_source: SaltSource::Fixed([0x11; 16]),
        ..ZipOptions::default()
    };
    let mut w = ZipWriter::with_options(Vec::new(), opts);
    let mut m = EntryMeta::new(EntryKind::File, Cow::Borrowed(name));
    m.mode = 0o644;
    m.size = data.len() as u64;
    let mut sink = w.start_entry(&m).unwrap();
    if !data.is_empty() {
        sink.write_chunk(data).unwrap();
    }
    sink.close().unwrap();
    w.finish().unwrap();
    w.into_inner()
}

fn read_first_with_password(bytes: &[u8], password: &[u8]) -> libarchive_oxide_core::Result<Vec<u8>> {
    let mut r = reader_with_password(bytes, Some(password)).unwrap();
    let mut e = r.next_entry()?.unwrap();
    let mut out = Vec::new();
    let mut tmp = [0u8; 40];
    loop {
        let n = e.data().read_chunk(&mut tmp)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&tmp[..n]);
    }
    Ok(out)
}

#[test]
fn arca_roundtrip_deflate_and_store() {
    let payload = b"secret payload ".repeat(64);
    for method in [ZipMethod::Deflate, ZipMethod::Store] {
        let z = arca_aes(b"secret.txt", &payload, method);
        // The stored method must be 99 (AES) in the local header.
        assert_eq!(u16::from_le_bytes([z[8], z[9]]), 99);
        let got = read_first_with_password(&z, PASSWORD).unwrap();
        assert_eq!(got, payload);
    }
}

#[test]
fn wrong_password_errors_without_panic() {
    let z = arca_aes(b"secret.txt", b"top secret", ZipMethod::Store);
    let err = read_first_with_password(&z, b"wrong password");
    assert!(err.is_err(), "wrong password must error");
}

#[test]
fn missing_password_errors_without_panic() {
    let z = arca_aes(b"secret.txt", b"top secret", ZipMethod::Store);
    let mut r = reader_with_password(&z, None).unwrap();
    assert!(
        r.next_entry().is_err(),
        "method 99 without password must error"
    );
}

#[test]
fn zip_crate_decrypts_arca_output() {
    let payload = b"cross-impl payload ".repeat(50);
    let z = arca_aes(b"x.txt", &payload, ZipMethod::Deflate);

    let mut archive = ZipArchive::new(Cursor::new(z)).expect("zip crate opens arca AES archive");
    let mut f = archive
        .by_index_decrypt(0, PASSWORD)
        .expect("zip crate decrypts arca AE-2 entry");
    let mut got = Vec::new();
    f.read_to_end(&mut got).unwrap();
    assert_eq!(got, payload);
}

#[test]
fn arca_decrypts_zip_crate_fixture() {
    // Build an AES-256 archive with the `zip` crate, decrypt it with arca.
    let payload = b"fixture from the zip crate ".repeat(40);
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zw = zip::write::ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .with_aes_encryption(AesMode::Aes256, std::str::from_utf8(PASSWORD).unwrap());
        zw.start_file("fixture.txt", opts).unwrap();
        zw.write_all(&payload).unwrap();
        zw.finish().unwrap();
    }
    let bytes = buf.into_inner();

    let got = read_first_with_password(&bytes, PASSWORD).unwrap();
    assert_eq!(got, payload);

    // Wrong password against the external fixture must error, not panic.
    assert!(read_first_with_password(&bytes, b"nope").is_err());
}
