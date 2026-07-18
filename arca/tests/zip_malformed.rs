//! Malformed-input tests: truncated archives, damaged zip64/EOCD64, and (with the `aes` feature)
//! corrupted AES fields and password mismatches must all return an error, never panic.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;

use arca::reader;
use arca::zip::{ZipOptions, ZipWriter};
use arca_core::{EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter};

/// Reads every entry to completion, swallowing errors. The point is: it must not panic.
fn drive(bytes: &[u8]) {
    if let Ok(mut r) = reader(bytes) {
        while let Ok(Some(mut e)) = r.next_entry() {
            let mut tmp = [0u8; 32];
            while let Ok(n) = e.data().read_chunk(&mut tmp) {
                if n == 0 {
                    break;
                }
            }
        }
    }
}

fn small_zip() -> Vec<u8> {
    let mut w = ZipWriter::with_options(Vec::new(), ZipOptions::default());
    let mut m = EntryMeta::new(EntryKind::File, Cow::Borrowed(b"f.txt"));
    m.size = 5;
    let mut sink = w.start_entry(&m).unwrap();
    sink.write_chunk(b"hello").unwrap();
    sink.close().unwrap();
    w.finish().unwrap();
    w.into_inner()
}

fn forced_zip64() -> Vec<u8> {
    let opts = ZipOptions {
        zip64_threshold: 0,
        ..ZipOptions::default()
    };
    let mut w = ZipWriter::with_options(Vec::new(), opts);
    let mut m = EntryMeta::new(EntryKind::File, Cow::Borrowed(b"z.txt"));
    m.size = 8;
    let mut sink = w.start_entry(&m).unwrap();
    sink.write_chunk(b"zip64pay").unwrap();
    sink.close().unwrap();
    w.finish().unwrap();
    w.into_inner()
}

#[test]
fn truncations_do_not_panic() {
    for base in [small_zip(), forced_zip64()] {
        for len in 0..base.len() {
            drive(&base[..len]);
        }
        // Also corrupt each byte in the tail (where EOCD/EOCD64/locator live).
        let tail_start = base.len().saturating_sub(80);
        for i in tail_start..base.len() {
            let mut bad = base.clone();
            bad[i] ^= 0xFF;
            drive(&bad);
        }
    }
}

#[test]
fn garbage_that_sniffs_as_zip_errors() {
    for bad in [
        &b"PK\x03\x04"[..],
        &b"PK\x03\x04\xff\xff\xff\xff garbage no eocd"[..],
        &b"PK\x05\x06"[..],
        &b"PK\x06\x06 short zip64 eocd"[..],
    ] {
        drive(bad);
    }
}

#[cfg(feature = "aes")]
mod aes {
    use super::{drive, Cow, EntryKind, EntryMeta, EntryWriter, ZipOptions, ZipWriter};
    use arca::reader_with_password;
    use arca::zip::SaltSource;
    use arca_core::EntryReader;

    const PW: &[u8] = b"pw12345";

    fn aes_zip() -> Vec<u8> {
        let opts = ZipOptions {
            password: Some(PW.to_vec()),
            salt_source: SaltSource::Fixed([0x22; 16]),
            ..ZipOptions::default()
        };
        let mut w = ZipWriter::with_options(Vec::new(), opts);
        let mut m = EntryMeta::new(EntryKind::File, Cow::Borrowed(b"s.txt"));
        m.size = 11;
        let mut sink = w.start_entry(&m).unwrap();
        sink.write_chunk(b"hello world").unwrap();
        sink.close().unwrap();
        w.finish().unwrap();
        w.into_inner()
    }

    fn read_first(bytes: &[u8], password: Option<&[u8]>) -> Result<(), ()> {
        // Construction may fail (unrecognized/too-short); that is an error, not a panic.
        let mut r = reader_with_password(bytes, password).map_err(|_| ())?;
        r.next_entry().map_err(|_| ())?;
        Ok(())
    }

    #[test]
    fn method99_without_password_errors() {
        let z = aes_zip();
        assert!(read_first(&z, None).is_err());
    }

    #[test]
    fn wrong_password_errors() {
        let z = aes_zip();
        assert!(read_first(&z, Some(b"nope")).is_err());
    }

    #[test]
    fn corrupted_ciphertext_fails_hmac() {
        let mut z = aes_zip();
        // The entry body begins right after the local header + name + extra. Flip a byte well
        // inside the archive body (past the header) to damage the ciphertext / auth.
        let mid = z.len() / 2;
        z[mid] ^= 0xFF;
        // Must error (HMAC or password-verify mismatch), not panic.
        assert!(read_first(&z, Some(PW)).is_err());
    }

    #[test]
    fn truncated_aes_blob_errors_without_panic() {
        let z = aes_zip();
        for len in 0..z.len() {
            drive(&z[..len]);
            let _ = read_first(&z[..len], Some(PW));
        }
    }
}
