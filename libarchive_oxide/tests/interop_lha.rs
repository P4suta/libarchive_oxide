// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! LHA/LZH read interoperability and hostile-input contracts.

#![cfg(feature = "lha")]
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::io::Cursor;

use libarchive_oxide::{
    ArchiveEngine, Limits, OpenOptions, PlanDisposition, Policy, ReaderEvent, RejectionReason,
    SeekArchiveReader,
};
use libarchive_oxide_core::{EntryKind, EntryMetadata, ErrorKind, FormatId};

#[derive(Debug)]
struct ObservedEntry {
    metadata: EntryMetadata,
    body: Vec<u8>,
}

const LH2_ARCHIVE: &[u8] = include_bytes!("fixtures/lha/compcol-lh2.lzh");

fn lh2_test_packed() -> &'static [u8] {
    let start = usize::from(LH2_ARCHIVE[0]) + 2;
    let length = usize::try_from(u32::from_le_bytes(LH2_ARCHIVE[7..11].try_into().unwrap()))
        .expect("fixture packed length fits usize");
    &LH2_ARCHIVE[start..start + length]
}

fn lh2_test_body() -> Vec<u8> {
    let mut text = Vec::new();
    for index in 0..60_u32 {
        text.extend_from_slice(format!("line {index}: the quick brown fox jumps. ").as_bytes());
        if index % 20 == 0 {
            text.extend(std::iter::repeat_n(b'=', 300));
        }
        text.push(b'\n');
    }
    text
}

fn decode_hex(input: &str) -> Vec<u8> {
    let digits: Vec<_> = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert_eq!(digits.len() % 2, 0);
    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            u8::try_from(high * 16 + low).unwrap()
        })
        .collect()
}

fn read_entries(bytes: Vec<u8>) -> Result<Vec<ObservedEntry>, libarchive_oxide::Error> {
    let mut reader = SeekArchiveReader::new(Cursor::new(bytes))?;
    assert_eq!(reader.format(), FormatId::Lha);
    let mut entries: Vec<ObservedEntry> = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Entry(metadata) => entries.push(ObservedEntry {
                metadata,
                body: Vec::new(),
            }),
            ReaderEvent::Data(chunk) => entries.last_mut().unwrap().body.extend_from_slice(chunk),
            ReaderEvent::Done => return Ok(entries),
            _ => {},
        }
    }
}

fn header_level(metadata: &EntryMetadata) -> u8 {
    metadata
        .extensions()
        .iter()
        .find(|extension| extension.namespace() == "lha" && extension.key() == b"header-level")
        .expect("preserved LHA header level")
        .value()[0]
}

fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0_u16;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xa001
            };
        }
    }
    crc
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0xedb8_8320
            };
        }
    }
    !crc
}

/// Builds one canonical level-0 `-lh0-` member followed by the zero end marker.
fn level_zero(method: [u8; 5], name: &[u8], body: &[u8], payload: &[u8]) -> Vec<u8> {
    let compressed_size = u32::try_from(payload.len()).unwrap();
    let original_size = u32::try_from(body.len()).unwrap();
    let header_size = u8::try_from(22 + name.len()).unwrap();
    let mut out = Vec::new();
    out.push(header_size);
    out.push(0); // header checksum, filled below
    out.extend_from_slice(&method);
    out.extend_from_slice(&compressed_size.to_le_bytes());
    out.extend_from_slice(&original_size.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes()); // MS-DOS timestamp
    out.push(0x20); // archive attribute
    out.push(0); // header level
    out.push(u8::try_from(name.len()).unwrap());
    out.extend_from_slice(name);
    out.extend_from_slice(&crc16(body).to_le_bytes());
    out[1] = out[2..]
        .iter()
        .fold(0_u8, |sum, &byte| sum.wrapping_add(byte));
    out.extend_from_slice(payload);
    out.push(0);
    out
}

fn level_zero_store(name: &[u8], body: &[u8]) -> Vec<u8> {
    level_zero(*b"-lh0-", name, body, body)
}

fn mz_sfx(prefix_len: usize, archive: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x90; prefix_len];
    bytes[..2].copy_from_slice(b"MZ");
    bytes.extend_from_slice(archive);
    bytes
}

fn assert_independent_method<A: compcol::Algorithm>(method: [u8; 5], body: &[u8]) {
    let payload = compcol::vec::compress_to_vec::<A>(body).expect("encode raw LHA payload");
    let (path, decoded) = read_all(
        level_zero(method, b"independent.bin", body, &payload),
        Limits::safe(),
    )
    .unwrap();
    assert_eq!(path, b"independent.bin");
    assert_eq!(decoded, body);
}

fn read_all(bytes: Vec<u8>, limits: Limits) -> Result<(Vec<u8>, Vec<u8>), libarchive_oxide::Error> {
    let mut reader = SeekArchiveReader::with_limits(Cursor::new(bytes), limits)?;
    assert_eq!(reader.format(), FormatId::Lha);
    let mut path = Vec::new();
    let mut body = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Entry(metadata) => {
                assert_eq!(metadata.kind(), EntryKind::File);
                path = metadata.path().as_bytes().to_vec();
            },
            ReaderEvent::Data(chunk) => body.extend_from_slice(chunk),
            ReaderEvent::Done => return Ok((path, body)),
            _ => {},
        }
    }
}

#[test]
fn level_zero_store_streams_exact_path_and_payload() {
    let payload = b"hello from a bounded LHA reader\n".repeat(4096);
    let (path, decoded) = read_all(
        level_zero_store(b"docs/readme.txt", &payload),
        Limits::safe(),
    )
    .unwrap();
    assert_eq!(path, b"docs/readme.txt");
    assert_eq!(decoded, payload);
}

#[test]
fn scans_and_reports_a_bounded_mz_sfx_prefix() {
    const MAX_SFX_PREFIX: usize = 20 * 1024;

    let make_sfx = |prefix_len| mz_sfx(prefix_len, &level_zero_store(b"sfx.bin", b"SFX payload"));

    let mut reader = SeekArchiveReader::new(Cursor::new(make_sfx(257))).unwrap();
    assert_eq!(reader.format(), FormatId::Lha);
    let mut prefix = None;
    let mut body = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::ArchiveMetadata(metadata) => {
                prefix = metadata
                    .extensions()
                    .iter()
                    .find(|extension| extension.key() == b"sfx-prefix-bytes")
                    .map(|extension| extension.value().to_vec());
            },
            ReaderEvent::Data(bytes) => body.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(prefix, Some(257_u64.to_le_bytes().to_vec()));
    assert_eq!(body, b"SFX payload");

    let (path, decoded) = read_all(make_sfx(MAX_SFX_PREFIX), Limits::safe()).unwrap();
    assert_eq!(path, b"sfx.bin");
    assert_eq!(decoded, b"SFX payload");

    let options = OpenOptions::new().with_format(Some(FormatId::Lha));
    let error =
        SeekArchiveReader::with_options(Cursor::new(make_sfx(MAX_SFX_PREFIX + 1)), &options)
            .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Limit);
}

#[test]
fn engine_prepares_auto_and_explicit_lha_sfx_sessions() {
    let bytes = mz_sfx(173, &level_zero_store(b"engine.bin", b"engine SFX"));
    for session in [
        ArchiveEngine::new().prepare(Cursor::new(bytes.clone())),
        ArchiveEngine::new().prepare_with_format(Cursor::new(bytes.clone()), FormatId::Lha),
    ] {
        let mut session = session.expect("prepare LHA SFX session");
        let inspection = session.inspect().expect("inspect LHA SFX");
        assert_eq!(inspection.format(), FormatId::Lha);
        assert_eq!(inspection.entries().len(), 1);
        assert_eq!(
            inspection.entries()[0].metadata().path().as_bytes(),
            b"engine.bin"
        );
    }
}

#[test]
fn range_reader_uses_the_same_lha_state_machine() {
    use libarchive_oxide::RangeArchiveReader;
    use libarchive_oxide::advanced::{MemoryReadAt, SourceIdentity};

    let body = b"LHA over immutable range reads".repeat(128);
    let source = MemoryReadAt::new(
        mz_sfx(67, &level_zero_store(b"range.bin", &body)),
        SourceIdentity::try_new(b"lha-range-fixture".to_vec()).unwrap(),
    );
    let mut reader = RangeArchiveReader::new(source).unwrap();
    assert_eq!(reader.format(), FormatId::Lha);
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().unwrap() {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, body);
    assert!(reader.metrics().requests() > 0);
}

#[cfg(feature = "async")]
#[test]
fn futures_seek_reader_uses_the_same_lha_state_machine() {
    futures_lite::future::block_on(async {
        let body = b"LHA over futures seek".repeat(128);
        let input =
            futures_lite::io::Cursor::new(mz_sfx(97, &level_zero_store(b"async.bin", &body)));
        let mut reader = libarchive_oxide::AsyncSeekArchiveReader::with_limits(
            input,
            Limits::safe().with_in_flight_bytes(Some(7)),
        )
        .await
        .unwrap();
        assert_eq!(reader.format(), FormatId::Lha);
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(decoded, body);
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_seek_reader_uses_the_same_lha_state_machine() {
    let body = b"LHA over Tokio seek".repeat(128);
    let input = Cursor::new(mz_sfx(111, &level_zero_store(b"tokio.bin", &body)));
    let mut reader = libarchive_oxide::TokioSeekArchiveReader::new(input)
        .await
        .unwrap();
    assert_eq!(reader.format(), FormatId::Lha);
    let mut decoded = Vec::new();
    loop {
        match reader.next_event().await.unwrap() {
            ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
            ReaderEvent::Done => break,
            _ => {},
        }
    }
    assert_eq!(decoded, body);
}

#[test]
fn real_producer_fixtures_cover_header_levels_zero_through_three() {
    let fixtures = [
        (
            0,
            include_str!("fixtures/lha/lhmelt-1.65.3.6-h0-subdir.lzh.hex"),
        ),
        (
            1,
            include_str!("fixtures/lha/lhmelt-1.65.3.6-h1-subdir.lzh.hex"),
        ),
        (
            2,
            include_str!("fixtures/lha/lhmelt-1.65.3.6-h2-subdir.lzh.hex"),
        ),
    ];
    for (level, fixture) in fixtures {
        let entries = read_entries(decode_hex(fixture)).unwrap();
        assert_eq!(entries.len(), 2, "level {level}");
        assert_eq!(entries[0].metadata.kind(), EntryKind::File);
        assert_eq!(
            entries[0].metadata.path().as_bytes(),
            b"subdir/subdir2/hello.txt"
        );
        assert_eq!(entries[0].body, b"hello world\n");
        assert_eq!(header_level(&entries[0].metadata), level);
        assert_eq!(entries[1].metadata.kind(), EntryKind::Dir);
        assert_eq!(entries[1].metadata.path().as_bytes(), b"subdir/subdir2");
        assert_eq!(header_level(&entries[1].metadata), level);
    }

    let entries = read_entries(decode_hex(include_str!(
        "fixtures/lha/lha-os2-2.08-h3-subdir.lzh.hex"
    )))
    .unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].metadata.kind(), EntryKind::Dir);
    assert_eq!(entries[0].metadata.path().as_bytes(), b"subdir");
    assert_eq!(entries[1].metadata.kind(), EntryKind::Dir);
    assert_eq!(entries[1].metadata.path().as_bytes(), b"subdir/subdir2");
    assert_eq!(entries[2].metadata.kind(), EntryKind::File);
    assert_eq!(
        entries[2].metadata.path().as_bytes(),
        b"subdir/subdir2/HELLO.TXT"
    );
    assert_eq!(entries[2].body, b"hello world!\r\n");
    assert!(
        entries
            .iter()
            .all(|entry| header_level(&entry.metadata) == 3)
    );
}

#[test]
fn real_unix_fixture_exposes_symbolic_link_target_and_mode() {
    let entries = read_entries(decode_hex(include_str!(
        "fixtures/lha/lha-unix-1.14i-h1-symlink.lzh.hex"
    )))
    .unwrap();
    assert_eq!(entries.len(), 1);
    let metadata = &entries[0].metadata;
    assert_eq!(metadata.kind(), EntryKind::Symlink);
    assert_eq!(metadata.path().as_bytes(), b"symlink");
    assert_eq!(
        metadata.link_target().unwrap().as_bytes(),
        b"path/to/target"
    );
    assert_eq!(metadata.mode(), Some(0o777));
    assert_eq!(header_level(metadata), 1);
    assert_eq!(entries[0].body, [] as [u8; 0]);
}

#[test]
fn unlha32_lhx_fixture_streams_and_verifies_the_large_dictionary_member() {
    let entries = read_entries(decode_hex(include_str!(
        "fixtures/lha/unlha32-2.67a-h2-lhx.lzh.hex"
    )))
    .expect("auto-detect and decode UNLHA32 LHx fixture");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.metadata.kind(), EntryKind::File);
    assert_eq!(entry.metadata.path().as_bytes(), b"GPL-2");
    assert_eq!(entry.body.len(), 18_092);
    assert_eq!(header_level(&entry.metadata), 2);
    assert!(entry.metadata.extensions().iter().any(|extension| {
        extension.namespace() == "lha"
            && extension.key() == b"method"
            && extension.value() == b"-lhx-"
    }));
}

#[test]
fn real_pmarc_fixtures_decode_pm1_and_pm2() {
    let fixtures = [
        (
            include_str!("fixtures/lha/pmarc-1.24-pm1.pma.hex"),
            b"COPYING.TXT".as_slice(),
            b"-pm1-".as_slice(),
            25_284,
            0xb7d0_e42c,
        ),
        (
            include_str!("fixtures/lha/pmarc2-pm2.pma.hex"),
            b"GPL-2.".as_slice(),
            b"-pm2-".as_slice(),
            18_176,
            0x8e20_93a7,
        ),
    ];

    for (fixture, expected_path, expected_method, expected_size, expected_crc) in fixtures {
        let entries = read_entries(decode_hex(fixture)).expect("decode PMArc fixture");
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.metadata.kind(), EntryKind::File);
        assert_eq!(entry.metadata.path().as_bytes(), expected_path);
        assert_eq!(entry.body.len(), expected_size);
        assert_eq!(crc32(&entry.body), expected_crc);
        assert!(entry.metadata.extensions().iter().any(|extension| {
            extension.namespace() == "lha"
                && extension.key() == b"method"
                && extension.value() == expected_method
        }));
    }
}

#[test]
fn pmarc_workspaces_are_preflighted_before_decoder_construction() {
    let fixtures = [
        (
            decode_hex(include_str!("fixtures/lha/pmarc-1.24-pm1.pma.hex")),
            16 * 1024,
            b"COPYING.TXT".as_slice(),
            25_284,
        ),
        (
            decode_hex(include_str!("fixtures/lha/pmarc2-pm2.pma.hex")),
            8 * 1024,
            b"GPL-2.".as_slice(),
            18_176,
        ),
    ];

    for (archive, workspace, expected_path, expected_size) in fixtures {
        let limits = Limits::safe().with_codec_memory(Some(workspace - 1));
        let error = SeekArchiveReader::with_limits(Cursor::new(archive.clone()), limits)
            .expect_err("reject PMArc workspace one byte below the bound");
        assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

        let limits = Limits::safe()
            .with_codec_memory(Some(workspace))
            .with_in_flight_bytes(Some(7));
        let (path, body) = read_all(archive, limits).expect("decode at exact PMArc bound");
        assert_eq!(path, expected_path);
        assert_eq!(body.len(), expected_size);
    }
}

#[test]
fn pmarc_payload_truncation_never_panics_or_succeeds() {
    for archive in [
        decode_hex(include_str!("fixtures/lha/pmarc-1.24-pm1.pma.hex")),
        decode_hex(include_str!("fixtures/lha/pmarc2-pm2.pma.hex")),
    ] {
        let header_end = usize::from(archive[0]) + 2;
        let packed_size =
            usize::try_from(u32::from_le_bytes(archive[7..11].try_into().unwrap())).unwrap();
        let payload_end = header_end + packed_size;
        for end in [
            header_end,
            header_end + 1,
            archive.len() / 2,
            payload_end - 1,
        ] {
            let result =
                std::panic::catch_unwind(|| read_all(archive[..end].to_vec(), Limits::safe()));
            assert!(result.is_ok(), "PMArc truncation panicked at byte {end}");
            assert!(
                result.unwrap().is_err(),
                "PMArc truncation was accepted at byte {end}"
            );
        }
    }
}

#[test]
fn independent_clean_room_encoder_covers_lh1_and_static_huffman_methods() {
    let mut payload = b"LHA interoperability payload\n".repeat(2048);
    payload.extend(0_u8..=u8::MAX);
    assert_independent_method::<compcol::lha::Lh1>(*b"-lh1-", &payload);
    assert_independent_method::<compcol::lha::Lh4>(*b"-lh4-", &payload);
    assert_independent_method::<compcol::lha::Lh5>(*b"-lh5-", &payload);
    assert_independent_method::<compcol::lha::Lh6>(*b"-lh6-", &payload);
    assert_independent_method::<compcol::lha::Lh7>(*b"-lh7-", &payload);
}

#[test]
fn bounded_lh2_payload_is_decoded_through_the_codec_boundary() {
    let (path, decoded) =
        read_all(LH2_ARCHIVE.to_vec(), Limits::safe()).expect("decode bounded LH2 member");
    assert_eq!(path, b"lh2.txt");
    assert_eq!(decoded, lh2_test_body());
}

#[test]
fn obsolete_compcol_lh2_encoding_is_rejected() {
    let archive = decode_hex(include_str!(
        "fixtures/lha/compcol-0.6.8-lh2-level0.lzh.hex"
    ));
    let error = read_all(archive, Limits::safe()).expect_err("reject nonconforming LH2 payload");
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn bounded_lh3_payload_is_decoded_through_the_codec_boundary() {
    let archive = decode_hex(include_str!(
        "fixtures/lha/first-party-lh3-canonical-match-level0.lzh.hex"
    ));
    let (path, decoded) = read_all(archive, Limits::safe()).expect("decode bounded LH3 fixture");
    assert_eq!(path, b"lh3.txt");
    assert_eq!(decoded, vec![b'A'; 64]);
}

#[test]
fn lh3_buffers_are_preflighted_and_crc_is_mandatory() {
    let archive = decode_hex(include_str!(
        "fixtures/lha/first-party-lh3-canonical-match-level0.lzh.hex"
    ));
    let buffered = 42 + 64 + 8 * 1024;
    let error = SeekArchiveReader::with_limits(
        Cursor::new(archive.clone()),
        Limits::safe().with_in_flight_bytes(Some(buffered - 1)),
    )
    .expect_err("reject LH3 whole-payload buffers before allocation");
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let mut bad_crc = archive;
    let crc_offset = 22 + b"lh3.txt".len();
    bad_crc[crc_offset] ^= 0x80;
    bad_crc[1] = bad_crc[2..2 + usize::from(bad_crc[0])]
        .iter()
        .fold(0_u8, |sum, &byte| sum.wrapping_add(byte));
    let error = read_all(bad_crc, Limits::safe()).expect_err("verify LH3 CRC16");
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);
}

#[test]
fn lh3_truncation_and_skip_fail_closed() {
    let archive = decode_hex(include_str!(
        "fixtures/lha/first-party-lh3-canonical-match-level0.lzh.hex"
    ));
    let error = SeekArchiveReader::new(Cursor::new(archive[..archive.len() - 2].to_vec()))
        .expect_err("reject LH3 payload truncated before its declared extent");
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    reader
        .skip_entry()
        .expect("decode and verify LH3 while skipping");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::EndEntry
    ));
    assert!(matches!(reader.next_event().unwrap(), ReaderEvent::Done));
}

#[test]
fn lh2_buffers_are_preflighted_and_crc_is_mandatory() {
    let body = lh2_test_body();
    let archive = level_zero(*b"-lh2-", b"bounded.bin", &body, lh2_test_packed());
    let buffered = lh2_test_packed().len() + body.len() + 8 * 1024;
    let error = SeekArchiveReader::with_limits(
        Cursor::new(archive.clone()),
        Limits::safe().with_in_flight_bytes(Some(buffered - 1)),
    )
    .expect_err("reject LH2 whole-payload buffers before allocation");
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let mut bad_crc = archive;
    let crc_offset = 22 + b"bounded.bin".len();
    bad_crc[crc_offset] ^= 0x80;
    bad_crc[1] = bad_crc[2..2 + usize::from(bad_crc[0])]
        .iter()
        .fold(0_u8, |sum, &byte| sum.wrapping_add(byte));
    let error = read_all(bad_crc, Limits::safe()).expect_err("verify LH2 CRC16");
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);
}

#[test]
fn lh2_truncation_and_skip_fail_closed() {
    let body = lh2_test_body();
    let archive = level_zero(*b"-lh2-", b"skip.bin", &body, lh2_test_packed());
    let error = SeekArchiveReader::new(Cursor::new(archive[..archive.len() - 2].to_vec()))
        .expect_err("reject LH2 payload truncated before its declared extent");
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    reader
        .skip_entry()
        .expect("decode and verify LH2 while skipping");
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::EndEntry
    ));
    assert!(matches!(reader.next_event().unwrap(), ReaderEvent::Done));
}

#[test]
fn method_dictionary_is_preflighted_before_payload_decode() {
    let body = b"bounded dictionary".repeat(32);
    let compressed = compcol::vec::compress_to_vec::<compcol::lha::Lh7>(&body).unwrap();
    let archive = level_zero(*b"-lh7-", b"large-dict.bin", &body, &compressed);
    let limits = Limits::safe().with_codec_memory(Some(64 * 1024 - 1));
    let error = SeekArchiveReader::with_limits(Cursor::new(archive), limits).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn lhx_dictionary_limit_is_checked_before_decoder_construction() {
    let archive = decode_hex(include_str!("fixtures/lha/unlha32-2.67a-h2-lhx.lzh.hex"));
    let limits = Limits::safe().with_codec_memory(Some(512 * 1024 - 1));
    let error = SeekArchiveReader::with_limits(Cursor::new(archive.clone()), limits).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);

    let limits = Limits::safe()
        .with_codec_memory(Some(512 * 1024))
        .with_in_flight_bytes(Some(7));
    let (path, body) = read_all(archive, limits).expect("decode at exact LHx dictionary bound");
    assert_eq!(path, b"GPL-2");
    assert_eq!(body.len(), 18_092);
}

#[test]
fn crc_mismatch_is_a_typed_integrity_error() {
    let mut archive = level_zero_store(b"bad.txt", b"payload");
    let payload = archive.len() - b"payload".len() - 1;
    archive[payload] ^= 0x80;
    let error = read_all(archive, Limits::safe()).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Integrity);
}

#[test]
fn declared_compressed_extent_is_a_hard_decoder_boundary() {
    let mut archive = level_zero_store(b"extent.bin", b"x");
    archive[7..11].copy_from_slice(&0_u32.to_le_bytes());
    let header_size = usize::from(archive[0]);
    archive[1] = archive[2..2 + header_size]
        .iter()
        .fold(0_u8, |sum, &byte| sum.wrapping_add(byte));

    let error = read_all(archive, Limits::safe()).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Malformed);
}

#[test]
fn unknown_method_is_typed_and_can_be_skipped_without_decoding() {
    let archive = level_zero(*b"-lh8-", b"future.bin", b"x", b"not-a-codec");
    let error = read_all(archive.clone(), Limits::safe()).unwrap_err();
    assert_eq!(
        error.archive_error().unwrap().kind(),
        ErrorKind::Unsupported
    );

    let mut reader = SeekArchiveReader::new(Cursor::new(archive)).unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::ArchiveMetadata(_)
    ));
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::Entry(_)
    ));
    reader.skip_entry().unwrap();
    assert!(matches!(
        reader.next_event().unwrap(),
        ReaderEvent::EndEntry
    ));
    assert!(matches!(reader.next_event().unwrap(), ReaderEvent::Done));
}

#[test]
fn safe_engine_plan_rejects_lha_parent_traversal() {
    let archive = level_zero_store(b"../escape.txt", b"blocked");
    let mut session = ArchiveEngine::new().prepare(Cursor::new(archive)).unwrap();
    let plan = session.plan(Policy::safe()).unwrap();
    assert_eq!(plan.entries().len(), 1);
    assert_eq!(
        plan.entries()[0].disposition(),
        PlanDisposition::Reject(RejectionReason::UnsafePath)
    );
}

#[test]
fn entry_and_total_output_limits_are_checked_before_decode() {
    let archive = level_zero_store(b"large.bin", &[0_u8; 32]);
    for limits in [
        Limits::safe().with_entry_bytes(Some(31)),
        Limits::safe().with_decoded_total(Some(31)),
    ] {
        let error =
            SeekArchiveReader::with_limits(Cursor::new(archive.clone()), limits).unwrap_err();
        assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
    }
}

#[test]
fn in_flight_limit_controls_output_staging_and_zero_cannot_progress() {
    let body = b"small bounded chunks".repeat(64);
    let (path, decoded) = read_all(
        level_zero_store(b"chunked.bin", &body),
        Limits::safe().with_in_flight_bytes(Some(7)),
    )
    .unwrap();
    assert_eq!(path, b"chunked.bin");
    assert_eq!(decoded, body);

    let error = read_all(
        level_zero_store(b"blocked.bin", b"x"),
        Limits::safe().with_in_flight_bytes(Some(0)),
    )
    .unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn header_metadata_budget_is_enforced_during_parsing() {
    let archive = level_zero_store(&[b'n'; 200], b"x");
    let limits = Limits::safe().with_metadata_bytes(Some(64));
    let error = SeekArchiveReader::with_limits(Cursor::new(archive), limits).unwrap_err();
    assert_eq!(error.archive_error().unwrap().kind(), ErrorKind::Limit);
}

#[test]
fn truncation_at_every_header_and_payload_boundary_never_panics() {
    let archive = level_zero_store(b"file.txt", b"body");
    for end in 1..archive.len() - 1 {
        let result = std::panic::catch_unwind(|| {
            let mut reader = SeekArchiveReader::new(Cursor::new(archive[..end].to_vec()))?;
            loop {
                if matches!(reader.next_event()?, ReaderEvent::Done) {
                    return Ok::<_, libarchive_oxide::Error>(());
                }
            }
        });
        assert!(result.is_ok(), "panicked at byte {end}");
        assert!(
            result.unwrap().is_err(),
            "accepted truncation at byte {end}"
        );
    }
}
