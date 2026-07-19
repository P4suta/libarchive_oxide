// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Semantic contracts for the v0.2 state-machine surface.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use alloc::vec::Vec;

use libarchive_oxide_core::{
    ArDecoder, ArEncoder, ArchiveDecoder, ArchiveEncoder, ArchivePath, CodecStatus, CodecStep,
    CpioDecoder, CpioDialect, CpioEncoder, DecodeEvent, Device, EncodeCommand, EncodeStatus,
    EndOfInput, EntryKind, EntryMetadata, ErrorKind, FilterId, FormatId, Limits, ProbeResult,
    TarDecoder, TarEncoder, Timestamp,
};

extern crate alloc;

fn emit_control<'a, E: ArchiveEncoder>(
    encoder: &mut E,
    output: &mut Vec<u8>,
    command: impl Fn() -> EncodeCommand<'a>,
) -> EncodeStatus {
    loop {
        let mut buffer = [0_u8; 29];
        let step = encoder.step(command(), &mut buffer).unwrap();
        output.extend_from_slice(&buffer[..step.produced]);
        if step.status != EncodeStatus::NeedOutput {
            return step.status;
        }
    }
}

fn emit_data<E: ArchiveEncoder>(encoder: &mut E, output: &mut Vec<u8>, mut data: &[u8]) {
    while !data.is_empty() {
        let mut buffer = [0_u8; 11];
        let step = encoder
            .step(EncodeCommand::Data(data), &mut buffer)
            .unwrap();
        output.extend_from_slice(&buffer[..step.produced]);
        data = &data[step.consumed..];
    }
}

fn encode_one<E: ArchiveEncoder>(mut encoder: E, path: &[u8], body: &[u8]) -> Vec<u8> {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path.to_vec()))
        .size(Some(body.len() as u64))
        .mode(Some(0o644))
        .build();
    encode_metadata(&mut encoder, &metadata, body)
}

fn encode_metadata<E: ArchiveEncoder>(
    encoder: &mut E,
    metadata: &EntryMetadata,
    body: &[u8],
) -> Vec<u8> {
    let mut output = Vec::new();
    assert_eq!(
        emit_control(encoder, &mut output, || {
            EncodeCommand::BeginEntry(metadata)
        }),
        EncodeStatus::NeedCommand
    );
    emit_data(encoder, &mut output, body);
    assert_eq!(
        emit_control(encoder, &mut output, || EncodeCommand::EndEntry),
        EncodeStatus::NeedCommand
    );
    assert_eq!(
        emit_control(encoder, &mut output, || EncodeCommand::Finish),
        EncodeStatus::Done
    );
    output
}

fn decode_first_metadata<D: ArchiveDecoder>(decoder: &mut D, archive: &[u8]) -> EntryMetadata {
    let mut position = 0;
    let mut scratch = [0_u8; 17];
    loop {
        let step = decoder
            .step(&archive[position..], &mut scratch, EndOfInput::End)
            .unwrap();
        position += step.consumed;
        if let DecodeEvent::Entry(metadata) = step.event {
            return metadata;
        }
        assert!(
            step.consumed != 0 || step.produced != 0,
            "decoder made no progress before its first entry"
        );
    }
}

#[test]
fn mandatory_mode_fields_receive_safe_defaults() {
    let metadata =
        EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("default-mode.txt"))
            .size(Some(0))
            .build();

    let mut tar_encoder = TarEncoder::new(Limits::default());
    let tar = encode_metadata(&mut tar_encoder, &metadata, b"");
    let tar_metadata = decode_first_metadata(&mut TarDecoder::new(Limits::default()), &tar);
    assert_eq!(tar_metadata.mode(), Some(0o644));

    let mut cpio_encoder = CpioEncoder::new(Limits::default());
    let cpio = encode_metadata(&mut cpio_encoder, &metadata, b"");
    let cpio_metadata = decode_first_metadata(&mut CpioDecoder::new(Limits::default()), &cpio);
    assert_eq!(cpio_metadata.mode(), Some(0o644));

    let mut ar_encoder = ArEncoder::new(Limits::default());
    let ar = encode_metadata(&mut ar_encoder, &metadata, b"");
    let ar_metadata = decode_first_metadata(&mut ArDecoder::new(Limits::default()), &ar);
    assert_eq!(ar_metadata.mode(), Some(0o644));
}

fn tar_bytes() -> Vec<u8> {
    let body = b"incremental body";
    encode_one(TarEncoder::new(Limits::default()), b"hello.txt", body)
}

fn put_octal(header: &mut [u8; 512], start: usize, width: usize, value: u64) {
    let digits = format!("{value:0width$o}", width = width - 1);
    header[start..start + width - 1].copy_from_slice(digits.as_bytes());
    header[start + width - 1] = 0;
}

fn tar_record(name: &[u8], kind: u8, body: &[u8]) -> Vec<u8> {
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name);
    put_octal(&mut header, 100, 8, 0o644);
    put_octal(&mut header, 108, 8, 12);
    put_octal(&mut header, 116, 8, 34);
    put_octal(&mut header, 124, 12, body.len() as u64);
    put_octal(&mut header, 136, 12, 1);
    header[156] = kind;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[265..270].copy_from_slice(b"owner");
    header[297..302].copy_from_slice(b"group");
    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    header[148..154].copy_from_slice(format!("{checksum:06o}").as_bytes());
    header[154] = 0;
    header[155] = b' ';
    let mut output = header.to_vec();
    output.extend_from_slice(body);
    output.resize(output.len().next_multiple_of(512), 0);
    output
}

fn pax_record(key: &str, value: &str) -> Vec<u8> {
    let tail = format!(" {key}={value}\n");
    let mut length = tail.len() + 1;
    loop {
        let record = format!("{length}{tail}");
        if record.len() == length {
            return record.into_bytes();
        }
        length += 1;
    }
}

#[test]
fn tar_decoder_is_chunk_invariant() {
    let archive = tar_bytes();
    for chunk_size in [1, 2, 7, 511, 512, archive.len()] {
        let mut decoder = TarDecoder::new(Limits::default());
        let mut scratch = [0_u8; 17];
        let mut pending = Vec::new();
        let mut position = 0;
        let mut path = None;
        let mut body = Vec::new();

        loop {
            if pending.is_empty() && position < archive.len() {
                let end = (position + chunk_size).min(archive.len());
                pending.extend_from_slice(&archive[position..end]);
                position = end;
            }
            let eof = if position == archive.len() {
                EndOfInput::End
            } else {
                EndOfInput::More
            };
            let step = decoder.step(&pending, &mut scratch, eof).unwrap();
            let consumed = step.consumed;
            let mut done = false;
            match step.event {
                DecodeEvent::NeedInput | DecodeEvent::EndEntry => {},
                DecodeEvent::Entry(meta) => path = Some(meta.path().as_bytes().to_vec()),
                DecodeEvent::Data(chunk) => body.extend_from_slice(chunk.as_bytes()),
                DecodeEvent::Done => done = true,
                other => panic!("unexpected event: {other:?}"),
            }
            pending.drain(..consumed);
            if done {
                break;
            }
        }

        assert_eq!(path.as_deref(), Some(&b"hello.txt"[..]));
        assert_eq!(body, b"incremental body");
    }
}

#[test]
fn tar_decoder_enforces_path_budget() {
    let archive = tar_bytes();
    let limits = Limits::default();
    let mut decoder = TarDecoder::new(limits);
    let mut scratch = [];
    let mut pending = archive.as_slice();

    loop {
        match decoder.step(pending, &mut scratch, EndOfInput::End) {
            Ok(step) => {
                pending = &pending[step.consumed..];
                if matches!(step.event, DecodeEvent::Done) {
                    break;
                }
            },
            Err(error) => panic!("unexpected error: {error}"),
        }
    }
}

#[test]
fn tar_decoder_types_pax_metadata_and_materializes_sparse_holes() {
    let mut archive = Vec::new();
    let mut global = pax_record("comment.vendor", "kept");
    global.extend(pax_record("gname", "global-group"));
    archive.extend(tar_record(b"GlobalHead", b'g', &global));

    let mut pax = pax_record("path", "sparse.bin");
    pax.extend(pax_record("size", "5"));
    pax.extend(pax_record("GNU.sparse.map", "2,3,8,2"));
    pax.extend(pax_record("GNU.sparse.realsize", "12"));
    pax.extend(pax_record("mtime", "1700000000.5"));
    pax.extend(pax_record("atime", "1700000001.25"));
    pax.extend(pax_record("ctime", "-1.5"));
    pax.extend(pax_record("uname", "local-owner"));
    pax.extend(pax_record("SCHILY.xattr.user.demo", "value"));
    pax.extend(pax_record("SCHILY.acl.access", "user::rw-"));
    pax.extend(pax_record("vendor.unknown", "preserve-me"));
    archive.extend(tar_record(b"PaxHeader", b'x', &pax));
    archive.extend(tar_record(b"placeholder", b'0', b"abcde"));
    archive.extend_from_slice(&[0_u8; 1024]);

    let mut decoder = TarDecoder::new(Limits::default());
    let mut pending = Vec::new();
    let mut input_position = 0;
    let mut body = Vec::new();
    let mut metadata = None;
    let mut archive_metadata = None;
    loop {
        if pending.is_empty() && input_position < archive.len() {
            pending.push(archive[input_position]);
            input_position += 1;
        }
        let end = if input_position == archive.len() {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        let mut scratch = [0_u8; 3];
        let step = decoder.step(&pending, &mut scratch, end).unwrap();
        let consumed = step.consumed;
        let done = match step.event {
            DecodeEvent::ArchiveMetadata(value) => {
                archive_metadata = Some(value);
                false
            },
            DecodeEvent::Entry(value) => {
                metadata = Some(value);
                false
            },
            DecodeEvent::Data(chunk) => {
                body.extend_from_slice(chunk.as_bytes());
                false
            },
            DecodeEvent::Done => true,
            _ => false,
        };
        pending.drain(..consumed);
        if done {
            break;
        }
    }

    let archive_metadata = archive_metadata.unwrap();
    assert!(
        archive_metadata.extensions().iter().any(|extension| {
            extension.key() == b"comment.vendor" && extension.value() == b"kept"
        })
    );
    let metadata = metadata.unwrap();
    assert_eq!(metadata.path().as_bytes(), b"sparse.bin");
    assert_eq!(metadata.size(), Some(12));
    assert_eq!(
        metadata.owner().user.as_deref(),
        Some(b"local-owner".as_slice())
    );
    assert_eq!(
        metadata.owner().group.as_deref(),
        Some(b"global-group".as_slice())
    );
    assert_eq!(
        metadata.times().modified,
        Some(Timestamp {
            secs: 1_700_000_000,
            nanos: 500_000_000,
        })
    );
    assert_eq!(
        metadata.times().changed,
        Some(Timestamp {
            secs: -2,
            nanos: 500_000_000,
        })
    );
    assert_eq!(metadata.sparse_extents().len(), 2);
    assert_eq!(
        metadata.xattrs(),
        &[(b"user.demo".to_vec(), b"value".to_vec())]
    );
    assert_eq!(metadata.acl(), &[b"user::rw-".to_vec()]);
    assert!(metadata.extensions().iter().any(|extension| {
        extension.key() == b"vendor.unknown" && extension.value() == b"preserve-me"
    }));
    assert_eq!(body, b"\0\0abc\0\0\0de\0\0");
}

#[test]
fn codec_progress_validation_rejects_out_of_range_counts() {
    let error = CodecStep {
        consumed: 2,
        produced: 0,
        status: CodecStatus::NeedInput,
    }
    .validate(1, 0)
    .unwrap_err();
    assert_eq!(error.kind(), ErrorKind::Protocol);

    CodecStep {
        consumed: 0,
        produced: 0,
        status: CodecStatus::NeedOutput,
    }
    .validate(1, 0)
    .unwrap();
    assert_eq!(
        CodecStep {
            consumed: 0,
            produced: 0,
            status: CodecStatus::NeedInput,
        }
        .validate(1, 1)
        .unwrap_err()
        .kind(),
        ErrorKind::Protocol
    );
}

#[test]
fn format_and_filter_probes_share_the_incremental_contract() {
    assert!(matches!(
        FilterId::probe(&[0x1f]),
        ProbeResult::NeedMore { minimum: 2 }
    ));
    assert_eq!(
        FilterId::probe(&[0x1f, 0x8b]),
        ProbeResult::Match(FilterId::Gzip)
    );
    assert!(matches!(
        FormatId::probe(b"PK"),
        ProbeResult::NeedMore { minimum: 4 }
    ));
    assert_eq!(
        FormatId::probe(b"PK\x05\x06"),
        ProbeResult::Match(FormatId::Zip)
    );
    assert_eq!(
        FormatId::probe(b"!<thin>\n"),
        ProbeResult::Match(FormatId::Ar)
    );
}

#[test]
fn cpio_decoder_supports_one_byte_boundaries() {
    let archive = encode_one(
        CpioEncoder::new(Limits::default()),
        b"one-byte.txt",
        b"payload",
    );

    let mut decoder = CpioDecoder::new(Limits::default());
    let mut pending = Vec::new();
    let mut position = 0;
    let mut body = Vec::new();
    let mut saw_entry = false;
    loop {
        if pending.is_empty() && position < archive.len() {
            pending.push(archive[position]);
            position += 1;
        }
        let end = if position == archive.len() {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        let step = decoder.step(&pending, &mut [], end).unwrap();
        let consumed = step.consumed;
        let done = match step.event {
            DecodeEvent::Entry(metadata) => {
                saw_entry = true;
                assert_eq!(metadata.path().as_bytes(), b"one-byte.txt");
                assert_eq!(metadata.size(), Some(7));
                false
            },
            DecodeEvent::Data(chunk) => {
                body.extend_from_slice(chunk.as_bytes());
                false
            },
            DecodeEvent::Done => true,
            _ => false,
        };
        pending.drain(..consumed);
        if done {
            break;
        }
    }
    assert!(saw_entry);
    assert_eq!(body, b"payload");
}

fn encode_cpio_entries(entries: &[(&EntryMetadata, &[u8])]) -> Vec<u8> {
    encode_cpio_entries_with(CpioEncoder::new(Limits::default()), entries)
}

fn encode_cpio_entries_with(
    mut encoder: CpioEncoder,
    entries: &[(&EntryMetadata, &[u8])],
) -> Vec<u8> {
    let mut archive = Vec::new();
    for (metadata, body) in entries {
        assert_eq!(
            emit_control(&mut encoder, &mut archive, || {
                EncodeCommand::BeginEntry(metadata)
            }),
            EncodeStatus::NeedCommand
        );
        emit_data(&mut encoder, &mut archive, body);
        assert_eq!(
            emit_control(&mut encoder, &mut archive, || EncodeCommand::EndEntry),
            EncodeStatus::NeedCommand
        );
    }
    assert_eq!(
        emit_control(&mut encoder, &mut archive, || EncodeCommand::Finish),
        EncodeStatus::Done
    );
    archive
}

fn decode_cpio_entries(archive: &[u8]) -> Vec<(EntryMetadata, Vec<u8>)> {
    let mut decoder = CpioDecoder::new(Limits::default());
    let mut pending = Vec::new();
    let mut position = 0;
    let mut entries: Vec<(EntryMetadata, Vec<u8>)> = Vec::new();
    loop {
        if pending.is_empty() && position < archive.len() {
            pending.push(archive[position]);
            position += 1;
        }
        let end = if position == archive.len() {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        let step = decoder.step(&pending, &mut [], end).unwrap();
        let consumed = step.consumed;
        let done = match step.event {
            DecodeEvent::Entry(metadata) => {
                entries.push((metadata, Vec::new()));
                false
            },
            DecodeEvent::Data(chunk) => {
                entries
                    .last_mut()
                    .unwrap()
                    .1
                    .extend_from_slice(chunk.as_bytes());
                false
            },
            DecodeEvent::Done => true,
            _ => false,
        };
        pending.drain(..consumed);
        if done {
            return entries;
        }
    }
}

#[test]
fn cpio_hardlinks_roundtrip_as_typed_links() {
    let device = Device { major: 8, minor: 1 };
    let target = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("target"))
        .size(Some(4))
        .inode_and_links(Some(42), Some(2))
        .devices(Some(device), None)
        .build();
    let link = EntryMetadata::builder(EntryKind::Hardlink, ArchivePath::from_utf8("alias"))
        .size(Some(0))
        .link_target(Some(ArchivePath::from_utf8("target")))
        .build();
    let archive = encode_cpio_entries(&[(&target, b"body"), (&link, b"")]);
    let entries = decode_cpio_entries(&archive);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0.kind(), EntryKind::File);
    assert_eq!(entries[0].1, b"body");
    assert_eq!(entries[1].0.kind(), EntryKind::Hardlink);
    assert_eq!(
        entries[1].0.link_target().map(ArchivePath::as_bytes),
        Some(b"target".as_slice())
    );
    assert!(entries[1].1.is_empty());
}

#[test]
fn cpio_last_payload_hardlink_dialect_is_reordered_without_losing_semantics() {
    let device = Device { major: 8, minor: 1 };
    let first = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("first"))
        .size(Some(0))
        .inode_and_links(Some(99), Some(2))
        .devices(Some(device), None)
        .build();
    let second = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("second"))
        .size(Some(7))
        .inode_and_links(Some(99), Some(2))
        .devices(Some(device), None)
        .build();
    let archive = encode_cpio_entries(&[(&first, b""), (&second, b"payload")]);
    let entries = decode_cpio_entries(&archive);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0.path().as_bytes(), b"second");
    assert_eq!(entries[0].0.kind(), EntryKind::File);
    assert_eq!(entries[0].1, b"payload");
    assert_eq!(entries[1].0.path().as_bytes(), b"first");
    assert_eq!(entries[1].0.kind(), EntryKind::Hardlink);
    assert_eq!(
        entries[1].0.link_target().map(ArchivePath::as_bytes),
        Some(b"second".as_slice())
    );
}

#[test]
fn cpio_encoder_roundtrips_every_supported_dialect() {
    let body = b"dialect payload";
    let checksum = body
        .iter()
        .fold(0_u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
    for dialect in [
        CpioDialect::Newc,
        CpioDialect::Crc,
        CpioDialect::Odc,
        CpioDialect::BinaryLittleEndian,
        CpioDialect::BinaryBigEndian,
    ] {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("dialect.txt"))
                .size(Some(body.len() as u64))
                .inode_and_links(Some(42), Some(1))
                .devices(Some(Device { major: 0, minor: 7 }), None)
                .checksum((dialect == CpioDialect::Crc).then(|| checksum.to_be_bytes().to_vec()))
                .build();
        let archive = encode_cpio_entries_with(
            CpioEncoder::with_dialect(Limits::default(), dialect),
            &[(&metadata, body)],
        );
        let entries = decode_cpio_entries(&archive);
        assert_eq!(entries.len(), 1, "{dialect:?}");
        assert_eq!(
            entries[0].0.path().as_bytes(),
            b"dialect.txt",
            "{dialect:?}"
        );
        assert_eq!(entries[0].1, body, "{dialect:?}");
        if dialect == CpioDialect::Crc {
            assert_eq!(
                entries[0].0.checksum(),
                Some(checksum.to_be_bytes().as_slice())
            );
        }
    }
}

#[test]
fn ar_decoder_supports_bsd_names_at_one_byte_boundaries() {
    let path = b"a-name-longer-than-fifteen.txt";
    let archive = encode_one(ArEncoder::new(Limits::default()), path, b"member");

    let mut decoder = ArDecoder::new(Limits::default());
    let mut pending = Vec::new();
    let mut position = 0;
    let mut body = Vec::new();
    let mut decoded_path = None;
    loop {
        if pending.is_empty() && position < archive.len() {
            pending.push(archive[position]);
            position += 1;
        }
        let end = if position == archive.len() {
            EndOfInput::End
        } else {
            EndOfInput::More
        };
        let step = decoder.step(&pending, &mut [], end).unwrap();
        let consumed = step.consumed;
        let done = match step.event {
            DecodeEvent::Entry(metadata) => {
                decoded_path = Some(metadata.path().as_bytes().to_vec());
                false
            },
            DecodeEvent::Data(chunk) => {
                body.extend_from_slice(chunk.as_bytes());
                false
            },
            DecodeEvent::Done => true,
            _ => false,
        };
        pending.drain(..consumed);
        if done {
            break;
        }
    }
    assert_eq!(decoded_path.as_deref(), Some(&path[..]));
    assert_eq!(body, b"member");
}
