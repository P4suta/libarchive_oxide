// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Contract tests for futures-io seek archive adapters.

#![cfg(feature = "async")]
#![allow(clippy::unwrap_used, clippy::panic)]

use futures_lite::future::block_on;
use futures_lite::io::Cursor;
use libarchive_oxide::{
    AsyncSeekArchiveReader, AsyncSeekArchiveWriter, ReaderEvent, SeekArchiveReader,
};
use libarchive_oxide_core::{ArchivePath, EntryKind, EntryMetadata, FormatId, Limits};

#[test]
fn futures_seek_iso_writer_and_reader_share_the_sync_state_machine() {
    block_on(async {
        let output = Cursor::new(Vec::new());
        let mut writer =
            AsyncSeekArchiveWriter::with_format(output, FormatId::Iso9660, Limits::default())
                .await
                .unwrap();
        let directory = EntryMetadata::builder(EntryKind::Dir, ArchivePath::from_utf8("docs/"))
            .size(Some(0))
            .build();
        writer.start_entry(&directory).await.unwrap();
        writer.write_data(&[]).await.unwrap();
        writer.end_entry().await.unwrap();

        let body = b"async seek payload";
        let file =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("docs/readme.txt"))
                .size(Some(body.len() as u64))
                .build();
        writer.start_entry(&file).await.unwrap();
        writer.write_data(body).await.unwrap();
        writer.end_entry().await.unwrap();
        let archive = writer.finish().await.unwrap().into_inner();

        let mut sync_reader =
            SeekArchiveReader::new(std::io::Cursor::new(archive.clone())).unwrap();
        let mut sync_decoded = Vec::new();
        loop {
            match sync_reader.next_event().unwrap() {
                ReaderEvent::Data(bytes) => sync_decoded.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        assert_eq!(sync_decoded, body);

        let mut reader = AsyncSeekArchiveReader::new(Cursor::new(archive))
            .await
            .unwrap();
        assert_eq!(reader.format(), FormatId::Iso9660);
        let mut current = Vec::new();
        let mut found = false;
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) => {},
                ReaderEvent::Data(bytes) => current.extend_from_slice(bytes),
                ReaderEvent::EndEntry => {
                    if current == body {
                        found = true;
                    }
                    current.clear();
                },
                ReaderEvent::Done => break,
                _ => panic!("unknown seek reader event"),
            }
        }
        assert!(found);
    });
}

#[test]
fn futures_seek_zip_roundtrips_a_payload_larger_than_the_adapter_buffer() {
    block_on(async {
        let output = Cursor::new(Vec::new());
        let mut writer =
            AsyncSeekArchiveWriter::with_format(output, FormatId::Zip, Limits::default())
                .await
                .unwrap();
        let body = (0_u8..=251).cycle().take(200_000).collect::<Vec<_>>();
        let file =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("large/async.bin"))
                .size(Some(body.len() as u64))
                .build();
        writer.start_entry(&file).await.unwrap();
        for chunk in body.chunks(997) {
            writer.write_data(chunk).await.unwrap();
        }
        writer.end_entry().await.unwrap();
        let archive = writer.finish().await.unwrap().into_inner();

        let mut reader = AsyncSeekArchiveReader::new(Cursor::new(archive))
            .await
            .unwrap();
        assert_eq!(reader.format(), FormatId::Zip);
        let mut decoded = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) | ReaderEvent::EndEntry => {
                },
                ReaderEvent::Data(bytes) => decoded.extend_from_slice(bytes),
                ReaderEvent::Done => break,
                _ => panic!("unknown seek reader event"),
            }
        }
        assert_eq!(decoded, body);
    });
}

#[cfg(feature = "sevenz")]
#[test]
fn futures_seek_sevenz_retries_demand_reads_without_losing_decoder_state() {
    block_on(async {
        let output = Cursor::new(Vec::new());
        let mut writer =
            AsyncSeekArchiveWriter::with_format(output, FormatId::SevenZip, Limits::default())
                .await
                .unwrap();
        let bodies = [
            b"solid member one".repeat(8_000),
            (0_u8..=239).cycle().take(180_000).collect::<Vec<_>>(),
        ];
        for (index, body) in bodies.iter().enumerate() {
            let metadata = EntryMetadata::builder(
                EntryKind::File,
                ArchivePath::from_utf8(format!("member-{index}.bin")),
            )
            .size(Some(body.len() as u64))
            .build();
            writer.start_entry(&metadata).await.unwrap();
            for chunk in body.chunks(613) {
                writer.write_data(chunk).await.unwrap();
            }
            writer.end_entry().await.unwrap();
        }
        let archive = writer.finish().await.unwrap().into_inner();

        let mut reader = AsyncSeekArchiveReader::new(Cursor::new(archive))
            .await
            .unwrap();
        assert_eq!(reader.format(), FormatId::SevenZip);
        let mut decoded = Vec::new();
        let mut current = Vec::new();
        loop {
            match reader.next_event().await.unwrap() {
                ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Entry(_) => {},
                ReaderEvent::Data(bytes) => current.extend_from_slice(bytes),
                ReaderEvent::EndEntry => decoded.push(std::mem::take(&mut current)),
                ReaderEvent::Done => break,
                _ => panic!("unknown seek reader event"),
            }
        }
        assert_eq!(decoded, bodies);
    });
}

#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
async fn tokio_seek_archive_adapters_match_the_futures_contract() {
    use libarchive_oxide::{TokioSeekArchiveReader, TokioSeekArchiveWriter};

    let output = std::io::Cursor::new(Vec::new());
    let mut writer =
        TokioSeekArchiveWriter::with_format(output, FormatId::Iso9660, Limits::default())
            .await
            .unwrap();
    let body = b"tokio seek body";
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("tokio.txt"))
        .size(Some(body.len() as u64))
        .build();
    writer.start_entry(&metadata).await.unwrap();
    writer.write_data(body).await.unwrap();
    writer.end_entry().await.unwrap();
    let archive = writer.finish().await.unwrap().into_inner();

    let mut reader = TokioSeekArchiveReader::new(std::io::Cursor::new(archive))
        .await
        .unwrap();
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
