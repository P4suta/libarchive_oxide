// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! mtree v1/v2 format, metadata, limits, and writer interoperability contracts.

#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::path::PathBuf;
#[cfg(feature = "async")]
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
#[cfg(feature = "async")]
use std::task::{Context, Poll};

#[cfg(feature = "async")]
use futures_io::AsyncRead;
#[cfg(feature = "async")]
use futures_lite::future::block_on;
use libarchive_oxide::{
    ArchiveEngine, ArchivePath, ArchiveReader, ChecksumAlgorithm, CreateOptions, EntryKind,
    EntryMetadata, EntryTimes, Error, ErrorKind, Extension, FormatId, Limits, Owner, ReaderEvent,
    Timestamp,
};
#[cfg(feature = "async")]
use libarchive_oxide::{AsyncArchiveReader, AsyncArchiveWriter};

fn read_entries_from(input: impl Read, limits: Limits) -> Result<Vec<EntryMetadata>, Error> {
    let mut reader = ArchiveReader::with_limits(input, limits);
    let mut entries = Vec::new();
    loop {
        match reader.next_event()? {
            ReaderEvent::Entry(metadata) => entries.push(metadata),
            ReaderEvent::Data(data) => {
                panic!("mtree unexpectedly carried {} data bytes", data.len())
            },
            ReaderEvent::Done => return Ok(entries),
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::EndEntry => {},
            _ => panic!("unknown mtree reader event"),
        }
    }
}

fn read_entries(bytes: &[u8], limits: Limits) -> Result<Vec<EntryMetadata>, Error> {
    read_entries_from(Cursor::new(bytes), limits)
}

struct OneByte {
    bytes: Vec<u8>,
    position: usize,
}

impl OneByte {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            position: 0,
        }
    }
}

impl Read for OneByte {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == self.bytes.len() {
            return Ok(0);
        }
        output[0] = self.bytes[self.position];
        self.position += 1;
        Ok(1)
    }
}

#[cfg(feature = "async")]
impl AsyncRead for OneByte {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Read::read(&mut *self, output))
    }
}

#[test]
fn v2_full_entries_decode_typed_metadata_defaults_and_escapes() {
    let manifest = concat!(
        "#mtree v2.0\n",
        "/set type=file mode=0644 uid=100 gid=200 uname=alice gname=staff\n",
        "./empty\\040file size=0 time=1700000000.123456789 ",
        "sha256=1111111111111111111111111111111111111111111111111111111111111111 optional\n",
        "./target\\040link type=link mode=0777 link=empty\\040file\n",
        "/unset uid gid uname gname\n",
        "./pipe type=fifo mode=0600 vendor-key=value\\040with\\040spaces\n",
    );

    let entries = read_entries(manifest.as_bytes(), Limits::safe()).expect("read mtree v2");
    assert_eq!(entries.len(), 3);

    let file = &entries[0];
    assert_eq!(file.path().as_bytes(), b"./empty file");
    assert_eq!(file.kind(), EntryKind::File);
    assert_eq!(file.size(), Some(0));
    assert_eq!(file.mode(), Some(0o644));
    assert_eq!(file.owner().uid, Some(100));
    assert_eq!(file.owner().gid, Some(200));
    assert_eq!(file.owner().user.as_deref(), Some(b"alice".as_slice()));
    assert_eq!(file.owner().group.as_deref(), Some(b"staff".as_slice()));
    assert_eq!(
        file.times().modified,
        Some(Timestamp::new(1_700_000_000, 123_456_789).expect("timestamp"))
    );
    let checksum = file.checksum().expect("typed SHA-256");
    assert_eq!(checksum.algorithm(), ChecksumAlgorithm::Sha256);
    assert_eq!(checksum.as_bytes(), &[0x11; 32]);
    assert!(file.extensions().iter().any(|extension| {
        extension.namespace() == "mtree"
            && extension.key() == b"optional"
            && extension.value().is_empty()
    }));

    let link = &entries[1];
    assert_eq!(link.kind(), EntryKind::Symlink);
    assert_eq!(
        link.link_target().map(ArchivePath::as_bytes),
        Some(b"empty file".as_slice())
    );

    let fifo = &entries[2];
    assert_eq!(fifo.kind(), EntryKind::Fifo);
    assert_eq!(fifo.owner().uid, None);
    assert!(fifo.extensions().iter().any(|extension| {
        extension.namespace() == "mtree"
            && extension.key() == b"vendor-key"
            && extension.value() == b"value with spaces"
    }));
}

#[test]
fn relative_directory_entries_update_and_pop_the_current_path() {
    let manifest = concat!(
        "#mtree v1.0\n",
        ". type=dir mode=0755\n",
        "sub type=dir mode=0750\n",
        "child type=file size=0\n",
        "..\n",
        "root type=file size=0\n",
    );
    let entries = read_entries(manifest.as_bytes(), Limits::safe()).expect("read relative mtree");
    let paths = entries
        .iter()
        .map(|entry| entry.path().as_bytes())
        .collect::<Vec<_>>();
    assert_eq!(paths, vec![b".".as_slice(), b"sub", b"sub/child", b"root"]);
}

#[test]
fn v2_single_component_paths_do_not_inherit_the_previous_directory() {
    let manifest = concat!(
        "#mtree v2.0\n",
        "directory type=dir mode=0755\n",
        "root.txt type=file size=0\n",
    );
    let entries = read_entries(manifest.as_bytes(), Limits::safe()).expect("read mtree v2");
    let paths = entries
        .iter()
        .map(|entry| entry.path().as_bytes())
        .collect::<Vec<_>>();
    assert_eq!(paths, [b"directory".as_slice(), b"root.txt"]);
}

#[test]
fn one_byte_reads_split_signature_keywords_escapes_and_continuations() {
    let manifest = concat!(
        "#mtree v2.0\r\n",
        "/set type=file \\\r\n",
        "mode=0644\r\n",
        "./one\\040byte size=0\r\n",
    );
    let entries = read_entries_from(OneByte::new(manifest.as_bytes()), Limits::safe())
        .expect("read one byte at a time");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path().as_bytes(), b"./one byte");
    assert_eq!(entries[0].mode(), Some(0o644));
}

#[cfg(feature = "async")]
#[test]
fn futures_reader_and_writer_use_the_mtree_state_machine() {
    block_on(async {
        let manifest = b"#mtree v2.0\n./async\\040file type=file mode=0644 size=1\n";
        let mut reader = AsyncArchiveReader::new(OneByte::new(manifest));
        let metadata = loop {
            match reader.next_event().await.expect("read async mtree") {
                ReaderEvent::Entry(metadata) => break metadata,
                ReaderEvent::ArchiveMetadata(_) => {},
                ReaderEvent::Data(_) | ReaderEvent::EndEntry | ReaderEvent::Done => {
                    panic!("async mtree entry was not emitted")
                },
                _ => panic!("unknown async mtree reader event"),
            }
        };
        assert_eq!(metadata.path().as_bytes(), b"./async file");

        let mut writer = AsyncArchiveWriter::with_format(Vec::new(), FormatId::Mtree)
            .expect("async mtree writer");
        writer
            .start_entry(&metadata)
            .await
            .expect("start async entry");
        writer.write_data(b"x").await.expect("write async data");
        writer.end_entry().await.expect("end async entry");
        let encoded = writer.finish().await.expect("finish async mtree");
        let entries = read_entries(&encoded, Limits::safe()).expect("read async writer output");
        assert_eq!(entries, [metadata]);
    });
}

#[cfg(all(feature = "async", feature = "tokio"))]
#[tokio::test(flavor = "current_thread")]
async fn tokio_reader_and_writer_use_the_mtree_state_machine() {
    use libarchive_oxide::{TokioArchiveReader, TokioArchiveWriter};

    let manifest = b"#mtree v2.0\n./tokio type=file size=0\n";
    let mut reader = TokioArchiveReader::new(manifest.as_slice());
    let metadata = loop {
        match reader.next_event().await.expect("read Tokio mtree") {
            ReaderEvent::Entry(metadata) => break metadata,
            ReaderEvent::ArchiveMetadata(_) => {},
            ReaderEvent::Data(_) | ReaderEvent::EndEntry | ReaderEvent::Done => {
                panic!("Tokio mtree entry was not emitted")
            },
            _ => panic!("unknown Tokio mtree reader event"),
        }
    };

    let mut writer =
        TokioArchiveWriter::with_format(Vec::new(), FormatId::Mtree).expect("Tokio mtree writer");
    writer
        .start_entry(&metadata)
        .await
        .expect("start Tokio entry");
    writer.end_entry().await.expect("end Tokio entry");
    let encoded = writer.finish().await.expect("finish Tokio mtree");
    let entries = read_entries(&encoded, Limits::safe()).expect("read Tokio writer output");
    assert_eq!(entries, [metadata]);
}

#[test]
fn mtree_writer_discards_manifest_payload_and_round_trips_metadata() {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Mtree),
        )
        .expect("mtree writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"nested/file name".to_vec()),
    )
    .size(Some(3))
    .mode(Some(0o640))
    .owner(Owner {
        uid: Some(501),
        gid: Some(20),
        user: Some(b"test user".to_vec()),
        group: Some(b"staff".to_vec()),
    })
    .times(EntryTimes {
        modified: Some(Timestamp::new(1_700_000_001, 42).expect("mtime")),
        ..EntryTimes::default()
    })
    .extension(Extension::new("mtree", b"optional".to_vec(), Vec::new()))
    .try_build()
    .expect("valid metadata");
    writer.start_entry(&metadata).expect("start mtree entry");
    writer
        .write_data(b"abc")
        .expect("consume described file bytes");
    writer.end_entry().expect("end mtree entry");
    let manifest = writer.finish().expect("finish mtree");

    assert!(manifest.starts_with(b"#mtree v2.0\n"));
    assert!(manifest.windows(4).any(|window| window == b"\\040"));
    assert!(!manifest.windows(3).any(|window| window == b"abc"));
    let entries = read_entries(&manifest, Limits::safe()).expect("read written mtree");
    assert_eq!(entries, vec![metadata]);
}

fn drive_to_error(bytes: &[u8], limits: Limits) -> Error {
    let mut reader = ArchiveReader::with_limits(Cursor::new(bytes), limits);
    loop {
        match reader.next_event() {
            Ok(ReaderEvent::Done) => panic!("mtree fixture unexpectedly succeeded"),
            Ok(_) => {},
            Err(error) => return error,
        }
    }
}

#[test]
fn malformed_escapes_truncation_and_resource_limits_are_typed() {
    let malformed = drive_to_error(b"#mtree\n./bad\\08x type=file size=0\n", Limits::safe());
    assert_eq!(malformed.kind(), ErrorKind::Malformed);

    let continuation = drive_to_error(b"#mtree\n./file type=file \\", Limits::safe());
    assert_eq!(continuation.kind(), ErrorKind::Malformed);

    let long_line = format!("#mtree\n./{} type=file size=0\n", "x".repeat(128));
    let limited = drive_to_error(
        long_line.as_bytes(),
        Limits::safe().with_metadata_bytes(Some(32)),
    );
    assert_eq!(limited.kind(), ErrorKind::Limit);

    let too_many = drive_to_error(
        b"#mtree\n./a type=file size=0\n./b type=file size=0\n",
        Limits::safe().with_entries(Some(1)),
    );
    assert_eq!(too_many.kind(), ErrorKind::Limit);
}

#[test]
fn mtree_writer_rejects_unrepresentable_metadata_before_emitting_an_entry() {
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Mtree),
        )
        .expect("mtree writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"xattr.bin".to_vec()),
    )
    .size(Some(0))
    .xattr(b"user.test".to_vec(), b"value".to_vec())
    .build();
    let error = writer
        .start_entry(&metadata)
        .expect_err("mtree cannot represent xattrs");
    assert_eq!(error.kind(), ErrorKind::Unsupported);

    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Mtree),
        )
        .expect("mtree writer");
    let conflicting = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"conflict.bin".to_vec()),
    )
    .size(Some(0))
    .extension(Extension::new("mtree", b"type".to_vec(), b"dir".to_vec()))
    .build();
    let error = writer
        .start_entry(&conflicting)
        .expect_err("typed mtree keywords cannot be overridden by extensions");
    assert_eq!(error.kind(), ErrorKind::Unsupported);
}

#[test]
fn mtree_writer_escapes_comments_and_rejects_invalid_absolute_or_nul_paths() {
    let comment_like = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"#hidden".to_vec()),
    )
    .size(Some(0))
    .build();
    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Mtree),
        )
        .unwrap();
    writer.start_entry(&comment_like).unwrap();
    writer.end_entry().unwrap();
    let manifest = writer.finish().unwrap();
    assert!(manifest.windows(4).any(|window| window == b"\\043"));
    assert_eq!(
        read_entries(&manifest, Limits::safe()).unwrap(),
        [comment_like]
    );

    for path in [b"/set".as_slice(), b"/absolute", b"nul\0path"] {
        let invalid =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_bytes(path.to_vec()))
                .size(Some(0))
                .build();
        let mut writer = ArchiveEngine::new()
            .create(
                Vec::new(),
                CreateOptions::new().with_format(FormatId::Mtree),
            )
            .unwrap();
        let error = writer
            .start_entry(&invalid)
            .expect_err("mtree writer must reject a path its reader cannot represent");
        assert_eq!(error.kind(), ErrorKind::Malformed, "{path:?}");
        assert_eq!(writer.abort().unwrap(), [] as [u8; 0]);
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "libarchive-oxide-mtree-{}-{tag}-{sequence}",
        std::process::id()
    ))
}

fn has_bsdtar() -> bool {
    Command::new("tar")
        .arg("--version")
        .output()
        .is_ok_and(|output| {
            output.stdout.windows(6).any(|window| window == b"bsdtar")
                || output.stderr.windows(6).any(|window| window == b"bsdtar")
        })
}

#[test]
fn system_bsdtar_interoperates_with_reader_and_writer() {
    if !has_bsdtar() {
        return;
    }

    let directory = temp_dir("producer");
    fs::create_dir_all(&directory).expect("create bsdtar fixture directory");
    fs::write(directory.join("seed file.txt"), b"abc").expect("write bsdtar fixture input");
    let produced = Command::new("tar")
        .args(["--format=mtree", "-cf", "-", "-C"])
        .arg(&directory)
        .arg("seed file.txt")
        .output()
        .expect("run bsdtar producer");
    let _ = fs::remove_dir_all(&directory);
    assert!(
        produced.status.success(),
        "bsdtar mtree creation failed: {}",
        String::from_utf8_lossy(&produced.stderr)
    );
    let entries = read_entries(&produced.stdout, Limits::safe()).expect("read bsdtar mtree");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path().as_bytes(), b"./seed file.txt");
    assert_eq!(entries[0].size(), Some(3));

    let mut writer = ArchiveEngine::new()
        .create(
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Mtree),
        )
        .expect("mtree writer");
    let metadata = EntryMetadata::builder(
        EntryKind::File,
        ArchivePath::from_bytes(b"./consumer file.txt".to_vec()),
    )
    .size(Some(0))
    .mode(Some(0o644))
    .build();
    writer.start_entry(&metadata).expect("start mtree entry");
    writer.end_entry().expect("end mtree entry");
    let manifest = writer.finish().expect("finish mtree");

    let mut child = Command::new("tar")
        .args(["-tf", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run bsdtar consumer");
    child
        .stdin
        .take()
        .expect("bsdtar stdin")
        .write_all(&manifest)
        .expect("send mtree to bsdtar");
    let consumed = child.wait_with_output().expect("wait for bsdtar consumer");
    assert!(
        consumed.status.success(),
        "bsdtar rejected mtree output: {}",
        String::from_utf8_lossy(&consumed.stderr)
    );
    let listing = String::from_utf8(consumed.stdout).expect("bsdtar listing is UTF-8");
    assert_eq!(listing.lines().collect::<Vec<_>>(), ["./consumer file.txt"]);
}
