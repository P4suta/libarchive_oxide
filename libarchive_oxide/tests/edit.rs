// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Archive editor public-contract tests.

#![allow(clippy::expect_used, clippy::panic)]

use std::cell::Cell;
use std::io::{self, Cursor, Write};
use std::rc::Rc;

use libarchive_oxide::{
    ArchiveEditor, ArchivePath, ArchiveWriter, CreateOptions, EntryKind, EntryMetadata, ErrorKind,
    FormatId, Limits, OpenOptions, ReaderEvent,
};

fn source_tar() -> Vec<u8> {
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Tar).expect("tar writer");
    for (path, body) in [("keep.txt", b"keep".as_slice()), ("drop.txt", b"drop")] {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8(path))
            .size(Some(body.len() as u64))
            .try_build()
            .expect("valid file metadata");
        writer.start_entry(&metadata).expect("start file");
        writer.write_data(body).expect("write file");
        writer.end_entry().expect("end file");
    }
    let hardlink =
        EntryMetadata::builder(EntryKind::Hardlink, ArchivePath::from_utf8("keep-link.txt"))
            .size(Some(0))
            .link_target(Some(ArchivePath::from_utf8("keep.txt")))
            .try_build()
            .expect("valid hardlink metadata");
    writer.start_entry(&hardlink).expect("start hardlink");
    writer.end_entry().expect("end hardlink");
    writer.finish().expect("finish tar")
}

fn one_file_archive(format: FormatId) -> Vec<u8> {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("old.txt"))
        .size(Some(3))
        .try_build()
        .expect("valid file metadata");
    let mut writer = ArchiveWriter::with_format(Vec::new(), format).expect("archive writer");
    writer.start_entry(&metadata).expect("start file");
    writer.write_data(b"old").expect("write file");
    writer.end_entry().expect("end file");
    writer.finish().expect("finish archive")
}

#[test]
fn whole_rewrite_renames_removes_and_repairs_hardlink_targets() {
    let outcome = ArchiveEditor::new()
        .rename(
            ArchivePath::from_utf8("keep.txt"),
            ArchivePath::from_utf8("renamed.txt"),
        )
        .remove(ArchivePath::from_utf8("drop.txt"))
        .rewrite(
            Cursor::new(source_tar()),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Tar),
        )
        .expect("edit tar");

    assert_eq!(outcome.report().source_entries(), 3);
    assert_eq!(outcome.report().entries(), 2);
    assert_eq!(outcome.report().removed_entries(), 1);
    assert_eq!(outcome.report().renamed_entries(), 1);
    assert_eq!(outcome.report().payload_bytes(), 4);
    assert_eq!(outcome.report().metadata_losses(), []);

    let mut reader = libarchive_oxide::ArchiveReader::with_options(
        Cursor::new(outcome.into_output()),
        &OpenOptions::new().with_format(Some(FormatId::Tar)),
    )
    .expect("open edited tar");
    let mut entries = Vec::new();
    loop {
        match reader.next_event().expect("read edited event") {
            ReaderEvent::ArchiveMetadata(_) | ReaderEvent::Data(_) | ReaderEvent::EndEntry => {},
            ReaderEvent::Entry(metadata) => entries.push(metadata),
            ReaderEvent::Done => break,
            event => panic!("unexpected future reader event: {event:?}"),
        }
    }
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].path().as_bytes(), b"renamed.txt");
    assert_eq!(entries[1].path().as_bytes(), b"keep-link.txt");
    assert_eq!(
        entries[1]
            .link_target()
            .expect("rewritten hardlink target")
            .as_bytes(),
        b"renamed.txt"
    );
}

#[test]
fn edit_plan_rejects_unmatched_operations_and_duplicate_results() {
    let missing = ArchiveEditor::new()
        .remove(ArchivePath::from_utf8("missing.txt"))
        .rewrite(
            Cursor::new(source_tar()),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Tar),
        )
        .expect_err("a typo in an edit path must not silently succeed");
    assert_eq!(missing.kind(), ErrorKind::Policy);
    assert!(missing.to_string().contains("did not match"));

    let duplicate = ArchiveEditor::new()
        .rename(
            ArchivePath::from_utf8("keep.txt"),
            ArchivePath::from_utf8("drop.txt"),
        )
        .rewrite(
            Cursor::new(source_tar()),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Tar),
        )
        .expect_err("renaming over another archive entry must fail");
    assert_eq!(duplicate.kind(), ErrorKind::Policy);
    assert!(duplicate.to_string().contains("conflicting output path"));
}

#[test]
fn unsafe_edit_plan_fails_before_output_is_touched() {
    let writes = Rc::new(Cell::new(0));
    let output = CountingWriter {
        writes: Rc::clone(&writes),
    };
    let error = ArchiveEditor::new()
        .rename(
            ArchivePath::from_utf8("keep.txt"),
            ArchivePath::from_utf8("../escape.txt"),
        )
        .rewrite(
            Cursor::new(source_tar()),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            output,
            CreateOptions::new().with_format(FormatId::Tar),
        )
        .expect_err("unsafe rename destination must fail before writer creation");
    assert_eq!(error.kind(), ErrorKind::Policy);
    assert_eq!(writes.get(), 0);

    let output = CountingWriter {
        writes: Rc::clone(&writes),
    };
    let error = ArchiveEditor::new()
        .rename(
            ArchivePath::from_utf8("keep.txt"),
            ArchivePath::from_utf8("long-name.txt"),
        )
        .rewrite(
            Cursor::new(source_tar()),
            &OpenOptions::new()
                .with_format(Some(FormatId::Tar))
                .with_limits(Limits::safe().with_path_bytes(Some(4))),
            output,
            CreateOptions::new().with_format(FormatId::Tar),
        )
        .expect_err("oversized edit path must fail before writer creation");
    assert_eq!(error.kind(), ErrorKind::Limit);
    assert_eq!(writes.get(), 0);
}

#[test]
fn removing_a_referenced_hardlink_target_is_refused() {
    let error = ArchiveEditor::new()
        .remove(ArchivePath::from_utf8("keep.txt"))
        .rewrite(
            Cursor::new(source_tar()),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Tar),
        )
        .expect_err("removal must not leave a dangling hardlink");
    assert_eq!(error.kind(), ErrorKind::Policy);
    assert!(error.to_string().contains("hardlink"));
}

#[test]
fn editor_supports_every_source_and_destination_access_pair() {
    let edit = || {
        ArchiveEditor::new().rename(
            ArchivePath::from_utf8("old.txt"),
            ArchivePath::from_utf8("new.txt"),
        )
    };
    let source_options = OpenOptions::new().with_format(Some(FormatId::Tar));
    let to_seek = edit()
        .rewrite_to_seek(
            Cursor::new(one_file_archive(FormatId::Tar)),
            &source_options,
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Xar),
        )
        .expect("stream to seek edit");
    assert_eq!(to_seek.report().renamed_entries(), 1);

    let zip = one_file_archive(FormatId::Zip);
    let source_options = OpenOptions::new().with_format(Some(FormatId::Zip));
    let from_seek = edit()
        .rewrite_from_seek(
            Cursor::new(zip.clone()),
            &source_options,
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Tar),
        )
        .expect("seek to stream edit");
    assert_eq!(from_seek.report().renamed_entries(), 1);

    let seek = edit()
        .rewrite_seek(
            Cursor::new(zip),
            &source_options,
            Cursor::new(Vec::new()),
            CreateOptions::new().with_format(FormatId::Xar),
        )
        .expect("seek to seek edit");
    assert_eq!(seek.report().renamed_entries(), 1);
}

#[test]
fn unsafe_source_paths_must_be_removed_instead_of_preserved() {
    let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("../escape"))
        .size(Some(1))
        .try_build()
        .expect("archive metadata may carry an unsafe extraction path");
    let mut writer = ArchiveWriter::with_format(Vec::new(), FormatId::Tar).expect("tar writer");
    writer.start_entry(&metadata).expect("start unsafe entry");
    writer.write_data(b"x").expect("write unsafe entry");
    writer.end_entry().expect("end unsafe entry");
    let source = writer.finish().expect("finish unsafe tar");

    let error = ArchiveEditor::new()
        .rewrite(
            Cursor::new(source.clone()),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Tar),
        )
        .expect_err("unsafe retained path must fail closed");
    assert_eq!(error.kind(), ErrorKind::Policy);

    let cleaned = ArchiveEditor::new()
        .remove(ArchivePath::from_utf8("../escape"))
        .rewrite(
            Cursor::new(source),
            &OpenOptions::new().with_format(Some(FormatId::Tar)),
            Vec::new(),
            CreateOptions::new().with_format(FormatId::Tar),
        )
        .expect("explicit removal may sanitize an archive");
    assert_eq!(cleaned.report().source_entries(), 1);
    assert_eq!(cleaned.report().entries(), 0);
    assert_eq!(cleaned.report().removed_entries(), 1);
}

#[derive(Debug)]
struct CountingWriter {
    writes: Rc<Cell<usize>>,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes.set(self.writes.get() + 1);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
