//! Building a plain tar archive from filesystem paths (the std convenience over `TarWriter`).

use std::borrow::Cow;
use std::fs;
use std::io;
use std::path::Path;

use arca_core::format::tar::TarWriter;
use arca_core::{EntryKind, EntryMeta, EntryWriter};

/// Builds a plain (uncompressed) tar in memory from the given input paths, recursing into
/// directories. Each input's archive name is the path as given (normalized to `/` separators).
pub fn build_tar<S: AsRef<str>>(inputs: &[S]) -> io::Result<Vec<u8>> {
    let mut writer = TarWriter::new(Vec::new());
    for input in inputs {
        let name = normalize_name(input.as_ref());
        add_path(&mut writer, Path::new(input.as_ref()), &name)?;
    }
    writer.finish().map_err(to_io)?;
    Ok(writer.into_inner())
}

/// Builds an archive from `inputs`, compressing according to `dest_name`'s extension
/// (`.gz`/`.tgz`, `.zst`, `.xz`, `.lz4`); other names produce a plain tar.
pub fn build_archive<S: AsRef<str>>(inputs: &[S], dest_name: &str) -> io::Result<Vec<u8>> {
    let tar = build_tar(inputs)?;
    match crate::filter_for_name(dest_name) {
        Some(id) => crate::compress(&tar, id).map_err(to_io),
        None => Ok(tar),
    }
}

/// Recursively adds `fs_path` (with archive name `name`) to the writer.
fn add_path(writer: &mut TarWriter<Vec<u8>>, fs_path: &Path, name: &str) -> io::Result<()> {
    let file_type = fs::symlink_metadata(fs_path)?.file_type();

    if file_type.is_symlink() {
        let target = fs::read_link(fs_path)?;
        write_entry(
            writer,
            EntryKind::Symlink,
            name,
            0o777,
            &[],
            Some(target.to_string_lossy().as_bytes()),
        )?;
    } else if file_type.is_dir() {
        write_entry(
            writer,
            EntryKind::Dir,
            &format!("{name}/"),
            0o755,
            &[],
            None,
        )?;
        let mut children: Vec<_> = fs::read_dir(fs_path)?.collect::<io::Result<_>>()?;
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            let child_name = format!("{name}/{}", child.file_name().to_string_lossy());
            add_path(writer, &child.path(), &child_name)?;
        }
    } else {
        let data = fs::read(fs_path)?;
        write_entry(writer, EntryKind::File, name, 0o644, &data, None)?;
    }
    Ok(())
}

/// Writes a single entry (header + payload) to the writer.
fn write_entry(
    writer: &mut TarWriter<Vec<u8>>,
    kind: EntryKind,
    name: &str,
    mode: u32,
    data: &[u8],
    link: Option<&[u8]>,
) -> io::Result<()> {
    let mut meta = EntryMeta::new(kind, Cow::Borrowed(name.as_bytes()));
    meta.mode = mode;
    meta.size = data.len() as u64;
    meta.link_target = link.map(Cow::Borrowed);

    let mut sink = writer.start_entry(&meta).map_err(to_io)?;
    if !data.is_empty() {
        sink.write_chunk(data).map_err(to_io)?;
    }
    sink.close().map_err(to_io)?;
    Ok(())
}

/// Normalizes a filesystem argument into a tar entry name: `/` separators, no `./` prefix or
/// trailing slash.
fn normalize_name(arg: &str) -> String {
    let slashed = arg.replace('\\', "/");
    let trimmed = slashed.trim_end_matches('/');
    trimmed.strip_prefix("./").unwrap_or(trimmed).to_string()
}

/// Maps a sans-IO core error into a std I/O error.
fn to_io(e: arca_core::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{e}"))
}
