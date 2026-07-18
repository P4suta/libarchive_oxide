//! Building a plain tar archive from filesystem paths (the std convenience over `TarWriter`).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::Path;

use libarchive_oxide_core::format::tar::TarWriter;
use libarchive_oxide_core::{EntryKind, EntryMeta, EntryWriter};

use crate::zip::{ZipOptions, ZipWriter};

/// Options for [`build_archive`], threaded from the CLI. Currently carries zip-specific options
/// (method, password, salt); other formats ignore it.
#[derive(Debug, Clone, Default)]
pub struct CreateOptions {
    /// Options applied when the destination is a `.zip`.
    pub zip: ZipOptions,
}

/// Builds a plain (uncompressed) tar in memory from the given input paths, recursing into
/// directories. Each input's archive name is the path as given (normalized to a safe relative
/// `/`-separated name). Regular files, directories, and symlinks are archived; other special
/// files (FIFOs, devices, sockets) are skipped rather than read.
pub fn build_tar<S: AsRef<str>>(inputs: &[S]) -> io::Result<Vec<u8>> {
    let mut writer = TarWriter::new(Vec::new());
    for input in inputs {
        let name = normalize_name(input.as_ref());
        add_path(&mut writer, Path::new(input.as_ref()), &name)?;
    }
    writer.finish().map_err(to_io)?;
    Ok(writer.into_inner())
}

/// Builds a plain (uncompressed) cpio (newc) archive in memory from the given input paths,
/// recursing into directories. The dual of [`build_tar`] for the cpio format; used by the
/// `oxcpio -o` and `oxtar --format cpio` create paths. The same conservative filesystem walk is
/// reused: regular files, directories, and symlinks are archived; other special files are skipped.
pub fn build_cpio<S: AsRef<str>>(inputs: &[S]) -> io::Result<Vec<u8>> {
    use libarchive_oxide_core::format::cpio::CpioWriter;
    let mut writer = CpioWriter::new(Vec::new());
    for input in inputs {
        let name = normalize_name(input.as_ref());
        add_path(&mut writer, Path::new(input.as_ref()), &name)?;
    }
    writer.finish().map_err(to_io)?;
    Ok(writer.into_inner())
}

/// Builds an archive from `inputs` with default options; see [`build_archive_with`].
pub fn build_archive<S: AsRef<str>>(inputs: &[S], dest_name: &str) -> io::Result<Vec<u8>> {
    build_archive_with(inputs, dest_name, &CreateOptions::default())
}

/// Builds an archive from `inputs`, dispatching on `dest_name`'s extension: `.zip` routes to the
/// zip writer (bypassing the tar+filter pipeline); `.gz`/`.tgz`/`.zst`/`.xz`/`.lz4` produce a
/// compressed tar; any other name produces a plain tar.
pub fn build_archive_with<S: AsRef<str>>(
    inputs: &[S],
    dest_name: &str,
    options: &CreateOptions,
) -> io::Result<Vec<u8>> {
    if is_zip_name(dest_name) {
        return build_zip(inputs, &options.zip);
    }
    if has_extension(dest_name, "iso") {
        return build_iso(inputs);
    }
    #[cfg(feature = "sevenz")]
    if has_extension(dest_name, "7z") {
        return build_sevenz(inputs);
    }
    let tar = build_tar(inputs)?;
    match crate::filter_for_name(dest_name) {
        Some(id) => crate::compress(&tar, id).map_err(to_io),
        None => Ok(tar),
    }
}

/// Whether `name` has a `.zip` extension (case-insensitive).
fn is_zip_name(name: &str) -> bool {
    has_extension(name, "zip")
}

/// Whether `name`'s extension equals `ext` (case-insensitive).
fn has_extension(name: &str, ext: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case(ext))
}

/// Builds a 7z archive in memory from `inputs`, using the shared filesystem walk.
#[cfg(feature = "sevenz")]
fn build_sevenz<S: AsRef<str>>(inputs: &[S]) -> io::Result<Vec<u8>> {
    use crate::sevenz::SevenZWriter;
    let mut writer = SevenZWriter::new(Vec::new());
    for input in inputs {
        let name = normalize_name(input.as_ref());
        add_path(&mut writer, Path::new(input.as_ref()), &name)?;
    }
    writer.finish().map_err(to_io)?;
    Ok(writer.into_inner())
}

/// Builds an ISO 9660 + Joliet image in memory from `inputs`, using the shared filesystem walk.
fn build_iso<S: AsRef<str>>(inputs: &[S]) -> io::Result<Vec<u8>> {
    use libarchive_oxide_core::format::iso9660::IsoWriter;
    let mut writer = IsoWriter::new(Vec::new());
    for input in inputs {
        let name = normalize_name(input.as_ref());
        add_path(&mut writer, Path::new(input.as_ref()), &name)?;
    }
    writer.finish().map_err(to_io)?;
    Ok(writer.into_inner())
}

/// Builds a zip archive in memory from `inputs`, using the shared filesystem walk.
fn build_zip<S: AsRef<str>>(inputs: &[S], zip: &ZipOptions) -> io::Result<Vec<u8>> {
    let mut writer = ZipWriter::with_options(Vec::new(), zip.clone());
    for input in inputs {
        let name = normalize_name(input.as_ref());
        add_path(&mut writer, Path::new(input.as_ref()), &name)?;
    }
    writer.finish().map_err(to_io)?;
    Ok(writer.into_inner())
}

/// Recursively adds `fs_path` (with archive name `name`, raw bytes) to the writer.
fn add_path<W: EntryWriter>(writer: &mut W, fs_path: &Path, name: &[u8]) -> io::Result<()> {
    let file_type = fs::symlink_metadata(fs_path)?.file_type();

    if file_type.is_symlink() {
        let target = fs::read_link(fs_path)?;
        write_entry(
            writer,
            EntryKind::Symlink,
            name,
            0o777,
            &[],
            Some(&os_bytes(target.as_os_str())),
        )?;
    } else if file_type.is_dir() {
        let mut dir_name = name.to_vec();
        dir_name.push(b'/');
        write_entry(writer, EntryKind::Dir, &dir_name, 0o755, &[], None)?;

        let mut children: Vec<_> = fs::read_dir(fs_path)?.collect::<io::Result<_>>()?;
        children.sort_by_key(std::fs::DirEntry::file_name);
        for child in children {
            let mut child_name = name.to_vec();
            child_name.push(b'/');
            child_name.extend_from_slice(&os_bytes(&child.file_name()));
            add_path(writer, &child.path(), &child_name)?;
        }
    } else if file_type.is_file() {
        let data = fs::read(fs_path)?;
        write_entry(writer, EntryKind::File, name, 0o644, &data, None)?;
    }
    // FIFOs, character/block devices, and sockets are skipped: reading them could block forever
    // or allocate without bound (e.g. /dev/zero).
    Ok(())
}

/// Writes a single entry (header + payload) to the writer.
fn write_entry<W: EntryWriter>(
    writer: &mut W,
    kind: EntryKind,
    name: &[u8],
    mode: u32,
    data: &[u8],
    link: Option<&[u8]>,
) -> io::Result<()> {
    let mut meta = EntryMeta::new(kind, Cow::Borrowed(name));
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

/// Normalizes a filesystem argument into a safe relative tar entry name (raw bytes):
/// strips a leading `/` (so members are never absolute) and any `./` prefix or trailing `/`.
/// On Windows, backslashes are treated as separators; on other platforms they are left literal.
fn normalize_name(arg: &str) -> Vec<u8> {
    #[cfg(windows)]
    let owned = arg.replace('\\', "/");
    #[cfg(windows)]
    let mut s: &str = &owned;
    #[cfg(not(windows))]
    let mut s: &str = arg;

    s = s.trim_end_matches('/');
    while let Some(rest) = s.strip_prefix("./") {
        s = rest;
    }
    s = s.trim_start_matches('/');
    s.as_bytes().to_vec()
}

/// Returns the raw bytes of an `OsStr`, preserving non-UTF-8 names where the platform allows it.
#[cfg(unix)]
fn os_bytes(s: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    s.as_bytes().to_vec()
}

/// On non-Unix targets, `OsStr` is not raw bytes; fall back to a lossy UTF-8 view.
#[cfg(not(unix))]
fn os_bytes(s: &OsStr) -> Vec<u8> {
    s.to_string_lossy().into_owned().into_bytes()
}

/// Maps a sans-IO core error into a std I/O error.
fn to_io(e: libarchive_oxide_core::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::normalize_name;

    #[test]
    fn normalize_strips_leading_slash_and_dot() {
        assert_eq!(normalize_name("/etc/hosts"), b"etc/hosts");
        assert_eq!(normalize_name("./a/b"), b"a/b");
        assert_eq!(normalize_name("dir/"), b"dir");
        assert_eq!(normalize_name("plain"), b"plain");
    }
}
