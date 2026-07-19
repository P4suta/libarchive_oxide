// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Archive detection and filesystem extraction.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use libarchive_oxide_core::format::ar::{Ar, ArReader};
use libarchive_oxide_core::format::cpio::{Cpio, CpioReader};
use libarchive_oxide_core::format::iso9660::{Iso9660, IsoReader};
use libarchive_oxide_core::format::tar::{Tar, TarReader};
use libarchive_oxide_core::format::{ArchiveFormat, Detection};
use libarchive_oxide_core::{EntryData, EntryKind, EntryMeta, EntryReader, OwnedData, Result};

use crate::path::sanitize;
use crate::zip::ZipReader;

/// Runtime-selected entry data.
#[derive(Debug)]
pub enum AnyEntryData<'a> {
    /// A core (`no_std`) format's cursor (tar/cpio/ar).
    Core(libarchive_oxide_core::AnyEntryData<'a>),
    /// Zip's per-entry decompressed buffer.
    Owned(OwnedData),
}

impl Default for AnyEntryData<'_> {
    fn default() -> Self {
        Self::Owned(OwnedData::default())
    }
}

impl EntryData for AnyEntryData<'_> {
    fn read_chunk(&mut self, out: &mut [u8]) -> Result<usize> {
        match self {
            Self::Core(d) => d.read_chunk(out),
            Self::Owned(d) => d.read_chunk(out),
        }
    }
}

/// Runtime-selected archive reader implementation.
#[derive(Debug)]
enum AnyReaderKind<'a> {
    Core(libarchive_oxide_core::AnyReader<'a>),
    Zip(ZipReader<'a>),
    #[cfg(feature = "sevenz")]
    SevenZ(crate::sevenz::SevenZReader<'a>),
}

/// Runtime-selected archive reader.
///
/// Implements [`EntryReader`] with [`AnyEntryData`].
#[derive(Debug)]
pub struct AnyReader<'a> {
    kind: AnyReaderKind<'a>,
    slot: AnyEntryData<'a>,
}

impl<'a> EntryReader for AnyReader<'a> {
    type Data = AnyEntryData<'a>;

    fn next_entry(&mut self) -> Result<Option<libarchive_oxide_core::Entry<'_, AnyEntryData<'a>>>> {
        let meta: EntryMeta<'static> = match &mut self.kind {
            AnyReaderKind::Core(r) => match r.next_entry()? {
                Some(mut e) => {
                    let meta = e.meta().to_static();
                    self.slot = AnyEntryData::Core(core::mem::take(e.data()));
                    meta
                },
                None => return Ok(None),
            },
            AnyReaderKind::Zip(r) => match r.next_entry()? {
                Some(mut e) => {
                    let meta = e.meta().to_static();
                    self.slot = AnyEntryData::Owned(core::mem::take(e.data()));
                    meta
                },
                None => return Ok(None),
            },
            #[cfg(feature = "sevenz")]
            AnyReaderKind::SevenZ(r) => match r.next_entry()? {
                Some(mut e) => {
                    let meta = e.meta().to_static();
                    self.slot = AnyEntryData::Owned(core::mem::take(e.data()));
                    meta
                },
                None => return Ok(None),
            },
        };
        Ok(Some(libarchive_oxide_core::Entry::new(
            meta,
            &mut self.slot,
        )))
    }
}

/// Detects the archive format from `plain` (already decompressed) and builds a reader.
///
/// Recognizes zip, 7z, tar, ISO 9660, ar, and cpio.
pub fn reader(plain: &[u8]) -> io::Result<AnyReader<'_>> {
    reader_with_password(plain, None)
}

/// Like [`reader`], but supplies a password used to decrypt `WinZip` AES (method 99) zip entries.
/// The password is ignored for non-zip and non-encrypted archives.
pub fn reader_with_password<'a>(
    plain: &'a [u8],
    password: Option<&[u8]>,
) -> io::Result<AnyReader<'a>> {
    let kind = if crate::zip::is_zip(plain) {
        let zr = match password {
            Some(pw) => ZipReader::with_password(plain, pw),
            None => ZipReader::new(plain),
        };
        AnyReaderKind::Zip(zr)
    } else if sevenz_reader(plain) {
        #[cfg(feature = "sevenz")]
        {
            AnyReaderKind::SevenZ(crate::sevenz::SevenZReader::new(plain))
        }
        #[cfg(not(feature = "sevenz"))]
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "libarchive_oxide: 7z support not built in (enable the `sevenz` feature)",
            ));
        }
    } else if matches!(Tar::sniff(plain), Detection::Match) {
        AnyReaderKind::Core(libarchive_oxide_core::AnyReader::tar(TarReader::new(plain)))
    } else if matches!(Ar::sniff(plain), Detection::Match) {
        AnyReaderKind::Core(libarchive_oxide_core::AnyReader::ar(ArReader::new(plain)))
    } else if matches!(Cpio::sniff(plain), Detection::Match) {
        AnyReaderKind::Core(libarchive_oxide_core::AnyReader::cpio(CpioReader::new(
            plain,
        )))
    } else if matches!(Iso9660::sniff(plain), Detection::Match) {
        AnyReaderKind::Core(libarchive_oxide_core::AnyReader::iso(IsoReader::new(plain)))
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "libarchive_oxide: unrecognized archive format",
        ));
    };
    Ok(AnyReader {
        kind,
        slot: AnyEntryData::default(),
    })
}

/// Whether `plain` begins with the 7z signature magic. Detection is independent of the `sevenz`
/// feature so the reader chain can emit a clear "not built in" error rather than misclassifying.
fn sevenz_reader(plain: &[u8]) -> bool {
    plain.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])
}

/// Counts of what an extraction materialized.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Regular files written.
    pub files: usize,
    /// Directories created.
    pub dirs: usize,
    /// Entries skipped (unsafe path, or an unsupported kind such as symlink/device).
    pub skipped: usize,
}

/// Extracts every entry of `reader` under `dest`, sanitizing each path against traversal.
///
/// Files and directories are materialized; symlinks, devices, and unsafe paths are counted as
/// skipped (a conservative, portable default). `dest` is created if missing.
pub fn extract<R: EntryReader>(reader: &mut R, dest: &Path) -> io::Result<Stats> {
    fs::create_dir_all(dest)?;
    let mut stats = Stats::default();

    while let Some(mut entry) = reader.next_entry().map_err(to_io)? {
        let kind = entry.meta().kind;
        let Some(rel) = sanitize(&entry.meta().path) else {
            stats.skipped += 1;
            continue;
        };
        let path = dest.join(&rel);

        match kind {
            EntryKind::Dir => {
                fs::create_dir_all(&path)?;
                stats.dirs += 1;
            },
            EntryKind::File => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut file = fs::File::create(&path)?;
                let mut buf = [0u8; 16 * 1024];
                loop {
                    let n = entry.data().read_chunk(&mut buf).map_err(to_io)?;
                    if n == 0 {
                        break;
                    }
                    file.write_all(&buf[..n])?;
                }
                stats.files += 1;
            },
            _ => stats.skipped += 1,
        }
    }

    Ok(stats)
}

/// Maps a sans-IO core error into a std I/O error for the std surface.
fn to_io(e: libarchive_oxide_core::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{e}"))
}
