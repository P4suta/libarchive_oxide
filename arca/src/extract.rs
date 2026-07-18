//! Archive format auto-detection and safe filesystem extraction (the std entry points).

use std::fs;
use std::io::{self, Write};
use std::path::Path;

use arca_core::format::ar::{Ar, ArReader};
use arca_core::format::cpio::{Cpio, CpioReader};
use arca_core::format::iso9660::{Iso9660, IsoReader};
use arca_core::format::tar::{Tar, TarReader};
use arca_core::format::{ArchiveFormat, Detection};
use arca_core::{EntryData, EntryKind, EntryMeta, EntryReader, OwnedData, Result};

use crate::path::sanitize;
use crate::zip::ZipReader;

/// The payload cursor of whichever std-side archive is being read. The `EntryData` dual of
/// [`AnyReader`]: a sealed enum bundling the core cursor kinds and zip's owned buffer, so dispatch
/// stays fully monomorphized (no type erasure). Adding a std format is a compiler-checked exhaustiveness
/// obligation.
#[derive(Debug)]
pub enum AnyEntryData<'a> {
    /// A core (`no_std`) format's cursor (tar/cpio/ar).
    Core(arca_core::AnyEntryData<'a>),
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

/// The concrete kind of std-side archive reader, selected at runtime. Sealed enum; the exhaustive
/// `match` in [`AnyReader::next_entry`] fails to compile if a variant is added unhandled.
#[derive(Debug)]
enum AnyReaderKind<'a> {
    Core(arca_core::AnyReader<'a>),
    Zip(ZipReader<'a>),
    #[cfg(feature = "sevenz")]
    SevenZ(crate::sevenz::SevenZReader<'a>),
}

/// Runtime-selected std archive reader, dispatched over a sealed enum with **zero type erasure**.
/// It is itself an [`EntryReader`] (`Data = AnyEntryData`), returned by value from [`reader`].
///
/// Like [`arca_core::AnyReader`], `next_entry` re-homes the inner entry into `self.slot`: the
/// metadata is deep-cloned to an owned form and the payload cursor is lifted out by `mem::take`
/// (both inner cursor kinds are `Default`).
#[derive(Debug)]
pub struct AnyReader<'a> {
    kind: AnyReaderKind<'a>,
    slot: AnyEntryData<'a>,
}

impl<'a> EntryReader for AnyReader<'a> {
    type Data = AnyEntryData<'a>;

    fn next_entry(&mut self) -> Result<Option<arca_core::Entry<'_, AnyEntryData<'a>>>> {
        let meta: EntryMeta<'static> = match &mut self.kind {
            AnyReaderKind::Core(r) => match r.next_entry()? {
                Some(mut e) => {
                    let meta = e.meta().to_static();
                    self.slot = AnyEntryData::Core(core::mem::take(e.data()));
                    meta
                }
                None => return Ok(None),
            },
            AnyReaderKind::Zip(r) => match r.next_entry()? {
                Some(mut e) => {
                    let meta = e.meta().to_static();
                    self.slot = AnyEntryData::Owned(core::mem::take(e.data()));
                    meta
                }
                None => return Ok(None),
            },
            #[cfg(feature = "sevenz")]
            AnyReaderKind::SevenZ(r) => match r.next_entry()? {
                Some(mut e) => {
                    let meta = e.meta().to_static();
                    self.slot = AnyEntryData::Owned(core::mem::take(e.data()));
                    meta
                }
                None => return Ok(None),
            },
        };
        Ok(Some(arca_core::Entry::new(meta, &mut self.slot)))
    }
}

/// Detects the archive format from `plain` (already decompressed) and builds a reader.
///
/// Recognizes zip, tar, ar, and cpio. Errors if the bytes match none of them. The reader is
/// returned **by value** (a sealed [`AnyReader`] enum), never boxed behind a trait object.
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
                "arca: 7z support not built in (enable the `sevenz` feature)",
            ));
        }
    } else if matches!(Tar::sniff(plain), Detection::Match) {
        AnyReaderKind::Core(arca_core::AnyReader::tar(TarReader::new(plain)))
    } else if matches!(Ar::sniff(plain), Detection::Match) {
        AnyReaderKind::Core(arca_core::AnyReader::ar(ArReader::new(plain)))
    } else if matches!(Cpio::sniff(plain), Detection::Match) {
        AnyReaderKind::Core(arca_core::AnyReader::cpio(CpioReader::new(plain)))
    } else if matches!(Iso9660::sniff(plain), Detection::Match) {
        AnyReaderKind::Core(arca_core::AnyReader::iso(IsoReader::new(plain)))
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "arca: unrecognized archive format",
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
            }
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
            }
            _ => stats.skipped += 1,
        }
    }

    Ok(stats)
}

/// Maps a sans-IO core error into a std I/O error for the std surface.
fn to_io(e: arca_core::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{e}"))
}
