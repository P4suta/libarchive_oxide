// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Machine-readable built-in capability ledger.
//!
//! This table is the canonical source for provider capability queries, CLI
//! reporting, generated support documentation, and capability contract tests.

use crate::{FilterId, FormatId};

/// An archive operation represented in a [`DirectionSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Direction {
    /// Decode or inspect an existing archive.
    Read,
    /// Create an archive or encoded stream.
    Write,
}

/// A typed set of supported archive directions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct DirectionSet(u8);

impl DirectionSet {
    const READ_BIT: u8 = 1;
    const WRITE_BIT: u8 = 2;

    /// No supported direction.
    pub const NONE: Self = Self(0);
    /// Read support only.
    pub const READ: Self = Self(Self::READ_BIT);
    /// Write support only.
    pub const WRITE: Self = Self(Self::WRITE_BIT);
    /// Read and write support.
    pub const READ_WRITE: Self = Self(Self::READ_BIT | Self::WRITE_BIT);

    /// Whether this set contains a direction.
    #[must_use]
    pub const fn contains(self, direction: Direction) -> bool {
        let bit = match direction {
            Direction::Read => Self::READ_BIT,
            Direction::Write => Self::WRITE_BIT,
        };
        self.0 & bit == bit
    }

    /// Returns the union of two direction sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether no direction is supported.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Input-access model required by a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AccessMode {
    /// Incremental forward-only input.
    Sequential,
    /// Random access through a seek or range source.
    Seek,
    /// A streaming compression filter around another format.
    Filter,
}

/// Direction-specific access requirements for one capability.
///
/// `None` means that the corresponding direction is not implemented. Keeping
/// access next to the direction avoids flattening asymmetric formats such as
/// ZIP, whose reader needs random access while its writer is incremental.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct AccessProfile {
    read: Option<AccessMode>,
    write: Option<AccessMode>,
}

impl AccessProfile {
    /// No implemented direction.
    pub const NONE: Self = Self::new(None, None);

    /// Creates an explicit direction-to-access mapping.
    #[must_use]
    pub const fn new(read: Option<AccessMode>, write: Option<AccessMode>) -> Self {
        Self { read, write }
    }

    /// Uses the same access mode for every direction in `directions`.
    #[must_use]
    pub const fn uniform(directions: DirectionSet, access: AccessMode) -> Self {
        Self {
            read: if directions.contains(Direction::Read) {
                Some(access)
            } else {
                None
            },
            write: if directions.contains(Direction::Write) {
                Some(access)
            } else {
                None
            },
        }
    }

    /// Access required for `direction`, or `None` when it is unsupported.
    #[must_use]
    pub const fn get(self, direction: Direction) -> Option<AccessMode> {
        match direction {
            Direction::Read => self.read,
            Direction::Write => self.write,
        }
    }

    /// Access required when reading.
    #[must_use]
    pub const fn read(self) -> Option<AccessMode> {
        self.read
    }

    /// Access required when writing.
    #[must_use]
    pub const fn write(self) -> Option<AccessMode> {
        self.write
    }

    /// Directions represented by this profile.
    #[must_use]
    pub const fn directions(self) -> DirectionSet {
        let mut directions = DirectionSet::NONE;
        if self.read.is_some() {
            directions = directions.union(DirectionSet::READ);
        }
        if self.write.is_some() {
            directions = directions.union(DirectionSet::WRITE);
        }
        directions
    }
}

/// On-disk identifier for a method inside one archive format.
///
/// Method identifiers are scoped by the containing [`FormatId`]. Formats use
/// different identifier spaces: ZIP and CAB use integers, 7z uses byte
/// strings, and XAR uses XML encoding names. Preserving those representations
/// prevents lossy placeholder codes in the canonical ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MethodId {
    /// Integer method code.
    Numeric(u32),
    /// Opaque byte-string method identifier.
    Bytes(&'static [u8]),
    /// Textual method identifier.
    Name(&'static str),
}

/// The entity described by a capability record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CapabilitySubject {
    /// Whole archive format.
    Format(FormatId),
    /// Compression or storage method inside a format.
    Method {
        /// Containing archive format.
        format: FormatId,
        /// Exact on-disk method identifier.
        id: MethodId,
    },
    /// Outer compression filter.
    Filter(FilterId),
}

/// One canonical capability record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapabilityRecord {
    key: &'static str,
    subject: CapabilitySubject,
    name: &'static str,
    access: AccessProfile,
    portable: DirectionSet,
    native: DirectionSet,
    requirements: &'static [&'static str],
    note: &'static str,
}

impl CapabilityRecord {
    #[allow(clippy::too_many_arguments)] // Mirrors the fixed ledger column schema.
    const fn new(
        key: &'static str,
        subject: CapabilitySubject,
        name: &'static str,
        access: AccessProfile,
        portable: DirectionSet,
        native: DirectionSet,
        requirements: &'static [&'static str],
        note: &'static str,
    ) -> Self {
        Self {
            key,
            subject,
            name,
            access,
            portable,
            native,
            requirements,
            note,
        }
    }

    /// Stable machine key.
    #[must_use]
    pub const fn key(self) -> &'static str {
        self.key
    }

    /// Typed subject.
    #[must_use]
    pub const fn subject(self) -> CapabilitySubject {
        self.subject
    }

    /// Human-readable capability name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Required access model.
    #[must_use]
    pub const fn access(self) -> AccessProfile {
        self.access
    }

    /// Directions implemented by the portable backend.
    #[must_use]
    pub const fn portable(self) -> DirectionSet {
        self.portable
    }

    /// Directions implemented by the native backend.
    #[must_use]
    pub const fn native(self) -> DirectionSet {
        self.native
    }

    /// Cargo features that must all be enabled.
    #[must_use]
    pub const fn requirements(self) -> &'static [&'static str] {
        self.requirements
    }

    /// Short implementation or deficit note.
    #[must_use]
    pub const fn note(self) -> &'static str {
        self.note
    }
}

const NONE: &[&str] = &[];
const CAB_LZX: &[&str] = &["cab-lzx"];
const CAB_QUANTUM: &[&str] = &["cab-quantum"];
const SEVENZ: &[&str] = &["sevenz"];
const BZIP2: &[&str] = &["bzip2"];
const ZSTD: &[&str] = &["zstd"];
const XZ: &[&str] = &["xz"];
const LZ4: &[&str] = &["lz4"];
const COMPRESS: &[&str] = &["compress"];
const LZIP: &[&str] = &["lzip"];
const AES: &[&str] = &["aes"];
const DEFLATE64: &[&str] = &["gzip"];
const SEVENZ_BZIP2: &[&str] = &["sevenz", "bzip2"];
const SEVENZ_ZSTD: &[&str] = &["sevenz", "zstd"];
const SEVENZ_AES: &[&str] = &["sevenz", "aes"];

const SEQUENTIAL_READ: AccessProfile = AccessProfile::new(Some(AccessMode::Sequential), None);
const SEQUENTIAL_READ_WRITE: AccessProfile =
    AccessProfile::new(Some(AccessMode::Sequential), Some(AccessMode::Sequential));
const SEEK_READ: AccessProfile = AccessProfile::new(Some(AccessMode::Seek), None);
const SEEK_READ_WRITE: AccessProfile =
    AccessProfile::new(Some(AccessMode::Seek), Some(AccessMode::Seek));
const SEEK_READ_SEQUENTIAL_WRITE: AccessProfile =
    AccessProfile::new(Some(AccessMode::Seek), Some(AccessMode::Sequential));
const FILTER_READ: AccessProfile = AccessProfile::new(Some(AccessMode::Filter), None);
const FILTER_READ_WRITE: AccessProfile =
    AccessProfile::new(Some(AccessMode::Filter), Some(AccessMode::Filter));

/// Canonical capability ledger for every built-in format, method, and filter.
pub const CAPABILITY_LEDGER: &[CapabilityRecord] = &[
    CapabilityRecord::new(
        "format.tar",
        CapabilitySubject::Format(FormatId::Tar),
        "tar",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "v7, ustar, pax, and GNU dialects",
    ),
    CapabilityRecord::new(
        "format.cpio",
        CapabilitySubject::Format(FormatId::Cpio),
        "cpio",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "binary LE/BE, odc, newc, and crc",
    ),
    CapabilityRecord::new(
        "format.ar",
        CapabilitySubject::Format(FormatId::Ar),
        "ar",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "GNU, BSD, and thin-member metadata",
    ),
    CapabilityRecord::new(
        "format.zip",
        CapabilitySubject::Format(FormatId::Zip),
        "zip",
        SEEK_READ_SEQUENTIAL_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "ZIP64 and bounded entry payload events",
    ),
    CapabilityRecord::new(
        "format.7z",
        CapabilitySubject::Format(FormatId::SevenZip),
        "7z",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "reader supports general coder graphs; writer emits LZMA2",
    ),
    CapabilityRecord::new(
        "format.iso9660",
        CapabilitySubject::Format(FormatId::Iso9660),
        "iso9660",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "ISO 9660, Rock Ridge/SUSP continuation areas, and Joliet",
    ),
    CapabilityRecord::new(
        "format.udf",
        CapabilitySubject::Format(FormatId::Udf),
        "udf",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "read-only UDF 1.02–2.60 with Metadata, Sparable, Metadata-over-Sparable, and Virtual/VAT Partition translation, short/long/extended allocation descriptors, streams, and external EA spaces; writer is intentionally absent",
    ),
    CapabilityRecord::new(
        "format.cab",
        CapabilitySubject::Format(FormatId::Cab),
        "cab",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "read-only; explicit bounded multi-cabinet continuation through advanced::CabVolumeReader over caller-owned VolumeSet",
    ),
    CapabilityRecord::new(
        "format.xar",
        CapabilitySubject::Format(FormatId::Xar),
        "xar",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "read-only",
    ),
    CapabilityRecord::new(
        "format.empty",
        CapabilitySubject::Format(FormatId::Empty),
        "empty",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "canonical zero-byte archive; read-only",
    ),
    CapabilityRecord::new(
        "format.raw",
        CapabilitySubject::Format(FormatId::Raw),
        "raw",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "explicit single-entry byte stream; never auto-detected; read-only",
    ),
    CapabilityRecord::new(
        "format.warc",
        CapabilitySubject::Format(FormatId::Warc),
        "warc",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "WARC 1.0 and 1.1 records; strict bounded CRLF framing; read-only",
    ),
    CapabilityRecord::new(
        "method.zip.store",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(0),
        },
        "Store",
        SEEK_READ_SEQUENTIAL_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "",
    ),
    CapabilityRecord::new(
        "method.zip.deflate",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(8),
        },
        "Deflate",
        SEEK_READ_SEQUENTIAL_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "",
    ),
    CapabilityRecord::new(
        "method.zip.deflate64",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(9),
        },
        "Deflate64",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        DEFLATE64,
        "read-only, including WinZip AES wrapping; no public writer method",
    ),
    CapabilityRecord::new(
        "method.zip.bzip2",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(12),
        },
        "BZip2",
        SEEK_READ_SEQUENTIAL_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        BZIP2,
        "",
    ),
    CapabilityRecord::new(
        "method.zip.lzma",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(14),
        },
        "LZMA",
        SEEK_READ_SEQUENTIAL_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        XZ,
        "",
    ),
    CapabilityRecord::new(
        "method.zip.zstd",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(93),
        },
        "Zstandard",
        SEEK_READ_SEQUENTIAL_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        ZSTD,
        "",
    ),
    CapabilityRecord::new(
        "method.zip.aes",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(99),
        },
        "WinZip AES",
        SEEK_READ_SEQUENTIAL_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        AES,
        "authenticated AE-2 wrapper; the underlying compression method is recorded separately",
    ),
    CapabilityRecord::new(
        "method.7z.lzma",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x01, 0x01]),
        },
        "LZMA",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "",
    ),
    CapabilityRecord::new(
        "method.7z.lzma2",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x21]),
        },
        "LZMA2",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "",
    ),
    CapabilityRecord::new(
        "method.7z.bzip2",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x04, 0x02, 0x02]),
        },
        "BZip2",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ_BZIP2,
        "",
    ),
    CapabilityRecord::new(
        "method.7z.zstd",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x04, 0xf7, 0x11, 0x01]),
        },
        "Zstandard",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ_ZSTD,
        "",
    ),
    CapabilityRecord::new(
        "method.7z.ppmd",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x04, 0x01]),
        },
        "PPMd",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "PPMd7/variant H read-only; archive-declared model memory is limit-checked",
    ),
    CapabilityRecord::new(
        "method.7z.bcj2",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x01, 0x1b]),
        },
        "BCJ2",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "read-only; bounded four-stream junction over shared seek extents",
    ),
    CapabilityRecord::new(
        "method.7z.delta",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03]),
        },
        "Delta",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "read-only; distance 1..=256",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-x86",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x01, 0x03]),
        },
        "BCJ x86",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "read-only branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-ppc",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x02, 0x05]),
        },
        "BCJ PowerPC",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "read-only branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-ia64",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x04, 0x01]),
        },
        "BCJ IA-64",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "read-only branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-arm",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x05, 0x01]),
        },
        "BCJ ARM",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "read-only branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-arm-thumb",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x07, 0x01]),
        },
        "BCJ ARM Thumb",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "read-only branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-sparc",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x08, 0x05]),
        },
        "BCJ SPARC",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "read-only branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-arm64",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x0a]),
        },
        "BCJ ARM64",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "read-only branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-riscv",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x0b]),
        },
        "BCJ RISC-V",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "read-only branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.deflate",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x04, 0x01, 0x08]),
        },
        "Deflate",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "read-only raw DEFLATE coder",
    ),
    CapabilityRecord::new(
        "method.7z.aes256-sha256",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x06, 0xf1, 0x07, 0x01]),
        },
        "AES-256/SHA-256",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ_AES,
        "read-only decryption; requires a caller-supplied password",
    ),
    CapabilityRecord::new(
        "method.cab.store",
        CapabilitySubject::Method {
            format: FormatId::Cab,
            id: MethodId::Numeric(0),
        },
        "Store",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "",
    ),
    CapabilityRecord::new(
        "method.cab.mszip",
        CapabilitySubject::Method {
            format: FormatId::Cab,
            id: MethodId::Numeric(1),
        },
        "MSZIP",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "",
    ),
    CapabilityRecord::new(
        "method.cab.quantum",
        CapabilitySubject::Method {
            format: FormatId::Cab,
            id: MethodId::Numeric(2),
        },
        "Quantum",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        CAB_QUANTUM,
        "read-only; levels 1..=7, 10..=21-bit window, aligned CFDATA trailer, bounded persistent folder dictionary and models",
    ),
    CapabilityRecord::new(
        "method.cab.lzx",
        CapabilitySubject::Method {
            format: FormatId::Cab,
            id: MethodId::Numeric(3),
        },
        "LZX",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        CAB_LZX,
        "read-only; 15..=21-bit window, per-CFDATA word realignment, bounded folder history",
    ),
    CapabilityRecord::new(
        "method.xar.store",
        CapabilitySubject::Method {
            format: FormatId::Xar,
            id: MethodId::Name("application/octet-stream"),
        },
        "Store",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "",
    ),
    CapabilityRecord::new(
        "method.xar.zlib",
        CapabilitySubject::Method {
            format: FormatId::Xar,
            id: MethodId::Name("application/x-gzip"),
        },
        "zlib",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "",
    ),
    CapabilityRecord::new(
        "method.xar.bzip2",
        CapabilitySubject::Method {
            format: FormatId::Xar,
            id: MethodId::Name("application/x-bzip2"),
        },
        "BZip2",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        BZIP2,
        "",
    ),
    CapabilityRecord::new(
        "filter.gzip",
        CapabilitySubject::Filter(FilterId::Gzip),
        "gzip",
        FILTER_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "",
    ),
    CapabilityRecord::new(
        "filter.compress",
        CapabilitySubject::Filter(FilterId::Compress),
        "compress",
        FILTER_READ,
        DirectionSet::READ,
        DirectionSet::NONE,
        COMPRESS,
        "Unix compress(1) .Z stream using bounded LZW; writer is intentionally absent",
    ),
    CapabilityRecord::new(
        "filter.lzip",
        CapabilitySubject::Filter(FilterId::Lzip),
        "lzip",
        FILTER_READ,
        DirectionSet::READ,
        DirectionSet::NONE,
        LZIP,
        "strict concatenated lzip members with bounded LZMA dictionaries; writer is intentionally absent",
    ),
    CapabilityRecord::new(
        "filter.bzip2",
        CapabilitySubject::Filter(FilterId::Bzip2),
        "bzip2",
        FILTER_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        BZIP2,
        "",
    ),
    CapabilityRecord::new(
        "filter.zstd",
        CapabilitySubject::Filter(FilterId::Zstd),
        "zstd",
        FILTER_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        ZSTD,
        "",
    ),
    CapabilityRecord::new(
        "filter.xz",
        CapabilitySubject::Filter(FilterId::Xz),
        "xz",
        FILTER_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        XZ,
        "",
    ),
    CapabilityRecord::new(
        "filter.lz4",
        CapabilitySubject::Filter(FilterId::Lz4),
        "lz4",
        FILTER_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        LZ4,
        "",
    ),
    CapabilityRecord::new(
        "filter.deflate",
        CapabilitySubject::Filter(FilterId::Deflate),
        "deflate",
        FILTER_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        SEVENZ,
        "raw RFC 1951 stream; structurally selected by 7z and never auto-probed",
    ),
];

/// Finds the canonical whole-format record.
#[must_use]
pub fn format_capability(format: FormatId) -> Option<&'static CapabilityRecord> {
    CAPABILITY_LEDGER.iter().find(|record| {
        matches!(record.subject(), CapabilitySubject::Format(candidate) if candidate == format)
    })
}

/// Finds the canonical outer-filter record.
#[must_use]
pub fn filter_capability(filter: FilterId) -> Option<&'static CapabilityRecord> {
    CAPABILITY_LEDGER.iter().find(|record| {
        matches!(record.subject(), CapabilitySubject::Filter(candidate) if candidate == filter)
    })
}

/// Finds a canonical method record by its exact format-scoped identifier.
#[must_use]
pub fn method_capability(format: FormatId, id: MethodId) -> Option<&'static CapabilityRecord> {
    CAPABILITY_LEDGER.iter().find(|record| {
        matches!(
            record.subject(),
            CapabilitySubject::Method {
                format: candidate_format,
                id: candidate_id,
            } if candidate_format == format && candidate_id == id
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_keys_are_unique_and_formats_have_records() {
        for (index, record) in CAPABILITY_LEDGER.iter().enumerate() {
            assert!(
                !CAPABILITY_LEDGER[..index]
                    .iter()
                    .any(|candidate| candidate.key() == record.key()),
                "duplicate capability key: {}",
                record.key()
            );
        }
        for format in [
            FormatId::Tar,
            FormatId::Cpio,
            FormatId::Ar,
            FormatId::Zip,
            FormatId::SevenZip,
            FormatId::Iso9660,
            FormatId::Udf,
            FormatId::Cab,
            FormatId::Xar,
            FormatId::Empty,
            FormatId::Raw,
            FormatId::Warc,
        ] {
            assert!(format_capability(format).is_some(), "{format:?}");
        }
        for filter in [
            FilterId::Gzip,
            FilterId::Zstd,
            FilterId::Xz,
            FilterId::Lz4,
            FilterId::Bzip2,
            FilterId::Deflate,
            FilterId::Compress,
            FilterId::Lzip,
        ] {
            assert!(filter_capability(filter).is_some(), "{filter:?}");
        }
    }

    #[test]
    fn directions_and_access_profiles_are_consistent() {
        for record in CAPABILITY_LEDGER {
            let directions = record.portable().union(record.native());
            assert_eq!(
                record.access().directions(),
                directions,
                "access/direction mismatch for {}",
                record.key()
            );
        }
    }

    #[test]
    fn method_identifiers_are_nonempty_and_unique_per_format() {
        for (index, record) in CAPABILITY_LEDGER.iter().enumerate() {
            let CapabilitySubject::Method { format, id } = record.subject() else {
                continue;
            };
            match id {
                MethodId::Bytes(bytes) => {
                    assert!(!bytes.is_empty(), "empty method byte ID: {}", record.key());
                },
                MethodId::Name(name) => {
                    assert!(!name.is_empty(), "empty method name ID: {}", record.key());
                },
                MethodId::Numeric(_) => {},
            }
            assert!(
                !CAPABILITY_LEDGER[..index].iter().any(|candidate| {
                    matches!(
                        candidate.subject(),
                        CapabilitySubject::Method {
                            format: candidate_format,
                            id: candidate_id,
                        } if candidate_format == format && candidate_id == id
                    )
                }),
                "duplicate method identifier for {}",
                record.key()
            );
            assert_eq!(
                method_capability(format, id).map(|candidate| candidate.key()),
                Some(record.key())
            );
        }
    }

    #[test]
    fn custom_identifiers_cannot_collide_with_builtins() {
        assert!(FormatId::custom(FormatId::Tar.as_raw()).is_none());
        assert!(FilterId::custom(FilterId::Gzip.as_raw()).is_none());
        assert!(FormatId::custom(0x8000_0001).is_some_and(FormatId::is_custom));
        assert!(FilterId::custom(0xffff_fffe).is_some_and(FilterId::is_custom));
    }
}
