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
const LHA: &[&str] = &["lha"];
const RAR: &[&str] = &["rar"];
const SEVENZ: &[&str] = &["sevenz"];
const BZIP2: &[&str] = &["bzip2"];
const ZSTD: &[&str] = &["zstd"];
const XZ: &[&str] = &["xz"];
const PPMD: &[&str] = &["ppmd"];
const LZ4: &[&str] = &["lz4"];
const LZOP: &[&str] = &["lzop"];
const COMPRESS: &[&str] = &["compress"];
const LZIP: &[&str] = &["lzip"];
const LZMA: &[&str] = &["lzma"];
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
        "v7, ustar, pax, and GNU dialects; archive and entry metadata are lossless-or-error, preserving exact 12-bit permission modes, opaque global PAX and last-wins comment multiplicity alongside coherent typed entry comments/owners/times/xattrs/ACL fields, field-exact GNU sparse records, and Char/Block devices through the 8-byte base-256 maximum; global keys that override future entries, foreign extensions, typed/raw conflicts, higher mode bits, untyped or unsupported sparse/device properties, and unsupported filesystem fields or kinds fail before entry output",
    ),
    CapabilityRecord::new(
        "format.cpio",
        CapabilitySubject::Format(FormatId::Cpio),
        "cpio",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "binary LE/BE, odc, newc, and crc; 12-bit permission modes, owner IDs, non-negative whole-second mtime, dialect-bounded inode/link/device/size fields, and dialect-correct CRC sums are lossless-or-error, with required-size, reserved TRAILER!!! path, and default-newc u32 projection shared by transcoding; higher mode bits and unsupported or lossy entry fields are rejected before output",
    ),
    CapabilityRecord::new(
        "format.ar",
        CapabilitySubject::Format(FormatId::Ar),
        "ar",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "GNU, BSD, and thin-member metadata; control-looking short paths plus long paths use four-byte-padded BSD inline names, while 12-bit regular-file mode, fixed-width numeric owner, non-negative whole-second mtime, and ten-digit member size including padded inline-name bytes are lossless-or-error; missing sizes, higher mode bits, unsupported kinds, lossy times, and numeric overflow are rejected before output",
    ),
    CapabilityRecord::new(
        "format.zip",
        CapabilitySubject::Format(FormatId::Zip),
        "zip",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "bounded forward-only local-header reads for Store/Deflate/Deflate64/BZip2/LZMA/Zstandard/XZ/PPMd8, including signed classic/ZIP64 descriptors and unsigned descriptors for self-terminating Deflate/Deflate64/BZip2/PPMd8, EOS-terminated LZMA, and a single standard Zstandard frame; LZMA and PPMd8 use acknowledged pull-worker input so only range-decoder-owned bytes are committed. ZipCrypto and WinZip AES Store/Deflate/BZip2/LZMA/Zstandard/XZ/PPMd8 use the same path with ordered OpenOptions password candidates; EOS-terminated LZMA, PPMd8, and Deflate64 additionally compose with both wrappers under known sizes or signed/unsigned classic/ZIP64 descriptors. Seek reads retain every listed method and encryption profile and project non-directory central-directory DOS attributes into typed file flags. Standard multi-disk archives use caller-owned bounded VolumeSet sources or explicit terminal .zip/.z01 path discovery, translate classic and ZIP64 disk-relative central/local offsets, and compose with every supported compression/encryption decoder; nonempty archive/file comments, exact typed owner/time/12-bit permission-mode/low-byte non-directory DOS file-flag fields, field-coherent timestamp/Unix-owner and applicable Unicode path/comment extras, non-structural two-byte raw extras, serialized pathname bounds, and bounded metadata-owned unencrypted symlink targets are lossless-or-error; higher mode or file-flag bits, indistinguishable empty typed comments, unsupported kinds/fields, typed/raw conflicts, encrypted symlinks, and container-owned or malformed extras are rejected or reported by transcoding",
    ),
    CapabilityRecord::new(
        "format.7z",
        CapabilitySubject::Format(FormatId::SevenZip),
        "7z",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "general coder-graph reader with bounded caller-owned split-volume input and explicit path-based numeric sibling discovery; solid and one-folder-per-stream writers across every listed coder; File/Dir/Symlink path/mode/size/target metadata, non-structural Windows file flags, and checked full-range u64 FILETIME mtimes are lossless-or-error, metadata-owned symlink payloads transcode without duplication, unknown archive/file properties round-trip, and unrepresentable typed fields plus end-marker or container-owned raw properties fail before entry output; archive metadata replacement accounts only the current bounded property set",
    ),
    CapabilityRecord::new(
        "format.iso9660",
        CapabilitySubject::Format(FormatId::Iso9660),
        "iso9660",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "ISO 9660, Rock Ridge/SUSP continuation areas, Joliet, and bounded multi-extent/interleaved/extended-attribute reads with typed ECMA owner, permission, and year 0–9999 time metadata at exact 10 ms precision; writes and transcoding preserve File/Dir/Symlink/Char/Block/Fifo/Socket kinds, u32-bounded PX/PN owner/inode/link/device metadata, 12-bit modes, and u32 entry sizes, while hardlinks, owner names, comments, required out-of-range devices, and other unrepresentable typed fields fail before output or become explicit optional-field losses; primary/Joliet descriptor geometry, declared volume bounds, and per-record volume-sequence checks prevent mis-sized, trailer, or cross-volume reads; PVD-exact volume names, nonempty/non-trimmed system/application identifiers, and canonical unknown SUSP fields round-trip losslessly, and replacement accounts only the current metadata",
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
        "read-only; explicit bounded multi-cabinet continuation through root VolumeArchiveReader over OpenOptions and caller-owned VolumeSet",
    ),
    CapabilityRecord::new(
        "format.xar",
        CapabilitySubject::Format(FormatId::Xar),
        "xar",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "Store/zlib/BZip2 seek writer with independent per-entry streams, codec-memory preflight, encoded-expansion bounds, and a bounded spill-to-disk heap spool",
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
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "WARC 1.0 and 1.1 records; strict bounded CRLF framing, required declared content sizes, streamed content blocks, and lossless named-field extensions; virtual entry paths are collision-free record-ID/sequence projections and mode is normalized to 0644, both reported explicitly by transcoding",
    ),
    CapabilityRecord::new(
        "format.rar-legacy",
        CapabilitySubject::Format(FormatId::RarLegacy),
        "rar-legacy",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "bounded RAR 3.x/4.x container, Store entries, and feature-gated clean-room RAR3 LZ77/Huffman plus PPMd-H/PPMd-II blocks for methods 0x31-0x35 with decoded CRC32; AES-gated RAR3 AES-128-CBC reads decrypt bounded headers and non-solid, non-split file data through ordered OpenOptions candidates, cache zeroizing candidate keys per salt, and release plaintext only after exact size and CRC32 validation; all five standard RAR3 VM filters use validated fingerprints and closed-enum execution without arbitrary bytecode interpretation; one concrete decoder retains either LZ dictionary/Huffman/distance state or the bounded PPMd model plus its shared output window and standard-program table across sequential solid members; packed, unpacked, ciphertext/candidate/output, fixed workspace, filter programs/queue/scratch, and requested PPMd heap bytes are preflighted against in-flight and codec-memory budgets, including one retained packed copy for bounded non-solid split-volume joins; arbitrary VM programs and encrypted solid, split-volume, or symlink payloads remain typed unsupported; checksum-verified streamed auxiliary/recovery blocks are reported without repair; raw flags, Unicode names, times, ownership/modes/attributes, SFX, 64-bit sizes, Store symlinks, bounded VolumeSet Store/compressed joins, and adjacent-volume discovery are preserved; writing is license-excluded",
    ),
    CapabilityRecord::new(
        "format.rar5",
        CapabilitySubject::Format(FormatId::Rar5),
        "rar5",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "bounded RAR5 container, Store entries, and feature-gated clean-room generation-0 RAR5 LZ77/Huffman methods 1-5 with x86 E8/E9, Delta, and ARM filters plus decoded CRC32/BLAKE2sp verification; AES-gated RAR5 AES-256-CBC reads decrypt bounded headers, services, and single-volume non-solid Store/LZ file data through at most 16 ordered OpenOptions password candidates, a finite PBKDF2-HMAC-SHA256 budget, zeroizing cached keys, bounded AES-padding replay, and raw or HMAC-tweaked CRC32/BLAKE2sp authentication before plaintext release; exact dictionaries, each self-described encoded block, ciphertext/candidate/output, filter scratch, and the pending-filter queue are preflighted against codec-memory and in-flight budgets without bounding total packed size; one bounded concrete decoder state continues unencrypted generation-0 compressed file members across both sequential solid and caller-owned VolumeSet boundaries with per-part and logical checksums, while independently compressed comment/quick-open/recovery/ACL/alternate-stream services use a separate concrete decoder and decoded-size budgets without leaking service bytes as entry data; CRC-checked unknown headers carrying skip-if-unknown discard their exact data extent without allocation; generation 1/RAR7, encrypted solid/split members, encrypted payloads without CRC32/BLAKE2sp, solid or split services, and rare filter types 4-7 remain typed unsupported; comments, quick-open/recovery reporting without repair, ACL/alternate-stream records, names/times/ownership/attributes/versions/links/extras, adjacent-volume discovery, and Store joins are preserved; writing is license-excluded",
    ),
    CapabilityRecord::new(
        "format.lha",
        CapabilitySubject::Format(FormatId::Lha),
        "lha",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "read-only levels 0–3; bounded lh0/lh1/lh2/lh3/lh4/lh5/lh6/lh7/lhx/lzs/lz4/lz5/pm0/pm1/pm2 payloads with CRC16 verification; lh2/lh3 preflight whole packed/output buffering while the other compressed methods stream fixed dictionaries; MZ SFX prefixes are scanned with a fixed 4 KiB window through 20 KiB and their byte length is reported",
    ),
    CapabilityRecord::new(
        "format.mtree",
        CapabilitySubject::Format(FormatId::Mtree),
        "mtree",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "mtree v1/v2 manifests; octal escapes including comment-looking names, defaults, relative NUL-free traversal, typed metadata, and unknown keyword preservation; unrepresentable paths fail before output, and contents paths are metadata only and never opened",
    ),
    CapabilityRecord::new(
        "method.zip.store",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(0),
        },
        "Store",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "forward-only descriptor reads require the optional signature because stored payloads have no self-terminating boundary; ZipCrypto known-size and signed-descriptor reads validate the 12-byte header, CRC32, and both sizes",
    ),
    CapabilityRecord::new(
        "method.lha.lh0",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-lh0-"),
        },
        "LH0 Store",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "",
    ),
    CapabilityRecord::new(
        "method.lha.lh1",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-lh1-"),
        },
        "LH1",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "4 KiB dictionary",
    ),
    CapabilityRecord::new(
        "method.lha.lh2",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-lh2-"),
        },
        "LH2",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "8 KiB dictionary; whole packed/output buffers are preflighted; checked-in evidence is a clean-room same-codec vector, not an independent producer fixture",
    ),
    CapabilityRecord::new(
        "method.lha.lh3",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-lh3-"),
        },
        "LH3",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "8 KiB dictionary and canonical block trees; whole packed/output buffers are preflighted; checked-in evidence is a first-party specification vector, not an independent producer fixture",
    ),
    CapabilityRecord::new(
        "method.lha.lh4",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-lh4-"),
        },
        "LH4",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "4 KiB dictionary",
    ),
    CapabilityRecord::new(
        "method.lha.lh5",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-lh5-"),
        },
        "LH5",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "8 KiB dictionary",
    ),
    CapabilityRecord::new(
        "method.lha.lh6",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-lh6-"),
        },
        "LH6",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "32 KiB dictionary",
    ),
    CapabilityRecord::new(
        "method.lha.lh7",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-lh7-"),
        },
        "LH7",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "64 KiB dictionary",
    ),
    CapabilityRecord::new(
        "method.lha.lhx",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-lhx-"),
        },
        "UNLHA32 LHx",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "512 KiB dictionary",
    ),
    CapabilityRecord::new(
        "method.lha.lzs",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-lzs-"),
        },
        "LArc LZS",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "2 KiB dictionary",
    ),
    CapabilityRecord::new(
        "method.lha.lz4",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-lz4-"),
        },
        "LArc LZ4 Store",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "",
    ),
    CapabilityRecord::new(
        "method.lha.lz5",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-lz5-"),
        },
        "LArc LZ5",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "4 KiB dictionary",
    ),
    CapabilityRecord::new(
        "method.lha.pm0",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-pm0-"),
        },
        "PM0 Store",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "",
    ),
    CapabilityRecord::new(
        "method.lha.pm1",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-pm1-"),
        },
        "PMArc PM1",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "16 KiB dictionary",
    ),
    CapabilityRecord::new(
        "method.lha.pm2",
        CapabilitySubject::Method {
            format: FormatId::Lha,
            id: MethodId::Bytes(b"-pm2-"),
        },
        "PMArc PM2",
        SEEK_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        LHA,
        "8 KiB dictionary",
    ),
    CapabilityRecord::new(
        "method.zip.deflate",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(8),
        },
        "Deflate",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "forward-only reads accept signed or unsigned classic/ZIP64 descriptors; ZipCrypto reads accept known sizes or signed descriptors with committed ciphertext accounting",
    ),
    CapabilityRecord::new(
        "method.zip.deflate64",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(9),
        },
        "Deflate64",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        DEFLATE64,
        "read-only; plain, ZipCrypto, and WinZip AES forward-only reads accept known local sizes or signed/unsigned classic/ZIP64 descriptors, and the seek path composes with both encryption wrappers; writing remains unavailable",
    ),
    CapabilityRecord::new(
        "method.zip.bzip2",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(12),
        },
        "BZip2",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        BZIP2,
        "forward-only reads accept signed or unsigned classic/ZIP64 descriptors; ZipCrypto reads accept known sizes or signed descriptors through a direct consumed-byte decompressor",
    ),
    CapabilityRecord::new(
        "method.zip.lzma",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(14),
        },
        "LZMA",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        XZ,
        "bounded pull decoders stream seek and forward-only members without whole-member buffering; known extents accept declared-size and EOS-marker conventions, while acknowledged worker input exposes exact ownership for EOS-terminated signed/unsigned classic/ZIP64 descriptors and composes with ZipCrypto and WinZip AES",
    ),
    CapabilityRecord::new(
        "method.zip.zstd",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(93),
        },
        "Zstandard",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        ZSTD,
        "forward-only reads accept known local sizes or signed/unsigned classic/ZIP64 descriptors around one standard frame; ZipCrypto reads accept known sizes or signed descriptors with structural frame tracking; seek reads additionally accept concatenated frames",
    ),
    CapabilityRecord::new(
        "method.zip.xz",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(95),
        },
        "XZ",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        XZ,
        "complete XZ stream with allocation-bearing headers validated before decode; forward-only plain and ZipCrypto reads accept known local sizes and signed classic/ZIP64 descriptors, while unsigned descriptors are rejected",
    ),
    CapabilityRecord::new(
        "method.zip.ppmd8",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(98),
        },
        "PPMd8",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        PPMD,
        "variant I revision 1; bounded seek and forward-only reads plus streaming writes with limit-checked model memory; known local sizes and signed/unsigned classic/ZIP64 descriptors compose with plain, ZipCrypto, and WinZip AES input through exact range-decoder acknowledgements",
    ),
    CapabilityRecord::new(
        "method.zip.aes",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Numeric(99),
        },
        "WinZip AES",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        AES,
        "authenticated AE-2 wrapper; forward-only OpenOptions reads cover Store/Deflate/BZip2/Zstandard/XZ with known sizes or signed classic/ZIP64 descriptors plus EOS-terminated LZMA, PPMd8, and Deflate64 with known sizes or signed/unsigned classic/ZIP64 descriptors, all three AES strengths, ordered password candidates, bounded one-byte sync/futures/Tokio input, and bounded authenticated XZ padding; seek reads and streaming writes cover the same compression methods. The underlying compression method is recorded separately",
    ),
    CapabilityRecord::new(
        "method.zip.zipcrypto",
        CapabilitySubject::Method {
            format: FormatId::Zip,
            id: MethodId::Name("general-purpose bit 0"),
        },
        "Traditional ZipCrypto",
        SEQUENTIAL_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        AES,
        "weak legacy compatibility wrapper; forward-only OpenOptions reads cover Store/Deflate/BZip2/Zstandard/XZ with known sizes or signed classic/ZIP64 descriptors plus EOS-terminated LZMA, PPMd8, and read-only Deflate64 with known sizes or signed/unsigned classic/ZIP64 descriptors, ordered password candidates, and bounded one-byte sync/futures/Tokio input; seek reads and streaming writes cover the same writable compression methods. CRC32 remains the integrity check, and one-byte verifier collisions continue through payload validation",
    ),
    CapabilityRecord::new(
        "method.7z.store",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x00]),
        },
        "Store",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "solid/non-solid pass-through with CRC32",
    ),
    CapabilityRecord::new(
        "method.7z.lzma",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x01, 0x01]),
        },
        "LZMA",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "solid/non-solid raw LZMA1 with bounded dictionary",
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
        "solid/non-solid LZMA2 with bounded dictionary",
    ),
    CapabilityRecord::new(
        "method.7z.bzip2",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x04, 0x02, 0x02]),
        },
        "BZip2",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ_BZIP2,
        "feature-gated solid/non-solid BZip2 folders",
    ),
    CapabilityRecord::new(
        "method.7z.zstd",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x04, 0xf7, 0x11, 0x01]),
        },
        "Zstandard",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ_ZSTD,
        "feature-gated bounded solid/non-solid Zstandard frames",
    ),
    CapabilityRecord::new(
        "method.7z.ppmd",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x04, 0x01]),
        },
        "PPMd",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "solid/non-solid PPMd7 variant H with limit-checked model memory",
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
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "bounded byte filter; distance 1..=256",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-x86",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x01, 0x03]),
        },
        "BCJ x86",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "bounded reversible branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-ppc",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x02, 0x05]),
        },
        "BCJ PowerPC",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "bounded reversible branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-ia64",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x04, 0x01]),
        },
        "BCJ IA-64",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "bounded reversible branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-arm",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x05, 0x01]),
        },
        "BCJ ARM",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "bounded reversible branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-arm-thumb",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x07, 0x01]),
        },
        "BCJ ARM Thumb",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "bounded reversible branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-sparc",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x03, 0x03, 0x08, 0x05]),
        },
        "BCJ SPARC",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "bounded reversible branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-arm64",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x0a]),
        },
        "BCJ ARM64",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "bounded reversible branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.bcj-riscv",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x0b]),
        },
        "BCJ RISC-V",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "bounded reversible branch filter",
    ),
    CapabilityRecord::new(
        "method.7z.deflate",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x04, 0x01, 0x08]),
        },
        "Deflate",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ,
        "solid/non-solid raw RFC 1951 DEFLATE coder",
    ),
    CapabilityRecord::new(
        "method.7z.aes256-sha256",
        CapabilitySubject::Method {
            format: FormatId::SevenZip,
            id: MethodId::Bytes(&[0x06, 0xf1, 0x07, 0x01]),
        },
        "AES-256/SHA-256",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        SEVENZ_AES,
        "solid/non-solid bounded CBC; ordered header/folder password candidates, CRC preflight before plaintext, candidate-local decoder failures without masked source I/O, per-folder random salt/IV, and capped SHA-256 KDF",
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
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "writer emits canonical zlib-compressed TOC and stored heap payloads",
    ),
    CapabilityRecord::new(
        "method.xar.zlib",
        CapabilitySubject::Method {
            format: FormatId::Xar,
            id: MethodId::Name("application/x-gzip"),
        },
        "zlib",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "writer emits one bounded zlib stream per regular-file heap payload",
    ),
    CapabilityRecord::new(
        "method.xar.bzip2",
        CapabilitySubject::Method {
            format: FormatId::Xar,
            id: MethodId::Name("application/x-bzip2"),
        },
        "BZip2",
        SEEK_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        BZIP2,
        "writer emits one bounded BZip2 stream per regular-file heap payload",
    ),
    CapabilityRecord::new(
        "method.rar-legacy.store",
        CapabilitySubject::Method {
            format: FormatId::RarLegacy,
            id: MethodId::Numeric(0x30),
        },
        "Store",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "regular files, directories, and CRC-preflighted stored Unix symlinks; AES-gated single-volume regular-file reads buffer bounded AES-128-CBC ciphertext and try ordered passwords without exposing plaintext before exact size/CRC32 validation; encrypted symlinks and split/solid encrypted data remain unsupported; caller-owned VolumeSet joins unencrypted split regular-file parts with bounded continuation and CRC32 validation; RAR writing is license-excluded",
    ),
    CapabilityRecord::new(
        "method.rar-legacy.aes128",
        CapabilitySubject::Method {
            format: FormatId::RarLegacy,
            id: MethodId::Name("file flag 0x0004"),
        },
        "RAR3 AES-128-CBC",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        AES,
        "read-only header and non-solid/non-split data encryption with optional 8-byte file salts, mandatory 8-byte encrypted-header salts, the fixed 2^18-round SHA-1 KDF including RAR3's long-password compatibility behavior, ordered zeroizing password candidates, bounded whole-ciphertext candidate replay, and CRC-before-plaintext release; encrypted solid/split files and symlinks remain unsupported; RAR writing is license-excluded",
    ),
    CapabilityRecord::new(
        "method.rar5.store",
        CapabilitySubject::Method {
            format: FormatId::Rar5,
            id: MethodId::Numeric(0),
        },
        "Store",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "unencrypted payloads; encrypted entry headers are structurally validated and listable before payload access returns typed unsupported; caller-owned VolumeSet joins unencrypted split file parts with bounded continuation and checksum validation; RAR writing is license-excluded",
    ),
    CapabilityRecord::new(
        "method.rar-legacy.lz-1",
        CapabilitySubject::Method {
            format: FormatId::RarLegacy,
            id: MethodId::Numeric(0x31),
        },
        "RAR3 level 1 (LZ/PPMd)",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        RAR,
        "whole-payload bounded clean-room LZ77/Huffman and PPMd-H/PPMd-II decode with sequential solid continuation and non-solid split-volume joins; AES-gated encrypted single-volume/non-solid data uses candidate-local decoders and CRC-before-plaintext release; all five standard RAR3 VM filters use bounded closed-enum execution, while arbitrary VM bytecode remains unsupported; PPMd model and filter workspace are preflighted against the codec budget; encrypted solid/split data, solid split-volume compression, and writing are unsupported",
    ),
    CapabilityRecord::new(
        "method.rar-legacy.lz-2",
        CapabilitySubject::Method {
            format: FormatId::RarLegacy,
            id: MethodId::Numeric(0x32),
        },
        "RAR3 level 2 (LZ/PPMd)",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        RAR,
        "whole-payload bounded clean-room LZ77/Huffman and PPMd-H/PPMd-II decode with sequential solid continuation and non-solid split-volume joins; AES-gated encrypted single-volume/non-solid data uses candidate-local decoders and CRC-before-plaintext release; all five standard RAR3 VM filters use bounded closed-enum execution, while arbitrary VM bytecode remains unsupported; PPMd model and filter workspace are preflighted against the codec budget; encrypted solid/split data, solid split-volume compression, and writing are unsupported",
    ),
    CapabilityRecord::new(
        "method.rar-legacy.lz-3",
        CapabilitySubject::Method {
            format: FormatId::RarLegacy,
            id: MethodId::Numeric(0x33),
        },
        "RAR3 level 3 (LZ/PPMd)",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        RAR,
        "whole-payload bounded clean-room LZ77/Huffman and PPMd-H/PPMd-II decode with sequential solid continuation and non-solid split-volume joins; AES-gated encrypted single-volume/non-solid data uses candidate-local decoders and CRC-before-plaintext release; all five standard RAR3 VM filters use bounded closed-enum execution, while arbitrary VM bytecode remains unsupported; PPMd model and filter workspace are preflighted against the codec budget; encrypted solid/split data, solid split-volume compression, and writing are unsupported",
    ),
    CapabilityRecord::new(
        "method.rar-legacy.lz-4",
        CapabilitySubject::Method {
            format: FormatId::RarLegacy,
            id: MethodId::Numeric(0x34),
        },
        "RAR3 level 4 (LZ/PPMd)",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        RAR,
        "whole-payload bounded clean-room LZ77/Huffman and PPMd-H/PPMd-II decode with sequential solid continuation and non-solid split-volume joins; AES-gated encrypted single-volume/non-solid data uses candidate-local decoders and CRC-before-plaintext release; all five standard RAR3 VM filters use bounded closed-enum execution, while arbitrary VM bytecode remains unsupported; PPMd model and filter workspace are preflighted against the codec budget; encrypted solid/split data, solid split-volume compression, and writing are unsupported",
    ),
    CapabilityRecord::new(
        "method.rar-legacy.lz-5",
        CapabilitySubject::Method {
            format: FormatId::RarLegacy,
            id: MethodId::Numeric(0x35),
        },
        "RAR3 level 5 (LZ/PPMd)",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        RAR,
        "whole-payload bounded clean-room LZ77/Huffman and PPMd-H/PPMd-II decode with sequential solid continuation and non-solid split-volume joins; AES-gated encrypted single-volume/non-solid data uses candidate-local decoders and CRC-before-plaintext release; all five standard RAR3 VM filters use bounded closed-enum execution, while arbitrary VM bytecode remains unsupported; PPMd model and filter workspace are preflighted against the codec budget; encrypted solid/split data, solid split-volume compression, and writing are unsupported",
    ),
    CapabilityRecord::new(
        "method.rar5.lz-1",
        CapabilitySubject::Method {
            format: FormatId::Rar5,
            id: MethodId::Numeric(1),
        },
        "RAR5 LZ level 1",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        RAR,
        "bounded generation-0 LZ77/Huffman decode for file and independent sequential service payloads with x86, Delta, and ARM filters plus sequential and split-volume solid-file continuation; generation 1, solid/split services, rare filter types 4-7, and writing are unsupported",
    ),
    CapabilityRecord::new(
        "method.rar5.lz-2",
        CapabilitySubject::Method {
            format: FormatId::Rar5,
            id: MethodId::Numeric(2),
        },
        "RAR5 LZ level 2",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        RAR,
        "bounded generation-0 LZ77/Huffman decode for file and independent sequential service payloads with x86, Delta, and ARM filters plus sequential and split-volume solid-file continuation; generation 1, solid/split services, rare filter types 4-7, and writing are unsupported",
    ),
    CapabilityRecord::new(
        "method.rar5.lz-3",
        CapabilitySubject::Method {
            format: FormatId::Rar5,
            id: MethodId::Numeric(3),
        },
        "RAR5 LZ level 3",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        RAR,
        "bounded generation-0 LZ77/Huffman decode for file and independent sequential service payloads with x86, Delta, and ARM filters plus sequential and split-volume solid-file continuation; generation 1, solid/split services, rare filter types 4-7, and writing are unsupported",
    ),
    CapabilityRecord::new(
        "method.rar5.lz-4",
        CapabilitySubject::Method {
            format: FormatId::Rar5,
            id: MethodId::Numeric(4),
        },
        "RAR5 LZ level 4",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        RAR,
        "bounded generation-0 LZ77/Huffman decode for file and independent sequential service payloads with x86, Delta, and ARM filters plus sequential and split-volume solid-file continuation; generation 1, solid/split services, rare filter types 4-7, and writing are unsupported",
    ),
    CapabilityRecord::new(
        "method.rar5.lz-5",
        CapabilitySubject::Method {
            format: FormatId::Rar5,
            id: MethodId::Numeric(5),
        },
        "RAR5 LZ level 5",
        SEQUENTIAL_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        RAR,
        "bounded generation-0 LZ77/Huffman decode for file and independent sequential service payloads with x86, Delta, and ARM filters plus sequential and split-volume solid-file continuation; generation 1, solid/split services, rare filter types 4-7, and writing are unsupported",
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
        FILTER_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::NONE,
        COMPRESS,
        "Unix compress(1) .Z stream using bounded portable LZW read/write",
    ),
    CapabilityRecord::new(
        "filter.lzip",
        CapabilitySubject::Filter(FilterId::Lzip),
        "lzip",
        FILTER_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::NONE,
        LZIP,
        "strict concatenated lzip reads and canonical single-member writes with bounded LZMA dictionaries",
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
    CapabilityRecord::new(
        "filter.lzma",
        CapabilitySubject::Filter(FilterId::Lzma),
        "lzma-alone",
        FILTER_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::NONE,
        LZMA,
        "bounded portable LZMA1 read/write; explicit-only because the 13-byte header has no magic",
    ),
    CapabilityRecord::new(
        "filter.lzop",
        CapabilitySubject::Filter(FilterId::Lzop),
        "lzop",
        FILTER_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::NONE,
        LZOP,
        "bounded concatenated-member read with Safe Rust LZO1X decompression and deterministic stored-block write",
    ),
    CapabilityRecord::new(
        "filter.uuencode",
        CapabilitySubject::Filter(FilterId::Uuencode),
        "uuencode",
        FILTER_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "bounded POSIX framing; compatible space/backtick decoding and canonical 45-byte-line writing",
    ),
    CapabilityRecord::new(
        "filter.base64",
        CapabilitySubject::Filter(FilterId::Base64),
        "base64",
        FILTER_READ_WRITE,
        DirectionSet::READ_WRITE,
        DirectionSet::READ_WRITE,
        NONE,
        "strict RFC 4648 Base64 with canonical padding; explicit-only to avoid text false positives",
    ),
    CapabilityRecord::new(
        "filter.rpm",
        CapabilitySubject::Filter(FilterId::Rpm),
        "rpm",
        FILTER_READ,
        DirectionSet::READ,
        DirectionSet::READ,
        NONE,
        "bounded RPM lead/header removal; emits the payload for nested compression and cpio detection",
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
            FormatId::RarLegacy,
            FormatId::Rar5,
            FormatId::Lha,
            FormatId::Mtree,
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
            FilterId::Lzma,
            FilterId::Lzop,
            FilterId::Uuencode,
            FilterId::Base64,
            FilterId::Rpm,
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
    fn rar_legacy_store_is_sequential_read_only() {
        let record = method_capability(FormatId::RarLegacy, MethodId::Numeric(0x30))
            .expect("RAR legacy Store capability");
        assert_eq!(record.access().read(), Some(AccessMode::Sequential));
        assert_eq!(record.access().write(), None);
        assert_eq!(record.portable(), DirectionSet::READ);
        assert_eq!(record.native(), DirectionSet::READ);
    }

    #[test]
    fn rar5_store_is_sequential_read_only() {
        let record =
            method_capability(FormatId::Rar5, MethodId::Numeric(0)).expect("RAR5 Store capability");
        assert_eq!(record.access().read(), Some(AccessMode::Sequential));
        assert_eq!(record.access().write(), None);
        assert_eq!(record.portable(), DirectionSet::READ);
        assert_eq!(record.native(), DirectionSet::READ);
    }

    #[test]
    fn rar_lz_methods_are_feature_gated_sequential_read_only() {
        for (format, methods) in [
            (FormatId::RarLegacy, &[0x31, 0x32, 0x33, 0x34, 0x35][..]),
            (FormatId::Rar5, &[1, 2, 3, 4, 5][..]),
        ] {
            for &method in methods {
                let record = method_capability(format, MethodId::Numeric(method))
                    .expect("RAR LZ capability");
                assert_eq!(record.access().read(), Some(AccessMode::Sequential));
                assert_eq!(record.access().write(), None);
                assert_eq!(record.portable(), DirectionSet::READ);
                assert_eq!(record.native(), DirectionSet::READ);
                assert_eq!(record.requirements(), &["rar"]);
            }
        }
    }

    #[test]
    fn zipcrypto_is_sequential_read_write() {
        let record = method_capability(FormatId::Zip, MethodId::Name("general-purpose bit 0"))
            .expect("ZIP ZipCrypto capability");
        assert_eq!(record.access().read(), Some(AccessMode::Sequential));
        assert_eq!(record.access().write(), Some(AccessMode::Sequential));
        assert_eq!(record.portable(), DirectionSet::READ_WRITE);
        assert_eq!(record.native(), DirectionSet::READ_WRITE);
    }

    #[test]
    fn winzip_aes_is_sequential_read_write() {
        let record = method_capability(FormatId::Zip, MethodId::Numeric(99))
            .expect("ZIP WinZip AES capability");
        assert_eq!(record.access().read(), Some(AccessMode::Sequential));
        assert_eq!(record.access().write(), Some(AccessMode::Sequential));
        assert_eq!(record.portable(), DirectionSet::READ_WRITE);
        assert_eq!(record.native(), DirectionSet::READ_WRITE);
    }

    #[test]
    fn sevenz_deflate_is_seek_read_write() {
        let record = method_capability(FormatId::SevenZip, MethodId::Bytes(&[0x04, 0x01, 0x08]))
            .expect("7z Deflate capability");
        assert_eq!(record.access().read(), Some(AccessMode::Seek));
        assert_eq!(record.access().write(), Some(AccessMode::Seek));
        assert_eq!(record.portable(), DirectionSet::READ_WRITE);
        assert_eq!(record.native(), DirectionSet::READ_WRITE);
    }

    #[test]
    fn sevenz_lzma_is_seek_read_write() {
        let record = method_capability(FormatId::SevenZip, MethodId::Bytes(&[0x03, 0x01, 0x01]))
            .expect("7z LZMA capability");
        assert_eq!(record.access().read(), Some(AccessMode::Seek));
        assert_eq!(record.access().write(), Some(AccessMode::Seek));
        assert_eq!(record.portable(), DirectionSet::READ_WRITE);
        assert_eq!(record.native(), DirectionSet::READ_WRITE);
    }

    #[test]
    fn sevenz_bzip2_is_feature_gated_seek_read_write() {
        let record = method_capability(FormatId::SevenZip, MethodId::Bytes(&[0x04, 0x02, 0x02]))
            .expect("7z BZip2 capability");
        assert_eq!(record.access().read(), Some(AccessMode::Seek));
        assert_eq!(record.access().write(), Some(AccessMode::Seek));
        assert_eq!(record.portable(), DirectionSet::READ_WRITE);
        assert_eq!(record.native(), DirectionSet::READ_WRITE);
        assert_eq!(record.requirements(), &["sevenz", "bzip2"]);
    }

    #[test]
    fn sevenz_zstd_is_feature_gated_seek_read_write() {
        let record = method_capability(
            FormatId::SevenZip,
            MethodId::Bytes(&[0x04, 0xf7, 0x11, 0x01]),
        )
        .expect("7z Zstandard capability");
        assert_eq!(record.access().read(), Some(AccessMode::Seek));
        assert_eq!(record.access().write(), Some(AccessMode::Seek));
        assert_eq!(record.portable(), DirectionSet::READ_WRITE);
        assert_eq!(record.native(), DirectionSet::READ_WRITE);
        assert_eq!(record.requirements(), &["sevenz", "zstd"]);
    }

    #[test]
    fn sevenz_ppmd7_is_seek_read_write_with_a_bounded_model() {
        let record = method_capability(FormatId::SevenZip, MethodId::Bytes(&[0x03, 0x04, 0x01]))
            .expect("7z PPMd7 capability");
        assert_eq!(record.access().read(), Some(AccessMode::Seek));
        assert_eq!(record.access().write(), Some(AccessMode::Seek));
        assert_eq!(record.portable(), DirectionSet::READ_WRITE);
        assert_eq!(record.native(), DirectionSet::READ_WRITE);
        assert_eq!(record.requirements(), &["sevenz"]);
    }

    #[test]
    fn sevenz_delta_is_seek_read_write() {
        let record = method_capability(FormatId::SevenZip, MethodId::Bytes(&[0x03]))
            .expect("7z Delta capability");
        assert_eq!(record.access().read(), Some(AccessMode::Seek));
        assert_eq!(record.access().write(), Some(AccessMode::Seek));
        assert_eq!(record.portable(), DirectionSet::READ_WRITE);
        assert_eq!(record.native(), DirectionSet::READ_WRITE);
    }

    #[test]
    fn all_xar_payload_methods_are_seek_read_write() {
        let format = format_capability(FormatId::Xar).expect("XAR format capability");
        assert_eq!(format.access().read(), Some(AccessMode::Seek));
        assert_eq!(format.access().write(), Some(AccessMode::Seek));
        assert_eq!(format.portable(), DirectionSet::READ_WRITE);
        assert_eq!(format.native(), DirectionSet::READ_WRITE);

        let store = method_capability(FormatId::Xar, MethodId::Name("application/octet-stream"))
            .expect("XAR Store capability");
        assert_eq!(store.access().write(), Some(AccessMode::Seek));
        assert_eq!(store.portable(), DirectionSet::READ_WRITE);

        for encoding in ["application/x-gzip", "application/x-bzip2"] {
            let compressed = method_capability(FormatId::Xar, MethodId::Name(encoding))
                .expect("XAR compressed capability");
            assert_eq!(compressed.access().write(), Some(AccessMode::Seek));
            assert_eq!(compressed.portable(), DirectionSet::READ_WRITE);
            assert_eq!(compressed.native(), DirectionSet::READ_WRITE);
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
