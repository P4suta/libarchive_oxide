// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Built-in archive format identifiers and core implementations.

use crate::protocol::ProbeResult;
use core::fmt;

pub(crate) mod ar;
pub(crate) mod cpio;
pub(crate) mod empty;
pub(crate) mod mtree;
pub(crate) mod rar5;
pub(crate) mod rar_legacy;
pub(crate) mod raw;
pub(crate) mod tar;
pub(crate) mod warc;

/// Stable, extensible archive-format identifier.
///
/// Built-in identifiers are exposed as associated constants. Downstream
/// providers can allocate an identifier in the custom range with
/// [`FormatId::custom`], which rejects values reserved for this crate.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct FormatId(u32);

#[allow(non_upper_case_globals)]
impl FormatId {
    const CUSTOM_BIT: u32 = 1 << 31;

    /// POSIX tar and its ustar/PAX/GNU dialects.
    pub const Tar: Self = Self(1);
    /// cpio.
    pub const Cpio: Self = Self(2);
    /// Unix ar and thin ar.
    pub const Ar: Self = Self(3);
    /// ZIP.
    pub const Zip: Self = Self(4);
    /// 7-Zip.
    pub const SevenZip: Self = Self(5);
    /// ISO 9660.
    pub const Iso9660: Self = Self(6);
    /// Universal Disk Format (read-only).
    pub const Udf: Self = Self(7);
    /// Microsoft Cabinet (read-only).
    pub const Cab: Self = Self(8);
    /// XAR extensible archive.
    pub const Xar: Self = Self(9);
    /// Canonical zero-byte archive (read-only).
    pub const Empty: Self = Self(10);
    /// Explicit single-entry raw byte stream (read-only).
    pub const Raw: Self = Self(11);
    /// WARC 1.0 and 1.1.
    pub const Warc: Self = Self(12);
    /// RAR 3.x and 4.x archives (read-only).
    pub const RarLegacy: Self = Self(13);
    /// RAR 5.x and later archives (read-only).
    pub const Rar5: Self = Self(14);
    /// LHA/LZH archives (read-only).
    pub const Lha: Self = Self(15);
    /// mtree file hierarchies.
    pub const Mtree: Self = Self(16);

    /// Creates a downstream identifier from the collision-free custom range.
    ///
    /// Values below `0x8000_0000` are reserved for built-in formats.
    #[must_use]
    pub const fn custom(value: u32) -> Option<Self> {
        if value & Self::CUSTOM_BIT == Self::CUSTOM_BIT {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the stable numeric representation.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Whether this identifier belongs to the downstream custom range.
    #[must_use]
    pub const fn is_custom(self) -> bool {
        self.0 & Self::CUSTOM_BIT == Self::CUSTOM_BIT
    }

    /// Probes every built-in archive format using one common three-way
    /// incremental contract.
    #[must_use]
    pub fn probe(prefix: &[u8]) -> ProbeResult<Self> {
        const ISO_SIGNATURE_END: usize = 16 * 2048 + 6;
        const UDF_SIGNATURE_END: usize = 17 * 2048 + 6;

        for (identifier, signature) in [
            (Self::Rar5, b"Rar!\x1a\x07\x01\x00".as_slice()),
            (Self::RarLegacy, b"Rar!\x1a\x07\x00".as_slice()),
            (Self::Warc, b"WARC/1.0\r\n".as_slice()),
            (Self::Warc, b"WARC/1.1\r\n".as_slice()),
            (Self::Mtree, b"#mtree".as_slice()),
            (Self::Zip, b"PK\x03\x04".as_slice()),
            (Self::Zip, b"PK\x05\x06".as_slice()),
            (
                Self::SevenZip,
                [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c].as_slice(),
            ),
            (Self::Cab, b"MSCF".as_slice()),
            (Self::Xar, b"xar!".as_slice()),
        ] {
            if prefix.len() >= signature.len() && prefix.starts_with(signature) {
                return ProbeResult::Match(identifier);
            }
        }

        if matches!(cpio::CpioDecoder::probe(prefix), ProbeResult::Match(())) {
            return ProbeResult::Match(Self::Cpio);
        }
        if matches!(ar::ArDecoder::probe(prefix), ProbeResult::Match(())) {
            return ProbeResult::Match(Self::Ar);
        }
        if lha_signature(prefix) {
            return ProbeResult::Match(Self::Lha);
        }

        if prefix.len() >= UDF_SIGNATURE_END
            && prefix[16 * 2048 + 1..16 * 2048 + 6] == *b"BEA01"
            && matches!(
                &prefix[17 * 2048 + 1..UDF_SIGNATURE_END],
                b"NSR02" | b"NSR03"
            )
        {
            return ProbeResult::Match(Self::Udf);
        }
        if prefix.len() >= UDF_SIGNATURE_END
            && prefix.len() >= ISO_SIGNATURE_END
            && prefix[16 * 2048 + 1..ISO_SIGNATURE_END] == *b"CD001"
        {
            return ProbeResult::Match(Self::Iso9660);
        }
        if matches!(tar::TarDecoder::probe(prefix), ProbeResult::Match(())) {
            return ProbeResult::Match(Self::Tar);
        }

        let mut minimum = usize::MAX;
        for signature in [
            b"Rar!\x1a\x07\x01\x00".as_slice(),
            b"Rar!\x1a\x07\x00".as_slice(),
            b"WARC/1.0\r\n".as_slice(),
            b"WARC/1.1\r\n".as_slice(),
            b"#mtree".as_slice(),
            b"PK\x03\x04".as_slice(),
            b"PK\x05\x06".as_slice(),
            [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c].as_slice(),
            b"MSCF".as_slice(),
            b"xar!".as_slice(),
        ] {
            if prefix.len() < signature.len() && signature.starts_with(prefix) {
                minimum = minimum.min(signature.len());
            }
        }
        for result in [
            cpio::CpioDecoder::probe(prefix),
            ar::ArDecoder::probe(prefix),
            tar::TarDecoder::probe(prefix),
        ] {
            if let ProbeResult::NeedMore { minimum: candidate } = result {
                minimum = minimum.min(candidate);
            }
        }
        if prefix.len() < 7 && plausible_lha_prefix(prefix) {
            minimum = minimum.min(7);
        }
        if prefix.len() < UDF_SIGNATURE_END {
            minimum = minimum.min(UDF_SIGNATURE_END);
        }
        if minimum == usize::MAX {
            ProbeResult::NoMatch
        } else {
            ProbeResult::NeedMore { minimum }
        }
    }
}

impl fmt::Debug for FormatId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::Tar => "Tar",
            Self::Cpio => "Cpio",
            Self::Ar => "Ar",
            Self::Zip => "Zip",
            Self::SevenZip => "SevenZip",
            Self::Iso9660 => "Iso9660",
            Self::Udf => "Udf",
            Self::Cab => "Cab",
            Self::Xar => "Xar",
            Self::Empty => "Empty",
            Self::Raw => "Raw",
            Self::Warc => "Warc",
            Self::RarLegacy => "RarLegacy",
            Self::Rar5 => "Rar5",
            Self::Lha => "Lha",
            Self::Mtree => "Mtree",
            _ => return write!(formatter, "FormatId({:#010x})", self.0),
        };
        formatter.write_str(name)
    }
}

fn lha_signature(prefix: &[u8]) -> bool {
    prefix.len() >= 7
        && prefix[2] == b'-'
        && prefix[6] == b'-'
        && matches!(
            &prefix[3..6],
            b"lh0"
                | b"lh1"
                | b"lh2"
                | b"lh3"
                | b"lh4"
                | b"lh5"
                | b"lh6"
                | b"lh7"
                | b"lh8"
                | b"lh9"
                | b"lhx"
                | b"lhd"
                | b"lzs"
                | b"lz4"
                | b"lz5"
                | b"pm0"
                | b"pm1"
                | b"pm2"
        )
}

fn plausible_lha_prefix(prefix: &[u8]) -> bool {
    prefix.len() <= 2
        || (prefix.get(2) == Some(&b'-') && prefix.get(3).is_none_or(|b| *b == b'l' || *b == b'p'))
}

#[cfg(test)]
mod tests {
    use super::FormatId;
    use crate::ProbeResult;
    use alloc::format;

    #[test]
    fn planned_format_ids_are_stable_and_named() {
        assert_eq!(FormatId::RarLegacy.as_raw(), 13);
        assert_eq!(FormatId::Rar5.as_raw(), 14);
        assert_eq!(FormatId::Lha.as_raw(), 15);
        assert_eq!(FormatId::Mtree.as_raw(), 16);
        assert_eq!(format!("{:?}", FormatId::RarLegacy), "RarLegacy");
        assert_eq!(format!("{:?}", FormatId::Rar5), "Rar5");
        assert_eq!(format!("{:?}", FormatId::Lha), "Lha");
        assert_eq!(format!("{:?}", FormatId::Mtree), "Mtree");
    }

    #[test]
    fn rar_generations_probe_independently_and_incrementally() {
        assert_eq!(
            FormatId::probe(b"Rar!\x1a\x07\x00"),
            ProbeResult::Match(FormatId::RarLegacy)
        );
        assert_eq!(
            FormatId::probe(b"Rar!\x1a\x07\x01\x00"),
            ProbeResult::Match(FormatId::Rar5)
        );
        assert_eq!(
            FormatId::probe(b"Rar!\x1a\x07\x01"),
            ProbeResult::NeedMore { minimum: 8 }
        );
    }

    #[test]
    fn lha_and_mtree_have_conservative_signatures() {
        assert_eq!(
            FormatId::probe(b"\x16\x00-lh5-"),
            ProbeResult::Match(FormatId::Lha)
        );
        assert_eq!(
            FormatId::probe(b"\x4a\x00-lhx-"),
            ProbeResult::Match(FormatId::Lha)
        );
        assert_eq!(
            FormatId::probe(b"#mtree\n/set type=file\n"),
            ProbeResult::Match(FormatId::Mtree)
        );
    }
}
