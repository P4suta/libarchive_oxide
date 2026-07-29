// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Built-in archive format identifiers and core implementations.

use crate::protocol::ProbeResult;
use core::fmt;

pub(crate) mod ar;
pub(crate) mod cpio;
pub(crate) mod empty;
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
    /// XAR extensible archive (read-only).
    pub const Xar: Self = Self(9);
    /// Canonical zero-byte archive (read-only).
    pub const Empty: Self = Self(10);
    /// Explicit single-entry raw byte stream (read-only).
    pub const Raw: Self = Self(11);
    /// WARC 1.0 and 1.1 (read-only).
    pub const Warc: Self = Self(12);

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
            (Self::Warc, b"WARC/1.0\r\n".as_slice()),
            (Self::Warc, b"WARC/1.1\r\n".as_slice()),
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
            b"WARC/1.0\r\n".as_slice(),
            b"WARC/1.1\r\n".as_slice(),
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
            _ => return write!(formatter, "FormatId({:#010x})", self.0),
        };
        formatter.write_str(name)
    }
}
