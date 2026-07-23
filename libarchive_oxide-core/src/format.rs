// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Built-in archive format identifiers and core implementations.

use crate::protocol::ProbeResult;

pub(crate) mod ar;
pub(crate) mod cpio;
pub(crate) mod tar;

/// Stable, extensible identifier for a built-in archive format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FormatId {
    /// POSIX tar and its ustar/PAX/GNU dialects.
    Tar,
    /// cpio.
    Cpio,
    /// Unix ar and thin ar.
    Ar,
    /// ZIP.
    Zip,
    /// 7-Zip.
    SevenZip,
    /// ISO 9660.
    Iso9660,
    /// Microsoft Cabinet (read-only).
    Cab,
    /// XAR extensible archive (read-only).
    Xar,
}

impl FormatId {
    /// Probes every built-in archive format using one common three-way
    /// incremental contract.
    #[must_use]
    pub fn probe(prefix: &[u8]) -> ProbeResult<Self> {
        const ISO_SIGNATURE_END: usize = 16 * 2048 + 6;

        for (identifier, signature) in [
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

        if prefix.len() >= ISO_SIGNATURE_END
            && prefix[16 * 2048 + 1..ISO_SIGNATURE_END] == *b"CD001"
        {
            return ProbeResult::Match(Self::Iso9660);
        }
        if matches!(tar::TarDecoder::probe(prefix), ProbeResult::Match(())) {
            return ProbeResult::Match(Self::Tar);
        }

        let mut minimum = usize::MAX;
        for signature in [
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
        if prefix.len() < ISO_SIGNATURE_END {
            minimum = minimum.min(ISO_SIGNATURE_END);
        }
        if minimum == usize::MAX {
            ProbeResult::NoMatch
        } else {
            ProbeResult::NeedMore { minimum }
        }
    }
}
