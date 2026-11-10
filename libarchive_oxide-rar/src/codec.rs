// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal static protocol shared by the locally owned RAR payload decoders.

use core::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Corrupt,
    UnexpectedEnd,
    BadHeader,
    InvalidHuffmanTree,
    InvalidDistance,
    UnsupportedFilter,
    OutputLimitExceeded,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Corrupt => "RAR payload is corrupt",
            Self::UnexpectedEnd => "RAR payload ended unexpectedly",
            Self::BadHeader => "RAR payload header is malformed",
            Self::InvalidHuffmanTree => "RAR payload has invalid Huffman codes",
            Self::InvalidDistance => "RAR payload has an invalid dictionary distance",
            Self::UnsupportedFilter => "RAR payload uses an unsupported filter",
            Self::OutputLimitExceeded => "RAR payload exceeds its decoded output limit",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Progress {
    pub(crate) consumed: usize,
    pub(crate) written: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Status {
    InputEmpty,
    OutputFull,
    StreamEnd,
}

/// Concrete decoder contract used only through generic static dispatch.
pub(crate) trait Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<(Progress, Status), Error>;

    fn finish(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error>;
}
