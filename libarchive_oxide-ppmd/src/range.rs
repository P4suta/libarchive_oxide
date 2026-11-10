// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: Apache-2.0

use crate::Error;

const TOP: u32 = 1 << 24;
const RAR_BOTTOM: u32 = 0x8000;
const BIN_SCALE: u32 = 1 << 14;
const MAX_EOF_PADDING: usize = 64;

/// Carryless range decoder used by RAR 3.x/4.x `PPMd` blocks.
#[derive(Clone, Debug)]
pub struct RarRangeDecoder<'input> {
    input: &'input [u8],
    position: usize,
    padding: usize,
    low: u32,
    code: u32,
    range: u32,
}

impl<'input> RarRangeDecoder<'input> {
    /// Primes a RAR range decoder from its four-byte initial code.
    pub fn new(input: &'input [u8]) -> Result<Self, Error> {
        if input.len() < 4 {
            return Err(Error::UnexpectedEnd);
        }
        let code = u32::from_be_bytes([input[0], input[1], input[2], input[3]]);
        if code == u32::MAX {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            input,
            position: 4,
            padding: 0,
            low: 0,
            code,
            range: u32::MAX,
        })
    }

    /// Number of physical input bytes fetched by the decoder.
    #[must_use]
    pub const fn consumed(&self) -> usize {
        self.position
    }

    pub(crate) fn get_threshold(&mut self, total: u32) -> Result<u32, Error> {
        if total == 0 {
            return Err(Error::Corrupt);
        }
        self.range /= total;
        if self.range == 0 {
            return Err(Error::Corrupt);
        }
        Ok(self.code.wrapping_sub(self.low) / self.range)
    }

    pub(crate) fn decode(&mut self, start: u32, size: u32) -> Result<(), Error> {
        if size == 0 {
            return Err(Error::Corrupt);
        }
        self.low = self.low.wrapping_add(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize()
    }

    pub(crate) fn decode_bit(&mut self, size_zero: u32) -> Result<bool, Error> {
        let value = self.get_threshold(BIN_SCALE)?;
        if value < size_zero {
            self.decode(0, size_zero)?;
            Ok(false)
        } else {
            self.decode(size_zero, BIN_SCALE - size_zero)?;
            Ok(true)
        }
    }

    fn normalize(&mut self) -> Result<(), Error> {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= TOP {
                if self.range >= RAR_BOTTOM {
                    return Ok(());
                }
                self.range = self.low.wrapping_neg() & (RAR_BOTTOM - 1);
            }
            self.code = self.code.wrapping_shl(8) | u32::from(self.next_byte()?);
            self.range = self.range.wrapping_shl(8);
            self.low = self.low.wrapping_shl(8);
        }
    }

    fn next_byte(&mut self) -> Result<u8, Error> {
        if let Some(byte) = self.input.get(self.position).copied() {
            self.position += 1;
            return Ok(byte);
        }
        self.padding += 1;
        if self.padding > MAX_EOF_PADDING {
            return Err(Error::UnexpectedEnd);
        }
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialization_is_exact_and_bounded() {
        assert_eq!(
            RarRangeDecoder::new(&[0, 1, 2]).unwrap_err(),
            Error::UnexpectedEnd
        );
        assert_eq!(
            RarRangeDecoder::new(&[0xff; 4]).unwrap_err(),
            Error::Corrupt
        );
        let decoder = RarRangeDecoder::new(&[1, 2, 3, 4]).unwrap();
        assert_eq!(decoder.consumed(), 4);
    }
}
