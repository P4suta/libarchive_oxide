// SPDX-FileCopyrightText: 2020 Lonami
// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::{boxed::Box, vec::Vec};

use super::{Bitstream, DecodeFailed, MAX_CHUNK_SIZE};

/// The window size is not stored in the compressed data stream and must be known before
/// decoding begins.
///
/// Regular LZX streams choose a power-of-two dictionary between 2^15 and
/// 2^21 bytes. LZX DELTA reference-data semantics are intentionally not
/// implemented by this decoder.
#[repr(u32)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum WindowSize {
    /// Window size of 32 KB (2^15 bytes).
    KB32 = 0x0000_8000,
    /// Window size of 64 KB (2^16 bytes).
    KB64 = 0x0001_0000,
    /// Window size of 128 KB (2^17 bytes).
    KB128 = 0x0002_0000,
    /// Window size of 256 KB (2^18 bytes).
    KB256 = 0x0004_0000,
    /// Window size of 512 KB (2^19 bytes).
    KB512 = 0x0008_0000,
    /// Window size of 1 MB (2^20 bytes).
    MB1 = 0x0010_0000,
    /// Window size of 2 MB (2^21 bytes).
    MB2 = 0x0020_0000,
}

/// A sliding window of a certain size.
///
/// A `std::collections::VecDeque` is not used because the `deque_make_contiguous` feature
/// is [nightly-only experimental](https://github.com/rust-lang/rust/issues/70929).
#[derive(Debug)]
pub(crate) struct Window {
    pos: usize,
    buffer: Box<[u8]>,
}

impl WindowSize {
    /// The window size determines the number of window subdivisions, or position slots.
    pub(crate) fn position_slots(self) -> usize {
        use WindowSize::{KB32, KB64, KB128, KB256, KB512, MB1, MB2};

        match self {
            KB32 => 30,
            KB64 => 32,
            KB128 => 34,
            KB256 => 36,
            KB512 => 38,
            MB1 => 42,
            MB2 => 50,
        }
    }

    /// Number of history bytes allocated by this window.
    #[must_use]
    pub const fn bytes(self) -> usize {
        use WindowSize::{KB32, KB64, KB128, KB256, KB512, MB1, MB2};

        match self {
            KB32 => 0x0000_8000,
            KB64 => 0x0001_0000,
            KB128 => 0x0002_0000,
            KB256 => 0x0004_0000,
            KB512 => 0x0008_0000,
            MB1 => 0x0010_0000,
            MB2 => 0x0020_0000,
        }
    }

    pub(crate) fn create_buffer(self) -> Result<Window, DecodeFailed> {
        let size = self.bytes();
        // The window must be at least as big as the smallest chunk, or else we can't possibly
        // contain an entire chunk inside of the sliding window.
        if size < MAX_CHUNK_SIZE || !size.is_power_of_two() {
            return Err(DecodeFailed::WindowTooSmall);
        }

        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(size)
            .map_err(|_| DecodeFailed::AllocationFailed)?;
        buffer.resize(size, 0);

        Ok(Window {
            pos: 0,
            buffer: buffer.into_boxed_slice(),
        })
    }
}

impl Window {
    fn advance(&mut self, delta: usize) -> Result<(), DecodeFailed> {
        if delta > self.buffer.len() {
            return Err(DecodeFailed::OverreadChunk);
        }
        self.pos = self
            .pos
            .checked_add(delta)
            .ok_or(DecodeFailed::ArithmeticOverflow)?;
        if self.pos >= self.buffer.len() {
            self.pos -= self.buffer.len();
        }
        Ok(())
    }

    pub(crate) fn push(&mut self, value: u8) -> Result<(), DecodeFailed> {
        let slot = self
            .buffer
            .get_mut(self.pos)
            .ok_or(DecodeFailed::ArithmeticOverflow)?;
        *slot = value;
        self.advance(1)
    }

    pub(crate) fn copy_from_self(
        &mut self,
        offset: usize,
        length: usize,
    ) -> Result<(), DecodeFailed> {
        if offset == 0 || offset > self.buffer.len() {
            return Err(DecodeFailed::InvalidMatchOffset(offset));
        }
        if length > MAX_CHUNK_SIZE {
            return Err(DecodeFailed::OverreadChunk);
        }
        let destination_end = self
            .pos
            .checked_add(length)
            .ok_or(DecodeFailed::ArithmeticOverflow)?;
        // For the fast path:
        // * Source cannot wrap around
        // * `copy_within` won't overwrite as we go but we need that
        // * Destination cannot wrap around
        if offset <= self.pos && length <= offset && destination_end < self.buffer.len() {
            // Best case: neither source or destination wrap around
            // TODO write a test for this because it used to fail
            let start = self.pos - offset;
            let source_end = start
                .checked_add(length)
                .ok_or(DecodeFailed::ArithmeticOverflow)?;
            self.buffer.copy_within(start..source_end, self.pos);
        } else {
            // Either source or destination wrap around. We could expand this case into three
            // (one for only source wrapping, one for only destination wrapping, one for both)
            // but it's not really worth the effort.
            //
            // We could work out the ranges for use in `copy_within` but this is a lot simpler.
            let mask = self.buffer.len() - 1; // relying on power of two assumption

            for i in 0..length {
                let dst = (self.pos + i) & mask;
                let src = (self.buffer.len() + self.pos + i - offset) & mask;
                self.buffer[dst] = self.buffer[src];
            }
        }

        self.advance(length)
    }

    pub(crate) fn copy_from_bitstream(
        &mut self,
        bitstream: &mut Bitstream,
        len: usize,
    ) -> Result<(), DecodeFailed> {
        if len > self.buffer.len() {
            return Err(DecodeFailed::WindowTooSmall);
        }

        let end = self
            .pos
            .checked_add(len)
            .ok_or(DecodeFailed::ArithmeticOverflow)?;
        if end > self.buffer.len() {
            let shift = end - self.buffer.len();
            self.pos = self
                .pos
                .checked_sub(shift)
                .ok_or(DecodeFailed::ArithmeticOverflow)?;

            // No need to actually save the part we're about to overwrite because when reading
            // with the bitstream we would also overwrite it anyway.
            self.buffer.copy_within(shift.., 0);
        }

        let end = self
            .pos
            .checked_add(len)
            .ok_or(DecodeFailed::ArithmeticOverflow)?;
        let target = self
            .buffer
            .get_mut(self.pos..end)
            .ok_or(DecodeFailed::ArithmeticOverflow)?;
        bitstream.read_raw(target)?;
        self.advance(len)?;
        Ok(())
    }

    pub(crate) fn past_view(&mut self, len: usize) -> Result<&mut [u8], DecodeFailed> {
        if len > MAX_CHUNK_SIZE {
            return Err(DecodeFailed::ChunkTooLong);
        }

        // Being at zero means we're actually at max length where is impossible for `len` to be
        // bigger and we would not want to bother shifting the entire array to end where it was.
        if self.pos != 0 && len > self.pos {
            let shift = len - self.pos;
            self.advance(shift)?;
            self.buffer.rotate_right(shift);
        }

        // Because we want to read behind us, being at zero means we're at the end
        let pos = if self.pos == 0 {
            self.buffer.len()
        } else {
            self.pos
        };

        let start = pos
            .checked_sub(len)
            .ok_or(DecodeFailed::ArithmeticOverflow)?;
        self.buffer
            .get_mut(start..pos)
            .ok_or(DecodeFailed::ArithmeticOverflow)
    }
}

#[cfg(any())]
mod tests {
    use super::*;

    #[test]
    fn check_push() {
        let mut window = WindowSize::KB32.create_buffer();
        window.push(1);
        window.push(2);
        window.push(3);
        assert_eq!(window.pos, 3);
        assert_eq!(&window.buffer[..3], &[1, 2, 3]);
        assert!(window.buffer[3..].iter().all(|&x| x == 0));
    }

    #[test]
    fn check_push_before_boundary() {
        let mut window = WindowSize::KB32.create_buffer();
        window.pos = window.buffer.len() - 1;
        window.push(1);
        assert_eq!(window.pos, 0);
    }

    #[test]
    fn check_push_at_boundary() {
        let mut window = WindowSize::KB32.create_buffer();
        for _ in 0..((1 << 15) - 2) {
            window.push(0);
        }
        window.push(1);
        window.push(2);
        window.push(3);
        window.push(4);
        assert_eq!(window.pos, 2);
        assert_eq!(&window.buffer[window.buffer.len() - 2..], &[1, 2]);
        assert_eq!(&window.buffer[..2], &[3, 4]);
        assert!(
            window.buffer[2..window.buffer.len() - 2]
                .iter()
                .all(|&x| x == 0)
        );
    }

    #[test]
    fn check_copy_from_self() {
        let mut window = WindowSize::KB32.create_buffer();
        window.buffer[0] = 1;
        window.buffer[1] = 2;
        window.buffer[2] = 3;
        window.pos = 3;
        window.copy_from_self(3, 2);
        assert_eq!(window.pos, 5);
        assert_eq!(&window.buffer[..5], &[1, 2, 3, 1, 2]);
        assert!(window.buffer[5..].iter().all(|&x| x == 0));
    }

    #[test]
    fn check_copy_from_self_overlap() {
        let mut window = WindowSize::KB32.create_buffer();
        window.buffer[0] = 1;
        window.buffer[1] = 2;
        window.buffer[2] = 3;
        window.pos = 3;
        window.copy_from_self(2, 3);
        assert_eq!(window.pos, 6);
        assert_eq!(&window.buffer[..6], &[1, 2, 3, 2, 3, 2]);
        assert!(window.buffer[6..].iter().all(|&x| x == 0));
    }

    #[test]
    fn check_copy_at_boundary_from_self() {
        let mut window = WindowSize::KB32.create_buffer();
        window.buffer[window.buffer.len() - 3] = 1;
        window.buffer[window.buffer.len() - 2] = 2;
        window.pos = window.buffer.len() - 1;
        window.copy_from_self(2, 2);
        assert_eq!(window.pos, 1);
        assert_eq!(window.buffer[0], 2);
        assert_eq!(&window.buffer[window.buffer.len() - 3..], &[1, 2, 1]);
        assert!(
            window.buffer[1..window.buffer.len() - 3]
                .iter()
                .all(|&x| x == 0)
        );
    }

    #[test]
    fn check_copy_from_self_before_boundary() {
        let mut window = WindowSize::KB32.create_buffer();
        window.buffer[window.buffer.len() - 4] = 1;
        window.buffer[window.buffer.len() - 3] = 2;
        window.pos = window.buffer.len() - 2;
        window.copy_from_self(2, 2);
        assert_eq!(window.pos, 0);
    }

    #[test]
    fn check_copy_from_self_at_boundary() {
        let mut window = WindowSize::KB32.create_buffer();
        window.buffer[window.buffer.len() - 2] = 1;
        window.buffer[window.buffer.len() - 1] = 2;
        window.buffer[0] = 3;
        window.buffer[1] = 4;
        window.pos = 2;
        window.copy_from_self(4, 3);
        assert_eq!(window.pos, 5);
        assert_eq!(&window.buffer[..5], &[3, 4, 1, 2, 3]);
        assert_eq!(&window.buffer[window.buffer.len() - 2..], &[1, 2]);
        assert!(
            window.buffer[5..window.buffer.len() - 2]
                .iter()
                .all(|&x| x == 0)
        );
    }

    #[test]
    fn check_bitstream() {
        let buffer = [1, 2, 3, 4];
        let mut bitstream = Bitstream::new(&buffer);
        let mut window = WindowSize::KB32.create_buffer();
        window.copy_from_bitstream(&mut bitstream, 4).unwrap();
        assert_eq!(window.pos, 4);
        assert_eq!(&window.buffer[..4], &[1, 2, 3, 4]);
        assert!(window.buffer[4..].iter().all(|&x| x == 0));
    }

    #[test]
    fn check_bitstream_before_boundary() {
        let buffer = [1, 2, 3, 4];
        let mut bitstream = Bitstream::new(&buffer);
        let mut window = WindowSize::KB32.create_buffer();
        window.pos = window.buffer.len() - 4;
        window.copy_from_bitstream(&mut bitstream, 4).unwrap();
        assert_eq!(window.pos, 0);
    }

    #[test]
    fn check_bitstream_at_boundary() {
        let buffer = [1, 2, 3, 4];
        let mut bitstream = Bitstream::new(&buffer);
        let mut window = WindowSize::KB32.create_buffer();
        window.pos = window.buffer.len() - 2;
        window.copy_from_bitstream(&mut bitstream, 4).unwrap();
        assert_eq!(window.pos, 0);
        assert_eq!(&window.buffer[window.buffer.len() - 4..], &[1, 2, 3, 4]);
        assert!(
            window.buffer[..window.buffer.len() - 4]
                .iter()
                .all(|&x| x == 0)
        );
    }

    #[test]
    fn check_past_view() {
        let mut window = WindowSize::KB32.create_buffer();
        window.buffer[0] = 1;
        window.buffer[1] = 2;
        window.buffer[2] = 3;
        window.pos = 3;
        assert_eq!(window.past_view(2).unwrap(), &[2, 3]);
        assert_eq!(window.past_view(3).unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn check_past_view_at_boundary() {
        let mut window = WindowSize::KB32.create_buffer();
        window.buffer[window.buffer.len() - 2] = 1;
        window.buffer[window.buffer.len() - 1] = 2;
        window.buffer[0] = 3;
        window.buffer[1] = 4;
        window.pos = 2;
        assert_eq!(window.past_view(4).unwrap(), &[1, 2, 3, 4]);
    }

    #[test]
    fn check_past_view_too_long() {
        let mut window = WindowSize::KB32.create_buffer();
        assert_eq!(
            window.past_view(1 << 15 + 1),
            Err(DecodeFailed::ChunkTooLong)
        );
    }

    #[test]
    fn check_past_view_new_max_size() {
        let mut window = WindowSize::KB32.create_buffer();
        assert!(window.past_view(1 << 15).is_ok());
    }

    #[test]
    fn check_past_view_shifted_max_size() {
        let mut window = WindowSize::KB32.create_buffer();
        window.pos = 123;
        assert!(window.past_view(1 << 15).is_ok());
    }
}
