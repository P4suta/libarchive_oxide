// SPDX-FileCopyrightText: 2020 Lonami
// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Incremental regular-LZX decompression for CAB-style 32 KiB frames.
//!
//! Lempel-Ziv Extended (LZX) is an LZ77-based compression engine, as described in [UASDC],
//! that is a universal lossless data compression algorithm. It performs no analysis on the
//! data.
//!
//! This fork originated from the `lzxd` crate, but intentionally exposes only
//! regular LZX. LZX DELTA reference data and extended match lengths are not
//! accepted or advertised.
//!
//! In order to use this module, refer to [`LzxDecoder`] and its methods.
//!
//! [UASDC]: https://ieeexplore.ieee.org/document/1055714
use alloc::{boxed::Box, vec::Vec};
use core::{fmt, mem};

pub(crate) use bitstream::Bitstream;
pub(crate) use block::{Block, Decoded, Kind as BlockKind};
pub(crate) use tree::{CanonicalTree, Tree};
use window::Window;
pub use window::WindowSize;

mod bitstream;
mod block;
mod tree;
mod window;

/// A chunk represents exactly 32 KB of uncompressed data until the last chunk in the stream,
/// which can represent less than 32 KB.
pub const MAX_CHUNK_SIZE: usize = 32 * 1024;

/// Conservative non-window workspace bound for one decoder.
///
/// This covers old and newly-built Huffman lookup tables during a block
/// transition, canonical trees, the optional 32 KiB E8 buffer, and fixed
/// state. Add [`WindowSize::bytes`] before constructing a decoder.
pub const MAX_WORKSPACE_OVERHEAD: usize = 640 * 1024;

/// Decoder state needed for new blocks.
// TODO not sure how much we want to keep in DecoderState and LzxDecoder respectively
#[derive(Debug)]
pub(crate) struct DecoderState {
    /// The window size we're working with.
    window_size: WindowSize,

    /// This tree cannot be used directly, it exists only to apply the delta of upcoming trees
    /// to its path lengths.
    main_tree: CanonicalTree,

    /// This tree cannot be used directly, it exists only to apply the delta of upcoming trees
    /// to its path lengths.
    length_tree: CanonicalTree,
}

#[derive(Debug)]
struct PostProcessState {
    /// The pointer in the file at which to stop performing E8 translation.
    e8_translation_size: i32,

    /// A buffer that can be used to hold postprocessed chunks.
    data_chunk: Box<[u8]>,
}

/// Stateful regular-LZX decoder over independently framed input chunks.
///
/// This structure stores the required state to process the compressed chunks of data in a
/// sequential order.
///
/// ```no_run
/// # fn get_compressed_chunk() -> Option<(Vec<u8>, usize)> { None }
/// # fn write_data(_: &[u8]) {}
/// use libarchive_oxide_codecs::lzx::{LzxDecoder, WindowSize};
///
/// let mut lzx = LzxDecoder::new(WindowSize::KB64)?;
///
/// while let Some((chunk, output_size)) = get_compressed_chunk() {
///     let decompressed = lzx.decompress_next(&chunk, output_size)?;
///     write_data(decompressed);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct LzxDecoder {
    /// Sliding window into which data is decompressed.
    window: Window,

    /// Current decoder state.
    state: DecoderState,

    /// > The three most recent real match offsets are kept in a list.
    r: [u32; 3],

    /// The current offset into the decompressed data.
    chunk_offset: usize,

    /// Has the very first chunk been read yet? Unlike the rest, it has additional data.
    first_chunk_read: bool,

    /// Current block.
    current_block: Block,

    /// Information and data related to E8 postprocessing. This is populated after
    /// the first chunk is read.
    postprocess: Option<PostProcessState>,
}

/// Specific cause for decompression failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeFailed {
    /// The chunk data caused a read of more items than the current block had in a single step.
    OverreadBlock,

    /// One decoded element would cross the caller-declared chunk boundary.
    OverreadChunk,

    /// A decoder step produced no bytes and consumed no useful input.
    ZeroProgress,

    /// There was not enough data in the chunk to fully decode, and a premature end was found.
    UnexpectedEof,

    /// An invalid block type was found.
    InvalidBlock(u8),

    /// An invalid block size was found.
    InvalidBlockSize(u32),

    /// An invalid pretree element was found.
    InvalidPretreeElement(u16),

    /// Invalid pretree run-length encoding.
    InvalidPretreeRle,

    /// When attempting to construct a decode tree, we encountered an invalid path length tree.
    InvalidPathLengths,

    /// A required decode tree was empty (all path lengths were 0).
    EmptyTree,

    /// A bit-reader operation requested more bits than its typed contract permits.
    InvalidBitCount(u8),

    /// A match offset was zero or exceeded the available decoded history.
    InvalidMatchOffset(usize),

    /// A match referred to a position slot outside the configured tree.
    InvalidPositionSlot(u16),

    /// The given window size was too small.
    WindowTooSmall,

    /// Tried to read a chunk longer than [`MAX_CHUNK_SIZE`].
    ///
    /// [`MAX_CHUNK_SIZE`]: constant.MAX_CHUNK_SIZE.html
    ChunkTooLong,

    /// A bounded decoder allocation could not be satisfied.
    AllocationFailed,

    /// Bounded position or output accounting overflowed the host address space.
    ArithmeticOverflow,
}

impl fmt::Display for DecodeFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DecodeFailed::{
            AllocationFailed, ArithmeticOverflow, ChunkTooLong, EmptyTree, InvalidBitCount,
            InvalidBlock, InvalidBlockSize, InvalidMatchOffset, InvalidPathLengths,
            InvalidPositionSlot, InvalidPretreeElement, InvalidPretreeRle, OverreadBlock,
            OverreadChunk, UnexpectedEof, WindowTooSmall, ZeroProgress,
        };

        match self {
            OverreadBlock => write!(
                f,
                "read more items than available in the block in a single step"
            ),
            OverreadChunk => write!(f, "decoded element crosses the declared chunk boundary"),
            ZeroProgress => write!(f, "decoder made no progress"),
            UnexpectedEof => write!(f, "reached end of chunk without fully decoding it"),
            InvalidBlock(kind) => write!(f, "block type {kind} is invalid"),
            InvalidBlockSize(size) => write!(f, "block size {size} is invalid"),
            InvalidPretreeElement(elem) => write!(f, "found invalid pretree element {elem}"),
            InvalidPretreeRle => write!(f, "found invalid pretree rle element"),
            InvalidPathLengths => write!(f, "encountered invalid path lengths"),
            EmptyTree => write!(f, "encountered empty decode tree"),
            InvalidBitCount(bits) => write!(f, "invalid bit count {bits}"),
            InvalidMatchOffset(offset) => write!(f, "invalid match offset {offset}"),
            InvalidPositionSlot(slot) => write!(f, "invalid position slot {slot}"),
            WindowTooSmall => write!(f, "decode window was too small"),
            ChunkTooLong => write!(
                f,
                "tried reading a chunk longer than {MAX_CHUNK_SIZE} bytes"
            ),
            AllocationFailed => write!(f, "bounded LZX decoder allocation failed"),
            ArithmeticOverflow => write!(f, "LZX decoder accounting overflowed"),
        }
    }
}

impl core::error::Error for DecodeFailed {}

/// The error type used when decompression fails.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct DecompressError(DecodeFailed);

impl fmt::Display for DecompressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl core::error::Error for DecompressError {}

impl DecompressError {
    /// Returns the structured decoder failure reason.
    #[must_use]
    pub const fn reason(self) -> DecodeFailed {
        self.0
    }
}

impl From<DecodeFailed> for DecompressError {
    fn from(value: DecodeFailed) -> Self {
        Self(value)
    }
}

impl LzxDecoder {
    /// Creates a new regular-LZX decoder. The [`WindowSize`] must be obtained
    /// from elsewhere (e.g. it may be predetermined to a certain value), and if it's wrong,
    /// the decompressed values won't be those expected.
    ///
    /// [`WindowSize`]: enum.WindowSize.html
    pub fn new(window_size: WindowSize) -> Result<Self, DecompressError> {
        // > The main tree comprises 256 elements that correspond to all possible 8-bit
        // > characters, plus 8 * NUM_POSITION_SLOTS elements that correspond to matches.
        let main_tree = CanonicalTree::new(256 + 8 * window_size.position_slots())?;

        // > The length tree comprises 249 elements.
        let length_tree = CanonicalTree::new(249)?;

        Ok(Self {
            window: window_size.create_buffer()?,
            // > Because trees are output several times during compression of large amounts of
            // > data (multiple blocks), LZXD optimizes compression by encoding only the delta
            // > path lengths lengths between the current and previous trees.
            //
            // Because it uses deltas, we need to store the previous value across blocks.
            state: DecoderState {
                window_size,
                main_tree,
                length_tree,
            },
            // > The initial state of R0, R1, R2 is (1, 1, 1).
            r: [1, 1, 1],
            first_chunk_read: false,
            chunk_offset: 0,
            postprocess: None,
            // Start with some dummy value.
            current_block: Block {
                remaining: 0,
                size: 0,
                kind: BlockKind::Uncompressed { r: [1, 1, 1] },
            },
        })
    }

    /// Try reading the header for the first chunk.
    fn try_read_first_chunk(&mut self, bitstream: &mut Bitstream) -> Result<(), DecodeFailed> {
        // > The first bit in the first chunk in the LZXD bitstream (following the 2-byte,
        // > chunk-size prefix described in section 2.2.1) indicates the presence or absence of
        // > two 16-bit fields immediately following the single bit. If the bit is set, E8
        // > translation is enabled.
        if !self.first_chunk_read {
            self.first_chunk_read = true;

            let e8_translation = bitstream.read_bit()? != 0;
            self.postprocess = if e8_translation {
                let mut data_chunk = Vec::new();
                data_chunk
                    .try_reserve_exact(MAX_CHUNK_SIZE)
                    .map_err(|_| DecodeFailed::AllocationFailed)?;
                data_chunk.resize(MAX_CHUNK_SIZE, 0);
                Some(PostProcessState {
                    data_chunk: data_chunk.into_boxed_slice(),
                    e8_translation_size: i32::from_le_bytes(bitstream.read_bits(32)?.to_le_bytes()),
                })
            } else {
                None
            };
        }

        Ok(())
    }

    /// Copies a match only when every referenced byte has already been produced.
    fn copy_match(
        &mut self,
        offset: usize,
        length: usize,
        decoded_len: usize,
    ) -> Result<(), DecodeFailed> {
        let available = self
            .chunk_offset
            .checked_add(decoded_len)
            .ok_or(DecodeFailed::ArithmeticOverflow)?
            .min(self.state.window_size.bytes());
        if offset == 0 || offset > available {
            return Err(DecodeFailed::InvalidMatchOffset(offset));
        }
        self.window.copy_from_self(offset, length)
    }

    /// Consumes the byte that word-aligns an odd uncompressed block.
    fn consume_uncompressed_padding(
        block: &Block,
        bitstream: &mut Bitstream<'_>,
    ) -> Result<(), DecodeFailed> {
        if block.remaining == 0
            && matches!(block.kind, BlockKind::Uncompressed { .. })
            && (block.size & 1) != 0
        {
            bitstream.read_byte().ok_or(DecodeFailed::UnexpectedEof)?;
        }
        Ok(())
    }

    /// Attempts to perform post-decompression E8 fixups on an output data buffer.
    fn postprocess(
        translation_size: i32,
        chunk_offset: usize,
        idata: &mut [u8],
    ) -> Result<&[u8], DecodeFailed> {
        let mut processed = 0usize;

        // Find the next E8 match, or finish once there are no more E8 matches.
        while let Some(pos) = idata
            .get(processed..)
            .ok_or(DecodeFailed::ArithmeticOverflow)?
            .iter()
            .position(|&e| e == 0xE8)
            .and_then(|pos| processed.checked_add(pos))
        {
            // N.B: E8 fixups are only performed for up to 10 bytes before the end of a chunk.
            if idata.len() - pos <= 10 {
                break;
            }

            // This is the current file output pointer.
            let current_pointer = chunk_offset
                .checked_add(pos)
                .ok_or(DecodeFailed::ArithmeticOverflow)?;
            let current_pointer =
                i32::try_from(current_pointer).map_err(|_| DecodeFailed::ArithmeticOverflow)?;
            let operand = idata
                .get(pos + 1..pos + 5)
                .ok_or(DecodeFailed::ArithmeticOverflow)?;

            // Match. Fix up the following bytes.
            let abs_val = i32::from_le_bytes([operand[0], operand[1], operand[2], operand[3]]);
            if abs_val >= -current_pointer && abs_val < translation_size {
                let rel_val = if abs_val >= 0 {
                    abs_val.wrapping_sub(current_pointer)
                } else {
                    abs_val.wrapping_add(translation_size)
                };

                idata
                    .get_mut(pos + 1..pos + 5)
                    .ok_or(DecodeFailed::ArithmeticOverflow)?
                    .copy_from_slice(&rel_val.to_le_bytes());
            }

            processed = pos.checked_add(5).ok_or(DecodeFailed::ArithmeticOverflow)?;
        }

        Ok(idata)
    }

    /// Decompresses the next independently framed regular-LZX `chunk`.
    pub fn decompress_next(
        &mut self,
        chunk: &[u8],
        output_len: usize,
    ) -> Result<&[u8], DecompressError> {
        if output_len == 0 {
            return Err(DecodeFailed::ZeroProgress.into());
        }
        if output_len > MAX_CHUNK_SIZE {
            return Err(DecodeFailed::ChunkTooLong.into());
        }
        // > A chunk represents exactly 32 KB of uncompressed data until the last chunk in the
        // > stream, which can represent less than 32 KB.
        //
        // > The LZXD engine encodes a compressed, chunk-size prefix field preceding each
        // > compressed chunk in the compressed byte stream. The compressed, chunk-size prefix
        // > field is a byte aligned, little-endian, 16-bit field.
        //
        // However, this doesn't seem to be part of LZXD itself? At least when testing with
        // `.xnb` files, every chunk comes with a compressed chunk size unless it has the flag
        // set to 0xff where it also includes the uncompressed chunk size.
        //
        // TODO maybe the docs could clarify whether this length is compressed or not

        let mut bitstream = Bitstream::new(chunk);

        self.try_read_first_chunk(&mut bitstream)?;

        let mut decoded_len = 0;
        while decoded_len != output_len {
            if self.current_block.remaining == 0 {
                self.current_block = Block::read(&mut bitstream, &mut self.state)?;
                if self.current_block.remaining == 0 {
                    return Err(DecodeFailed::InvalidBlockSize(0).into());
                }
            }

            let decoded = self
                .current_block
                .decode_element(&mut bitstream, &mut self.r)?;

            let advance = match &decoded {
                Decoded::Single(_) => 1,
                Decoded::Match { length, .. } => *length,
                Decoded::Read(length) => {
                    // Read up to end of chunk, to allow for larger blocks.
                    usize::min(bitstream.remaining_bytes(), *length)
                },
            };

            if advance == 0 {
                return Err(DecodeFailed::UnexpectedEof.into());
            }
            let remaining_output = output_len
                .checked_sub(decoded_len)
                .ok_or(DecodeFailed::ArithmeticOverflow)?;
            if advance > remaining_output {
                return Err(DecodeFailed::OverreadChunk.into());
            }
            let advance_u32 =
                u32::try_from(advance).map_err(|_| DecodeFailed::ArithmeticOverflow)?;
            let remaining_block = self
                .current_block
                .remaining
                .checked_sub(advance_u32)
                .ok_or(DecodeFailed::OverreadBlock)?;

            match decoded {
                Decoded::Single(value) => self.window.push(value)?,
                Decoded::Match { offset, length } => {
                    self.copy_match(offset, length, decoded_len)?;
                },
                Decoded::Read(_) => {
                    // Will re-align if needed, just as decompressed reads mandate.
                    self.window.copy_from_bitstream(&mut bitstream, advance)?;
                },
            }
            decoded_len = decoded_len
                .checked_add(advance)
                .ok_or(DecodeFailed::ArithmeticOverflow)?;
            self.current_block.remaining = remaining_block;
            Self::consume_uncompressed_padding(&self.current_block, &mut bitstream)?;
        }

        let chunk_offset = self.chunk_offset;
        self.chunk_offset = self
            .chunk_offset
            .checked_add(decoded_len)
            .ok_or(DecodeFailed::ArithmeticOverflow)?;

        let view = self.window.past_view(decoded_len)?;
        if let Some(postprocess) = self.postprocess.as_mut() {
            // E8 fixups are disabled after 1GB of input data,
            // or if the chunk size is too small.
            if chunk_offset >= 0x4000_0000 || decoded_len <= 10 {
                Ok(view)
            } else {
                let postprocess_buf = postprocess
                    .data_chunk
                    .get_mut(..decoded_len)
                    .ok_or(DecodeFailed::OverreadChunk)?;
                postprocess_buf.copy_from_slice(view);

                // E8 fixups are enabled. Postprocess the output buffer.
                let view = Self::postprocess(
                    postprocess.e8_translation_size,
                    chunk_offset,
                    postprocess_buf,
                )?;
                Ok(view)
            }
        } else {
            Ok(view)
        }
    }

    /// Resets the decoder state.
    ///
    /// This is equivalent to calling [`Self::new`] with the same [`WindowSize`].
    /// [`WindowSize`]: enum.WindowSize.html
    pub fn reset(&mut self) -> Result<(), DecompressError> {
        let this = Self::new(self.state.window_size)?;
        let _ = mem::replace(self, this);
        Ok(())
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::{DecodeFailed, LzxDecoder, WindowSize};

    #[test]
    fn e8_absolute_zero_translates_relative_to_the_current_pointer() {
        let mut data = [0_u8; 13];
        data[2] = 0xE8;

        let output = LzxDecoder::postprocess(100, 5, &mut data).expect("bounded E8 fixup");

        assert_eq!(&output[3..7], &(-7_i32).to_le_bytes());
    }

    #[test]
    fn a_match_cannot_reference_zero_initialized_window_bytes() {
        let mut decoder = LzxDecoder::new(WindowSize::KB32).expect("bounded decoder allocation");

        let error = decoder
            .copy_match(1, 2, 0)
            .expect_err("no match history exists before the first output byte");

        assert_eq!(error, DecodeFailed::InvalidMatchOffset(1));
    }
}

// Retained verbatim upstream tests target the pre-fork infallible constructor.
// Repository coverage lives in `tests/lzx_safety.rs` and CAB interoperability.
#[cfg(any())]
mod tests {
    use super::*;

    #[test]
    fn check_uncompressed() {
        let data = [
            0x00, 0x30, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, b'a', b'b', b'c', 0x00,
        ];

        let mut lzxd = LzxDecoder::new(WindowSize::KB32); // size does not matter
        let res = lzxd.decompress_next(&data, 3);
        assert_eq!(res.unwrap(), [b'a', b'b', b'c']);
    }

    #[test]
    fn reset() {
        let data = [
            0x00, 0x30, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, b'a', b'b', b'c', 0x00,
        ];

        let mut lzxd = LzxDecoder::new(WindowSize::KB32); // size does not matter
        let res = lzxd.decompress_next(&data, 3);
        assert_eq!(res.unwrap(), [b'a', b'b', b'c']);

        lzxd.reset();
        let res = lzxd.decompress_next(&data, 3);
        assert_eq!(res.unwrap(), [b'a', b'b', b'c']);
    }

    #[test]
    fn check_e8() {
        let data = [
            0x5B, 0x80, 0x80, 0x8D, 0x00, 0x30, 0x80, 0x0A, 0x18, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x54, 0x68, 0x69, 0x73, 0x20, 0x66, 0x69, 0x6C,
            0x65, 0x20, 0x68, 0x61, 0x73, 0x20, 0x61, 0x6E, 0x20, 0x45, 0x38, 0x20, 0x62, 0x79,
            0x74, 0x65, 0x20, 0x74, 0x6F, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x45, 0x38, 0x20,
            0x74, 0x72, 0x61, 0x6E, 0x73, 0x6C, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2C, 0x20, 0x58,
            0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
            0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
            0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
            0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
            0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
            0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
            0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0xE8, 0x7B,
            0x00, 0x00, 0x00, 0xE8, 0x7B, 0x00, 0x00, 0x00, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
            0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
        ];

        let mut lzxd = LzxDecoder::new(WindowSize::KB32);
        let res = lzxd.decompress_next(&data, 168);
        assert_eq!(
            res.unwrap(),
            b"This file has an E8 byte to test E8 translation, Xdddddddddddddddd\
              dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
              dddddddddddddd\xE8\xE9\xFF\xFF\xFF\xE8\xE4\xFF\xFF\xFFdddddddddddd"
        );
    }

    #[test]
    fn uncompressed_single_byte_data() {
        let mut lzxd = LzxDecoder::new(WindowSize::KB32);
        let res = lzxd.decompress_next(&[0x00], 32);
        assert_eq!(res.unwrap_err().0, DecodeFailed::UnexpectedEof);
    }

    #[test]
    fn uncompressed_advance_zero() {
        // Regression test for "assertion `left != right` failed: left: 0, right: 0" panic
        // This occurs when the decoder cannot advance (advance == 0)
        // Data from fuzzer crash
        let data = vec![
            0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32,
            0x32, 0x32,
        ];

        let mut lzxd = LzxDecoder::new(WindowSize::KB32);
        let res = lzxd.decompress_next(&data, 32);
        assert_eq!(res.unwrap_err().0, DecodeFailed::UnexpectedEof);
    }

    #[test]
    fn peek_bits_oneword_bounds_check() {
        // Regression test for peek_bits_oneword index out of bounds panic
        // This exercises the buffer.len() < 2 check in peek_bits_oneword
        // Data from fuzzer crash
        let data = vec![
            0x12, 0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12,
            0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x00, 0x00, 0x00, 0x12, 0x8a,
        ];

        let mut lzxd = LzxDecoder::new(WindowSize::KB32);
        let res = lzxd.decompress_next(&data, 32);
        assert_eq!(res.unwrap_err().0, DecodeFailed::UnexpectedEof);
    }
}
