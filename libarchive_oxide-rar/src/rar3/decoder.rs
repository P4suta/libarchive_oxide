// SPDX-FileCopyrightText: 2026 Karpeles Lab Inc.
//
// SPDX-License-Identifier: MIT

//! RAR 3.x LZ77/Huffman and `PPMd-H` decoder.
//!
//! ## Calling convention
//!
//! RAR3 streams are not self-delimiting: the archive container records the uncompressed size separately, and the compressed payload itself has no end-of-stream marker that the decoder can rely on without overrunning the requested size.
//! Callers therefore construct the decoder with [`Decoder::with_unpack_size`] and feed the raw compressed bytes that immediately follow the RAR file header — see the module-level `//!` block for details.
//! [`Decoder::new`] is provided as a default that decodes up to `u64::MAX` bytes (suitable for tests where the caller independently tracks output length).
//!
//! ## What's supported
//!
//! - LZ77 + Huffman blocks.
//! - `PPMd-II` / variant-H blocks with bounded model allocation, RAR's carryless range coder, escape matches, block transitions, mandatory end markers, and solid model/window continuation.
//! - All five Huffman codes (precode + main + offset + low-offset + length).
//! - The 4-deep rolling-offset buffer, short offsets (codes 263..=270), and the full match-length / offset machinery.
//! - The keep-table flag — successive blocks may reuse the previous code lengths.
//! - The five standard RAR3 VM filters through a bounded, statically dispatched codec crate.
//!
//! ## What's refused
//!
//! - **Non-standard VM bytecode**. Unknown programs fail with a typed unsupported error and are never interpreted.
//! - **Dictionary sizes** other than the default 4 MiB.
//!   Streams compressed with smaller dictionaries decode correctly with the larger window —
//!   the larger window doesn't change semantics.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use libarchive_oxide_ppmd::{Ppmd7, RarRangeDecoder};
use libarchive_oxide_rarvm::{FilterDescriptor, FilterPrograms};

use crate::codec::{Error, Progress, Status};

use super::bits::BitReader;
use super::huffman::Huffman;
use super::tables::{
    DICT_DEFAULT_SIZE, HUFF_TABLE_SIZE, LENGTH_BASE, LENGTH_EXTRA_BITS, LENGTH_SIZE,
    LOW_OFFSET_SIZE, MAIN_SIZE, OFFSET_BASE, OFFSET_EXTRA_BITS, OFFSET_SIZE, PRECODE_SIZE,
    SHORT_BASE, SHORT_EXTRA_BITS,
};

const MAX_PENDING_FILTERS: usize = 1_024;

/// Streaming RAR 3.x decoder.
/// See module docs for the calling convention.
pub(crate) struct Decoder {
    /// Pending compressed bytes the caller has supplied but we haven't yet consumed.
    state: State,
    /// Sink we hand decoded output to before the caller drains it.
    out_buf: Vec<u8>,
    out_drained: usize,
    /// Caller-declared maximum unpacked size.
    /// The decoder stops emitting once this is reached.
    /// The default is `u64::MAX`.
    unpack_size: u64,
    /// Dictionary, Huffman, and distance state retained after a completed member so a following solid member can continue it.
    solid_state: Option<SolidState>,
    /// Set on any irrecoverable error.
    poisoned: bool,
    /// Maximum `PPMd` model allocation left after the caller's other RAR3 workspace reservations.
    ppmd_model_limit: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawProgress {
    consumed: usize,
    written: usize,
    done: bool,
}

enum State {
    /// Buffering input until [`finish`] is called.
    Buffering { input: Vec<u8> },
    /// Decoding is finished; bytes are in `out_buf`.
    /// After all `out_buf` bytes are drained to the caller, transitions to `Done`.
    Draining,
    /// Stream is fully decoded and output drained.
    Done,
}

impl Decoder {
    /// Construct a decoder with no explicit unpacked-size cap.
    /// The decoder will produce as much output as the compressed stream encodes.
    ///
    /// Most callers should prefer [`Decoder::with_unpack_size`] so the decoder knows when to stop — RAR3 streams do not carry their uncompressed length in-band.
    pub(crate) fn new() -> Self {
        Self {
            state: State::Buffering { input: Vec::new() },
            out_buf: Vec::new(),
            out_drained: 0,
            unpack_size: u64::MAX,
            solid_state: None,
            poisoned: false,
            ppmd_model_limit: None,
        }
    }

    /// Construct a decoder that will produce at most `n` uncompressed bytes.
    pub(crate) fn with_unpack_size(n: u64) -> Self {
        Self {
            state: State::Buffering { input: Vec::new() },
            out_buf: Vec::new(),
            out_drained: 0,
            unpack_size: n,
            solid_state: None,
            poisoned: false,
            ppmd_model_limit: None,
        }
    }

    /// Constructs a decoder with a caller-preflighted `PPMd` model allowance.
    pub(crate) fn with_unpack_size_and_ppmd_limit(
        unpack_size: u64,
        ppmd_model_limit: Option<usize>,
    ) -> Self {
        let mut decoder = Self::with_unpack_size(unpack_size);
        decoder.ppmd_model_limit = ppmd_model_limit;
        decoder
    }

    /// Reuses the completed member's compression state for the next solid member while resetting all member-local input, output, and filter data.
    pub(crate) fn continue_solid(
        &mut self,
        unpack_size: u64,
        ppmd_model_limit: Option<usize>,
    ) -> Result<(), Error> {
        if self.poisoned
            || !matches!(self.state, State::Done)
            || !self.out_buf.is_empty()
            || self.out_drained != 0
            || self.solid_state.is_none()
        {
            return Err(Error::Corrupt);
        }
        self.state = State::Buffering { input: Vec::new() };
        self.unpack_size = unpack_size;
        if ppmd_model_limit.is_some_and(|limit| {
            self.solid_state
                .as_ref()
                .and_then(|state| state.ppmd.as_ref())
                .is_some_and(|model| model.allocation_bytes() > limit)
        }) {
            return Err(Error::OutputLimitExceeded);
        }
        self.ppmd_model_limit = ppmd_model_limit;
        Ok(())
    }

    fn poison<T>(&mut self, e: Error) -> Result<T, Error> {
        self.poisoned = true;
        Err(e)
    }

    /// Drain `out_buf` into the caller's `output`.
    /// Returns bytes written.
    fn drain_into(&mut self, output: &mut [u8]) -> usize {
        let mut written = 0usize;
        while self.out_drained < self.out_buf.len() && written < output.len() {
            let n = (self.out_buf.len() - self.out_drained).min(output.len() - written);
            output[written..written + n]
                .copy_from_slice(&self.out_buf[self.out_drained..self.out_drained + n]);
            written += n;
            self.out_drained += n;
        }
        if self.out_drained == self.out_buf.len() {
            // Once everything is drained, free the buffer.
            self.out_buf.clear();
            self.out_drained = 0;
            self.state = State::Done;
        }
        written
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let mut consumed = 0usize;
        let mut written = 0usize;
        // RAR3 needs the entire compressed stream before it can decode —
        // we don't snapshot the inner state to handle mid-symbol stalls,
        // so the streaming model is buffer-then-drain.
        // The caller may however interleave `decode` calls (to push input) with periodic drains, which we honor here.
        match &mut self.state {
            State::Buffering { input: buf } => {
                buf.extend_from_slice(input);
                consumed = input.len();
            },
            State::Draining => {
                written = self.drain_into(output);
            },
            State::Done => {},
        }
        Ok(RawProgress {
            consumed,
            written,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        // If we still need to decode, do it now.
        if let State::Buffering { input } = &mut self.state {
            let input = core::mem::take(input);
            // Move into a separate scope so the `match` borrow ends before we mutate `self.state`.
            match run_decode_with_state(
                &input,
                self.unpack_size,
                self.solid_state.take(),
                self.ppmd_model_limit,
            ) {
                Ok((out, solid_state)) => {
                    self.out_buf = out;
                    self.out_drained = 0;
                    self.solid_state = Some(solid_state);
                    self.state = State::Draining;
                },
                Err(e) => return self.poison(e),
            }
        }
        let written = self.drain_into(output);
        let done = matches!(self.state, State::Done);
        Ok(RawProgress {
            consumed: 0,
            written,
            done,
        })
    }
}

impl crate::codec::Decoder for Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<(Progress, Status), Error> {
        let progress = self.raw_decode(input, output)?;
        let status = if progress.done {
            Status::StreamEnd
        } else if progress.written == output.len() && !output.is_empty() {
            Status::OutputFull
        } else if progress.consumed >= input.len() {
            Status::InputEmpty
        } else {
            Status::OutputFull
        };
        Ok((
            Progress {
                consumed: progress.consumed,
                written: progress.written,
            },
            status,
        ))
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<(Progress, Status), Error> {
        let progress = self.raw_finish(output)?;
        let status = if progress.done {
            Status::StreamEnd
        } else {
            Status::OutputFull
        };
        Ok((
            Progress {
                consumed: 0,
                written: progress.written,
            },
            status,
        ))
    }
}

// ─── Internal decode pipeline ─────────────────────────────────────────────

fn run_decode_with_state(
    input: &[u8],
    unpack_size: u64,
    solid_state: Option<SolidState>,
    ppmd_model_limit: Option<usize>,
) -> Result<(Vec<u8>, SolidState), Error> {
    let continuing = solid_state.is_some();
    let solid_state = solid_state.unwrap_or_else(SolidState::new);
    if unpack_size == 0 {
        return Ok((Vec::new(), solid_state));
    }
    let mut br = BitReader::new();
    br.feed_slice(input);

    let previous_was_ppmd = solid_state.is_ppmd_block;
    let mut ctx = Box::new(solid_state.into_run_context(br, unpack_size, ppmd_model_limit));

    // A fresh stream starts with tables.
    // A solid successor starts directly with symbols from the preceding member's live tables; its physical byte extent supplies a fresh bit reader but does not reset LZ state.
    if !continuing || previous_was_ppmd {
        parse_block_header(&mut ctx)?;
    }
    expand(&mut ctx)?;
    apply_pending_filters(&mut ctx)?;

    let out = core::mem::take(&mut ctx.out);
    Ok((out, SolidState::from_run_context(*ctx)))
}

struct SolidState {
    lengths: Vec<u8>,
    main: Option<Box<Huffman>>,
    offset: Option<Box<Huffman>>,
    low_offset: Option<Box<Huffman>>,
    length: Option<Box<Huffman>>,
    old_offsets: [u32; 4],
    last_offset: u32,
    last_length: u32,
    last_low_offset: u32,
    num_low_offset_repeats: u32,
    window: Vec<u8>,
    wmask: usize,
    window_pos: usize,
    ppmd: Option<Ppmd7>,
    ppmd_escape: u8,
    is_ppmd_block: bool,
    filter_programs: FilterPrograms,
}

impl SolidState {
    fn new() -> Self {
        Self {
            // The length table survives across blocks and solid members: a successive block can signal "keep table" and apply deltas to the most recently decoded lengths.
            lengths: vec![0u8; HUFF_TABLE_SIZE],
            main: None,
            offset: None,
            low_offset: None,
            length: None,
            old_offsets: [1u32, 1, 1, 1],
            last_offset: 0,
            last_length: 0,
            last_low_offset: 0,
            num_low_offset_repeats: 0,
            window: vec![0u8; DICT_DEFAULT_SIZE],
            wmask: {
                debug_assert!(DICT_DEFAULT_SIZE.is_power_of_two());
                DICT_DEFAULT_SIZE - 1
            },
            window_pos: 0,
            ppmd: None,
            ppmd_escape: 2,
            is_ppmd_block: false,
            filter_programs: FilterPrograms::new(),
        }
    }

    fn into_run_context(
        self,
        bits: BitReader,
        unpack_size: u64,
        ppmd_model_limit: Option<usize>,
    ) -> RunCtx {
        RunCtx {
            bits,
            lengths: self.lengths,
            main: self.main,
            offset: self.offset,
            low_offset: self.low_offset,
            length: self.length,
            old_offsets: self.old_offsets,
            last_offset: self.last_offset,
            last_length: self.last_length,
            last_low_offset: self.last_low_offset,
            num_low_offset_repeats: self.num_low_offset_repeats,
            out: Vec::new(),
            window: self.window,
            wmask: self.wmask,
            window_pos: self.window_pos,
            unpack_size,
            ppmd: self.ppmd,
            ppmd_escape: self.ppmd_escape,
            is_ppmd_block: self.is_ppmd_block,
            filter_programs: self.filter_programs,
            pending_filters: Vec::new(),
            ppmd_model_limit,
        }
    }

    fn from_run_context(context: RunCtx) -> Self {
        Self {
            lengths: context.lengths,
            main: context.main,
            offset: context.offset,
            low_offset: context.low_offset,
            length: context.length,
            old_offsets: context.old_offsets,
            last_offset: context.last_offset,
            last_length: context.last_length,
            last_low_offset: context.last_low_offset,
            num_low_offset_repeats: context.num_low_offset_repeats,
            window: context.window,
            wmask: context.wmask,
            window_pos: context.window_pos,
            ppmd: context.ppmd,
            ppmd_escape: context.ppmd_escape,
            is_ppmd_block: context.is_ppmd_block,
            filter_programs: context.filter_programs,
        }
    }
}

struct RunCtx {
    bits: BitReader,
    lengths: Vec<u8>,
    main: Option<Box<Huffman>>,
    offset: Option<Box<Huffman>>,
    low_offset: Option<Box<Huffman>>,
    length: Option<Box<Huffman>>,
    /// 4-deep rolling offset history; index 0 is the most recent.
    old_offsets: [u32; 4],
    /// Most-recently-used (offset, length) pair, used by main symbol 258.
    last_offset: u32,
    last_length: u32,
    /// Last low-offset value, plus a repeat counter for the `LowOffset` "16" symbol.
    last_low_offset: u32,
    num_low_offset_repeats: u32,
    /// The decoded output stream.
    out: Vec<u8>,
    /// Sliding window — kept in sync with `out` for back-reference lookups.
    /// We use a plain Vec sized to `DICT_DEFAULT_SIZE` so wrap-around at the end is cheap; reads use bitwise masking.
    window: Vec<u8>,
    /// Cached `window.len() - 1`.
    /// The window length is always a power of two so wrap-around is a single AND.
    wmask: usize,
    window_pos: usize,
    unpack_size: u64,
    ppmd: Option<Ppmd7>,
    ppmd_escape: u8,
    is_ppmd_block: bool,
    filter_programs: FilterPrograms,
    pending_filters: Vec<FilterDescriptor>,
    ppmd_model_limit: Option<usize>,
}

impl RunCtx {
    fn emit_literal(&mut self, b: u8) {
        self.out.push(b);
        self.window[self.window_pos] = b;
        self.window_pos = (self.window_pos + 1) & self.wmask;
    }

    fn emit_match(&mut self, offset: u32, length: u32) -> Result<(), Error> {
        if offset == 0 {
            return Err(Error::InvalidDistance);
        }
        // Copy `length` bytes from `offset` behind the window head.
        let wlen = self.window.len();
        let wmask = self.wmask;
        let off = usize::try_from(offset).map_err(|_| Error::InvalidDistance)?;
        if off > wlen {
            return Err(Error::InvalidDistance);
        }
        // Clamp the run to the declared unpack size (the old loop broke per byte once `out` reached it — produce exactly the same byte count).
        let remaining_out = self.unpack_size.saturating_sub(self.out.len() as u64);
        let length =
            usize::try_from(u64::from(length).min(remaining_out)).map_err(|_| Error::Corrupt)?;
        let mut src = (self.window_pos + wlen - off) & wmask;
        self.out.reserve(length);

        if off == 1 {
            // Distance-1 run: one repeated byte.
            // Fill directly.
            let b = self.window[src];
            for _ in 0..length {
                self.out.push(b);
                self.window[self.window_pos] = b;
                self.window_pos = (self.window_pos + 1) & wmask;
            }
        } else if off >= length {
            // Non-overlapping: src and dst regions are disjoint.
            // Copy in contiguous window segments (no per-byte recompute of `src`).
            let mut done = 0usize;
            while done < length {
                let run = (length - done).min(wlen - src).min(wlen - self.window_pos);
                for k in 0..run {
                    let b = self.window[src + k];
                    self.out.push(b);
                    self.window[self.window_pos + k] = b;
                }
                src = (src + run) & wmask;
                self.window_pos = (self.window_pos + run) & wmask;
                done += run;
            }
        } else {
            // Overlapping match: each written byte feeds a later read.
            for _ in 0..length {
                let b = self.window[src];
                self.out.push(b);
                self.window[self.window_pos] = b;
                src = (src + 1) & wmask;
                self.window_pos = (self.window_pos + 1) & wmask;
            }
        }
        Ok(())
    }

    fn done(&self) -> bool {
        (self.out.len() as u64) >= self.unpack_size
    }
}

// ─── Block header parsing ────────────────────────────────────────────────

// The block grammar is kept in one auditable state transition because both LZ tables and PPMd range state can replace the current decoder in-band.
#[allow(clippy::too_many_lines)]
fn parse_block_header(ctx: &mut RunCtx) -> Result<(), Error> {
    // RAR3 byte-aligns the bitstream before reading every block header,
    // including the very first one (where alignment is a no-op since we start on a byte boundary).
    ctx.bits.byte_align();
    // 1 bit: PPMd-block flag.
    let is_ppmd = ctx.bits.read_bits(1)?;
    if is_ppmd != 0 {
        let flags = u8::try_from(ctx.bits.read_bits(7)?).map_err(|_| Error::BadHeader)?;
        let reset_model = flags & 0x20 != 0;
        let model_bytes = if reset_model {
            let megabytes =
                usize::try_from(ctx.bits.read_bits(8)? + 1).map_err(|_| Error::BadHeader)?;
            Some(
                megabytes
                    .checked_shl(20)
                    .ok_or(Error::OutputLimitExceeded)?,
            )
        } else {
            None
        };
        let escape = if flags & 0x40 != 0 {
            u8::try_from(ctx.bits.read_bits(8)?).map_err(|_| Error::BadHeader)?
        } else {
            2
        };
        ctx.ppmd_escape = escape;
        if let Some(model_bytes) = model_bytes {
            let allocation_bytes =
                Ppmd7::required_allocation_bytes(model_bytes).map_err(|error| match error {
                    libarchive_oxide_ppmd::Error::InvalidParameter => Error::BadHeader,
                    _ => Error::Corrupt,
                })?;
            if ctx
                .ppmd_model_limit
                .is_some_and(|maximum| allocation_bytes > maximum)
            {
                return Err(Error::OutputLimitExceeded);
            }
            let encoded_order = u32::from(flags & 0x1f) + 1;
            let max_order = if encoded_order > 16 {
                16 + (encoded_order - 16) * 3
            } else {
                encoded_order
            };
            if max_order < 2 {
                return Err(Error::BadHeader);
            }
            ctx.ppmd = Some(Ppmd7::new(max_order, model_bytes, escape).map_err(
                |error| match error {
                    libarchive_oxide_ppmd::Error::Allocation => Error::OutputLimitExceeded,
                    libarchive_oxide_ppmd::Error::InvalidParameter => Error::BadHeader,
                    _ => Error::Corrupt,
                },
            )?);
        } else {
            let model = ctx.ppmd.as_mut().ok_or(Error::BadHeader)?;
            model.set_initial_escape(escape);
        }
        ctx.is_ppmd_block = true;
        return Ok(());
    }
    ctx.is_ppmd_block = false;
    // 1 bit: keep-table flag.
    // 0 ⇒ reset the persistent length table.
    let keep_table = ctx.bits.read_bits(1)? != 0;
    if !keep_table {
        ctx.lengths.fill(0);
    }

    let precode = read_precode(ctx)?;
    let pre_tree = Huffman::from_lengths(&precode)?;

    // Decode the HUFF_TABLE_SIZE-length code-length array using the precode.
    let mut idx = 0usize;
    while idx < HUFF_TABLE_SIZE {
        let sym = pre_tree.decode(&mut ctx.bits)?;
        if sym < 16 {
            // Incremental: add to existing value mod 16.
            ctx.lengths[idx] = u8::try_from((u16::from(ctx.lengths[idx]) + sym) & 0xF)
                .map_err(|_| Error::Corrupt)?;
            idx += 1;
        } else if sym == 16 {
            if idx == 0 {
                return Err(Error::Corrupt);
            }
            let n = (ctx.bits.read_bits(3)? as usize) + 3;
            let prev = ctx.lengths[idx - 1];
            for _ in 0..n {
                if idx >= HUFF_TABLE_SIZE {
                    break;
                }
                ctx.lengths[idx] = prev;
                idx += 1;
            }
        } else if sym == 17 {
            if idx == 0 {
                return Err(Error::Corrupt);
            }
            let n = (ctx.bits.read_bits(7)? as usize) + 11;
            let prev = ctx.lengths[idx - 1];
            for _ in 0..n {
                if idx >= HUFF_TABLE_SIZE {
                    break;
                }
                ctx.lengths[idx] = prev;
                idx += 1;
            }
        } else if sym == 18 {
            let n = (ctx.bits.read_bits(3)? as usize) + 3;
            for _ in 0..n {
                if idx >= HUFF_TABLE_SIZE {
                    break;
                }
                ctx.lengths[idx] = 0;
                idx += 1;
            }
        } else if sym == 19 {
            let n = (ctx.bits.read_bits(7)? as usize) + 11;
            for _ in 0..n {
                if idx >= HUFF_TABLE_SIZE {
                    break;
                }
                ctx.lengths[idx] = 0;
                idx += 1;
            }
        } else {
            return Err(Error::Corrupt);
        }
    }

    // Build the four data-Huffman codes.
    ctx.main = Some(Box::new(Huffman::from_lengths(&ctx.lengths[..MAIN_SIZE])?));
    ctx.offset = Some(Box::new(Huffman::from_lengths(
        &ctx.lengths[MAIN_SIZE..MAIN_SIZE + OFFSET_SIZE],
    )?));
    ctx.low_offset = Some(Box::new(Huffman::from_lengths(
        &ctx.lengths[MAIN_SIZE + OFFSET_SIZE..MAIN_SIZE + OFFSET_SIZE + LOW_OFFSET_SIZE],
    )?));
    ctx.length = Some(Box::new(Huffman::from_lengths(
        &ctx.lengths[MAIN_SIZE + OFFSET_SIZE + LOW_OFFSET_SIZE
            ..MAIN_SIZE + OFFSET_SIZE + LOW_OFFSET_SIZE + LENGTH_SIZE],
    )?));
    Ok(())
}

fn read_precode(ctx: &mut RunCtx) -> Result<[u8; PRECODE_SIZE], Error> {
    // Read 20 lengths, four bits each.
    // 0xF followed by a nonzero nibble is a run of zeros; a zero second nibble means a literal length of 15.
    let mut precode = [0u8; PRECODE_SIZE];
    let mut index = 0usize;
    while index < PRECODE_SIZE {
        let value = u8::try_from(ctx.bits.read_bits(4)?).map_err(|_| Error::Corrupt)?;
        if value != 0x0F {
            precode[index] = value;
            index += 1;
            continue;
        }
        let run = u8::try_from(ctx.bits.read_bits(4)?).map_err(|_| Error::Corrupt)?;
        if run == 0 {
            precode[index] = 0x0F;
            index += 1;
            continue;
        }
        let end = (index + usize::from(run) + 2).min(PRECODE_SIZE);
        precode[index..end].fill(0);
        index = end;
    }
    Ok(precode)
}

// ─── Expansion ───────────────────────────────────────────────────────────

fn expand(ctx: &mut RunCtx) -> Result<(), Error> {
    loop {
        if ctx.is_ppmd_block {
            if expand_ppmd(ctx)? == Expansion::End {
                return Ok(());
            }
            continue;
        }
        if ctx.done() {
            return Ok(());
        }
        let main_tree = ctx.main.as_ref().ok_or(Error::InvalidHuffmanTree)?;
        let symbol = match main_tree.decode(&mut ctx.bits) {
            Ok(symbol) => symbol,
            Err(Error::UnexpectedEnd) => return Ok(()),
            Err(error) => return Err(error),
        };
        if symbol < 256 {
            ctx.emit_literal(u8::try_from(symbol).map_err(|_| Error::Corrupt)?);
        } else if expand_symbol(ctx, symbol)? == Expansion::End {
            return Ok(());
        }
    }
}

fn expand_ppmd(ctx: &mut RunCtx) -> Result<Expansion, Error> {
    let remaining = ctx.bits.take_remaining_aligned()?;
    let mut range = RarRangeDecoder::new(&remaining).map_err(map_ppmd_error)?;
    loop {
        let symbol = decode_ppmd_symbol(ctx, &mut range)?;
        if !ctx.done() && symbol != ctx.ppmd_escape {
            ctx.emit_literal(symbol);
            continue;
        }
        if symbol != ctx.ppmd_escape {
            return Err(Error::Corrupt);
        }
        let code = decode_ppmd_symbol(ctx, &mut range)?;
        match code {
            0 => {
                let consumed = range.consumed();
                ctx.bits.replace_aligned(&remaining[consumed..]);
                parse_block_header(ctx)?;
                return Ok(Expansion::Continue);
            },
            2 => {
                if !ctx.done() {
                    return Err(Error::UnexpectedEnd);
                }
                return Ok(Expansion::End);
            },
            3 => read_ppmd_filter(ctx, &mut range)?,
            4 => {
                if ctx.done() {
                    return Err(Error::Corrupt);
                }
                let mut offset = 0u32;
                for _ in 0..3 {
                    offset = (offset << 8) | u32::from(decode_ppmd_symbol(ctx, &mut range)?);
                }
                let length = u32::from(decode_ppmd_symbol(ctx, &mut range)?) + 32;
                ctx.emit_match(offset + 2, length)?;
            },
            5 => {
                if ctx.done() {
                    return Err(Error::Corrupt);
                }
                let length = u32::from(decode_ppmd_symbol(ctx, &mut range)?) + 4;
                ctx.emit_match(1, length)?;
            },
            _ => {
                if ctx.done() {
                    return Err(Error::Corrupt);
                }
                ctx.emit_literal(ctx.ppmd_escape);
            },
        }
    }
}

fn decode_ppmd_symbol(ctx: &mut RunCtx, range: &mut RarRangeDecoder<'_>) -> Result<u8, Error> {
    ctx.ppmd
        .as_mut()
        .ok_or(Error::BadHeader)?
        .decode_symbol(range)
        .map_err(map_ppmd_error)
}

fn map_ppmd_error(error: libarchive_oxide_ppmd::Error) -> Error {
    match error {
        libarchive_oxide_ppmd::Error::UnexpectedEnd => Error::UnexpectedEnd,
        libarchive_oxide_ppmd::Error::Allocation => Error::OutputLimitExceeded,
        libarchive_oxide_ppmd::Error::InvalidParameter => Error::BadHeader,
        _ => Error::Corrupt,
    }
}

fn read_lz_filter(ctx: &mut RunCtx) -> Result<(), Error> {
    let flags = u8::try_from(ctx.bits.read_bits(8)?).map_err(|_| Error::Corrupt)?;
    let length = lz_filter_descriptor_length(ctx, flags)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::OutputLimitExceeded)?;
    for _ in 0..length {
        bytes.push(u8::try_from(ctx.bits.read_bits(8)?).map_err(|_| Error::Corrupt)?);
    }
    install_filter(ctx, flags, &bytes)
}

fn lz_filter_descriptor_length(ctx: &mut RunCtx, flags: u8) -> Result<usize, Error> {
    let encoded = usize::from(flags & 0x07) + 1;
    let length = if encoded == 7 {
        usize::try_from(ctx.bits.read_bits(8)?).map_err(|_| Error::Corrupt)? + 7
    } else if encoded == 8 {
        let high = usize::try_from(ctx.bits.read_bits(8)?).map_err(|_| Error::Corrupt)?;
        let low = usize::try_from(ctx.bits.read_bits(8)?).map_err(|_| Error::Corrupt)?;
        (high << 8) | low
    } else {
        encoded
    };
    if length == 0 {
        return Err(Error::Corrupt);
    }
    Ok(length)
}

fn read_ppmd_filter(ctx: &mut RunCtx, range: &mut RarRangeDecoder<'_>) -> Result<(), Error> {
    let flags = decode_ppmd_symbol(ctx, range)?;
    let encoded = usize::from(flags & 0x07) + 1;
    let length = if encoded == 7 {
        usize::from(decode_ppmd_symbol(ctx, range)?) + 7
    } else if encoded == 8 {
        (usize::from(decode_ppmd_symbol(ctx, range)?) << 8)
            | usize::from(decode_ppmd_symbol(ctx, range)?)
    } else {
        encoded
    };
    if length == 0 {
        return Err(Error::Corrupt);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Error::OutputLimitExceeded)?;
    for _ in 0..length {
        bytes.push(decode_ppmd_symbol(ctx, range)?);
    }
    install_filter(ctx, flags, &bytes)
}

fn install_filter(ctx: &mut RunCtx, flags: u8, bytes: &[u8]) -> Result<(), Error> {
    let position = u64::try_from(ctx.out.len()).map_err(|_| Error::OutputLimitExceeded)?;
    let dictionary = u64::try_from(ctx.window.len()).map_err(|_| Error::OutputLimitExceeded)?;
    let descriptor = ctx
        .filter_programs
        .parse(flags, bytes, position, dictionary)
        .map_err(map_rarvm_error)?;
    if descriptor.resets_pending_filters() {
        ctx.pending_filters.clear();
    }
    if ctx.pending_filters.len() >= MAX_PENDING_FILTERS {
        return Err(Error::OutputLimitExceeded);
    }
    ctx.pending_filters
        .try_reserve(1)
        .map_err(|_| Error::OutputLimitExceeded)?;
    ctx.pending_filters.push(descriptor);
    Ok(())
}

fn apply_pending_filters(ctx: &mut RunCtx) -> Result<(), Error> {
    let pending = core::mem::take(&mut ctx.pending_filters);
    let mut scratch = Vec::new();
    let mut previous: Option<(usize, usize, usize)> = None;
    for descriptor in pending {
        let start = usize::try_from(descriptor.block_start()).map_err(|_| Error::Corrupt)?;
        let length = usize::try_from(descriptor.block_length()).map_err(|_| Error::Corrupt)?;
        let end = start.checked_add(length).ok_or(Error::Corrupt)?;
        if end > ctx.out.len() {
            return Err(Error::UnexpectedEnd);
        }
        if let Some((previous_start, previous_end, previous_length)) = previous {
            let chained = start == previous_start && length == previous_length;
            if start < previous_end && !chained {
                return Err(Error::Corrupt);
            }
        }

        let scratch_bytes = descriptor.scratch_bytes().map_err(map_rarvm_error)?;
        if scratch.len() < scratch_bytes {
            scratch
                .try_reserve_exact(scratch_bytes - scratch.len())
                .map_err(|_| Error::OutputLimitExceeded)?;
            scratch.resize(scratch_bytes, 0);
        }
        libarchive_oxide_rarvm::apply(
            descriptor.program(),
            descriptor.registers(),
            &mut ctx.out[start..end],
            u64::try_from(start).map_err(|_| Error::Corrupt)?,
            &mut scratch[..scratch_bytes],
        )
        .map_err(map_rarvm_error)?;
        previous = Some((start, end, length));
    }
    Ok(())
}

fn map_rarvm_error(error: libarchive_oxide_rarvm::Error) -> Error {
    match error {
        libarchive_oxide_rarvm::Error::TruncatedDescriptor => Error::UnexpectedEnd,
        libarchive_oxide_rarvm::Error::UnsupportedProgram => Error::UnsupportedFilter,
        libarchive_oxide_rarvm::Error::ResourceLimit
        | libarchive_oxide_rarvm::Error::ScratchTooSmall => Error::OutputLimitExceeded,
        _ => Error::Corrupt,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Expansion {
    Continue,
    End,
}

fn expand_symbol(ctx: &mut RunCtx, symbol: u16) -> Result<Expansion, Error> {
    match symbol {
        256 => {
            if ctx.bits.read_bits(1)? == 0 {
                return Ok(Expansion::End);
            }
            parse_block_header(ctx)?;
        },
        257 => read_lz_filter(ctx)?,
        258 => {
            if ctx.last_length == 0 {
                return Err(Error::Corrupt);
            }
            ctx.emit_match(ctx.last_offset, ctx.last_length)?;
        },
        259..=262 => expand_repeated_offset(ctx, symbol)?,
        263..=270 => expand_short_offset(ctx, symbol)?,
        271..=298 => expand_new_match(ctx, symbol)?,
        _ => return Err(Error::Corrupt),
    }
    Ok(Expansion::Continue)
}

fn expand_repeated_offset(ctx: &mut RunCtx, symbol: u16) -> Result<(), Error> {
    let index = usize::from(symbol - 259);
    let offset = ctx.old_offsets[index];
    let length_tree = ctx.length.as_ref().ok_or(Error::InvalidHuffmanTree)?;
    let length_symbol = usize::from(length_tree.decode(&mut ctx.bits)?);
    let base = LENGTH_BASE
        .get(length_symbol)
        .copied()
        .ok_or(Error::Corrupt)?;
    let extra_bits = u32::from(LENGTH_EXTRA_BITS[length_symbol]);
    let extra = if extra_bits == 0 {
        0
    } else {
        ctx.bits.read_bits(extra_bits)?
    };
    let length = u32::from(base) + 2 + extra;
    promote_offset(ctx, index, offset);
    ctx.last_offset = offset;
    ctx.last_length = length;
    ctx.emit_match(offset, length)
}

fn expand_short_offset(ctx: &mut RunCtx, symbol: u16) -> Result<(), Error> {
    let index = usize::from(symbol - 263);
    let extra_bits = u32::from(SHORT_EXTRA_BITS[index]);
    let extra = if extra_bits == 0 {
        0
    } else {
        ctx.bits.read_bits(extra_bits)?
    };
    let offset = SHORT_BASE[index] + extra + 1;
    ctx.old_offsets.rotate_right(1);
    ctx.old_offsets[0] = offset;
    ctx.last_offset = offset;
    ctx.last_length = 2;
    ctx.emit_match(offset, 2)
}

fn expand_new_match(ctx: &mut RunCtx, symbol: u16) -> Result<(), Error> {
    let index = usize::from(symbol - 271);
    let length_base = LENGTH_BASE.get(index).copied().ok_or(Error::Corrupt)?;
    let length_bits = u32::from(LENGTH_EXTRA_BITS[index]);
    let length_extra = if length_bits == 0 {
        0
    } else {
        ctx.bits.read_bits(length_bits)?
    };
    let mut length = u32::from(length_base) + 3 + length_extra;

    let offset_tree = ctx.offset.as_ref().ok_or(Error::InvalidHuffmanTree)?;
    let offset_symbol = usize::from(offset_tree.decode(&mut ctx.bits)?);
    let mut offset = OFFSET_BASE
        .get(offset_symbol)
        .copied()
        .ok_or(Error::Corrupt)?
        + 1;
    let offset_bits = u32::from(OFFSET_EXTRA_BITS[offset_symbol]);
    if offset_symbol > 9 {
        offset = decode_large_offset(ctx, offset, offset_bits)?;
    } else if offset_bits > 0 {
        offset = offset.wrapping_add(ctx.bits.read_bits(offset_bits)?);
    }
    if offset >= 0x4_0000 {
        length += 1;
    }
    if offset >= 0x2000 {
        length += 1;
    }
    ctx.old_offsets.rotate_right(1);
    ctx.old_offsets[0] = offset;
    ctx.last_offset = offset;
    ctx.last_length = length;
    ctx.emit_match(offset, length)
}

fn decode_large_offset(ctx: &mut RunCtx, mut offset: u32, bits: u32) -> Result<u32, Error> {
    if bits > 4 {
        offset = offset.wrapping_add(ctx.bits.read_bits(bits - 4)? << 4);
    }
    if ctx.num_low_offset_repeats > 0 {
        ctx.num_low_offset_repeats -= 1;
        return Ok(offset.wrapping_add(ctx.last_low_offset));
    }
    let low_tree = ctx.low_offset.as_ref().ok_or(Error::InvalidHuffmanTree)?;
    let low_symbol = low_tree.decode(&mut ctx.bits)?;
    if low_symbol == 16 {
        ctx.num_low_offset_repeats = 15;
    } else {
        ctx.last_low_offset = u32::from(low_symbol);
    }
    Ok(offset.wrapping_add(ctx.last_low_offset))
}

/// Promote the offset at `idx` (in the rolling buffer) to position 0,
/// shifting everything above it down.
/// Used by symbols 259..=262.
fn promote_offset(ctx: &mut RunCtx, idx: usize, offs: u32) {
    // Shift indices 0..idx by one slot down, then store `offs` at 0.
    let mut i = idx;
    while i > 0 {
        ctx.old_offsets[i] = ctx.old_offsets[i - 1];
        i -= 1;
    }
    ctx.old_offsets[0] = offs;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Decoder as _;
    extern crate std;
    use std::vec;

    #[test]
    fn unpack_size_zero_is_immediate_done() {
        let mut dec = Decoder::with_unpack_size(0);
        let mut out = [0u8; 8];
        let (p, status) = dec.finish(&mut out).unwrap();
        assert_eq!(p.written, 0);
        assert!(matches!(status, Status::StreamEnd));
    }

    #[test]
    fn promote_offset_rotates_correctly() {
        // Construct a context-shaped struct just to test the helper.
        let mut ctx = RunCtx {
            bits: BitReader::new(),
            lengths: vec![],
            main: None,
            offset: None,
            low_offset: None,
            length: None,
            old_offsets: [10, 20, 30, 40],
            last_offset: 0,
            last_length: 0,
            last_low_offset: 0,
            num_low_offset_repeats: 0,
            out: vec![],
            window: vec![0u8; 16],
            wmask: 15,
            window_pos: 0,
            unpack_size: 0,
            ppmd: None,
            ppmd_escape: 2,
            is_ppmd_block: false,
            filter_programs: FilterPrograms::new(),
            pending_filters: vec![],
            ppmd_model_limit: None,
        };
        // Promote slot 2 (value 30) — result should be [30, 10, 20, 40].
        promote_offset(&mut ctx, 2, 30);
        assert_eq!(ctx.old_offsets, [30, 10, 20, 40]);
    }
}
