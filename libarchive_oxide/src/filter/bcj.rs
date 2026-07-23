// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Branch/Call/Jump (BCJ) decode filters as a sans-I/O [`Codec`].
//!
//! BCJ filters convert position-relative branch targets back to their stored,
//! position-independent form so that repeated call/jump instructions compress
//! better. This module is decode-only: it inverts the transform 7z/XZ encoders
//! apply. The transform at each instruction is a pure function of the bytes at
//! that position, the running instruction pointer, and (for x86) a small running
//! mask, so the reconstructed bytes are independent of how the input is chunked.
//!
//! Each family scans on a fixed stride (x86 byte-by-byte with stateful E8/E9
//! detection; ARM/ARM64/PPC/SPARC on 4-byte, ARM-Thumb on 2-byte, IA-64 on
//! 16-byte, RISC-V on 2/4/8-byte instructions). Because a branch instruction may
//! straddle a chunk boundary, [`BcjDecoder`] retains the trailing bytes that do
//! not yet form a complete instruction window and re-scans them once more input
//! arrives; at end of input any remaining tail is emitted untransformed, exactly
//! as the encoder left it.

// The branch transforms are ported bit-for-bit from the reference filters and rely on wrapping,
// sign-reinterpreting integer casts throughout; individual casts are not independently meaningful.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use libarchive_oxide_core::{ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput};

/// Which instruction family a BCJ filter targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BranchKind {
    /// x86 `E8`/`E9` call/jump (stateful, byte-granular).
    X86,
    /// 32-bit ARM `BL`.
    Arm,
    /// ARM Thumb `BL`/`BLX`.
    ArmThumb,
    /// 64-bit ARM `BL`/`ADRP`.
    Arm64,
    /// PowerPC `bl`.
    Ppc,
    /// SPARC `call`.
    Sparc,
    /// Itanium (IA-64) bundles.
    Ia64,
    /// RISC-V `JAL`/`AUIPC`.
    RiscV,
}

/// Running BCJ transform state (instruction pointer plus x86 mask).
struct BcjFilter {
    kind: BranchKind,
    /// Running position of the first byte of the buffer handed to [`Self::decode`].
    pos: usize,
    /// x86-only running branch mask carried across instructions.
    prev_mask: u32,
}

const MASK_TO_ALLOWED_STATUS: [bool; 8] = [true, true, true, false, true, false, false, false];
const MASK_TO_BIT_NUMBER: [u32; 8] = [0, 1, 2, 2, 3, 3, 3, 3];

#[inline]
const fn test_86_ms_byte(b: u8) -> bool {
    b == 0x00 || b == 0xFF
}

impl BcjFilter {
    fn new(kind: BranchKind, start_pos: usize) -> Self {
        // Per-family starting offsets mirror the reference encoders so decode is
        // their exact inverse.
        let pos = match kind {
            BranchKind::X86 => start_pos.wrapping_add(5),
            BranchKind::Arm => start_pos.wrapping_add(8),
            BranchKind::ArmThumb => start_pos.wrapping_add(4),
            BranchKind::Arm64
            | BranchKind::Ppc
            | BranchKind::Sparc
            | BranchKind::Ia64
            | BranchKind::RiscV => start_pos,
        };
        Self {
            kind,
            pos,
            prev_mask: 0,
        }
    }

    /// Transforms a leading run of complete instructions in place and returns the
    /// number of bytes committed. Trailing bytes that cannot yet hold a full
    /// instruction window are left untouched for the next call.
    fn decode(&mut self, buf: &mut [u8]) -> usize {
        match self.kind {
            BranchKind::X86 => self.x86(buf),
            BranchKind::Arm => self.arm(buf),
            BranchKind::ArmThumb => self.arm_thumb(buf),
            BranchKind::Arm64 => self.arm64(buf),
            BranchKind::Ppc => self.ppc(buf),
            BranchKind::Sparc => self.sparc(buf),
            BranchKind::Ia64 => self.ia64(buf),
            BranchKind::RiscV => self.riscv(buf),
        }
    }

    fn x86(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len();
        if len < 5 {
            return 0;
        }
        let end = len - 5;
        let mut prev_pos: isize = -1;
        let mut prev_mask = self.prev_mask;
        let mut i = 0usize;
        while i <= end {
            let b = buf[i];
            if b != 0xE9 && b != 0xE8 {
                i += 1;
                continue;
            }
            prev_pos = i as isize - prev_pos;
            if (prev_pos & !3) != 0 {
                prev_mask = 0;
            } else {
                prev_mask = (prev_mask << ((prev_pos - 1) as u32)) & 7;
                if prev_mask != 0
                    && (!MASK_TO_ALLOWED_STATUS[prev_mask as usize]
                        || test_86_ms_byte(
                            buf[i + 4 - MASK_TO_BIT_NUMBER[prev_mask as usize] as usize],
                        ))
                {
                    prev_pos = i as isize;
                    prev_mask = (prev_mask << 1) | 1;
                    i += 1;
                    continue;
                }
            }

            prev_pos = i as isize;
            if test_86_ms_byte(buf[i + 4]) {
                let mut src = i32::from(buf[i + 1])
                    | (i32::from(buf[i + 2]) << 8)
                    | (i32::from(buf[i + 3]) << 16)
                    | (i32::from(buf[i + 4]) << 24);
                let mut dest: i32;
                loop {
                    dest = src.wrapping_sub((self.pos.wrapping_add(i)) as i32);
                    if prev_mask == 0 {
                        break;
                    }
                    let index = MASK_TO_BIT_NUMBER[prev_mask as usize] * 8;
                    if !test_86_ms_byte(((dest >> (24 - index)) & 0xFF) as u8) {
                        break;
                    }
                    src = dest ^ ((1i32 << (32 - index)) - 1);
                }

                buf[i + 1] = dest as u8;
                buf[i + 2] = (dest >> 8) as u8;
                buf[i + 3] = (dest >> 16) as u8;
                buf[i + 4] = (!(((dest >> 24) & 1) - 1)) as u8;
                i += 4;
            } else {
                prev_mask = (prev_mask << 1) | 1;
            }
            i += 1;
        }

        prev_pos = i as isize - prev_pos;
        prev_mask = if (prev_pos & !3) != 0 {
            0
        } else {
            prev_mask << ((prev_pos - 1) as u32)
        };

        self.prev_mask = prev_mask;
        self.pos = self.pos.wrapping_add(i);
        i
    }

    fn arm(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len();
        if len < 4 {
            return 0;
        }
        let end = len - 4;
        let mut i = 0usize;
        while i <= end {
            if buf[i + 3] == 0xEB {
                let b2 = i32::from(buf[i + 2]);
                let b1 = i32::from(buf[i + 1]);
                let b0 = i32::from(buf[i]);

                let src = ((b2 << 16) | (b1 << 8) | b0) << 2;
                let p = self.pos.wrapping_add(i) as i32;
                let dest = src.wrapping_sub(p) >> 2;
                buf[i + 2] = ((dest >> 16) & 0xFF) as u8;
                buf[i + 1] = ((dest >> 8) & 0xFF) as u8;
                buf[i] = (dest & 0xFF) as u8;
            }
            i += 4;
        }
        self.pos = self.pos.wrapping_add(i);
        i
    }

    fn arm_thumb(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len();
        if len < 4 {
            return 0;
        }
        let end = len - 4;
        let mut i = 0usize;
        while i <= end {
            let b1 = i32::from(buf[i + 1]);
            let b3 = i32::from(buf[i + 3]);
            if (b3 & 0xF8) == 0xF8 && (b1 & 0xF8) == 0xF0 {
                let b2 = i32::from(buf[i + 2]);
                let b0 = i32::from(buf[i]);

                let src =
                    ((b1 & 0x07) << 19) | ((b0 & 0xFF) << 11) | ((b3 & 0x07) << 8) | (b2 & 0xFF);
                let src = src << 1;
                let dest = src.wrapping_sub(self.pos.wrapping_add(i) as i32) >> 1;
                buf[i + 1] = (0xF0 | ((dest >> 19) & 0x07)) as u8;
                buf[i] = (dest >> 11) as u8;
                buf[i + 3] = (0xF8 | ((dest >> 8) & 0x07)) as u8;
                buf[i + 2] = (dest & 0xFF) as u8;
                i += 2;
            }
            i += 2;
        }
        self.pos = self.pos.wrapping_add(i);
        i
    }

    fn arm64(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len();
        if len < 4 {
            return 0;
        }
        let end = len - 4;
        let mut i = 0usize;
        while i <= end {
            let b3 = i32::from(buf[i + 3]);
            let b2 = i32::from(buf[i + 2]);
            let b1 = i32::from(buf[i + 1]);
            let b0 = i32::from(buf[i]);

            let src = (b3 << 24) + (b2 << 16) + (b1 << 8) + b0;
            let p = self.pos.wrapping_add(i) as i32;

            // BL
            if ((src >> 26) & 0x3F) == 0x25 {
                let dest_adr = src.wrapping_sub(p >> 2);
                let dest = (dest_adr & 0x03FF_FFFF) | (0x94 << 24);

                buf[i + 3] = ((dest >> 24) & 0xFF) as u8;
                buf[i + 2] = ((dest >> 16) & 0xFF) as u8;
                buf[i + 1] = ((dest >> 8) & 0xFF) as u8;
                buf[i] = (dest & 0xFF) as u8;
            }

            // ADRP
            if ((src >> 24) & 0x9F) == 0x90 {
                let addr = ((src >> 29) & 3) | ((src >> 3) & 0x001F_FFFC);

                if 0 == (addr.wrapping_add(0x0002_0000) & 0x001C_0000) {
                    let dest = (0x90 << 24) | (src & 0x1F);
                    let addr = addr.wrapping_sub(p >> 12);
                    let dest = dest | ((addr & 3) << 29);
                    let dest = dest | ((addr & 0x0003_FFFC) << 3);
                    let dest = dest | (0i32.wrapping_sub(addr & 0x0002_0000) & 0x00E0_0000);

                    buf[i + 3] = ((dest >> 24) & 0xFF) as u8;
                    buf[i + 2] = ((dest >> 16) & 0xFF) as u8;
                    buf[i + 1] = ((dest >> 8) & 0xFF) as u8;
                    buf[i] = (dest & 0xFF) as u8;
                }
            }

            i += 4;
        }
        self.pos = self.pos.wrapping_add(i);
        i
    }

    fn ppc(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len();
        if len < 4 {
            return 0;
        }
        let end = len - 4;
        let mut i = 0usize;
        while i <= end {
            let b3 = i32::from(buf[i + 3]);
            let b0 = i32::from(buf[i]);

            if (b0 & 0xFC) == 0x48 && (b3 & 0x03) == 0x01 {
                let b2 = i32::from(buf[i + 2]);
                let b1 = i32::from(buf[i + 1]);

                let src =
                    ((b0 & 0x03) << 24) | ((b1 & 0xFF) << 16) | ((b2 & 0xFF) << 8) | (b3 & 0xFC);
                let p = self.pos.wrapping_add(i) as i32;
                let dest = src.wrapping_sub(p);

                buf[i] = (0x48 | ((dest >> 24) & 0x03)) as u8;
                buf[i + 1] = (dest >> 16) as u8;
                buf[i + 2] = (dest >> 8) as u8;
                buf[i + 3] = ((b3 & 0x03) | dest) as u8;
            }
            i += 4;
        }
        self.pos = self.pos.wrapping_add(i);
        i
    }

    fn sparc(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len();
        if len < 4 {
            return 0;
        }
        let end = len - 4;
        let mut i = 0usize;
        while i <= end {
            let b0 = i32::from(buf[i]);
            let b1 = i32::from(buf[i + 1]);

            if (b0 == 0x40 && (b1 & 0xC0) == 0x00) || (b0 == 0x7F && (b1 & 0xC0) == 0xC0) {
                let b2 = i32::from(buf[i + 2]);
                let b3 = i32::from(buf[i + 3]);

                let src =
                    ((b0 & 0xFF) << 24) | ((b1 & 0xFF) << 16) | ((b2 & 0xFF) << 8) | (b3 & 0xFF);
                let src = src << 2;
                let p = self.pos.wrapping_add(i) as i32;
                let dest = src.wrapping_sub(p) >> 2;
                let dest = (((0 - ((dest >> 22) & 1)) << 22) & 0x3FFF_FFFF)
                    | (dest & 0x3F_FFFF)
                    | 0x4000_0000;

                buf[i] = (dest >> 24) as u8;
                buf[i + 1] = (dest >> 16) as u8;
                buf[i + 2] = (dest >> 8) as u8;
                buf[i + 3] = dest as u8;
            }
            i += 4;
        }
        self.pos = self.pos.wrapping_add(i);
        i
    }

    fn ia64(&mut self, buf: &mut [u8]) -> usize {
        const BRANCH_TABLE: [u32; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4,
            4, 0, 0,
        ];

        let len = buf.len();
        if len < 16 {
            return 0;
        }
        let end = len - 16;
        let mut i = 0usize;

        while i <= end {
            let instr_template = (buf[i] & 0x1F) as usize;
            let mask = BRANCH_TABLE[instr_template];

            for slot in 0..3 {
                let bit_pos = 5 + slot * 41;
                if ((mask >> slot) & 1) == 0 {
                    continue;
                }

                let byte_pos = bit_pos >> 3;
                let bit_res = bit_pos & 7;

                let mut instr: u64 = 0;
                for j in 0..6 {
                    if i + byte_pos + j < buf.len() {
                        instr |= u64::from(buf[i + byte_pos + j]) << (8 * j);
                    }
                }

                let instr_norm = instr >> bit_res;

                if ((instr_norm >> 37) & 0x0F) != 0x05 || ((instr_norm >> 9) & 0x07) != 0x00 {
                    continue;
                }

                let mut src = ((instr_norm >> 13) & 0x0F_FFFF) as i32;
                src |= (((instr_norm >> 36) & 1) as i32) << 20;
                src <<= 4;

                let dest = src.wrapping_sub((self.pos as i32).wrapping_add(i as i32));
                let dest = (dest as u32) >> 4;

                let mut instr_norm = instr_norm;
                instr_norm &= !(0x8F_FFFF_u64 << 13);
                instr_norm |= u64::from(dest & 0x0F_FFFF) << 13;
                instr_norm |= u64::from(dest & 0x10_0000) << (36 - 20);

                let mut instr = instr & ((1_u64 << bit_res) - 1);
                instr |= instr_norm << bit_res;

                for j in 0..6 {
                    if i + byte_pos + j < buf.len() {
                        buf[i + byte_pos + j] = (instr >> (8 * j)) as u8;
                    }
                }
            }

            i += 16;
        }

        self.pos = self.pos.wrapping_add(i);
        i
    }

    fn riscv(&mut self, buf: &mut [u8]) -> usize {
        let len = buf.len();
        if len < 8 {
            return 0;
        }
        let end = len - 8;
        let mut i = 0usize;

        while i <= end {
            let inst = u32::from(buf[i]);

            if inst == 0xEF {
                // JAL
                let b1 = u32::from(buf[i + 1]);
                if (b1 & 0x0D) != 0 {
                    i += 2;
                    continue;
                }

                let b2 = u32::from(buf[i + 2]);
                let b3 = u32::from(buf[i + 3]);
                let pc = (self.pos + i) as i32;

                let addr = ((b1 & 0xF0) << 13) | (b2 << 9) | (b3 << 1);
                let addr = (addr as i32).wrapping_sub(pc);

                buf[i + 1] = ((b1 & 0x0F) | ((addr as u32 >> 8) & 0xF0)) as u8;
                buf[i + 2] =
                    (((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)) as u8;
                buf[i + 3] = (((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)) as u8;

                i += 4;
            } else if (inst & 0x7F) == 0x17 {
                // AUIPC
                let mut inst_full = inst
                    | (u32::from(buf[i + 1]) << 8)
                    | (u32::from(buf[i + 2]) << 16)
                    | (u32::from(buf[i + 3]) << 24);

                if (inst_full & 0xE80) != 0 {
                    let inst2 =
                        u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);

                    if (((inst_full << 8) ^ inst2) & 0xF_8003) != 3 {
                        i += 6;
                        continue;
                    }

                    let addr =
                        ((inst_full & 0xFFFF_F000) as i32).wrapping_add((inst2 >> 20) as i32);

                    inst_full = 0x17 | (2 << 7) | (inst2 << 12);
                    let inst2_new = addr;

                    buf[i] = inst_full as u8;
                    buf[i + 1] = (inst_full >> 8) as u8;
                    buf[i + 2] = (inst_full >> 16) as u8;
                    buf[i + 3] = (inst_full >> 24) as u8;

                    buf[i + 4] = inst2_new as u8;
                    buf[i + 5] = (inst2_new >> 8) as u8;
                    buf[i + 6] = (inst2_new >> 16) as u8;
                    buf[i + 7] = (inst2_new >> 24) as u8;
                } else {
                    let fake_rs1 = inst_full >> 27;

                    if ((inst_full.wrapping_sub(0x3100)) & 0x3F80) >= (fake_rs1 & 0x1D) {
                        i += 4;
                        continue;
                    }

                    let addr = i32::from_be_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
                    let addr = addr.wrapping_sub((self.pos + i) as i32);

                    let inst2_rs1 = inst_full >> 27;
                    let inst2 = (inst_full >> 12) | ((addr as u32) << 20);

                    inst_full =
                        0x17 | (inst2_rs1 << 7) | ((addr.wrapping_add(0x800) as u32) & 0xFFFF_F000);

                    buf[i] = inst_full as u8;
                    buf[i + 1] = (inst_full >> 8) as u8;
                    buf[i + 2] = (inst_full >> 16) as u8;
                    buf[i + 3] = (inst_full >> 24) as u8;

                    buf[i + 4] = inst2 as u8;
                    buf[i + 5] = (inst2 >> 8) as u8;
                    buf[i + 6] = (inst2 >> 16) as u8;
                    buf[i + 7] = (inst2 >> 24) as u8;
                }

                i += 8;
            } else {
                i += 2;
            }
        }

        self.pos = self.pos.wrapping_add(i);
        i
    }
}

/// Incremental BCJ decoder driving a [`BcjFilter`] with a small carry buffer so
/// that instruction windows straddling input chunks are handled correctly.
pub(crate) struct BcjDecoder {
    filter: BcjFilter,
    /// Encoded bytes accepted but not yet committed as a complete instruction run.
    buf: Vec<u8>,
    /// Decoded bytes ready to emit.
    out: Vec<u8>,
    /// Emit cursor into `out`.
    out_pos: usize,
    finished: bool,
}

impl BcjDecoder {
    /// Builds a decoder for `kind`, with the running position seeded from `start`.
    pub(crate) fn new(kind: BranchKind, start: usize) -> Self {
        Self {
            filter: BcjFilter::new(kind, start),
            buf: Vec::new(),
            out: Vec::new(),
            out_pos: 0,
            finished: false,
        }
    }
}

impl core::fmt::Debug for BcjDecoder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BcjDecoder")
            .field("kind", &self.filter.kind)
            .field("buffered", &self.buf.len())
            .field("pending", &(self.out.len() - self.out_pos))
            .finish_non_exhaustive()
    }
}

impl Codec for BcjDecoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        // Phase A: drain decoded bytes already staged from an earlier call.
        if self.out_pos < self.out.len() {
            let available = self.out.len() - self.out_pos;
            let count = available.min(output.len());
            output[..count].copy_from_slice(&self.out[self.out_pos..self.out_pos + count]);
            self.out_pos += count;
            if self.out_pos == self.out.len() {
                self.out.clear();
                self.out_pos = 0;
            }
            return Ok(CodecStep {
                consumed: 0,
                produced: count,
                status: CodecStatus::NeedOutput,
            });
        }
        if self.finished {
            return Ok(CodecStep {
                consumed: 0,
                produced: 0,
                status: CodecStatus::Done,
            });
        }

        // Phase B: ingest this call's input and either filter it or, at true end
        // of input, flush the untransformed tail.
        let consumed = input.len();
        if consumed > 0 {
            self.buf.extend_from_slice(input);
        }
        let at_end = matches!(end, EndOfInput::End) && consumed == 0;
        if at_end {
            // The trailing bytes that never formed a complete instruction window
            // are emitted exactly as stored.
            core::mem::swap(&mut self.out, &mut self.buf);
            self.finished = true;
        } else {
            let filtered = self.filter.decode(&mut self.buf);
            if filtered > 0 {
                self.out.extend_from_slice(&self.buf[..filtered]);
                self.buf.drain(..filtered);
            }
        }

        // Phase C: emit whatever the filter produced.
        if self.out.is_empty() {
            let status = if self.finished {
                CodecStatus::Done
            } else {
                // Input consumed but no complete instruction yet; ask for more.
                CodecStatus::NeedInput
            };
            return Ok(CodecStep {
                consumed,
                produced: 0,
                status,
            });
        }
        let count = self.out.len().min(output.len());
        output[..count].copy_from_slice(&self.out[..count]);
        self.out_pos = count;
        if self.out_pos == self.out.len() {
            self.out.clear();
            self.out_pos = 0;
        }
        Ok(CodecStep {
            consumed,
            produced: count,
            status: CodecStatus::NeedInput,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::io::{Cursor, Read, Write};

    use lzma_rust2::filter::bcj::{BcjReader, BcjWriter};

    use super::*;
    use crate::codec_read::CodecReader;

    /// Deterministic pseudo-random bytes so branch opcodes actually occur and get transformed.
    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut state: u64 = 0x1234_5678_9abc_def1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    /// A reader that yields at most `chunk` bytes per `read`, to stress input-boundary handling.
    struct ChunkReader {
        data: Vec<u8>,
        pos: usize,
        chunk: usize,
    }

    impl Read for ChunkReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let remaining = self.data.len() - self.pos;
            let n = remaining.min(self.chunk).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn encode(kind: BranchKind, data: &[u8]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = match kind {
            BranchKind::X86 => BcjWriter::new_x86(cursor, 0),
            BranchKind::Arm => BcjWriter::new_arm(cursor, 0),
            BranchKind::ArmThumb => BcjWriter::new_arm_thumb(cursor, 0),
            BranchKind::Arm64 => BcjWriter::new_arm64(cursor, 0),
            BranchKind::Ppc => BcjWriter::new_ppc(cursor, 0),
            BranchKind::Sparc => BcjWriter::new_sparc(cursor, 0),
            BranchKind::Ia64 => BcjWriter::new_ia64(cursor, 0),
            BranchKind::RiscV => BcjWriter::new_riscv(cursor, 0),
        };
        writer.write_all(data).unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn reference_decode(kind: BranchKind, encoded: &[u8]) -> Vec<u8> {
        let cursor = Cursor::new(encoded.to_vec());
        let mut reader = match kind {
            BranchKind::X86 => BcjReader::new_x86(cursor, 0),
            BranchKind::Arm => BcjReader::new_arm(cursor, 0),
            BranchKind::ArmThumb => BcjReader::new_arm_thumb(cursor, 0),
            BranchKind::Arm64 => BcjReader::new_arm64(cursor, 0),
            BranchKind::Ppc => BcjReader::new_ppc(cursor, 0),
            BranchKind::Sparc => BcjReader::new_sparc(cursor, 0),
            BranchKind::Ia64 => BcjReader::new_ia64(cursor, 0),
            BranchKind::RiscV => BcjReader::new_riscv(cursor, 0),
        };
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        out
    }

    fn arca_decode(kind: BranchKind, encoded: &[u8], out_chunk: usize, in_chunk: usize) -> Vec<u8> {
        let inner = ChunkReader {
            data: encoded.to_vec(),
            pos: 0,
            chunk: in_chunk,
        };
        let mut reader = CodecReader::new(inner, BcjDecoder::new(kind, 0), "bcj");
        let mut out = Vec::new();
        let mut buf = vec![0u8; out_chunk];
        loop {
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    #[test]
    fn every_branch_kind_round_trips_against_lzma_rust2() {
        let data = pseudo_random(150_003);
        for kind in [
            BranchKind::X86,
            BranchKind::Arm,
            BranchKind::ArmThumb,
            BranchKind::Arm64,
            BranchKind::Ppc,
            BranchKind::Sparc,
            BranchKind::Ia64,
            BranchKind::RiscV,
        ] {
            let encoded = encode(kind, &data);
            // The reference decoder must reconstruct the input (encoder actually transformed it).
            assert_eq!(
                reference_decode(kind, &encoded),
                data,
                "reference round trip failed for {kind:?}"
            );
            // A non-trivial transform occurred for at least the byte-granular x86 filter.
            if kind == BranchKind::X86 {
                assert_ne!(encoded, data, "x86 encoder made no change");
            }
            // arca decodes byte-identically regardless of input/output chunking.
            for (out_chunk, in_chunk) in [(1, 1), (3, 7), (64, 5), (4096, 64), (200_000, 200_000)] {
                assert_eq!(
                    arca_decode(kind, &encoded, out_chunk, in_chunk),
                    data,
                    "arca decode mismatch for {kind:?} at out={out_chunk} in={in_chunk}"
                );
            }
        }
    }

    #[test]
    fn tiny_output_matches_bulk_output() {
        // Empty and near-window-boundary lengths for the x86 filter's held-back tail.
        for len in [0usize, 1, 4, 5, 6, 8, 4095, 4096, 4097] {
            let data = pseudo_random(len);
            let encoded = encode(BranchKind::X86, &data);
            let bulk = arca_decode(
                BranchKind::X86,
                &encoded,
                usize::max(len, 1),
                usize::max(len, 1),
            );
            let single = arca_decode(BranchKind::X86, &encoded, 1, 1);
            assert_eq!(bulk, data, "bulk decode mismatch at len {len}");
            assert_eq!(single, data, "single-byte decode mismatch at len {len}");
        }
    }
}
