// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: BSD-2-Clause

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Bounded, allocation-free execution of RAR3 standard VM filters.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// RAR3 VM address-space size.
pub const VM_MEMORY_BYTES: usize = 0x4_0000;
/// Bytes available to a standard filter program before its global-data area.
pub const PROGRAM_WORK_BYTES: usize = 0x3_c000;
/// Largest scratch buffer required by Delta, RGB, or Audio.
pub const MAX_FILTER_SCRATCH_BYTES: usize = PROGRAM_WORK_BYTES / 2;
/// Largest bytecode program accepted by the RAR3 descriptor grammar.
pub const MAX_PROGRAM_BYTES: usize = 0x1_0000;
/// Maximum persistent standard programs retained by one solid decoder.
pub const MAX_PROGRAMS: usize = 1_024;
const PROGRAM_SYSTEM_GLOBAL_ADDRESS: u32 = 0x3_c000;
const PROGRAM_USER_GLOBAL_BYTES: u32 = 0x1_fc0;

const E8_FINGERPRINT: u64 = 0x0035_ad57_6887;
const E8E9_FINGERPRINT: u64 = 0x0039_3cd7_e57e;
const DELTA_FINGERPRINT: u64 = 0x001d_0e06_077d;
const RGB_FINGERPRINT: u64 = 0x0095_1c2c_5dc8;
const AUDIO_FINGERPRINT: u64 = 0x00d8_bc85_e701;
const E8_FILE_SIZE: u32 = 0x100_0000;

/// Failure while validating or executing a standard filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// The bytecode is empty or exceeds the format's finite length bound.
    MalformedProgram,
    /// The RAR XOR bytecode checksum does not match.
    ProgramChecksumMismatch,
    /// The bytecode is valid but is not one of the recognized standard filters.
    UnsupportedProgram,
    /// A filter descriptor ends in the middle of a field.
    TruncatedDescriptor,
    /// A descriptor contains inconsistent indices, offsets, lengths, or registers.
    InvalidDescriptor,
    /// A descriptor exceeds a fixed format or allocation bound.
    ResourceLimit,
    /// Register values or the supplied block length are inconsistent.
    InvalidRegisters,
    /// The caller-provided scratch buffer cannot hold the source block.
    ScratchTooSmall,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MalformedProgram => "RAR3 VM program length is invalid",
            Self::ProgramChecksumMismatch => "RAR3 VM program checksum does not match",
            Self::UnsupportedProgram => "RAR3 VM program is not a supported standard filter",
            Self::TruncatedDescriptor => "RAR3 VM filter descriptor is truncated",
            Self::InvalidDescriptor => "RAR3 VM filter descriptor is invalid",
            Self::ResourceLimit => "RAR3 VM filter descriptor exceeds a resource limit",
            Self::InvalidRegisters => "RAR3 VM standard-filter registers are invalid",
            Self::ScratchTooSmall => "RAR3 VM standard-filter scratch is too small",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProgramRecord {
    program: Program,
    usage_count: u32,
    old_filter_length: u32,
}

/// Persistent standard-program table carried by RAR3 solid decoding state.
#[derive(Debug, Default)]
pub struct FilterPrograms {
    programs: Vec<ProgramRecord>,
    last_program: usize,
}

impl FilterPrograms {
    /// Creates an empty standard-program table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            programs: Vec::new(),
            last_program: 0,
        }
    }

    /// Parses one bounded descriptor body decoded after its flags byte.
    ///
    /// `current_position` is the number of bytes already reconstructed for the current member.
    /// `dictionary_bytes` is the caller-preflighted RAR window bound.
    /// A selector value of zero resets the persistent program table and asks the caller to discard pending filters.
    pub fn parse(
        &mut self,
        flags: u8,
        bytes: &[u8],
        current_position: u64,
        dictionary_bytes: u64,
    ) -> Result<FilterDescriptor, Error> {
        let mut reader = MemoryBits::new(bytes);
        let mut resets_pending = false;
        let selected = if flags & 0x80 != 0 {
            let encoded = reader.next_number()?;
            if encoded == 0 {
                self.programs.clear();
                self.last_program = 0;
                resets_pending = true;
                0
            } else {
                usize::try_from(encoded - 1).map_err(|_| Error::InvalidDescriptor)?
            }
        } else {
            self.last_program
        };
        if selected > self.programs.len() {
            return Err(Error::InvalidDescriptor);
        }

        let block_delta = u64::from(reader.next_number()?);
        let mut block_start = current_position
            .checked_add(block_delta)
            .ok_or(Error::InvalidDescriptor)?;
        if flags & 0x40 != 0 {
            block_start = block_start
                .checked_add(258)
                .ok_or(Error::InvalidDescriptor)?;
        }

        let existing = self.programs.get(selected).copied();
        let block_length = if flags & 0x20 != 0 {
            reader.next_number()?
        } else {
            existing.map_or(0, |record| record.old_filter_length)
        };
        if u64::from(block_length) > dictionary_bytes
            || usize::try_from(block_length).map_err(|_| Error::InvalidDescriptor)?
                > VM_MEMORY_BYTES
        {
            return Err(Error::InvalidDescriptor);
        }

        let usage_count = if let Some(record) = existing {
            record
                .usage_count
                .checked_add(1)
                .ok_or(Error::ResourceLimit)?
        } else {
            0
        };
        let registers = parse_registers(&mut reader, flags, block_length, usage_count)?;

        let program = if let Some(record) = existing {
            record.program
        } else {
            if self.programs.len() >= MAX_PROGRAMS {
                return Err(Error::ResourceLimit);
            }
            parse_new_program(&mut reader)?
        };

        skip_global_data(&mut reader, flags)?;

        let record = ProgramRecord {
            program,
            usage_count,
            old_filter_length: block_length,
        };
        if selected == self.programs.len() {
            self.programs
                .try_reserve(1)
                .map_err(|_| Error::ResourceLimit)?;
            self.programs.push(record);
        } else {
            self.programs[selected] = record;
        }
        self.last_program = selected;

        Ok(FilterDescriptor {
            program,
            registers,
            block_start,
            block_length,
            resets_pending,
        })
    }
}

fn parse_registers(
    reader: &mut MemoryBits<'_>,
    flags: u8,
    block_length: u32,
    usage_count: u32,
) -> Result<[u32; 8], Error> {
    let mut registers = [0_u32; 8];
    registers[3] = PROGRAM_SYSTEM_GLOBAL_ADDRESS;
    registers[4] = block_length;
    registers[5] = usage_count;
    registers[7] = u32::try_from(VM_MEMORY_BYTES).map_err(|_| Error::ResourceLimit)?;
    if flags & 0x10 != 0 {
        let mask = u8::try_from(reader.read_bits(7)?).map_err(|_| Error::InvalidDescriptor)?;
        for (index, register) in registers.iter_mut().take(7).enumerate() {
            if mask & (1 << index) != 0 {
                *register = reader.next_number()?;
            }
        }
    }
    Ok(registers)
}

fn parse_new_program(reader: &mut MemoryBits<'_>) -> Result<Program, Error> {
    let length = usize::try_from(reader.next_number()?).map_err(|_| Error::InvalidDescriptor)?;
    if length == 0 || length > MAX_PROGRAM_BYTES {
        return Err(Error::ResourceLimit);
    }
    let mut bytecode = Vec::new();
    bytecode
        .try_reserve_exact(length)
        .map_err(|_| Error::ResourceLimit)?;
    for _ in 0..length {
        bytecode.push(u8::try_from(reader.read_bits(8)?).map_err(|_| Error::InvalidDescriptor)?);
    }
    Program::compile(&bytecode)
}

fn skip_global_data(reader: &mut MemoryBits<'_>, flags: u8) -> Result<(), Error> {
    if flags & 0x08 == 0 {
        return Ok(());
    }
    let length = reader.next_number()?;
    if length > PROGRAM_USER_GLOBAL_BYTES {
        return Err(Error::ResourceLimit);
    }
    for _ in 0..length {
        let _ = reader.read_bits(8)?;
    }
    Ok(())
}

/// One validated invocation of a recognized standard RAR3 VM program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilterDescriptor {
    program: Program,
    registers: [u32; 8],
    block_start: u64,
    block_length: u32,
    resets_pending: bool,
}

impl FilterDescriptor {
    /// Statically recognized program.
    #[must_use]
    pub const fn program(self) -> Program {
        self.program
    }

    /// Initial VM registers supplied by the descriptor.
    #[must_use]
    pub const fn registers(self) -> [u32; 8] {
        self.registers
    }

    /// Start offset in the current decoded member.
    #[must_use]
    pub const fn block_start(self) -> u64 {
        self.block_start
    }

    /// Number of decoded bytes transformed by this invocation.
    #[must_use]
    pub const fn block_length(self) -> u32 {
        self.block_length
    }

    /// Whether an encoded program-table reset also discards pending filters.
    #[must_use]
    pub const fn resets_pending_filters(self) -> bool {
        self.resets_pending
    }

    /// Scratch bytes required to execute this invocation.
    pub fn scratch_bytes(self) -> Result<usize, Error> {
        let length = usize::try_from(self.block_length).map_err(|_| Error::InvalidDescriptor)?;
        Ok(self.program.scratch_bytes(length))
    }
}

struct MemoryBits<'a> {
    bytes: &'a [u8],
    bit_position: usize,
}

impl<'a> MemoryBits<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            bit_position: 0,
        }
    }

    fn read_bits(&mut self, count: u8) -> Result<u32, Error> {
        if count > 32 {
            return Err(Error::InvalidDescriptor);
        }
        let end = self
            .bit_position
            .checked_add(usize::from(count))
            .ok_or(Error::TruncatedDescriptor)?;
        if end > self.bytes.len().saturating_mul(8) {
            return Err(Error::TruncatedDescriptor);
        }
        let mut value = 0_u32;
        while self.bit_position < end {
            let byte = self.bytes[self.bit_position / 8];
            let shift = 7 - (self.bit_position & 7);
            value = (value << 1) | u32::from((byte >> shift) & 1);
            self.bit_position += 1;
        }
        Ok(value)
    }

    fn next_number(&mut self) -> Result<u32, Error> {
        match self.read_bits(2)? {
            0 => self.read_bits(4),
            1 => {
                let value = self.read_bits(8)?;
                if value >= 16 {
                    Ok(value)
                } else {
                    Ok(0xffff_ff00 | (value << 4) | self.read_bits(4)?)
                }
            },
            2 => self.read_bits(16),
            3 => self.read_bits(32),
            _ => Err(Error::InvalidDescriptor),
        }
    }
}

/// Standard RAR3 programs recognized by their bytecode fingerprint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FilterKind {
    /// Planar/interleaved byte-delta reconstruction.
    Delta,
    /// Intel `E8` relative-call translation.
    E8,
    /// Intel `E8` and `E9` relative-call/jump translation.
    E8E9,
    /// Three-plane RGB reconstruction and green-channel correlation.
    Rgb,
    /// Adaptive multimedia audio predictor.
    Audio,
}

/// A validated, statically dispatched standard RAR3 VM program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Program {
    kind: FilterKind,
}

impl Program {
    /// Validates and identifies one RAR3 bytecode program.
    ///
    /// Only the five standard programs are accepted.
    /// Their bytecode is never interpreted: length and CRC identify a statically dispatched transform.
    pub fn compile(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_PROGRAM_BYTES {
            return Err(Error::MalformedProgram);
        }
        let checksum = bytes[1..].iter().fold(0_u8, |xor, byte| xor ^ byte);
        if checksum != bytes[0] {
            return Err(Error::ProgramChecksumMismatch);
        }
        Self::from_fingerprint(fingerprint(bytes)).ok_or(Error::UnsupportedProgram)
    }

    /// Constructs an already-identified standard program.
    #[must_use]
    pub const fn standard(kind: FilterKind) -> Self {
        Self { kind }
    }

    /// Recognizes the length-and-CRC fingerprint used by RAR3 standard programs.
    #[must_use]
    pub const fn from_fingerprint(fingerprint: u64) -> Option<Self> {
        let kind = match fingerprint {
            DELTA_FINGERPRINT => FilterKind::Delta,
            E8_FINGERPRINT => FilterKind::E8,
            E8E9_FINGERPRINT => FilterKind::E8E9,
            RGB_FINGERPRINT => FilterKind::Rgb,
            AUDIO_FINGERPRINT => FilterKind::Audio,
            _ => return None,
        };
        Some(Self::standard(kind))
    }

    /// Identified standard-filter kind.
    #[must_use]
    pub const fn kind(self) -> FilterKind {
        self.kind
    }

    /// Maximum scratch needed for a block of `block_bytes` bytes.
    #[must_use]
    pub const fn scratch_bytes(self, block_bytes: usize) -> usize {
        match self.kind {
            FilterKind::E8 | FilterKind::E8E9 => 0,
            FilterKind::Delta | FilterKind::Rgb | FilterKind::Audio => block_bytes,
        }
    }
}

fn fingerprint(bytes: &[u8]) -> u64 {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    (length << 32) | u64::from(crc32(bytes))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let low = crc & 1;
            crc = (crc >> 1) ^ (0xedb8_8320_u32 & 0_u32.wrapping_sub(low));
        }
    }
    !crc
}

/// Executes one standard RAR3 filter over a complete block.
///
/// Register 4 must equal `data.len()`.
/// Delta, RGB, and Audio copy their encoded source into the first `data.len()` bytes of `scratch`; E8 variants do not use scratch.
/// `position` is the block's decoded-file offset.
pub fn apply(
    program: Program,
    registers: [u32; 8],
    data: &mut [u8],
    position: u64,
    scratch: &mut [u8],
) -> Result<(), Error> {
    let declared = usize::try_from(registers[4]).map_err(|_| Error::InvalidRegisters)?;
    if declared != data.len() {
        return Err(Error::InvalidRegisters);
    }
    match program.kind {
        FilterKind::Delta => apply_delta(data, registers[0], scratch),
        FilterKind::E8 => apply_e8(data, position, false),
        FilterKind::E8E9 => apply_e8(data, position, true),
        FilterKind::Rgb => apply_rgb(data, registers[0], registers[1], scratch),
        FilterKind::Audio => apply_audio(data, registers[0], scratch),
    }
}

fn stage_source<'a>(data: &mut [u8], scratch: &'a mut [u8]) -> Result<&'a [u8], Error> {
    if data.len() > MAX_FILTER_SCRATCH_BYTES {
        return Err(Error::InvalidRegisters);
    }
    let source = scratch
        .get_mut(..data.len())
        .ok_or(Error::ScratchTooSmall)?;
    source.copy_from_slice(data);
    data.fill(0);
    Ok(source)
}

fn apply_delta(data: &mut [u8], channels: u32, scratch: &mut [u8]) -> Result<(), Error> {
    let channels = usize::try_from(channels).map_err(|_| Error::InvalidRegisters)?;
    if channels == 0 || channels > data.len() {
        return Err(Error::InvalidRegisters);
    }
    let source = stage_source(data, scratch)?;
    let mut source_index = 0usize;
    for channel in 0..channels {
        let mut last = 0u8;
        for destination in (channel..data.len()).step_by(channels) {
            let delta = *source.get(source_index).ok_or(Error::InvalidRegisters)?;
            source_index += 1;
            last = last.wrapping_sub(delta);
            data[destination] = last;
        }
    }
    if source_index != data.len() {
        return Err(Error::InvalidRegisters);
    }
    Ok(())
}

fn apply_e8(data: &mut [u8], position: u64, e9_also: bool) -> Result<(), Error> {
    if data.len() > PROGRAM_WORK_BYTES || data.len() <= 4 {
        return Err(Error::InvalidRegisters);
    }
    let mut index = 0usize;
    while index <= data.len() - 5 {
        if data[index] != 0xe8 && !(e9_also && data[index] == 0xe9) {
            index += 1;
            continue;
        }
        let position_low =
            u32::try_from(position & u64::from(u32::MAX)).map_err(|_| Error::InvalidRegisters)?;
        let current_index = u32::try_from(index).map_err(|_| Error::InvalidRegisters)?;
        let current = position_low.wrapping_add(current_index).wrapping_add(1);
        let address = i32::from_le_bytes([
            data[index + 1],
            data[index + 2],
            data[index + 3],
            data[index + 4],
        ]);
        let translated = if address < 0 && current >= address.unsigned_abs() {
            Some(address.cast_unsigned().wrapping_add(E8_FILE_SIZE))
        } else if address >= 0 && address.cast_unsigned() < E8_FILE_SIZE {
            Some(address.cast_unsigned().wrapping_sub(current))
        } else {
            None
        };
        if let Some(translated) = translated {
            data[index + 1..index + 5].copy_from_slice(&translated.to_le_bytes());
        }
        index += 5;
    }
    Ok(())
}

fn apply_rgb(
    data: &mut [u8],
    stride: u32,
    byte_offset: u32,
    scratch: &mut [u8],
) -> Result<(), Error> {
    let stride = usize::try_from(stride).map_err(|_| Error::InvalidRegisters)?;
    let byte_offset = usize::try_from(byte_offset).map_err(|_| Error::InvalidRegisters)?;
    if stride == 0 || stride > data.len() || data.len() < 3 || byte_offset > 2 {
        return Err(Error::InvalidRegisters);
    }
    let source = stage_source(data, scratch)?;
    let mut source_index = 0usize;
    for channel in 0..3usize {
        let mut byte = 0u8;
        for destination in (channel..data.len()).step_by(3) {
            if let Some(previous) = destination.checked_sub(stride) {
                let next_previous = data.get(previous + 3).copied().unwrap_or(0);
                let previous_byte = data[previous];
                let delta1 = (i32::from(next_previous) - i32::from(previous_byte)).unsigned_abs();
                let delta2 = (i32::from(byte) - i32::from(previous_byte)).unsigned_abs();
                let delta3 = (i32::from(next_previous) - 2 * i32::from(previous_byte)
                    + i32::from(byte))
                .unsigned_abs();
                if delta1 > delta2 || delta1 > delta3 {
                    byte = if delta2 <= delta3 {
                        next_previous
                    } else {
                        previous_byte
                    };
                }
            }
            let delta = *source.get(source_index).ok_or(Error::InvalidRegisters)?;
            source_index += 1;
            byte = byte.wrapping_sub(delta);
            data[destination] = byte;
        }
    }
    if source_index != data.len() {
        return Err(Error::InvalidRegisters);
    }
    for index in (byte_offset..data.len() - 2).step_by(3) {
        data[index] = data[index].wrapping_add(data[index + 1]);
        data[index + 2] = data[index + 2].wrapping_add(data[index + 1]);
    }
    Ok(())
}

#[derive(Default)]
struct AudioState {
    weight: [i8; 3],
    delta: [i16; 3],
    last_delta: i8,
    error: [i32; 7],
    count: u32,
    last_byte: u8,
}

fn apply_audio(data: &mut [u8], channels: u32, scratch: &mut [u8]) -> Result<(), Error> {
    let channels = usize::try_from(channels).map_err(|_| Error::InvalidRegisters)?;
    if channels == 0 || channels > data.len() {
        return Err(Error::InvalidRegisters);
    }
    let source = stage_source(data, scratch)?;
    let mut source_index = 0usize;
    for channel in 0..channels {
        let mut state = AudioState::default();
        for destination in (channel..data.len()).step_by(channels) {
            state.delta[2] = state.delta[1];
            state.delta[1] = i16::from(state.last_delta) - state.delta[0];
            state.delta[0] = i16::from(state.last_delta);
            let prediction = (8 * i32::from(state.last_byte)
                + i32::from(state.weight[0]) * i32::from(state.delta[0])
                + i32::from(state.weight[1]) * i32::from(state.delta[1])
                + i32::from(state.weight[2]) * i32::from(state.delta[2]))
                >> 3;
            let predicted = u8::try_from(prediction & 0xff).map_err(|_| Error::InvalidRegisters)?;
            let delta =
                i8::from_ne_bytes([*source.get(source_index).ok_or(Error::InvalidRegisters)?]);
            source_index += 1;
            let byte = predicted.wrapping_sub(delta.cast_unsigned());
            let prediction_error = i32::from(delta) * 8;
            state.error[0] += prediction_error.abs();
            for (slot, source_delta, subtract) in [
                (1, state.delta[0], true),
                (2, state.delta[0], false),
                (3, state.delta[1], true),
                (4, state.delta[1], false),
                (5, state.delta[2], true),
                (6, state.delta[2], false),
            ] {
                let candidate = if subtract {
                    prediction_error - i32::from(source_delta)
                } else {
                    prediction_error + i32::from(source_delta)
                };
                state.error[slot] += candidate.abs();
            }
            state.last_delta = i8::from_ne_bytes([byte.wrapping_sub(state.last_byte)]);
            state.last_byte = byte;
            data[destination] = byte;
            if state.count.trailing_zeros() >= 5 {
                adjust_audio_weights(&mut state);
            }
            state.count = state.count.wrapping_add(1);
        }
    }
    if source_index != data.len() {
        return Err(Error::InvalidRegisters);
    }
    Ok(())
}

fn adjust_audio_weights(state: &mut AudioState) {
    let mut best = 0usize;
    for index in 1..state.error.len() {
        if state.error[index] < state.error[best] {
            best = index;
        }
    }
    state.error.fill(0);
    let (weight, increment) = match best {
        1 => (0, false),
        2 => (0, true),
        3 => (1, false),
        4 => (1, true),
        5 => (2, false),
        6 => (2, true),
        _ => return,
    };
    if increment {
        if state.weight[weight] < 16 {
            state.weight[weight] += 1;
        }
    } else if state.weight[weight] >= -16 {
        state.weight[weight] -= 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use super::{Error, FilterKind, FilterPrograms, MAX_PROGRAMS, Program, ProgramRecord, apply};

    #[derive(Default)]
    struct BitWriter {
        bytes: Vec<u8>,
        bit: u8,
    }

    impl BitWriter {
        fn bits(&mut self, value: u32, count: u8) {
            for shift in (0..count).rev() {
                if self.bit == 0 {
                    self.bytes.push(0);
                }
                let last = self.bytes.len() - 1;
                self.bytes[last] |= (((value >> shift) & 1) as u8) << (7 - self.bit);
                self.bit = (self.bit + 1) & 7;
            }
        }

        fn number(&mut self, value: u32) {
            if value <= 15 {
                self.bits(0, 2);
                self.bits(value, 4);
            } else if u16::try_from(value).is_ok() {
                self.bits(2, 2);
                self.bits(value, 16);
            } else {
                self.bits(3, 2);
                self.bits(value, 32);
            }
        }
    }

    fn delta_programs(old_filter_length: u32) -> FilterPrograms {
        let mut programs = FilterPrograms::default();
        programs.programs.push(ProgramRecord {
            program: Program::standard(FilterKind::Delta),
            usage_count: 0,
            old_filter_length,
        });
        programs
    }

    #[test]
    fn recognizes_the_five_libarchive_standard_programs() {
        assert_eq!(
            Program::from_fingerprint(0x001d_0e06_077d),
            Some(Program::standard(FilterKind::Delta))
        );
        assert_eq!(
            Program::from_fingerprint(0x0035_ad57_6887),
            Some(Program::standard(FilterKind::E8))
        );
        assert_eq!(
            Program::from_fingerprint(0x0039_3cd7_e57e),
            Some(Program::standard(FilterKind::E8E9))
        );
        assert_eq!(
            Program::from_fingerprint(0x0095_1c2c_5dc8),
            Some(Program::standard(FilterKind::Rgb))
        );
        assert_eq!(
            Program::from_fingerprint(0x00d8_bc85_e701),
            Some(Program::standard(FilterKind::Audio))
        );
        assert_eq!(Program::from_fingerprint(0), None);
    }

    #[test]
    fn compiler_validates_rar_checksum_before_fingerprinting() {
        assert_eq!(Program::compile(&[]), Err(Error::MalformedProgram));
        assert_eq!(
            Program::compile(&[0, 1]),
            Err(Error::ProgramChecksumMismatch)
        );
        assert_eq!(Program::compile(&[0, 0]), Err(Error::UnsupportedProgram));
    }

    #[test]
    fn fingerprint_uses_standard_crc32_and_byte_length() {
        assert_eq!(
            super::fingerprint(b"123456789"),
            (9_u64 << 32) | 0xcbf4_3926
        );
    }

    #[test]
    fn descriptor_reuses_program_and_populates_registers() {
        let mut writer = BitWriter::default();
        writer.number(5);
        writer.number(6);
        writer.bits(0b000_0011, 7);
        writer.number(2);
        writer.number(1);
        writer.number(2);
        writer.bits(0xaa, 8);
        writer.bits(0x55, 8);

        let descriptor = delta_programs(4)
            .parse(0x20 | 0x10 | 0x08, &writer.bytes, 10, 100)
            .unwrap();

        assert_eq!(descriptor.program().kind(), FilterKind::Delta);
        assert_eq!(descriptor.block_start(), 15);
        assert_eq!(descriptor.block_length(), 6);
        assert_eq!(descriptor.registers()[0], 2);
        assert_eq!(descriptor.registers()[1], 1);
        assert_eq!(descriptor.registers()[3], 0x3_c000);
        assert_eq!(descriptor.registers()[4], 6);
        assert_eq!(descriptor.registers()[5], 1);
        assert_eq!(descriptor.registers()[7], 0x4_0000);
        assert!(!descriptor.resets_pending_filters());
    }

    #[test]
    fn descriptor_uses_previous_block_length_when_omitted() {
        let mut writer = BitWriter::default();
        writer.number(0);
        let descriptor = delta_programs(7).parse(0, &writer.bytes, 3, 100).unwrap();
        assert_eq!(descriptor.block_start(), 3);
        assert_eq!(descriptor.block_length(), 7);
    }

    #[test]
    fn reset_clears_programs_before_compiling_a_replacement() {
        let mut writer = BitWriter::default();
        writer.number(0);
        writer.number(0);
        writer.number(1);
        writer.number(2);
        writer.bits(0, 8);
        writer.bits(0, 8);
        let mut programs = delta_programs(1);

        assert_eq!(
            programs.parse(0x80 | 0x20, &writer.bytes, 0, 100),
            Err(Error::UnsupportedProgram)
        );
        assert_eq!(programs.programs, [] as [ProgramRecord; 0]);
    }

    #[test]
    fn descriptor_rejects_truncation_and_resource_excess() {
        assert_eq!(
            delta_programs(1).parse(0x20, &[], 0, 100),
            Err(Error::TruncatedDescriptor)
        );

        let mut too_large = BitWriter::default();
        too_large.number(0);
        too_large.number(0x4_0001);
        assert_eq!(
            delta_programs(1).parse(0x20, &too_large.bytes, 0, u64::MAX),
            Err(Error::InvalidDescriptor)
        );

        let mut global = BitWriter::default();
        global.number(0);
        global.number(1);
        global.number(0x1_fc1);
        assert_eq!(
            delta_programs(1).parse(0x20 | 0x08, &global.bytes, 0, 100),
            Err(Error::ResourceLimit)
        );
    }

    #[test]
    fn program_table_has_a_fixed_entry_limit() {
        let record = ProgramRecord {
            program: Program::standard(FilterKind::Delta),
            usage_count: 0,
            old_filter_length: 1,
        };
        let mut programs = FilterPrograms {
            programs: alloc::vec![record; MAX_PROGRAMS],
            last_program: MAX_PROGRAMS,
        };
        let mut writer = BitWriter::default();
        writer.number(0);
        writer.number(1);
        assert_eq!(
            programs.parse(0x20, &writer.bytes, 0, 100),
            Err(Error::ResourceLimit)
        );
    }

    #[test]
    fn delta_reconstructs_interleaved_channels() {
        let mut bytes = [1, 2, 3, 4, 5, 6];
        let mut scratch = [0; 6];
        let mut registers = [0; 8];
        registers[0] = 2;
        registers[4] = 6;

        apply(
            Program::standard(FilterKind::Delta),
            registers,
            &mut bytes,
            0,
            &mut scratch,
        )
        .unwrap();

        assert_eq!(bytes, [255, 252, 253, 247, 250, 241]);
    }

    #[test]
    fn e8_and_e8e9_use_the_rar3_sixteen_mib_address_window() {
        let mut e8 = [0xe8, 0xff, 0xff, 0xff, 0xff, 0xe9, 8, 0, 0, 0];
        let mut registers = [0; 8];
        registers[4] = 10;
        apply(
            Program::standard(FilterKind::E8),
            registers,
            &mut e8,
            10,
            &mut [],
        )
        .unwrap();
        assert_eq!(&e8[1..5], &0x00ff_ffff_u32.to_le_bytes());
        assert_eq!(&e8[6..10], &8_u32.to_le_bytes());

        let mut e8e9 = [0xe9, 8, 0, 0, 0];
        registers[4] = 5;
        apply(
            Program::standard(FilterKind::E8E9),
            registers,
            &mut e8e9,
            2,
            &mut [],
        )
        .unwrap();
        assert_eq!(&e8e9[1..5], &5_u32.to_le_bytes());
    }

    #[test]
    fn rgb_reconstructs_three_planes_and_green_correlation() {
        let mut bytes = [1, 2, 3, 4, 5, 6];
        let mut scratch = [0; 6];
        let mut registers = [0; 8];
        registers[0] = 3;
        registers[1] = 0;
        registers[4] = 6;

        apply(
            Program::standard(FilterKind::Rgb),
            registers,
            &mut bytes,
            0,
            &mut scratch,
        )
        .unwrap();

        assert_eq!(bytes, [252, 253, 248, 250, 252, 246]);
    }

    #[test]
    fn audio_reconstructs_a_single_channel_predictor() {
        let mut bytes = [1, 2, 3, 4];
        let mut scratch = [0; 4];
        let mut registers = [0; 8];
        registers[0] = 1;
        registers[4] = 4;

        apply(
            Program::standard(FilterKind::Audio),
            registers,
            &mut bytes,
            0,
            &mut scratch,
        )
        .unwrap();

        assert_eq!(bytes, [255, 253, 250, 246]);
    }

    #[test]
    fn invalid_registers_and_short_scratch_are_rejected() {
        let mut bytes = [1, 2, 3];
        let mut registers = [0; 8];
        registers[0] = 1;
        registers[4] = 3;
        assert_eq!(
            apply(
                Program::standard(FilterKind::Delta),
                registers,
                &mut bytes,
                0,
                &mut [0; 2],
            ),
            Err(Error::ScratchTooSmall)
        );

        registers[0] = 4;
        assert_eq!(
            apply(
                Program::standard(FilterKind::Audio),
                registers,
                &mut bytes,
                0,
                &mut [0; 3],
            ),
            Err(Error::InvalidRegisters)
        );

        registers[0] = 1;
        registers[4] = 4;
        assert_eq!(
            apply(
                Program::standard(FilterKind::Delta),
                registers,
                &mut bytes,
                0,
                &mut [0; 3],
            ),
            Err(Error::InvalidRegisters)
        );
    }
}
