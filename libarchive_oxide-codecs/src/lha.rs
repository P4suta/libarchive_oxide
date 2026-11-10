// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded caller-driven adapters for rare LHA payload methods.

use alloc::vec::Vec;
use core::fmt;

use compcol::Algorithm;
use compcol::lha::{DecoderConfig, Lh2};
use libarchive_oxide_protocol::{
    ArchiveError, Codec, CodecStatus, CodecStep, EndOfInput, ErrorKind, Limits,
};

use crate::compcol_adapter::Adapter;

/// The LHA `-lh2-` sliding dictionary.
pub const LH2_DICTIONARY_BYTES: usize = 8 * 1024;
/// Conservative allowance for adaptive literal and position trees.
const LH2_TREE_BYTES: usize = 64 * 1024;
/// The LHA `-lh3-` sliding dictionary.
pub const LH3_DICTIONARY_BYTES: usize = 8 * 1024;
/// Conservative allowance for both canonical trees and their construction.
const LH3_TREE_BYTES: usize = 64 * 1024;

/// Bounded read-only LHA `-lh2-` payload decoder.
pub struct Lh2Decoder {
    inner: Adapter<compcol::lha::Decoder>,
}

impl Lh2Decoder {
    /// Creates a decoder after preflighting whole-payload buffering.
    pub fn new(
        packed_size: u64,
        unpacked_size: u64,
        input_window: usize,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        const FORMAT: &str = "lha";
        if input_window == 0 {
            return Err(ArchiveError::new(ErrorKind::Protocol)
                .with_format(FORMAT)
                .with_context("LHA payload input window must be non-zero"));
        }
        if limits
            .entry_bytes()
            .is_some_and(|maximum| unpacked_size > maximum)
            || limits
                .decoded_total()
                .is_some_and(|maximum| unpacked_size > maximum)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format(FORMAT)
                .with_context("LHA -lh2- payload exceeds the decoded-byte budget"));
        }
        let packed = usize::try_from(packed_size).map_err(|_| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format(FORMAT)
                .with_context("LHA -lh2- packed size exceeds the address space")
        })?;
        let unpacked = usize::try_from(unpacked_size).map_err(|_| {
            ArchiveError::new(ErrorKind::Limit)
                .with_format(FORMAT)
                .with_context("LHA -lh2- unpacked size exceeds the address space")
        })?;
        let in_flight = packed
            .checked_add(unpacked)
            .and_then(|value| value.checked_add(input_window))
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format(FORMAT)
                    .with_context("LHA -lh2- buffered payload size overflowed")
            })?;
        if limits
            .in_flight_bytes()
            .is_some_and(|maximum| in_flight > maximum)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format(FORMAT)
                .with_context("LHA -lh2- whole-payload buffers exceed the in-flight budget"));
        }
        // The decoder buffers packed input and decoded output.
        // Vec growth can temporarily approach twice the packed length, so charge that plus the dictionary, adaptive trees, and caller-side input window.
        let workspace = packed
            .checked_mul(2)
            .and_then(|value| value.checked_add(unpacked))
            .and_then(|value| value.checked_add(input_window))
            .and_then(|value| value.checked_add(LH2_DICTIONARY_BYTES))
            .and_then(|value| value.checked_add(LH2_TREE_BYTES))
            .ok_or_else(|| {
                ArchiveError::new(ErrorKind::Limit)
                    .with_format(FORMAT)
                    .with_context("LHA -lh2- codec-memory estimate overflowed")
            })?;
        if limits
            .codec_memory()
            .is_some_and(|maximum| workspace > maximum)
        {
            return Err(ArchiveError::new(ErrorKind::Limit)
                .with_format(FORMAT)
                .with_context("LHA -lh2- decoder exceeds the codec-memory budget"));
        }
        Ok(Self {
            inner: Adapter::new(
                Lh2::decoder_with(DecoderConfig::with_len(unpacked)),
                FORMAT,
                packed_size,
                unpacked_size,
            ),
        })
    }
}

impl fmt::Debug for Lh2Decoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Lh2Decoder")
            .field("terminal", &self.inner.terminal_name())
            .field("packed_bytes", &self.inner.consumed_bytes())
            .field("decoded_bytes", &self.inner.decoded_bytes())
            .finish_non_exhaustive()
    }
}

impl Codec for Lh2Decoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        self.inner.process(input, output, end)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lh3State {
    Collecting,
    Draining,
    Done,
    Failed,
}

/// Bounded read-only LHA `-lh3-` payload decoder.
///
/// LH3 describes each block with canonical literal/length and distance trees,
/// then decodes LZ matches against an 8 KiB history.
/// The format has no payload terminator independent of the member header, so this adapter collects the exact declared packed extent and decodes exactly the declared output size.
pub struct Lh3Decoder {
    packed: Vec<u8>,
    decoded: Vec<u8>,
    output_position: usize,
    expected_packed: usize,
    expected_unpacked: usize,
    state: Lh3State,
}

impl Lh3Decoder {
    /// Creates a decoder after preflighting whole-payload and tree buffering.
    pub fn new(
        packed_size: u64,
        unpacked_size: u64,
        input_window: usize,
        limits: Limits,
    ) -> Result<Self, ArchiveError> {
        if input_window == 0 {
            return Err(lh3_error(
                ErrorKind::Protocol,
                "LHA payload input window must be non-zero",
            ));
        }
        if limits
            .entry_bytes()
            .is_some_and(|maximum| unpacked_size > maximum)
            || limits
                .decoded_total()
                .is_some_and(|maximum| unpacked_size > maximum)
        {
            return Err(lh3_error(
                ErrorKind::Limit,
                "LHA -lh3- payload exceeds the decoded-byte budget",
            ));
        }
        let packed = usize::try_from(packed_size).map_err(|_| {
            lh3_error(
                ErrorKind::Limit,
                "LHA -lh3- packed size exceeds the address space",
            )
        })?;
        let unpacked = usize::try_from(unpacked_size).map_err(|_| {
            lh3_error(
                ErrorKind::Limit,
                "LHA -lh3- unpacked size exceeds the address space",
            )
        })?;
        let buffered = packed
            .checked_add(unpacked)
            .and_then(|value| value.checked_add(input_window))
            .ok_or_else(|| {
                lh3_error(
                    ErrorKind::Limit,
                    "LHA -lh3- buffered payload size overflowed",
                )
            })?;
        if limits
            .in_flight_bytes()
            .is_some_and(|maximum| buffered > maximum)
        {
            return Err(lh3_error(
                ErrorKind::Limit,
                "LHA -lh3- whole-payload buffers exceed the in-flight budget",
            ));
        }
        let workspace = buffered
            .checked_add(LH3_DICTIONARY_BYTES)
            .and_then(|value| value.checked_add(LH3_TREE_BYTES))
            .ok_or_else(|| {
                lh3_error(
                    ErrorKind::Limit,
                    "LHA -lh3- codec-memory estimate overflowed",
                )
            })?;
        if limits
            .codec_memory()
            .is_some_and(|maximum| workspace > maximum)
        {
            return Err(lh3_error(
                ErrorKind::Limit,
                "LHA -lh3- decoder exceeds the codec-memory budget",
            ));
        }

        let mut packed_buffer = Vec::new();
        packed_buffer.try_reserve_exact(packed).map_err(|_| {
            lh3_error(
                ErrorKind::Limit,
                "LHA -lh3- packed buffer allocation failed",
            )
        })?;
        Ok(Self {
            packed: packed_buffer,
            decoded: Vec::new(),
            output_position: 0,
            expected_packed: packed,
            expected_unpacked: unpacked,
            state: Lh3State::Collecting,
        })
    }

    fn drain(&mut self, output: &mut [u8], consumed: usize) -> CodecStep {
        let remaining = self.decoded.len().saturating_sub(self.output_position);
        let produced = remaining.min(output.len());
        output[..produced]
            .copy_from_slice(&self.decoded[self.output_position..self.output_position + produced]);
        self.output_position += produced;
        let status = if self.output_position == self.decoded.len() {
            self.state = Lh3State::Done;
            CodecStatus::Done
        } else {
            CodecStatus::NeedOutput
        };
        CodecStep {
            consumed,
            produced,
            status,
        }
    }
}

impl fmt::Debug for Lh3Decoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Lh3Decoder")
            .field("state", &self.state)
            .field("packed_bytes", &self.packed.len())
            .field("decoded_bytes", &self.decoded.len())
            .field("output_position", &self.output_position)
            .finish_non_exhaustive()
    }
}

impl Codec for Lh3Decoder {
    fn process(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        match self.state {
            Lh3State::Done if input.is_empty() => {
                return Ok(CodecStep {
                    consumed: 0,
                    produced: 0,
                    status: CodecStatus::Done,
                });
            },
            Lh3State::Done => {
                return Err(lh3_error(
                    ErrorKind::Protocol,
                    "input supplied after LHA -lh3- payload completion",
                ));
            },
            Lh3State::Failed => {
                return Err(lh3_error(
                    ErrorKind::Protocol,
                    "LHA -lh3- decoder reused after failure",
                ));
            },
            Lh3State::Draining if !input.is_empty() => {
                self.state = Lh3State::Failed;
                return Err(lh3_error(
                    ErrorKind::Protocol,
                    "input supplied after LHA -lh3- finalization started",
                ));
            },
            Lh3State::Draining => return Ok(self.drain(output, 0)),
            Lh3State::Collecting => {},
        }

        let supplied =
            self.packed.len().checked_add(input.len()).ok_or_else(|| {
                lh3_error(ErrorKind::Limit, "LHA -lh3- packed byte count overflowed")
            })?;
        if supplied > self.expected_packed {
            self.state = Lh3State::Failed;
            return Err(lh3_error(
                ErrorKind::Malformed,
                "LHA -lh3- payload exceeds its declared packed size",
            ));
        }
        if matches!(end, EndOfInput::End) && supplied != self.expected_packed {
            self.state = Lh3State::Failed;
            return Err(lh3_error(
                ErrorKind::Malformed,
                "LHA -lh3- payload is truncated",
            ));
        }
        self.packed.extend_from_slice(input);
        let consumed = input.len();
        if !matches!(end, EndOfInput::End) {
            return Ok(CodecStep {
                consumed,
                produced: 0,
                status: CodecStatus::NeedInput,
            });
        }

        self.decoded = match decode_lh3(&self.packed, self.expected_unpacked) {
            Ok(decoded) => decoded,
            Err(error) => {
                self.state = Lh3State::Failed;
                return Err(error);
            },
        };
        self.state = Lh3State::Draining;
        Ok(self.drain(output, consumed))
    }
}

fn lh3_error(kind: ErrorKind, context: &'static str) -> ArchiveError {
    ArchiveError::new(kind)
        .with_format("lha")
        .with_context(context)
}

struct MsbBits<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> MsbBits<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read(&mut self, count: usize) -> Result<u32, ArchiveError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| lh3_error(ErrorKind::Malformed, "LHA -lh3- bit offset overflowed"))?;
        let available = self
            .bytes
            .len()
            .checked_mul(8)
            .ok_or_else(|| lh3_error(ErrorKind::Limit, "LHA -lh3- bit length overflowed"))?;
        if count > 32 || end > available {
            return Err(lh3_error(
                ErrorKind::Malformed,
                "LHA -lh3- payload ended inside a coded value",
            ));
        }
        let mut value = 0_u32;
        while self.position < end {
            let byte = self.bytes[self.position / 8];
            let shift = 7 - (self.position % 8);
            value = (value << 1) | u32::from((byte >> shift) & 1);
            self.position += 1;
        }
        Ok(value)
    }

    fn bit(&mut self) -> Result<u32, ArchiveError> {
        self.read(1)
    }
}

#[derive(Clone, Copy)]
struct HuffmanNode {
    children: [u16; 2],
    symbol: u16,
}

impl HuffmanNode {
    const ABSENT: u16 = u16::MAX;
    const EMPTY: Self = Self {
        children: [Self::ABSENT; 2],
        symbol: Self::ABSENT,
    };
}

struct CanonicalTree {
    nodes: Vec<HuffmanNode>,
}

impl CanonicalTree {
    fn from_lengths(lengths: &[u8]) -> Result<Self, ArchiveError> {
        let mut counts = [0_u32; 17];
        let mut symbols = 0_usize;
        for &length in lengths {
            let index = usize::from(length);
            if index >= counts.len() {
                return Err(lh3_error(
                    ErrorKind::Malformed,
                    "LHA -lh3- Huffman code length exceeds 16 bits",
                ));
            }
            if index != 0 {
                counts[index] += 1;
                symbols += 1;
            }
        }
        if symbols == 0 {
            return Err(lh3_error(
                ErrorKind::Malformed,
                "LHA -lh3- Huffman table has no symbols",
            ));
        }
        let mut available = 1_u32;
        for &count in &counts[1..] {
            available = available.checked_mul(2).ok_or_else(|| {
                lh3_error(ErrorKind::Malformed, "LHA -lh3- Huffman tree overflowed")
            })?;
            if count > available {
                return Err(lh3_error(
                    ErrorKind::Malformed,
                    "LHA -lh3- Huffman table is oversubscribed",
                ));
            }
            available -= count;
        }

        let mut next_code = [0_u32; 17];
        let mut code = 0_u32;
        for depth in 1..=16 {
            code = code
                .checked_add(counts[depth - 1])
                .and_then(|value| value.checked_mul(2))
                .ok_or_else(|| {
                    lh3_error(ErrorKind::Malformed, "LHA -lh3- canonical code overflowed")
                })?;
            next_code[depth] = code;
        }

        let node_capacity = symbols
            .checked_mul(17)
            .ok_or_else(|| lh3_error(ErrorKind::Limit, "LHA -lh3- Huffman workspace overflowed"))?;
        let mut nodes = Vec::new();
        nodes.try_reserve_exact(node_capacity).map_err(|_| {
            lh3_error(
                ErrorKind::Limit,
                "LHA -lh3- Huffman workspace allocation failed",
            )
        })?;
        nodes.push(HuffmanNode::EMPTY);
        for (symbol, &length) in lengths.iter().enumerate() {
            if length == 0 {
                continue;
            }
            let depth = usize::from(length);
            let symbol_code = next_code[depth];
            next_code[depth] += 1;
            let mut node = 0_usize;
            for bit_index in (0..depth).rev() {
                if nodes[node].symbol != HuffmanNode::ABSENT {
                    return Err(lh3_error(
                        ErrorKind::Malformed,
                        "LHA -lh3- Huffman code extends an existing symbol",
                    ));
                }
                let branch = usize::from(((symbol_code >> bit_index) & 1) != 0);
                node = if nodes[node].children[branch] == HuffmanNode::ABSENT {
                    let child = nodes.len();
                    let compact_child = u16::try_from(child).map_err(|_| {
                        lh3_error(ErrorKind::Limit, "LHA -lh3- Huffman node index exceeds u16")
                    })?;
                    nodes.push(HuffmanNode::EMPTY);
                    nodes[node].children[branch] = compact_child;
                    child
                } else {
                    usize::from(nodes[node].children[branch])
                };
            }
            if nodes[node].symbol != HuffmanNode::ABSENT
                || nodes[node].children != [HuffmanNode::ABSENT; 2]
            {
                return Err(lh3_error(
                    ErrorKind::Malformed,
                    "LHA -lh3- Huffman code conflicts with another symbol",
                ));
            }
            nodes[node].symbol = u16::try_from(symbol)
                .map_err(|_| lh3_error(ErrorKind::Limit, "LHA -lh3- symbol index exceeds u16"))?;
        }
        Ok(Self { nodes })
    }

    fn decode(&self, bits: &mut MsbBits<'_>) -> Result<u16, ArchiveError> {
        let mut node = 0_usize;
        for _ in 0..16 {
            let branch = usize::from(bits.bit()? != 0);
            let child = self.nodes[node].children[branch];
            if child == HuffmanNode::ABSENT {
                return Err(lh3_error(
                    ErrorKind::Malformed,
                    "LHA -lh3- bit sequence is absent from the Huffman table",
                ));
            }
            node = usize::from(child);
            let symbol = self.nodes[node].symbol;
            if symbol != HuffmanNode::ABSENT {
                return Ok(symbol);
            }
        }
        Err(lh3_error(
            ErrorKind::Malformed,
            "LHA -lh3- Huffman code exceeds 16 bits",
        ))
    }
}

enum SymbolDecoder {
    Constant(u16),
    Tree(CanonicalTree),
}

impl SymbolDecoder {
    fn decode(&self, bits: &mut MsbBits<'_>) -> Result<u16, ArchiveError> {
        match self {
            Self::Constant(symbol) => Ok(*symbol),
            Self::Tree(tree) => tree.decode(bits),
        }
    }
}

fn read_literal_tree(bits: &mut MsbBits<'_>) -> Result<SymbolDecoder, ArchiveError> {
    let mut lengths = [0_u8; 286];
    let mut one_count = 0_u8;
    for (index, length) in lengths.iter_mut().enumerate() {
        if bits.bit()? != 0 {
            *length = u8::try_from(bits.read(4)? + 1).map_err(|_| {
                lh3_error(
                    ErrorKind::Malformed,
                    "LHA -lh3- literal code length overflowed",
                )
            })?;
        }
        if *length == 1 {
            one_count += 1;
        }
        if index == 2 && one_count == 3 {
            let symbol = u16::try_from(bits.read(9)?).map_err(|_| {
                lh3_error(ErrorKind::Malformed, "LHA -lh3- literal symbol overflowed")
            })?;
            if usize::from(symbol) >= lengths.len() {
                return Err(lh3_error(
                    ErrorKind::Malformed,
                    "LHA -lh3- constant literal symbol is out of range",
                ));
            }
            return Ok(SymbolDecoder::Constant(symbol));
        }
    }
    CanonicalTree::from_lengths(&lengths).map(SymbolDecoder::Tree)
}

const LH3_DISTANCE_LENGTHS: [u8; 128] = [
    2, 4, 4, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
];

fn read_distance_tree(bits: &mut MsbBits<'_>) -> Result<SymbolDecoder, ArchiveError> {
    if bits.bit()? == 0 {
        return CanonicalTree::from_lengths(&LH3_DISTANCE_LENGTHS).map(SymbolDecoder::Tree);
    }
    let mut lengths = [0_u8; 128];
    let mut one_count = 0_u8;
    for (index, length) in lengths.iter_mut().enumerate() {
        *length = u8::try_from(bits.read(4)?).map_err(|_| {
            lh3_error(
                ErrorKind::Malformed,
                "LHA -lh3- distance code length overflowed",
            )
        })?;
        if *length == 1 {
            one_count += 1;
        }
        if index == 2 && one_count == 3 {
            let symbol = u16::try_from(bits.read(9)?).map_err(|_| {
                lh3_error(ErrorKind::Malformed, "LHA -lh3- distance symbol overflowed")
            })?;
            if usize::from(symbol) >= lengths.len() {
                return Err(lh3_error(
                    ErrorKind::Malformed,
                    "LHA -lh3- constant distance symbol is out of range",
                ));
            }
            return Ok(SymbolDecoder::Constant(symbol));
        }
    }
    CanonicalTree::from_lengths(&lengths).map(SymbolDecoder::Tree)
}

fn decode_lh3(packed: &[u8], expected: usize) -> Result<Vec<u8>, ArchiveError> {
    let mut output = Vec::new();
    output.try_reserve_exact(expected).map_err(|_| {
        lh3_error(
            ErrorKind::Limit,
            "LHA -lh3- output buffer allocation failed",
        )
    })?;
    let mut bits = MsbBits::new(packed);
    let mut block_remaining = 0_u32;
    let mut literals = SymbolDecoder::Constant(0);
    let mut distances = SymbolDecoder::Constant(0);

    while output.len() < expected {
        if block_remaining == 0 {
            block_remaining = bits.read(16)?;
            if block_remaining == 0 {
                block_remaining = 0x1_0000;
            }
            literals = read_literal_tree(&mut bits)?;
            distances = read_distance_tree(&mut bits)?;
        }
        block_remaining -= 1;
        let mut symbol = u32::from(literals.decode(&mut bits)?);
        if symbol < 256 {
            output.push(u8::try_from(symbol).map_err(|_| {
                lh3_error(ErrorKind::Malformed, "LHA -lh3- literal byte overflowed")
            })?);
            continue;
        }
        if symbol == 285 {
            symbol = symbol.checked_add(bits.read(8)?).ok_or_else(|| {
                lh3_error(ErrorKind::Malformed, "LHA -lh3- match length overflowed")
            })?;
        }
        if !(256..=540).contains(&symbol) {
            return Err(lh3_error(
                ErrorKind::Malformed,
                "LHA -lh3- literal/length symbol is out of range",
            ));
        }
        let count = usize::try_from(symbol - 253)
            .map_err(|_| lh3_error(ErrorKind::Limit, "LHA -lh3- match length exceeds usize"))?;
        let distance_high = usize::from(distances.decode(&mut bits)?);
        let distance_low = usize::try_from(bits.read(6)?)
            .map_err(|_| lh3_error(ErrorKind::Limit, "LHA -lh3- match distance exceeds usize"))?;
        let distance = distance_high
            .checked_mul(64)
            .and_then(|value| value.checked_add(distance_low))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                lh3_error(ErrorKind::Malformed, "LHA -lh3- match distance overflowed")
            })?;
        if distance > LH3_DICTIONARY_BYTES {
            return Err(lh3_error(
                ErrorKind::Malformed,
                "LHA -lh3- match exceeds the 8 KiB dictionary",
            ));
        }
        let end = output
            .len()
            .checked_add(count)
            .ok_or_else(|| lh3_error(ErrorKind::Limit, "LHA -lh3- output length overflowed"))?;
        if end > expected {
            return Err(lh3_error(
                ErrorKind::Malformed,
                "LHA -lh3- match exceeds the declared output size",
            ));
        }
        while output.len() < end {
            let byte = output
                .len()
                .checked_sub(distance)
                .map_or(0x20, |source| output[source]);
            output.push(byte);
        }
    }
    Ok(output)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use alloc::{vec, vec::Vec};

    use compcol::lha::Lh2;
    use compcol::{Algorithm, Encoder, Status};
    use libarchive_oxide_protocol::{ErrorKind, Limits};

    use super::{CanonicalTree, Lh2Decoder, Lh3Decoder};
    use crate::test_support::{drive_codec, try_drive_codec};

    fn encode_lh2(plain: &[u8]) -> Vec<u8> {
        let mut encoder = Lh2::encoder();
        let mut empty = [];
        let (progress, status) = encoder.encode(plain, &mut empty).expect("encode LH2 input");
        assert_eq!(progress.consumed, plain.len());
        assert_eq!(status, Status::InputEmpty);
        let mut compressed = Vec::new();
        let mut output = vec![0_u8; 257];
        loop {
            let (progress, status) = encoder.finish(&mut output).expect("finish LH2 fixture");
            compressed.extend_from_slice(&output[..progress.written]);
            if status == Status::StreamEnd {
                break;
            }
        }
        compressed
    }

    #[test]
    fn lh2_round_trip_is_chunk_invariant() {
        let plain = b"LH2 adaptive Huffman payload ".repeat(40);
        let packed = encode_lh2(&plain);
        for (input_chunk, output_chunk) in [(1, 1), (7, 3), (4096, 257)] {
            let decoded = drive_codec(
                Lh2Decoder::new(
                    packed.len() as u64,
                    plain.len() as u64,
                    8 * 1024,
                    Limits::safe(),
                )
                .expect("bounded LH2 decoder"),
                &packed,
                input_chunk,
                output_chunk,
            );
            assert_eq!(decoded, plain);
        }
    }

    #[test]
    fn lh2_preflights_buffering_before_allocation() {
        let plain = b"bounded LH2".repeat(32);
        let packed = encode_lh2(&plain);
        let buffered = packed.len() + plain.len() + 8 * 1024;
        let error = Lh2Decoder::new(
            packed.len() as u64,
            plain.len() as u64,
            8 * 1024,
            Limits::safe().with_in_flight_bytes(Some(buffered - 1)),
        )
        .expect_err("LH2 whole-payload buffers exceed in-flight limit");
        assert_eq!(error.kind(), ErrorKind::Limit);

        let workspace = packed.len() * 2
            + plain.len()
            + 8 * 1024
            + super::LH2_DICTIONARY_BYTES
            + super::LH2_TREE_BYTES;
        let error = Lh2Decoder::new(
            packed.len() as u64,
            plain.len() as u64,
            8 * 1024,
            Limits::safe().with_codec_memory(Some(workspace - 1)),
        )
        .expect_err("LH2 decoder workspace exceeds codec-memory limit");
        assert_eq!(error.kind(), ErrorKind::Limit);
        Lh2Decoder::new(
            packed.len() as u64,
            plain.len() as u64,
            8 * 1024,
            Limits::safe().with_codec_memory(Some(workspace)),
        )
        .expect("exact LH2 codec-memory bound");
    }

    #[test]
    fn lh2_truncation_and_declared_size_mismatch_fail_closed() {
        let plain = b"truncated LH2 payload".repeat(20);
        let packed = encode_lh2(&plain);
        let truncated = try_drive_codec(
            Lh2Decoder::new(
                (packed.len() - 1) as u64,
                plain.len() as u64,
                8 * 1024,
                Limits::safe(),
            )
            .expect("bounded truncated LH2 decoder"),
            &packed[..packed.len() - 1],
            5,
            13,
        )
        .expect_err("truncated LH2 payload");
        assert!(matches!(
            truncated.kind(),
            ErrorKind::Malformed | ErrorKind::Integrity
        ));

        let mismatch = try_drive_codec(
            Lh2Decoder::new(
                packed.len() as u64,
                (plain.len() + 1) as u64,
                8 * 1024,
                Limits::safe(),
            )
            .expect("bounded wrong-size LH2 decoder"),
            &packed,
            packed.len(),
            1024,
        )
        .expect_err("declared LH2 output size mismatch");
        assert!(matches!(
            mismatch.kind(),
            ErrorKind::Malformed | ErrorKind::Integrity
        ));
    }

    const LH3_CANONICAL_MATCH: &[u8] = &[
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x8f, 0x80, 0x00,
    ];

    #[test]
    fn lh3_canonical_tree_and_match_are_chunk_invariant() {
        let expected = vec![b'A'; 64];
        for (input_chunk, output_chunk) in [(1, 1), (7, 3), (4096, 257)] {
            let decoded = drive_codec(
                Lh3Decoder::new(
                    LH3_CANONICAL_MATCH.len() as u64,
                    expected.len() as u64,
                    8 * 1024,
                    Limits::safe(),
                )
                .expect("bounded LH3 decoder"),
                LH3_CANONICAL_MATCH,
                input_chunk,
                output_chunk,
            );
            assert_eq!(decoded, expected);
        }
    }

    #[test]
    fn lh3_preflights_buffering_before_allocation() {
        assert_eq!(core::mem::size_of::<super::HuffmanNode>(), 6);
        let buffered = LH3_CANONICAL_MATCH.len() + 64 + 8 * 1024;
        let error = Lh3Decoder::new(
            LH3_CANONICAL_MATCH.len() as u64,
            64,
            8 * 1024,
            Limits::safe().with_in_flight_bytes(Some(buffered - 1)),
        )
        .expect_err("LH3 whole-payload buffers exceed in-flight limit");
        assert_eq!(error.kind(), ErrorKind::Limit);

        let workspace = buffered + super::LH3_DICTIONARY_BYTES + super::LH3_TREE_BYTES;
        let error = Lh3Decoder::new(
            LH3_CANONICAL_MATCH.len() as u64,
            64,
            8 * 1024,
            Limits::safe().with_codec_memory(Some(workspace - 1)),
        )
        .expect_err("LH3 decoder workspace exceeds codec-memory limit");
        assert_eq!(error.kind(), ErrorKind::Limit);
        Lh3Decoder::new(
            LH3_CANONICAL_MATCH.len() as u64,
            64,
            8 * 1024,
            Limits::safe().with_codec_memory(Some(workspace)),
        )
        .expect("exact LH3 codec-memory bound");
    }

    #[test]
    fn lh3_truncation_size_mismatch_and_invalid_tree_fail_closed() {
        let truncated = try_drive_codec(
            Lh3Decoder::new(
                (LH3_CANONICAL_MATCH.len() - 1) as u64,
                64,
                8 * 1024,
                Limits::safe(),
            )
            .expect("bounded truncated LH3 decoder"),
            &LH3_CANONICAL_MATCH[..LH3_CANONICAL_MATCH.len() - 1],
            5,
            13,
        )
        .expect_err("truncated LH3 payload");
        assert_eq!(truncated.kind(), ErrorKind::Malformed);

        let mismatch = try_drive_codec(
            Lh3Decoder::new(
                LH3_CANONICAL_MATCH.len() as u64,
                65,
                8 * 1024,
                Limits::safe(),
            )
            .expect("bounded wrong-size LH3 decoder"),
            LH3_CANONICAL_MATCH,
            LH3_CANONICAL_MATCH.len(),
            1024,
        )
        .expect_err("declared LH3 output size mismatch");
        assert_eq!(mismatch.kind(), ErrorKind::Malformed);

        let invalid = CanonicalTree::from_lengths(&[1, 1, 1])
            .err()
            .expect("oversubscribed canonical tree");
        assert_eq!(invalid.kind(), ErrorKind::Malformed);
    }
}
