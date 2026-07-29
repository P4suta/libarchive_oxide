// SPDX-FileCopyrightText: 2020 Lonami
// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::vec::Vec;

use super::{Bitstream, DecodeFailed, DecoderState, Tree};

// if position_slot < 4 {
//     0
// } else if position_slot >= 36 {
//     17
// } else {
//     (position_slot - 2) / 2
// }
const FOOTER_BITS: [u8; 50] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
];

// if position_slot == 0 {
//     0
// } else {
//     BASE_POSITION[position_slot - 1] + (1 << FOOTER_BITS[position_slot - 1])
// }
// This table is copied verbatim from the LZX position-slot definition; decimal
// values make comparison with the specification and upstream fork practical.
#[allow(clippy::unreadable_literal)]
const BASE_POSITION: [u32; 50] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 393216, 524288, 655360, 786432, 917504, 1048576, 1179648, 1310720, 1441792, 1572864,
    1703936, 1835008, 1966080,
];

// These names intentionally mirror the three independently encoded LZX trees.
#[allow(clippy::struct_field_names)]
struct DecodeInfo<'a> {
    aligned_offset_tree: Option<&'a Tree>,
    main_tree: &'a Tree,
    length_tree: Option<&'a Tree>,
}

#[derive(Debug)]
pub(crate) enum Decoded {
    Single(u8),
    Match { offset: usize, length: usize },
    Read(usize),
}

#[derive(Debug)]
pub(crate) enum Kind {
    Verbatim {
        main_tree: Tree,
        length_tree: Option<Tree>,
    },
    AlignedOffset {
        aligned_offset_tree: Tree,
        main_tree: Tree,
        length_tree: Option<Tree>,
    },
    Uncompressed {
        r: [u32; 3],
    },
}

/// Note that this is not the block header, but the head of the block's body, which includes
/// everything except the tail of the block data (either uncompressed data or token sequence).
#[derive(Debug)]
pub(crate) struct Block {
    /// Only 24 bits may be used.
    pub remaining: u32,
    pub size: u32,
    pub kind: Kind,
}

/// Read the pretrees for the main and length tree, and with those also read the trees
/// themselves, using the path lengths from a previous tree if any.
///
/// This is used when reading a verbatim or aligned block.
fn read_main_and_length_trees(
    bitstream: &mut Bitstream,
    state: &mut DecoderState,
) -> Result<(), DecodeFailed> {
    // Verbatim block
    // Entry                                             Comments
    // Pretree for first 256 elements of main tree       20 elements, 4 bits each
    // Path lengths of first 256 elements of main tree   Encoded using pretree
    // Pretree for remainder of main tree                20 elements, 4 bits each
    // Path lengths of remaining elements of main tree   Encoded using pretree
    // Pretree for length tree                           20 elements, 4 bits each
    // Path lengths of elements in length tree           Encoded using pretree
    // Token sequence (matches and literals)             Specified in section 2.6

    state
        .main_tree
        .update_range_with_pretree(bitstream, 0..256)?;

    state
        .main_tree
        .update_range_with_pretree(bitstream, 256..256 + 8 * state.window_size.position_slots())?;

    state
        .length_tree
        .update_range_with_pretree(bitstream, 0..249)?;

    Ok(())
}

fn decode_element(
    bitstream: &mut Bitstream,
    r: &mut [u32; 3],
    DecodeInfo {
        aligned_offset_tree,
        main_tree,
        length_tree,
    }: DecodeInfo,
) -> Result<Decoded, DecodeFailed> {
    // Decoding Matches and Literals (Aligned and Verbatim Blocks)
    let main_element = main_tree.decode_element(bitstream)?;

    // Check if it is a literal character.
    Ok(if main_element < 256 {
        // It is a literal, so copy the literal to output.
        Decoded::Single(u8::try_from(main_element).map_err(|_| DecodeFailed::ArithmeticOverflow)?)
    } else {
        // Decode the match. For a match, there are two components, offset and length.
        let length_header = (main_element - 256) & 7;

        let match_length = if length_header == 7 {
            // Length of the footer.
            length_tree
                .ok_or(DecodeFailed::EmptyTree)?
                .decode_element(bitstream)?
                + 7
                + 2
        } else {
            length_header + 2 // no length footer
            // Decoding a match length (if a match length < 257).
        };
        if match_length == 0 {
            return Err(DecodeFailed::ZeroProgress);
        }

        let position_slot = (main_element - 256) >> 3;

        // Check for repeated offsets (positions 0, 1, 2).
        let match_offset;
        if position_slot == 0 {
            match_offset = r[0];
        } else if position_slot == 1 {
            match_offset = r[1];
            r.swap(0, 1);
        } else if position_slot == 2 {
            match_offset = r[2];
            r.swap(0, 2);
        } else {
            // Not a repeated offset.
            let position_slot_index = usize::from(position_slot);
            let offset_bits = FOOTER_BITS
                .get(position_slot_index)
                .copied()
                .ok_or(DecodeFailed::InvalidPositionSlot(position_slot))?;
            let base_position = BASE_POSITION
                .get(position_slot_index)
                .copied()
                .ok_or(DecodeFailed::InvalidPositionSlot(position_slot))?;

            let formatted_offset = if let Some(aligned_offset_tree) = aligned_offset_tree.as_ref() {
                let verbatim_bits;
                let aligned_bits;

                // This means there are some aligned bits.
                if offset_bits >= 3 {
                    verbatim_bits = bitstream.read_bits(offset_bits - 3)? << 3;
                    aligned_bits = aligned_offset_tree.decode_element(bitstream)?;
                } else {
                    // 0, 1, or 2 verbatim bits
                    verbatim_bits = bitstream.read_bits(offset_bits)?;
                    aligned_bits = 0;
                }

                base_position
                    .checked_add(verbatim_bits)
                    .and_then(|value| value.checked_add(u32::from(aligned_bits)))
                    .ok_or(DecodeFailed::ArithmeticOverflow)?
            } else {
                // Block_type is a verbatim_block.
                let verbatim_bits = bitstream.read_bits(offset_bits)?;
                base_position
                    .checked_add(verbatim_bits)
                    .ok_or(DecodeFailed::ArithmeticOverflow)?
            };

            // Decoding a match offset.
            match_offset = formatted_offset
                .checked_sub(2)
                .ok_or(DecodeFailed::InvalidMatchOffset(0))?;
            if match_offset == 0 {
                return Err(DecodeFailed::InvalidMatchOffset(0));
            }

            // Update repeated offset least recently used queue.
            r[2] = r[1];
            r[1] = r[0];
            r[0] = match_offset;
        }

        // Check for extra length.
        // > If the match length is 257 or larger, the encoded match length token
        // > (or match length, as specified in section 2.6) value is 257, and an
        // > encoded Extra Length field follows the other match encoding components,
        // > as specified in section 2.6.7, in the bitstream.

        // TODO for some reason, if we do this, parsing .xnb files with window size
        //      64KB, it breaks and stops decompressing correctly, but no idea why.
        /*
        let match_length = if match_length == 257 {
            // Decode the extra length.
            let extra_len = if bitstream.read_bit() != 0 {
                if bitstream.read_bit() != 0 {
                    if bitstream.read_bit() != 0 {
                        // > Prefix 0b111; Number of bits to decode 15;
                        bitstream.read_bits(15)
                    } else {
                        // > Prefix 0b110; Number of bits to decode 12;
                        bitstream.read_bits(12) + 1024 + 256
                    }
                } else {
                    // > Prefix 0b10; Number of bits to decode 10;
                    bitstream.read_bits(10) + 256
                }
            } else {
                // > Prefix 0b0; Number of bits to decode 8;
                bitstream.read_bits(8)
            };

            // Get the match length (if match length >= 257).
            // In all cases,
            // > Base value to add to decoded value 257 + …
            257 + extra_len
        } else {
            match_length as u16
        };
        */

        if match_offset == 0 {
            return Err(DecodeFailed::InvalidMatchOffset(0));
        }

        // Get match length and offset. Perform copy and paste work.
        Decoded::Match {
            offset: usize::try_from(match_offset).map_err(|_| DecodeFailed::ArithmeticOverflow)?,
            length: usize::from(match_length),
        }
    })
}

impl Block {
    pub(crate) fn read(
        bitstream: &mut Bitstream,
        state: &mut DecoderState,
    ) -> Result<Self, DecodeFailed> {
        // > Each block of compressed data begins with a 3-bit Block Type field.
        // > Of the eight possible values, only three are valid values for the Block Type
        // > field.
        let kind =
            u8::try_from(bitstream.read_bits(3)?).map_err(|_| DecodeFailed::ArithmeticOverflow)?;
        let size = bitstream.read_u24_be()?;
        if size == 0 {
            return Err(DecodeFailed::InvalidBlockSize(size));
        }

        let kind = match kind {
            0b001 => {
                read_main_and_length_trees(bitstream, state)?;

                Kind::Verbatim {
                    main_tree: state.main_tree.create_instance()?,
                    length_tree: state.length_tree.create_instance_allow_empty()?,
                }
            },
            0b010 => {
                // > encoding only the delta path lengths between the current and previous trees
                //
                // This means we don't need to worry about deltas on this tree.
                let aligned_offset_tree = {
                    let mut path_lengths = Vec::new();
                    path_lengths
                        .try_reserve_exact(8)
                        .map_err(|_| DecodeFailed::AllocationFailed)?;
                    for _ in 0..8 {
                        path_lengths.push(
                            u8::try_from(bitstream.read_bits(3)?)
                                .map_err(|_| DecodeFailed::ArithmeticOverflow)?,
                        );
                    }

                    Tree::from_path_lengths(path_lengths)?
                };

                // > An aligned offset block is identical to the verbatim block except for the
                // > presence of the aligned offset tree preceding the other trees.
                read_main_and_length_trees(bitstream, state)?;

                Kind::AlignedOffset {
                    aligned_offset_tree,
                    main_tree: state.main_tree.create_instance()?,
                    length_tree: state.length_tree.create_instance_allow_empty()?,
                }
            },
            0b011 => {
                bitstream.align()?;
                Kind::Uncompressed {
                    r: [
                        bitstream.read_u32_le()?,
                        bitstream.read_u32_le()?,
                        bitstream.read_u32_le()?,
                    ],
                }
            },
            _ => return Err(DecodeFailed::InvalidBlock(kind)),
        };

        Ok(Block {
            remaining: size,
            size,
            kind,
        })
    }

    pub(crate) fn decode_element(
        &self,
        bitstream: &mut Bitstream,
        r: &mut [u32; 3],
    ) -> Result<Decoded, DecodeFailed> {
        match &self.kind {
            Kind::Verbatim {
                main_tree,
                length_tree,
            } => decode_element(
                bitstream,
                r,
                DecodeInfo {
                    aligned_offset_tree: None,
                    main_tree,
                    length_tree: length_tree.as_ref(),
                },
            ),
            Kind::AlignedOffset {
                aligned_offset_tree,
                main_tree,
                length_tree,
            } => decode_element(
                bitstream,
                r,
                DecodeInfo {
                    aligned_offset_tree: Some(aligned_offset_tree),
                    main_tree,
                    length_tree: length_tree.as_ref(),
                },
            ),
            Kind::Uncompressed { r: new_r } => {
                r.copy_from_slice(new_r);
                let remaining = usize::try_from(self.remaining)
                    .map_err(|_| DecodeFailed::ArithmeticOverflow)?;
                Ok(Decoded::Read(remaining))
            },
        }
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::{BASE_POSITION, FOOTER_BITS};
    use crate::lzx::WindowSize;

    #[test]
    fn regular_lzx_maximum_window_fits_position_tables_exactly() {
        assert_eq!(FOOTER_BITS.len(), BASE_POSITION.len());
        assert_eq!(FOOTER_BITS.len(), WindowSize::MB2.position_slots());
    }
}
