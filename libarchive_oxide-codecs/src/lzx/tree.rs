// SPDX-FileCopyrightText: 2020 Lonami
// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroU8;
use core::ops::Range;

use super::{Bitstream, DecodeFailed};

/// The canonical tree cannot be used to decode elements. Instead, it behaves like a builder for
/// instances of the actual tree that can decode elements efficiently.
#[derive(Debug)]
pub(crate) struct CanonicalTree {
    // > Each tree element can have a path length of [0, 16], where a zero path length indicates
    // > that the element has a zero frequency and is not present in the tree.
    //
    // We represent them as `u8` due to their very short range.
    path_lengths: Vec<u8>,
}

pub(crate) struct Tree {
    path_lengths: Vec<u8>,
    largest_length: NonZeroU8,
    lookup: Vec<u16>,
}

fn checked_rle_end(
    start: usize,
    encoded_run: u32,
    base_run: usize,
    range_end: usize,
) -> Result<usize, DecodeFailed> {
    let run = usize::try_from(encoded_run)
        .map_err(|_| DecodeFailed::ArithmeticOverflow)?
        .checked_add(base_run)
        .ok_or(DecodeFailed::ArithmeticOverflow)?;
    let end = start
        .checked_add(run)
        .ok_or(DecodeFailed::ArithmeticOverflow)?;
    if end > range_end {
        return Err(DecodeFailed::InvalidPretreeRle);
    }
    Ok(end)
}

impl CanonicalTree {
    pub(crate) fn new(count: usize) -> Result<Self, DecodeFailed> {
        let mut path_lengths = Vec::new();
        path_lengths
            .try_reserve_exact(count)
            .map_err(|_| DecodeFailed::AllocationFailed)?;
        // > In the case of the very first such tree, the delta is calculated against a tree
        // > in which all elements have a zero path length.
        path_lengths.resize(count, 0);
        Ok(Self { path_lengths })
    }

    /// Create a new `Tree` instance from this cast that can be used to decode elements. If the
    /// resulting tree is empty (all path lengths are 0), then `Ok(None)` is returned.
    ///
    /// This method transforms the canonical Huffman tree into a different structure that can
    /// be used to better decode elements.
    // > an LZXD decoder uses only the path lengths of the Huffman tree to reconstruct the
    // > identical tree,
    pub(crate) fn create_instance_allow_empty(&self) -> Result<Option<Tree>, DecodeFailed> {
        // The ideas implemented by this method are heavily inspired from LeonBlade's xnbcli
        // on GitHub.
        //
        // The path lengths contains the bit indices or zero if its not present, so find the
        // highest path length to determine how big our tree needs to be.
        let largest = self
            .path_lengths
            .iter()
            .copied()
            .max()
            .ok_or(DecodeFailed::InvalidPathLengths)?;
        // An all-zero path-length set is the permitted empty-tree representation.
        let Some(largest_length) = NonZeroU8::new(largest) else {
            return Ok(None);
        };
        if largest_length.get() > 16 {
            return Err(DecodeFailed::InvalidPathLengths);
        }
        let table_len = 1_usize
            .checked_shl(u32::from(largest_length.get()))
            .ok_or(DecodeFailed::ArithmeticOverflow)?;
        let mut huffman_tree = Vec::new();
        huffman_tree
            .try_reserve_exact(table_len)
            .map_err(|_| DecodeFailed::AllocationFailed)?;
        huffman_tree.resize(table_len, 0);

        // > a zero path length indicates that the element has a zero frequency and is not
        // > present in the tree. Tree elements are output in sequential order starting with the
        // > first element
        //
        // We start at the MSB, 1, and write the tree elements in sequential order from index 0.
        let mut pos = 0_usize;
        for bit in 1..=largest_length.get() {
            let amount = 1_usize << (largest_length.get() - bit);

            // The codes correspond with the indices of the path length (because
            // `path_lengths[code]` is its path length).
            for code in 0..self.path_lengths.len() {
                // As soon as a code's path length matches with our bit index write the code as
                // many times as the bit index itself represents.
                if self.path_lengths[code] == bit {
                    let code = u16::try_from(code).map_err(|_| DecodeFailed::InvalidPathLengths)?;
                    let end = pos
                        .checked_add(amount)
                        .ok_or(DecodeFailed::ArithmeticOverflow)?;
                    huffman_tree
                        .get_mut(pos..end)
                        .ok_or(DecodeFailed::InvalidPathLengths)?
                        .iter_mut()
                        .for_each(|x| *x = code);

                    pos = end;
                }
            }
        }

        // If we didn't fill the entire table, the path lengths were wrong.
        if pos != huffman_tree.len() {
            return Err(DecodeFailed::InvalidPathLengths);
        }

        let mut path_lengths = Vec::new();
        path_lengths
            .try_reserve_exact(self.path_lengths.len())
            .map_err(|_| DecodeFailed::AllocationFailed)?;
        path_lengths.extend_from_slice(&self.path_lengths);
        Ok(Some(Tree {
            path_lengths,
            largest_length,
            lookup: huffman_tree,
        }))
    }

    /// Create a new `Tree` instance from this cast that can be used to decode elements.
    ///
    /// This method transforms the canonical Huffman tree into a different structure that can
    /// be used to better decode elements.
    // > an LZXD decoder uses only the path lengths of the Huffman tree to reconstruct the
    // > identical tree,
    pub(crate) fn create_instance(&self) -> Result<Tree, DecodeFailed> {
        self.create_instance_allow_empty()?
            .ok_or(DecodeFailed::EmptyTree)
    }

    // Note: the tree already exists and is used to apply the deltas.
    pub(crate) fn update_range_with_pretree(
        &mut self,
        bitstream: &mut Bitstream,
        range: Range<usize>,
    ) -> Result<(), DecodeFailed> {
        if range.start > range.end || range.end > self.path_lengths.len() {
            return Err(DecodeFailed::InvalidPathLengths);
        }
        // > Each of the 17 possible values of (len[x] - prev_len[x]) mod 17, plus three
        // > additional codes used for run-length encoding, are not output directly as 5-bit
        // > numbers but are instead encoded via a Huffman tree called the pretree. The pretree
        // > is generated dynamically according to the frequencies of the 20 allowable tree
        // > codes. The structure of the pretree is encoded in a total of 80 bits by using 4 bits
        // > to output the path length of each of the 20 pretree elements. Once again, a zero
        // > path length indicates a zero-frequency element.
        let pretree = {
            let mut path_lengths = Vec::new();
            path_lengths
                .try_reserve_exact(20)
                .map_err(|_| DecodeFailed::AllocationFailed)?;
            for _ in 0..20 {
                path_lengths.push(
                    u8::try_from(bitstream.read_bits(4)?)
                        .map_err(|_| DecodeFailed::ArithmeticOverflow)?,
                );
            }

            Tree::from_path_lengths(path_lengths)?
        };

        // > Tree elements are output in sequential order starting with the first element.
        let mut i = range.start;
        while i < range.end {
            // > The "real" tree is then encoded using the pretree Huffman codes.
            let code = pretree.decode_element(bitstream)?;

            // > Elements can be encoded in one of two ways: if several consecutive elements have
            // > the same path length, run-length encoding is employed; otherwise, the element is
            // > output by encoding the difference between the current path length and the
            // > previous path length of the tree, mod 17.
            match code {
                0..=16 => {
                    let length = self
                        .path_lengths
                        .get_mut(i)
                        .ok_or(DecodeFailed::InvalidPathLengths)?;
                    let delta = u8::try_from(code)
                        .map_err(|_| DecodeFailed::InvalidPretreeElement(code))?;
                    *length = (17 + *length - delta) % 17;
                    i += 1;
                },
                // > Codes 17, 18, and 19 are used to represent consecutive elements that have the
                // > same path length.
                17 => {
                    let zeros = bitstream.read_bits(4)?;
                    let end = checked_rle_end(i, zeros, 4, range.end)?;
                    self.path_lengths
                        .get_mut(i..end)
                        .ok_or(DecodeFailed::InvalidPretreeRle)?
                        .iter_mut()
                        .for_each(|x| *x = 0);
                    i = end;
                },
                18 => {
                    let zeros = bitstream.read_bits(5)?;
                    let end = checked_rle_end(i, zeros, 20, range.end)?;
                    self.path_lengths
                        .get_mut(i..end)
                        .ok_or(DecodeFailed::InvalidPretreeRle)?
                        .iter_mut()
                        .for_each(|x| *x = 0);
                    i = end;
                },
                19 => {
                    let same = bitstream.read_bits(1)?;
                    // "Decode new code" is used to parse the next code from the bitstream, which
                    // has a value range of [0, 16].
                    let code = pretree.decode_element(bitstream)?;
                    if code > 16 {
                        Err(DecodeFailed::InvalidPretreeElement(code))?;
                    }

                    let previous = self
                        .path_lengths
                        .get(i)
                        .copied()
                        .ok_or(DecodeFailed::InvalidPathLengths)?;
                    let delta = u8::try_from(code)
                        .map_err(|_| DecodeFailed::InvalidPretreeElement(code))?;
                    let value = (17 + previous - delta) % 17;
                    let end = checked_rle_end(i, same, 4, range.end)?;
                    self.path_lengths
                        .get_mut(i..end)
                        .ok_or(DecodeFailed::InvalidPretreeRle)?
                        .iter_mut()
                        .for_each(|x| *x = value);
                    i = end;
                },
                _ => return Err(DecodeFailed::InvalidPretreeElement(code)),
            }
        }

        Ok(())
    }
}

impl Tree {
    /// Create a new usable tree instance directly from known path lengths.
    pub(crate) fn from_path_lengths(path_lengths: Vec<u8>) -> Result<Self, DecodeFailed> {
        CanonicalTree { path_lengths }.create_instance()
    }

    pub(crate) fn decode_element(&self, bitstream: &mut Bitstream) -> Result<u16, DecodeFailed> {
        // Perform the inverse translation, peeking as many bits as our tree is…
        let index = usize::try_from(bitstream.peek_bits(self.largest_length.get())?)
            .map_err(|_| DecodeFailed::ArithmeticOverflow)?;
        let code = self
            .lookup
            .get(index)
            .copied()
            .ok_or(DecodeFailed::InvalidPathLengths)?;

        // …and advancing the stream for as many bits this code actually takes (read to seek).
        let bits = self
            .path_lengths
            .get(usize::from(code))
            .copied()
            .ok_or(DecodeFailed::InvalidPathLengths)?;
        bitstream.read_bits(bits)?;

        Ok(code)
    }
}

impl fmt::Debug for Tree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tree")
            .field("path_lengths", &self.path_lengths.len())
            .field("largest_length", &self.largest_length)
            .field("lookup", &self.lookup.len())
            .finish()
    }
}

#[cfg(test)]
mod boundary_tests {
    use alloc::vec::Vec;

    use super::{Bitstream, CanonicalTree, DecodeFailed};

    fn push_bits(bits: &mut Vec<bool>, value: u32, width: u8) {
        for shift in (0..width).rev() {
            bits.push((value & (1 << shift)) != 0);
        }
    }

    fn encode_words(bits: &mut Vec<bool>) -> Vec<u8> {
        while (bits.len() & 15) != 0 {
            bits.push(false);
        }
        let mut encoded = Vec::new();
        for word_bits in bits.chunks_exact(16) {
            let mut word = 0_u16;
            for bit in word_bits {
                word = (word << 1) | u16::from(*bit);
            }
            encoded.extend_from_slice(&word.to_le_bytes());
        }
        encoded
    }

    #[test]
    fn pretree_rle_cannot_cross_an_independently_encoded_range() {
        let mut bits = Vec::new();
        for element in 0..20 {
            push_bits(
                &mut bits,
                u32::from(u8::from(element == 17 || element == 18)),
                4,
            );
        }
        // Five maximum code-18 runs reach element 255.
        for _ in 0..5 {
            bits.push(true);
            push_bits(&mut bits, 31, 5);
        }
        // Code 17 with its shortest run would cross range.end=256.
        bits.push(false);
        push_bits(&mut bits, 0, 4);

        let encoded = encode_words(&mut bits);
        let mut bitstream = Bitstream::new(&encoded);
        let mut tree = CanonicalTree::new(300).expect("bounded test tree allocation");
        let error = tree
            .update_range_with_pretree(&mut bitstream, 0..256)
            .expect_err("RLE must not spill into the next independently encoded range");

        assert_eq!(error, DecodeFailed::InvalidPretreeRle);
    }
}

#[cfg(any())]
mod tests {
    use super::*;

    #[test]
    fn decode_simple_table() {
        // Based on some aligned offset tree
        let tree = Tree::from_path_lengths(vec![6, 5, 1, 3, 4, 6, 2, 0]).unwrap();
        let value_count = vec![(2, 32), (6, 16), (3, 8), (4, 4), (1, 2), (0, 1), (5, 1)];

        let mut i = 0;
        for (value, count) in value_count.into_iter() {
            (0..count).for_each(|_| {
                assert_eq!(tree.lookup[i], value);
                i += 1;
            })
        }
    }

    #[test]
    fn decode_complex_table() {
        // Based on the pretree of some length tree
        let tree = Tree::from_path_lengths(vec![
            1, 0, 0, 0, 0, 7, 3, 3, 4, 4, 5, 5, 5, 7, 8, 8, 0, 7, 0, 0,
        ])
        .unwrap();
        let value_count = vec![
            (0, 128),
            (6, 32),
            (7, 32),
            (8, 16),
            (9, 16),
            (10, 8),
            (11, 8),
            (12, 8),
            (5, 2),
            (13, 2),
            (17, 2),
            (14, 1),
            (15, 1),
        ];

        let mut i = 0;
        for (value, count) in value_count.into_iter() {
            (0..count).for_each(|_| {
                assert_eq!(tree.lookup[i], value);
                i += 1;
            })
        }
    }

    #[test]
    fn decode_elements() {
        let tree = Tree::from_path_lengths(vec![6, 5, 1, 3, 4, 6, 2, 0]).unwrap();

        let buffer = [0x5b, 0xda, 0x3f, 0xf8];
        let mut bitstream = Bitstream::new(&buffer);
        bitstream.read_bits(11).unwrap();
        assert_eq!(tree.decode_element(&mut bitstream), Ok(3));
        assert_eq!(tree.decode_element(&mut bitstream), Ok(5));
        assert_eq!(tree.decode_element(&mut bitstream), Ok(6));
        assert_eq!(tree.decode_element(&mut bitstream), Ok(2));
    }
}
