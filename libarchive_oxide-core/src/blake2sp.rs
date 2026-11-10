// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal incremental BLAKE2sp-256 used by RAR5 data verification.

const BLOCK_BYTES: usize = 64;
const PARALLELISM: usize = 8;
const STRIPE_BYTES: usize = BLOCK_BYTES * PARALLELISM;
const NODE_OFFSETS: [u32; PARALLELISM] = [0, 1, 2, 3, 4, 5, 6, 7];

const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[derive(Debug, Clone)]
struct Blake2s {
    chaining: [u32; 8],
    count: u64,
    buffer: [u8; BLOCK_BYTES],
    buffer_len: usize,
    last_node: bool,
}

impl Blake2s {
    fn tree_node(node_offset: u32, node_depth: u8, last_node: bool) -> Self {
        let mut parameter = [0_u8; 32];
        parameter[0] = 32;
        parameter[2] = 8;
        parameter[3] = 2;
        parameter[8..12].copy_from_slice(&node_offset.to_le_bytes());
        parameter[14] = node_depth;
        parameter[15] = 32;
        let mut chaining = IV;
        for (word, bytes) in chaining.iter_mut().zip(parameter.as_chunks::<4>().0.iter()) {
            *word ^= u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        Self {
            chaining,
            count: 0,
            buffer: [0; BLOCK_BYTES],
            buffer_len: 0,
            last_node,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        if self.buffer_len != 0 {
            let fill = BLOCK_BYTES - self.buffer_len;
            if input.len() <= fill {
                self.buffer[self.buffer_len..self.buffer_len + input.len()].copy_from_slice(input);
                self.buffer_len += input.len();
                return;
            }
            self.buffer[self.buffer_len..].copy_from_slice(&input[..fill]);
            self.count = self.count.wrapping_add(BLOCK_BYTES as u64);
            let block = self.buffer;
            self.compress(block, false);
            self.buffer_len = 0;
            input = &input[fill..];
        }
        while input.len() > BLOCK_BYTES {
            let mut block = [0_u8; BLOCK_BYTES];
            block.copy_from_slice(&input[..BLOCK_BYTES]);
            self.count = self.count.wrapping_add(BLOCK_BYTES as u64);
            self.compress(block, false);
            input = &input[BLOCK_BYTES..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_len = input.len();
    }

    fn finalize(mut self) -> [u8; 32] {
        self.count = self.count.wrapping_add(self.buffer_len as u64);
        self.buffer[self.buffer_len..].fill(0);
        let block = self.buffer;
        self.compress(block, true);
        let mut digest = [0_u8; 32];
        for (output, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(self.chaining) {
            output.copy_from_slice(&word.to_le_bytes());
        }
        digest
    }

    fn compress(&mut self, block: [u8; BLOCK_BYTES], last_block: bool) {
        let mut message = [0_u32; 16];
        for (word, bytes) in message.iter_mut().zip(block.as_chunks::<4>().0.iter()) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        let mut state = [0_u32; 16];
        state[..8].copy_from_slice(&self.chaining);
        state[8..].copy_from_slice(&IV);
        let count = self.count.to_le_bytes();
        state[12] ^= u32::from_le_bytes([count[0], count[1], count[2], count[3]]);
        state[13] ^= u32::from_le_bytes([count[4], count[5], count[6], count[7]]);
        if last_block {
            state[14] = !state[14];
            if self.last_node {
                state[15] = !state[15];
            }
        }
        for schedule in SIGMA {
            mix(
                &mut state,
                0,
                4,
                8,
                12,
                message[schedule[0]],
                message[schedule[1]],
            );
            mix(
                &mut state,
                1,
                5,
                9,
                13,
                message[schedule[2]],
                message[schedule[3]],
            );
            mix(
                &mut state,
                2,
                6,
                10,
                14,
                message[schedule[4]],
                message[schedule[5]],
            );
            mix(
                &mut state,
                3,
                7,
                11,
                15,
                message[schedule[6]],
                message[schedule[7]],
            );
            mix(
                &mut state,
                0,
                5,
                10,
                15,
                message[schedule[8]],
                message[schedule[9]],
            );
            mix(
                &mut state,
                1,
                6,
                11,
                12,
                message[schedule[10]],
                message[schedule[11]],
            );
            mix(
                &mut state,
                2,
                7,
                8,
                13,
                message[schedule[12]],
                message[schedule[13]],
            );
            mix(
                &mut state,
                3,
                4,
                9,
                14,
                message[schedule[14]],
                message[schedule[15]],
            );
        }
        for index in 0..8 {
            self.chaining[index] ^= state[index] ^ state[index + 8];
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn mix(
    state: &mut [u32; 16],
    first: usize,
    second: usize,
    third: usize,
    fourth: usize,
    message_first: u32,
    message_second: u32,
) {
    state[first] = state[first]
        .wrapping_add(state[second])
        .wrapping_add(message_first);
    state[fourth] = (state[fourth] ^ state[first]).rotate_right(16);
    state[third] = state[third].wrapping_add(state[fourth]);
    state[second] = (state[second] ^ state[third]).rotate_right(12);
    state[first] = state[first]
        .wrapping_add(state[second])
        .wrapping_add(message_second);
    state[fourth] = (state[fourth] ^ state[first]).rotate_right(8);
    state[third] = state[third].wrapping_add(state[fourth]);
    state[second] = (state[second] ^ state[third]).rotate_right(7);
}

/// Incremental unkeyed BLAKE2sp-256 state.
#[derive(Debug, Clone)]
pub(crate) struct Blake2sp {
    leaves: [Blake2s; PARALLELISM],
    buffer: [u8; STRIPE_BYTES],
    buffer_len: usize,
}

impl Blake2sp {
    pub(crate) fn new() -> Self {
        Self {
            leaves: core::array::from_fn(|index| {
                Blake2s::tree_node(NODE_OFFSETS[index], 0, index + 1 == PARALLELISM)
            }),
            buffer: [0; STRIPE_BYTES],
            buffer_len: 0,
        }
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        if self.buffer_len != 0 {
            let fill = STRIPE_BYTES - self.buffer_len;
            if input.len() < fill {
                self.buffer[self.buffer_len..self.buffer_len + input.len()].copy_from_slice(input);
                self.buffer_len += input.len();
                return;
            }
            self.buffer[self.buffer_len..].copy_from_slice(&input[..fill]);
            let stripe = self.buffer;
            self.process_stripe(&stripe);
            self.buffer_len = 0;
            input = &input[fill..];
        }
        while input.len() >= STRIPE_BYTES {
            let mut stripe = [0_u8; STRIPE_BYTES];
            stripe.copy_from_slice(&input[..STRIPE_BYTES]);
            self.process_stripe(&stripe);
            input = &input[STRIPE_BYTES..];
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffer_len = input.len();
    }

    pub(crate) fn finalize(mut self) -> [u8; 32] {
        for (index, leaf) in self.leaves.iter_mut().enumerate() {
            let start = index * BLOCK_BYTES;
            if self.buffer_len > start {
                let end = self.buffer_len.min(start + BLOCK_BYTES);
                leaf.update(&self.buffer[start..end]);
            }
        }
        let mut root = Blake2s::tree_node(0, 1, true);
        for leaf in self.leaves {
            root.update(&leaf.finalize());
        }
        root.finalize()
    }

    fn process_stripe(&mut self, stripe: &[u8; STRIPE_BYTES]) {
        for (index, leaf) in self.leaves.iter_mut().enumerate() {
            let start = index * BLOCK_BYTES;
            leaf.update(&stripe[start..start + BLOCK_BYTES]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Blake2sp;

    fn byte_sequence<const LENGTH: usize>() -> [u8; LENGTH] {
        let mut value = 0_u8;
        core::array::from_fn(|_| {
            let current = value;
            value = value.wrapping_add(1);
            current
        })
    }

    #[test]
    fn official_unkeyed_known_answer_vectors() {
        let cases = [
            (
                &[][..],
                [
                    0xdd, 0x0e, 0x89, 0x17, 0x76, 0x93, 0x3f, 0x43, 0xc7, 0xd0, 0x32, 0xb0, 0x8a,
                    0x91, 0x7e, 0x25, 0x74, 0x1f, 0x8a, 0xa9, 0xa1, 0x2c, 0x12, 0xe1, 0xca, 0xc8,
                    0x80, 0x15, 0x00, 0xf2, 0xca, 0x4f,
                ],
            ),
            (
                &[0][..],
                [
                    0xa6, 0xb9, 0xee, 0xcc, 0x25, 0x22, 0x7a, 0xd7, 0x88, 0xc9, 0x9d, 0x3f, 0x23,
                    0x6d, 0xeb, 0xc8, 0xda, 0x40, 0x88, 0x49, 0xe9, 0xa5, 0x17, 0x89, 0x78, 0x72,
                    0x7a, 0x81, 0x45, 0x7f, 0x72, 0x39,
                ],
            ),
        ];
        for (input, expected) in cases {
            let mut hash = Blake2sp::new();
            hash.update(input);
            assert_eq!(hash.finalize(), expected);
        }
    }

    #[test]
    fn incremental_updates_match_official_201_byte_vector() {
        let input: [u8; 201] = byte_sequence();
        let expected = [
            0xd9, 0x3a, 0xf9, 0x47, 0xb1, 0x46, 0x3a, 0x81, 0x7d, 0xb4, 0x41, 0xa4, 0x74, 0x58,
            0x8d, 0x6f, 0x99, 0x6d, 0x24, 0x39, 0x83, 0xe8, 0x3c, 0x7e, 0xee, 0x90, 0xe1, 0xef,
            0xa4, 0x40, 0xd9, 0xba,
        ];
        let mut hash = Blake2sp::new();
        for chunk in input.chunks(7) {
            hash.update(chunk);
        }
        assert_eq!(hash.finalize(), expected);
    }

    #[test]
    fn incremental_updates_cross_the_parallel_stripe_boundary() {
        // Independently derived with Python's standard-library BLAKE2s tree parameters; 513 bytes force a second block into leaf zero.
        let input: [u8; 513] = byte_sequence();
        let expected = [
            0x13, 0x36, 0x62, 0x8c, 0x7f, 0x15, 0x41, 0xc7, 0x81, 0x5f, 0xc0, 0xff, 0x1f, 0xb5,
            0xdf, 0xb0, 0x7a, 0x85, 0xcf, 0x5a, 0x17, 0xa2, 0x87, 0x2a, 0x3c, 0xe4, 0xb3, 0x22,
            0xd4, 0xa0, 0x3d, 0x0b,
        ];
        let mut hash = Blake2sp::new();
        for chunk in input.chunks(31) {
            hash.update(chunk);
        }
        assert_eq!(hash.finalize(), expected);
    }
}
