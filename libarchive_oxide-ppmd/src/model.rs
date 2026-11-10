// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: Apache-2.0

use alloc::vec::Vec;
use core::fmt;

use crate::{Error, RarRangeDecoder};

const UNIT_SIZE: usize = 12;
const MAX_FREQ: u8 = 124;
const NUM_INDEXES: usize = 38;
const INT_BITS: u32 = 7;
const PERIOD_BITS: u32 = 7;
const BIN_SCALE: u32 = 1 << (INT_BITS + PERIOD_BITS);
const MIN_ORDER: u32 = 2;
const MAX_ORDER: u32 = 64;
const SEE_DUMMY: usize = 25 * 16;

const INIT_BIN_ESCAPE: [u16; 8] = [
    0x3cdd, 0x1f3f, 0x59bf, 0x48f3, 0x64a1, 0x5abc, 0x6632, 0x6051,
];
const EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

/// `PPMd` variant H (`Ppmd7`) statistical model.
///
/// All model references are integer offsets into one owned byte heap.
/// This preserves the reference suballocator's deterministic restart behavior without raw pointers or `unsafe` code.
pub struct Ppmd7 {
    heap: Vec<u8>,
    size: usize,
    align_offset: usize,
    free_list: [usize; NUM_INDEXES],
    glue_count: u8,
    text_ref: usize,
    units_start_ref: usize,
    lo_unit_ref: usize,
    hi_unit_ref: usize,
    max_order: u32,
    min_context: usize,
    max_context: usize,
    found_state: usize,
    order_fall: u32,
    init_escape: u32,
    prev_success: u32,
    run_length: i32,
    init_run_length: i32,
    hi_bits_flag: usize,
    units_to_index: [u8; 128],
    index_to_units: [u8; NUM_INDEXES],
    ns_to_bs_index: [u8; 256],
    ns_to_index: [u8; 256],
    high_bit_flag: [u8; 256],
    bin_summ: [[u16; 64]; 128],
    see_summ: [u16; SEE_DUMMY],
    see_shift: [u8; SEE_DUMMY],
    see_count: [u8; SEE_DUMMY],
    char_mask: [u8; 256],
    state_scratch: [usize; 256],
}

impl fmt::Debug for Ppmd7 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ppmd7")
            .field("model_bytes", &self.size)
            .field("max_order", &self.max_order)
            .field("order_fall", &self.order_fall)
            .finish_non_exhaustive()
    }
}

impl Ppmd7 {
    /// Allocates and initializes a `PPMd-H` model.
    pub fn new(max_order: u32, model_bytes: usize, initial_escape: u8) -> Result<Self, Error> {
        if !(MIN_ORDER..=MAX_ORDER).contains(&max_order) {
            return Err(Error::InvalidParameter);
        }
        let total = Self::required_allocation_bytes(model_bytes)?;
        let align_offset = 4 - (model_bytes & 3);
        let mut heap = Vec::new();
        heap.try_reserve_exact(total)
            .map_err(|_| Error::Allocation)?;
        heap.resize(total, 0);

        let mut units_to_index = [0; 128];
        let mut index_to_units = [0; NUM_INDEXES];
        let mut count = 0usize;
        for (index, units) in index_to_units.iter_mut().enumerate() {
            let step = if index >= 12 { 4 } else { (index >> 2) + 1 };
            for _ in 0..step {
                units_to_index[count] = u8::try_from(index).map_err(|_| Error::InvalidParameter)?;
                count += 1;
            }
            *units = u8::try_from(count).map_err(|_| Error::InvalidParameter)?;
        }

        let mut ns_to_bs_index = [0; 256];
        ns_to_bs_index[1] = 2;
        ns_to_bs_index[2..11].fill(4);
        ns_to_bs_index[11..].fill(6);
        let mut ns_to_index = [0; 256];
        ns_to_index[1] = 1;
        ns_to_index[2] = 2;
        let mut index = 3u8;
        let mut left = 1u8;
        for slot in &mut ns_to_index[3..] {
            *slot = index;
            left -= 1;
            if left == 0 {
                index += 1;
                left = index - 2;
            }
        }
        let mut high_bit_flag = [0; 256];
        high_bit_flag[0x40..].fill(8);

        let mut model = Self {
            heap,
            size: model_bytes,
            align_offset,
            free_list: [0; NUM_INDEXES],
            glue_count: 0,
            text_ref: 0,
            units_start_ref: 0,
            lo_unit_ref: 0,
            hi_unit_ref: 0,
            max_order,
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_escape: u32::from(initial_escape),
            prev_success: 0,
            run_length: 0,
            init_run_length: 0,
            hi_bits_flag: 0,
            units_to_index,
            index_to_units,
            ns_to_bs_index,
            ns_to_index,
            high_bit_flag,
            bin_summ: [[0; 64]; 128],
            see_summ: [0; SEE_DUMMY],
            see_shift: [0; SEE_DUMMY],
            see_count: [0; SEE_DUMMY],
            char_mask: [0; 256],
            state_scratch: [0; 256],
        };
        model.restart_model();
        Ok(model)
    }

    /// Model heap bytes requested by the archive.
    #[must_use]
    pub const fn model_bytes(&self) -> usize {
        self.size
    }

    /// Exact byte length of the owned flat heap, including alignment and the suballocator's terminal unit.
    #[must_use]
    pub fn allocation_bytes(&self) -> usize {
        self.heap.len()
    }

    /// Computes the exact flat-heap allocation for a requested model size.
    pub fn required_allocation_bytes(model_bytes: usize) -> Result<usize, Error> {
        if model_bytes < UNIT_SIZE || model_bytes > u32::MAX as usize - UNIT_SIZE - 4 {
            return Err(Error::InvalidParameter);
        }
        let align_offset = 4 - (model_bytes & 3);
        align_offset
            .checked_add(model_bytes)
            .and_then(|value| value.checked_add(UNIT_SIZE))
            .ok_or(Error::InvalidParameter)
    }

    /// Updates the RAR escape seed used when a binary context expands.
    pub fn set_initial_escape(&mut self, escape: u8) {
        self.init_escape = u32::from(escape);
    }

    /// Decodes one byte and updates the model.
    // Keep the public-domain model's control flow and terminology recognizable
    // so parity reviews can compare this safe offset-based port mechanically.
    #[allow(clippy::if_not_else, clippy::similar_names, clippy::too_many_lines)]
    pub fn decode_symbol(&mut self, range: &mut RarRangeDecoder<'_>) -> Result<u8, Error> {
        if self.context_num_stats(self.min_context) != 1 {
            let mut state = self.context_stats(self.min_context);
            let total = u32::from(self.context_sum_freq(self.min_context));
            let count = range.get_threshold(total)?;
            let mut high_count = u32::from(self.state_freq(state));
            if count < high_count {
                range.decode(0, u32::from(self.state_freq(state)))?;
                self.found_state = state;
                let symbol = self.state_symbol(state);
                self.update_first();
                return Ok(symbol);
            }
            self.prev_success = 0;
            let mut remaining = self.context_num_stats(self.min_context) - 1;
            loop {
                state += 6;
                high_count += u32::from(self.state_freq(state));
                if high_count > count {
                    range.decode(
                        high_count - u32::from(self.state_freq(state)),
                        u32::from(self.state_freq(state)),
                    )?;
                    self.found_state = state;
                    let symbol = self.state_symbol(state);
                    self.update_later();
                    return Ok(symbol);
                }
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
            if count >= total {
                return Err(Error::Corrupt);
            }
            self.hi_bits_flag =
                usize::from(self.high_bit_flag[usize::from(self.state_symbol(self.found_state))]);
            range.decode(high_count, total - high_count)?;
            self.char_mask.fill(0xff);
            self.char_mask[usize::from(self.state_symbol(state))] = 0;
            let mut remaining = self.context_num_stats(self.min_context) - 1;
            loop {
                state -= 6;
                self.char_mask[usize::from(self.state_symbol(state))] = 0;
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
        } else {
            let one = Self::one_state(self.min_context);
            let row = usize::from(self.state_freq(one) - 1);
            let suffix_stats = self.context_num_stats(self.context_suffix(self.min_context));
            self.hi_bits_flag =
                usize::from(self.high_bit_flag[usize::from(self.state_symbol(self.found_state))]);
            let column = self.prev_success as usize
                + usize::from(self.ns_to_bs_index[usize::from(suffix_stats - 1)])
                + self.hi_bits_flag
                + 2 * usize::from(self.high_bit_flag[usize::from(self.state_symbol(one))])
                + usize::try_from((self.run_length >> 26) & 0x20).map_err(|_| Error::Corrupt)?;
            let probability = self.bin_summ[row][column];
            if !range.decode_bit(u32::from(probability))? {
                self.bin_summ[row][column] = probability
                    .wrapping_add(1 << INT_BITS)
                    .wrapping_sub(Self::mean(probability));
                self.found_state = one;
                let symbol = self.state_symbol(one);
                self.update_binary();
                return Ok(symbol);
            }
            let probability = probability.wrapping_sub(Self::mean(probability));
            self.bin_summ[row][column] = probability;
            self.init_escape = u32::from(EXP_ESCAPE[usize::from(probability >> 10)]);
            self.char_mask.fill(0xff);
            self.char_mask[usize::from(self.state_symbol(one))] = 0;
            self.prev_success = 0;
        }

        loop {
            let masked = self.context_num_stats(self.min_context);
            loop {
                self.order_fall = self.order_fall.saturating_add(1);
                let suffix = self.context_suffix(self.min_context);
                if suffix == 0 {
                    return Err(Error::Corrupt);
                }
                self.min_context = suffix;
                if self.context_num_stats(self.min_context) != masked {
                    break;
                }
            }
            let mut high_count = 0u32;
            let mut state = self.context_stats(self.min_context);
            let wanted = usize::from(self.context_num_stats(self.min_context) - masked);
            let mut available = 0usize;
            while available != wanted {
                let symbol = usize::from(self.state_symbol(state));
                if self.char_mask[symbol] != 0 {
                    high_count += u32::from(self.state_freq(state));
                    self.state_scratch[available] = state;
                    available += 1;
                }
                state += 6;
            }
            let (see_index, escape_frequency) = self.make_escape_frequency(masked);
            let frequency_sum = escape_frequency + high_count;
            let count = range.get_threshold(frequency_sum)?;
            if count < high_count {
                let mut accumulated = 0u32;
                for selected in 0..available {
                    let candidate = self.state_scratch[selected];
                    accumulated += u32::from(self.state_freq(candidate));
                    if accumulated > count {
                        range.decode(
                            accumulated - u32::from(self.state_freq(candidate)),
                            u32::from(self.state_freq(candidate)),
                        )?;
                        self.update_see(see_index);
                        self.found_state = candidate;
                        let symbol = self.state_symbol(candidate);
                        self.update_masked();
                        return Ok(symbol);
                    }
                }
                return Err(Error::Corrupt);
            }
            if count >= frequency_sum {
                return Err(Error::Corrupt);
            }
            range.decode(high_count, frequency_sum - high_count)?;
            self.add_see_sum(see_index, frequency_sum);
            for index in 0..available {
                let symbol = usize::from(self.state_symbol(self.state_scratch[index]));
                self.char_mask[symbol] = 0;
            }
        }
    }

    fn restart_model(&mut self) {
        self.free_list.fill(0);
        self.text_ref = self.align_offset;
        self.hi_unit_ref = self.text_ref + self.size;
        self.lo_unit_ref = self.hi_unit_ref - (self.size / 8 / UNIT_SIZE) * 7 * UNIT_SIZE;
        self.units_start_ref = self.lo_unit_ref;
        self.glue_count = 0;
        self.order_fall = self.max_order;
        self.init_run_length = -i32::try_from(self.max_order.min(12)).unwrap_or(12) - 1;
        self.run_length = self.init_run_length;
        self.prev_success = 0;
        self.hi_bits_flag = 0;
        self.hi_unit_ref -= UNIT_SIZE;
        self.min_context = self.hi_unit_ref;
        self.max_context = self.min_context;
        self.set_context_suffix(self.min_context, 0);
        self.set_context_num_stats(self.min_context, 256);
        self.set_context_sum_freq(self.min_context, 257);
        self.found_state = self.lo_unit_ref;
        self.lo_unit_ref += Self::units_to_bytes(128);
        self.set_context_stats(self.min_context, self.found_state);
        for symbol in 0u16..=255 {
            let state = self.found_state + usize::from(symbol) * 6;
            self.set_state_symbol(state, u8::try_from(symbol).unwrap_or(u8::MAX));
            self.set_state_freq(state, 1);
            self.set_state_successor(state, 0);
        }
        for row in 0..128 {
            for (column, escape) in INIT_BIN_ESCAPE.iter().copied().enumerate() {
                let row_value = u32::try_from(row).unwrap_or(u32::MAX);
                let value = u16::try_from(BIN_SCALE - u32::from(escape) / (row_value + 2))
                    .unwrap_or(u16::MAX);
                for repeated in (column..64).step_by(8) {
                    self.bin_summ[row][repeated] = value;
                }
            }
        }
        for row in 0..25 {
            for column in 0..16 {
                let index = row * 16 + column;
                self.see_shift[index] = u8::try_from(PERIOD_BITS - 4).unwrap_or(u8::MAX);
                self.see_summ[index] =
                    u16::try_from((5 * row + 10) << usize::from(self.see_shift[index]))
                        .unwrap_or(u16::MAX);
                self.see_count[index] = 4;
            }
        }
    }

    fn make_escape_frequency(&mut self, masked: u16) -> (usize, u32) {
        let stats = self.context_num_stats(self.min_context);
        let non_masked = stats - masked;
        if stats == 256 {
            return (SEE_DUMMY, 1);
        }
        let suffix_stats = self.context_num_stats(self.context_suffix(self.min_context));
        let column = usize::from(
            u8::from(
                u32::from(non_masked) < u32::from(suffix_stats).wrapping_sub(u32::from(stats)),
            ) + 2 * u8::from(self.context_sum_freq(self.min_context) < 11 * stats)
                + 4 * u8::from(masked > non_masked),
        ) + self.hi_bits_flag;
        let index = usize::from(self.ns_to_index[usize::from(non_masked - 1)]) * 16 + column;
        let value = self.see_summ[index] >> self.see_shift[index];
        self.see_summ[index] = self.see_summ[index].wrapping_sub(value);
        (index, u32::from(value) + u32::from(value == 0))
    }

    fn update_see(&mut self, index: usize) {
        if index == SEE_DUMMY {
            return;
        }
        if u32::from(self.see_shift[index]) < PERIOD_BITS {
            self.see_count[index] = self.see_count[index].wrapping_sub(1);
            if self.see_count[index] == 0 {
                self.see_summ[index] = self.see_summ[index].wrapping_shl(1);
                self.see_count[index] = 3u8.wrapping_shl(u32::from(self.see_shift[index]));
                self.see_shift[index] += 1;
            }
        }
    }

    fn add_see_sum(&mut self, index: usize, value: u32) {
        if index != SEE_DUMMY {
            self.see_summ[index] =
                self.see_summ[index].wrapping_add(u16::try_from(value).unwrap_or(u16::MAX));
        }
    }

    fn create_successors(&mut self, skip: bool) -> usize {
        let mut context = self.min_context;
        let up_branch = self.state_successor(self.found_state);
        let mut count = 0usize;
        let found_symbol = self.state_symbol(self.found_state);
        if !skip {
            self.state_scratch[count] = self.found_state;
            count += 1;
        }
        while self.context_suffix(context) != 0 {
            context = self.context_suffix(context);
            let mut state = if self.context_num_stats(context) == 1 {
                Self::one_state(context)
            } else {
                self.context_stats(context)
            };
            while self.state_symbol(state) != found_symbol {
                state += 6;
            }
            let successor = self.state_successor(state);
            if successor != up_branch {
                context = successor;
                if count == 0 {
                    return context;
                }
                break;
            }
            if count == self.state_scratch.len() {
                return 0;
            }
            self.state_scratch[count] = state;
            count += 1;
        }

        let up_symbol = self.get_u8(up_branch);
        let up_successor = up_branch + 1;
        let up_frequency = if self.context_num_stats(context) == 1 {
            self.state_freq(Self::one_state(context))
        } else {
            let mut state = self.context_stats(context);
            while self.state_symbol(state) != up_symbol {
                state += 6;
            }
            let candidate = u32::from(self.state_freq(state) - 1);
            let remainder = u32::from(self.context_sum_freq(context))
                - u32::from(self.context_num_stats(context))
                - candidate;
            let adjustment = if 2 * candidate <= remainder {
                u32::from(5 * candidate > remainder)
            } else {
                (2 * candidate + 3 * remainder - 1) / (2 * remainder)
            };
            u8::try_from(1 + adjustment).unwrap_or(u8::MAX)
        };

        while count != 0 {
            let child = if self.hi_unit_ref != self.lo_unit_ref {
                self.hi_unit_ref -= UNIT_SIZE;
                self.hi_unit_ref
            } else if self.free_list[0] != 0 {
                self.remove_node(0)
            } else {
                let allocated = self.alloc_units_rare(0);
                if allocated == 0 {
                    return 0;
                }
                allocated
            };
            self.set_context_num_stats(child, 1);
            let one = Self::one_state(child);
            self.set_state_symbol(one, up_symbol);
            self.set_state_freq(one, up_frequency);
            self.set_state_successor(one, up_successor);
            self.set_context_suffix(child, context);
            count -= 1;
            self.set_state_successor(self.state_scratch[count], child);
            context = child;
        }
        context
    }

    // Preserve the reference algorithm's branch layout for auditability.
    #[allow(clippy::if_not_else, clippy::similar_names, clippy::too_many_lines)]
    fn update_model(&mut self) {
        let mut found_successor = self.state_successor(self.found_state);
        let found_symbol = self.state_symbol(self.found_state);
        let found_frequency = self.state_freq(self.found_state);
        if found_frequency < MAX_FREQ / 4 && self.context_suffix(self.min_context) != 0 {
            let context = self.context_suffix(self.min_context);
            if self.context_num_stats(context) == 1 {
                let state = Self::one_state(context);
                if self.state_freq(state) < 32 {
                    self.set_state_freq(state, self.state_freq(state) + 1);
                }
            } else {
                let mut state = self.context_stats(context);
                if self.state_symbol(state) != found_symbol {
                    loop {
                        state += 6;
                        if self.state_symbol(state) == found_symbol {
                            break;
                        }
                    }
                    if self.state_freq(state) >= self.state_freq(state - 6) {
                        self.swap_states(state, state - 6);
                        state -= 6;
                    }
                }
                if self.state_freq(state) < MAX_FREQ - 9 {
                    self.set_state_freq(state, self.state_freq(state) + 2);
                    self.set_context_sum_freq(context, self.context_sum_freq(context) + 2);
                }
            }
        }

        if self.order_fall == 0 {
            let created = self.create_successors(true);
            if created == 0 {
                self.restart_model();
                return;
            }
            self.min_context = created;
            self.max_context = created;
            self.set_state_successor(self.found_state, created);
            return;
        }
        self.set_u8(self.text_ref, found_symbol);
        self.text_ref += 1;
        let mut successor = self.text_ref;
        if self.text_ref >= self.units_start_ref {
            self.restart_model();
            return;
        }
        if found_successor != 0 {
            if found_successor <= successor {
                let created = self.create_successors(false);
                if created == 0 {
                    self.restart_model();
                    return;
                }
                found_successor = created;
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                successor = found_successor;
                if self.max_context != self.min_context {
                    self.text_ref -= 1;
                }
            }
        } else {
            self.set_state_successor(self.found_state, successor);
            found_successor = self.min_context;
        }

        let stats = self.context_num_stats(self.min_context);
        let base_sum = u32::from(self.context_sum_freq(self.min_context))
            - u32::from(stats)
            - u32::from(found_frequency - 1);
        let mut context = self.max_context;
        while context != self.min_context {
            let old_stats = self.context_num_stats(context);
            if old_stats != 1 {
                if old_stats & 1 == 0 {
                    let old_units = usize::from(old_stats >> 1);
                    let old_index = self.units_index(old_units);
                    if old_index != self.units_index(old_units + 1) {
                        let replacement = self.alloc_units(old_index + 1);
                        if replacement == 0 {
                            self.restart_model();
                            return;
                        }
                        let old = self.context_stats(context);
                        self.copy_units(replacement, old, old_units);
                        self.insert_node(old, old_index);
                        self.set_context_stats(context, replacement);
                    }
                }
                let bump = u16::from(2 * old_stats < stats)
                    + 2 * u16::from(
                        4 * old_stats <= stats && self.context_sum_freq(context) <= 8 * old_stats,
                    );
                self.set_context_sum_freq(
                    context,
                    self.context_sum_freq(context).wrapping_add(bump),
                );
            } else {
                let state = self.alloc_units(0);
                if state == 0 {
                    self.restart_model();
                    return;
                }
                self.copy_state(state, Self::one_state(context));
                self.set_context_stats(context, state);
                let frequency = if self.state_freq(state) < MAX_FREQ / 4 - 1 {
                    self.state_freq(state) << 1
                } else {
                    MAX_FREQ - 4
                };
                self.set_state_freq(state, frequency);
                self.set_context_sum_freq(
                    context,
                    u16::from(frequency)
                        .wrapping_add(u16::try_from(self.init_escape).unwrap_or(u16::MAX))
                        .wrapping_add(u16::from(stats > 3)),
                );
            }
            let candidate =
                2u64 * u64::from(found_frequency) * u64::from(self.context_sum_freq(context) + 6);
            let scale = u64::from(base_sum) + u64::from(self.context_sum_freq(context));
            let new_frequency = if candidate < 6 * scale {
                self.set_context_sum_freq(context, self.context_sum_freq(context).wrapping_add(3));
                1 + u8::from(candidate > scale) + u8::from(candidate >= 4 * scale)
            } else {
                let value = 4
                    + u8::from(candidate >= 9 * scale)
                    + u8::from(candidate >= 12 * scale)
                    + u8::from(candidate >= 15 * scale);
                self.set_context_sum_freq(
                    context,
                    self.context_sum_freq(context)
                        .wrapping_add(u16::from(value)),
                );
                value
            };
            let state = self.context_stats(context) + usize::from(old_stats) * 6;
            self.set_state_successor(state, successor);
            self.set_state_symbol(state, found_symbol);
            self.set_state_freq(state, new_frequency);
            self.set_context_num_stats(context, old_stats + 1);
            context = self.context_suffix(context);
        }
        self.max_context = found_successor;
        self.min_context = found_successor;
    }

    #[allow(clippy::similar_names)]
    fn rescale(&mut self) {
        let stats = self.context_stats(self.min_context);
        let mut state = self.found_state;
        let saved = self.state_bytes(state);
        while state != stats {
            self.copy_state(state, state - 6);
            state -= 6;
        }
        self.set_state_bytes(stats, saved);
        state = stats;

        let mut escape_frequency =
            i32::from(self.context_sum_freq(self.min_context)) - i32::from(self.state_freq(state));
        self.set_state_freq(state, self.state_freq(state).wrapping_add(4));
        let adder = u8::from(self.order_fall != 0);
        self.set_state_freq(state, self.state_freq(state).wrapping_add(adder) >> 1);
        let mut sum_frequency = u16::from(self.state_freq(state));
        let mut remaining = self.context_num_stats(self.min_context) - 1;
        loop {
            state += 6;
            escape_frequency -= i32::from(self.state_freq(state));
            self.set_state_freq(state, self.state_freq(state).wrapping_add(adder) >> 1);
            sum_frequency = sum_frequency.wrapping_add(u16::from(self.state_freq(state)));
            if self.state_freq(state) > self.state_freq(state - 6) {
                let saved = self.state_bytes(state);
                let saved_frequency = saved[1];
                let mut insertion = state;
                loop {
                    self.copy_state(insertion, insertion - 6);
                    insertion -= 6;
                    if insertion == stats || saved_frequency <= self.state_freq(insertion - 6) {
                        break;
                    }
                }
                self.set_state_bytes(insertion, saved);
            }
            remaining -= 1;
            if remaining == 0 {
                break;
            }
        }

        if self.state_freq(state) == 0 {
            let old_stats = self.context_num_stats(self.min_context);
            let mut removed = 0u16;
            loop {
                removed += 1;
                state -= 6;
                if self.state_freq(state) != 0 {
                    break;
                }
            }
            escape_frequency += i32::from(removed);
            self.set_context_num_stats(self.min_context, old_stats - removed);
            if self.context_num_stats(self.min_context) == 1 {
                let mut saved = self.state_bytes(stats);
                let mut frequency = saved[1];
                while escape_frequency > 1 {
                    frequency -= frequency >> 1;
                    escape_frequency >>= 1;
                }
                saved[1] = frequency;
                self.insert_node(stats, self.units_index(usize::from((old_stats + 1) >> 1)));
                self.found_state = Self::one_state(self.min_context);
                self.set_state_bytes(self.found_state, saved);
                return;
            }
            let old_units = usize::from((old_stats + 1) >> 1);
            let new_units = usize::from((self.context_num_stats(self.min_context) + 1) >> 1);
            if old_units != new_units {
                let replacement = self.shrink_units(stats, old_units, new_units);
                self.set_context_stats(self.min_context, replacement);
            }
        }
        let escape = u16::try_from(escape_frequency).unwrap_or(0);
        self.set_context_sum_freq(
            self.min_context,
            sum_frequency.wrapping_add(escape.wrapping_sub(escape >> 1)),
        );
        self.found_state = self.context_stats(self.min_context);
    }

    fn next_context(&mut self) {
        let context = self.state_successor(self.found_state);
        if self.order_fall == 0 && context > self.text_ref {
            self.min_context = context;
            self.max_context = context;
        } else {
            self.update_model();
        }
    }

    fn update_later(&mut self) {
        let mut state = self.found_state;
        self.set_state_freq(state, self.state_freq(state).wrapping_add(4));
        self.set_context_sum_freq(
            self.min_context,
            self.context_sum_freq(self.min_context).wrapping_add(4),
        );
        if self.state_freq(state) > self.state_freq(state - 6) {
            self.swap_states(state, state - 6);
            state -= 6;
            self.found_state = state;
            if self.state_freq(state) > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    fn update_first(&mut self) {
        self.prev_success = u32::from(
            2 * u16::from(self.state_freq(self.found_state))
                > self.context_sum_freq(self.min_context),
        );
        self.run_length = self
            .run_length
            .wrapping_add(i32::try_from(self.prev_success).unwrap_or_default());
        self.set_context_sum_freq(
            self.min_context,
            self.context_sum_freq(self.min_context).wrapping_add(4),
        );
        self.set_state_freq(
            self.found_state,
            self.state_freq(self.found_state).wrapping_add(4),
        );
        if self.state_freq(self.found_state) > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    fn update_binary(&mut self) {
        if self.state_freq(self.found_state) < 128 {
            self.set_state_freq(self.found_state, self.state_freq(self.found_state) + 1);
        }
        self.prev_success = 1;
        self.run_length = self.run_length.wrapping_add(1);
        self.next_context();
    }

    fn update_masked(&mut self) {
        self.set_context_sum_freq(
            self.min_context,
            self.context_sum_freq(self.min_context).wrapping_add(4),
        );
        self.set_state_freq(
            self.found_state,
            self.state_freq(self.found_state).wrapping_add(4),
        );
        if self.state_freq(self.found_state) > MAX_FREQ {
            self.rescale();
        }
        self.run_length = self.init_run_length;
        self.update_model();
    }

    fn glue_free_blocks(&mut self) {
        let head = self.align_offset + self.size;
        let mut current = head;
        self.glue_count = u8::MAX;
        for index in 0..NUM_INDEXES {
            let units = usize::from(self.index_to_units[index]);
            let mut next = self.free_list[index];
            self.free_list[index] = 0;
            while next != 0 {
                let node = next;
                self.set_u32(node + 4, current);
                self.set_u32(current + 8, node);
                current = node;
                next = self.get_u32(node);
                self.set_u16(node, 0);
                self.set_u16(node + 2, u16::try_from(units).unwrap_or(u16::MAX));
            }
        }
        self.set_u16(head, 1);
        self.set_u32(head + 4, current);
        self.set_u32(current + 8, head);
        if self.lo_unit_ref != self.hi_unit_ref {
            self.set_u16(self.lo_unit_ref, 1);
        }
        while current != head {
            let node = current;
            let mut units = usize::from(self.get_u16(node + 2));
            loop {
                let adjacent = node + Self::units_to_bytes(units);
                let combined = units + usize::from(self.get_u16(adjacent + 2));
                if self.get_u16(adjacent) != 0 || combined >= 0x1_0000 {
                    break;
                }
                units = combined;
                let previous = self.get_u32(adjacent + 8);
                let next = self.get_u32(adjacent + 4);
                self.set_u32(previous + 4, next);
                self.set_u32(next + 8, previous);
                self.set_u16(node + 2, u16::try_from(units).unwrap_or(u16::MAX));
            }
            current = self.get_u32(node + 4);
        }
        current = self.get_u32(head + 4);
        while current != head {
            let mut node = current;
            let next = self.get_u32(node + 4);
            let mut units = usize::from(self.get_u16(node + 2));
            while units > 128 {
                self.insert_node(node, NUM_INDEXES - 1);
                units -= 128;
                node += Self::units_to_bytes(128);
            }
            let mut index = self.units_index(units);
            if usize::from(self.index_to_units[index]) != units {
                index -= 1;
                let block = usize::from(self.index_to_units[index]);
                self.insert_node(node + Self::units_to_bytes(block), units - block - 1);
            }
            self.insert_node(node, index);
            current = next;
        }
    }

    fn alloc_units_rare(&mut self, index: usize) -> usize {
        if self.glue_count == 0 {
            self.glue_free_blocks();
            if self.free_list[index] != 0 {
                return self.remove_node(index);
            }
        }
        let mut larger = index;
        loop {
            larger += 1;
            if larger == NUM_INDEXES {
                let bytes = Self::units_to_bytes(usize::from(self.index_to_units[index]));
                self.glue_count = self.glue_count.saturating_sub(1);
                if self.units_start_ref.saturating_sub(self.text_ref) > bytes {
                    self.units_start_ref -= bytes;
                    return self.units_start_ref;
                }
                return 0;
            }
            if self.free_list[larger] != 0 {
                let result = self.remove_node(larger);
                self.split_block(result, larger, index);
                return result;
            }
        }
    }

    fn alloc_units(&mut self, index: usize) -> usize {
        if self.free_list[index] != 0 {
            return self.remove_node(index);
        }
        let bytes = Self::units_to_bytes(usize::from(self.index_to_units[index]));
        if bytes <= self.hi_unit_ref.saturating_sub(self.lo_unit_ref) {
            let result = self.lo_unit_ref;
            self.lo_unit_ref += bytes;
            return result;
        }
        self.alloc_units_rare(index)
    }

    fn shrink_units(&mut self, old: usize, old_units: usize, new_units: usize) -> usize {
        let old_index = self.units_index(old_units);
        let new_index = self.units_index(new_units);
        if old_index == new_index {
            return old;
        }
        if self.free_list[new_index] != 0 {
            let replacement = self.remove_node(new_index);
            self.copy_units(replacement, old, new_units);
            self.insert_node(old, old_index);
            return replacement;
        }
        self.split_block(old, old_index, new_index);
        old
    }

    fn insert_node(&mut self, node: usize, index: usize) {
        self.set_u32(node, self.free_list[index]);
        self.free_list[index] = node;
    }

    fn remove_node(&mut self, index: usize) -> usize {
        let node = self.free_list[index];
        self.free_list[index] = self.get_u32(node);
        node
    }

    fn split_block(&mut self, pointer: usize, old_index: usize, new_index: usize) {
        let units = usize::from(self.index_to_units[old_index])
            - usize::from(self.index_to_units[new_index]);
        let pointer = pointer + Self::units_to_bytes(usize::from(self.index_to_units[new_index]));
        let mut index = self.units_index(units);
        if usize::from(self.index_to_units[index]) != units {
            index -= 1;
            let block = usize::from(self.index_to_units[index]);
            self.insert_node(pointer + Self::units_to_bytes(block), units - block - 1);
        }
        self.insert_node(pointer, index);
    }

    fn units_index(&self, units: usize) -> usize {
        usize::from(self.units_to_index[units - 1])
    }

    const fn units_to_bytes(units: usize) -> usize {
        units * UNIT_SIZE
    }

    const fn one_state(context: usize) -> usize {
        context + 2
    }

    fn get_u8(&self, index: usize) -> u8 {
        self.heap[index]
    }

    fn set_u8(&mut self, index: usize, value: u8) {
        self.heap[index] = value;
    }

    fn get_u16(&self, index: usize) -> u16 {
        u16::from_le_bytes([self.heap[index], self.heap[index + 1]])
    }

    fn set_u16(&mut self, index: usize, value: u16) {
        self.heap[index..index + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn get_u32(&self, index: usize) -> usize {
        usize::try_from(u32::from_le_bytes([
            self.heap[index],
            self.heap[index + 1],
            self.heap[index + 2],
            self.heap[index + 3],
        ]))
        .unwrap_or(usize::MAX)
    }

    fn set_u32(&mut self, index: usize, value: usize) {
        let value = u32::try_from(value).unwrap_or(u32::MAX);
        self.heap[index..index + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn context_num_stats(&self, context: usize) -> u16 {
        self.get_u16(context)
    }

    fn set_context_num_stats(&mut self, context: usize, value: u16) {
        self.set_u16(context, value);
    }

    fn context_sum_freq(&self, context: usize) -> u16 {
        self.get_u16(context + 2)
    }

    fn set_context_sum_freq(&mut self, context: usize, value: u16) {
        self.set_u16(context + 2, value);
    }

    fn context_stats(&self, context: usize) -> usize {
        self.get_u32(context + 4)
    }

    fn set_context_stats(&mut self, context: usize, value: usize) {
        self.set_u32(context + 4, value);
    }

    fn context_suffix(&self, context: usize) -> usize {
        self.get_u32(context + 8)
    }

    fn set_context_suffix(&mut self, context: usize, value: usize) {
        self.set_u32(context + 8, value);
    }

    fn state_symbol(&self, state: usize) -> u8 {
        self.get_u8(state)
    }

    fn set_state_symbol(&mut self, state: usize, value: u8) {
        self.set_u8(state, value);
    }

    fn state_freq(&self, state: usize) -> u8 {
        self.get_u8(state + 1)
    }

    fn set_state_freq(&mut self, state: usize, value: u8) {
        self.set_u8(state + 1, value);
    }

    fn state_successor(&self, state: usize) -> usize {
        usize::from(self.get_u16(state + 2)) | (usize::from(self.get_u16(state + 4)) << 16)
    }

    fn set_state_successor(&mut self, state: usize, value: usize) {
        self.set_u16(state + 2, u16::try_from(value & 0xffff).unwrap_or(u16::MAX));
        self.set_u16(
            state + 4,
            u16::try_from((value >> 16) & 0xffff).unwrap_or(u16::MAX),
        );
    }

    fn state_bytes(&self, state: usize) -> [u8; 6] {
        let mut value = [0; 6];
        value.copy_from_slice(&self.heap[state..state + 6]);
        value
    }

    fn set_state_bytes(&mut self, state: usize, value: [u8; 6]) {
        self.heap[state..state + 6].copy_from_slice(&value);
    }

    fn copy_state(&mut self, destination: usize, source: usize) {
        self.heap.copy_within(source..source + 6, destination);
    }

    fn swap_states(&mut self, first: usize, second: usize) {
        for offset in 0..6 {
            self.heap.swap(first + offset, second + offset);
        }
    }

    fn copy_units(&mut self, destination: usize, source: usize, units: usize) {
        let bytes = Self::units_to_bytes(units);
        self.heap.copy_within(source..source + bytes, destination);
    }

    const fn mean(sum: u16) -> u16 {
        sum.wrapping_add(1 << (PERIOD_BITS - 2)) >> PERIOD_BITS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_model_envelope_before_allocation() {
        assert_eq!(
            Ppmd7::new(1, 1 << 20, 2).unwrap_err(),
            Error::InvalidParameter
        );
        assert_eq!(
            Ppmd7::new(65, 1 << 20, 2).unwrap_err(),
            Error::InvalidParameter
        );
        assert_eq!(Ppmd7::new(4, 11, 2).unwrap_err(), Error::InvalidParameter);
    }

    #[test]
    fn exact_model_size_is_owned() {
        let model = Ppmd7::new(4, 1 << 20, 2).unwrap();
        assert_eq!(model.model_bytes(), 1 << 20);
        assert_eq!(
            Ppmd7::required_allocation_bytes(1 << 20).unwrap(),
            (1 << 20) + 16
        );
        assert_eq!(model.allocation_bytes(), (1 << 20) + 16);
    }
}
