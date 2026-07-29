<!--
SPDX-FileCopyrightText: 2020 Lonami
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Audited regular-LZX fork provenance

The code in this directory is an explicit fork of `lzxd` 0.2.7 by Lonami,
published under `MIT OR Apache-2.0`.

The public [`LzxDecoder`](mod.rs) API implements the regular-LZX subset used by
CAB. It does not claim LZX DELTA reference data or extended-match support; the
upstream project name records provenance rather than the advertised capability.

- Upstream repository: <https://github.com/Lonami/lzxd>
- Upstream commit: `f90cea6d3d9738a4cd1e8d5c9bfe347541f5adcc`
- Imported from the crates.io `lzxd-0.2.7` source on 2026-07-29
- Original source SHA-256:
  - `bitstream.rs`: `323933669CC04884C99AE06CC974876D1BBCF40BB2985C139A66996144B1EE88`
  - `block.rs`: `844DA2C755360FF3E124697994DB1787D8F1B5AB7565EEDF66E28D75920AEBFE`
  - `lib.rs` (now `mod.rs`): `C74BC24FA4BEEC7F49761B1583CA51BA48FD7E7E980EF7338877FE6B16CD8A7C`
  - `tree.rs`: `42004B71056A71D28C2FD2BD1FD868A0357B3F2FE7EC96CC4557B7F689F2E7F5`
  - `window.rs`: `A2F4BDBC5D43B3164A0B26C0CF6876763FF14C6E0E96302D36B8F175A8FA6B57`

## Local changes

The fork is kept inside `libarchive_oxide-codecs` so the CAB adapter can rely
on a reviewed `no_std + alloc`, safe-Rust implementation without an opaque
panic or allocation boundary. Local changes:

- replace `std` with `core`/`alloc` and forbid unsafe code at the crate root;
- make every decoder allocation fallible and report `AllocationFailed`;
- replace production assertions and zero-progress behavior with typed errors;
- reject chunk, block, match-offset, bit-count, and arithmetic overruns before
  mutating the history window;
- reject pretree runs that cross independently encoded tree ranges and matches
  that precede available history;
- replace narrowing integer casts with checked conversions, and handle 0/16-bit
  masks without width-sized shifts that can panic in debug builds;
- consume odd uncompressed-block padding in its originating frame and bound
  position tables to regular LZX's 50 slots and 2 MiB maximum window;
- correct the E8 absolute-zero boundary and test it independently;
- expose an audited worst-case workspace bound for pre-allocation limit checks;
- retain a fresh bitstream per 32 KiB chunk while preserving window, Huffman
  tree, recent-offset, and E8 state across chunks, as required by CAB CFDATA.

The crate-level MIT and Apache-2.0 license texts cover both upstream and local
changes. Each forked source file retains upstream and local SPDX attribution.
