# `LHA` interoperability fixtures

Six external `.hex` files encode `LHA` archives from the `rust-delharc` interoperability corpus.
The 2026-08-14 capture used tag `v0.6.2`, commit `737ab3fc9913dad0a4fb9965f0bcd95a013f5a28`, at <https://github.com/royaltm/rust-delharc>.

The two PMArc fixtures come from the Lhasa regression corpus under the `ISC` license.
The source is commit `75ed83559f23e9538e0045c62f53f77ab03d03d6` at <https://github.com/fragglet/lhasa>.
The paths are `test/archives/pmarc124/pm1.pma` and `test/archives/pmarc2/pm2.pma`.
Lhasa identifies the producers as PMArc 1.24 for `CP/M` by Yoshihiko Mino and PMARC2 for `MSX-DOS`.

The directory contains archive samples without producer executables or source code.
Five archives contain only trivial test material: `hello world` text, directory names, or one symbolic-link record.
The LHx archive contains the `GNU General Public License` version 2 as its single `GPL-2` member.
The `REUSE.toml` annotation uses `GPL-2.0-or-later`.
Encoding the bytes as hex makes both the payload and changes to it reviewable.

`lhmelt-1.65.3.6-h0-subdir.lzh.hex` contains 102 bytes from LHMelt 1.65.3.6 / lmlzh32.dll 2.67.1.2.
The SHA-256 digest is `25c92b3794706b77048b9799963f2916c26aa1edd427d90005e54cf1215349f6`.

`lhmelt-1.65.3.6-h1-subdir.lzh.hex` contains 131 bytes from LHMelt 1.65.3.6 / lmlzh32.dll 2.67.1.2.
The SHA-256 digest is `b137296f60438bf78cb823ab13f4bc946158f57cbadde48871759f511c6999f2`.

`lhmelt-1.65.3.6-h2-subdir.lzh.hex` contains 203 bytes from LHMelt 1.65.3.6 / lmlzh32.dll 2.67.1.2.
The SHA-256 digest is `a41c2d643e8f7afabeefd3a9d668a3ccff8bbe7d02a6b7cf4448eaba539066a1`.

`lha-os2-2.08-h3-subdir.lzh.hex` contains 271 bytes from `LHA` for OS/2 2.08.
The SHA-256 digest is `201051c47213d0964c596d40f574486dbb683665b2baa2a27a81bae69e3a9b655`.

`lha-unix-1.14i-h1-symlink.lzh.hex` contains 72 bytes from `LHA` for Unix 1.14i.
The SHA-256 digest is `50829a67bf917a3fc0c15c6315ee56a0e27b926c1910dc40a9966afc8653ae0b`.

`unlha32-2.67a-h2-lhx.lzh.hex` contains 6903 bytes from `UNLHA32.DLL` 2.67a with `-jmm19`.
The SHA-256 digest is `c9ab661c5502714f9556be89617bddff237e0e21e72657dc019707aed9751d9b`.

`pmarc-1.24-pm1.pma.hex` contains 9984 bytes from PMArc 1.24 for `CP/M` with `-pm1-`.
The SHA-256 digest is `13dfdbd992c2fac4964b3028c646aa68eb7a4a941a4224c4837058c3771b6346`.

`pmarc2-pm2.pma.hex` contains 7168 bytes from PMARC2 for `MSX-DOS` with `-pm2-`.
The SHA-256 digest is `4428e8d9d4e5f61aa7fd041fc6048cfdb64052eaf2776f8b23b9430f506e7979`.

`compcol-0.6.8-lh2-level0.lzh.hex` contains 79 bytes from libarchive_oxide test envelope + compcol 0.6.8 clean-room LH2 encoder.
The SHA-256 digest is `1dc4be45df63a080c0c492c8270812755eae3c852d3b13cb6c4d605db924ff75`.

`compcol-lh2.lzh` contains 285 bytes from compcol 0.7.9 regression corpus.
The SHA-256 digest is `faa3a42486ea3fa1f3c1da8b3cb188bb413dbf9d2e4fb7e891fdc5bf747ae816`.

`first-party-lh3-canonical-match-level0.lzh.hex` contains 74 bytes from libarchive_oxide specification vector.
The SHA-256 digest is `d0a84a5f3a3665a13f2101b695168af0f0588af73e6ad85a7783b38974b011eb`.

The earlier audit used libarchive/bsdtar 3.8.4 to inspect the corpus.
Official 7-Zip 26.02 decodes the real-corpus LH4 through LH7 payloads used during the manual differential audit.
The OS/2 level-3 sample fails to decode.
The tests create LH1 and LH4 through LH7 payloads with the independent pure-Rust `compcol` encoder.
Windows libarchive/bsdtar 3.8.4 can't recognize the UNLHA32 LHx extension.
Tests check its 18,092-byte decoded size, `CRC16` value `a33a`, level-2 header, and method from the producer corpus manifest.
The decoder also verifies the checksum.
Product code contains no `LHA` writer.
Lhasa's independent `test/test-decompress` oracle fixes PM1 at 25,284 decoded bytes with `CRC32` value `b7d0e42c`.
PM2 contains 18,176 bytes with `CRC32` value `8e2093a7`.
Integration tests check the lengths, checksums, paths, and methods.
Both payloads contain the `GNU General Public License` version 2 text.
The `REUSE.toml` annotations use `GPL-2.0-or-later`.

The compcol 0.6.8 LH2 fixture has capture date 2026-08-16.
Its `adaptive.bin` member contains 40 repetitions of `LH2 adaptive Huffman payload `.
The decoded size is 1,160 bytes with `CRC16` value `7a02`.
The 42-byte raw payload uses the obsolete encoding corrected in compcol 0.7.6.
Keep the original bytes as a nonconforming-input regression.

The valid LH2 fixture comes from [compcol 0.7.9](https://github.com/KarpelesLab/compcol/blob/v0.7.9/tests/fixtures/lha/lh2.lzh).
The license is `MIT`, copyright 2026 Karpeles Lab Inc.
Its `lh2.txt` member contains 3,110 bytes with `CRC16` value `f60c`.
The matching [upstream test](https://github.com/KarpelesLab/compcol/blob/v0.7.9/tests/lha.rs) defines the exact plaintext.
Local integration and fuzz replay check the full plaintext, limits, truncation, and checksum behavior.
The producer and decoder share the same codec implementation.

The LH3 fixture has capture date 2026-08-16 and follows the public `LHA` header and codec description.
The original audit compared the fixture with Ancient's LH3 decoder under the `BSD-2-Clause` license.
The raw 42-byte payload declares a two-symbol block:
literal `A`, followed by a 63-byte distance-one match using the standard distance tree.
A canonical level-0 envelope names the 64-byte result `lh3.txt` and records `CRC16` value `cb8a`.
The fixture exercises the canonical literal tree, standard distance tree, overlapping matches, exact sizes, and prehistory contract.
The fixture is a specification vector.
bsdtar/libarchive 3.8.4 lists the member but reports LH3 as unsupported.
