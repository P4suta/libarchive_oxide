# LHA interoperability fixtures

Six external `.hex` files in this directory are textual encodings of LHA archives from the `rust-delharc` interoperability corpus.
They were captured on 2026-08-14 from tag `v0.6.2`, commit `737ab3fc9913dad0a4fb9965f0bcd95a013f5a28`, at <https://github.com/royaltm/rust-delharc>.

The two PMArc fixtures are from the ISC-licensed Lhasa regression corpus at commit `75ed83559f23e9538e0045c62f53f77ab03d03d6`, under `test/archives/pmarc124/pm1.pma` and `test/archives/pmarc2/pm2.pma` at <https://github.com/fragglet/lhasa>. Lhasa records them as outputs from PMArc 1.24 for CP/M by Yoshihiko Mino and PMARC2 for MSX-DOS, respectively.

No producer executable or third-party source code is redistributed.
Five archives contain only trivial test material: `hello world` text, directory names, or one symbolic-link record.
The LHx archive contains the text of the GNU GPL version 2 as its single `GPL-2` member and is conservatively annotated `GPL-2.0-or-later` in `REUSE.toml`.
Encoding the bytes as hex makes both the payload and changes to it reviewable.

| Fixture | Original producer | Bytes | SHA-256 of decoded hex |
| --- | --- | ---: | --- |
| `lhmelt-1.65.3.6-h0-subdir.lzh.hex` | LHMelt 1.65.3.6 / lmlzh32.dll 2.67.1.2 | 102 | `25c92b3794706b77048b9799963f2916c26aa1edd427d90005e54cf1215349f6` |
| `lhmelt-1.65.3.6-h1-subdir.lzh.hex` | LHMelt 1.65.3.6 / lmlzh32.dll 2.67.1.2 | 131 | `b137296f60438bf78cb823ab13f4bc946158f57cbadde48871759f511c6999f2` |
| `lhmelt-1.65.3.6-h2-subdir.lzh.hex` | LHMelt 1.65.3.6 / lmlzh32.dll 2.67.1.2 | 203 | `a41c2d643e8f7afabeefd3a9d668a3ccff8bbe7d02a6b7cf4448eaba539066a1` |
| `lha-os2-2.08-h3-subdir.lzh.hex` | LHA for OS/2 2.08 | 271 | `201051c47213d0964c596d40f574486dbb683665b2baa2a27a81bae69e3a9b655` |
| `lha-unix-1.14i-h1-symlink.lzh.hex` | LHA for Unix 1.14i | 72 | `50829a67bf917a3fc0c15c6315ee56a0e27b926c1910dc40a9966afc8653ae0b` |
| `unlha32-2.67a-h2-lhx.lzh.hex` | UNLHA32.DLL 2.67a (`-jmm19`) | 6903 | `c9ab661c5502714f9556be89617bddff237e0e21e72657dc019707aed9751d9b` |
| `pmarc-1.24-pm1.pma.hex` | PMArc 1.24 for CP/M (`-pm1-`) | 9984 | `13dfdbd992c2fac4964b3028c646aa68eb7a4a941a4224c4837058c3771b6346` |
| `pmarc2-pm2.pma.hex` | PMARC2 for MSX-DOS (`-pm2-`) | 7168 | `4428e8d9d4e5f61aa7fd041fc6048cfdb64052eaf2776f8b23b9430f506e7979` |
| `compcol-0.6.8-lh2-level0.lzh.hex` | libarchive_oxide test envelope + compcol 0.6.8 clean-room LH2 encoder | 79 | `1dc4be45df63a080c0c492c8270812755eae3c852d3b13cb6c4d605db924ff75` |
| `first-party-lh3-canonical-match-level0.lzh.hex` | libarchive_oxide specification vector | 74 | `d0a84a5f3a3665a13f2101b695168af0f0588af73e6ad85a7783b38974b011eb` |

The corpus was also inspected with libarchive/bsdtar 3.8.4.
Official 7-Zip 26.02 decodes the real-corpus LH4 through LH7 payloads used during the manual differential audit; it does not accept the OS/2 level-3 sample.
The checked-in tests additionally create LH1 and LH4 through LH7 payloads with the independent pure-Rust `compcol` encoder.
Windows libarchive/bsdtar 3.8.4 does not recognize the UNLHA32 LHx extension; its decoded size (18,092 bytes), CRC16 (`a33a`),
level-2 header, and method are therefore locked against the producer corpus manifest as well as the decoder's own CRC verification.
Product code contains no LHA writer.
Lhasa's independent `test/test-decompress` oracle fixes PM1 at 25,284 decoded bytes with CRC32 `b7d0e42c` and PM2 at 18,176 bytes with CRC32 `8e2093a7`; the integration test checks those values as well as each archived path and method.
Both payloads contain GNU GPL version 2 text and therefore retain the conservative `GPL-2.0-or-later` annotation in `REUSE.toml`.

The LH2 fixture is first-party test material generated on 2026-08-16.
Its member is 40 repetitions of `LH2 adaptive Huffman payload ` (1,160 bytes),
named `adaptive.bin`, with CRC16 `7a02`; the 42-byte raw payload came from the pinned compcol 0.6.8 encoder and was wrapped in a canonical level-0 header by the test helper.
It locks the archive/codec boundary, limits, exact sizes, and CRC behavior.
Because its decoder and producer share the same clean-room implementation, it is explicitly not independent interoperability evidence.

The LH3 fixture is first-party test material constructed on 2026-08-16 from the public LHA header/codec description and cross-audited against Ancient's BSD-2-Clause LH3 decoder.
The raw 42-byte payload declares a two-symbol block:
literal `A`, followed by a 63-byte distance-one match using the standard distance tree.
A canonical level-0 envelope names the 64-byte result `lh3.txt` and records CRC16 `cb8a`.
This specifically exercises the canonical literal tree, standard distance tree, LZ overlap, exact sizes, and prehistory contract; it is not an independently produced archive.
bsdtar/libarchive 3.8.4 lists the member but reports LH3 itself as unsupported, which is retained as an honest negative differential result rather than described as successful independent verification.
