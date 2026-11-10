<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# RAR5 synthetic-fixture provenance

The RAR5 container and Store fixtures are generated entirely by first-party test code from RARLAB's published [RAR 5.0 archive format technote](https://www.rarlab.com/technote.htm).
They contain only synthetic paths and payloads authored for this repository.

The builders implement the documented eight-byte signature, vint-framed main,
file, and end blocks, header CRC-32, Store-method file fields, payload CRC-32,
BLAKE2sp hash records, and documented archive metadata/locator, time, owner,
version, redirection, UTF-8 archive comment and ignored quick-open service headers, and unknown extra records.
BLAKE2sp known-answer values come from the official CC0 BLAKE2 test-vector set; stripe-boundary behavior is also checked against Python's independent standard-library BLAKE2s tree mode.
Tests additionally synthesize truncations, oversized declarations, unsupported compression/encryption/hash methods, unknown, duplicate, or misplaced service headers, volume flags, CRC/hash corruption, malformed metadata/comments, and SFX prefixes.
No archive is produced by WinRAR/RAR/UnRAR, and no RARLAB, UnRAR, 7-Zip, or other third-party implementation source or binary output is copied or redistributed in those Store fixtures.

The compressed RAR5 file and service integration, codec, and fuzz invariant tests additionally reproduce a 16-byte raw member payload from the MIT-licensed `compcol` 0.6.8 RAR5 test.
Upstream records the command `rar a -ma5 -m3` and the expected plaintext of 200 ASCII `A` bytes followed by a newline, but does not record the RAR producer version.
Only that raw member and first-party plaintext are reproduced.
First-party framing reuses the payload as both a regular file and independently compressed CMT/quick-open service data; this is one decoder oracle, not complete interoperability triangulation.

`libarchive-v3.8.8-multiple-files-solid.rar.hex` is a text-hex conversion of libarchive v3.8.8's BSD-2-Clause `libarchive/test/test_read_format_rar5_multiple_files_solid.rar.uu` fixture.
The upstream uuencoded file is 999 bytes with SHA-256 `0184822d0b061ae1a705a46cf1ca4adb4981b9e37bdb6500a48530a19c56fd88`;
the decoded archive is 677 bytes with SHA-256 `0aa2c652c06304dedd93019663c1d52d5e85055d5fdb8045bfcc4345b90b4a0f`.
The corresponding upstream test independently expects four 4096-byte files named `test1.bin` through `test4.bin` and regenerates every little-endian word from its documented quadratic sequence.
The repository test reproduces that oracle and delivers the archive one byte at a time.
No RAR writer or UnRAR source was used by this project.

The decoded fixture was also extracted independently with Windows bsdtar 3.8.4 (libarchive 3.8.4, liblzma 5.8.1).
All four paths and all 16,384 output bytes matched the same generated oracle.
This consumer check uses neither the project decoder nor the newer v3.8.8 fixture test implementation.

The volume-state integration test reuses the fixture's first two raw member extents (archive offsets `68..445` and `489..514`) without changing their bytes.
It wraps the first member as a complete physical-volume entry and splits the second, genuinely dictionary-dependent member across two more documented RAR5 volume headers.
The existing quadratic oracle supplies both plaintext CRCs.
This derived envelope tests state transfer and volume framing; it is not represented as an additional independent producer corpus.

The identical text-hex record is copied to `fuzz/corpus/read_rar5/libarchive-v3.8.8-solid.hex` so the existing bounded replay gate applies truncations and field-smash mutations to this valid deep parser seed on every development loop.

`rarfile-rar5-data-password.rar`,
`rarfile-rar5-data-password-blake.rar`, and `rarfile-rar5-header-password.rar` are byte-for-byte copies of the ISC-licensed `rarfile` revision `c4bb54b3aa6d8316b77e8d15947bd59e27b6f9b5` fixtures `rar5-psw.rar`,
`rar5-psw-blake.rar`, and `rar5-hpsw.rar`.
Their SHA-256 digests are,
respectively,
`b6840e95152a1c3b5acd736dc34f988509866f04158b67da1b5a29e166a31355`,
`6f6914979dfdc56b323f362f8fbead9ab70105b5f8590b7d3a6fa3a7cdd9540c`,
and `9aff93dfd85b1e44daeef233105831999a2076299997b7790e1cf1fd557a4457`.
The data-password fixture is also copied byte-for-byte to `fuzz/corpus/read_rar5/rarfile-rar5-data-password.rar`; the shared fuzz harness supplies its documented password so mutation replay reaches the authenticated payload path.
All use the upstream documented password `password` and contain the same 2048-byte sequence of lines `000\n` through `511\n` as both a compressed and a Store member.
The Store plaintext was independently reproduced with .NET's PBKDF2-HMAC-SHA256 and AES-256-CBC implementations and has SHA-256 `2eaebb4c18cdef7f20089f8a2fa3475bc59c2a193f66e2f1513609a4bef13e22`.
These fixtures cover CRC32, `BLAKE2sp`, and encrypted-header variants without shipping or invoking an UnRAR implementation.

The BLAKE2sp verifier is an independently written scalar implementation based on the public BLAKE2 specification, not RAR or UnRAR implementation code.
Broad compressed-method interoperability still requires a larger corpus.

`rars-rar7-generation1.rar` is a complete one-member RAR7 archive generated from this repository's 30,173-byte `README.md` snapshot by `rars-cli` 0.7.0 at revision `89f825239c17a85b8cb6aad6b0fe0d9e294805d1`.
The exact command was `rars add --format rar70 --dict-size 192k --level 5 --no-filter`; its verbose inspection reports algorithm generation 1, method 5, a 196,608-byte exact dictionary, 11,352 packed bytes, and decoded CRC32 `0x543DAA56`.
The 11,448-byte archive SHA-256 is `c9623f935d6bdb572cd4c37f777a1e63e452112e78f52addf9c19d30f5283c12`;
the decoded payload SHA-256 is `36c235c669c64ed6c68af49065e9450c689120b8e33ba06669db48ed343fd6ea`.
The upstream generator's own integrity command accepted it.
Independently,
7-Zip 26.02 identified `v7:192K:m5`, reported `Everything is Ok`, and produced the same decoded size and SHA-256.
The project integration test supplies the archive one byte at a time.

`fuzz/corpus/read_rar5/rars-rar7-generation1.rar` is a deliberately smaller 816-byte archive generated by the same revision and options from the repository's 1,296-byte `LICENSES/BSD-2-Clause.txt`.
It still reports generation 1, method 5, and a 196,608-byte dictionary, but avoids making the development-loop mutation count proportional to the larger integration fixture.
Its archive SHA-256 is `72087a2471849074815d9285279c9f33fcc40ccb0f4231bc2ac36a48edc4d85d` and its decoded payload SHA-256 is `8254c53c3d4452a8d29592c72da61b90eec31b9a3732210ffa279804d93d20f4`.
No third-party RAR codec source is copied or linked into this project.

RARLAB's current [license](https://www.rarlab.com/license.htm) is the governing exclusion for a RAR-compatible writer; the project remains read-only for RAR.
