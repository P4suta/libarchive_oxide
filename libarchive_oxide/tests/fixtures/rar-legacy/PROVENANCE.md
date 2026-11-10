<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# Legacy RAR compressed-payload provenance

The compressed RAR3 integration, codec, and fuzz invariant tests reproduce a 30-byte raw member payload from the MIT-licensed `compcol` 0.6.8 RAR3 test.
Its upstream test records that the block was extracted from libarchive's BSD-2-Clause `test_read_format_rar_compress_normal.rar` fixture and checked with `unrar p`.
The expected plaintext is the first-party string `test text document\r\n`.

Only those raw member bytes and the expected plaintext are reproduced here.
The repository's first-party builder supplies a minimal checksum-correct legacy RAR container declaring unpack version 29 and method `0x33`; no libarchive,
UnRAR, or RARLAB program or source is included.
The original archive producer,
producer version, and command were not recorded upstream, so this is one redistributable decoder oracle rather than complete producer/consumer triangulation.

The project provides no RAR writer.
The bytes exercise read-only decompression,
exact output, CRC32 verification, one-byte delivery, truncation, and resource limits only.

## ISC RAR3 encryption archives

`rarfile-rar3-data-password.rar` and `rarfile-rar3-header-password.rar` are the byte-exact `test/files/rar3-comment-psw.rar` and `test/files/rar3-comment-hpsw.rar` fixtures from the ISC-licensed `rarfile` project at commit `c4bb54b3aa6d8316b77e8d15947bd59e27b6f9b5`.
Their SHA-256 digests are respectively `ffb9b41571ac4d56ebf9a5ce5323740ea6150d66823b66abf7566f8dd2639803` and `29c61403d1e7cec0b15eb7e33cfa217cebd56bf1a4a78a2642715eca474350b2`.

Both archives use the password `password`, contain `file1.txt` and `file2.txt`, and expect zero-byte plaintext payloads.
The first keeps headers in the clear and encrypts each compressed data area; the second also encrypts the file headers.
They exercise ordered password candidates, per-entry salts,
AES block framing, header CRC validation, and plaintext CRC32 without adding a RAR writer or any UnRAR-licensed implementation.

## BSD RAR3 standard VM-filter archive

`libarchive-rar3-filter.rar` is the byte-exact decoded form of libarchive's `libarchive/test/test_read_format_rar_filter.rar.uu` at commit `44cbcfc560c487020da31d0fb82f0e2395fd90fd`.
The upstream test and fixture are distributed under BSD-2-Clause and test an executable compressed with an in-band RAR3 standard VM filter.
The 94,301-byte archive has SHA-256 `b058412adcd3329a868cb66561a224eb0acf22ad2d380ef5d9e17e432a47d6a8`.

libarchive independently expects one `bsdcat.exe` entry of 204,288 bytes whose first 12 bytes are `4d5a90000300000004000000`.
Windows' system bsdtar (libarchive 3.8.4) was also used as an independent consumer.
The complete payload SHA-256 is `a961532b3a196e0b2c0126ad6f35d511c9fdfeadacbe78a1b15dc221251ad9a2`.

## CC0 RAR3 solid archive

`ssokolow-rar3-solid.cbr.hex` is the byte-exact 381-byte `build/testfile.rar3.solid.cbr` file from Stephan Sokolow's `rar-test-files` repository at commit `16b785c2b1b504e99fc307676e5369a26d3ce060`.
It was produced by a licensed RAR/WinRAR installation using the repository's reproducible Makefile and is dedicated to the public domain under CC0-1.0.
Its SHA-256 is `610376cfa11ec11bf55cd117f5d5b83dd11dded6aad2f825b41dbe84d7f3098d`.

`ssokolow-rar3-solid-payloads.hex` concatenates the upstream source files `sources/testfile.png` (87 bytes, SHA-256 `fdda20984cc1591419ec4583e24e72e4dba39d0b96608253f853a2dfb238ad1a`) and `sources/testfile.jpg` (220 bytes, SHA-256 `e514232511df1a4f4221a75c27523518c3c62a2fe6470fa56e430364428eecd1`).
The fixture therefore checks a real two-member solid dictionary transition,
not only acceptance of an archive-level solid flag.

The same CC0 archive uses PPMd-H/PPMd-II and carries its statistical model plus output window into the second solid member.
It is an independent interoperability fixture for exact output, one-byte delivery, finite model memory, corruption,
truncation, and cross-member continuation.

## Junrar RAR4 LZ solid archive

`junrar-rar4-solid.rar.hex` is the byte-exact 464-byte `src/test/resources/com/github/junrar/solid/rar4-solid.rar` fixture from the junrar repository at commit `1397faba2381d289a4c4cedecf292ba16ca87826`.
It was introduced by commit `a0a68813098d40e3602036ffe6c355d7398cfe6b`.
Its SHA-256 is `b158d4b0e3506f04fcaff18db9b369b573fd54f313062c7b8c622cb33b9c5da4`.

The upstream Apache-licensed test independently expects nine entries named `file1.txt` through `file9.txt`, each containing the corresponding ASCII text `fileN\n`.
The archive is used only as a read-only interoperability oracle;
no junrar or UnRAR implementation source is copied or linked.
The fixture is tracked separately under `LicenseRef-UnRAR`, matching its upstream repository.
