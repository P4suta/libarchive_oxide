# SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Deterministically generate a ZIP method-14 (LZMA) fixture via CPython zipfile/liblzma."""
import zipfile, sys
OUT = sys.argv[1] if len(sys.argv) > 1 else "lzma-basic.zip"
DATE = (1980, 1, 1, 0, 0, 0)
big = b"the quick brown fox jumps over the lazy dog\n" * 200
members = [("readme.txt", b"hello lzma world\n"),
           ("sub/big.txt", big),
           ("sub/empty.txt", b"")]
with zipfile.ZipFile(OUT, "w") as z:
    for name, content in members:
        zi = zipfile.ZipInfo(name, date_time=DATE)
        zi.compress_type = zipfile.ZIP_LZMA
        zi.external_attr = 0o644 << 16
        z.writestr(zi, content)
