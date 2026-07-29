<!--
SPDX-FileCopyrightText: 2026 libarchive_oxide contributors

SPDX-License-Identifier: MIT OR Apache-2.0
-->

# CAB fixture provenance

Provenance registry for Microsoft Cabinet (`.cab`) interoperability evidence in
`tests/interop_cab_meta.rs` and `tests/cab_volumes.rs`. Binary CAB files are
stored as deterministic ASCII hex so repository policy and diffs remain
text-only; tests remove whitespace and decode the bytes before use.

## Producer registry

| Fixture / label | Producer | Method | Independent evidence |
|---|---|---|---|
| in-code `raw-cab-builder` | first-party byte builder | Store | independent container framing |
| in-code `raw-cab-builder + flate2` | `flate2` 1.1.9 raw DEFLATE | MSZIP | independent CAB framing; codec family is documented below |
| `makecab/lzx-history.hex` | Microsoft `makecab.exe` | LZX, 2 MiB window, three CFDATA frames | proprietary producer plus Microsoft `expand.exe` oracle |
| `makecab/makecab-store{1,2}.cab.hex` | Microsoft `makecab.exe` | Store, one split CFDATA across two cabinets | proprietary producer plus Microsoft `extrac32.exe /A` oracle |
| `libmspack/mszip_lzx_qtm.hex` | upstream libmspack test corpus | mixed MSZIP/LZX/Quantum folders | independent open-source producer/corpus |
| `libmspack/cve-2010-2801-qtm-flush.hex` | upstream libmspack/cabextract regression corpus | Quantum, 256 KiB window, 16 CFDATA frames | independent open-source corpus and libmspack oracle |

The external artifacts are byte-for-byte fixtures; they are not generated or
fetched during tests.

## Microsoft makecab history fixture

- Capture date: 2026-07-29
- Producer: `C:\Windows\System32\makecab.exe`
- File/Product version: `5.00 (WinBuild.160101.0800)` / `5.00`
- Producer SHA-256:
  `070A98B4F7C03F99048A10F490D5916A9A98417E0D0DE2C414C76B3DD00CB35E`
- Command:

  ```powershell
  makecab.exe /V1 /D CompressionType=LZX /D CompressionMemory=21 `
    /D CabinetNameTemplate=lzx-history.cab /L C:\tmp C:\tmp\lzx-history.bin
  ```

- Deterministic source generation: 96 KiB where byte `i` is
  `((i % 4096) % 251)`.
- Source SHA-256:
  `2B777B7A936E5870265715C28B6143A7A2648BDACC104043DE39777F31BF4102`
- Decoded CAB length: 640 bytes
- Decoded CAB SHA-256:
  `CD46014EED4CBAA5CD42D761A4F19BD62B95F40BAD6722AAB5949F0EE305813D`
- Independent consumer: `C:\Windows\System32\expand.exe`, version
  `5.00 (WinBuild.160101.0800)`, SHA-256
  `E5CD2D9536B0729CE90368DCE9D923DCCFA6F75F2996E31BB349E6A75A2AA897`.

The fixture deliberately contains three full 32 KiB CFDATA chunks. The second
and third chunks require history/tree continuity but start a fresh 16-bit
word-aligned bitstream. It therefore detects both an accidental per-chunk
decoder reset and failure to discard CAB frame padding.

Microsoft Windows system tools and their generated test output are used only
as interoperability evidence. No Microsoft executable is redistributed.

## Microsoft makecab multi-cab Store fixture

- Capture date: 2026-07-29
- Producer: `C:\Windows\System32\makecab.exe`
- Input: `makecab-store.bin`, exactly 20,500 zero bytes
- Input SHA-256:
  `BD4E117AC624A5D12E9C8B6CD4B4030C7EF86D87D009AB393629698EA81F0CA0`
- Directive essentials:

  ```text
  .Set Cabinet=on
  .Set Compress=off
  .Set CabinetNameTemplate=makecab-store*.cab
  .Set MaxDiskSize=20480
  ```

- `makecab-store1.cab`: 20,480 bytes, SHA-256
  `3CC1388C494ADEB105472F5389D190C383D9358091D849F33FF419DF93CFAA47`
- `makecab-store2.cab`: 244 bytes, SHA-256
  `E6DAA0772F761D38A1C9FD88A4733CB850525CBE1537E66D588AD21E6E487BEC`
- Independent consumer:
  `extrac32.exe /Y /A /E /L <output> makecab-store1.cab`
- Independently extracted member: `makecab-store.bin`, 20,500 bytes, SHA-256
  equal to the input hash above.

The first cabinet ends with a checksummed physical CFDATA whose `cbUncomp` is
zero. The second cabinet's first record supplies the combined uncompressed
length. This fixture therefore proves real `setID`/`iCabinet`, prev/next-name,
continued-file sentinel, split-CFDATA reassembly, and checksum interoperability
without embedding or invoking Microsoft tools in the test suite.

## libmspack mixed-method fixture

- Capture date: 2026-07-29
- Upstream:
  <https://github.com/kyz/libmspack/blob/master/libmspack/test/test_files/cabd/mszip_lzx_qtm.cab>
- Raw capture URL:
  <https://raw.githubusercontent.com/kyz/libmspack/master/libmspack/test/test_files/cabd/mszip_lzx_qtm.cab>
- Decoded CAB length: 379 bytes
- Decoded CAB SHA-256:
  `0CE0B55FE705B744D41BB361170C0467DB30DA0C7F9BDD386D5DADE71A78E171`
- Independently extracted LZX member SHA-256:
  `E978598104671296857E0543F4280F4D4E0506DD3CAD5162E9F2A4F604FAFC78`
- Independently specified Quantum member SHA-256:
  `BDCFDAF09E54D61F950B165B201D4AD5F5ACFDECFF1FC5641E382AA382C74B45`
- Upstream project license: LGPL-2.1-or-later; the fixture is copied unchanged
  from the upstream test corpus and redistributed as hexadecimal test data with
  source attribution.

The tests read the MSZIP, LZX, and Quantum members byte-for-byte. Feature-off
builds still list the corresponding metadata and return a typed `Unsupported`
payload error.

## libmspack Quantum history fixture

- Capture date: 2026-07-29
- Upstream:
  <https://github.com/kyz/libmspack/blob/master/cabextract/test/bugs/cve-2010-2801-qtm-flush.cab>
- Raw capture URL:
  <https://raw.githubusercontent.com/kyz/libmspack/master/cabextract/test/bugs/cve-2010-2801-qtm-flush.cab>
- Decoded CAB length: 285 bytes
- Decoded CAB SHA-256:
  `78BB4C9540E36D3D4228E22CDFF0A5677F9C2DDDC4239C322277D0B9125D8364`
- Expected member: `zeroes`, 524,159 zero bytes
- Expected member SHA-256:
  `0E005E3D2C88E64A5BF04C0A8CECC7DDEB2B820C28D70AF04F0AA11D66BE4045`
- Upstream project license: LGPL-2.1-or-later; the byte-exact fixture is
  redistributed as hexadecimal test data with source attribution.

Despite its regression-test name, the archive carries a valid Quantum stream;
the historic CVE concerned the consumer's output-flush accounting. The folder
has fifteen full 32 KiB CFDATA blocks followed by a 32,639-byte final block.
The tiny continuation payloads require the Quantum dictionary and adaptive
arithmetic models to survive every block boundary, so a per-block decoder reset
cannot pass this fixture. No public Quantum encoder is available; this
independent corpus plus libmspack's published expected output is the available
producer/consumer evidence. Windows `expand.exe` can list the member but the
current Windows implementation does not decompress this legacy Quantum stream,
so it is not claimed as an oracle.

## In-code fixtures

- Store covers a multi-file solid folder, empty member, nested path, and exact
  `(path, kind, content)` output.
- MSZIP covers single-block, real LZ77 back-references, and multi-CFDATA file
  spanning. The CAB framing is first-party; `flate2` and the portable reader
  share the `miniz_oxide` implementation family, so this is not claimed as an
  independent DEFLATE-codec differential test.
- Failure fixtures cover truncated headers/extents and arithmetic streams,
  checksummed corruption, inconsistent declared output, invalid LZX/Quantum
  windows and Quantum levels, reserved bits, oversized or short-interior
  frames, decoded-total/codec-memory/in-flight/scan limits, and an E8
  `0xFFFF_FFFF` regression that must terminate with a typed error rather than
  panic or loop.

## Supported and unsupported boundaries

- Store (method 0): read.
- MSZIP (method 1): read with folder history.
- Quantum (method 2): read behind the additive `cab-quantum` feature; CAB
  levels `1..=7`, windows `10..=21`, injected per-CFDATA `0xFF` alignment
  trailers, and persistent folder dictionary/arithmetic models.
- LZX (method 3): read behind the additive `cab-lzx` feature, CAB windows
  `15..=21`, fresh bitstream alignment per CFDATA, persistent folder state.
- Cross-cabinet continuation is read through the explicit
  `advanced::CabVolumeReader` / `CabVolumeProvider` path over a caller-owned
  bounded `VolumeSet`. Store and MSZIP split blocks, plus LZX dictionary and
  Quantum model state, remain continuous across cabinets. The ordinary
  single-source `SeekArchiveReader` continues to return structured
  `Unsupported` because it has no resolver and performs no implicit lookup.

The audited LZXD fork and its upstream hashes/license are recorded in
`libarchive_oxide-codecs/src/lzx/UPSTREAM.md`.

## Verification

```sh
cargo test -p libarchive_oxide-codecs --no-default-features --features lzx \
  --test lzx_safety
cargo test -p libarchive_oxide --no-default-features --features cab-quantum \
  --test interop_cab_meta
cargo test -p libarchive_oxide --no-default-features --features cab-lzx \
  --test interop_cab_meta
cargo test -p libarchive_oxide --no-default-features --test cab_volumes
cargo test -p libarchive_oxide --no-default-features --features cab-lzx,cab-quantum \
  --test cab_volumes
```
