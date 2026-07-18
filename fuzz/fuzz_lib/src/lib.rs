// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! `libarchive_oxide-fuzz-cases` — the invariant bodies of libarchive_oxide's fuzzing, factored out as plain functions.
//!
//! This crate holds **no** libFuzzer machinery, so it builds and runs anywhere (including the
//! Windows/MSVC dev box with a stable toolchain). Two callers share it:
//!
//! - `fuzz/fuzz_targets/*.rs` — thin `fuzz_target!` shims (built only under the `fuzz` crate on a
//!   nightly Linux CI box) that delegate straight to these functions.
//! - `libarchive_oxide/tests/fuzz_replay.rs` — a portable `cargo test` runner that replays committed corpus
//!   files and a batch of `arbitrary`-seeded structured inputs through the **same** functions.
//!
//! # Invariants
//!
//! - **Reader targets** (`read_*`): feed arbitrary bytes to a format reader, run detection +
//!   `next_entry` + `read_chunk` to EOF. The only requirement is *no panic* and *bounded work*
//!   (a malformed archive must never hang or allocate without bound); errors are expected and fine.
//! - **Round-trip targets** (`roundtrip_*`): synthesize a valid file set from an `arbitrary` seed,
//!   write it, read it back, and assert `read ∘ write = id`.
//! - **Codec targets** (`codec_*`): decode arbitrary bytes without panicking, and — where an encoder
//!   exists — assert `decode ∘ encode = id`.
//!
//! There is **zero type erasure** here: every driver is generic over the concrete reader/writer.

#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};

use arbitrary::Arbitrary;

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::format::ar::{Ar, ArReader, ArWriter};
use libarchive_oxide_core::format::cpio::{Cpio, CpioReader, CpioWriter};
use libarchive_oxide_core::format::iso9660::{Iso9660, IsoReader, IsoWriter};
use libarchive_oxide_core::format::tar::{Tar, TarReader, TarWriter};
use libarchive_oxide_core::format::ArchiveFormat;
use libarchive_oxide_core::{
    decode_to_vec, decode_to_vec_capped, EntryData, EntryKind, EntryMeta, EntryReader, EntryWriter,
};

use libarchive_oxide::sevenz::{SevenZReader, SevenZWriter};
use libarchive_oxide::zip::ZipReader;

// ── Bounds: the guardrails that make "no panic / bounded work" enforceable on adversarial input. ──

/// Never follow a reader past this many entries (a malformed count field must not loop forever).
const MAX_ENTRIES: usize = 200_000;
/// Never accumulate more than this many payload bytes from one archive (bomb defense).
const MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
/// Cap on any single materialized decode (bomb defense for the codec targets).
const CODEC_CAP: usize = 64 * 1024 * 1024;
/// Largest plaintext we round-trip through a codec (keeps `encode∘decode` cheap).
const CODEC_ROUNDTRIP_MAX: usize = 256 * 1024;
/// LZMA2 dictionary size matching `Lzma2Options::with_preset(6)` (8 MiB).
const LZMA2_DICT: u32 = 8 * 1024 * 1024;

/// Most files a synthesized round-trip archive holds.
const MAX_ROUNDTRIP_ENTRIES: usize = 48;
/// Longest synthesized entry name (bytes).
const MAX_NAME_LEN: usize = 40;
/// Largest synthesized per-entry payload.
const MAX_ROUNDTRIP_DATA: usize = 4096;

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Reader targets: arbitrary bytes → detection + drain, asserting no panic and bounded work.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// Drives any [`EntryReader`] to exhaustion under the bounds above. Fully monomorphized (no `dyn`).
fn drive_reader<R: EntryReader>(mut reader: R) {
    let mut entries = 0usize;
    let mut total: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        // Stop on end-of-archive (`Ok(None)`) or any parse error (`Err`) — both are acceptable.
        let mut entry = match reader.next_entry() {
            Ok(Some(entry)) => entry,
            _ => return,
        };
        entries += 1;
        if entries > MAX_ENTRIES {
            return;
        }
        // Touch the metadata so name/link decoding is exercised too.
        let _ = entry.meta().path.len();
        let _ = entry.meta().link_target.as_ref().map(|t| t.len());
        loop {
            match entry.data().read_chunk(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    total += n as u64;
                    if total > MAX_TOTAL_BYTES {
                        return;
                    }
                },
            }
        }
    }
}

/// tar reader: no panic on any input.
pub fn read_tar(data: &[u8]) {
    let _ = Tar::sniff(data);
    drive_reader(TarReader::new(data));
}

/// cpio reader: no panic on any input.
pub fn read_cpio(data: &[u8]) {
    let _ = Cpio::sniff(data);
    drive_reader(CpioReader::new(data));
}

/// ar reader: no panic on any input.
pub fn read_ar(data: &[u8]) {
    let _ = Ar::sniff(data);
    drive_reader(ArReader::new(data));
}

/// ISO 9660 reader: no panic on any input.
pub fn read_iso(data: &[u8]) {
    let _ = Iso9660::sniff(data);
    drive_reader(IsoReader::new(data));
}

/// zip reader: no panic on any input.
pub fn read_zip(data: &[u8]) {
    let _ = libarchive_oxide::zip::is_zip(data);
    drive_reader(ZipReader::new(data));
}

/// 7z reader: no panic on any input.
pub fn read_7z(data: &[u8]) {
    drive_reader(SevenZReader::new(data));
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Round-trip targets: synthesized file set → write → read back → assert `read ∘ write = id`.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// A synthesized archive member. `arbitrary` fills `name`/`data` from the fuzzer's byte stream; the
/// raw values are then sanitized by [`normalize_files`] into a set every format can round-trip.
#[derive(Debug, Clone, Arbitrary)]
pub struct FuzzEntry {
    /// Raw candidate name (sanitized before use).
    pub name: Vec<u8>,
    /// Raw candidate payload (truncated before use).
    pub data: Vec<u8>,
}

/// Turns arbitrary [`FuzzEntry`] values into a canonical set of `(name, data)` files that every
/// writer accepts and every reader returns identically: names are restricted to a portable
/// character set, kept non-empty, bounded in length, and made unique case-insensitively (ISO 9660's
/// primary tree is case-folding, so case-only differences could otherwise collide).
fn normalize_files(entries: &[FuzzEntry]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (i, entry) in entries.iter().take(MAX_ROUNDTRIP_ENTRIES).enumerate() {
        let mut name: Vec<u8> = entry
            .name
            .iter()
            .copied()
            .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            .take(MAX_NAME_LEN)
            .collect();
        // A leading '.' or '-' is awkward across shells and 8.3 mangling; drop them.
        while matches!(name.first(), Some(b'.' | b'-')) {
            name.remove(0);
        }
        if name.is_empty() {
            name = format!("f{i}").into_bytes();
        }
        // Ensure case-insensitive uniqueness; disambiguate with the index if needed.
        if !seen.insert(name.to_ascii_lowercase()) {
            let mut disamb = format!("{i}_").into_bytes();
            disamb.extend_from_slice(&name);
            if !seen.insert(disamb.to_ascii_lowercase()) {
                continue;
            }
            name = disamb;
        }
        let data: Vec<u8> = entry
            .data
            .iter()
            .copied()
            .take(MAX_ROUNDTRIP_DATA)
            .collect();
        out.push((name, data));
    }
    out
}

/// Writes one regular-file entry, returning `Err` with the failing stage if the writer rejects it.
///
/// [`normalize_files`] only ever produces entries that *every* writer accepts (portable name set,
/// bounded length, `EntryKind::File`, small payload), so a failure here is a **writer regression**,
/// not a legitimate rejection. Callers assert on it (see [`write_file_asserted`]) rather than
/// silently aborting — the old early-`return` made a broken writer pass the round-trip vacuously.
fn write_file<W: EntryWriter>(
    writer: &mut W,
    name: &[u8],
    data: &[u8],
) -> Result<(), &'static str> {
    let mut meta = EntryMeta::new(EntryKind::File, Cow::Borrowed(name));
    meta.mode = 0o644;
    meta.size = data.len() as u64;
    let mut sink = writer.start_entry(&meta).map_err(|_| "start_entry")?;
    if !data.is_empty() {
        sink.write_chunk(data).map_err(|_| "write_chunk")?;
    }
    sink.close().map_err(|_| "close")
}

/// Writes one entry and asserts it succeeded. A failure means a writer stage returned `Err` on an
/// input `normalize_files` guarantees is writable — a regression that must fail loudly, never no-op.
fn write_file_asserted<W: EntryWriter>(writer: &mut W, name: &[u8], data: &[u8], fmt: &str) {
    if let Err(stage) = write_file(writer, name, data) {
        panic!(
            "{fmt}: writer.{stage} rejected a normalized entry (name {name:?}, {} byte(s)) — \
             a writer regression, not a legitimate rejection",
            data.len()
        );
    }
}

/// Reads an archive back into a `name → data` map over its regular files. Directory order is not
/// significant (ISO sorts its directory records), so a map is the right equality domain.
fn read_back_map<R: EntryReader>(mut reader: R) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut map = BTreeMap::new();
    // `while let Ok(Some(..))` stops on both end-of-archive and error; a mid-stream error on our
    // own freshly written archive then surfaces as a map mismatch.
    while let Ok(Some(mut entry)) = reader.next_entry() {
        if entry.meta().kind != EntryKind::File {
            continue;
        }
        let name = entry.meta().path.to_vec();
        let mut data = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match entry.data().read_chunk(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => data.extend_from_slice(&buf[..n]),
            }
        }
        map.insert(name, data);
    }
    map
}

/// The expected `name → data` map for a normalized file set.
fn expected_map(files: &[(Vec<u8>, Vec<u8>)]) -> BTreeMap<Vec<u8>, Vec<u8>> {
    files.iter().cloned().collect()
}

/// tar round-trip: `read ∘ write = id`.
pub fn roundtrip_tar(entries: &[FuzzEntry]) {
    let files = normalize_files(entries);
    let mut writer = TarWriter::new(Vec::new());
    for (name, data) in &files {
        write_file_asserted(&mut writer, name, data, "tar");
    }
    writer
        .finish()
        .expect("tar: finish must succeed on a normalized file set");
    let bytes = writer.into_inner();
    let got = read_back_map(TarReader::new(&bytes));
    assert_eq!(got, expected_map(&files), "tar read∘write");
}

/// cpio (newc) round-trip: `read ∘ write = id`.
pub fn roundtrip_cpio(entries: &[FuzzEntry]) {
    let files = normalize_files(entries);
    let mut writer = CpioWriter::new(Vec::new());
    for (name, data) in &files {
        write_file_asserted(&mut writer, name, data, "cpio");
    }
    writer
        .finish()
        .expect("cpio: finish must succeed on a normalized file set");
    let bytes = writer.into_inner();
    let got = read_back_map(CpioReader::new(&bytes));
    assert_eq!(got, expected_map(&files), "cpio read∘write");
}

/// ar round-trip: `read ∘ write = id`.
pub fn roundtrip_ar(entries: &[FuzzEntry]) {
    let files = normalize_files(entries);
    let mut writer = ArWriter::new(Vec::new());
    for (name, data) in &files {
        write_file_asserted(&mut writer, name, data, "ar");
    }
    writer
        .finish()
        .expect("ar: finish must succeed on a normalized file set");
    let bytes = writer.into_inner();
    let got = read_back_map(ArReader::new(&bytes));
    assert_eq!(got, expected_map(&files), "ar read∘write");
}

/// 7z round-trip: `read ∘ write = id` (single-folder LZMA2 subset).
pub fn roundtrip_7z(entries: &[FuzzEntry]) {
    let files = normalize_files(entries);
    let mut writer = SevenZWriter::new(Vec::new());
    for (name, data) in &files {
        write_file_asserted(&mut writer, name, data, "7z");
    }
    writer
        .finish()
        .expect("7z: finish must succeed on a normalized file set");
    let bytes = writer.into_inner();
    let got = read_back_map(SevenZReader::new(&bytes));
    assert_eq!(got, expected_map(&files), "7z read∘write");
}

/// ISO 9660 + Joliet round-trip: `read ∘ write = id`.
pub fn roundtrip_iso(entries: &[FuzzEntry]) {
    let files = normalize_files(entries);
    let mut writer = IsoWriter::new(Vec::new());
    for (name, data) in &files {
        write_file_asserted(&mut writer, name, data, "iso");
    }
    writer
        .finish()
        .expect("iso: finish must succeed on a normalized file set");
    let bytes = writer.into_inner();
    let got = read_back_map(IsoReader::new(&bytes));
    assert_eq!(got, expected_map(&files), "iso read∘write");
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Codec targets: decode arbitrary bytes without panicking; `decode ∘ encode = id` where possible.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// Feeds arbitrary bytes to a codec's decoder with an output cap; errors are expected, panics are not.
fn codec_decode_no_panic(id: FilterId, data: &[u8]) {
    if let Some(mut decoder) = libarchive_oxide::filter::decoder(id) {
        let _ = decode_to_vec_capped(&mut decoder, data, CODEC_CAP);
    }
}

/// Asserts `decode ∘ encode = id` for a codec whose encoder is exposed via [`libarchive_oxide::filter::encoder`].
fn codec_roundtrip(id: FilterId, data: &[u8]) {
    let plain: Vec<u8> = data.iter().copied().take(CODEC_ROUNDTRIP_MAX).collect();
    let Some(mut encoder) = libarchive_oxide::filter::encoder(id) else {
        return;
    };
    let Ok(compressed) = decode_to_vec(&mut encoder, &plain) else {
        return;
    };
    let Some(mut decoder) = libarchive_oxide::filter::decoder(id) else {
        return;
    };
    // Our own encoder's output must decode back to the exact input.
    let round = decode_to_vec(&mut decoder, &compressed)
        .expect("codec: decoding our own encoder output must succeed");
    assert_eq!(round, plain, "{id:?} decode∘encode");
}

/// gzip codec: decode-no-panic + `decode ∘ encode = id`.
pub fn codec_gzip(data: &[u8]) {
    codec_decode_no_panic(FilterId::Gzip, data);
    codec_roundtrip(FilterId::Gzip, data);
}

/// zstd codec: decode-no-panic + `decode ∘ encode = id`.
pub fn codec_zstd(data: &[u8]) {
    codec_decode_no_panic(FilterId::Zstd, data);
    codec_roundtrip(FilterId::Zstd, data);
}

/// xz codec: decode-no-panic + `decode ∘ encode = id`.
pub fn codec_xz(data: &[u8]) {
    codec_decode_no_panic(FilterId::Xz, data);
    codec_roundtrip(FilterId::Xz, data);
}

/// lz4 codec: decode-no-panic + `decode ∘ encode = id`.
pub fn codec_lz4(data: &[u8]) {
    codec_decode_no_panic(FilterId::Lz4, data);
    codec_roundtrip(FilterId::Lz4, data);
}

/// Reads a `std::io::Read` to EOF under a byte cap; `None` on any read error or overflow.
fn read_capped<R: Read>(mut reader: R, cap: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Some(out),
            Ok(n) => {
                if out.len().saturating_add(n) > cap {
                    return None;
                }
                out.extend_from_slice(&buf[..n]);
            },
            Err(_) => return None,
        }
    }
}

/// Interprets `data` as a raw LZMA2 stream and decodes it under a cap (errors expected, no panic).
fn lzma2_decode_capped(data: &[u8], cap: usize) -> Option<Vec<u8>> {
    let reader =
        lzma_rust2::Lzma2Reader::new(std::io::Cursor::new(data.to_vec()), LZMA2_DICT, None);
    read_capped(reader, cap)
}

/// LZMA2-compresses `plain` (preset 6, matching the 7z writer); `None` on encoder error.
fn lzma2_encode(plain: &[u8]) -> Option<Vec<u8>> {
    let options = lzma_rust2::Lzma2Options::with_preset(6);
    let mut writer = lzma_rust2::Lzma2Writer::new(Vec::new(), options);
    writer.write_all(plain).ok()?;
    writer.finish().ok()
}

/// LZMA2 codec: decode-no-panic + `decode ∘ encode = id` (the codec behind the 7z folder).
pub fn codec_lzma2(data: &[u8]) {
    let _ = lzma2_decode_capped(data, CODEC_CAP);

    let plain: Vec<u8> = data.iter().copied().take(CODEC_ROUNDTRIP_MAX).collect();
    if let Some(compressed) = lzma2_encode(&plain) {
        let round = lzma2_decode_capped(&compressed, CODEC_CAP)
            .expect("lzma2: decoding our own encoder output must succeed");
        assert_eq!(round, plain, "lzma2 decode∘encode");
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// Dispatch + seeds: shared by the portable replay test so every target is reachable by name.
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// Every fuzz-target name, in the order the corpus directories and CI bin targets use them.
pub const TARGETS: &[&str] = &[
    "read_tar",
    "read_cpio",
    "read_ar",
    "read_zip",
    "read_7z",
    "read_iso",
    "roundtrip_tar",
    "roundtrip_cpio",
    "roundtrip_ar",
    "roundtrip_7z",
    "roundtrip_iso",
    "codec_gzip",
    "codec_zstd",
    "codec_xz",
    "codec_lz4",
    "codec_lzma2",
];

/// Runs the named target over `data`. Reader/codec targets consume the bytes directly; round-trip
/// targets interpret the bytes through `arbitrary` into a `Vec<FuzzEntry>`. Unknown names are a no-op.
///
/// This is exactly the body each `fuzz_target!` shim runs, so corpus files and replay seeds exercise
/// the same code the fuzzer does.
pub fn run_target(name: &str, data: &[u8]) {
    match name {
        "read_tar" => read_tar(data),
        "read_cpio" => read_cpio(data),
        "read_ar" => read_ar(data),
        "read_zip" => read_zip(data),
        "read_7z" => read_7z(data),
        "read_iso" => read_iso(data),
        "roundtrip_tar" => roundtrip_tar(&entries_from_bytes(data)),
        "roundtrip_cpio" => roundtrip_cpio(&entries_from_bytes(data)),
        "roundtrip_ar" => roundtrip_ar(&entries_from_bytes(data)),
        "roundtrip_7z" => roundtrip_7z(&entries_from_bytes(data)),
        "roundtrip_iso" => roundtrip_iso(&entries_from_bytes(data)),
        "codec_gzip" => codec_gzip(data),
        "codec_zstd" => codec_zstd(data),
        "codec_xz" => codec_xz(data),
        "codec_lz4" => codec_lz4(data),
        "codec_lzma2" => codec_lzma2(data),
        _ => {},
    }
}

/// Decodes a `Vec<FuzzEntry>` from raw bytes via `arbitrary` (empty on exhaustion) — the same
/// structured decoding `fuzz_target!(|entries: Vec<FuzzEntry>| ...)` performs.
fn entries_from_bytes(data: &[u8]) -> Vec<FuzzEntry> {
    let mut u = arbitrary::Unstructured::new(data);
    Vec::<FuzzEntry>::arbitrary(&mut u).unwrap_or_default()
}
