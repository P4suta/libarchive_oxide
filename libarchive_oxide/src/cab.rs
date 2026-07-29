// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Microsoft Cabinet (`.cab`) read-only, seek-native provider (RM-305).
//!
//! A bounded parser for the MSCF container: `CFHEADER`, the `CFFOLDER` table,
//! the `CFFILE` table, and the per-folder `CFDATA` blocks. `NONE` (stored) and
//! `MSZIP` (a `'CK'` prefix followed by raw DEFLATE with folder-wide history)
//! are always decoded; `cab-lzx` adds regular LZX and `cab-quantum` adds
//! Quantum method 2. Feature-disabled codecs surface as structured
//! `Unsupported`. The ordinary single-source reader also rejects
//! cross-cabinet continuation; [`CabVolumeReader`] resolves it explicitly over
//! a caller-owned bounded [`crate::advanced::VolumeSet`].
//!
//! A folder is a solid unit: the decompressed output of its `CFDATA` blocks is
//! concatenated and each file is sliced from `uoffFolderStart`. The decoder is
//! streamed one `CFDATA` block at a time (each `<= 32 KiB` uncompressed), so no
//! whole folder is ever materialized and every emitted chunk stays within the
//! 64 KiB event budget.

use std::io::{Read, Seek, SeekFrom};

#[cfg(feature = "cab-quantum")]
use compcol::quantum::Decoder as QuantumDecoder;
#[cfg(feature = "cab-quantum")]
use compcol::{Decoder as _, Error as CompcolError, Status as CompcolStatus};
#[cfg(feature = "cab-lzx")]
use libarchive_oxide_codecs::lzx::{LzxDecoder, MAX_WORKSPACE_OVERHEAD, WindowSize};
use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, ArchivePath, EntryKind, EntryMetadata, EntryTimes, ErrorKind,
    Limits, Owner, PathEncoding, Timestamp,
};
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{
    DecompressorOxide, decompress, inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
};

use crate::{ReaderEvent, StreamError};

mod volume;
pub use volume::{CabVolumeProvider, CabVolumeReader};

/// Maximum size of a streamed payload chunk in the reader's 64-bit length domain.
const BUFFER_U64: u64 = 64 * 1024;
/// Fixed `CFHEADER` bytes before any optional reserve or cabinet names.
const CAB_HEADER_SIZE: u64 = 36;
/// The MSZIP LZ77 window size; also the maximum `CFDATA` uncompressed size.
const MSZIP_WINDOW: usize = 0x8000;
/// Previous MSZIP history plus one complete non-wrapping output frame.
const MSZIP_WORKSPACE: usize = 2 * MSZIP_WINDOW;
/// Largest representable per-CFDATA reserved area.
const CFDATA_RESERVE_MAX: usize = 255;
/// CAB LZX emits one independently-sized output frame per `CFDATA` block.
const LZX_FRAME: usize = 0x8000;
/// Smallest and largest CAB LZX window exponents.
const LZX_MIN_WINDOW_BITS: u8 = 15;
const LZX_MAX_WINDOW_BITS: u8 = 21;
/// CAB Quantum uses the same 32 KiB output frame size as CFDATA.
const QUANTUM_FRAME: usize = 0x8000;
/// CAB SDK bounds for Quantum's out-of-band window exponent.
const QUANTUM_MIN_WINDOW_BITS: u8 = 10;
const QUANTUM_MAX_WINDOW_BITS: u8 = 21;
/// CAB SDK bounds for the encoder level stored in `typeCompress`.
const QUANTUM_MIN_LEVEL: u8 = 1;
const QUANTUM_MAX_LEVEL: u8 = 7;
/// Conservative bound for `compcol`'s retained compressed-input allocation,
/// fixed arithmetic models, per-packet snapshot, decoder state, and allocation
/// bookkeeping. The dictionary is charged separately from this workspace.
#[cfg(feature = "cab-quantum")]
const QUANTUM_WORKSPACE_OVERHEAD: usize = 80 * 1024;
/// The `CFHEADER` `RESERVE_PRESENT` flag.
const FLAG_RESERVE_PRESENT: u16 = 0x0004;
/// The `CFHEADER` `PREV_CABINET` flag.
const FLAG_PREV: u16 = 0x0001;
/// The `CFHEADER` `NEXT_CABINET` flag.
const FLAG_NEXT: u16 = 0x0002;
/// The `CFFILE` "name is UTF-8" attribute bit.
const ATTR_NAME_UTF8: u16 = 0x80;

/// The compression method of a folder (`typeCompress & 0x000F`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    /// Stored: each `CFDATA` payload is the literal decompressed bytes.
    Store,
    /// MSZIP: a `'CK'` prefix then a raw-DEFLATE stream, window carried across blocks.
    Mszip,
    /// Quantum with the validated CAB window exponent.
    Quantum { window_bits: u8 },
    /// LZX with the validated CAB window exponent.
    Lzx { window_bits: u8 },
    /// An unknown method — metadata is listed, payload is unsupported.
    Unsupported(u16),
}

/// A parsed `CFFOLDER` record.
#[derive(Debug, Clone, Copy)]
struct CabFolder {
    /// Absolute offset of this folder's first `CFDATA` block.
    data_offset: u64,
    /// Number of `CFDATA` blocks in the folder.
    num_data: u16,
    /// The folder's compression method.
    method: Method,
    /// Sum of this folder's declared `CFDATA` output, pre-scanned for framed codecs.
    decoded_size: Option<u64>,
}

/// A parsed `CFFILE` record.
#[derive(Debug)]
struct CabFile {
    /// Path with backslashes normalized to `/`.
    name: Vec<u8>,
    /// Uncompressed file size (`cbFile`).
    size: u64,
    /// Byte offset of the file within its folder's decompressed stream.
    folder_offset: u64,
    /// Index into the folder table.
    folder_index: usize,
    /// Cross-cabinet continuation encoded by `iFolder`.
    continuation: FileContinuation,
    /// Original DOS date field, retained for a lossless logical-CAB view.
    date: u16,
    /// Original DOS time field, retained for a lossless logical-CAB view.
    time: u16,
    /// Original attributes, retained for a lossless logical-CAB view.
    attribs: u16,
    /// Modification time from the DOS date/time fields.
    mtime: Option<Timestamp>,
    /// Whether the name is UTF-8 (else code-page bytes preserved verbatim).
    is_utf8: bool,
}

impl CabFile {
    /// Fallibly duplicates attacker-controlled path storage before the reader
    /// mutably advances its decoder state.
    fn try_clone(&self) -> core::result::Result<Self, StreamError> {
        let mut name = Vec::new();
        name.try_reserve_exact(self.name.len())
            .map_err(|_| cab_error(ErrorKind::Limit, "CAB entry path allocation failed"))?;
        name.extend_from_slice(&self.name);
        Ok(Self {
            name,
            size: self.size,
            folder_offset: self.folder_offset,
            folder_index: self.folder_index,
            continuation: self.continuation,
            date: self.date,
            time: self.time,
            attribs: self.attribs,
            mtime: self.mtime,
            is_utf8: self.is_utf8,
        })
    }
}

/// Meaning of a `CFFILE::iFolder` continuation sentinel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileContinuation {
    None,
    FromPrevious,
    ToNext,
    PreviousAndNext,
}

impl FileContinuation {
    const fn starts_before(self) -> bool {
        matches!(self, Self::FromPrevious | Self::PreviousAndNext)
    }

    const fn continues_after(self) -> bool {
        matches!(self, Self::ToNext | Self::PreviousAndNext)
    }
}

/// The streaming decoder for one solid folder.
struct FolderStream {
    /// Which folder this stream decodes.
    folder_index: usize,
    /// The folder's compression method.
    method: Method,
    /// Number of `CFDATA` blocks in the folder.
    num_blocks: u16,
    /// Index of the next `CFDATA` block to decode.
    next_block: u16,
    /// Absolute file offset of the next `CFDATA` block header.
    block_cursor: u64,
    /// Per-`CFDATA` reserved-field size from the header.
    reserve_data: u8,
    /// Whether zero-sized split records may continue in the following physical record.
    allow_spanning: bool,
    /// Total decompressed bytes already consumed by the reader.
    produced: u64,
    /// Decompressed bytes of the current block awaiting consumption.
    buf: Vec<u8>,
    /// Consumption cursor within [`FolderStream::buf`].
    buf_pos: usize,
    /// Valid-history prefix plus non-wrapping output space for MSZIP.
    mszip_buffer: Vec<u8>,
    /// Number of valid history bytes in [`FolderStream::mszip_buffer`].
    mszip_history_len: usize,
    /// Stateful LZX decoder; history, trees, and E8 state span `CFDATA` blocks.
    #[cfg(feature = "cab-lzx")]
    lzx: Option<LzxStream>,
    /// Stateful Quantum decoder; window and arithmetic models span `CFDATA` blocks.
    #[cfg(feature = "cab-quantum")]
    quantum: Option<QuantumStream>,
}

/// Adapter state around the audited regular-LZX fork.
#[cfg(feature = "cab-lzx")]
struct LzxStream {
    decoder: LzxDecoder,
}

/// Adapter state around `compcol`'s safe streaming Quantum decoder.
#[cfg(feature = "cab-quantum")]
struct QuantumStream {
    decoder: QuantumDecoder,
    /// Declared output not yet emitted by the incremental decoder.
    declared_remaining: u64,
    /// Whether bounded EOF draining reached the CAB-declared folder length.
    finished: bool,
}

/// The reader's payload state machine (mirrors the 7z reader's phases).
#[derive(Debug, Clone, Copy)]
enum CabPhase {
    /// Between entries.
    Idle,
    /// Streaming a file payload with this many bytes still to emit.
    Data { remaining: u64 },
    /// The open entry uses an unavailable codec or unresolved single-source
    /// continuation.
    Unsupported,
    /// The open entry's payload is exhausted.
    EndEntry,
    /// The archive is fully consumed.
    Done,
    /// A non-recoverable parse, resource, or I/O error poisoned decoder state.
    Failed { kind: ErrorKind },
}

/// Seek-capable read-only Microsoft Cabinet reader.
pub(crate) struct CabSeekReader<R> {
    input: R,
    limits: Limits,
    image_length: u64,
    archive_metadata: Option<ArchiveMetadata>,
    folders: Vec<CabFolder>,
    files: Vec<CabFile>,
    next_file: usize,
    phase: CabPhase,
    folder_stream: Option<FolderStream>,
    reserve_data: u8,
    allow_spanning: bool,
    event_data: Vec<u8>,
    decoded_total: u64,
}

impl<R> std::fmt::Debug for CabSeekReader<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CabSeekReader")
            .field("folders", &self.folders.len())
            .field("files", &self.files.len())
            .field("next_file", &self.next_file)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl<R: Read + Seek> CabSeekReader<R> {
    pub(crate) fn new(input: R, limits: Limits) -> core::result::Result<Self, StreamError> {
        Self::new_with_spanning(input, limits, false)
    }

    fn new_with_spanning(
        mut input: R,
        limits: Limits,
        allow_spanning: bool,
    ) -> core::result::Result<Self, StreamError> {
        let (header, image_length) = read_single_cab_header(&mut input)?;
        let coff_files = u64::from(u32::from_le_bytes([
            header[16], header[17], header[18], header[19],
        ]));
        let num_folders = u16::from_le_bytes([header[26], header[27]]);
        let num_files = u16::from_le_bytes([header[28], header[29]]);
        let flags = u16::from_le_bytes([header[30], header[31]]);

        if coff_files == 0 || coff_files >= image_length {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CFFILE table offset is outside the cabinet",
            ));
        }
        if limits
            .entries()
            .is_some_and(|maximum| u64::from(num_files) > maximum)
        {
            return Err(cab_error(
                ErrorKind::Limit,
                "file count exceeds configured limit",
            ));
        }

        let (reserve_folder, reserve_data) = if flags & FLAG_RESERVE_PRESENT != 0 {
            ensure_stream_extent(
                &mut input,
                4,
                image_length,
                "CAB reserve descriptor extends past cbCabinet",
            )?;
            let mut reserve = [0_u8; 4];
            input.read_exact(&mut reserve).map_err(StreamError::io)?;
            let cb_header = u16::from_le_bytes([reserve[0], reserve[1]]);
            let after_reserve = CAB_HEADER_SIZE
                .checked_add(4)
                .and_then(|value| value.checked_add(u64::from(cb_header)))
                .ok_or_else(|| cab_error(ErrorKind::Malformed, "CAB reserve extent overflow"))?;
            if after_reserve > image_length {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CAB header reserve extends past cbCabinet",
                ));
            }
            input
                .seek(SeekFrom::Start(after_reserve))
                .map_err(StreamError::io)?;
            (reserve[2], reserve[3])
        } else {
            (0_u8, 0_u8)
        };

        if flags & FLAG_PREV != 0 {
            skip_cstring(&mut input, limits, image_length)?;
            skip_cstring(&mut input, limits, image_length)?;
        }
        if flags & FLAG_NEXT != 0 {
            skip_cstring(&mut input, limits, image_length)?;
            skip_cstring(&mut input, limits, image_length)?;
        }

        let folder_table = input.stream_position().map_err(StreamError::io)?;
        let (folders, folder_metadata) = read_folders(
            &mut input,
            folder_table,
            num_folders,
            reserve_folder,
            reserve_data,
            image_length,
            limits,
            allow_spanning,
        )?;
        let file_limits = limits.with_metadata_bytes(
            limits
                .metadata_bytes()
                .map(|maximum| maximum - folder_metadata),
        );
        let files = read_files(
            &mut input,
            coff_files,
            num_files,
            &folders,
            image_length,
            file_limits,
        )?;

        Ok(Self {
            input,
            limits,
            image_length,
            archive_metadata: Some(ArchiveMetadata::new()),
            folders,
            files,
            next_file: 0,
            phase: CabPhase::Idle,
            folder_stream: None,
            reserve_data,
            allow_spanning,
            event_data: Vec::new(),
            decoded_total: 0,
        })
    }

    pub(crate) fn next_event(&mut self) -> core::result::Result<ReaderEvent<'_>, StreamError> {
        self.event_data.clear();
        if let CabPhase::Failed { kind } = self.phase {
            return Err(cab_error(
                kind,
                "CAB reader is poisoned after a previous error",
            ));
        }
        if let Some(metadata) = self.archive_metadata.take() {
            return Ok(ReaderEvent::ArchiveMetadata(metadata));
        }
        loop {
            match self.phase {
                CabPhase::Idle => {
                    let Some(file) = self.files.get(self.next_file) else {
                        self.phase = CabPhase::Done;
                        return Ok(ReaderEvent::Done);
                    };
                    let file = match file.try_clone() {
                        Ok(file) => file,
                        Err(error) => {
                            self.phase = CabPhase::Failed { kind: error.kind() };
                            return Err(error);
                        },
                    };
                    let metadata = match self.prepare_file(file) {
                        Ok(metadata) => metadata,
                        Err(error) => {
                            self.phase = CabPhase::Failed { kind: error.kind() };
                            return Err(error);
                        },
                    };
                    // `get(self.next_file)` succeeded, so incrementing cannot
                    // overflow `usize`.
                    self.next_file += 1;
                    return Ok(ReaderEvent::Entry(metadata));
                },
                CabPhase::Data { remaining: 0 } => {
                    self.phase = CabPhase::EndEntry;
                },
                CabPhase::Data { remaining } => {
                    let want = usize::try_from(remaining.min(BUFFER_U64)).map_err(|_| {
                        cab_error(ErrorKind::Limit, "payload chunk exceeds address space")
                    })?;
                    let count = match self.pull_into_event(want) {
                        Ok(count) => count,
                        Err(error) => {
                            self.phase = CabPhase::Failed { kind: error.kind() };
                            return Err(error);
                        },
                    };
                    if count == 0 {
                        self.phase = CabPhase::Failed {
                            kind: ErrorKind::Malformed,
                        };
                        return Err(cab_error(
                            ErrorKind::Malformed,
                            "folder ended before the declared file size",
                        ));
                    }
                    let count = u64::try_from(count)
                        .map_err(|_| cab_error(ErrorKind::Limit, "payload count exceeds u64"))?;
                    self.phase = CabPhase::Data {
                        remaining: remaining - count,
                    };
                    return Ok(ReaderEvent::Data(&self.event_data));
                },
                CabPhase::Unsupported => {
                    return Err(cab_error(
                        ErrorKind::Unsupported,
                        "folder compression method is unsupported",
                    ));
                },
                CabPhase::EndEntry => {
                    self.phase = CabPhase::Idle;
                    return Ok(ReaderEvent::EndEntry);
                },
                CabPhase::Done => return Ok(ReaderEvent::Done),
                CabPhase::Failed { kind } => {
                    return Err(cab_error(
                        kind,
                        "CAB reader is poisoned after a previous error",
                    ));
                },
            }
        }
    }

    pub(crate) fn skip_entry(&mut self) -> core::result::Result<(), StreamError> {
        match self.phase {
            CabPhase::Data { mut remaining } => {
                while remaining != 0 {
                    let step = match self.discard_decoded(remaining) {
                        Ok(step) => step,
                        Err(error) => {
                            self.phase = CabPhase::Failed { kind: error.kind() };
                            return Err(error);
                        },
                    };
                    if step == 0 {
                        self.phase = CabPhase::Failed {
                            kind: ErrorKind::Malformed,
                        };
                        return Err(cab_error(
                            ErrorKind::Malformed,
                            "folder ended while skipping a file",
                        ));
                    }
                    remaining -= step;
                }
                self.phase = CabPhase::EndEntry;
                Ok(())
            },
            CabPhase::Unsupported => {
                self.phase = CabPhase::EndEntry;
                Ok(())
            },
            CabPhase::EndEntry => Ok(()),
            CabPhase::Failed { kind } => Err(cab_error(
                kind,
                "CAB reader is poisoned after a previous error",
            )),
            CabPhase::Idle | CabPhase::Done => Err(cab_error(
                ErrorKind::Protocol,
                "skip_entry called without an open entry",
            )),
        }
    }

    pub(crate) fn into_inner(self) -> R {
        self.input
    }

    pub(crate) fn source_ref(&self) -> &R {
        &self.input
    }

    /// Positions the folder decoder and payload phase for `file`, then builds its metadata.
    #[allow(clippy::if_not_else)] // Continuations take the intentionally small unsupported branch.
    fn prepare_file(&mut self, file: CabFile) -> core::result::Result<EntryMetadata, StreamError> {
        if file.continuation != FileContinuation::None {
            self.phase = CabPhase::Unsupported;
        } else {
            let folder = self
                .folders
                .get(file.folder_index)
                .copied()
                .ok_or_else(|| {
                    cab_error(ErrorKind::Malformed, "file references a missing folder")
                })?;
            match folder.method {
                Method::Unsupported(_) => self.phase = CabPhase::Unsupported,
                #[cfg(not(feature = "cab-quantum"))]
                Method::Quantum { .. } => self.phase = CabPhase::Unsupported,
                #[cfg(not(feature = "cab-lzx"))]
                Method::Lzx { .. } => self.phase = CabPhase::Unsupported,
                Method::Store | Method::Mszip => {
                    self.ensure_folder_stream(file.folder_index, folder)?;
                    self.drain_to(file.folder_offset)?;
                    self.phase = CabPhase::Data {
                        remaining: file.size,
                    };
                },
                #[cfg(feature = "cab-quantum")]
                Method::Quantum { .. } => {
                    self.ensure_folder_stream(file.folder_index, folder)?;
                    self.drain_to(file.folder_offset)?;
                    self.phase = CabPhase::Data {
                        remaining: file.size,
                    };
                },
                #[cfg(feature = "cab-lzx")]
                Method::Lzx { .. } => {
                    self.ensure_folder_stream(file.folder_index, folder)?;
                    self.drain_to(file.folder_offset)?;
                    self.phase = CabPhase::Data {
                        remaining: file.size,
                    };
                },
            }
        }

        let path = if file.is_utf8 {
            ArchivePath::try_from_encoded(file.name, PathEncoding::Utf8)?
        } else {
            ArchivePath::from_bytes(file.name)
        };
        let times = EntryTimes {
            modified: file.mtime,
            ..EntryTimes::default()
        };
        Ok(EntryMetadata::builder(EntryKind::File, path)
            .size(Some(file.size))
            .mode(Some(0o644))
            .owner(Owner::default())
            .times(times)
            .build())
    }

    /// Installs a fresh [`FolderStream`] for `index` unless the current one already decodes it.
    fn ensure_folder_stream(
        &mut self,
        index: usize,
        folder: CabFolder,
    ) -> core::result::Result<(), StreamError> {
        if self
            .folder_stream
            .as_ref()
            .is_some_and(|stream| stream.folder_index == index)
        {
            return Ok(());
        }
        // A folder switch is irreversible because CFFILE offsets must be
        // monotonic within a folder. Drop the old codec before constructing
        // the new one so two dictionaries never overlap their budget.
        drop(self.folder_stream.take());

        let mut mszip_buffer = Vec::new();
        if folder.method == Method::Mszip {
            if self
                .limits
                .codec_memory()
                .is_some_and(|maximum| MSZIP_WORKSPACE > maximum)
            {
                return Err(cab_error(
                    ErrorKind::Limit,
                    "MSZIP history and output workspace exceed codec-memory limit",
                ));
            }
            mszip_buffer
                .try_reserve_exact(MSZIP_WORKSPACE)
                .map_err(|_| cab_error(ErrorKind::Limit, "MSZIP history allocation failed"))?;
            mszip_buffer.resize(MSZIP_WORKSPACE, 0);
        }
        #[cfg(feature = "cab-lzx")]
        let lzx = match folder.method {
            Method::Lzx { window_bits } => {
                folder.decoded_size.ok_or_else(|| {
                    cab_error(
                        ErrorKind::Unsupported,
                        "spanning LZX folder requires another cabinet",
                    )
                })?;
                let window = lzx_window_size(window_bits)?;
                Some(LzxStream {
                    decoder: LzxDecoder::new(window).map_err(|_| {
                        cab_error(ErrorKind::Limit, "LZX decoder allocation failed")
                    })?,
                })
            },
            Method::Store | Method::Mszip | Method::Quantum { .. } | Method::Unsupported(_) => None,
        };
        #[cfg(feature = "cab-quantum")]
        let quantum = match folder.method {
            Method::Quantum { window_bits } => {
                folder.decoded_size.ok_or_else(|| {
                    cab_error(
                        ErrorKind::Unsupported,
                        "spanning Quantum folder requires another cabinet",
                    )
                })?;
                Some(QuantumStream {
                    decoder: QuantumDecoder::with_window_bits(u32::from(window_bits)).map_err(
                        |_| cab_error(ErrorKind::Malformed, "invalid CAB Quantum window exponent"),
                    )?,
                    declared_remaining: 0,
                    finished: false,
                })
            },
            Method::Store | Method::Mszip | Method::Lzx { .. } | Method::Unsupported(_) => None,
        };
        self.folder_stream = Some(FolderStream {
            folder_index: index,
            method: folder.method,
            num_blocks: folder.num_data,
            next_block: 0,
            block_cursor: folder.data_offset,
            reserve_data: self.reserve_data,
            allow_spanning: self.allow_spanning,
            produced: 0,
            buf: Vec::new(),
            buf_pos: 0,
            mszip_buffer,
            mszip_history_len: 0,
            #[cfg(feature = "cab-lzx")]
            lzx,
            #[cfg(feature = "cab-quantum")]
            quantum,
        });
        Ok(())
    }

    /// Advances the folder decoder to `offset`, discarding intervening bytes.
    fn drain_to(&mut self, offset: u64) -> core::result::Result<(), StreamError> {
        let produced = self
            .folder_stream
            .as_ref()
            .map_or(0, |stream| stream.produced);
        if offset < produced {
            return Err(cab_error(
                ErrorKind::Malformed,
                "file offsets are not monotonic within a folder",
            ));
        }
        let mut remaining = offset - produced;
        while remaining != 0 {
            let step = self.discard_decoded(remaining)?;
            if step == 0 {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "folder ended before a file offset",
                ));
            }
            remaining -= step;
        }
        Ok(())
    }

    /// Copies up to `max` decoded bytes into `event_data`, returning the count.
    fn pull_into_event(&mut self, max: usize) -> core::result::Result<usize, StreamError> {
        if !self.ensure_block()? {
            return Ok(0);
        }
        let stream = self
            .folder_stream
            .as_mut()
            .ok_or_else(|| cab_error(ErrorKind::Protocol, "folder stream disappeared"))?;
        let available = stream.buf.len() - stream.buf_pos;
        let count = available.min(max);
        self.event_data.try_reserve_exact(count).map_err(|_| {
            cab_error(
                ErrorKind::Limit,
                "CAB event buffer allocation exceeds address space",
            )
        })?;
        self.event_data
            .extend_from_slice(&stream.buf[stream.buf_pos..stream.buf_pos + count]);
        stream.buf_pos += count;
        let count_u64 = u64::try_from(count)
            .map_err(|_| cab_error(ErrorKind::Limit, "payload count exceeds u64"))?;
        stream.produced = stream
            .produced
            .checked_add(count_u64)
            .ok_or_else(|| cab_error(ErrorKind::Limit, "folder position overflow"))?;
        Ok(count)
    }

    /// Advances the folder decoder by up to `max` bytes without copying, returning the count.
    fn discard_decoded(&mut self, max: u64) -> core::result::Result<u64, StreamError> {
        if !self.ensure_block()? {
            return Ok(0);
        }
        let stream = self
            .folder_stream
            .as_mut()
            .ok_or_else(|| cab_error(ErrorKind::Protocol, "folder stream disappeared"))?;
        let available = u64::try_from(stream.buf.len() - stream.buf_pos)
            .map_err(|_| cab_error(ErrorKind::Limit, "decoded frame exceeds u64"))?;
        let step = available.min(max);
        let advance = usize::try_from(step)
            .map_err(|_| cab_error(ErrorKind::Limit, "skip step exceeds address space"))?;
        stream.buf_pos += advance;
        stream.produced += step;
        Ok(step)
    }

    /// Ensures the current folder block buffer has unconsumed bytes, decoding the next
    /// `CFDATA` block when needed. Returns `false` once the folder is fully decoded.
    fn ensure_block(&mut self) -> core::result::Result<bool, StreamError> {
        loop {
            let needs_quantum_finish = {
                let stream = self
                    .folder_stream
                    .as_ref()
                    .ok_or_else(|| cab_error(ErrorKind::Protocol, "no folder stream is open"))?;
                if stream.buf_pos < stream.buf.len() {
                    return Ok(true);
                }
                let folder_end = stream.next_block >= stream.num_blocks;
                let needs_finish = folder_end && needs_quantum_finish(stream);
                if folder_end && !needs_finish {
                    return Ok(false);
                }
                needs_finish
            };
            #[cfg(not(feature = "cab-quantum"))]
            let _ = needs_quantum_finish;
            // The current frame has been fully consumed, and no caller can
            // retain an event borrow across this `&mut self` call. Release
            // both staging allocations before the next payload and decoded
            // frame coexist, preserving `validate_cfdata_in_flight`'s bound.
            self.event_data = Vec::new();
            let Self {
                input,
                folder_stream,
                image_length,
                limits,
                decoded_total,
                ..
            } = self;
            let stream = folder_stream
                .as_mut()
                .ok_or_else(|| cab_error(ErrorKind::Protocol, "no folder stream is open"))?;
            stream.buf = Vec::new();
            stream.buf_pos = 0;
            #[cfg(feature = "cab-quantum")]
            let produced = if needs_quantum_finish {
                quantum_finish_folder(stream)?
            } else {
                decode_next_block(input, stream, *image_length, *limits, *decoded_total)?
            };
            #[cfg(not(feature = "cab-quantum"))]
            let produced =
                decode_next_block(input, stream, *image_length, *limits, *decoded_total)?;
            let produced_u64 = u64::try_from(produced)
                .map_err(|_| cab_error(ErrorKind::Limit, "decoded frame exceeds address space"))?;
            *decoded_total = decoded_total
                .checked_add(produced_u64)
                .ok_or_else(|| cab_error(ErrorKind::Limit, "decoded total overflow"))?;
        }
    }
}

/// Whether Quantum still owes container-declared output after its final
/// CFDATA input. Feature-off builds always return false without codec state.
fn needs_quantum_finish(stream: &FolderStream) -> bool {
    #[cfg(feature = "cab-quantum")]
    {
        stream
            .quantum
            .as_ref()
            .is_some_and(|state| !state.finished && state.declared_remaining != 0)
    }
    #[cfg(not(feature = "cab-quantum"))]
    {
        let _ = stream;
        false
    }
}

/// Reads the fixed header and turns `cbCabinet` into the sole CAB boundary.
/// A larger backing object is valid, but its trailing bytes stay invisible to
/// every parser and decoder extent check.
fn read_single_cab_header<R: Read + Seek>(
    input: &mut R,
) -> core::result::Result<([u8; 36], u64), StreamError> {
    let source_length = input.seek(SeekFrom::End(0)).map_err(StreamError::io)?;
    if source_length < CAB_HEADER_SIZE {
        return Err(cab_error(
            ErrorKind::Malformed,
            "cabinet source is shorter than the fixed CFHEADER",
        ));
    }
    input.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;

    let mut header = [0_u8; 36];
    input.read_exact(&mut header).map_err(StreamError::io)?;
    if &header[0..4] != b"MSCF" {
        return Err(cab_error(ErrorKind::Malformed, "bad MSCF signature"));
    }
    let image_length = u64::from(u32::from_le_bytes([
        header[8], header[9], header[10], header[11],
    ]));
    if image_length < CAB_HEADER_SIZE {
        return Err(cab_error(
            ErrorKind::Malformed,
            "cbCabinet is shorter than the fixed CAB header",
        ));
    }
    if image_length > source_length {
        return Err(cab_error(
            ErrorKind::Malformed,
            "cabinet source is shorter than cbCabinet",
        ));
    }
    Ok((header, image_length))
}

/// Reads the `CFFOLDER` table starting at `offset`.
#[allow(clippy::too_many_arguments)]
fn read_folders<R: Read + Seek>(
    input: &mut R,
    offset: u64,
    count: u16,
    reserve_folder: u8,
    reserve_data: u8,
    image_length: u64,
    limits: Limits,
    allow_spanning: bool,
) -> core::result::Result<(Vec<CabFolder>, usize), StreamError> {
    let folder_count = usize::from(count);
    let folder_metadata = folder_count
        .checked_mul(core::mem::size_of::<CabFolder>())
        .ok_or_else(|| cab_error(ErrorKind::Limit, "folder metadata accounting overflow"))?;
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| folder_metadata > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "folder table exceeds configured metadata limit",
        ));
    }
    input
        .seek(SeekFrom::Start(offset))
        .map_err(StreamError::io)?;
    let mut folders = Vec::new();
    folders
        .try_reserve_exact(folder_count)
        .map_err(|_| cab_error(ErrorKind::Limit, "folder table allocation failed"))?;
    for _ in 0..count {
        ensure_stream_extent(
            input,
            8_u64
                .checked_add(u64::from(reserve_folder))
                .ok_or_else(|| {
                    cab_error(ErrorKind::Malformed, "CFFOLDER record extent overflow")
                })?,
            image_length,
            "CFFOLDER record extends past cbCabinet",
        )?;
        let mut record = [0_u8; 8];
        input.read_exact(&mut record).map_err(StreamError::io)?;
        let data_offset = u64::from(u32::from_le_bytes([
            record[0], record[1], record[2], record[3],
        ]));
        let num_data = u16::from_le_bytes([record[4], record[5]]);
        let type_compress = u16::from_le_bytes([record[6], record[7]]);
        if data_offset >= image_length {
            return Err(cab_error(
                ErrorKind::Malformed,
                "folder data offset is outside the cabinet",
            ));
        }
        let method = parse_folder_method(type_compress, limits)?;
        folders.push(CabFolder {
            data_offset,
            num_data,
            method,
            decoded_size: None,
        });
        if reserve_folder != 0 {
            input
                .seek(SeekFrom::Current(i64::from(reserve_folder)))
                .map_err(StreamError::io)?;
        }
    }

    scan_folder_outputs(
        input,
        &mut folders,
        reserve_data,
        image_length,
        limits,
        allow_spanning,
    )?;
    Ok((folders, folder_metadata))
}

/// Pre-scans framed folders so their output and header-walk costs are
/// validated before any dictionary or payload staging allocation.
fn scan_folder_outputs<R: Read + Seek>(
    input: &mut R,
    folders: &mut [CabFolder],
    reserve_data: u8,
    image_length: u64,
    limits: Limits,
    allow_spanning: bool,
) -> core::result::Result<(), StreamError> {
    validate_folder_record_extents(input, folders, reserve_data, image_length, allow_spanning)?;
    let mut lzx_decoded_total = 0_u64;
    for folder in folders.iter_mut() {
        if matches!(folder.method, Method::Lzx { .. }) {
            let decoded_size = scan_lzx_folder(
                input,
                folder.data_offset,
                folder.num_data,
                reserve_data,
                image_length,
                limits,
                allow_spanning,
            )?;
            folder.decoded_size = decoded_size;
            if let Some(size) = decoded_size {
                lzx_decoded_total = lzx_decoded_total.checked_add(size).ok_or_else(|| {
                    cab_error(ErrorKind::Limit, "LZX decoded-total accounting overflow")
                })?;
            }
        }
    }
    #[cfg(feature = "cab-quantum")]
    let mut quantum_decoded_total = 0_u64;
    for folder in folders.iter_mut() {
        if matches!(folder.method, Method::Quantum { .. }) {
            let decoded_size = scan_quantum_folder(
                input,
                folder.data_offset,
                folder.num_data,
                reserve_data,
                image_length,
                limits,
                allow_spanning,
            )?;
            folder.decoded_size = decoded_size;
            #[cfg(feature = "cab-quantum")]
            if let Some(size) = decoded_size {
                quantum_decoded_total =
                    quantum_decoded_total.checked_add(size).ok_or_else(|| {
                        cab_error(
                            ErrorKind::Limit,
                            "Quantum decoded-total accounting overflow",
                        )
                    })?;
            }
        }
    }
    #[cfg(feature = "cab-lzx")]
    if limits
        .decoded_total()
        .is_some_and(|maximum| lzx_decoded_total > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "LZX folder output exceeds configured decoded-total limit",
        ));
    }
    #[cfg(feature = "cab-quantum")]
    if limits
        .decoded_total()
        .is_some_and(|maximum| quantum_decoded_total > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "Quantum folder output exceeds configured decoded-total limit",
        ));
    }
    Ok(())
}

/// Bounds and walks every claimed CFDATA record, irrespective of compression
/// method, then rejects overlapping folder extents. This keeps Store/MSZIP and
/// feature-disabled codecs under the same open-time work and extent checks as
/// LZX/Quantum.
fn validate_folder_record_extents<R: Read + Seek>(
    input: &mut R,
    folders: &[CabFolder],
    reserve_data: u8,
    image_length: u64,
    allow_spanning: bool,
) -> core::result::Result<(), StreamError> {
    let claimed_records = folders.iter().try_fold(0_u64, |total, folder| {
        total
            .checked_add(u64::from(folder.num_data))
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CFDATA scan accounting overflow"))
    })?;
    let minimum_record = 8_u64
        .checked_add(u64::from(reserve_data))
        .ok_or_else(|| cab_error(ErrorKind::Malformed, "CFDATA header extent overflow"))?;
    if claimed_records > image_length / minimum_record {
        return Err(cab_error(
            ErrorKind::Limit,
            "aggregate CFDATA scan work exceeds the cabinet extent",
        ));
    }

    let mut extents = Vec::<(u64, u64)>::new();
    extents
        .try_reserve_exact(folders.len())
        .map_err(|_| cab_error(ErrorKind::Limit, "CFDATA extent index allocation failed"))?;
    for folder in folders {
        let mut cursor = folder.data_offset;
        let mut pending_split = false;
        for _ in 0..folder.num_data {
            input
                .seek(SeekFrom::Start(cursor))
                .map_err(StreamError::io)?;
            ensure_stream_extent(
                input,
                minimum_record,
                image_length,
                "CFDATA header extends past cbCabinet",
            )?;
            let mut header = [0_u8; 8];
            input.read_exact(&mut header).map_err(StreamError::io)?;
            let cb_data = u64::from(u16::from_le_bytes([header[4], header[5]]));
            let cb_uncomp = usize::from(u16::from_le_bytes([header[6], header[7]]));
            if cb_uncomp > MSZIP_WINDOW {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CFDATA uncompressed size exceeds 32 KiB",
                ));
            }
            pending_split = cb_uncomp == 0;
            cursor = cursor
                .checked_add(minimum_record)
                .and_then(|value| value.checked_add(cb_data))
                .ok_or_else(|| cab_error(ErrorKind::Malformed, "CFDATA extent overflow"))?;
            if cursor > image_length {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CFDATA record extends past cbCabinet",
                ));
            }
        }
        if allow_spanning && pending_split {
            return Err(cab_error(
                ErrorKind::Malformed,
                "logical CAB folder ends in an incomplete split CFDATA",
            ));
        }
        if folder.num_data != 0 {
            extents.push((folder.data_offset, cursor));
        }
    }

    extents.sort_unstable_by_key(|extent| extent.0);
    for adjacent in extents.windows(2) {
        if adjacent[0].1 > adjacent[1].0 {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CAB folder CFDATA extents overlap",
            ));
        }
    }
    Ok(())
}

/// Parses a `CFFOLDER::typeCompress` value without discarding codec settings.
fn parse_folder_method(
    type_compress: u16,
    limits: Limits,
) -> core::result::Result<Method, StreamError> {
    #[cfg(not(any(feature = "cab-lzx", feature = "cab-quantum")))]
    let _ = limits;
    match type_compress & 0x000F {
        0 => Ok(Method::Store),
        1 => Ok(Method::Mszip),
        2 => {
            if type_compress & 0xE000 != 0 {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CAB Quantum typeCompress has reserved high bits",
                ));
            }
            let level = u8::try_from((type_compress >> 4) & 0x0F)
                .map_err(|_| cab_error(ErrorKind::Malformed, "invalid CAB Quantum level"))?;
            if !(QUANTUM_MIN_LEVEL..=QUANTUM_MAX_LEVEL).contains(&level) {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CAB Quantum level is outside 1..=7",
                ));
            }
            let window_bits = u8::try_from((type_compress >> 8) & 0x1F).map_err(|_| {
                cab_error(ErrorKind::Malformed, "invalid CAB Quantum window exponent")
            })?;
            if !(QUANTUM_MIN_WINDOW_BITS..=QUANTUM_MAX_WINDOW_BITS).contains(&window_bits) {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CAB Quantum window exponent is outside 10..=21",
                ));
            }
            #[cfg(feature = "cab-quantum")]
            validate_quantum_codec_memory(window_bits, limits)?;
            Ok(Method::Quantum { window_bits })
        },
        3 => {
            if type_compress & 0xE000 != 0 {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CAB LZX typeCompress has reserved high bits",
                ));
            }
            let window_bits = u8::try_from((type_compress >> 8) & 0x1F)
                .map_err(|_| cab_error(ErrorKind::Malformed, "invalid CAB LZX window exponent"))?;
            if !(LZX_MIN_WINDOW_BITS..=LZX_MAX_WINDOW_BITS).contains(&window_bits) {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "CAB LZX window exponent is outside 15..=21",
                ));
            }
            #[cfg(feature = "cab-lzx")]
            validate_lzx_codec_memory(window_bits, limits)?;
            Ok(Method::Lzx { window_bits })
        },
        other => Ok(Method::Unsupported(other)),
    }
}

/// Charges `compcol`'s archive-declared dictionary and fixed Quantum state
/// before its first decode call can allocate the sliding window.
#[cfg(feature = "cab-quantum")]
fn validate_quantum_codec_memory(
    window_bits: u8,
    limits: Limits,
) -> core::result::Result<(), StreamError> {
    let dictionary = 1_usize
        .checked_shl(u32::from(window_bits))
        .ok_or_else(|| cab_error(ErrorKind::Limit, "Quantum window exceeds address space"))?;
    let required = dictionary
        .checked_add(QUANTUM_WORKSPACE_OVERHEAD)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "Quantum workspace accounting overflow"))?;
    if limits
        .codec_memory()
        .is_some_and(|maximum| required > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "Quantum window and workspace exceed configured codec-memory limit",
        ));
    }
    Ok(())
}

/// Maps CAB's validated window exponent to the audited decoder's value type.
#[cfg(feature = "cab-lzx")]
fn lzx_window_size(window_bits: u8) -> core::result::Result<WindowSize, StreamError> {
    match window_bits {
        15 => Ok(WindowSize::KB32),
        16 => Ok(WindowSize::KB64),
        17 => Ok(WindowSize::KB128),
        18 => Ok(WindowSize::KB256),
        19 => Ok(WindowSize::KB512),
        20 => Ok(WindowSize::MB1),
        21 => Ok(WindowSize::MB2),
        _ => Err(cab_error(
            ErrorKind::Malformed,
            "CAB LZX window exponent is outside 15..=21",
        )),
    }
}

/// Charges the archive-declared window and audited worst-case workspace before
/// the decoder constructor can allocate.
#[cfg(feature = "cab-lzx")]
fn validate_lzx_codec_memory(
    window_bits: u8,
    limits: Limits,
) -> core::result::Result<(), StreamError> {
    let dictionary = 1_usize
        .checked_shl(u32::from(window_bits))
        .ok_or_else(|| cab_error(ErrorKind::Limit, "LZX window exceeds address space"))?;
    let required = dictionary
        .checked_add(MAX_WORKSPACE_OVERHEAD)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "LZX workspace accounting overflow"))?;
    if limits
        .codec_memory()
        .is_some_and(|maximum| required > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "LZX window and workspace exceed configured codec-memory limit",
        ));
    }
    Ok(())
}

/// Walks an LZX folder's `CFDATA` headers without reading payload bytes. This
/// rejects resource claims before either the decoder dictionary or our block
/// staging buffers allocate.
fn scan_lzx_folder<R: Read + Seek>(
    input: &mut R,
    data_offset: u64,
    num_blocks: u16,
    reserve_data: u8,
    image_length: u64,
    limits: Limits,
    allow_spanning: bool,
) -> core::result::Result<Option<u64>, StreamError> {
    let mut cursor = data_offset;
    let mut decoded = 0_u64;
    let mut spanning = false;
    let mut pending_data = 0_usize;
    for _ in 0..num_blocks {
        input
            .seek(SeekFrom::Start(cursor))
            .map_err(StreamError::io)?;
        ensure_stream_extent(
            input,
            8_u64
                .checked_add(u64::from(reserve_data))
                .ok_or_else(|| cab_error(ErrorKind::Malformed, "LZX CFDATA extent overflow"))?,
            image_length,
            "LZX CFDATA header extends past cbCabinet",
        )?;
        let mut header = [0_u8; 8];
        input.read_exact(&mut header).map_err(StreamError::io)?;
        let cb_data = usize::from(u16::from_le_bytes([header[4], header[5]]));
        let cb_uncomp = usize::from(u16::from_le_bytes([header[6], header[7]]));
        if cb_uncomp == 0 {
            spanning = true;
            pending_data = pending_data
                .checked_add(cb_data)
                .ok_or_else(|| cab_error(ErrorKind::Limit, "split LZX payload size overflow"))?;
        } else {
            if cb_uncomp > LZX_FRAME {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "LZX CFDATA output exceeds its 32 KiB frame",
                ));
            }
            let cb_uncomp_u64 = u64::try_from(cb_uncomp)
                .map_err(|_| cab_error(ErrorKind::Limit, "LZX frame exceeds u64"))?;
            decoded = decoded
                .checked_add(cb_uncomp_u64)
                .ok_or_else(|| cab_error(ErrorKind::Limit, "LZX folder size overflow"))?;
            let combined_data = pending_data
                .checked_add(cb_data)
                .ok_or_else(|| cab_error(ErrorKind::Limit, "split LZX payload size overflow"))?;
            validate_cfdata_in_flight(combined_data, cb_uncomp, limits)?;
            pending_data = 0;
        }

        if cb_uncomp == 0 {
            validate_cfdata_in_flight(cb_data, 0, limits)?;
        }

        let cb_data = u64::try_from(cb_data)
            .map_err(|_| cab_error(ErrorKind::Limit, "LZX payload exceeds u64"))?;
        cursor = cursor
            .checked_add(8)
            .and_then(|value| value.checked_add(u64::from(reserve_data)))
            .and_then(|value| value.checked_add(cb_data))
            .ok_or_else(|| cab_error(ErrorKind::Malformed, "LZX CFDATA extent overflow"))?;
        if cursor > image_length {
            return Err(cab_error(
                ErrorKind::Malformed,
                "LZX CFDATA block extends past the cabinet",
            ));
        }
    }
    if allow_spanning && pending_data != 0 {
        return Err(cab_error(
            ErrorKind::Malformed,
            "split LZX CFDATA has no continuation record",
        ));
    }
    Ok((allow_spanning || !spanning).then_some(decoded))
}

/// Walks a Quantum folder's `CFDATA` headers without reading payload bytes.
///
/// `compcol` follows the de-facto CAB framing used by Microsoft and
/// libmspack: every non-final block declares exactly 32 KiB, while the last
/// may be shorter. Arithmetic lookahead can delay a block's final bytes until
/// the next payload is supplied, so this is a container invariant rather than
/// a per-call decoder-output invariant.
fn scan_quantum_folder<R: Read + Seek>(
    input: &mut R,
    data_offset: u64,
    num_blocks: u16,
    reserve_data: u8,
    image_length: u64,
    limits: Limits,
    allow_spanning: bool,
) -> core::result::Result<Option<u64>, StreamError> {
    let mut cursor = data_offset;
    let mut decoded = 0_u64;
    let mut spanning = false;
    let mut pending_data = 0_usize;
    for block_index in 0..num_blocks {
        input
            .seek(SeekFrom::Start(cursor))
            .map_err(StreamError::io)?;
        ensure_stream_extent(
            input,
            8_u64
                .checked_add(u64::from(reserve_data))
                .ok_or_else(|| cab_error(ErrorKind::Malformed, "Quantum CFDATA extent overflow"))?,
            image_length,
            "Quantum CFDATA header extends past cbCabinet",
        )?;
        let mut header = [0_u8; 8];
        input.read_exact(&mut header).map_err(StreamError::io)?;
        let cb_data = usize::from(u16::from_le_bytes([header[4], header[5]]));
        let cb_uncomp = usize::from(u16::from_le_bytes([header[6], header[7]]));
        if cb_uncomp == 0 {
            spanning = true;
            pending_data = pending_data.checked_add(cb_data).ok_or_else(|| {
                cab_error(ErrorKind::Limit, "split Quantum payload size overflow")
            })?;
        } else {
            if cb_uncomp > QUANTUM_FRAME {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "Quantum CFDATA output exceeds its 32 KiB frame",
                ));
            }
            if block_index + 1 < num_blocks && cb_uncomp != QUANTUM_FRAME {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "non-final Quantum CFDATA block is not a full 32 KiB frame",
                ));
            }
            let cb_uncomp_u64 = u64::try_from(cb_uncomp)
                .map_err(|_| cab_error(ErrorKind::Limit, "Quantum frame exceeds u64"))?;
            decoded = decoded
                .checked_add(cb_uncomp_u64)
                .ok_or_else(|| cab_error(ErrorKind::Limit, "Quantum folder size overflow"))?;
            let combined_data = pending_data.checked_add(cb_data).ok_or_else(|| {
                cab_error(ErrorKind::Limit, "split Quantum payload size overflow")
            })?;
            validate_quantum_cfdata_in_flight(combined_data, cb_uncomp, limits)?;
            pending_data = 0;
        }

        if cb_uncomp == 0 {
            validate_quantum_cfdata_in_flight(cb_data, 0, limits)?;
        }

        let cb_data_u64 = u64::try_from(cb_data)
            .map_err(|_| cab_error(ErrorKind::Limit, "Quantum payload exceeds u64"))?;
        cursor = cursor
            .checked_add(8)
            .and_then(|value| value.checked_add(u64::from(reserve_data)))
            .and_then(|value| value.checked_add(cb_data_u64))
            .ok_or_else(|| cab_error(ErrorKind::Malformed, "Quantum CFDATA extent overflow"))?;
        if cursor > image_length {
            return Err(cab_error(
                ErrorKind::Malformed,
                "Quantum CFDATA block extends past the cabinet",
            ));
        }
    }
    if allow_spanning && pending_data != 0 {
        return Err(cab_error(
            ErrorKind::Malformed,
            "split Quantum CFDATA has no continuation record",
        ));
    }
    Ok((allow_spanning || !spanning).then_some(decoded))
}

/// Validates the maximum pair of simultaneously-live adapter buffers for one
/// CFDATA frame: compressed+decoded during decode, or decoded+event during emit.
///
/// [`CabSeekReader::ensure_block`] releases the consumed frame and event
/// staging before decode, so neither retained allocation overlaps this pair.
fn validate_cfdata_in_flight(
    cb_data: usize,
    cb_uncomp: usize,
    limits: Limits,
) -> core::result::Result<(), StreamError> {
    let decode_staging = cb_data
        .checked_add(cb_uncomp)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "CFDATA staging accounting overflow"))?;
    let emit_staging = cb_uncomp
        .checked_mul(2)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "CFDATA event accounting overflow"))?;
    let required = decode_staging.max(emit_staging);
    if limits
        .in_flight_bytes()
        .is_some_and(|maximum| required > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "CFDATA staging exceeds configured in-flight limit",
        ));
    }
    Ok(())
}

/// Validates Quantum's peak adapter staging. `compcol` copies the framed
/// compressed bytes into its incremental input buffer, so decode time holds
/// the adapter payload, the codec copy, and one decoded frame concurrently.
fn validate_quantum_cfdata_in_flight(
    cb_data: usize,
    cb_uncomp: usize,
    limits: Limits,
) -> core::result::Result<(), StreamError> {
    let framed = cb_data
        .checked_add(1)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "Quantum trailer accounting overflow"))?;
    let decode_staging = framed
        .checked_mul(2)
        .and_then(|value| value.checked_add(cb_uncomp))
        .ok_or_else(|| cab_error(ErrorKind::Limit, "Quantum staging accounting overflow"))?;
    let emit_staging = cb_uncomp
        .checked_mul(2)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "Quantum event accounting overflow"))?;
    let required = decode_staging.max(emit_staging);
    if limits
        .in_flight_bytes()
        .is_some_and(|maximum| required > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "Quantum CFDATA staging exceeds configured in-flight limit",
        ));
    }
    Ok(())
}

/// Validates a live `CFDATA` header before allocating or reading its payload.
fn validate_cfdata_sizes(
    cb_data: usize,
    cb_uncomp: usize,
    limits: Limits,
) -> core::result::Result<(), StreamError> {
    if cb_uncomp == 0 {
        return Err(cab_error(
            ErrorKind::Unsupported,
            "spanning CFDATA block continues in another cabinet",
        ));
    }
    if cb_uncomp > MSZIP_WINDOW {
        return Err(cab_error(
            ErrorKind::Malformed,
            "CFDATA uncompressed size exceeds 32 KiB",
        ));
    }

    // The LZX folder pre-scan rejects ordinary inputs at open time. This live
    // check covers every method and custom sources that change before extraction.
    validate_cfdata_in_flight(cb_data, cb_uncomp, limits)?;

    Ok(())
}

/// Computes the CAB XOR checksum, including its big-endian-packed tail.
fn cab_checksum(data: &[u8], seed: u32) -> u32 {
    let mut checksum = seed;
    let mut words = data.chunks_exact(4);
    for word in &mut words {
        checksum ^= u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
    }
    let tail_value = words
        .remainder()
        .iter()
        .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
    checksum ^ tail_value
}

/// Verifies a nonzero `CFDATA::csum` over header, reserve, and payload bytes.
fn validate_cfdata_checksum(
    stored: u32,
    size_fields: &[u8],
    reserved: &[u8],
    payload: &[u8],
) -> core::result::Result<(), StreamError> {
    if stored == 0 {
        return Ok(());
    }
    let payload_sum = cab_checksum(payload, 0);
    let header_sum = cab_checksum(size_fields, payload_sum);
    let computed = cab_checksum(reserved, header_sum);
    if computed != stored {
        return Err(cab_error(ErrorKind::Malformed, "CFDATA checksum mismatch"));
    }
    Ok(())
}

/// Rejects a frame before allocation when it would exceed decoded-total.
fn validate_decoded_total(
    current: u64,
    additional: usize,
    limits: Limits,
) -> core::result::Result<(), StreamError> {
    let additional = u64::try_from(additional)
        .map_err(|_| cab_error(ErrorKind::Limit, "decoded frame exceeds address space"))?;
    let next = current
        .checked_add(additional)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "decoded total overflow"))?;
    if limits.decoded_total().is_some_and(|maximum| next > maximum) {
        return Err(cab_error(
            ErrorKind::Limit,
            "decoded total exceeds configured limit",
        ));
    }
    Ok(())
}

/// Reads the `CFFILE` table starting at `offset`, bounding names and metadata by `limits`.
#[allow(clippy::too_many_lines)] // Fixed fields and path/aggregate budgets are validated together.
fn read_files<R: Read + Seek>(
    input: &mut R,
    offset: u64,
    count: u16,
    folders: &[CabFolder],
    image_length: u64,
    limits: Limits,
) -> core::result::Result<Vec<CabFile>, StreamError> {
    let file_count = usize::from(count);
    let fixed_metadata = file_count
        .checked_mul(core::mem::size_of::<CabFile>())
        .ok_or_else(|| cab_error(ErrorKind::Limit, "file metadata accounting overflow"))?;
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| fixed_metadata > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "file table exceeds configured metadata limit",
        ));
    }
    input
        .seek(SeekFrom::Start(offset))
        .map_err(StreamError::io)?;
    let mut files = Vec::new();
    files
        .try_reserve_exact(file_count)
        .map_err(|_| cab_error(ErrorKind::Limit, "file table allocation failed"))?;
    let mut metadata_used = fixed_metadata;
    for _ in 0..count {
        ensure_stream_extent(
            input,
            16,
            image_length,
            "CFFILE record extends past cbCabinet",
        )?;
        let mut record = [0_u8; 16];
        input.read_exact(&mut record).map_err(StreamError::io)?;
        let size = u64::from(u32::from_le_bytes([
            record[0], record[1], record[2], record[3],
        ]));
        let folder_offset = u64::from(u32::from_le_bytes([
            record[4], record[5], record[6], record[7],
        ]));
        let i_folder = u16::from_le_bytes([record[8], record[9]]);
        let date = u16::from_le_bytes([record[10], record[11]]);
        let time = u16::from_le_bytes([record[12], record[13]]);
        let attribs = u16::from_le_bytes([record[14], record[15]]);

        let metadata_remaining = limits
            .metadata_bytes()
            .map(|maximum| maximum - metadata_used);
        let mut name = read_cstring(input, limits, metadata_remaining, image_length)?;
        for byte in &mut name {
            if *byte == b'\\' {
                *byte = b'/';
            }
        }

        if limits.entry_bytes().is_some_and(|maximum| size > maximum) {
            return Err(cab_error(
                ErrorKind::Limit,
                "file size exceeds configured limit",
            ));
        }
        metadata_used = metadata_used
            .checked_add(name.len())
            .ok_or_else(|| cab_error(ErrorKind::Limit, "metadata accounting overflow"))?;
        if limits
            .metadata_bytes()
            .is_some_and(|maximum| metadata_used > maximum)
        {
            return Err(cab_error(
                ErrorKind::Limit,
                "file metadata exceeds configured limit",
            ));
        }

        let continuation = match i_folder {
            0xFFFD => FileContinuation::FromPrevious,
            0xFFFE => FileContinuation::ToNext,
            0xFFFF => FileContinuation::PreviousAndNext,
            _ => FileContinuation::None,
        };
        let folder_index = match continuation {
            FileContinuation::FromPrevious => 0,
            FileContinuation::ToNext => folders.len().checked_sub(1).ok_or_else(|| {
                cab_error(
                    ErrorKind::Malformed,
                    "continued file references an empty folder table",
                )
            })?,
            FileContinuation::PreviousAndNext => {
                if folders.len() != 1 {
                    return Err(cab_error(
                        ErrorKind::Malformed,
                        "file continued through a cabinet requires one folder fragment",
                    ));
                }
                0
            },
            FileContinuation::None => usize::from(i_folder),
        };
        if continuation == FileContinuation::None && folder_index >= folders.len() {
            return Err(cab_error(
                ErrorKind::Malformed,
                "file references a folder index out of range",
            ));
        }

        files.push(CabFile {
            name,
            size,
            folder_offset,
            folder_index,
            continuation,
            date,
            time,
            attribs,
            mtime: dos_datetime_to_timestamp(date, time),
            is_utf8: attribs & ATTR_NAME_UTF8 != 0,
        });
    }
    validate_cabinet_file_order(&files)?;
    Ok(files)
}

/// Enforces the CFFILE table order required by MS-CAB: effective folder index
/// first, then `uoffFolderStart`, with continuation sentinels at the table
/// edges. The streaming reader relies on this monotonic order so it never
/// rewinds and replays a solid folder.
fn validate_cabinet_file_order(files: &[CabFile]) -> core::result::Result<(), StreamError> {
    let mut previous = None::<(usize, u64)>;
    for (index, file) in files.iter().enumerate() {
        if file.continuation.starts_before() && index != 0 {
            return Err(cab_error(
                ErrorKind::Malformed,
                "continued-from-previous CFFILE is not first in its cabinet",
            ));
        }
        if file.continuation.continues_after() && index + 1 != files.len() {
            return Err(cab_error(
                ErrorKind::Malformed,
                "continued-to-next CFFILE is not last in its cabinet",
            ));
        }
        if let Some((previous_folder, previous_offset)) = previous
            && (file.folder_index < previous_folder
                || file.folder_index == previous_folder && file.folder_offset < previous_offset)
        {
            return Err(cab_error(
                ErrorKind::Malformed,
                "CFFILE table is not ordered by folder and folder offset",
            ));
        }
        previous = Some((file.folder_index, file.folder_offset));
    }
    Ok(())
}

/// Decodes the next `CFDATA` block of `stream`, replacing its buffer. Returns the block's
/// decompressed byte count.
fn decode_next_block<R: Read + Seek>(
    input: &mut R,
    stream: &mut FolderStream,
    image_length: u64,
    limits: Limits,
    decoded_total: u64,
) -> core::result::Result<usize, StreamError> {
    let mut payload = Vec::new();
    let cb_uncomp = loop {
        if stream.next_block >= stream.num_blocks {
            return Err(cab_error(
                ErrorKind::Malformed,
                "split CFDATA has no continuation record",
            ));
        }
        let (uncompressed, next_cursor) = append_cfdata_piece(
            input,
            stream.block_cursor,
            stream.reserve_data,
            image_length,
            limits,
            &mut payload,
        )?;
        stream.block_cursor = next_cursor;
        stream.next_block = stream
            .next_block
            .checked_add(1)
            .ok_or_else(|| cab_error(ErrorKind::Limit, "CFDATA block index overflow"))?;
        if uncompressed != 0 {
            break uncompressed;
        }
        if !stream.allow_spanning {
            return Err(cab_error(
                ErrorKind::Unsupported,
                "spanning CFDATA block continues in another cabinet",
            ));
        }
    };
    let cb_data = payload.len();
    validate_cfdata_sizes(cb_data, cb_uncomp, limits)?;
    if matches!(stream.method, Method::Quantum { .. }) {
        validate_quantum_cfdata_in_flight(cb_data, cb_uncomp, limits)?;
        if stream.next_block < stream.num_blocks && cb_uncomp != QUANTUM_FRAME {
            return Err(cab_error(
                ErrorKind::Malformed,
                "non-final Quantum CFDATA block is not a full 32 KiB frame",
            ));
        }
    }
    #[cfg(feature = "cab-quantum")]
    let decoded_base = if matches!(stream.method, Method::Quantum { .. }) {
        let pending = stream
            .quantum
            .as_ref()
            .ok_or_else(|| cab_error(ErrorKind::Protocol, "Quantum folder decoder is missing"))?
            .declared_remaining;
        decoded_total
            .checked_add(pending)
            .ok_or_else(|| cab_error(ErrorKind::Limit, "Quantum decoded-total overflow"))?
    } else {
        decoded_total
    };
    #[cfg(not(feature = "cab-quantum"))]
    let decoded_base = decoded_total;
    validate_decoded_total(decoded_base, cb_uncomp, limits)?;
    let decoded = decode_cfdata_payload(stream, payload, cb_data, cb_uncomp)?;

    let produced = decoded.len();
    stream.buf = decoded;
    stream.buf_pos = 0;
    Ok(produced)
}

/// Reads and checksum-validates one physical CFDATA record, appending only its
/// compressed bytes. A zero `cbUncomp` record is one fragment of a logical
/// block; its following record supplies the combined output size.
fn append_cfdata_piece<R: Read + Seek>(
    input: &mut R,
    start: u64,
    reserve_data: u8,
    image_length: u64,
    limits: Limits,
    payload: &mut Vec<u8>,
) -> core::result::Result<(usize, u64), StreamError> {
    input
        .seek(SeekFrom::Start(start))
        .map_err(StreamError::io)?;
    ensure_stream_extent(
        input,
        8_u64
            .checked_add(u64::from(reserve_data))
            .ok_or_else(|| cab_error(ErrorKind::Malformed, "CFDATA header extent overflow"))?,
        image_length,
        "CFDATA header extends past cbCabinet",
    )?;
    let mut header = [0_u8; 8];
    input.read_exact(&mut header).map_err(StreamError::io)?;
    let stored_checksum = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let cb_data = usize::from(u16::from_le_bytes([header[4], header[5]]));
    let cb_uncomp = usize::from(u16::from_le_bytes([header[6], header[7]]));
    if cb_uncomp > MSZIP_WINDOW {
        return Err(cab_error(
            ErrorKind::Malformed,
            "CFDATA uncompressed size exceeds 32 KiB",
        ));
    }
    validate_cfdata_in_flight(cb_data, cb_uncomp, limits)?;

    let payload_offset = start
        .checked_add(8)
        .and_then(|value| value.checked_add(u64::from(reserve_data)))
        .ok_or_else(|| cab_error(ErrorKind::Malformed, "CFDATA offset overflow"))?;
    let cb_data_u64 = u64::try_from(cb_data)
        .map_err(|_| cab_error(ErrorKind::Limit, "CFDATA payload exceeds u64"))?;
    let next_cursor = payload_offset
        .checked_add(cb_data_u64)
        .ok_or_else(|| cab_error(ErrorKind::Malformed, "CFDATA extent overflow"))?;
    if next_cursor > image_length {
        return Err(cab_error(
            ErrorKind::Malformed,
            "CFDATA block extends past the cabinet",
        ));
    }

    let mut reserved = [0_u8; CFDATA_RESERVE_MAX];
    let reserve_len = usize::from(reserve_data);
    input
        .read_exact(&mut reserved[..reserve_len])
        .map_err(StreamError::io)?;
    let piece_start = payload.len();
    let combined = piece_start
        .checked_add(cb_data)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "split CFDATA payload size overflow"))?;
    if limits
        .in_flight_bytes()
        .is_some_and(|maximum| combined > maximum)
    {
        return Err(cab_error(
            ErrorKind::Limit,
            "split CFDATA payload exceeds configured in-flight limit",
        ));
    }
    payload
        .try_reserve_exact(cb_data)
        .map_err(|_| cab_error(ErrorKind::Limit, "CFDATA payload allocation failed"))?;
    payload.resize(combined, 0);
    input
        .read_exact(&mut payload[piece_start..combined])
        .map_err(StreamError::io)?;
    validate_cfdata_checksum(
        stored_checksum,
        &header[4..8],
        &reserved[..reserve_len],
        &payload[piece_start..combined],
    )?;
    Ok((cb_uncomp, next_cursor))
}

/// Dispatches one validated CFDATA payload to the folder's persistent codec.
fn decode_cfdata_payload(
    stream: &mut FolderStream,
    payload: Vec<u8>,
    cb_data: usize,
    cb_uncomp: usize,
) -> core::result::Result<Vec<u8>, StreamError> {
    match stream.method {
        Method::Store => {
            if cb_data != cb_uncomp {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "stored CFDATA compressed and uncompressed sizes disagree",
                ));
            }
            Ok(payload)
        },
        Method::Mszip => {
            if payload.len() < 2 || &payload[0..2] != b"CK" {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "MSZIP CFDATA block missing 'CK' signature",
                ));
            }
            mszip_inflate_block(
                &mut stream.mszip_buffer,
                &mut stream.mszip_history_len,
                &payload[2..],
                cb_uncomp,
            )
        },
        #[cfg(feature = "cab-quantum")]
        Method::Quantum { .. } => {
            let quantum = stream.quantum.as_mut().ok_or_else(|| {
                cab_error(ErrorKind::Protocol, "Quantum folder decoder is missing")
            })?;
            let mut payload = payload;
            quantum_decode_block(quantum, &mut payload, cb_uncomp)
        },
        #[cfg(not(feature = "cab-quantum"))]
        Method::Quantum { .. } => Err(cab_error(
            ErrorKind::Unsupported,
            "CAB Quantum support is not compiled into this build",
        )),
        #[cfg(feature = "cab-lzx")]
        Method::Lzx { .. } => {
            let lzx = stream
                .lzx
                .as_mut()
                .ok_or_else(|| cab_error(ErrorKind::Protocol, "LZX folder decoder is missing"))?;
            lzx_decode_block(lzx, &payload, cb_uncomp)
        },
        #[cfg(not(feature = "cab-lzx"))]
        Method::Lzx { .. } => Err(cab_error(
            ErrorKind::Unsupported,
            "CAB LZX support is not compiled into this build",
        )),
        Method::Unsupported(_) => Err(cab_error(
            ErrorKind::Unsupported,
            "folder compression method is unsupported",
        )),
    }
}

/// Feeds one CAB Quantum `CFDATA` payload while preserving the window and
/// arithmetic models for the whole folder.
///
/// CAB injects an out-of-band `0xFF` after every compressed block so the
/// codec can consume 0..=4 alignment zeros. Arithmetic decoding may need
/// bytes from the next payload before it can commit the preceding frame's
/// final packet, so declared output is accounted folder-wide and this call
/// may return fewer bytes than the current `CFDATA::cbUncomp`.
#[cfg(feature = "cab-quantum")]
fn quantum_decode_block(
    state: &mut QuantumStream,
    payload: &mut Vec<u8>,
    declared: usize,
) -> core::result::Result<Vec<u8>, StreamError> {
    if state.finished {
        return Err(cab_error(
            ErrorKind::Protocol,
            "Quantum input supplied after folder completion",
        ));
    }
    let declared_u64 = u64::try_from(declared)
        .map_err(|_| cab_error(ErrorKind::Limit, "Quantum frame exceeds u64"))?;
    state.declared_remaining = state
        .declared_remaining
        .checked_add(declared_u64)
        .ok_or_else(|| cab_error(ErrorKind::Limit, "Quantum declared-output overflow"))?;

    payload
        .try_reserve_exact(1)
        .map_err(|_| cab_error(ErrorKind::Limit, "Quantum trailer allocation failed"))?;
    payload.push(0xFF);

    let output_capacity_u64 = state.declared_remaining.min(
        u64::try_from(QUANTUM_FRAME)
            .map_err(|_| cab_error(ErrorKind::Limit, "Quantum frame size exceeds u64"))?,
    );
    let output_capacity = usize::try_from(output_capacity_u64)
        .map_err(|_| cab_error(ErrorKind::Limit, "Quantum frame exceeds address space"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_capacity)
        .map_err(|_| cab_error(ErrorKind::Limit, "Quantum frame allocation failed"))?;
    output.resize(output_capacity, 0);

    let mut input_offset = 0_usize;
    let mut written = 0_usize;
    while written < output_capacity {
        let input = payload.get(input_offset..).ok_or_else(|| {
            cab_error(
                ErrorKind::Protocol,
                "Quantum decoder input cursor is inconsistent",
            )
        })?;
        let destination = output.get_mut(written..).ok_or_else(|| {
            cab_error(
                ErrorKind::Protocol,
                "Quantum decoder output cursor is inconsistent",
            )
        })?;
        let (progress, status) = state
            .decoder
            .decode(input, destination)
            .map_err(map_quantum_error)?;
        if progress.consumed > input.len() || progress.written > destination.len() {
            return Err(cab_error(
                ErrorKind::Protocol,
                "Quantum decoder reported progress outside its buffers",
            ));
        }
        input_offset = input_offset
            .checked_add(progress.consumed)
            .ok_or_else(|| cab_error(ErrorKind::Limit, "Quantum input cursor overflow"))?;
        written = written
            .checked_add(progress.written)
            .ok_or_else(|| cab_error(ErrorKind::Limit, "Quantum output cursor overflow"))?;
        if matches!(status, CompcolStatus::StreamEnd) {
            break;
        }
        if progress.consumed == 0 && progress.written == 0 {
            break;
        }
        if input_offset == payload.len() && matches!(status, CompcolStatus::InputEmpty) {
            break;
        }
    }

    if input_offset != payload.len() {
        return Err(cab_error(
            ErrorKind::Malformed,
            "CAB Quantum frame ended before consuming its compressed payload",
        ));
    }

    output.truncate(written);
    let written_u64 = u64::try_from(written)
        .map_err(|_| cab_error(ErrorKind::Limit, "Quantum output exceeds u64"))?;
    state.declared_remaining = state
        .declared_remaining
        .checked_sub(written_u64)
        .ok_or_else(|| cab_error(ErrorKind::Protocol, "Quantum output accounting underflow"))?;
    Ok(output)
}

/// Signals folder EOF and drains output that legitimately needed arithmetic
/// lookahead beyond the final payload. Quantum has no in-band end marker, so
/// reaching the container-declared byte count is the success condition.
#[cfg(feature = "cab-quantum")]
fn quantum_finish_folder(stream: &mut FolderStream) -> core::result::Result<usize, StreamError> {
    let state = stream
        .quantum
        .as_mut()
        .ok_or_else(|| cab_error(ErrorKind::Protocol, "Quantum folder decoder is missing"))?;
    if state.finished || state.declared_remaining == 0 {
        state.finished = true;
        return Ok(0);
    }

    let output_capacity_u64 = state.declared_remaining.min(
        u64::try_from(QUANTUM_FRAME)
            .map_err(|_| cab_error(ErrorKind::Limit, "Quantum frame size exceeds u64"))?,
    );
    let output_capacity = usize::try_from(output_capacity_u64)
        .map_err(|_| cab_error(ErrorKind::Limit, "Quantum frame exceeds address space"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(output_capacity)
        .map_err(|_| cab_error(ErrorKind::Limit, "Quantum final-frame allocation failed"))?;
    output.resize(output_capacity, 0);

    let mut written = 0_usize;
    let mut status = CompcolStatus::OutputFull;
    while written < output_capacity {
        let destination = output.get_mut(written..).ok_or_else(|| {
            cab_error(
                ErrorKind::Protocol,
                "Quantum final output cursor is inconsistent",
            )
        })?;
        let (progress, next_status) = state
            .decoder
            .finish(destination)
            .map_err(map_quantum_error)?;
        if progress.consumed != 0 || progress.written > destination.len() {
            return Err(cab_error(
                ErrorKind::Protocol,
                "Quantum decoder reported final progress outside its buffer",
            ));
        }
        written = written
            .checked_add(progress.written)
            .ok_or_else(|| cab_error(ErrorKind::Limit, "Quantum output cursor overflow"))?;
        status = next_status;
        if progress.written == 0 || matches!(status, CompcolStatus::StreamEnd) {
            break;
        }
    }

    output.truncate(written);
    let written_u64 = u64::try_from(written)
        .map_err(|_| cab_error(ErrorKind::Limit, "Quantum output exceeds u64"))?;
    state.declared_remaining = state
        .declared_remaining
        .checked_sub(written_u64)
        .ok_or_else(|| cab_error(ErrorKind::Protocol, "Quantum output accounting underflow"))?;
    if state.declared_remaining != 0 {
        if written == 0 || matches!(status, CompcolStatus::StreamEnd) {
            return Err(cab_error(
                ErrorKind::Malformed,
                "truncated CAB Quantum folder output",
            ));
        }
    } else {
        // Quantum has no true end marker. Do not probe beyond the declared
        // CAB output: EOF zero-padding could otherwise synthesize a packet.
        state.finished = true;
    }

    let produced = output.len();
    stream.buf = output;
    stream.buf_pos = 0;
    Ok(produced)
}

/// Maps `compcol`'s codec-wide errors into the archive's typed failure model.
#[cfg(feature = "cab-quantum")]
fn map_quantum_error(error: CompcolError) -> StreamError {
    let kind = match error {
        CompcolError::OutputLimitExceeded => ErrorKind::Limit,
        CompcolError::Unsupported => ErrorKind::Unsupported,
        _ => ErrorKind::Malformed,
    };
    cab_error(kind, "invalid or truncated CAB Quantum frame")
}

/// Decodes one CAB LZX `CFDATA` payload. The decoder creates a fresh bitstream
/// for every chunk, which discards the producer's 16-bit alignment padding,
/// while its window, recent offsets, Huffman trees, and E8 state stay live for
/// the whole folder.
#[cfg(feature = "cab-lzx")]
fn lzx_decode_block(
    state: &mut LzxStream,
    payload: &[u8],
    expected: usize,
) -> core::result::Result<Vec<u8>, StreamError> {
    let decoded = state
        .decoder
        .decompress_next(payload, expected)
        .map_err(|_| cab_error(ErrorKind::Malformed, "invalid or truncated CAB LZX frame"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(decoded.len())
        .map_err(|_| cab_error(ErrorKind::Limit, "LZX frame allocation failed"))?;
    output.extend_from_slice(decoded);
    Ok(output)
}

/// Inflates one MSZIP block after a valid-history prefix.
///
/// A non-wrapping 64 KiB workspace lets miniz reject distances before the
/// folder start while retaining up to 32 KiB from prior blocks.
fn mszip_inflate_block(
    workspace: &mut [u8],
    history_len: &mut usize,
    deflate: &[u8],
    expected: usize,
) -> core::result::Result<Vec<u8>, StreamError> {
    if workspace.len() != MSZIP_WORKSPACE || *history_len > MSZIP_WINDOW {
        return Err(cab_error(
            ErrorKind::Protocol,
            "MSZIP history workspace is inconsistent",
        ));
    }
    let combined_len = history_len
        .checked_add(expected)
        .ok_or_else(|| cab_error(ErrorKind::Malformed, "MSZIP output extent overflow"))?;
    if combined_len > workspace.len() {
        return Err(cab_error(
            ErrorKind::Malformed,
            "MSZIP history and output exceed the workspace",
        ));
    }

    let mut decompressor = DecompressorOxide::new();
    let mut output = Vec::new();
    output
        .try_reserve_exact(expected)
        .map_err(|_| cab_error(ErrorKind::Limit, "MSZIP frame allocation failed"))?;
    let mut input = deflate;
    // Raw DEFLATE (no zlib header), all input present. Non-wrapping mode
    // validates every distance against history plus bytes produced so far.
    loop {
        let start = history_len
            .checked_add(output.len())
            .ok_or_else(|| cab_error(ErrorKind::Malformed, "MSZIP output offset overflow"))?;
        let (status, consumed, written) = decompress(
            &mut decompressor,
            input,
            workspace,
            start,
            TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
        );
        if written > expected.saturating_sub(output.len()) {
            return Err(cab_error(
                ErrorKind::Malformed,
                "MSZIP block produced more than its declared size",
            ));
        }
        let end = start
            .checked_add(written)
            .ok_or_else(|| cab_error(ErrorKind::Malformed, "MSZIP output extent overflow"))?;
        let chunk = workspace
            .get(start..end)
            .ok_or_else(|| cab_error(ErrorKind::Malformed, "MSZIP output extent is invalid"))?;
        output.extend_from_slice(chunk);
        input = input
            .get(consumed..)
            .ok_or_else(|| cab_error(ErrorKind::Malformed, "MSZIP consumed count overflow"))?;
        match status {
            TINFLStatus::Done => break,
            TINFLStatus::HasMoreOutput => {
                if written == 0 && consumed == 0 {
                    return Err(cab_error(
                        ErrorKind::Malformed,
                        "MSZIP decoder made no progress",
                    ));
                }
            },
            TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "truncated MSZIP DEFLATE stream",
                ));
            },
            _ => {
                return Err(cab_error(
                    ErrorKind::Malformed,
                    "invalid MSZIP DEFLATE stream",
                ));
            },
        }
    }
    if output.len() != expected {
        return Err(cab_error(
            ErrorKind::Malformed,
            "MSZIP block size does not match its header",
        ));
    }

    let retained = combined_len.min(MSZIP_WINDOW);
    let history_start = combined_len - retained;
    workspace.copy_within(history_start..combined_len, 0);
    *history_len = retained;
    Ok(output)
}

/// Reads a NUL-terminated name with fallible growth, bounding both its path and
/// remaining aggregate-metadata footprint.
fn read_cstring<R: Read + Seek>(
    input: &mut R,
    limits: Limits,
    metadata_remaining: Option<usize>,
    image_length: u64,
) -> core::result::Result<Vec<u8>, StreamError> {
    let mut out = Vec::new();
    loop {
        ensure_stream_extent(input, 1, image_length, "CAB string extends past cbCabinet")?;
        let mut byte = [0_u8; 1];
        input.read_exact(&mut byte).map_err(StreamError::io)?;
        if byte[0] == 0 {
            return Ok(out);
        }
        if limits
            .path_bytes()
            .is_some_and(|maximum| out.len() >= maximum)
        {
            return Err(cab_error(
                ErrorKind::Limit,
                "name exceeds configured path limit",
            ));
        }
        if metadata_remaining.is_some_and(|maximum| out.len() >= maximum) {
            return Err(cab_error(
                ErrorKind::Limit,
                "name exceeds remaining metadata limit",
            ));
        }
        out.try_reserve(1)
            .map_err(|_| cab_error(ErrorKind::Limit, "CAB name allocation failed"))?;
        out.push(byte[0]);
    }
}

/// Skips a NUL-terminated cabinet header string, bounded by `path_bytes`.
fn skip_cstring<R: Read + Seek>(
    input: &mut R,
    limits: Limits,
    image_length: u64,
) -> core::result::Result<(), StreamError> {
    let mut length = 0_usize;
    loop {
        ensure_stream_extent(input, 1, image_length, "CAB string extends past cbCabinet")?;
        let mut byte = [0_u8; 1];
        input.read_exact(&mut byte).map_err(StreamError::io)?;
        if byte[0] == 0 {
            return Ok(());
        }
        if limits.path_bytes().is_some_and(|maximum| length >= maximum) {
            return Err(cab_error(
                ErrorKind::Limit,
                "cabinet name exceeds configured path limit",
            ));
        }
        length = length
            .checked_add(1)
            .ok_or_else(|| cab_error(ErrorKind::Limit, "cabinet name length overflow"))?;
    }
}

/// Rejects a stream-relative read before it can cross the authoritative
/// `CFHEADER::cbCabinet` boundary. Bytes after that boundary belong to the
/// caller's container or transport and are never CAB input.
fn ensure_stream_extent<R: Seek>(
    input: &mut R,
    length: u64,
    image_length: u64,
    message: &'static str,
) -> core::result::Result<(), StreamError> {
    let start = input.stream_position().map_err(StreamError::io)?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| cab_error(ErrorKind::Malformed, message))?;
    if end > image_length {
        return Err(cab_error(ErrorKind::Malformed, message));
    }
    Ok(())
}

/// Converts DOS date and time fields to a Unix [`Timestamp`], or `None` when unset/invalid.
fn dos_datetime_to_timestamp(date: u16, time: u16) -> Option<Timestamp> {
    if date == 0 && time == 0 {
        return None;
    }
    let year = 1980 + i64::from(date >> 9);
    let month = i64::from((date >> 5) & 0x0F);
    let day = i64::from(date & 0x1F);
    let hour = i64::from((time >> 11) & 0x1F);
    let minute = i64::from((time >> 5) & 0x3F);
    let second = i64::from(time & 0x1F) * 2;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days
        .checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)?;
    Some(Timestamp::from_seconds(secs))
}

/// Days from the Unix epoch to the given civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_shift = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_shift + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Builds a `cab`-tagged structured error.
fn cab_error(kind: ErrorKind, context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(kind)
            .with_format("cab")
            .with_context(context),
    )
}
