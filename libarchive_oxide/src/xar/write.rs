// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded XAR Store/zlib/BZip2 writer with a spill-to-disk heap.

use std::io::{Read, Seek, SeekFrom, Write};

use libarchive_oxide_core::{
    ArchiveMetadata, EntryKind, EntryMetadata, ErrorKind, Limits, Timestamp,
};
use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::deflate::core::{CompressorOxide, create_comp_flags_from_zip_params};
use miniz_oxide::deflate::stream::deflate as deflate_stream;
use miniz_oxide::{MZError, MZFlush, MZStatus};

use super::{MAX_DEPTH, xar_error};
use crate::spool::{DEFAULT_MEMORY_THRESHOLD, SpoolWriter};
use crate::{StreamError, XarCompression, XarWriteOptions};

const HEADER_SIZE: u16 = 28;
const COPY_BUFFER: usize = 64 * 1024;
const CODEC_BUFFER: usize = 64 * 1024;
const ZLIB_ENCODER_WORKSPACE: usize = 512 * 1024;
#[cfg(feature = "bzip2")]
const BZIP2_ENCODER_WORKSPACE: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct StoredData {
    offset: u64,
    stored_size: u64,
    length: u64,
    compression: XarCompression,
}

enum PayloadEncoder {
    Store,
    Zlib(Box<CompressorOxide>),
    #[cfg(feature = "bzip2")]
    Bzip2(Box<bzip2::Compress>),
}

impl std::fmt::Debug for PayloadEncoder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple(match self {
                Self::Store => "Store",
                Self::Zlib(_) => "Zlib",
                #[cfg(feature = "bzip2")]
                Self::Bzip2(_) => "Bzip2",
            })
            .finish()
    }
}

impl PayloadEncoder {
    // The error arm is compiled only when the additive BZip2 feature is off;
    // keep one constructor shape across both feature profiles.
    #[cfg_attr(feature = "bzip2", allow(clippy::unnecessary_wraps))]
    fn new(compression: XarCompression) -> Result<Self, StreamError> {
        match compression {
            XarCompression::Store => Ok(Self::Store),
            XarCompression::Zlib => {
                let flags = create_comp_flags_from_zip_params(6, 15, 0);
                Ok(Self::Zlib(Box::new(CompressorOxide::new(flags))))
            },
            XarCompression::Bzip2 => {
                #[cfg(feature = "bzip2")]
                {
                    Ok(Self::Bzip2(Box::new(bzip2::Compress::new(
                        bzip2::Compression::new(6),
                        0,
                    ))))
                }
                #[cfg(not(feature = "bzip2"))]
                {
                    Err(xar_error(
                        ErrorKind::Unsupported,
                        "XAR BZip2 writing is disabled",
                    ))
                }
            },
        }
    }

    fn write(
        &mut self,
        heap: &mut SpoolWriter,
        buffer: &mut [u8],
        bytes: &[u8],
    ) -> Result<(), StreamError> {
        match self {
            Self::Store => write_heap(heap, bytes),
            Self::Zlib(encoder) => write_zlib(encoder, heap, buffer, bytes),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(encoder) => write_bzip2(encoder, heap, buffer, bytes),
        }
    }

    fn finish(&mut self, heap: &mut SpoolWriter, buffer: &mut [u8]) -> Result<(), StreamError> {
        match self {
            Self::Store => Ok(()),
            Self::Zlib(encoder) => finish_zlib(encoder, heap, buffer),
            #[cfg(feature = "bzip2")]
            Self::Bzip2(encoder) => finish_bzip2(encoder, heap, buffer),
        }
    }
}

fn validate_compression_resources(
    compression: XarCompression,
    limits: Limits,
) -> Result<(), StreamError> {
    let workspace = match compression {
        XarCompression::Store => 0,
        XarCompression::Zlib => ZLIB_ENCODER_WORKSPACE,
        XarCompression::Bzip2 => {
            #[cfg(feature = "bzip2")]
            {
                BZIP2_ENCODER_WORKSPACE
            }
            #[cfg(not(feature = "bzip2"))]
            {
                return Err(xar_error(
                    ErrorKind::Unsupported,
                    "XAR BZip2 writing is disabled",
                ));
            }
        },
    };
    if limits
        .codec_memory()
        .is_some_and(|maximum| workspace > maximum)
    {
        return Err(xar_error(
            ErrorKind::Limit,
            "XAR encoder exceeds configured codec-memory limit",
        ));
    }
    if compression != XarCompression::Store && limits.in_flight_bytes() == Some(0) {
        return Err(xar_error(
            ErrorKind::Limit,
            "XAR compression requires a nonzero in-flight buffer",
        ));
    }
    Ok(())
}

fn maximum_heap_bytes(limits: Limits, compression: XarCompression) -> u64 {
    let Some(decoded) = limits.decoded_total() else {
        return u64::MAX;
    };
    let entries = limits.entries().unwrap_or(u64::MAX);
    match compression {
        XarCompression::Store => decoded,
        XarCompression::Zlib => decoded
            .saturating_add(decoded >> 12)
            .saturating_add(decoded >> 14)
            .saturating_add(decoded >> 25)
            .saturating_add(entries.saturating_mul(13)),
        XarCompression::Bzip2 => decoded
            .saturating_add(decoded / 100)
            .saturating_add(entries.saturating_mul(600)),
    }
}

fn write_heap(heap: &mut SpoolWriter, bytes: &[u8]) -> Result<(), StreamError> {
    heap.write_all(bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::FileTooLarge {
            xar_error(ErrorKind::Limit, "XAR heap exceeds its encoded-size bound")
        } else {
            StreamError::io(error)
        }
    })
}

fn write_zlib(
    encoder: &mut CompressorOxide,
    heap: &mut SpoolWriter,
    buffer: &mut [u8],
    bytes: &[u8],
) -> Result<(), StreamError> {
    let mut consumed = 0;
    while consumed != bytes.len() {
        let result = deflate_stream(encoder, &bytes[consumed..], buffer, MZFlush::None);
        write_heap(heap, &buffer[..result.bytes_written])?;
        consumed = consumed
            .checked_add(result.bytes_consumed)
            .ok_or_else(|| xar_error(ErrorKind::Limit, "XAR zlib input position overflow"))?;
        match result.status {
            Ok(MZStatus::StreamEnd) => {
                return Err(xar_error(
                    ErrorKind::Protocol,
                    "XAR zlib stream ended before entry finalization",
                ));
            },
            Ok(_) | Err(MZError::Buf)
                if result.bytes_consumed != 0 || result.bytes_written != 0 => {},
            _ => return Err(xar_error(ErrorKind::Malformed, "XAR zlib encoding failed")),
        }
    }
    Ok(())
}

fn finish_zlib(
    encoder: &mut CompressorOxide,
    heap: &mut SpoolWriter,
    buffer: &mut [u8],
) -> Result<(), StreamError> {
    loop {
        let result = deflate_stream(encoder, &[], buffer, MZFlush::Finish);
        write_heap(heap, &buffer[..result.bytes_written])?;
        match result.status {
            Ok(MZStatus::StreamEnd) => return Ok(()),
            Ok(_) | Err(MZError::Buf) if result.bytes_written != 0 => {},
            _ => {
                return Err(xar_error(
                    ErrorKind::Protocol,
                    "XAR zlib finalization made no progress",
                ));
            },
        }
    }
}

#[cfg(feature = "bzip2")]
fn write_bzip2(
    encoder: &mut bzip2::Compress,
    heap: &mut SpoolWriter,
    buffer: &mut [u8],
    bytes: &[u8],
) -> Result<(), StreamError> {
    let mut consumed = 0;
    while consumed != bytes.len() {
        let before_input = encoder.total_in();
        let before_output = encoder.total_out();
        let status = encoder
            .compress(&bytes[consumed..], buffer, bzip2::Action::Run)
            .map_err(|_| xar_error(ErrorKind::Malformed, "XAR BZip2 encoding failed"))?;
        let used = usize::try_from(encoder.total_in() - before_input)
            .map_err(|_| xar_error(ErrorKind::Limit, "XAR BZip2 input position overflow"))?;
        let produced = usize::try_from(encoder.total_out() - before_output)
            .map_err(|_| xar_error(ErrorKind::Limit, "XAR BZip2 output position overflow"))?;
        write_heap(heap, &buffer[..produced])?;
        consumed = consumed
            .checked_add(used)
            .ok_or_else(|| xar_error(ErrorKind::Limit, "XAR BZip2 input position overflow"))?;
        if status == bzip2::Status::StreamEnd {
            return Err(xar_error(
                ErrorKind::Protocol,
                "XAR BZip2 stream ended before entry finalization",
            ));
        }
        if used == 0 && produced == 0 {
            return Err(xar_error(
                ErrorKind::Protocol,
                "XAR BZip2 encoder made no progress",
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "bzip2")]
fn finish_bzip2(
    encoder: &mut bzip2::Compress,
    heap: &mut SpoolWriter,
    buffer: &mut [u8],
) -> Result<(), StreamError> {
    loop {
        let before_output = encoder.total_out();
        let status = encoder
            .compress(&[], buffer, bzip2::Action::Finish)
            .map_err(|_| xar_error(ErrorKind::Malformed, "XAR BZip2 finalization failed"))?;
        let produced = usize::try_from(encoder.total_out() - before_output)
            .map_err(|_| xar_error(ErrorKind::Limit, "XAR BZip2 output position overflow"))?;
        write_heap(heap, &buffer[..produced])?;
        match status {
            bzip2::Status::StreamEnd => return Ok(()),
            bzip2::Status::FinishOk if produced != 0 => {},
            _ => {
                return Err(xar_error(
                    ErrorKind::Protocol,
                    "XAR BZip2 finalization made no progress",
                ));
            },
        }
    }
}

#[derive(Debug)]
struct XarNode {
    name: Vec<u8>,
    kind: EntryKind,
    explicit: bool,
    mode: Option<u32>,
    uid: Option<u64>,
    gid: Option<u64>,
    mtime: Option<Timestamp>,
    link_target: Option<Vec<u8>>,
    data: Option<StoredData>,
    children: Vec<usize>,
}

impl XarNode {
    fn root() -> Self {
        Self {
            name: Vec::new(),
            kind: EntryKind::Dir,
            explicit: true,
            mode: None,
            uid: None,
            gid: None,
            mtime: None,
            link_target: None,
            data: None,
            children: Vec::new(),
        }
    }

    fn implicit_directory(name: Vec<u8>) -> Self {
        Self {
            name,
            kind: EntryKind::Dir,
            explicit: false,
            mode: None,
            uid: None,
            gid: None,
            mtime: None,
            link_target: None,
            data: None,
            children: Vec::new(),
        }
    }
}

#[derive(Debug)]
struct PendingEntry {
    node: usize,
    declared_size: Option<u64>,
    offset: u64,
    written: u64,
    encoder: Option<PayloadEncoder>,
}

/// Seek writer for canonical XAR archives with bounded heap payloads.
pub(crate) struct XarSeekWriter<W: Write + Seek> {
    output: W,
    heap: SpoolWriter,
    nodes: Vec<XarNode>,
    pending: Option<PendingEntry>,
    limits: Limits,
    metadata_used: usize,
    decoded_total: u64,
    declared_total: u64,
    compression: XarCompression,
    codec_buffer: Vec<u8>,
}

impl<W: Write + Seek + std::fmt::Debug> std::fmt::Debug for XarSeekWriter<W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("XarSeekWriter")
            .field("output", &self.output)
            .field("heap", &self.heap)
            .field("nodes", &self.nodes.len())
            .field("pending", &self.pending)
            .field("limits", &self.limits)
            .field("metadata_used", &self.metadata_used)
            .field("decoded_total", &self.decoded_total)
            .field("declared_total", &self.declared_total)
            .field("compression", &self.compression)
            .field("codec_buffer_length", &self.codec_buffer.len())
            .finish()
    }
}

impl<W: Write + Seek> XarSeekWriter<W> {
    pub(crate) fn new(output: W, limits: Limits) -> Result<Self, StreamError> {
        Self::new_with_options(output, limits, XarWriteOptions::new())
    }

    pub(crate) fn new_with_options(
        mut output: W,
        limits: Limits,
        options: XarWriteOptions,
    ) -> Result<Self, StreamError> {
        let compression = options.compression();
        validate_compression_resources(compression, limits)?;
        output.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        let threshold = limits
            .in_flight_bytes()
            .unwrap_or(DEFAULT_MEMORY_THRESHOLD)
            .min(DEFAULT_MEMORY_THRESHOLD);
        let maximum = maximum_heap_bytes(limits, compression);
        let codec_buffer_length = if compression == XarCompression::Store {
            0
        } else {
            limits
                .in_flight_bytes()
                .unwrap_or(CODEC_BUFFER)
                .min(CODEC_BUFFER)
        };
        Ok(Self {
            output,
            heap: SpoolWriter::with_limits(threshold, maximum),
            nodes: vec![XarNode::root()],
            pending: None,
            limits,
            metadata_used: core::mem::size_of::<XarNode>(),
            decoded_total: 0,
            declared_total: 0,
            compression,
            codec_buffer: vec![0_u8; codec_buffer_length],
        })
    }

    pub(crate) fn set_archive_metadata(
        &mut self,
        metadata: &ArchiveMetadata,
    ) -> Result<(), StreamError> {
        if self.pending.is_some() || self.nodes.len() != 1 {
            return Err(xar_error(
                ErrorKind::Protocol,
                "XAR archive metadata must be set before the first entry",
            ));
        }
        if metadata.volume_name().is_some()
            || metadata.comment().is_some()
            || !metadata.extensions().is_empty()
        {
            return Err(xar_error(
                ErrorKind::Unsupported,
                "XAR writer cannot represent the supplied archive metadata",
            ));
        }
        Ok(())
    }

    pub(crate) fn start_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        if self.pending.is_some() {
            return Err(xar_error(
                ErrorKind::Protocol,
                "previous XAR entry is still open",
            ));
        }
        validate_entry_metadata(metadata)?;
        let components = normalize_path(metadata, self.limits)?;
        if metadata.kind() == EntryKind::File
            && let Some(size) = metadata.size()
        {
            if self
                .limits
                .entry_bytes()
                .is_some_and(|maximum| size > maximum)
            {
                return Err(xar_error(
                    ErrorKind::Limit,
                    "XAR entry exceeds configured size limit",
                ));
            }
            let declared_total = self
                .declared_total
                .checked_add(size)
                .ok_or_else(|| xar_error(ErrorKind::Limit, "XAR declared total size overflow"))?;
            if self
                .limits
                .decoded_total()
                .is_some_and(|maximum| declared_total > maximum)
            {
                return Err(xar_error(
                    ErrorKind::Limit,
                    "XAR declared total exceeds configured limit",
                ));
            }
            self.declared_total = declared_total;
        }
        let node = self.insert_path(&components, metadata)?;
        self.pending = Some(PendingEntry {
            node,
            declared_size: metadata.size(),
            offset: self.heap.len(),
            written: 0,
            encoder: if metadata.kind() == EntryKind::File {
                Some(PayloadEncoder::new(self.compression)?)
            } else {
                None
            },
        });
        Ok(())
    }

    pub(crate) fn write_data(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        let pending = self.pending.as_ref().ok_or_else(|| {
            xar_error(
                ErrorKind::Protocol,
                "XAR data was supplied outside an entry",
            )
        })?;
        if bytes.is_empty() {
            return Ok(());
        }
        if self.nodes[pending.node].kind != EntryKind::File {
            return Err(xar_error(
                ErrorKind::Protocol,
                "only regular XAR files accept payload data",
            ));
        }
        let additional = u64::try_from(bytes.len())
            .map_err(|_| xar_error(ErrorKind::Limit, "XAR write size exceeds u64"))?;
        let next_size = pending
            .written
            .checked_add(additional)
            .ok_or_else(|| xar_error(ErrorKind::Limit, "XAR entry size overflow"))?;
        if pending
            .declared_size
            .is_some_and(|declared| next_size > declared)
        {
            return Err(xar_error(
                ErrorKind::Protocol,
                "XAR payload exceeds its declared size",
            ));
        }
        if self
            .limits
            .entry_bytes()
            .is_some_and(|maximum| next_size > maximum)
        {
            return Err(xar_error(
                ErrorKind::Limit,
                "XAR entry exceeds configured size limit",
            ));
        }
        let next_total = self
            .decoded_total
            .checked_add(additional)
            .ok_or_else(|| xar_error(ErrorKind::Limit, "XAR decoded total overflow"))?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|maximum| next_total > maximum)
        {
            return Err(xar_error(
                ErrorKind::Limit,
                "XAR decoded total exceeds configured limit",
            ));
        }
        let encoder = self
            .pending
            .as_mut()
            .and_then(|pending| pending.encoder.as_mut())
            .ok_or_else(|| xar_error(ErrorKind::Protocol, "XAR file encoder disappeared"))?;
        encoder.write(&mut self.heap, &mut self.codec_buffer, bytes)?;
        self.pending
            .as_mut()
            .ok_or_else(|| xar_error(ErrorKind::Protocol, "XAR pending entry disappeared"))?
            .written = next_size;
        self.decoded_total = next_total;
        Ok(())
    }

    pub(crate) fn end_entry(&mut self) -> Result<(), StreamError> {
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| xar_error(ErrorKind::Protocol, "no XAR entry is open"))?;
        if pending
            .declared_size
            .is_some_and(|declared| declared != pending.written)
        {
            return Err(xar_error(
                ErrorKind::Protocol,
                "XAR entry size does not match its declared size",
            ));
        }
        let mut pending = self
            .pending
            .take()
            .ok_or_else(|| xar_error(ErrorKind::Protocol, "XAR pending entry disappeared"))?;
        if self.nodes[pending.node].kind == EntryKind::File {
            pending
                .encoder
                .as_mut()
                .ok_or_else(|| xar_error(ErrorKind::Protocol, "XAR file encoder disappeared"))?
                .finish(&mut self.heap, &mut self.codec_buffer)?;
            let stored_size =
                self.heap.len().checked_sub(pending.offset).ok_or_else(|| {
                    xar_error(ErrorKind::Protocol, "XAR heap offset moved backwards")
                })?;
            self.nodes[pending.node].data = Some(StoredData {
                offset: pending.offset,
                stored_size,
                length: pending.written,
                compression: self.compression,
            });
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<W, StreamError> {
        if self.pending.is_some() {
            return Err(xar_error(
                ErrorKind::Protocol,
                "XAR entry is open at finish",
            ));
        }
        let heap_length = self.heap.len();
        if heap_length != 0 && self.limits.in_flight_bytes() == Some(0) {
            return Err(xar_error(
                ErrorKind::Limit,
                "XAR heap copy cannot progress under a zero in-flight limit",
            ));
        }
        let toc = self.build_toc()?;
        let compressed_bound = toc
            .len()
            .checked_add(toc.len() / 16)
            .and_then(|value| value.checked_add(128))
            .ok_or_else(|| xar_error(ErrorKind::Limit, "XAR TOC size overflow"))?;
        self.reserve_final_metadata(toc.len(), compressed_bound)?;
        let compressed = compress_to_vec_zlib(&toc, 6);
        if compressed.len() > compressed_bound {
            return Err(xar_error(
                ErrorKind::Protocol,
                "XAR TOC compressor exceeded its conservative bound",
            ));
        }
        let mut heap = self.heap.finish()?;
        self.output
            .seek(SeekFrom::Start(0))
            .map_err(StreamError::io)?;
        self.output
            .write_all(&0x7861_7221_u32.to_be_bytes())
            .map_err(StreamError::io)?;
        self.output
            .write_all(&HEADER_SIZE.to_be_bytes())
            .map_err(StreamError::io)?;
        self.output
            .write_all(&1_u16.to_be_bytes())
            .map_err(StreamError::io)?;
        self.output
            .write_all(&(compressed.len() as u64).to_be_bytes())
            .map_err(StreamError::io)?;
        self.output
            .write_all(&(toc.len() as u64).to_be_bytes())
            .map_err(StreamError::io)?;
        self.output
            .write_all(&0_u32.to_be_bytes())
            .map_err(StreamError::io)?;
        self.output
            .write_all(&compressed)
            .map_err(StreamError::io)?;
        Self::copy_heap(&mut self.output, self.limits, &mut heap, heap_length)?;
        self.output.flush().map_err(StreamError::io)?;
        Ok(self.output)
    }

    pub(crate) fn abort(self) -> W {
        self.output
    }

    fn insert_path(
        &mut self,
        components: &[Vec<u8>],
        metadata: &EntryMetadata,
    ) -> Result<usize, StreamError> {
        let mut parent = 0;
        for (position, component) in components.iter().enumerate() {
            let last = position + 1 == components.len();
            let existing = self.nodes[parent]
                .children
                .iter()
                .copied()
                .find(|&child| self.nodes[child].name == *component);
            if let Some(existing) = existing {
                if !last && self.nodes[existing].kind != EntryKind::Dir {
                    return Err(xar_error(
                        ErrorKind::Protocol,
                        "XAR path traverses a non-directory entry",
                    ));
                }
                if last {
                    if self.nodes[existing].explicit {
                        return Err(xar_error(ErrorKind::Protocol, "duplicate XAR entry path"));
                    }
                    if metadata.kind() != EntryKind::Dir {
                        return Err(xar_error(
                            ErrorKind::Protocol,
                            "XAR entry collides with an implicit directory",
                        ));
                    }
                    self.apply_metadata(existing, metadata)?;
                    return Ok(existing);
                }
                parent = existing;
                continue;
            }

            let node = if last {
                node_from_metadata(component.clone(), metadata)
            } else {
                XarNode::implicit_directory(component.clone())
            };
            self.reserve_node(&node)?;
            self.nodes
                .try_reserve(1)
                .map_err(|_| xar_error(ErrorKind::Limit, "XAR node allocation failed"))?;
            let index = self.nodes.len();
            self.nodes.push(node);
            self.nodes[parent]
                .children
                .try_reserve(1)
                .map_err(|_| xar_error(ErrorKind::Limit, "XAR child allocation failed"))?;
            self.nodes[parent].children.push(index);
            self.reserve_metadata(core::mem::size_of::<usize>())?;
            parent = index;
        }
        Ok(parent)
    }

    fn apply_metadata(&mut self, node: usize, metadata: &EntryMetadata) -> Result<(), StreamError> {
        let link = metadata
            .link_target()
            .map(|target| target.as_bytes().to_vec());
        self.reserve_metadata(link.as_ref().map_or(0, Vec::len))?;
        let target = &mut self.nodes[node];
        target.explicit = true;
        target.mode = metadata.mode();
        target.uid = metadata.owner().uid;
        target.gid = metadata.owner().gid;
        target.mtime = metadata.times().modified;
        target.link_target = link;
        Ok(())
    }

    fn reserve_node(&mut self, node: &XarNode) -> Result<(), StreamError> {
        let projected_entries = u64::try_from(self.nodes.len())
            .map_err(|_| xar_error(ErrorKind::Limit, "XAR entry count exceeds u64"))?;
        if self
            .limits
            .entries()
            .is_some_and(|maximum| projected_entries > maximum)
        {
            return Err(xar_error(
                ErrorKind::Limit,
                "XAR entry count exceeds configured limit",
            ));
        }
        let cost = core::mem::size_of::<XarNode>()
            .checked_add(node.name.len())
            .and_then(|value| value.checked_add(node.link_target.as_ref().map_or(0, Vec::len)))
            .ok_or_else(|| xar_error(ErrorKind::Limit, "XAR metadata accounting overflow"))?;
        self.reserve_metadata(cost)
    }

    fn reserve_metadata(&mut self, additional: usize) -> Result<(), StreamError> {
        let next = self
            .metadata_used
            .checked_add(additional)
            .ok_or_else(|| xar_error(ErrorKind::Limit, "XAR metadata accounting overflow"))?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| next > maximum)
        {
            return Err(xar_error(
                ErrorKind::Limit,
                "XAR metadata exceeds configured limit",
            ));
        }
        self.metadata_used = next;
        Ok(())
    }

    fn reserve_final_metadata(
        &self,
        toc_length: usize,
        compressed_bound: usize,
    ) -> Result<(), StreamError> {
        let required = self
            .metadata_used
            .checked_add(toc_length)
            .and_then(|value| value.checked_add(compressed_bound))
            .ok_or_else(|| xar_error(ErrorKind::Limit, "XAR metadata accounting overflow"))?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| required > maximum)
        {
            return Err(xar_error(
                ErrorKind::Limit,
                "XAR TOC exceeds configured metadata limit",
            ));
        }
        Ok(())
    }

    fn build_toc(&self) -> Result<Vec<u8>, StreamError> {
        let available = self.limits.metadata_bytes().map_or(usize::MAX, |maximum| {
            maximum.saturating_sub(self.metadata_used) / 2
        });
        let mut toc = TocBuilder::new(available);
        toc.push(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><xar><toc>")?;
        let mut id = 1_u64;
        for &child in &self.nodes[0].children {
            emit_node(&self.nodes, child, &mut id, &mut toc)?;
        }
        toc.push(b"</toc></xar>")?;
        Ok(toc.finish())
    }

    fn copy_heap(
        output: &mut W,
        limits: Limits,
        heap: &mut impl Read,
        heap_length: u64,
    ) -> Result<(), StreamError> {
        if heap_length == 0 {
            return Ok(());
        }
        let chunk = limits
            .in_flight_bytes()
            .unwrap_or(COPY_BUFFER)
            .min(COPY_BUFFER);
        if chunk == 0 {
            return Err(xar_error(
                ErrorKind::Limit,
                "XAR heap copy cannot progress under a zero in-flight limit",
            ));
        }
        let mut buffer = vec![0_u8; chunk];
        let mut copied = 0_u64;
        while copied != heap_length {
            let remaining = usize::try_from((heap_length - copied).min(chunk as u64))
                .map_err(|_| xar_error(ErrorKind::Limit, "XAR heap chunk exceeds usize"))?;
            heap.read_exact(&mut buffer[..remaining])
                .map_err(StreamError::io)?;
            output
                .write_all(&buffer[..remaining])
                .map_err(StreamError::io)?;
            copied += remaining as u64;
        }
        Ok(())
    }
}

fn node_from_metadata(name: Vec<u8>, metadata: &EntryMetadata) -> XarNode {
    XarNode {
        name,
        kind: metadata.kind(),
        explicit: true,
        mode: metadata.mode(),
        uid: metadata.owner().uid,
        gid: metadata.owner().gid,
        mtime: metadata.times().modified,
        link_target: metadata
            .link_target()
            .map(|target| target.as_bytes().to_vec()),
        data: None,
        children: Vec::new(),
    }
}

fn validate_entry_metadata(metadata: &EntryMetadata) -> Result<(), StreamError> {
    match metadata.kind() {
        EntryKind::File | EntryKind::Dir => {
            if metadata.link_target().is_some() {
                return Err(xar_error(
                    ErrorKind::Protocol,
                    "non-link XAR entry has a link target",
                ));
            }
        },
        EntryKind::Symlink => {
            let target = metadata.link_target().ok_or_else(|| {
                xar_error(ErrorKind::Protocol, "XAR symbolic link requires a target")
            })?;
            validate_xml_text(
                target.as_bytes(),
                "XAR symbolic-link target is not valid XML text",
            )?;
        },
        _ => {
            return Err(xar_error(
                ErrorKind::Unsupported,
                "XAR writer supports files, directories, and symbolic links",
            ));
        },
    }
    if metadata.kind() != EntryKind::File && metadata.size().is_some_and(|size| size != 0) {
        return Err(xar_error(
            ErrorKind::Protocol,
            "non-file XAR entry must have size zero or unknown",
        ));
    }
    let times = metadata.times();
    if times.accessed.is_some() || times.changed.is_some() || times.created.is_some() {
        return Err(xar_error(
            ErrorKind::Unsupported,
            "XAR writer currently represents only modification time",
        ));
    }
    if let Some(modified) = times.modified {
        let _ = format_timestamp(modified)?;
    }
    if metadata.owner().user.is_some()
        || metadata.owner().group.is_some()
        || metadata.inode().is_some()
        || metadata.links().is_some()
        || metadata.device().is_some()
        || metadata.referenced_device().is_some()
        || !metadata.sparse_extents().is_empty()
        || !metadata.xattrs().is_empty()
        || !metadata.acl().is_empty()
        || metadata.file_flags() != 0
        || metadata.checksum().is_some()
        || metadata.is_encrypted()
        || metadata.comment().is_some()
        || !metadata.extensions().is_empty()
    {
        return Err(xar_error(
            ErrorKind::Unsupported,
            "XAR entry contains metadata this writer cannot represent losslessly",
        ));
    }
    Ok(())
}

fn normalize_path(metadata: &EntryMetadata, limits: Limits) -> Result<Vec<Vec<u8>>, StreamError> {
    let mut path = metadata.path().as_bytes();
    while path.ends_with(b"/") {
        path = &path[..path.len() - 1];
    }
    if path.is_empty() || path.starts_with(b"/") {
        return Err(xar_error(
            ErrorKind::Malformed,
            "XAR path must be non-empty and relative",
        ));
    }
    if limits
        .path_bytes()
        .is_some_and(|maximum| path.len() > maximum)
    {
        return Err(xar_error(
            ErrorKind::Limit,
            "XAR path exceeds configured limit",
        ));
    }
    validate_xml_text(path, "XAR path is not valid XML text")?;
    let components = path
        .split(|&byte| byte == b'/')
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    if components
        .iter()
        .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(xar_error(
            ErrorKind::Malformed,
            "XAR path has an invalid component",
        ));
    }
    let depth_limit = limits.nesting().unwrap_or(MAX_DEPTH).min(MAX_DEPTH);
    if components.len() > depth_limit {
        return Err(xar_error(
            ErrorKind::Limit,
            "XAR path nesting exceeds configured limit",
        ));
    }
    Ok(components)
}

fn validate_xml_text(bytes: &[u8], context: &'static str) -> Result<(), StreamError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| xar_error(ErrorKind::Unsupported, context))?;
    if text.chars().any(|character| {
        !matches!(character, '\u{9}' | '\u{a}' | '\u{d}')
            && (character < '\u{20}' || character == '\u{fffe}' || character == '\u{ffff}')
    }) {
        return Err(xar_error(ErrorKind::Unsupported, context));
    }
    Ok(())
}

struct TocBuilder {
    bytes: Vec<u8>,
    maximum: usize,
}

impl TocBuilder {
    const fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| xar_error(ErrorKind::Limit, "XAR TOC length overflow"))?;
        if next > self.maximum {
            return Err(xar_error(
                ErrorKind::Limit,
                "XAR TOC exceeds configured metadata limit",
            ));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| xar_error(ErrorKind::Limit, "XAR TOC allocation failed"))?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn number(&mut self, value: u64) -> Result<(), StreamError> {
        self.push(value.to_string().as_bytes())
    }

    fn octal(&mut self, value: u32) -> Result<(), StreamError> {
        self.push(format!("{value:o}").as_bytes())
    }

    fn escaped(&mut self, value: &[u8]) -> Result<(), StreamError> {
        for &byte in value {
            match byte {
                b'&' => self.push(b"&amp;")?,
                b'<' => self.push(b"&lt;")?,
                b'>' => self.push(b"&gt;")?,
                b'\"' => self.push(b"&quot;")?,
                b'\'' => self.push(b"&apos;")?,
                _ => self.push(&[byte])?,
            }
        }
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

fn emit_node(
    nodes: &[XarNode],
    index: usize,
    id: &mut u64,
    toc: &mut TocBuilder,
) -> Result<(), StreamError> {
    let node = &nodes[index];
    toc.push(b"<file id=\"")?;
    toc.number(*id)?;
    *id = id
        .checked_add(1)
        .ok_or_else(|| xar_error(ErrorKind::Limit, "XAR file id overflow"))?;
    toc.push(b"\"><name>")?;
    toc.escaped(&node.name)?;
    toc.push(b"</name><type>")?;
    toc.push(match node.kind {
        EntryKind::File => b"file",
        EntryKind::Dir => b"directory",
        EntryKind::Symlink => b"symlink",
        _ => {
            return Err(xar_error(
                ErrorKind::Protocol,
                "unsupported XAR node reached TOC emission",
            ));
        },
    })?;
    toc.push(b"</type>")?;
    if let Some(mode) = node.mode {
        toc.push(b"<mode>")?;
        toc.octal(mode)?;
        toc.push(b"</mode>")?;
    }
    if let Some(uid) = node.uid {
        toc.push(b"<uid>")?;
        toc.number(uid)?;
        toc.push(b"</uid>")?;
    }
    if let Some(gid) = node.gid {
        toc.push(b"<gid>")?;
        toc.number(gid)?;
        toc.push(b"</gid>")?;
    }
    if let Some(mtime) = node.mtime {
        toc.push(b"<mtime>")?;
        toc.push(format_timestamp(mtime)?.as_bytes())?;
        toc.push(b"</mtime>")?;
    }
    if let Some(target) = &node.link_target {
        toc.push(b"<link>")?;
        toc.escaped(target)?;
        toc.push(b"</link>")?;
    }
    if let Some(data) = node.data {
        toc.push(b"<data><length>")?;
        toc.number(data.length)?;
        toc.push(b"</length><offset>")?;
        toc.number(data.offset)?;
        toc.push(b"</offset><size>")?;
        toc.number(data.stored_size)?;
        toc.push(b"</size><encoding style=\"")?;
        toc.push(match data.compression {
            XarCompression::Store => b"application/octet-stream",
            XarCompression::Zlib => b"application/x-gzip",
            XarCompression::Bzip2 => b"application/x-bzip2",
        })?;
        toc.push(b"\"/></data>")?;
    }
    for &child in &node.children {
        emit_node(nodes, child, id, toc)?;
    }
    toc.push(b"</file>")
}

fn format_timestamp(timestamp: Timestamp) -> Result<String, StreamError> {
    let seconds = timestamp.seconds();
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(0..=9999).contains(&year) {
        return Err(xar_error(
            ErrorKind::Unsupported,
            "XAR timestamp year is outside the four-digit XML profile",
        ));
    }
    let hour = day_seconds / 3600;
    let minute = day_seconds % 3600 / 60;
    let second = day_seconds % 60;
    let mut formatted = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
    if timestamp.nanoseconds() != 0 {
        let fraction = format!("{:09}", timestamp.nanoseconds());
        formatted.push('.');
        formatted.push_str(fraction.trim_end_matches('0'));
    }
    formatted.push('Z');
    Ok(formatted)
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = if month_part < 10 {
        month_part + 3
    } else {
        month_part - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}
