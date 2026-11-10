// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded streaming mtree v1/v2 manifest reader and writer.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::mem;

use crate::metadata::{
    ArchivePath, Checksum, ChecksumAlgorithm, Device, EntryMetadata, EntryTimes, Extension, Owner,
};
use crate::protocol::{
    ArchiveDecoder, ArchiveEncoder, DecodeEvent, DecodeStep, EncodeCommand, EncodeStatus,
    EncodeStep, EndOfInput, ProbeResult,
};
use crate::{ArchiveError, EntryKind, ErrorKind, Limits, Timestamp};

const SIGNATURE: &[u8] = b"#mtree";
const HEADER: &[u8] = b"#mtree v2.0\n";

#[derive(Debug)]
struct OptionValue {
    key: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeState {
    Lines,
    EndEntry,
    Done,
}

/// Incremental reader for signed mtree v1/v2 manifests.
#[derive(Debug)]
pub struct MtreeDecoder {
    limits: Limits,
    state: DecodeState,
    line: Vec<u8>,
    defaults: Vec<OptionValue>,
    current_dir: Vec<u8>,
    signature_seen: bool,
    full_paths: bool,
    entries: u64,
}

impl MtreeDecoder {
    /// Creates a reader with explicit finite budgets.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            state: DecodeState::Lines,
            line: Vec::new(),
            defaults: Vec::new(),
            current_dir: Vec::new(),
            signature_seen: false,
            full_paths: false,
            entries: 0,
        }
    }

    /// Detects the standard mtree signature prefix.
    #[must_use]
    pub fn probe(prefix: &[u8]) -> ProbeResult<()> {
        if prefix.len() >= SIGNATURE.len() {
            if prefix.starts_with(SIGNATURE) {
                ProbeResult::Match(())
            } else {
                ProbeResult::NoMatch
            }
        } else if SIGNATURE.starts_with(prefix) {
            ProbeResult::NeedMore {
                minimum: SIGNATURE.len(),
            }
        } else {
            ProbeResult::NoMatch
        }
    }

    fn error(kind: ErrorKind, context: &'static str) -> ArchiveError {
        mtree_error(kind, context)
    }

    fn append_line(&mut self, bytes: &[u8]) -> Result<(), ArchiveError> {
        let length = self
            .line
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| Self::error(ErrorKind::Limit, "mtree line length overflow"))?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| length > maximum)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "mtree logical line exceeds the metadata budget",
            ));
        }
        self.line
            .try_reserve(bytes.len())
            .map_err(|_| Self::error(ErrorKind::Limit, "mtree line allocation failed"))?;
        self.line.extend_from_slice(bytes);
        Ok(())
    }

    fn process_line(&mut self, line: &[u8]) -> Result<Option<EntryMetadata>, ArchiveError> {
        let line = trim_ascii(line);
        if !self.signature_seen {
            if line.is_empty() {
                return Ok(None);
            }
            self.full_paths = Self::parse_signature(line)?;
            self.signature_seen = true;
            return Ok(None);
        }
        if line.is_empty() || line.starts_with(b"#") {
            return Ok(None);
        }
        if let Some(body) = command_body(line, b"/set") {
            self.parse_set(body)?;
            return Ok(None);
        }
        if let Some(body) = command_body(line, b"/unset") {
            self.parse_unset(body)?;
            return Ok(None);
        }
        if !self.full_paths && line == b".." {
            self.pop_current_dir();
            return Ok(None);
        }
        if line.starts_with(b"/") {
            return Err(Self::error(
                ErrorKind::Malformed,
                "unknown mtree special command",
            ));
        }
        self.parse_entry(line).map(Some)
    }

    fn parse_signature(line: &[u8]) -> Result<bool, ArchiveError> {
        let Some(rest) = line.strip_prefix(SIGNATURE) else {
            return Err(Self::error(
                ErrorKind::Malformed,
                "mtree signature must be the first logical line",
            ));
        };
        if rest.is_empty() {
            return Ok(false);
        }
        let rest = trim_ascii(rest);
        match rest {
            b"v1.0" => Ok(false),
            b"v2.0" => Ok(true),
            _ => Err(Self::error(
                ErrorKind::Malformed,
                "unsupported mtree signature version",
            )),
        }
    }

    fn parse_set(&mut self, body: &[u8]) -> Result<(), ArchiveError> {
        if body.is_empty() {
            return Err(Self::error(
                ErrorKind::Malformed,
                "mtree /set requires at least one keyword",
            ));
        }
        for token in body.split(u8::is_ascii_whitespace) {
            if token.is_empty() {
                continue;
            }
            upsert_option(&mut self.defaults, parse_option(token)?)?;
            self.enforce_retained_budget()?;
        }
        Ok(())
    }

    fn parse_unset(&mut self, body: &[u8]) -> Result<(), ArchiveError> {
        if body.is_empty() {
            return Err(Self::error(
                ErrorKind::Malformed,
                "mtree /unset requires at least one keyword",
            ));
        }
        for key in body.split(u8::is_ascii_whitespace) {
            if key.is_empty() {
                continue;
            }
            validate_key(key)?;
            if key == b"all" {
                self.defaults.clear();
            } else if let Some(index) = self.defaults.iter().position(|option| option.key == key) {
                self.defaults.remove(index);
            }
        }
        Ok(())
    }
}

impl MtreeDecoder {
    #[allow(clippy::too_many_lines)]
    fn parse_entry(&mut self, line: &[u8]) -> Result<EntryMetadata, ArchiveError> {
        let mut tokens = line.split(u8::is_ascii_whitespace);
        let raw_path = tokens
            .find(|token| !token.is_empty())
            .ok_or_else(|| Self::error(ErrorKind::Malformed, "mtree entry has no pathname"))?;
        let path_component = decode_escapes(raw_path)?;
        if path_component.is_empty() || path_component.contains(&0) {
            return Err(Self::error(
                ErrorKind::Malformed,
                "mtree pathname is empty or contains NUL",
            ));
        }
        let relative = !self.full_paths && !path_component.iter().skip(1).any(|byte| *byte == b'/');
        if path_component.starts_with(b"/") {
            return Err(Self::error(
                ErrorKind::Malformed,
                "mtree pathname must be relative to the manifest root",
            ));
        }

        let mut options = clone_options(&self.defaults)?;
        for token in tokens.filter(|token| !token.is_empty()) {
            upsert_option(&mut options, parse_option(token)?)?;
        }
        let retained = path_component
            .len()
            .checked_add(options_cost(&options)?)
            .ok_or_else(|| {
                Self::error(ErrorKind::Limit, "mtree retained metadata size overflow")
            })?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| retained > maximum)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "mtree entry metadata exceeds the configured budget",
            ));
        }

        let kind_value = option_value(&options, b"type").ok_or_else(|| {
            Self::error(ErrorKind::Malformed, "mtree entry is missing type keyword")
        })?;
        let kind = parse_kind(kind_value)?;
        let path = self.resolve_path(&path_component, relative)?;
        if self
            .limits
            .path_bytes()
            .is_some_and(|maximum| path.len() > maximum)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "mtree entry pathname exceeds the configured limit",
            ));
        }
        let next_entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "mtree entry count overflow"))?;
        if self
            .limits
            .entries()
            .is_some_and(|maximum| next_entries > maximum)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "mtree entry count exceeds the configured limit",
            ));
        }

        let size = option_value(&options, b"size").map(parse_u64).transpose()?;
        if self
            .limits
            .entry_bytes()
            .is_some_and(|maximum| size.is_some_and(|size| size > maximum))
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "mtree declared entry size exceeds the configured limit",
            ));
        }
        let owner = Owner {
            uid: option_value(&options, b"uid").map(parse_u64).transpose()?,
            gid: option_value(&options, b"gid").map(parse_u64).transpose()?,
            user: option_value(&options, b"uname").map(<[u8]>::to_vec),
            group: option_value(&options, b"gname").map(<[u8]>::to_vec),
        };
        let times = EntryTimes {
            modified: option_value(&options, b"time")
                .map(parse_timestamp)
                .transpose()?,
            ..EntryTimes::default()
        };
        let link_target =
            option_value(&options, b"link").map(|value| ArchivePath::from_bytes(value.to_vec()));
        let inode = option_value(&options, b"inode")
            .map(parse_u64)
            .transpose()?;
        let links = option_value(&options, b"nlink")
            .map(parse_u64)
            .transpose()?;
        let device = option_value(&options, b"resdevice")
            .map(parse_device)
            .transpose()?
            .flatten();
        let referenced_device = option_value(&options, b"device")
            .map(parse_device)
            .transpose()?
            .flatten();
        let checksum = option_value(&options, b"sha256")
            .or_else(|| option_value(&options, b"sha256digest"))
            .map(|value| {
                Checksum::new(ChecksumAlgorithm::Sha256, decode_hex_32(value)?)
                    .map_err(|error| error.with_format("mtree"))
            })
            .transpose()?;

        let mut builder = EntryMetadata::builder(kind, ArchivePath::from_bytes(path.clone()))
            .size(size)
            .owner(owner)
            .times(times)
            .link_target(link_target)
            .inode_and_links(inode, links)
            .devices(device, referenced_device)
            .checksum(checksum);
        if let Some(value) = option_value(&options, b"mode") {
            match parse_mode(value)? {
                Some(mode) => builder = builder.mode(Some(mode)),
                None => {
                    builder = builder.extension(Extension::new(
                        "mtree",
                        b"mode".to_vec(),
                        value.to_vec(),
                    ));
                },
            }
        }
        for option in &options {
            if should_preserve(&option.key, &option.value) {
                builder = builder.extension(Extension::new(
                    "mtree",
                    option.key.clone(),
                    option.value.clone(),
                ));
            }
        }
        let metadata = builder
            .try_build()
            .map_err(|error| error.with_format("mtree"))?;
        self.entries = next_entries;
        if relative && kind == EntryKind::Dir && path_component != b"." {
            self.current_dir = path;
            self.enforce_retained_budget()?;
        }
        Ok(metadata)
    }

    fn resolve_path(&self, component: &[u8], relative: bool) -> Result<Vec<u8>, ArchiveError> {
        if !relative {
            return try_clone_bytes(component);
        }
        if component == b"." {
            return if self.current_dir.is_empty() {
                Ok(b".".to_vec())
            } else {
                try_clone_bytes(&self.current_dir)
            };
        }
        if self.current_dir.is_empty() {
            return try_clone_bytes(component);
        }
        let length = self
            .current_dir
            .len()
            .checked_add(1)
            .and_then(|length| length.checked_add(component.len()))
            .ok_or_else(|| Self::error(ErrorKind::Limit, "mtree pathname length overflow"))?;
        let mut path = Vec::new();
        path.try_reserve_exact(length)
            .map_err(|_| Self::error(ErrorKind::Limit, "mtree pathname allocation failed"))?;
        path.extend_from_slice(&self.current_dir);
        path.push(b'/');
        path.extend_from_slice(component);
        Ok(path)
    }

    fn pop_current_dir(&mut self) {
        if let Some(slash) = self.current_dir.iter().rposition(|byte| *byte == b'/') {
            self.current_dir.truncate(slash);
        } else {
            self.current_dir.clear();
        }
    }

    fn enforce_retained_budget(&self) -> Result<(), ArchiveError> {
        let retained = self
            .current_dir
            .len()
            .checked_add(options_cost(&self.defaults)?)
            .ok_or_else(|| Self::error(ErrorKind::Limit, "mtree metadata size overflow"))?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| retained > maximum)
        {
            return Err(Self::error(
                ErrorKind::Limit,
                "mtree retained defaults exceed the metadata budget",
            ));
        }
        Ok(())
    }
}

impl ArchiveDecoder for MtreeDecoder {
    fn step<'a>(
        &'a mut self,
        input: &'a [u8],
        _output: &'a mut [u8],
        end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        if self.state == DecodeState::EndEntry {
            self.state = DecodeState::Lines;
            return Ok(decode_step(0, DecodeEvent::EndEntry));
        }
        if self.state == DecodeState::Done {
            return Ok(decode_step(0, DecodeEvent::Done));
        }

        let mut consumed = 0_usize;
        loop {
            let remaining = &input[consumed..];
            if let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') {
                self.append_line(&remaining[..newline])?;
                consumed = consumed
                    .checked_add(newline + 1)
                    .ok_or_else(|| Self::error(ErrorKind::Limit, "mtree input offset overflow"))?;
                if self.line.last() == Some(&b'\r') {
                    self.line.pop();
                }
                if self.line.last() == Some(&b'\\') {
                    self.line.pop();
                    continue;
                }
                let line = mem::take(&mut self.line);
                if let Some(metadata) = self.process_line(&line)? {
                    self.state = DecodeState::EndEntry;
                    return Ok(decode_step(consumed, DecodeEvent::Entry(metadata)));
                }
                continue;
            }

            self.append_line(remaining)?;
            consumed = input.len();
            if matches!(end, EndOfInput::More) {
                return Ok(decode_step(consumed, DecodeEvent::NeedInput));
            }
            if self.line.last() == Some(&b'\\') {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "mtree input ends inside a continued logical line",
                ));
            }
            if !self.line.is_empty() {
                let line = mem::take(&mut self.line);
                if let Some(metadata) = self.process_line(&line)? {
                    self.state = DecodeState::EndEntry;
                    return Ok(decode_step(consumed, DecodeEvent::Entry(metadata)));
                }
            }
            if !self.signature_seen {
                return Err(Self::error(
                    ErrorKind::Malformed,
                    "mtree input ended before its signature",
                ));
            }
            self.state = DecodeState::Done;
            return Ok(decode_step(consumed, DecodeEvent::Done));
        }
    }
}

/// Sequential mtree v2 writer.
///
/// mtree describes external filesystem objects and contains no entry payload.
/// Data commands are bounded and size-checked, then deliberately discarded.
#[derive(Debug)]
pub struct MtreeEncoder {
    limits: Limits,
    pending: Vec<u8>,
    pending_pos: usize,
    header_written: bool,
    open: bool,
    remaining: Option<u64>,
    entries: u64,
    total_bytes: u64,
    done: bool,
}

impl MtreeEncoder {
    /// Creates a fresh v2 writer.
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self {
            limits,
            pending: Vec::new(),
            pending_pos: 0,
            header_written: false,
            open: false,
            remaining: None,
            entries: 0,
            total_bytes: 0,
            done: false,
        }
    }

    fn drain_pending(&mut self, output: &mut [u8]) -> usize {
        let remaining = self.pending.len().saturating_sub(self.pending_pos);
        let count = remaining.min(output.len());
        if count != 0 {
            output[..count]
                .copy_from_slice(&self.pending[self.pending_pos..self.pending_pos + count]);
            self.pending_pos += count;
        }
        if self.pending_pos == self.pending.len() {
            self.pending.clear();
            self.pending_pos = 0;
        }
        count
    }

    fn queue_header(&mut self) -> Result<(), ArchiveError> {
        if !self.header_written {
            self.pending
                .try_reserve(HEADER.len())
                .map_err(|_| mtree_error(ErrorKind::Limit, "mtree header allocation failed"))?;
            self.pending.extend_from_slice(HEADER);
            self.header_written = true;
        }
        Ok(())
    }
}

impl ArchiveEncoder for MtreeEncoder {
    #[allow(clippy::too_many_lines)]
    fn step(
        &mut self,
        command: EncodeCommand<'_>,
        output: &mut [u8],
    ) -> Result<EncodeStep, ArchiveError> {
        if self.done {
            return match command {
                EncodeCommand::Finish => Ok(encode_step(0, 0, EncodeStatus::Done)),
                _ => Err(mtree_error(
                    ErrorKind::Protocol,
                    "command supplied after mtree finish",
                )),
            };
        }
        if !self.pending.is_empty() {
            let produced = self.drain_pending(output);
            return Ok(encode_step(
                0,
                produced,
                if self.pending.is_empty() {
                    EncodeStatus::NeedCommand
                } else {
                    EncodeStatus::NeedOutput
                },
            ));
        }

        match command {
            EncodeCommand::BeginEntry(metadata) => {
                if self.open {
                    return Err(mtree_error(
                        ErrorKind::Protocol,
                        "previous mtree entry is still open",
                    ));
                }
                validate_writable_metadata(metadata)?;
                if self
                    .limits
                    .path_bytes()
                    .is_some_and(|maximum| metadata.path().as_bytes().len() > maximum)
                {
                    return Err(mtree_error(
                        ErrorKind::Limit,
                        "mtree entry pathname exceeds the configured limit",
                    ));
                }
                if self
                    .limits
                    .entry_bytes()
                    .is_some_and(|maximum| metadata.size().is_some_and(|size| size > maximum))
                {
                    return Err(mtree_error(
                        ErrorKind::Limit,
                        "mtree declared size exceeds the configured entry limit",
                    ));
                }
                let next_entries = self.entries.checked_add(1).ok_or_else(|| {
                    mtree_error(ErrorKind::Limit, "mtree writer entry count overflow")
                })?;
                if self
                    .limits
                    .entries()
                    .is_some_and(|maximum| next_entries > maximum)
                {
                    return Err(mtree_error(
                        ErrorKind::Limit,
                        "mtree writer entry count exceeds the configured limit",
                    ));
                }
                let line = encode_entry(metadata)?;
                if self
                    .limits
                    .metadata_bytes()
                    .is_some_and(|maximum| line.len() > maximum)
                {
                    return Err(mtree_error(
                        ErrorKind::Limit,
                        "encoded mtree entry exceeds the metadata budget",
                    ));
                }
                self.queue_header()?;
                self.pending
                    .try_reserve(line.len())
                    .map_err(|_| mtree_error(ErrorKind::Limit, "mtree entry allocation failed"))?;
                self.pending.extend_from_slice(&line);
                self.entries = next_entries;
                self.remaining = metadata.size();
                self.open = true;
                let produced = self.drain_pending(output);
                Ok(encode_step(
                    1,
                    produced,
                    if self.pending.is_empty() {
                        EncodeStatus::NeedCommand
                    } else {
                        EncodeStatus::NeedOutput
                    },
                ))
            },
            EncodeCommand::Data(data) => {
                if !self.open {
                    return Err(mtree_error(
                        ErrorKind::Protocol,
                        "mtree entry data supplied without an open entry",
                    ));
                }
                if self
                    .remaining
                    .is_some_and(|remaining| data.len() as u64 > remaining)
                {
                    return Err(mtree_error(
                        ErrorKind::Protocol,
                        "mtree entry data exceeds the declared size",
                    ));
                }
                let next_total =
                    self.total_bytes
                        .checked_add(data.len() as u64)
                        .ok_or_else(|| {
                            mtree_error(ErrorKind::Limit, "mtree writer byte count overflow")
                        })?;
                if self
                    .limits
                    .decoded_total()
                    .is_some_and(|maximum| next_total > maximum)
                {
                    return Err(mtree_error(
                        ErrorKind::Limit,
                        "mtree described bytes exceed the decoded-total limit",
                    ));
                }
                if let Some(remaining) = &mut self.remaining {
                    *remaining -= data.len() as u64;
                }
                self.total_bytes = next_total;
                Ok(encode_step(data.len(), 0, EncodeStatus::NeedCommand))
            },
            EncodeCommand::EndEntry => {
                if !self.open {
                    return Err(mtree_error(
                        ErrorKind::Protocol,
                        "mtree end-entry supplied without an open entry",
                    ));
                }
                if self.remaining.is_some_and(|remaining| remaining != 0) {
                    return Err(mtree_error(
                        ErrorKind::Protocol,
                        "mtree entry data is shorter than its declared size",
                    ));
                }
                self.open = false;
                self.remaining = None;
                Ok(encode_step(1, 0, EncodeStatus::NeedCommand))
            },
            EncodeCommand::Finish => {
                if self.open {
                    return Err(mtree_error(
                        ErrorKind::Protocol,
                        "cannot finish mtree with an open entry",
                    ));
                }
                self.queue_header()?;
                let produced = self.drain_pending(output);
                if self.pending.is_empty() {
                    self.done = true;
                    Ok(encode_step(0, produced, EncodeStatus::Done))
                } else {
                    Ok(encode_step(0, produced, EncodeStatus::NeedOutput))
                }
            },
        }
    }
}

fn parse_option(token: &[u8]) -> Result<OptionValue, ArchiveError> {
    let (key, raw_value) = token
        .iter()
        .position(|byte| *byte == b'=')
        .map_or((token, b"".as_slice()), |equals| {
            (&token[..equals], &token[equals + 1..])
        });
    validate_key(key)?;
    Ok(OptionValue {
        key: try_clone_bytes(key)?,
        value: decode_escapes(raw_value)?,
    })
}

fn validate_key(key: &[u8]) -> Result<(), ArchiveError> {
    if key.is_empty()
        || !key
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(mtree_error(
            ErrorKind::Malformed,
            "invalid mtree keyword name",
        ));
    }
    Ok(())
}

fn upsert_option(options: &mut Vec<OptionValue>, option: OptionValue) -> Result<(), ArchiveError> {
    if let Some(existing) = options
        .iter_mut()
        .find(|existing| existing.key == option.key)
    {
        existing.value = option.value;
    } else {
        options
            .try_reserve(1)
            .map_err(|_| mtree_error(ErrorKind::Limit, "mtree option allocation failed"))?;
        options.push(option);
    }
    Ok(())
}

fn clone_options(options: &[OptionValue]) -> Result<Vec<OptionValue>, ArchiveError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(options.len())
        .map_err(|_| mtree_error(ErrorKind::Limit, "mtree defaults allocation failed"))?;
    for option in options {
        cloned.push(OptionValue {
            key: try_clone_bytes(&option.key)?,
            value: try_clone_bytes(&option.value)?,
        });
    }
    Ok(cloned)
}

fn options_cost(options: &[OptionValue]) -> Result<usize, ArchiveError> {
    options.iter().try_fold(0_usize, |total, option| {
        total
            .checked_add(option.key.len())
            .and_then(|value| value.checked_add(option.value.len()))
            .ok_or_else(|| mtree_error(ErrorKind::Limit, "mtree option size overflow"))
    })
}

fn option_value<'a>(options: &'a [OptionValue], key: &[u8]) -> Option<&'a [u8]> {
    options
        .iter()
        .find(|option| option.key == key)
        .map(|option| option.value.as_slice())
}

fn parse_kind(value: &[u8]) -> Result<EntryKind, ArchiveError> {
    match value {
        b"file" => Ok(EntryKind::File),
        b"dir" => Ok(EntryKind::Dir),
        b"link" => Ok(EntryKind::Symlink),
        b"char" => Ok(EntryKind::Char),
        b"block" => Ok(EntryKind::Block),
        b"fifo" => Ok(EntryKind::Fifo),
        b"socket" => Ok(EntryKind::Socket),
        _ => Err(mtree_error(
            ErrorKind::Unsupported,
            "unsupported mtree entry type",
        )),
    }
}

fn parse_u64(value: &[u8]) -> Result<u64, ArchiveError> {
    let text = core::str::from_utf8(value)
        .map_err(|_| mtree_error(ErrorKind::Malformed, "mtree integer is not ASCII"))?;
    text.parse::<u64>()
        .map_err(|_| mtree_error(ErrorKind::Malformed, "invalid mtree integer"))
}

fn parse_mode(value: &[u8]) -> Result<Option<u32>, ArchiveError> {
    let digits = value.strip_prefix(b"0o").unwrap_or(value);
    if digits.is_empty() || !digits.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Ok(None);
    }
    let text = core::str::from_utf8(digits)
        .map_err(|_| mtree_error(ErrorKind::Malformed, "mtree mode is not ASCII"))?;
    u32::from_str_radix(text, 8)
        .map(Some)
        .map_err(|_| mtree_error(ErrorKind::Malformed, "mtree mode exceeds u32"))
}

fn parse_timestamp(value: &[u8]) -> Result<Timestamp, ArchiveError> {
    let (seconds, fraction) = value
        .iter()
        .position(|byte| *byte == b'.')
        .map_or((value, None), |dot| {
            (&value[..dot], Some(&value[dot + 1..]))
        });
    let seconds = core::str::from_utf8(seconds)
        .map_err(|_| mtree_error(ErrorKind::Malformed, "mtree time is not ASCII"))?
        .parse::<i64>()
        .map_err(|_| mtree_error(ErrorKind::Malformed, "invalid mtree time seconds"))?;
    let nanos = match fraction {
        None => 0,
        Some(fraction)
            if !fraction.is_empty()
                && fraction.len() <= 9
                && fraction.iter().all(u8::is_ascii_digit) =>
        {
            let mut nanos = core::str::from_utf8(fraction)
                .map_err(|_| mtree_error(ErrorKind::Malformed, "mtree time is not ASCII"))?
                .parse::<u32>()
                .map_err(|_| mtree_error(ErrorKind::Malformed, "invalid mtree time fraction"))?;
            for _ in fraction.len()..9 {
                nanos *= 10;
            }
            nanos
        },
        Some(_) => {
            return Err(mtree_error(
                ErrorKind::Malformed,
                "mtree time fraction must contain one to nine digits",
            ));
        },
    };
    Timestamp::new(seconds, nanos).map_err(|error| error.with_format("mtree"))
}

fn parse_device(value: &[u8]) -> Result<Option<Device>, ArchiveError> {
    let parts = value.split(|byte| *byte == b',').collect::<Vec<_>>();
    if parts.len() < 3 || parts.len() > 4 {
        return Ok(None);
    }
    let major = parse_u64(parts[1])?;
    let minor = parse_u64(parts[2])?;
    Ok(Some(Device { major, minor }))
}

fn decode_hex_32(value: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    if value.len() != 64 {
        return Err(mtree_error(
            ErrorKind::Malformed,
            "mtree SHA-256 must contain 64 hexadecimal digits",
        ));
    }
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(32)
        .map_err(|_| mtree_error(ErrorKind::Limit, "mtree checksum allocation failed"))?;
    for pair in value.as_chunks::<2>().0 {
        decoded.push((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?);
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Result<u8, ArchiveError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(mtree_error(
            ErrorKind::Malformed,
            "mtree checksum contains a non-hexadecimal digit",
        )),
    }
}

fn should_preserve(key: &[u8], value: &[u8]) -> bool {
    match key {
        b"type" | b"uid" | b"gid" | b"uname" | b"gname" | b"size" | b"time" | b"link"
        | b"inode" | b"nlink" | b"sha256" | b"sha256digest" => false,
        b"mode" => parse_mode(value).ok().flatten().is_none(),
        b"device" | b"resdevice" => parse_device(value).ok().flatten().is_none(),
        _ => true,
    }
}

fn decode_escapes(input: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    let mut output = Vec::new();
    output
        .try_reserve(input.len())
        .map_err(|_| mtree_error(ErrorKind::Limit, "mtree escape allocation failed"))?;
    let mut cursor = 0_usize;
    while cursor < input.len() {
        if input[cursor] != b'\\' {
            output.push(input[cursor]);
            cursor += 1;
            continue;
        }
        let octal = input
            .get(cursor + 1..cursor + 4)
            .ok_or_else(|| mtree_error(ErrorKind::Malformed, "truncated mtree octal escape"))?;
        if !octal.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
            return Err(mtree_error(
                ErrorKind::Malformed,
                "invalid mtree octal escape",
            ));
        }
        output.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0'));
        cursor += 4;
    }
    Ok(output)
}

fn encode_entry(metadata: &EntryMetadata) -> Result<Vec<u8>, ArchiveError> {
    let mut line = Vec::new();
    encode_escaped(&mut line, metadata.path().as_bytes())?;
    push_keyword(&mut line, b"type", kind_name(metadata.kind()))?;
    if let Some(mode) = metadata.mode() {
        push_keyword(&mut line, b"mode", format!("0{mode:o}").as_bytes())?;
    }
    if let Some(uid) = metadata.owner().uid {
        push_keyword(&mut line, b"uid", uid.to_string().as_bytes())?;
    }
    if let Some(gid) = metadata.owner().gid {
        push_keyword(&mut line, b"gid", gid.to_string().as_bytes())?;
    }
    if let Some(user) = metadata.owner().user.as_deref() {
        push_keyword(&mut line, b"uname", user)?;
    }
    if let Some(group) = metadata.owner().group.as_deref() {
        push_keyword(&mut line, b"gname", group)?;
    }
    if let Some(size) = metadata.size() {
        push_keyword(&mut line, b"size", size.to_string().as_bytes())?;
    }
    if let Some(modified) = metadata.times().modified {
        push_keyword(
            &mut line,
            b"time",
            format!("{}.{:09}", modified.seconds(), modified.nanoseconds()).as_bytes(),
        )?;
    }
    if let Some(inode) = metadata.inode() {
        push_keyword(&mut line, b"inode", inode.to_string().as_bytes())?;
    }
    if let Some(links) = metadata.links() {
        push_keyword(&mut line, b"nlink", links.to_string().as_bytes())?;
    }
    if let Some(target) = metadata.link_target() {
        push_keyword(&mut line, b"link", target.as_bytes())?;
    }
    if let Some(device) = metadata.device() {
        push_keyword(
            &mut line,
            b"resdevice",
            format!("native,{},{}", device.major, device.minor).as_bytes(),
        )?;
    }
    if let Some(device) = metadata.referenced_device() {
        push_keyword(
            &mut line,
            b"device",
            format!("native,{},{}", device.major, device.minor).as_bytes(),
        )?;
    }
    if let Some(checksum) = metadata.checksum() {
        let mut hex = String::new();
        hex.try_reserve(checksum.as_bytes().len().saturating_mul(2))
            .map_err(|_| mtree_error(ErrorKind::Limit, "mtree checksum encoding failed"))?;
        for byte in checksum.as_bytes() {
            use core::fmt::Write as _;
            write!(&mut hex, "{byte:02x}")
                .map_err(|_| mtree_error(ErrorKind::Limit, "mtree checksum encoding failed"))?;
        }
        push_keyword(&mut line, b"sha256", hex.as_bytes())?;
    }
    for extension in metadata
        .extensions()
        .iter()
        .filter(|extension| extension.namespace() == "mtree")
    {
        validate_key(extension.key())?;
        line.push(b' ');
        line.extend_from_slice(extension.key());
        if !extension.value().is_empty() {
            line.push(b'=');
            encode_escaped(&mut line, extension.value())?;
        }
    }
    line.push(b'\n');
    Ok(line)
}

fn validate_writable_metadata(metadata: &EntryMetadata) -> Result<(), ArchiveError> {
    let path = metadata.path().as_bytes();
    if path.starts_with(b"/") || path.contains(&0) {
        return Err(mtree_error(
            ErrorKind::Malformed,
            "mtree entry paths must be relative and contain no NUL bytes",
        ));
    }
    if metadata.kind() == EntryKind::Hardlink {
        return Err(mtree_error(
            ErrorKind::Unsupported,
            "mtree has no hardlink entry type",
        ));
    }
    if !metadata.xattrs().is_empty()
        || !metadata.acl().is_empty()
        || !metadata.sparse_extents().is_empty()
        || metadata.comment().is_some()
        || metadata.file_flags() != 0
        || metadata.is_encrypted()
    {
        return Err(mtree_error(
            ErrorKind::Unsupported,
            "mtree cannot represent requested extended entry metadata",
        ));
    }
    let times = metadata.times();
    if times.accessed.is_some() || times.changed.is_some() || times.created.is_some() {
        return Err(mtree_error(
            ErrorKind::Unsupported,
            "mtree writer represents only modification time",
        ));
    }
    for (index, extension) in metadata.extensions().iter().enumerate() {
        if extension.namespace() != "mtree" {
            return Err(mtree_error(
                ErrorKind::Unsupported,
                "non-mtree extension cannot be represented in mtree",
            ));
        }
        validate_key(extension.key())?;
        if is_typed_keyword(extension.key()) {
            return Err(mtree_error(
                ErrorKind::Unsupported,
                "typed mtree keyword cannot be overridden by an extension",
            ));
        }
        if metadata.extensions()[index + 1..]
            .iter()
            .any(|later| later.namespace() == "mtree" && later.key() == extension.key())
        {
            return Err(mtree_error(
                ErrorKind::Unsupported,
                "duplicate mtree extensions cannot round-trip without loss",
            ));
        }
    }
    if let Some(checksum) = metadata.checksum()
        && checksum.algorithm() != ChecksumAlgorithm::Sha256
    {
        return Err(mtree_error(
            ErrorKind::Unsupported,
            "mtree writer supports typed SHA-256 checksums only",
        ));
    }
    Ok(())
}

fn is_typed_keyword(key: &[u8]) -> bool {
    matches!(
        key,
        b"type"
            | b"mode"
            | b"uid"
            | b"gid"
            | b"uname"
            | b"gname"
            | b"size"
            | b"time"
            | b"inode"
            | b"nlink"
            | b"link"
            | b"device"
            | b"resdevice"
            | b"sha256"
            | b"sha256digest"
    )
}

fn push_keyword(output: &mut Vec<u8>, key: &[u8], value: &[u8]) -> Result<(), ArchiveError> {
    output
        .try_reserve(key.len().saturating_add(value.len()).saturating_add(2))
        .map_err(|_| mtree_error(ErrorKind::Limit, "mtree keyword allocation failed"))?;
    output.push(b' ');
    output.extend_from_slice(key);
    output.push(b'=');
    encode_escaped(output, value)
}

fn encode_escaped(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ArchiveError> {
    const OCTAL: &[u8; 8] = b"01234567";
    output
        .try_reserve(value.len())
        .map_err(|_| mtree_error(ErrorKind::Limit, "mtree escape allocation failed"))?;
    for byte in value {
        if matches!(*byte, b'!'..=b'~') && !matches!(*byte, b'\\' | b'#') {
            output.push(*byte);
        } else {
            output
                .try_reserve(4)
                .map_err(|_| mtree_error(ErrorKind::Limit, "mtree escape allocation failed"))?;
            output.extend_from_slice(&[
                b'\\',
                OCTAL[usize::from(*byte >> 6)],
                OCTAL[usize::from((*byte >> 3) & 7)],
                OCTAL[usize::from(*byte & 7)],
            ]);
        }
    }
    Ok(())
}

fn kind_name(kind: EntryKind) -> &'static [u8] {
    match kind {
        EntryKind::File => b"file",
        EntryKind::Dir => b"dir",
        EntryKind::Symlink => b"link",
        EntryKind::Char => b"char",
        EntryKind::Block => b"block",
        EntryKind::Fifo => b"fifo",
        EntryKind::Socket => b"socket",
        EntryKind::Hardlink => b"hardlink",
    }
}

fn command_body<'a>(line: &'a [u8], command: &[u8]) -> Option<&'a [u8]> {
    let rest = line.strip_prefix(command)?;
    if rest.is_empty() {
        Some(rest)
    } else if rest.first().is_some_and(u8::is_ascii_whitespace) {
        Some(trim_ascii(rest))
    } else {
        None
    }
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn try_clone_bytes(bytes: &[u8]) -> Result<Vec<u8>, ArchiveError> {
    let mut cloned = Vec::new();
    cloned
        .try_reserve_exact(bytes.len())
        .map_err(|_| mtree_error(ErrorKind::Limit, "mtree metadata allocation failed"))?;
    cloned.extend_from_slice(bytes);
    Ok(cloned)
}

fn decode_step(consumed: usize, event: DecodeEvent<'_>) -> DecodeStep<'_> {
    DecodeStep {
        consumed,
        produced: 0,
        event,
    }
}

const fn encode_step(consumed: usize, produced: usize, status: EncodeStatus) -> EncodeStep {
    EncodeStep {
        consumed,
        produced,
        status,
    }
}

fn mtree_error(kind: ErrorKind, context: &'static str) -> ArchiveError {
    ArchiveError::new(kind)
        .with_format("mtree")
        .with_context(context)
}
