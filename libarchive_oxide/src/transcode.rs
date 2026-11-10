// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded archive-to-archive streaming with explicit metadata-loss reports.

use std::io::{Read, Seek, Write};
use std::mem::size_of;

use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, ArchivePath, ChecksumAlgorithm, Device, EntryKind,
    EntryMetadata, EntryTimes, ErrorKind, Extension, FormatId, Limits, Owner, Timestamp,
    ar_bsd_inline_name_size, cpio_name_is_trailer,
};

use crate::iso_stream::{
    iso_archive_extension_supported, iso_entry_extension_supported, iso_volume_name_supported,
};
use crate::zip_stream::zip_entry_extension_supported;
use crate::{
    ArchiveEngine, ArchiveReader, ArchiveWriter, CreateOptions, OpenOptions, ReaderEvent,
    SeekArchiveReader, SeekArchiveWriter, StreamError,
};

const DEFAULT_MAXIMUM_METADATA_LOSSES: usize = 4_096;

/// Behavior when a destination cannot represent source metadata.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetadataLossPolicy {
    /// Continue and return every loss in the bounded report.
    #[default]
    Report,
    /// Fail before starting the affected archive entry.
    Reject,
}

/// A metadata component that the selected destination cannot represent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MetadataField {
    /// Archive volume name.
    ArchiveVolumeName,
    /// Archive-level comment.
    ArchiveComment,
    /// Archive-level format extensions.
    ArchiveExtensions,
    /// Declared size on an entry kind that stores no body.
    DeclaredSize,
    /// Entry path bytes are not represented by the destination.
    EntryPath,
    /// Permission or file-type mode bits.
    Mode,
    /// Numeric user and group identifiers.
    OwnerIds,
    /// User and group names.
    OwnerNames,
    /// Modification time.
    ModifiedTime,
    /// Access time.
    AccessedTime,
    /// Metadata-change time.
    ChangedTime,
    /// Creation or birth time.
    CreatedTime,
    /// Archive inode and link count.
    InodeAndLinkCount,
    /// Filesystem and referenced device numbers.
    Devices,
    /// Sparse data map.
    SparseMap,
    /// Extended attributes.
    ExtendedAttributes,
    /// Access-control lists.
    Acl,
    /// Filesystem flags.
    FileFlags,
    /// Entry checksum metadata.
    Checksum,
    /// Source encryption marker.
    Encryption,
    /// Entry-level comment.
    EntryComment,
    /// Entry-level format extensions.
    EntryExtensions,
}

/// One explicitly reported metadata loss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataLoss {
    entry_index: Option<u64>,
    path: Option<ArchivePath>,
    field: MetadataField,
}

impl MetadataLoss {
    /// Zero-based entry index, or `None` for archive-level metadata.
    #[must_use]
    pub const fn entry_index(&self) -> Option<u64> {
        self.entry_index
    }

    /// Source entry path, or `None` for archive-level metadata.
    #[must_use]
    pub const fn path(&self) -> Option<&ArchivePath> {
        self.path.as_ref()
    }

    /// Metadata component that was not copied.
    #[must_use]
    pub const fn field(&self) -> MetadataField {
        self.field
    }
}

/// Completed transcoding statistics and fidelity findings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TranscodeReport {
    entries: u64,
    payload_bytes: u64,
    metadata_losses: Vec<MetadataLoss>,
    metadata_loss_bytes: usize,
}

impl TranscodeReport {
    /// Number of entries copied.
    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.entries
    }

    /// Number of decoded payload bytes copied.
    #[must_use]
    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    /// Every metadata loss, in archive and entry order.
    #[must_use]
    pub fn metadata_losses(&self) -> &[MetadataLoss] {
        &self.metadata_losses
    }
}

/// Successful transcoding result containing the destination and its report.
#[derive(Debug)]
pub struct TranscodeOutcome<W> {
    output: W,
    report: TranscodeReport,
}

impl<W> TranscodeOutcome<W> {
    /// Fidelity and byte-count report.
    #[must_use]
    pub const fn report(&self) -> &TranscodeReport {
        &self.report
    }

    /// Returns the completed destination.
    #[must_use]
    pub fn into_output(self) -> W {
        self.output
    }

    /// Returns the completed destination and report.
    #[must_use]
    pub fn into_parts(self) -> (W, TranscodeReport) {
        (self.output, self.report)
    }
}

/// Stateless bounded archive-to-archive rewrite configuration.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveTranscoder {
    metadata_loss_policy: MetadataLossPolicy,
    maximum_metadata_losses: usize,
}

impl ArchiveTranscoder {
    /// Creates a transcoder that reports metadata loss and caps findings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            metadata_loss_policy: MetadataLossPolicy::Report,
            maximum_metadata_losses: DEFAULT_MAXIMUM_METADATA_LOSSES,
        }
    }

    /// Selects whether unrepresentable metadata is reported or rejected.
    #[must_use]
    pub const fn with_metadata_loss_policy(mut self, policy: MetadataLossPolicy) -> Self {
        self.metadata_loss_policy = policy;
        self
    }

    /// Caps stored loss records.
    /// Exceeding the cap is a typed limit error.
    #[must_use]
    pub const fn with_maximum_metadata_losses(mut self, maximum: usize) -> Self {
        self.maximum_metadata_losses = maximum;
        self
    }

    /// Transcodes a forward-only source to a sequential destination.
    pub fn transcode<R: Read, W: Write>(
        self,
        input: R,
        source: &OpenOptions,
        output: W,
        destination: CreateOptions,
    ) -> Result<TranscodeOutcome<W>, StreamError> {
        validate_destination(destination.format())?;
        let mut reader = ArchiveReader::with_options(input, source)?;
        let mut writer = ArchiveEngine::new()
            .with_limits(source.limits())
            .create(output, destination)?;
        let report = copy_events(
            &mut reader,
            &mut writer,
            destination.format(),
            source.limits(),
            self,
        )?;
        let output = writer.finish()?;
        Ok(TranscodeOutcome { output, report })
    }

    /// Transcodes a forward-only source to a seek-capable destination.
    pub fn transcode_to_seek<R: Read, W: Write + Seek>(
        self,
        input: R,
        source: &OpenOptions,
        output: W,
        destination: CreateOptions,
    ) -> Result<TranscodeOutcome<W>, StreamError> {
        validate_destination(destination.format())?;
        let mut reader = ArchiveReader::with_options(input, source)?;
        let mut writer = ArchiveEngine::new()
            .with_limits(source.limits())
            .create_seek(output, destination)?;
        let report = copy_events(
            &mut reader,
            &mut writer,
            destination.format(),
            source.limits(),
            self,
        )?;
        let output = writer.finish()?;
        Ok(TranscodeOutcome { output, report })
    }

    /// Transcodes a seek-native source to a sequential destination.
    pub fn transcode_from_seek<R: Read + Seek, W: Write>(
        self,
        input: R,
        source: &OpenOptions,
        output: W,
        destination: CreateOptions,
    ) -> Result<TranscodeOutcome<W>, StreamError> {
        validate_destination(destination.format())?;
        let mut reader = SeekArchiveReader::with_options(input, source)?;
        let mut writer = ArchiveEngine::new()
            .with_limits(source.limits())
            .create(output, destination)?;
        let report = copy_events(
            &mut reader,
            &mut writer,
            destination.format(),
            source.limits(),
            self,
        )?;
        let output = writer.finish()?;
        Ok(TranscodeOutcome { output, report })
    }

    /// Transcodes a seekable source to a seek-capable destination.
    ///
    /// Sequential destination formats also work through their shared seek writer adapter.
    /// Seek-native sources can use password candidates supplied by `source`; destination encryption still requires a dedicated writer.
    pub fn transcode_seek<R: Read + Seek, W: Write + Seek>(
        self,
        input: R,
        source: &OpenOptions,
        output: W,
        destination: CreateOptions,
    ) -> Result<TranscodeOutcome<W>, StreamError> {
        validate_destination(destination.format())?;
        let mut reader = SeekArchiveReader::with_options(input, source)?;
        let mut writer = ArchiveEngine::new()
            .with_limits(source.limits())
            .create_seek(output, destination)?;
        let report = copy_events(
            &mut reader,
            &mut writer,
            destination.format(),
            source.limits(),
            self,
        )?;
        let output = writer.finish()?;
        Ok(TranscodeOutcome { output, report })
    }
}

impl Default for ArchiveTranscoder {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) trait EventSource {
    fn next_transcode_event(&mut self) -> Result<ReaderEvent<'_>, StreamError>;
    fn source_format(&self) -> Option<FormatId>;
}

impl<R: Read> EventSource for ArchiveReader<R> {
    fn next_transcode_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.next_event()
    }

    fn source_format(&self) -> Option<FormatId> {
        self.format()
    }
}

impl<R: Read + Seek> EventSource for SeekArchiveReader<R> {
    fn next_transcode_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.next_event()
    }

    fn source_format(&self) -> Option<FormatId> {
        Some(self.format())
    }
}

pub(crate) trait EventSink {
    fn set_transcode_archive_metadata(
        &mut self,
        metadata: &ArchiveMetadata,
    ) -> Result<(), StreamError>;
    fn start_transcode_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError>;
    fn write_transcode_data(&mut self, bytes: &[u8]) -> Result<(), StreamError>;
    fn end_transcode_entry(&mut self) -> Result<(), StreamError>;
}

impl<W: Write> EventSink for ArchiveWriter<W> {
    fn set_transcode_archive_metadata(
        &mut self,
        metadata: &ArchiveMetadata,
    ) -> Result<(), StreamError> {
        self.set_archive_metadata(metadata)
    }

    fn start_transcode_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        self.start_entry(metadata)
    }

    fn write_transcode_data(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        self.write_data(bytes)
    }

    fn end_transcode_entry(&mut self) -> Result<(), StreamError> {
        self.end_entry()
    }
}

impl<W: Write + Seek> EventSink for SeekArchiveWriter<W> {
    fn set_transcode_archive_metadata(
        &mut self,
        metadata: &ArchiveMetadata,
    ) -> Result<(), StreamError> {
        self.set_archive_metadata(metadata)
    }

    fn start_transcode_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        self.start_entry(metadata)
    }

    fn write_transcode_data(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        self.write_data(bytes)
    }

    fn end_transcode_entry(&mut self) -> Result<(), StreamError> {
        self.end_entry()
    }
}

fn copy_events(
    reader: &mut impl EventSource,
    writer: &mut impl EventSink,
    destination: FormatId,
    limits: Limits,
    transcoder: ArchiveTranscoder,
) -> Result<TranscodeReport, StreamError> {
    copy_events_with_transform(
        reader,
        writer,
        destination,
        limits,
        transcoder,
        &mut |metadata| Ok(Some(metadata)),
    )
}

pub(crate) fn copy_events_with_transform(
    reader: &mut impl EventSource,
    writer: &mut impl EventSink,
    destination: FormatId,
    limits: Limits,
    transcoder: ArchiveTranscoder,
    transform: &mut impl FnMut(EntryMetadata) -> Result<Option<EntryMetadata>, StreamError>,
) -> Result<TranscodeReport, StreamError> {
    let mut report = TranscodeReport::default();
    let mut checked_source = false;
    let mut skipping_entry = false;
    let mut metadata_owned_payload = false;
    let mut pending_archive_metadata = ArchiveMetadata::new();
    loop {
        let event = reader.next_transcode_event()?;
        match event {
            ReaderEvent::ArchiveMetadata(metadata) => {
                if !checked_source {
                    reject_metadata_only_source(reader.source_format())?;
                    checked_source = true;
                }
                let (metadata, losses) = project_archive_metadata(&metadata, destination);
                add_losses(&mut report, losses, None, None, limits, transcoder)?;
                if report.entries == 0 {
                    merge_archive_metadata(&mut pending_archive_metadata, &metadata);
                } else {
                    add_losses(
                        &mut report,
                        archive_metadata_fields(&metadata),
                        None,
                        None,
                        limits,
                        transcoder,
                    )?;
                }
            },
            ReaderEvent::Entry(metadata) => {
                if !checked_source {
                    reject_metadata_only_source(reader.source_format())?;
                    checked_source = true;
                }
                skipping_entry = false;
                metadata_owned_payload = false;
                let Some(metadata) = transform(metadata)? else {
                    skipping_entry = true;
                    continue;
                };
                flush_archive_metadata(writer, &mut pending_archive_metadata)?;
                let entry_index = report.entries;
                let path = metadata.path().clone();
                let (metadata, losses) = project_entry_metadata(&metadata, destination)?;
                metadata_owned_payload = matches!(destination, FormatId::Zip | FormatId::SevenZip)
                    && metadata.kind() == EntryKind::Symlink;
                add_losses(
                    &mut report,
                    losses,
                    Some(entry_index),
                    Some(&path),
                    limits,
                    transcoder,
                )?;
                writer.start_transcode_entry(&metadata)?;
                report.entries = report.entries.checked_add(1).ok_or_else(|| {
                    transcode_error(ErrorKind::Limit, "transcoded entry count overflow")
                })?;
            },
            ReaderEvent::Data(bytes) => {
                if skipping_entry {
                    continue;
                }
                report.payload_bytes = report
                    .payload_bytes
                    .checked_add(bytes.len() as u64)
                    .ok_or_else(|| {
                        transcode_error(ErrorKind::Limit, "transcoded payload byte count overflow")
                    })?;
                if !metadata_owned_payload {
                    writer.write_transcode_data(bytes)?;
                }
            },
            ReaderEvent::EndEntry => {
                if skipping_entry {
                    skipping_entry = false;
                } else {
                    writer.end_transcode_entry()?;
                }
                metadata_owned_payload = false;
            },
            ReaderEvent::Done => {
                if !checked_source {
                    reject_metadata_only_source(reader.source_format())?;
                }
                flush_archive_metadata(writer, &mut pending_archive_metadata)?;
                return Ok(report);
            },
        }
    }
}

fn merge_archive_metadata(target: &mut ArchiveMetadata, source: &ArchiveMetadata) {
    let mut merged = core::mem::take(target);
    if let Some(volume_name) = source.volume_name() {
        merged = merged.with_volume_name(volume_name.clone());
    }
    if let Some(comment) = source.comment() {
        merged = merged.with_comment(comment);
    }
    for extension in source.extensions() {
        merged = merged.with_extension(extension.clone());
    }
    *target = merged;
}

fn flush_archive_metadata(
    writer: &mut impl EventSink,
    pending: &mut ArchiveMetadata,
) -> Result<(), StreamError> {
    if *pending != ArchiveMetadata::new() {
        writer.set_transcode_archive_metadata(pending)?;
        *pending = ArchiveMetadata::new();
    }
    Ok(())
}

fn archive_metadata_fields(metadata: &ArchiveMetadata) -> Vec<MetadataField> {
    let mut fields = Vec::new();
    if metadata.volume_name().is_some() {
        fields.push(MetadataField::ArchiveVolumeName);
    }
    if metadata.comment().is_some() {
        fields.push(MetadataField::ArchiveComment);
    }
    if !metadata.extensions().is_empty() {
        fields.push(MetadataField::ArchiveExtensions);
    }
    fields
}

pub(crate) fn validate_destination(format: FormatId) -> Result<(), StreamError> {
    if format == FormatId::Mtree {
        return Err(transcode_error(
            ErrorKind::Unsupported,
            "mtree is a metadata-only destination and would discard entry payloads",
        ));
    }
    Ok(())
}

fn reject_metadata_only_source(format: Option<FormatId>) -> Result<(), StreamError> {
    if format == Some(FormatId::Mtree) {
        return Err(transcode_error(
            ErrorKind::Unsupported,
            "mtree is a metadata-only source and cannot supply entry payloads",
        ));
    }
    Ok(())
}

fn add_losses(
    report: &mut TranscodeReport,
    fields: Vec<MetadataField>,
    entry_index: Option<u64>,
    path: Option<&ArchivePath>,
    limits: Limits,
    transcoder: ArchiveTranscoder,
) -> Result<(), StreamError> {
    if fields.is_empty() {
        return Ok(());
    }
    if transcoder.metadata_loss_policy == MetadataLossPolicy::Reject {
        return Err(transcode_error(
            ErrorKind::Unsupported,
            "destination conversion would cause metadata loss",
        ));
    }
    for field in fields {
        if report.metadata_losses.len() >= transcoder.maximum_metadata_losses {
            return Err(transcode_error(
                ErrorKind::Limit,
                "metadata loss report exceeds configured record limit",
            ));
        }
        let charge = size_of::<MetadataLoss>()
            .checked_add(path.map_or(0, |value| value.as_bytes().len()))
            .ok_or_else(|| {
                transcode_error(ErrorKind::Limit, "metadata loss accounting overflow")
            })?;
        report.metadata_loss_bytes =
            report
                .metadata_loss_bytes
                .checked_add(charge)
                .ok_or_else(|| {
                    transcode_error(ErrorKind::Limit, "metadata loss accounting overflow")
                })?;
        if limits
            .metadata_bytes()
            .is_some_and(|maximum| report.metadata_loss_bytes > maximum)
        {
            return Err(transcode_error(
                ErrorKind::Limit,
                "metadata loss report exceeds source metadata budget",
            ));
        }
        report.metadata_losses.push(MetadataLoss {
            entry_index,
            path: path.cloned(),
            field,
        });
    }
    Ok(())
}

fn project_archive_metadata(
    metadata: &ArchiveMetadata,
    destination: FormatId,
) -> (ArchiveMetadata, Vec<MetadataField>) {
    let mut output = ArchiveMetadata::new();
    let mut losses = Vec::new();
    if let Some(volume_name) = metadata.volume_name() {
        if destination == FormatId::Iso9660 && iso_volume_name_supported(volume_name) {
            output = output.with_volume_name(volume_name.clone());
        } else {
            losses.push(MetadataField::ArchiveVolumeName);
        }
    }
    if let Some(comment) = metadata.comment() {
        if destination == FormatId::Tar || (destination == FormatId::Zip && !comment.is_empty()) {
            output = output.with_comment(comment.to_vec());
        } else {
            losses.push(MetadataField::ArchiveComment);
        }
    }
    let mut dropped_extension = false;
    let mut iso_system_id = false;
    let mut iso_application_id = false;
    for extension in metadata.extensions() {
        let supported = archive_extension_supported(destination, extension);
        let unique = if supported && destination == FormatId::Iso9660 {
            match extension.key() {
                b"system-id" => {
                    let unique = !iso_system_id;
                    iso_system_id = true;
                    unique
                },
                b"application-id" => {
                    let unique = !iso_application_id;
                    iso_application_id = true;
                    unique
                },
                _ => false,
            }
        } else {
            true
        };
        if supported && unique {
            output = output.with_extension(extension.clone());
        } else {
            dropped_extension = true;
        }
    }
    if dropped_extension {
        losses.push(MetadataField::ArchiveExtensions);
    }
    (output, losses)
}

fn archive_extension_supported(destination: FormatId, extension: &Extension) -> bool {
    match destination {
        FormatId::Tar => tar_archive_extension_supported(extension),
        FormatId::Iso9660 => iso_archive_extension_supported(extension),
        FormatId::SevenZip => {
            #[cfg(feature = "sevenz")]
            {
                crate::sevenz::sevenz_archive_extension_supported(extension)
            }
            #[cfg(not(feature = "sevenz"))]
            {
                false
            }
        },
        _ => false,
    }
}

fn tar_archive_extension_supported(extension: &Extension) -> bool {
    if extension.namespace() != "pax" {
        return false;
    }
    let key = extension.key();
    if key == b"LIBARCHIVE.comment" {
        return true;
    }
    !key.starts_with(b"GNU.sparse.")
        && !key.starts_with(b"SCHILY.xattr.")
        && !matches!(
            key,
            b"path"
                | b"linkpath"
                | b"size"
                | b"uid"
                | b"gid"
                | b"mtime"
                | b"atime"
                | b"ctime"
                | b"LIBARCHIVE.creationtime"
                | b"SCHILY.birthtime"
                | b"uname"
                | b"gname"
                | b"SCHILY.acl.access"
                | b"SCHILY.acl.default"
                | b"LIBARCHIVE.acl.access"
                | b"LIBARCHIVE.acl.default"
        )
}

#[allow(clippy::too_many_lines)]
fn project_entry_metadata(
    metadata: &EntryMetadata,
    destination: FormatId,
) -> Result<(EntryMetadata, Vec<MetadataField>), StreamError> {
    validate_entry_kind(metadata.kind(), destination)?;
    validate_entry_path(metadata, destination)?;
    validate_declared_size(metadata, destination)?;
    let mut losses = Vec::new();
    if destination == FormatId::Warc {
        losses.push(MetadataField::EntryPath);
    }
    let mut builder = EntryMetadata::builder(metadata.kind(), metadata.path().clone());

    let size = if matches!(destination, FormatId::Zip | FormatId::SevenZip)
        && metadata.kind() == EntryKind::Symlink
    {
        let target_size = metadata
            .link_target()
            .map(|target| target.as_bytes().len() as u64)
            .ok_or_else(|| {
                transcode_error(
                    ErrorKind::Malformed,
                    "symbolic link is missing its target metadata",
                )
            })?;
        if metadata.size() != Some(target_size) {
            losses.push(MetadataField::DeclaredSize);
        }
        Some(target_size)
    } else if metadata.kind() != EntryKind::File
        && metadata.size().is_some_and(|size| size != 0)
        && matches!(destination, FormatId::Iso9660 | FormatId::Xar)
    {
        losses.push(MetadataField::DeclaredSize);
        Some(0)
    } else {
        metadata.size()
    };
    builder = builder.size(size);

    let (mode, mode_loss) = project_mode(destination, metadata.mode());
    builder = builder.mode(mode);
    if mode_loss {
        losses.push(MetadataField::Mode);
    }

    let owner = metadata.owner();
    let mut projected_owner = Owner::default();
    let (uid, gid, owner_ids_loss) = project_owner_ids(destination, owner);
    projected_owner.uid = uid;
    projected_owner.gid = gid;
    if owner_ids_loss {
        losses.push(MetadataField::OwnerIds);
    }
    if owner_names_supported(destination) {
        projected_owner.user.clone_from(&owner.user);
        projected_owner.group.clone_from(&owner.group);
    } else if owner.user.is_some() || owner.group.is_some() {
        losses.push(MetadataField::OwnerNames);
    }
    builder = builder.owner(projected_owner);

    let times = metadata.times();
    let (modified, modified_loss) =
        project_timestamp(destination, MetadataField::ModifiedTime, times.modified);
    let (accessed, accessed_loss) =
        project_timestamp(destination, MetadataField::AccessedTime, times.accessed);
    let (changed, changed_loss) =
        project_timestamp(destination, MetadataField::ChangedTime, times.changed);
    let (created, created_loss) =
        project_timestamp(destination, MetadataField::CreatedTime, times.created);
    for (field, lost) in [
        (MetadataField::ModifiedTime, modified_loss),
        (MetadataField::AccessedTime, accessed_loss),
        (MetadataField::ChangedTime, changed_loss),
        (MetadataField::CreatedTime, created_loss),
    ] {
        if lost {
            losses.push(field);
        }
    }
    builder = builder.times(EntryTimes {
        modified,
        accessed,
        changed,
        created,
    });
    builder = builder.link_target(metadata.link_target().cloned());

    let (inode, links, dropped_inode) =
        project_inode_and_links(destination, metadata.inode(), metadata.links());
    builder = builder.inode_and_links(inode, links);
    if dropped_inode {
        losses.push(MetadataField::InodeAndLinkCount);
    }
    let (device, referenced_device, dropped_device) = project_devices(metadata, destination)?;
    builder = builder.devices(device, referenced_device);
    if dropped_device {
        losses.push(MetadataField::Devices);
    }
    if sparse_supported(destination) {
        for extent in metadata.sparse_extents() {
            builder = builder.sparse_extent(*extent);
        }
    } else if !metadata.sparse_extents().is_empty() {
        losses.push(MetadataField::SparseMap);
    }
    if xattrs_supported(destination) {
        for (name, value) in metadata.xattrs() {
            builder = builder.xattr(name.clone(), value.clone());
        }
    } else if !metadata.xattrs().is_empty() {
        losses.push(MetadataField::ExtendedAttributes);
    }
    if acl_supported(destination) {
        for acl in metadata.acl() {
            builder = builder.acl(acl.clone());
        }
    } else if !metadata.acl().is_empty() {
        losses.push(MetadataField::Acl);
    }
    if metadata.file_flags() != 0 {
        losses.push(MetadataField::FileFlags);
    }

    if checksum_supported(destination, metadata) {
        builder = builder.checksum(metadata.checksum().cloned());
    } else if metadata.checksum().is_some() {
        losses.push(MetadataField::Checksum);
    }
    if metadata.is_encrypted() {
        losses.push(MetadataField::Encryption);
    }
    if entry_comment_supported(destination, metadata.comment()) {
        builder = builder.comment(metadata.comment().map(<[u8]>::to_vec));
    } else if metadata.comment().is_some() {
        losses.push(MetadataField::EntryComment);
    }
    let mut dropped_extension = false;
    for extension in metadata.extensions() {
        if entry_extension_supported(destination, extension) {
            builder = builder.extension(extension.clone());
        } else {
            dropped_extension = true;
        }
    }
    if dropped_extension {
        losses.push(MetadataField::EntryExtensions);
    }
    let projected = builder.try_build().map_err(StreamError::archive)?;
    Ok((projected, losses))
}

fn validate_entry_path(metadata: &EntryMetadata, destination: FormatId) -> Result<(), StreamError> {
    if destination == FormatId::Cpio && cpio_name_is_trailer(metadata.path().as_bytes()) {
        return Err(transcode_error(
            ErrorKind::Unsupported,
            "cpio trailer sentinel cannot be encoded as an entry path",
        ));
    }
    Ok(())
}

fn validate_declared_size(
    metadata: &EntryMetadata,
    destination: FormatId,
) -> Result<(), StreamError> {
    let size = metadata.size();
    if matches!(destination, FormatId::Cpio | FormatId::Ar | FormatId::Warc) && size.is_none() {
        return Err(transcode_error(
            ErrorKind::SizeRequired,
            "destination requires a declared entry size",
        ));
    }
    let Some(size) = size else {
        return Ok(());
    };
    let representable = match destination {
        FormatId::Cpio => u32::try_from(size).is_ok(),
        FormatId::Iso9660 if metadata.kind() == EntryKind::File => u32::try_from(size).is_ok(),
        FormatId::Ar => {
            const MAXIMUM_MEMBER_SIZE: u64 = 9_999_999_999;
            let inline_name_size = ar_bsd_inline_name_size(metadata.path().as_bytes())
                .and_then(|size| u64::try_from(size).ok());
            inline_name_size
                .and_then(|name_size| size.checked_add(name_size))
                .is_some_and(|total| total <= MAXIMUM_MEMBER_SIZE)
        },
        _ => true,
    };
    if representable {
        Ok(())
    } else {
        Err(transcode_error(
            ErrorKind::Unsupported,
            "declared entry size exceeds the destination wire field",
        ))
    }
}

fn validate_entry_kind(kind: EntryKind, destination: FormatId) -> Result<(), StreamError> {
    let supported = match destination {
        FormatId::Ar | FormatId::Warc => kind == EntryKind::File,
        FormatId::Tar => matches!(
            kind,
            EntryKind::File
                | EntryKind::Dir
                | EntryKind::Symlink
                | EntryKind::Hardlink
                | EntryKind::Char
                | EntryKind::Block
                | EntryKind::Fifo
        ),
        FormatId::Zip | FormatId::SevenZip | FormatId::Xar => {
            matches!(kind, EntryKind::File | EntryKind::Dir | EntryKind::Symlink)
        },
        FormatId::Iso9660 => matches!(
            kind,
            EntryKind::File
                | EntryKind::Dir
                | EntryKind::Symlink
                | EntryKind::Char
                | EntryKind::Block
                | EntryKind::Fifo
                | EntryKind::Socket
        ),
        FormatId::Mtree => false,
        _ => true,
    };
    if supported {
        Ok(())
    } else {
        Err(transcode_error(
            ErrorKind::Unsupported,
            "destination cannot represent the source entry kind",
        ))
    }
}

fn mode_supported(destination: FormatId, mode: Option<u32>) -> bool {
    match destination {
        FormatId::Tar | FormatId::Cpio | FormatId::Ar | FormatId::Zip => {
            mode.is_none_or(|value| value <= 0o7777)
        },
        FormatId::Warc => mode == Some(0o644),
        FormatId::SevenZip => mode.is_none_or(|value| value != 0 && value <= 0o7777),
        FormatId::Iso9660 => mode.is_none_or(|value| value <= 0o7777),
        _ => true,
    }
}

fn project_mode(destination: FormatId, mode: Option<u32>) -> (Option<u32>, bool) {
    if mode_supported(destination, mode) {
        return (mode, false);
    }
    if matches!(
        destination,
        FormatId::Tar | FormatId::Cpio | FormatId::Ar | FormatId::Zip
    ) {
        return (mode.map(|value| value & 0o7777), true);
    }
    if destination == FormatId::Warc {
        return (Some(0o644), true);
    }
    (None, mode.is_some())
}

fn project_owner_ids(destination: FormatId, owner: &Owner) -> (Option<u64>, Option<u64>, bool) {
    let exact = match destination {
        FormatId::Tar | FormatId::Xar | FormatId::Mtree => true,
        FormatId::Cpio | FormatId::Iso9660 => owner
            .uid
            .into_iter()
            .chain(owner.gid)
            .all(|value| u32::try_from(value).is_ok()),
        FormatId::Ar => owner
            .uid
            .into_iter()
            .chain(owner.gid)
            .all(|value| value < 1_000_000),
        FormatId::Zip => match (owner.uid, owner.gid) {
            (None, None) => true,
            (Some(uid), Some(gid)) => u16::try_from(uid).is_ok() && u16::try_from(gid).is_ok(),
            _ => false,
        },
        _ => owner.uid.is_none() && owner.gid.is_none(),
    };
    if exact {
        (owner.uid, owner.gid, false)
    } else {
        (None, None, true)
    }
}

fn owner_names_supported(destination: FormatId) -> bool {
    matches!(destination, FormatId::Tar | FormatId::Mtree)
}

fn sevenz_timestamp_supported(timestamp: Timestamp) -> bool {
    const FILETIME_EPOCH_DIFF: i128 = 11_644_473_600;
    if !timestamp.nanoseconds().is_multiple_of(100) {
        return false;
    }
    i128::from(timestamp.seconds())
        .checked_add(FILETIME_EPOCH_DIFF)
        .and_then(|seconds| seconds.checked_mul(10_000_000))
        .and_then(|ticks| ticks.checked_add(i128::from(timestamp.nanoseconds() / 100)))
        .and_then(|ticks| u64::try_from(ticks).ok())
        .is_some()
}

fn project_timestamp(
    destination: FormatId,
    field: MetadataField,
    timestamp: Option<Timestamp>,
) -> (Option<Timestamp>, bool) {
    let Some(timestamp) = timestamp else {
        return (None, false);
    };
    let supported = match destination {
        FormatId::Tar | FormatId::Iso9660 => true,
        FormatId::Zip => field != MetadataField::CreatedTime,
        FormatId::Cpio | FormatId::Ar | FormatId::SevenZip | FormatId::Xar | FormatId::Mtree => {
            field == MetadataField::ModifiedTime
        },
        _ => false,
    };
    if !supported {
        return (None, true);
    }
    let exact = match destination {
        FormatId::Tar | FormatId::Xar | FormatId::Mtree => true,
        FormatId::Zip => timestamp.nanoseconds() == 0 && i32::try_from(timestamp.seconds()).is_ok(),
        FormatId::Iso9660 => crate::iso_stream::iso_timestamp_supported(timestamp),
        FormatId::SevenZip => sevenz_timestamp_supported(timestamp),
        FormatId::Cpio => {
            timestamp.nanoseconds() == 0 && u32::try_from(timestamp.seconds()).is_ok()
        },
        FormatId::Ar => {
            timestamp.nanoseconds() == 0 && (0..=999_999_999_999).contains(&timestamp.seconds())
        },
        _ => false,
    };
    if exact {
        return (Some(timestamp), false);
    }
    let projected = match destination {
        FormatId::Zip => i32::try_from(timestamp.seconds())
            .ok()
            .map(|seconds| Timestamp::from_seconds(i64::from(seconds))),
        FormatId::Iso9660 => Timestamp::new(
            timestamp.seconds(),
            timestamp.nanoseconds() / 10_000_000 * 10_000_000,
        )
        .ok()
        .filter(|projected| crate::iso_stream::iso_timestamp_supported(*projected)),
        FormatId::SevenZip => {
            Timestamp::new(timestamp.seconds(), timestamp.nanoseconds() / 100 * 100)
                .ok()
                .filter(|projected| sevenz_timestamp_supported(*projected))
        },
        FormatId::Cpio => u32::try_from(timestamp.seconds())
            .ok()
            .map(|seconds| Timestamp::from_seconds(i64::from(seconds))),
        FormatId::Ar => (0..=999_999_999_999)
            .contains(&timestamp.seconds())
            .then(|| Timestamp::from_seconds(timestamp.seconds())),
        _ => Some(timestamp),
    };
    (projected, true)
}

fn project_inode_and_links(
    destination: FormatId,
    inode: Option<u64>,
    links: Option<u64>,
) -> (Option<u64>, Option<u64>, bool) {
    let exact = match destination {
        FormatId::Cpio | FormatId::Iso9660 => inode
            .into_iter()
            .chain(links)
            .all(|value| u32::try_from(value).is_ok()),
        FormatId::Mtree => true,
        _ => inode.is_none() && links.is_none(),
    };
    if exact {
        (inode, links, false)
    } else {
        (None, None, true)
    }
}

fn project_devices(
    metadata: &EntryMetadata,
    destination: FormatId,
) -> Result<(Option<Device>, Option<Device>, bool), StreamError> {
    let device = metadata.device();
    let referenced = metadata.referenced_device();
    let fits_u32 =
        |value: Device| u32::try_from(value.major).is_ok() && u32::try_from(value.minor).is_ok();
    let fits_tar = |value: Device| {
        const MAXIMUM: u64 = (1_u64 << 56) - 1;
        value.major <= MAXIMUM && value.minor <= MAXIMUM
    };
    match destination {
        FormatId::Cpio => {
            let exact = device.is_none_or(fits_u32) && referenced.is_none_or(fits_u32);
            Ok(if exact {
                (device, referenced, false)
            } else {
                (None, None, true)
            })
        },
        FormatId::Mtree => Ok((device, referenced, false)),
        FormatId::Tar => {
            if matches!(metadata.kind(), EntryKind::Char | EntryKind::Block) {
                let Some(referenced) = referenced.filter(|value| fits_tar(*value)) else {
                    return Err(transcode_error(
                        ErrorKind::Unsupported,
                        "Tar device entry requires base-256 major/minor metadata",
                    ));
                };
                Ok((None, Some(referenced), device.is_some()))
            } else {
                Ok((None, None, device.is_some() || referenced.is_some()))
            }
        },
        FormatId::Iso9660 => {
            let referenced_supported = referenced.is_none_or(fits_u32);
            if matches!(metadata.kind(), EntryKind::Char | EntryKind::Block)
                && (referenced.is_none() || !referenced_supported)
            {
                return Err(transcode_error(
                    ErrorKind::Unsupported,
                    "ISO device entry requires u32 major/minor metadata",
                ));
            }
            Ok((
                None,
                referenced.filter(|_| referenced_supported),
                device.is_some() || !referenced_supported,
            ))
        },
        _ => Ok((None, None, device.is_some() || referenced.is_some())),
    }
}

fn sparse_supported(destination: FormatId) -> bool {
    destination == FormatId::Tar
}

fn xattrs_supported(destination: FormatId) -> bool {
    destination == FormatId::Tar
}

fn acl_supported(destination: FormatId) -> bool {
    destination == FormatId::Tar
}

fn checksum_supported(destination: FormatId, metadata: &EntryMetadata) -> bool {
    destination == FormatId::Mtree
        && metadata
            .checksum()
            .is_some_and(|checksum| checksum.algorithm() == ChecksumAlgorithm::Sha256)
}

fn entry_comment_supported(destination: FormatId, comment: Option<&[u8]>) -> bool {
    destination == FormatId::Tar
        || (destination == FormatId::Zip && comment.is_none_or(|value| !value.is_empty()))
}

fn entry_extension_supported(destination: FormatId, extension: &Extension) -> bool {
    match destination {
        FormatId::Tar => extension.namespace() == "pax",
        FormatId::Zip => zip_entry_extension_supported(extension),
        FormatId::Iso9660 => iso_entry_extension_supported(extension),
        FormatId::Mtree => extension.namespace() == "mtree",
        FormatId::Warc => extension.namespace() == "warc",
        _ => false,
    }
}

fn transcode_error(kind: ErrorKind, context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(kind)
            .with_context(context)
            .with_format("transcode"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_archive_projection_reports_unrepresentable_extensions() {
        let metadata = ArchiveMetadata::new()
            .with_extension(Extension::new(
                "iso9660-volume",
                b"system-id".to_vec(),
                vec![b'S'; 33],
            ))
            .with_extension(Extension::new(
                "iso9660-volume",
                b"system-id".to_vec(),
                b"FIRST".to_vec(),
            ))
            .with_extension(Extension::new(
                "iso9660-volume",
                b"system-id".to_vec(),
                b"SECOND".to_vec(),
            ))
            .with_extension(Extension::new(
                "iso9660-volume",
                b"application-id".to_vec(),
                vec![b'A'; 129],
            ))
            .with_extension(Extension::new(
                "iso9660-volume",
                b"application-id".to_vec(),
                b"TRAILING ".to_vec(),
            ))
            .with_extension(Extension::new(
                "iso9660-volume",
                b"unknown".to_vec(),
                b"opaque".to_vec(),
            ));

        let (projected, losses) = project_archive_metadata(&metadata, FormatId::Iso9660);

        assert_eq!(projected.extensions().len(), 1);
        assert_eq!(projected.extensions()[0].key(), b"system-id");
        assert_eq!(projected.extensions()[0].value(), b"FIRST");
        assert_eq!(losses, [MetadataField::ArchiveExtensions]);
    }

    #[test]
    fn iso_archive_projection_reports_unrepresentable_volume_name() {
        let metadata = ArchiveMetadata::new()
            .with_volume_name(ArchivePath::from_utf8("lossy-name"))
            .with_extension(Extension::new(
                "iso9660-volume",
                b"system-id".to_vec(),
                b"SYSTEM".to_vec(),
            ));

        let (projected, losses) = project_archive_metadata(&metadata, FormatId::Iso9660);

        assert!(projected.volume_name().is_none());
        assert_eq!(projected.extensions().len(), 1);
        assert_eq!(losses, [MetadataField::ArchiveVolumeName]);
    }

    #[test]
    fn tar_archive_projection_reports_entry_affecting_global_pax() {
        let metadata = ArchiveMetadata::new()
            .with_extension(Extension::new(
                "pax",
                b"example.vendor".to_vec(),
                b"preserved".to_vec(),
            ))
            .with_extension(Extension::new(
                "pax",
                b"path".to_vec(),
                b"overrides-every-entry".to_vec(),
            ))
            .with_extension(Extension::new(
                "pax",
                b"SCHILY.xattr.user.demo".to_vec(),
                b"value".to_vec(),
            ));

        let (projected, losses) = project_archive_metadata(&metadata, FormatId::Tar);

        assert_eq!(projected.extensions().len(), 1);
        assert_eq!(projected.extensions()[0].key(), b"example.vendor");
        assert_eq!(losses, [MetadataField::ArchiveExtensions]);
    }

    #[test]
    fn iso_and_cpio_numeric_metadata_is_projected_at_wire_boundaries() {
        let maximum = u64::from(u32::MAX);
        let exact = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("exact.bin"))
            .size(Some(0))
            .inode_and_links(Some(maximum), Some(maximum))
            .devices(
                None,
                Some(libarchive_oxide_core::Device {
                    major: maximum,
                    minor: maximum,
                }),
            )
            .build();
        let (projected, losses) = project_entry_metadata(&exact, FormatId::Iso9660).unwrap();
        assert_eq!(projected.inode(), exact.inode());
        assert_eq!(projected.links(), exact.links());
        assert_eq!(projected.referenced_device(), exact.referenced_device());
        assert_eq!(losses, [] as [MetadataField; 0]);

        let overflow =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("overflow.bin"))
                .size(Some(0))
                .inode_and_links(Some(maximum + 1), Some(1))
                .devices(
                    Some(libarchive_oxide_core::Device {
                        major: maximum + 1,
                        minor: 0,
                    }),
                    Some(libarchive_oxide_core::Device {
                        major: maximum + 1,
                        minor: 0,
                    }),
                )
                .build();
        for destination in [FormatId::Iso9660, FormatId::Cpio] {
            let (projected, losses) = project_entry_metadata(&overflow, destination).unwrap();
            assert!(projected.inode().is_none(), "{destination:?}");
            assert!(projected.links().is_none(), "{destination:?}");
            assert!(projected.device().is_none(), "{destination:?}");
            assert!(projected.referenced_device().is_none(), "{destination:?}");
            assert!(
                losses.contains(&MetadataField::InodeAndLinkCount),
                "{destination:?}: {losses:?}"
            );
            assert!(
                losses.contains(&MetadataField::Devices),
                "{destination:?}: {losses:?}"
            );
        }

        let required =
            EntryMetadata::builder(EntryKind::Char, ArchivePath::from_utf8("required-device"))
                .size(Some(0))
                .devices(
                    None,
                    Some(libarchive_oxide_core::Device {
                        major: maximum + 1,
                        minor: 0,
                    }),
                )
                .build();
        let error = project_entry_metadata(&required, FormatId::Iso9660)
            .expect_err("ISO character device requires representable major/minor numbers");
        assert_eq!(error.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn cpio_projection_rejects_the_reserved_trailer_path() {
        let metadata = EntryMetadata::builder(
            EntryKind::File,
            ArchivePath::from_bytes(b"TRAILER!!!".to_vec()),
        )
        .size(Some(0))
        .build();
        assert_eq!(
            project_entry_metadata(&metadata, FormatId::Cpio)
                .expect_err("cpio trailer sentinel is not an entry path")
                .kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn fixed_width_destinations_reject_unrepresentable_declared_sizes() {
        for destination in [FormatId::Cpio, FormatId::Ar, FormatId::Warc] {
            let missing =
                EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("unknown.bin"))
                    .build();
            let error = project_entry_metadata(&missing, destination)
                .expect_err("destination requires a declared entry size");
            assert_eq!(error.kind(), ErrorKind::SizeRequired, "{destination:?}");
        }

        let maximum_u32 = u64::from(u32::MAX);
        for destination in [FormatId::Cpio, FormatId::Iso9660] {
            let exact =
                EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("exact-size.bin"))
                    .size(Some(maximum_u32))
                    .build();
            assert!(
                project_entry_metadata(&exact, destination).is_ok(),
                "{destination:?} must accept its exact wire maximum"
            );

            let overflow = exact
                .clone()
                .into_builder()
                .size(Some(maximum_u32 + 1))
                .build();
            let error = project_entry_metadata(&overflow, destination)
                .expect_err("destination must reject a size beyond its wire field");
            assert_eq!(error.kind(), ErrorKind::Unsupported, "{destination:?}");
        }

        let ar_maximum = 9_999_999_999_u64;
        let short = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("short"))
            .size(Some(ar_maximum))
            .build();
        assert!(project_entry_metadata(&short, FormatId::Ar).is_ok());
        let short_overflow = short
            .clone()
            .into_builder()
            .size(Some(ar_maximum + 1))
            .build();
        assert_eq!(
            project_entry_metadata(&short_overflow, FormatId::Ar)
                .expect_err("ar size field is ten decimal digits")
                .kind(),
            ErrorKind::Unsupported
        );

        let long_name = "this-name-is-long.bin";
        let long_inline_size = 24;
        let long = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8(long_name))
            .size(Some(ar_maximum - long_inline_size))
            .build();
        assert!(project_entry_metadata(&long, FormatId::Ar).is_ok());
        let long_overflow = long
            .into_builder()
            .size(Some(ar_maximum - long_inline_size + 1))
            .build();
        assert_eq!(
            project_entry_metadata(&long_overflow, FormatId::Ar)
                .expect_err("BSD inline name bytes count toward the ar size field")
                .kind(),
            ErrorKind::Unsupported
        );

        let reserved_name = "/";
        let reserved_inline_size = 4;
        let reserved =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8(reserved_name))
                .size(Some(ar_maximum - reserved_inline_size))
                .build();
        assert!(project_entry_metadata(&reserved, FormatId::Ar).is_ok());
        let reserved_overflow = reserved
            .into_builder()
            .size(Some(ar_maximum - reserved_inline_size + 1))
            .build();
        assert_eq!(
            project_entry_metadata(&reserved_overflow, FormatId::Ar)
                .expect_err("reserved ar names use BSD inline bytes in the size field")
                .kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn warc_projection_reports_synthesized_path_and_mode() {
        let metadata =
            EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("source.bin"))
                .size(Some(0))
                .extension(Extension::new(
                    "warc",
                    b"WARC-Type".to_vec(),
                    b"resource".to_vec(),
                ))
                .extension(Extension::new(
                    "warc",
                    b"WARC-Record-ID".to_vec(),
                    b"<urn:uuid:transcode>".to_vec(),
                ))
                .extension(Extension::new(
                    "warc",
                    b"WARC-Date".to_vec(),
                    b"2026-08-15T00:00:00Z".to_vec(),
                ))
                .build();

        let (projected, losses) = project_entry_metadata(&metadata, FormatId::Warc).unwrap();
        assert_eq!(projected.mode(), Some(0o644));
        assert_eq!(losses, [MetadataField::EntryPath, MetadataField::Mode]);
    }

    #[test]
    fn permission_only_destinations_report_stripped_mode_bits() {
        let metadata = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("mode.bin"))
            .size(Some(0))
            .mode(Some(0o100_640))
            .build();

        for destination in [FormatId::Tar, FormatId::Cpio, FormatId::Ar, FormatId::Zip] {
            let (projected, losses) = project_entry_metadata(&metadata, destination).unwrap();
            assert_eq!(projected.mode(), Some(0o640), "{destination:?}");
            assert_eq!(losses, [MetadataField::Mode], "{destination:?}");
        }
    }

    #[test]
    fn tar_device_metadata_is_projected_by_kind_and_base256_range() {
        let maximum = (1_u64 << 56) - 1;
        let file = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("file"))
            .size(Some(0))
            .devices(None, Some(Device { major: 1, minor: 2 }))
            .build();
        let (projected, losses) = project_entry_metadata(&file, FormatId::Tar).unwrap();
        assert!(projected.referenced_device().is_none());
        assert_eq!(losses, [MetadataField::Devices]);

        let exact = EntryMetadata::builder(EntryKind::Char, ArchivePath::from_utf8("device"))
            .size(Some(0))
            .devices(
                None,
                Some(Device {
                    major: maximum,
                    minor: maximum,
                }),
            )
            .build();
        let (projected, losses) = project_entry_metadata(&exact, FormatId::Tar).unwrap();
        assert_eq!(projected.referenced_device(), exact.referenced_device());
        assert_eq!(losses, [] as [MetadataField; 0]);

        for metadata in [
            EntryMetadata::builder(EntryKind::Char, ArchivePath::from_utf8("missing"))
                .size(Some(0))
                .build(),
            EntryMetadata::builder(EntryKind::Block, ArchivePath::from_utf8("overflow"))
                .size(Some(0))
                .devices(
                    None,
                    Some(Device {
                        major: maximum + 1,
                        minor: 0,
                    }),
                )
                .build(),
            EntryMetadata::builder(EntryKind::Socket, ArchivePath::from_utf8("socket"))
                .size(Some(0))
                .build(),
        ] {
            let error = project_entry_metadata(&metadata, FormatId::Tar)
                .expect_err("Tar must reject unrepresentable device kind metadata");
            assert_eq!(error.kind(), ErrorKind::Unsupported);
        }
    }

    #[test]
    fn entry_projection_retains_only_exact_raw_extensions() {
        let iso = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("entry.bin"))
            .size(Some(0))
            .extension(Extension::new(
                "iso-system-use",
                b"ZZ".to_vec(),
                vec![b'Z', b'Z', 4, 1],
            ))
            .extension(Extension::new(
                "iso-system-use",
                b"PX".to_vec(),
                vec![b'P', b'X', 4, 1],
            ))
            .extension(Extension::new(
                "foreign",
                b"XY".to_vec(),
                vec![b'X', b'Y', 4, 1],
            ))
            .build();
        let (iso, iso_losses) = project_entry_metadata(&iso, FormatId::Iso9660).unwrap();
        assert_eq!(iso.extensions().len(), 1);
        assert_eq!(iso.extensions()[0].key(), b"ZZ");
        assert_eq!(iso_losses, [MetadataField::EntryExtensions]);

        let zip = EntryMetadata::builder(EntryKind::File, ArchivePath::from_utf8("entry.bin"))
            .size(Some(0))
            .extension(Extension::new(
                "zip-extra",
                0xcafe_u16.to_le_bytes().to_vec(),
                vec![1],
            ))
            .extension(Extension::new("zip-extra", vec![0xca], vec![1]))
            .extension(Extension::new(
                "zip-extra",
                0x0001_u16.to_le_bytes().to_vec(),
                vec![1],
            ))
            .build();
        let (zip, zip_losses) = project_entry_metadata(&zip, FormatId::Zip).unwrap();
        assert_eq!(zip.extensions().len(), 1);
        assert_eq!(zip.extensions()[0].key(), 0xcafe_u16.to_le_bytes());
        assert_eq!(zip_losses, [MetadataField::EntryExtensions]);
    }
}
