// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded whole-archive editing with fail-closed path validation.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek, Write};
use std::mem::size_of;

use libarchive_oxide_core::{
    ArchiveError, ArchivePath, EntryKind, EntryMetadata, ErrorKind, FormatId, Limits,
};

use crate::path::{DestinationClaims, DestinationKey};
use crate::transcode::{copy_events_with_transform, validate_destination};
use crate::{
    ArchiveEngine, ArchiveReader, CreateOptions, MetadataLoss, MetadataLossPolicy, OpenOptions,
    SeekArchiveReader, StreamError, TranscodeReport,
};

const DEFAULT_MAXIMUM_EDIT_OPERATIONS: usize = 4_096;

/// One exact-path edit applied while rewriting an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EditOperation {
    /// Remove the matching entry and its payload.
    Remove(ArchivePath),
    /// Replace an entry path and matching hardlink targets.
    Rename {
        /// Exact source path.
        from: ArchivePath,
        /// Safe relative destination path.
        to: ArchivePath,
    },
}

impl EditOperation {
    fn source(&self) -> &ArchivePath {
        match self {
            Self::Remove(path) => path,
            Self::Rename { from, .. } => from,
        }
    }
}

/// Completed whole-rewrite statistics and fidelity findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditReport {
    source_entries: u64,
    removed_entries: u64,
    renamed_entries: u64,
    transcode: TranscodeReport,
}

impl EditReport {
    /// Number of entries decoded from the source archive.
    #[must_use]
    pub const fn source_entries(&self) -> u64 {
        self.source_entries
    }

    /// Number of entries written to the destination archive.
    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.transcode.entries()
    }

    /// Number of decoded payload bytes copied to retained entries.
    #[must_use]
    pub const fn payload_bytes(&self) -> u64 {
        self.transcode.payload_bytes()
    }

    /// Number of entries removed.
    #[must_use]
    pub const fn removed_entries(&self) -> u64 {
        self.removed_entries
    }

    /// Number of entry paths renamed.
    #[must_use]
    pub const fn renamed_entries(&self) -> u64 {
        self.renamed_entries
    }

    /// Metadata that the destination format could not represent.
    #[must_use]
    pub fn metadata_losses(&self) -> &[MetadataLoss] {
        self.transcode.metadata_losses()
    }

    /// The underlying format-conversion report.
    #[must_use]
    pub const fn transcode_report(&self) -> &TranscodeReport {
        &self.transcode
    }
}

/// Successful archive rewrite containing the destination and its report.
#[derive(Debug)]
pub struct EditOutcome<W> {
    output: W,
    report: EditReport,
}

impl<W> EditOutcome<W> {
    /// Edit and format-fidelity report.
    #[must_use]
    pub const fn report(&self) -> &EditReport {
        &self.report
    }

    /// Returns the completed destination.
    #[must_use]
    pub fn into_output(self) -> W {
        self.output
    }

    /// Returns the completed destination and report.
    #[must_use]
    pub fn into_parts(self) -> (W, EditReport) {
        (self.output, self.report)
    }
}

/// A bounded whole-archive rename/remove plan.
///
/// Entry payloads are decoded and copied incrementally.
/// Output paths are validated with the extraction planner's host-identity rules, so traversal,
/// aliases, duplicates, and file/directory topology conflicts fail closed.
#[derive(Debug, Clone)]
pub struct ArchiveEditor {
    operations: Vec<EditOperation>,
    metadata_loss_policy: MetadataLossPolicy,
    maximum_metadata_losses: usize,
    maximum_operations: usize,
}

impl ArchiveEditor {
    /// Creates an empty whole-rewrite plan.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            operations: Vec::new(),
            metadata_loss_policy: MetadataLossPolicy::Report,
            maximum_metadata_losses: 4_096,
            maximum_operations: DEFAULT_MAXIMUM_EDIT_OPERATIONS,
        }
    }

    /// Adds an exact-path removal.
    #[must_use]
    pub fn remove(mut self, path: ArchivePath) -> Self {
        self.operations.push(EditOperation::Remove(path));
        self
    }

    /// Adds an exact-path rename.
    /// Matching hardlink targets are updated too.
    #[must_use]
    pub fn rename(mut self, from: ArchivePath, to: ArchivePath) -> Self {
        self.operations.push(EditOperation::Rename { from, to });
        self
    }

    /// Adds a preconstructed operation.
    #[must_use]
    pub fn with_operation(mut self, operation: EditOperation) -> Self {
        self.operations.push(operation);
        self
    }

    /// Selects whether unrepresentable destination metadata is reported or rejected.
    #[must_use]
    pub const fn with_metadata_loss_policy(mut self, policy: MetadataLossPolicy) -> Self {
        self.metadata_loss_policy = policy;
        self
    }

    /// Caps stored metadata-loss records.
    #[must_use]
    pub const fn with_maximum_metadata_losses(mut self, maximum: usize) -> Self {
        self.maximum_metadata_losses = maximum;
        self
    }

    /// Caps exact-path edit operations before any input or output is touched.
    #[must_use]
    pub const fn with_maximum_operations(mut self, maximum: usize) -> Self {
        self.maximum_operations = maximum;
        self
    }

    /// Rewrites a forward-only source to a sequential destination.
    pub fn rewrite<R: Read, W: Write>(
        self,
        input: R,
        source: &OpenOptions,
        output: W,
        destination: CreateOptions,
    ) -> Result<EditOutcome<W>, StreamError> {
        let mut runtime = self.prepare(source.limits(), destination.format())?;
        let mut reader = ArchiveReader::with_options(input, source)?;
        let mut writer = ArchiveEngine::new()
            .with_limits(source.limits())
            .create(output, destination)?;
        let transcode = copy_events_with_transform(
            &mut reader,
            &mut writer,
            destination.format(),
            source.limits(),
            self.transcoder(),
            &mut |metadata| runtime.transform(metadata),
        )?;
        runtime.finish()?;
        let output = writer.finish()?;
        Ok(EditOutcome {
            output,
            report: runtime.report(transcode),
        })
    }

    /// Rewrites a forward-only source to a seek-capable destination.
    pub fn rewrite_to_seek<R: Read, W: Write + Seek>(
        self,
        input: R,
        source: &OpenOptions,
        output: W,
        destination: CreateOptions,
    ) -> Result<EditOutcome<W>, StreamError> {
        let mut runtime = self.prepare(source.limits(), destination.format())?;
        let mut reader = ArchiveReader::with_options(input, source)?;
        let mut writer = ArchiveEngine::new()
            .with_limits(source.limits())
            .create_seek(output, destination)?;
        let transcode = copy_events_with_transform(
            &mut reader,
            &mut writer,
            destination.format(),
            source.limits(),
            self.transcoder(),
            &mut |metadata| runtime.transform(metadata),
        )?;
        runtime.finish()?;
        let output = writer.finish()?;
        Ok(EditOutcome {
            output,
            report: runtime.report(transcode),
        })
    }

    /// Rewrites a seek-native source to a sequential destination.
    pub fn rewrite_from_seek<R: Read + Seek, W: Write>(
        self,
        input: R,
        source: &OpenOptions,
        output: W,
        destination: CreateOptions,
    ) -> Result<EditOutcome<W>, StreamError> {
        let mut runtime = self.prepare(source.limits(), destination.format())?;
        let mut reader = SeekArchiveReader::with_options(input, source)?;
        let mut writer = ArchiveEngine::new()
            .with_limits(source.limits())
            .create(output, destination)?;
        let transcode = copy_events_with_transform(
            &mut reader,
            &mut writer,
            destination.format(),
            source.limits(),
            self.transcoder(),
            &mut |metadata| runtime.transform(metadata),
        )?;
        runtime.finish()?;
        let output = writer.finish()?;
        Ok(EditOutcome {
            output,
            report: runtime.report(transcode),
        })
    }

    /// Rewrites a seek-native source to a seek-capable destination.
    pub fn rewrite_seek<R: Read + Seek, W: Write + Seek>(
        self,
        input: R,
        source: &OpenOptions,
        output: W,
        destination: CreateOptions,
    ) -> Result<EditOutcome<W>, StreamError> {
        let mut runtime = self.prepare(source.limits(), destination.format())?;
        let mut reader = SeekArchiveReader::with_options(input, source)?;
        let mut writer = ArchiveEngine::new()
            .with_limits(source.limits())
            .create_seek(output, destination)?;
        let transcode = copy_events_with_transform(
            &mut reader,
            &mut writer,
            destination.format(),
            source.limits(),
            self.transcoder(),
            &mut |metadata| runtime.transform(metadata),
        )?;
        runtime.finish()?;
        let output = writer.finish()?;
        Ok(EditOutcome {
            output,
            report: runtime.report(transcode),
        })
    }

    fn prepare(
        &self,
        limits: Limits,
        destination: FormatId,
    ) -> Result<EditRuntime<'_>, StreamError> {
        validate_destination(destination)?;
        EditRuntime::new(self, limits)
    }

    const fn transcoder(&self) -> crate::ArchiveTranscoder {
        crate::ArchiveTranscoder::new()
            .with_metadata_loss_policy(self.metadata_loss_policy)
            .with_maximum_metadata_losses(self.maximum_metadata_losses)
    }
}

impl Default for ArchiveEditor {
    fn default() -> Self {
        Self::new()
    }
}

struct EditRuntime<'a> {
    operations: &'a [EditOperation],
    by_source: BTreeMap<Vec<u8>, usize>,
    matched: Vec<bool>,
    claims: DestinationClaims,
    root_claimed: bool,
    metadata_charge: usize,
    metadata_limit: Option<usize>,
    source_entries: u64,
    removed_entries: u64,
    renamed_entries: u64,
}

impl<'a> EditRuntime<'a> {
    fn new(editor: &'a ArchiveEditor, limits: Limits) -> Result<Self, StreamError> {
        if editor.operations.len() > editor.maximum_operations {
            return Err(edit_error(
                ErrorKind::Limit,
                "archive edit operation count exceeds configured limit",
            ));
        }
        let mut by_source = BTreeMap::new();
        let mut rename_destinations = BTreeSet::new();
        let mut charged = editor
            .operations
            .len()
            .checked_mul(size_of::<EditOperation>())
            .ok_or_else(|| edit_error(ErrorKind::Limit, "archive edit accounting overflow"))?;
        for (index, operation) in editor.operations.iter().enumerate() {
            let source = operation.source();
            validate_edit_path(source, limits, "archive edit source path is invalid")?;
            charged = charged
                .checked_add(source.as_bytes().len())
                .ok_or_else(|| edit_error(ErrorKind::Limit, "archive edit accounting overflow"))?;
            if by_source
                .insert(source.as_bytes().to_vec(), index)
                .is_some()
            {
                return Err(edit_error(
                    ErrorKind::Policy,
                    "multiple archive edits select the same source path",
                ));
            }
            if let EditOperation::Rename { from, to } = operation {
                validate_edit_path(to, limits, "archive rename destination path is invalid")?;
                let destination = DestinationKey::from_archive_path(to).ok_or_else(|| {
                    edit_error(
                        ErrorKind::Policy,
                        "archive rename destination is not a safe relative path",
                    )
                })?;
                if from == to {
                    return Err(edit_error(
                        ErrorKind::Policy,
                        "archive rename source and destination must differ",
                    ));
                }
                if !rename_destinations.insert(destination) {
                    return Err(edit_error(
                        ErrorKind::Policy,
                        "multiple archive renames have the same destination path",
                    ));
                }
                charged = charged.checked_add(to.as_bytes().len()).ok_or_else(|| {
                    edit_error(ErrorKind::Limit, "archive edit accounting overflow")
                })?;
            }
        }
        if limits
            .metadata_bytes()
            .is_some_and(|maximum| charged > maximum)
        {
            return Err(edit_error(
                ErrorKind::Limit,
                "archive edit plan exceeds source metadata budget",
            ));
        }
        Ok(Self {
            operations: &editor.operations,
            by_source,
            matched: vec![false; editor.operations.len()],
            claims: DestinationClaims::default(),
            root_claimed: false,
            metadata_charge: charged,
            metadata_limit: limits.metadata_bytes(),
            source_entries: 0,
            removed_entries: 0,
            renamed_entries: 0,
        })
    }

    fn transform(&mut self, metadata: EntryMetadata) -> Result<Option<EntryMetadata>, StreamError> {
        self.source_entries =
            checked_increment(self.source_entries, "source entry count overflow")?;
        let selected = self.by_source.get(metadata.path().as_bytes()).copied();
        if let Some(index) = selected {
            self.matched[index] = true;
            if matches!(self.operations[index], EditOperation::Remove(_)) {
                self.removed_entries =
                    checked_increment(self.removed_entries, "removed entry count overflow")?;
                return Ok(None);
            }
        }

        let mut path = metadata.path().clone();
        if let Some(index) = selected
            && let EditOperation::Rename { to, .. } = &self.operations[index]
        {
            path.clone_from(to);
            self.renamed_entries =
                checked_increment(self.renamed_entries, "renamed entry count overflow")?;
        }

        let mut link_target = metadata.link_target().cloned();
        if metadata.kind() == EntryKind::Hardlink
            && let Some(target) = link_target.as_ref()
            && let Some(index) = self.by_source.get(target.as_bytes()).copied()
        {
            match &self.operations[index] {
                EditOperation::Remove(_) => {
                    return Err(edit_error(
                        ErrorKind::Policy,
                        "archive edit would leave a dangling hardlink target",
                    ));
                },
                EditOperation::Rename { to, .. } => link_target = Some(to.clone()),
            }
        }

        self.claim_output(&path, metadata.kind())?;
        let metadata = metadata
            .into_builder()
            .path(path)
            .link_target(link_target)
            .try_build()
            .map_err(StreamError::archive)?;
        Ok(Some(metadata))
    }

    fn claim_output(&mut self, path: &ArchivePath, kind: EntryKind) -> Result<(), StreamError> {
        if path.as_bytes() == b"." && kind == EntryKind::Dir {
            if self.root_claimed {
                return Err(edit_error(
                    ErrorKind::Policy,
                    "archive edit produced a conflicting output path",
                ));
            }
            self.charge_output_path(path.as_bytes().len(), 1)?;
            self.root_claimed = true;
            return Ok(());
        }
        let destination = DestinationKey::from_archive_path(path).ok_or_else(|| {
            edit_error(
                ErrorKind::Policy,
                "archive edit retained an unsafe output path",
            )
        })?;
        self.charge_output_path(
            path.as_bytes().len(),
            destination.path().components().count(),
        )?;
        if !self.claims.claim(&destination, kind) {
            return Err(edit_error(
                ErrorKind::Policy,
                "archive edit produced a conflicting output path",
            ));
        }
        Ok(())
    }

    fn charge_output_path(&mut self, bytes: usize, copies: usize) -> Result<(), StreamError> {
        // DestinationClaims retains the complete key plus each ancestor.
        // The multiplier conservatively covers platform path/identity expansion and ordered-set nodes without depending on their implementation.
        let per_copy = bytes
            .checked_mul(4)
            .and_then(|value| value.checked_add(size_of::<DestinationKey>() + 64))
            .ok_or_else(|| edit_error(ErrorKind::Limit, "archive edit accounting overflow"))?;
        let charge = per_copy
            .checked_mul(copies.max(1))
            .ok_or_else(|| edit_error(ErrorKind::Limit, "archive edit accounting overflow"))?;
        self.metadata_charge = self
            .metadata_charge
            .checked_add(charge)
            .ok_or_else(|| edit_error(ErrorKind::Limit, "archive edit accounting overflow"))?;
        if self
            .metadata_limit
            .is_some_and(|maximum| self.metadata_charge > maximum)
        {
            return Err(edit_error(
                ErrorKind::Limit,
                "archive edit path index exceeds source metadata budget",
            ));
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), StreamError> {
        if self.matched.iter().any(|matched| !matched) {
            return Err(edit_error(
                ErrorKind::Policy,
                "an archive edit operation did not match a source entry",
            ));
        }
        Ok(())
    }

    fn report(&self, transcode: TranscodeReport) -> EditReport {
        EditReport {
            source_entries: self.source_entries,
            removed_entries: self.removed_entries,
            renamed_entries: self.renamed_entries,
            transcode,
        }
    }
}

fn validate_edit_path(
    path: &ArchivePath,
    limits: Limits,
    context: &'static str,
) -> Result<(), StreamError> {
    if path.as_bytes().is_empty()
        || ArchivePath::try_from_encoded(path.as_bytes().to_vec(), path.encoding()).is_err()
    {
        return Err(edit_error(ErrorKind::Policy, context));
    }
    if limits
        .path_bytes()
        .is_some_and(|maximum| path.as_bytes().len() > maximum)
    {
        return Err(edit_error(
            ErrorKind::Limit,
            "archive edit path exceeds configured path-byte limit",
        ));
    }
    Ok(())
}

fn checked_increment(value: u64, context: &'static str) -> Result<u64, StreamError> {
    value
        .checked_add(1)
        .ok_or_else(|| edit_error(ErrorKind::Limit, context))
}

fn edit_error(kind: ErrorKind, context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(kind)
            .with_context(context)
            .with_format("edit"),
    )
}
