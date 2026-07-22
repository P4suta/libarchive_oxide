// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded Debian package (`.deb`) validator.
//!
//! A `.deb` is a Unix `ar` archive whose members are, in order, the text stamp
//! `debian-binary` (holding a `2.x` version line), a `control.tar.*`, and a
//! `data.tar.*`. The inner tarballs may be stored plain or wrapped in a single
//! outer gzip, xz, zstd, or bzip2 filter.
//!
//! [`DebValidator`] inspects an untrusted package without ever extracting it or
//! buffering a whole member. The outer `ar` container is read with the bounded
//! [`ArchiveReader`] event stream; each `*.tar.*` member is streamed, chunk by
//! chunk, through a per-member [`Pipeline`] that decodes only enough to check
//! the outer filter and the nested tar structure. Decompression is bounded by
//! the configured [`Limits`], so a decompression bomb is refused rather than
//! expanded.
//!
//! The result separates two questions: could the `ar` container be read at all
//! ([`SupportStatus::container_readable`]) and did the package satisfy the
//! Debian profile ([`SupportStatus::profile_valid`]). Every deviation is
//! reported as a typed [`PackageFinding`].

use std::collections::BTreeSet;
use std::io::Read;
use std::path::PathBuf;

use libarchive_oxide_core::filter::FilterId;
use libarchive_oxide_core::{ArchiveError, EntryMetadata, ErrorKind, Limits, ProbeResult};

use super::finding::{PackageFinding, PackageFindingCode, SupportStatus};
use crate::path::sanitize_archive_path;
use crate::provider::{
    BuiltinCodecProviders, BuiltinFormatProviders, ProviderCapability, ProviderSet,
    StaticCodecProviders,
};
use crate::stream::{ArchiveReader, Pipeline, PipelineEvent, ReaderEvent};

/// Profile name reported on every Debian finding.
const PROFILE: &str = "debian";

/// Bytes buffered from a member head before its outer filter is classified.
///
/// Six bytes cover the longest supported filter signature (xz).
const PROBE_LEN: usize = 6;

/// Maximum bytes retained from the `debian-binary` member body.
const VERSION_CAP: usize = 64;

/// Role a `.deb` member plays in the Debian profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    DebianBinary,
    Control,
    Data,
    Unknown,
}

impl Role {
    /// Ordering rank of the profile members; unknown members do not participate.
    const fn rank(self) -> i32 {
        match self {
            Self::DebianBinary => 0,
            Self::Control => 1,
            Self::Data => 2,
            Self::Unknown => i32::MAX,
        }
    }

    fn classify(name: &[u8]) -> Self {
        if name == b"debian-binary" {
            Self::DebianBinary
        } else if name == b"control.tar" || name.starts_with(b"control.tar.") {
            Self::Control
        } else if name == b"data.tar" || name.starts_with(b"data.tar.") {
            Self::Data
        } else {
            Self::Unknown
        }
    }
}

/// A bounded, per-package validator for the Debian `.deb` profile.
///
/// The type parameter selects the outer-codec provider chain used to decode
/// nested tarballs; the default is the crate's built-in codecs. Replacing it
/// with [`DebValidator::with_codec_providers`] lets a caller detect members
/// compressed with a method that a given build cannot decode, which is reported
/// as an [`PackageFindingCode::UnsupportedCompression`] finding.
#[derive(Debug, Clone, Copy)]
pub struct DebValidator<C = BuiltinCodecProviders>
where
    C: StaticCodecProviders,
{
    limits: Limits,
    providers: ProviderSet<BuiltinFormatProviders, C>,
}

impl DebValidator<BuiltinCodecProviders> {
    /// Creates a validator with the safe finite limits and built-in codecs.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: Limits::safe(),
            providers: ProviderSet::builtins(),
        }
    }
}

impl Default for DebValidator<BuiltinCodecProviders> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> DebValidator<C>
where
    C: StaticCodecProviders + Copy,
{
    /// Replaces the resource budgets bounding each nested tar decode.
    ///
    /// These limits bound the decompressed output of every `*.tar.*` member, so
    /// [`Limits::with_decoded_total`] is the decompression-bomb budget.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces the outer-codec provider chain used for nested tarballs.
    #[must_use]
    pub fn with_codec_providers<D>(
        self,
        providers: ProviderSet<BuiltinFormatProviders, D>,
    ) -> DebValidator<D>
    where
        D: StaticCodecProviders,
    {
        DebValidator {
            limits: self.limits,
            providers,
        }
    }

    /// Resource budgets bounding each nested tar decode.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Limits used for the outer `ar` container.
    ///
    /// The container carries no compression, so its decoded total is naturally
    /// bounded by the input length. Only the decoded-total budget is relaxed to
    /// a finite floor so a small nested-decode budget cannot spuriously reject
    /// the compressed member bytes; every other budget is retained.
    fn container_limits(&self) -> Limits {
        let floor = Limits::FOUR_GIB;
        let decoded_total = self
            .limits
            .decoded_total()
            .map_or(floor, |value| value.max(floor));
        self.limits.with_decoded_total(Some(decoded_total))
    }

    /// Validates an untrusted `.deb` byte stream without extracting it.
    ///
    /// The package is never materialized and no whole member is buffered. The
    /// returned [`DebValidation`] separates container readability from profile
    /// conformance and lists every typed finding.
    pub fn validate<R: Read>(&self, reader: R) -> DebValidation {
        let mut state = DebState::new();
        let mut container = ArchiveReader::with_limits(reader, self.container_limits());
        let mut current: Option<Member<C>> = None;
        loop {
            match container.next_event() {
                Ok(ReaderEvent::Entry(metadata)) => {
                    if let Some(member) = current.take() {
                        Self::finish_member(member, &mut state);
                    }
                    current = Some(self.begin_member(&metadata, &mut state));
                },
                Ok(ReaderEvent::Data(bytes)) => {
                    if let Some(member) = current.as_mut() {
                        member.feed(bytes, &mut state.findings);
                    }
                },
                Ok(ReaderEvent::EndEntry) => {
                    if let Some(member) = current.take() {
                        Self::finish_member(member, &mut state);
                    }
                },
                Ok(ReaderEvent::ArchiveMetadata(_)) => {},
                Ok(ReaderEvent::Done) => break,
                Err(error) => {
                    if let Some(member) = current.take() {
                        Self::finish_member(member, &mut state);
                    }
                    state.container_readable = false;
                    state.findings.push(PackageFinding::new(
                        PROFILE,
                        None,
                        PackageFindingCode::ContainerUnreadable,
                        format!("cannot read .deb ar container: {error}"),
                    ));
                    break;
                },
            }
        }
        state.finalize()
    }

    /// Applies member-order, duplicate, and name checks, then builds a processor.
    fn begin_member(&self, metadata: &EntryMetadata, state: &mut DebState) -> Member<C> {
        let name = metadata.path().as_bytes().to_vec();
        let index = state.member_index;
        state.member_index += 1;

        if sanitize_archive_path(metadata.path()).is_none() {
            state.findings.push(PackageFinding::new(
                PROFILE,
                Some(name),
                PackageFindingCode::UnsafeMemberName,
                "member name is absolute, traversing, or unrepresentable",
            ));
            return Member::Skip;
        }

        let role = Role::classify(&name);
        if index == 0 && role != Role::DebianBinary {
            state.findings.push(PackageFinding::new(
                PROFILE,
                Some(name.clone()),
                PackageFindingCode::MissingDebianBinary,
                "first ar member is not debian-binary",
            ));
            state.debian_reported = true;
        }

        match role {
            Role::DebianBinary => {
                if state.seen_debian {
                    state.push_duplicate(&name);
                }
                state.seen_debian = true;
                state.check_order(role, &name);
            },
            Role::Control => {
                if state.seen_control {
                    state.push_duplicate(&name);
                }
                state.seen_control = true;
                state.check_order(role, &name);
            },
            Role::Data => {
                if state.seen_data {
                    state.push_duplicate(&name);
                }
                state.seen_data = true;
                state.check_order(role, &name);
            },
            Role::Unknown => {
                state.findings.push(PackageFinding::new(
                    PROFILE,
                    Some(name.clone()),
                    PackageFindingCode::UnknownMember,
                    "member is outside the Debian profile",
                ));
            },
        }

        match role {
            Role::DebianBinary => Member::DebianBinary(DebianBinaryMember::new()),
            Role::Control | Role::Data => Member::Tar(Box::new(TarMember::new(
                name,
                role,
                self.limits,
                self.providers,
            ))),
            Role::Unknown => Member::Skip,
        }
    }

    /// Finalizes one member's processor, recording its outcome.
    fn finish_member(member: Member<C>, state: &mut DebState) {
        match member {
            Member::DebianBinary(inner) => {
                let ok = inner.body.starts_with(b"2.") && inner.body.contains(&b'\n');
                state.debian_version_ok = ok;
                if !ok {
                    state.findings.push(PackageFinding::new(
                        PROFILE,
                        Some(b"debian-binary".to_vec()),
                        PackageFindingCode::InvalidVersionStamp,
                        "debian-binary member lacks a supported 2.x version line",
                    ));
                }
            },
            Member::Tar(mut inner) => {
                inner.finish(&mut state.findings);
                match inner.role {
                    Role::Control => state.control_compression = inner.filter,
                    Role::Data => state.data_compression = inner.filter,
                    Role::DebianBinary | Role::Unknown => {},
                }
            },
            Member::Skip => {},
        }
    }
}

/// Mutable accumulator threaded through a single validation.
#[allow(clippy::struct_excessive_bools)]
struct DebState {
    findings: Vec<PackageFinding>,
    container_readable: bool,
    member_index: usize,
    seen_debian: bool,
    seen_control: bool,
    seen_data: bool,
    debian_version_ok: bool,
    debian_reported: bool,
    last_rank: i32,
    data_compression: Option<FilterId>,
    control_compression: Option<FilterId>,
}

impl DebState {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            container_readable: true,
            member_index: 0,
            seen_debian: false,
            seen_control: false,
            seen_data: false,
            debian_version_ok: false,
            debian_reported: false,
            last_rank: -1,
            data_compression: None,
            control_compression: None,
        }
    }

    fn push_duplicate(&mut self, name: &[u8]) {
        self.findings.push(PackageFinding::new(
            PROFILE,
            Some(name.to_vec()),
            PackageFindingCode::DuplicateMember,
            "profile member appears more than once",
        ));
    }

    fn check_order(&mut self, role: Role, name: &[u8]) {
        let rank = role.rank();
        if rank < self.last_rank {
            self.findings.push(PackageFinding::new(
                PROFILE,
                Some(name.to_vec()),
                PackageFindingCode::UnexpectedMemberOrder,
                "member appears out of debian-binary, control, data order",
            ));
        }
        self.last_rank = self.last_rank.max(rank);
    }

    fn finalize(mut self) -> DebValidation {
        if self.container_readable {
            if !self.seen_debian && !self.debian_reported {
                self.findings.push(PackageFinding::new(
                    PROFILE,
                    None,
                    PackageFindingCode::MissingDebianBinary,
                    "package has no debian-binary member",
                ));
            }
            if !self.seen_control {
                self.findings.push(PackageFinding::new(
                    PROFILE,
                    None,
                    PackageFindingCode::MissingRequiredMember,
                    "package has no control.tar member",
                ));
            }
            if !self.seen_data {
                self.findings.push(PackageFinding::new(
                    PROFILE,
                    None,
                    PackageFindingCode::MissingRequiredMember,
                    "package has no data.tar member",
                ));
            }
        }

        let blocking = self
            .findings
            .iter()
            .any(|finding| finding.severity() >= super::finding::Severity::Warning);
        let profile_valid = self.container_readable
            && !blocking
            && self.seen_debian
            && self.debian_version_ok
            && self.seen_control
            && self.seen_data;

        DebValidation {
            status: SupportStatus::new(self.container_readable, profile_valid),
            findings: self.findings,
            data_compression: self.data_compression,
            control_compression: self.control_compression,
        }
    }
}

/// A member's streaming processor.
enum Member<C: StaticCodecProviders> {
    DebianBinary(DebianBinaryMember),
    Tar(Box<TarMember<C>>),
    Skip,
}

impl<C: StaticCodecProviders + Copy> Member<C> {
    fn feed(&mut self, bytes: &[u8], findings: &mut Vec<PackageFinding>) {
        match self {
            Self::DebianBinary(inner) => inner.feed(bytes),
            Self::Tar(inner) => inner.feed(bytes, findings),
            Self::Skip => {},
        }
    }
}

/// Retains a bounded prefix of the `debian-binary` member body.
struct DebianBinaryMember {
    body: Vec<u8>,
}

impl DebianBinaryMember {
    const fn new() -> Self {
        Self { body: Vec::new() }
    }

    fn feed(&mut self, bytes: &[u8]) {
        let take = VERSION_CAP.saturating_sub(self.body.len()).min(bytes.len());
        self.body.extend_from_slice(&bytes[..take]);
    }
}

/// Streams one `*.tar.*` member through a bounded per-member pipeline.
#[allow(clippy::struct_excessive_bools)]
struct TarMember<C: StaticCodecProviders> {
    name: Vec<u8>,
    role: Role,
    limits: Limits,
    providers: ProviderSet<BuiltinFormatProviders, C>,
    prefix: Vec<u8>,
    decided: bool,
    skip: bool,
    failed: bool,
    done: bool,
    finished: bool,
    filter: Option<FilterId>,
    pipeline: Option<Pipeline<BuiltinFormatProviders, C>>,
    seen_paths: BTreeSet<PathBuf>,
}

impl<C: StaticCodecProviders + Copy> TarMember<C> {
    fn new(
        name: Vec<u8>,
        role: Role,
        limits: Limits,
        providers: ProviderSet<BuiltinFormatProviders, C>,
    ) -> Self {
        Self {
            name,
            role,
            limits,
            providers,
            prefix: Vec::with_capacity(PROBE_LEN),
            decided: false,
            skip: false,
            failed: false,
            done: false,
            finished: false,
            filter: None,
            pipeline: None,
            seen_paths: BTreeSet::new(),
        }
    }

    fn name_text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.name)
    }

    fn feed(&mut self, mut chunk: &[u8], findings: &mut Vec<PackageFinding>) {
        if self.skip || self.failed || self.done {
            return;
        }
        if !self.decided {
            let take = (PROBE_LEN - self.prefix.len()).min(chunk.len());
            self.prefix.extend_from_slice(&chunk[..take]);
            chunk = &chunk[take..];
            if self.prefix.len() < PROBE_LEN {
                return;
            }
            self.decide(findings);
            if self.skip || self.failed || self.done {
                return;
            }
        }
        self.feed_pipeline(chunk, findings);
    }

    /// Classifies the outer filter, checks capability, and starts the pipeline.
    fn decide(&mut self, findings: &mut Vec<PackageFinding>) {
        self.decided = true;
        if let ProbeResult::Match(filter) = FilterId::probe(&self.prefix) {
            self.filter = Some(filter);
            if !matches!(
                self.providers.codec_capability(filter),
                ProviderCapability::Available(_)
            ) {
                findings.push(PackageFinding::unsupported_method(
                    PROFILE,
                    Some(self.name.clone()),
                    format!(
                        "member {} uses a compression method this build cannot decode",
                        self.name_text()
                    ),
                ));
                self.skip = true;
                return;
            }
        }
        self.pipeline = Some(Pipeline::with_providers(self.limits, self.providers));
        let prefix = std::mem::take(&mut self.prefix);
        self.feed_pipeline(&prefix, findings);
    }

    fn feed_pipeline(&mut self, bytes: &[u8], findings: &mut Vec<PackageFinding>) {
        if self.failed || self.done || self.skip {
            return;
        }
        let Some(mut pipeline) = self.pipeline.take() else {
            return;
        };
        let mut cursor = bytes;
        while !cursor.is_empty() && !self.failed && !self.done {
            match pipeline.feed(cursor) {
                Ok(0) => break,
                Ok(count) => {
                    cursor = &cursor[count..];
                    self.drive(&mut pipeline, findings);
                },
                Err(error) => {
                    self.record_error(&error, false, findings);
                    break;
                },
            }
        }
        if !self.failed && !self.done {
            self.pipeline = Some(pipeline);
        }
    }

    fn drive(
        &mut self,
        pipeline: &mut Pipeline<BuiltinFormatProviders, C>,
        findings: &mut Vec<PackageFinding>,
    ) {
        loop {
            match pipeline.poll_event() {
                Ok(PipelineEvent::NeedInput) => return,
                Ok(PipelineEvent::Entry(metadata)) => self.check_entry(&metadata, findings),
                Ok(PipelineEvent::Done) => {
                    self.done = true;
                    return;
                },
                Ok(
                    PipelineEvent::ArchiveMetadata(_)
                    | PipelineEvent::Data(_)
                    | PipelineEvent::EndEntry,
                ) => {},
                Err(error) => {
                    self.record_error(&error, self.finished, findings);
                    return;
                },
            }
        }
    }

    fn check_entry(&mut self, metadata: &EntryMetadata, findings: &mut Vec<PackageFinding>) {
        let raw = metadata.path().as_bytes();
        if raw.is_empty() || raw == b"." || raw == b"./" {
            return;
        }
        match sanitize_archive_path(metadata.path()) {
            None => findings.push(PackageFinding::new(
                PROFILE,
                Some(raw.to_vec()),
                PackageFindingCode::UnsafeEntryPath,
                format!("entry in {} escapes the archive root", self.name_text()),
            )),
            Some(safe) => {
                if !self.seen_paths.insert(safe) {
                    findings.push(PackageFinding::new(
                        PROFILE,
                        Some(raw.to_vec()),
                        PackageFindingCode::DuplicateEntryPath,
                        format!("entry path repeats within {}", self.name_text()),
                    ));
                }
            },
        }
    }

    fn record_error(
        &mut self,
        error: &ArchiveError,
        after_finish: bool,
        findings: &mut Vec<PackageFinding>,
    ) {
        if self.failed {
            return;
        }
        self.failed = true;
        let code = match error.kind() {
            ErrorKind::Limit => PackageFindingCode::DecompressionBomb,
            ErrorKind::Capability => PackageFindingCode::UnsupportedCompression,
            ErrorKind::Malformed if after_finish => PackageFindingCode::TruncatedMember,
            _ => PackageFindingCode::MalformedNesting,
        };
        findings.push(PackageFinding::new(
            PROFILE,
            Some(self.name.clone()),
            code,
            format!("nested archive in {}: {error}", self.name_text()),
        ));
    }

    fn finish(&mut self, findings: &mut Vec<PackageFinding>) {
        if self.skip || self.failed {
            return;
        }
        if !self.decided {
            self.decide(findings);
            if self.skip || self.failed || self.done {
                return;
            }
        }
        if self.done {
            return;
        }
        let Some(mut pipeline) = self.pipeline.take() else {
            return;
        };
        self.finished = true;
        if let Err(error) = pipeline.finish_input() {
            self.record_error(&error, true, findings);
            return;
        }
        self.drive(&mut pipeline, findings);
        if !self.done && !self.failed {
            self.failed = true;
            findings.push(PackageFinding::new(
                PROFILE,
                Some(self.name.clone()),
                PackageFindingCode::TruncatedMember,
                format!("nested archive in {} did not terminate", self.name_text()),
            ));
        }
    }
}

/// Result of validating one `.deb` package.
#[derive(Debug, Clone)]
pub struct DebValidation {
    status: SupportStatus,
    findings: Vec<PackageFinding>,
    data_compression: Option<FilterId>,
    control_compression: Option<FilterId>,
}

impl DebValidation {
    /// Separated container-readability and profile-conformance verdict.
    #[must_use]
    pub const fn status(&self) -> SupportStatus {
        self.status
    }

    /// Whether the outer `ar` container was parseable.
    #[must_use]
    pub const fn container_readable(&self) -> bool {
        self.status.container_readable()
    }

    /// Whether the package satisfied the Debian profile with no blocking findings.
    #[must_use]
    pub const fn profile_valid(&self) -> bool {
        self.status.profile_valid()
    }

    /// Every typed finding, in discovery order.
    #[must_use]
    pub fn findings(&self) -> &[PackageFinding] {
        &self.findings
    }

    /// Detected outer filter of the `data.tar` member, when one was present.
    ///
    /// `None` means the member was stored as a plain tar, was absent, or could
    /// not be classified.
    #[must_use]
    pub const fn data_compression(&self) -> Option<FilterId> {
        self.data_compression
    }

    /// Detected outer filter of the `control.tar` member, when one was present.
    #[must_use]
    pub const fn control_compression(&self) -> Option<FilterId> {
        self.control_compression
    }

    /// Whether any finding carries the given code.
    #[must_use]
    pub fn has_code(&self, code: PackageFindingCode) -> bool {
        self.findings.iter().any(|finding| finding.code() == code)
    }
}
