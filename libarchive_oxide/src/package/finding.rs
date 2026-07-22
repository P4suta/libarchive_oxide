// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Shared package-validation result types.
//!
//! These plain types are shared by every package profile (currently Debian
//! `.deb`) and by any CLI or JSON front end. They carry no `serde` dependency:
//! everything a caller needs is available through accessors, [`fmt::Display`],
//! and the stable [`PackageFindingCode`] discriminants.

use std::fmt;

/// Ordered severity of a [`PackageFinding`].
///
/// The order is stable and total: `Info < Warning < Error`. A profile is
/// considered valid only when every finding is below [`Severity::Warning`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Advisory context that never invalidates a profile.
    Info,
    /// A condition that could not be fully validated but is not proven hostile.
    Warning,
    /// A structural or safety violation that invalidates the profile.
    Error,
}

impl Severity {
    /// Stable lowercase label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Stable classification of one package-validation observation.
///
/// Each code maps to a [`Severity`] through [`PackageFindingCode::default_severity`];
/// a constructed [`PackageFinding`] may override that default when needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PackageFindingCode {
    /// The package container could not be read at all.
    ContainerUnreadable,
    /// The mandatory leading `debian-binary` member was absent.
    MissingDebianBinary,
    /// The `debian-binary` member did not carry a supported `2.x` version line.
    InvalidVersionStamp,
    /// Members appeared in an order the profile forbids.
    UnexpectedMemberOrder,
    /// A member outside the profile's expected set was present.
    UnknownMember,
    /// A profile member appeared more than once.
    DuplicateMember,
    /// A member the profile requires was missing.
    MissingRequiredMember,
    /// A member name was absolute, traversing, or otherwise unsafe.
    UnsafeMemberName,
    /// A member declared as a nested archive did not decode as one.
    MalformedNesting,
    /// A nested archive ended before it was structurally complete.
    TruncatedMember,
    /// A nested entry path was absolute, traversing, or otherwise unsafe.
    UnsafeEntryPath,
    /// A nested entry path was repeated within one member.
    DuplicateEntryPath,
    /// A nested archive decoded past the configured decompression budget.
    DecompressionBomb,
    /// A member used a compression method this build cannot decode.
    UnsupportedCompression,
    /// The RPM lead was missing, truncated, or carried an invalid magic.
    InvalidLead,
    /// An RPM header section had an invalid magic or version, or was truncated.
    InvalidHeader,
    /// An RPM header's declared index or data store exceeded the metadata budget.
    HeaderTooLarge,
    /// The RPM payload-format tag was absent or not the expected `cpio`.
    PayloadFormatMismatch,
    /// The detected payload filter disagreed with the declared compressor tag.
    CompressorMismatch,
    /// An EPUB `mimetype` member was present but not the first archive member.
    MimetypeNotFirst,
    /// An EPUB `mimetype` member was compressed rather than stored.
    MimetypeNotStored,
    /// An EPUB `mimetype` member did not carry the `application/epub+zip` body.
    MimetypeInvalidContent,
    /// A member was encrypted in a profile that forbids encryption.
    UnexpectedEncryption,
    /// A package carried no detectable signature (informational).
    UnsignedPackage,
    /// A signing scheme was detected in the package (informational).
    SigningSchemeDetected,
}

impl PackageFindingCode {
    /// Stable machine-readable identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContainerUnreadable => "container-unreadable",
            Self::MissingDebianBinary => "missing-debian-binary",
            Self::InvalidVersionStamp => "invalid-version-stamp",
            Self::UnexpectedMemberOrder => "unexpected-member-order",
            Self::UnknownMember => "unknown-member",
            Self::DuplicateMember => "duplicate-member",
            Self::MissingRequiredMember => "missing-required-member",
            Self::UnsafeMemberName => "unsafe-member-name",
            Self::MalformedNesting => "malformed-nesting",
            Self::TruncatedMember => "truncated-member",
            Self::UnsafeEntryPath => "unsafe-entry-path",
            Self::DuplicateEntryPath => "duplicate-entry-path",
            Self::DecompressionBomb => "decompression-bomb",
            Self::UnsupportedCompression => "unsupported-compression",
            Self::InvalidLead => "invalid-lead",
            Self::InvalidHeader => "invalid-header",
            Self::HeaderTooLarge => "header-too-large",
            Self::PayloadFormatMismatch => "payload-format-mismatch",
            Self::CompressorMismatch => "compressor-mismatch",
            Self::MimetypeNotFirst => "mimetype-not-first",
            Self::MimetypeNotStored => "mimetype-not-stored",
            Self::MimetypeInvalidContent => "mimetype-invalid-content",
            Self::UnexpectedEncryption => "unexpected-encryption",
            Self::UnsignedPackage => "unsigned-package",
            Self::SigningSchemeDetected => "signing-scheme-detected",
        }
    }

    /// Severity assigned to this code unless a caller overrides it.
    #[must_use]
    pub const fn default_severity(self) -> Severity {
        match self {
            Self::UnknownMember | Self::UnsupportedCompression | Self::CompressorMismatch => {
                Severity::Warning
            },
            Self::UnsignedPackage | Self::SigningSchemeDetected => Severity::Info,
            _ => Severity::Error,
        }
    }
}

impl fmt::Display for PackageFindingCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One typed observation produced while validating a package.
///
/// The optional `path` carries the archive-native bytes of the member or nested
/// entry the finding is about, so a front end can render it without lossy
/// transcoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageFinding {
    profile: &'static str,
    path: Option<Vec<u8>>,
    code: PackageFindingCode,
    severity: Severity,
    detail: String,
}

impl PackageFinding {
    /// Creates a finding whose severity is the code's default.
    #[must_use]
    pub fn new(
        profile: &'static str,
        path: Option<Vec<u8>>,
        code: PackageFindingCode,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            profile,
            path,
            code,
            severity: code.default_severity(),
            detail: detail.into(),
        }
    }

    /// Creates a capability finding for a compression method this build cannot
    /// decode, mirroring [`crate::provider::ProviderCapability::Disabled`].
    #[must_use]
    pub fn unsupported_method(
        profile: &'static str,
        path: Option<Vec<u8>>,
        detail: impl Into<String>,
    ) -> Self {
        Self::new(
            profile,
            path,
            PackageFindingCode::UnsupportedCompression,
            detail,
        )
    }

    /// Overrides the finding severity.
    #[must_use]
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Profile that produced the finding (for example `"debian"`).
    #[must_use]
    pub const fn profile(&self) -> &'static str {
        self.profile
    }

    /// Archive-native path bytes of the member or entry, when applicable.
    #[must_use]
    pub fn path(&self) -> Option<&[u8]> {
        self.path.as_deref()
    }

    /// Stable classification code.
    #[must_use]
    pub const fn code(&self) -> PackageFindingCode {
        self.code
    }

    /// Effective severity.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Human-readable context.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for PackageFinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "[{}] {}: {}",
            self.severity, self.profile, self.code
        )?;
        if let Some(path) = &self.path {
            write!(formatter, " ({})", String::from_utf8_lossy(path))?;
        }
        write!(formatter, ": {}", self.detail)
    }
}

/// Separated readability and profile-conformance verdict for one package.
///
/// `container_readable` reports whether the outer container structure could be
/// parsed at all; `profile_valid` reports whether the package additionally
/// satisfied its profile with no blocking findings. They are independent: a
/// readable container can still fail its profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupportStatus {
    container_readable: bool,
    profile_valid: bool,
}

impl SupportStatus {
    /// Creates an explicit status.
    #[must_use]
    pub const fn new(container_readable: bool, profile_valid: bool) -> Self {
        Self {
            container_readable,
            profile_valid,
        }
    }

    /// Whether the outer container was parseable.
    #[must_use]
    pub const fn container_readable(self) -> bool {
        self.container_readable
    }

    /// Whether the package satisfied its profile with no blocking findings.
    #[must_use]
    pub const fn profile_valid(self) -> bool {
        self.profile_valid
    }
}
