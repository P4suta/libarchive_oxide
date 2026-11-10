// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! High-level, session-bound archive inspection, planning, and application.
//!
//! An [`ArchiveSession`] owns a bounded immutable snapshot of its input. Plans
//! are tied to that snapshot and to one session, so a caller cannot accidentally
//! inspect one byte stream and apply a different one.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use cap_std::fs::Dir;
use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, EntryKind, EntryMetadata, ErrorKind, FilterId, FormatId, Limits,
    ProbeResult,
};
use sha2::{Digest, Sha256};

use crate::extraction::{ExtractionReport, Policy, RejectionReason};
use crate::filesystem_driver::{apply_registered_plan, apply_seek_plan, apply_volume_plan};
use crate::path::{DestinationClaims, DestinationKey};
use crate::provider::{
    BuiltinCodecProviders, BuiltinFormatProviders, CodecProvider, CodecProviderNode,
    FormatProvider, FormatProviderNode, ProviderCapability, ProviderSet, StaticCodecProviders,
    StaticFormatProviders,
};
use crate::spool::{DEFAULT_MAX_BYTES, DEFAULT_MEMORY_THRESHOLD};
use crate::stream::ProviderArchiveWriter;
#[cfg(feature = "aes")]
use crate::{AesStrength, ZipWriteOptions};
use crate::{
    ArchiveReader, ArchiveWriter, BackendPreference, CapStdFilesystemAdapter, FilesystemAdapter,
    FilesystemFinding, FormatWriteOptions, OpenOptions, PasswordCandidates, ReaderEvent,
    SecretBytes, SeekArchiveReader, SeekArchiveWriter, SevenZipCompression, SevenZipEncryption,
    SevenZipFilter, SevenZipWriteOptions, SpoolReader, StreamError, VolumeArchiveReader, VolumeSet,
    XarCompression, XarWriteOptions, ZipCompression, ZipEncryption, ZipMethod,
};

const FORMAT_PROBE_BYTES: usize = 17 * 2048 + 6;
const DIGEST_BUFFER_BYTES: usize = 64 * 1024;
static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// SHA-256 identity of the immutable encoded input snapshot.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InputDigest([u8; 32]);

impl InputDigest {
    /// Digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for InputDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

impl fmt::Display for InputDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Explicit immutable snapshot used by inspect/plan/apply sessions.
#[derive(Debug)]
pub struct PreparedArchive {
    snapshot: SpoolReader,
    digest: InputDigest,
}

impl PreparedArchive {
    /// Spools an input with the safe finite memory and total-size bounds.
    pub fn spool(input: impl Read) -> Result<Self, StreamError> {
        Self::spool_with_limits(input, DEFAULT_MEMORY_THRESHOLD, DEFAULT_MAX_BYTES)
    }

    /// Spools an input with explicit memory and total-size bounds.
    pub fn spool_with_limits(
        input: impl Read,
        memory_threshold: usize,
        maximum: u64,
    ) -> Result<Self, StreamError> {
        let mut snapshot = SpoolReader::from_reader_with_limits(input, memory_threshold, maximum)?;
        let digest = digest_snapshot(&mut snapshot)?;
        Ok(Self { snapshot, digest })
    }

    /// SHA-256 identity of the encoded snapshot.
    #[must_use]
    pub const fn digest(&self) -> InputDigest {
        self.digest
    }

    /// Encoded snapshot length.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.snapshot.len()
    }

    /// Whether the encoded snapshot is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.snapshot.is_empty()
    }
}

/// High-level archive engine configuration.
#[derive(Debug, Clone, Copy)]
pub struct ArchiveEngine<F = BuiltinFormatProviders, C = BuiltinCodecProviders>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    limits: Limits,
    spool_memory_threshold: usize,
    spool_maximum: u64,
    backend: BackendPreference,
    providers: ProviderSet<F, C>,
}

impl ArchiveEngine<BuiltinFormatProviders, BuiltinCodecProviders> {
    /// Safe finite defaults with the built-in providers.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: Limits::safe(),
            spool_memory_threshold: DEFAULT_MEMORY_THRESHOLD,
            spool_maximum: DEFAULT_MAX_BYTES,
            backend: BackendPreference::Auto,
            providers: ProviderSet::builtins(),
        }
    }

    /// Selects the built-in portable or native codec backend at runtime.
    #[must_use]
    pub const fn with_backend_preference(mut self, backend: BackendPreference) -> Self {
        self.backend = backend;
        self.providers = ProviderSet::builtins_with_backend(backend);
        self
    }

    /// Opens an inspect/plan/apply session over caller-owned archive volumes.
    ///
    /// `OpenOptions` supplies the authoritative archive and source limits for this operation.
    /// Every required volume is resolved while the session is opened, then all encoded volume bytes are hashed into the session digest with bounded memory.
    /// Rewinds recreate the format reader over the same immutable `VolumeSet`; no adjacent path discovery is performed.
    pub fn open_volumes(self, options: &crate::OpenOptions) -> Result<ArchiveSession, StreamError> {
        let engine = self.with_limits(options.limits());
        let volumes = options.volumes().ok_or_else(|| {
            ArchiveError::new(ErrorKind::Capability)
                .with_context("ArchiveEngine::open_volumes requires a VolumeSet")
        })?;
        let mut discovery_reader = VolumeArchiveReader::with_options(options)?;
        loop {
            if matches!(discovery_reader.next_event()?, ReaderEvent::Done) {
                break;
            }
        }
        let digest = digest_volume_set(volumes)?;
        let reader = VolumeArchiveReader::with_options(options)?;
        let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        Ok(ArchiveSession {
            id,
            digest,
            limits: engine.limits,
            reader: Some(SessionReader::Volume {
                reader: Box::new(reader),
                options: Box::new(options.clone()),
            }),
            open_options: Box::new(options.clone()),
            applied: false,
        })
    }

    /// Opens a split 7z, ZIP, or RAR session by discovering adjacent volumes.
    ///
    /// Discovery is deliberately available only for path-based opens and only after [`crate::OpenOptions::with_adjacent_volume_discovery`] is enabled.
    /// Supported supplied names are numeric first-volume `archive.7z.001`,
    /// terminal `archive.zip` for standard `.z01` split ZIP, modern RAR `archive.part001.rar`, and legacy RAR 3.x/4.x `archive.rar`.
    /// Subsequent names preserve numeric width and case; old RAR names range from `.r00` through `.r99`.
    /// Every derived path stays in the same directory and is opened under the configured [`crate::SourceLimits`].
    ///
    /// Caller-owned [`crate::VolumeSet`] values cannot be combined with path discovery.
    /// Handle-, stream-, and range-based readers never inspect neighboring filesystem paths.
    pub fn open_path_with_options(
        self,
        path: impl AsRef<Path>,
        options: &crate::OpenOptions,
    ) -> Result<ArchiveSession, StreamError> {
        if !options.adjacent_volume_discovery() {
            return Err(ArchiveError::new(ErrorKind::Capability)
                .with_context(
                    "path-based adjacent volume discovery requires explicit OpenOptions opt-in",
                )
                .into());
        }
        if options.volumes().is_some() {
            return Err(ArchiveError::new(ErrorKind::Capability)
                .with_context(
                    "path-based adjacent volume discovery cannot be combined with a VolumeSet",
                )
                .into());
        }
        let path = path.as_ref();
        let naming = AdjacentVolumeNaming::parse(path, options.format())?;
        let format = options.format().or(naming.inferred_format());
        let primary_path = naming.primary_path();
        let required_last_volume = naming.required_last_volume();
        let primary: Arc<dyn crate::advanced::ReadAt> =
            Arc::new(crate::advanced::FileReadAt::open(primary_path).map_err(StreamError::io)?);
        let resolver = Arc::new(AdjacentPathVolumeResolver { naming });
        let volumes = Arc::new(
            crate::VolumeSet::new(primary, resolver, options.source_limits())
                .map_err(StreamError::io)?,
        );
        if let Some(last) = required_last_volume {
            for index in 1..=last {
                volumes
                    .resolve_required(crate::advanced::VolumeId::new(index))
                    .map_err(StreamError::io)?;
            }
        }
        let volume_options = options
            .clone()
            .with_format(format)
            .with_volumes(volumes)
            .with_adjacent_volume_discovery(false);
        self.open_volumes(&volume_options)
    }

    /// Creates a sequential writer from high-level options.
    pub fn create<W: Write>(
        self,
        output: W,
        options: CreateOptions,
    ) -> Result<ArchiveWriter<W>, StreamError> {
        let limits = options.limits.unwrap_or(self.limits);
        if let Some(format_options) = options.format_options {
            validate_format_options(options.format, format_options)?;
            if options.filter.is_some() {
                return Err(writer_error(
                    ErrorKind::Capability,
                    "format-specific writer options cannot be combined with an outer filter",
                ));
            }
            return match format_options {
                FormatWriteOptions::Zip(zip) => {
                    if zip.encryption() != ZipEncryption::None {
                        return Err(writer_error(
                            ErrorKind::Capability,
                            "encrypted ZIP creation requires create_with_password",
                        ));
                    }
                    Ok(ArchiveWriter::with_zip_method_and_backend(
                        output,
                        zip_method(zip.compression())?,
                        limits,
                        self.backend,
                    ))
                },
                FormatWriteOptions::SevenZip(_) => Err(writer_error(
                    ErrorKind::Capability,
                    "7z creation requires a seekable destination",
                )),
                FormatWriteOptions::Xar(_) => Err(writer_error(
                    ErrorKind::Capability,
                    "XAR creation requires a seekable destination",
                )),
            };
        }
        ArchiveWriter::with_filter_and_backend(
            output,
            options.format,
            options.filter,
            limits,
            self.backend,
        )
        .map_err(StreamError::archive)
    }

    /// Creates a streaming `WinZip` AES AE-2 writer.
    ///
    /// The high-level encrypted profile deliberately uses the same Deflate method as ordinary high-level ZIP creation.
    /// Passwords are accepted only for ZIP without an outer filter, so a supplied secret is never silently ignored by another format.
    #[cfg(feature = "aes")]
    pub fn create_with_password<W: Write>(
        self,
        output: W,
        options: CreateOptions,
        password: SecretBytes,
    ) -> Result<ArchiveWriter<W>, StreamError> {
        if options.format != FormatId::Zip {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability).with_context(
                    "password-protected high-level creation is available only for ZIP",
                ),
            ));
        }
        if options.filter.is_some() {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability)
                    .with_format("zip")
                    .with_context("password-protected ZIP cannot use an outer filter"),
            ));
        }
        let zip = match options.format_options {
            None => {
                ZipWriteOptions::new().with_encryption(ZipEncryption::Aes(AesStrength::Bits256))
            },
            Some(format_options) => {
                validate_format_options(options.format, format_options)?;
                let FormatWriteOptions::Zip(zip) = format_options else {
                    return Err(writer_error(
                        ErrorKind::Capability,
                        "7z options cannot configure a ZIP writer",
                    ));
                };
                zip
            },
        };
        let limits = options.limits.unwrap_or(self.limits);
        if !encrypted_zip_compression_supported(zip.compression()) {
            return Err(writer_error(
                ErrorKind::Unsupported,
                "encrypted ZIP writing does not support the requested compression method",
            ));
        }
        match zip.encryption() {
            ZipEncryption::Aes(strength) => {
                Ok(ArchiveWriter::with_zip_password_strength_and_backend(
                    output,
                    zip_method(zip.compression())?,
                    password,
                    strength,
                    limits,
                    self.backend,
                ))
            },
            ZipEncryption::ZipCrypto => Ok(ArchiveWriter::with_zipcrypto_password_and_backend(
                output,
                zip_method(zip.compression())?,
                password,
                limits,
                self.backend,
            )),
            ZipEncryption::None => Err(writer_error(
                ErrorKind::Capability,
                "password supplied for an unencrypted ZIP profile",
            )),
        }
    }

    /// Creates a seek-capable writer from high-level options.
    pub fn create_seek<W: Write + Seek>(
        self,
        output: W,
        options: CreateOptions,
    ) -> Result<SeekArchiveWriter<W>, StreamError> {
        if options.filter.is_some() {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability)
                    .with_context("seek-native high-level creation does not support outer filters"),
            ));
        }
        let limits = options.limits.unwrap_or(self.limits);
        match options.format_options {
            None => SeekArchiveWriter::with_format(output, options.format, limits),
            Some(format_options) => {
                validate_format_options(options.format, format_options)?;
                match format_options {
                    FormatWriteOptions::Zip(zip) => {
                        if zip.encryption() != ZipEncryption::None {
                            return Err(writer_error(
                                ErrorKind::Capability,
                                "encrypted ZIP creation requires create_with_password",
                            ));
                        }
                        Ok(SeekArchiveWriter::with_zip_method_and_backend(
                            output,
                            zip_method(zip.compression())?,
                            limits,
                            self.backend,
                        ))
                    },
                    FormatWriteOptions::SevenZip(sevenz) => {
                        validate_sevenz_write_options(sevenz)?;
                        if sevenz.encryption() != SevenZipEncryption::None {
                            return Err(writer_error(
                                ErrorKind::Capability,
                                "encrypted 7z creation requires create_seek_with_password",
                            ));
                        }
                        #[cfg(feature = "sevenz")]
                        {
                            SeekArchiveWriter::with_sevenz_options(output, sevenz, limits)
                        }
                        #[cfg(not(feature = "sevenz"))]
                        {
                            let _ = output;
                            Err(writer_error(
                                ErrorKind::Unsupported,
                                "7z support is disabled",
                            ))
                        }
                    },
                    FormatWriteOptions::Xar(xar) => {
                        validate_xar_write_options(xar)?;
                        SeekArchiveWriter::with_xar_options(output, xar, limits)
                    },
                }
            },
        }
    }

    /// Creates a seek-capable 7z AES-256/SHA-256 writer with an explicit password.
    ///
    /// Content is encrypted while the next header remains plaintext, so metadata can be listed without a password.
    /// A supplied secret is rejected for every unencrypted or non-7z profile.
    #[cfg(feature = "aes")]
    pub fn create_seek_with_password<W: Write + Seek>(
        self,
        output: W,
        options: CreateOptions,
        password: SecretBytes,
    ) -> Result<SeekArchiveWriter<W>, StreamError> {
        if options.format != FormatId::SevenZip {
            return Err(writer_error(
                ErrorKind::Capability,
                "password-protected seek creation is available only for 7z",
            ));
        }
        if options.filter.is_some() {
            return Err(writer_error(
                ErrorKind::Capability,
                "password-protected 7z creation cannot use an outer filter",
            ));
        }
        let sevenz = match options.format_options {
            None => SevenZipWriteOptions::new().with_encryption(SevenZipEncryption::Aes256),
            Some(format_options) => {
                validate_format_options(options.format, format_options)?;
                let FormatWriteOptions::SevenZip(sevenz) = format_options else {
                    return Err(writer_error(
                        ErrorKind::Capability,
                        "ZIP options cannot configure a 7z writer",
                    ));
                };
                sevenz
            },
        };
        validate_sevenz_write_options(sevenz)?;
        if sevenz.encryption() != SevenZipEncryption::Aes256 {
            return Err(writer_error(
                ErrorKind::Capability,
                "password supplied for an unencrypted 7z profile",
            ));
        }
        let limits = options.limits.unwrap_or(self.limits);
        #[cfg(feature = "sevenz")]
        {
            let result = SeekArchiveWriter::with_sevenz_options_and_password(
                output, sevenz, &password, limits,
            );
            drop(password);
            result
        }
        #[cfg(not(feature = "sevenz"))]
        {
            let _ = (output, password, limits);
            Err(writer_error(
                ErrorKind::Unsupported,
                "7z support is disabled",
            ))
        }
    }
}

#[derive(Debug)]
struct AdjacentPathVolumeResolver {
    naming: AdjacentVolumeNaming,
}

impl crate::advanced::VolumeResolver for AdjacentPathVolumeResolver {
    fn resolve(
        &self,
        volume: crate::advanced::VolumeId,
    ) -> std::io::Result<Option<Arc<dyn crate::advanced::ReadAt>>> {
        let Some(path) = self.naming.path(volume)? else {
            return Ok(None);
        };
        match crate::advanced::FileReadAt::open(path) {
            Ok(source) => Ok(Some(Arc::new(source))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[derive(Debug)]
enum AdjacentVolumeNaming {
    Numeric {
        template: PathBuf,
        width: usize,
    },
    RarPart {
        template: PathBuf,
        prefix: String,
        extension: String,
        width: usize,
    },
    LegacyRar {
        template: PathBuf,
        uppercase: bool,
    },
    ZipSplit {
        terminal: PathBuf,
        uppercase: bool,
        terminal_volume: u32,
    },
}

impl AdjacentVolumeNaming {
    const fn inferred_format(&self) -> Option<FormatId> {
        match self {
            Self::Numeric { .. } => Some(FormatId::SevenZip),
            Self::RarPart { .. } => None,
            Self::LegacyRar { .. } => Some(FormatId::RarLegacy),
            Self::ZipSplit { .. } => Some(FormatId::Zip),
        }
    }

    fn primary_path(&self) -> PathBuf {
        match self {
            Self::Numeric { template, .. }
            | Self::RarPart { template, .. }
            | Self::LegacyRar { template, .. } => template.clone(),
            Self::ZipSplit {
                terminal,
                uppercase,
                terminal_volume,
            } => {
                if *terminal_volume == 0 {
                    return terminal.clone();
                }
                let letter = if *uppercase { 'Z' } else { 'z' };
                let mut path = terminal.clone();
                path.set_extension(format!("{letter}01"));
                path
            },
        }
    }

    const fn required_last_volume(&self) -> Option<u32> {
        match self {
            Self::ZipSplit {
                terminal_volume, ..
            } => Some(*terminal_volume),
            _ => None,
        }
    }

    fn parse(path: &Path, format: Option<FormatId>) -> Result<Self, StreamError> {
        if !matches!(
            format,
            None | Some(FormatId::SevenZip | FormatId::RarLegacy | FormatId::Rar5 | FormatId::Zip)
        ) {
            return Err(adjacent_path_error(
                "adjacent volume discovery supports only 7z, ZIP, RAR 3.x/4.x, and RAR5",
            ));
        }

        if let Some(suffix) = path.extension().and_then(|suffix| suffix.to_str())
            && !suffix.is_empty()
            && suffix.bytes().all(|byte| byte.is_ascii_digit())
        {
            if format.is_some_and(|format| format != FormatId::SevenZip) {
                return Err(adjacent_path_error(
                    "numeric .001-style discovery requires 7z when format is explicit",
                ));
            }
            let physical = suffix.parse::<u32>().map_err(|_| {
                adjacent_path_error("adjacent numeric volume suffix exceeds the supported range")
            })?;
            if physical != 1 {
                return Err(adjacent_path_error(
                    "adjacent numeric discovery must start from physical volume one",
                ));
            }
            return Ok(Self::Numeric {
                template: path.to_path_buf(),
                width: suffix.len(),
            });
        }

        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .ok_or_else(|| {
                adjacent_path_error("adjacent ZIP/RAR discovery requires a UTF-8 terminal filename")
            })?;
        if extension.eq_ignore_ascii_case("zip") {
            if format.is_some_and(|format| format != FormatId::Zip) {
                return Err(adjacent_path_error(
                    "terminal .zip discovery requires ZIP when format is explicit",
                ));
            }
            let terminal = crate::advanced::FileReadAt::open(path).map_err(StreamError::io)?;
            let terminal_volume = crate::zip_volume::terminal_disk_number(&terminal)?;
            return Ok(Self::ZipSplit {
                terminal: path.to_path_buf(),
                uppercase: extension
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_uppercase),
                terminal_volume,
            });
        }
        Self::parse_rar(path, format, extension)
    }

    fn parse_rar(
        path: &Path,
        format: Option<FormatId>,
        extension: &str,
    ) -> Result<Self, StreamError> {
        if !extension.eq_ignore_ascii_case("rar") {
            return Err(adjacent_path_error(
                "adjacent volume path must use .001, terminal .zip, .part1.rar, or legacy .rar naming",
            ));
        }
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| {
                adjacent_path_error("adjacent RAR discovery requires a UTF-8 filename")
            })?;
        let lowercase = stem.to_ascii_lowercase();
        if let Some(part) = lowercase.rfind(".part") {
            if format == Some(FormatId::SevenZip) {
                return Err(adjacent_path_error(
                    ".part1.rar discovery requires a RAR format",
                ));
            }
            let digits = &stem[part + 5..];
            if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(adjacent_path_error(
                    "modern RAR discovery requires a numeric .part1.rar-style name",
                ));
            }
            let physical = digits.parse::<u32>().map_err(|_| {
                adjacent_path_error("RAR part number exceeds the supported numeric range")
            })?;
            if physical != 1 {
                return Err(adjacent_path_error(
                    "modern RAR discovery must start from part one",
                ));
            }
            return Ok(Self::RarPart {
                template: path.to_path_buf(),
                prefix: stem[..part + 5].to_owned(),
                extension: extension.to_owned(),
                width: digits.len(),
            });
        }

        if format.is_some_and(|format| format != FormatId::RarLegacy) {
            return Err(adjacent_path_error(
                "unsuffixed .rar discovery is the legacy RAR 3.x/4.x naming scheme",
            ));
        }
        Ok(Self::LegacyRar {
            template: path.to_path_buf(),
            uppercase: extension
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_uppercase),
        })
    }

    fn path(&self, volume: crate::advanced::VolumeId) -> std::io::Result<Option<PathBuf>> {
        if volume.get() == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "adjacent resolver cannot resolve the primary volume",
            ));
        }
        match self {
            Self::Numeric { template, width } => {
                let physical = volume
                    .get()
                    .checked_add(1)
                    .ok_or_else(|| std::io::Error::other("adjacent volume number overflow"))?;
                let mut path = template.clone();
                path.set_extension(format!("{physical:0width$}"));
                Ok(Some(path))
            },
            Self::RarPart {
                template,
                prefix,
                extension,
                width,
            } => {
                let physical = volume
                    .get()
                    .checked_add(1)
                    .ok_or_else(|| std::io::Error::other("RAR part number overflow"))?;
                let mut path = template.clone();
                path.set_file_name(format!("{prefix}{physical:0width$}.{extension}"));
                Ok(Some(path))
            },
            Self::LegacyRar {
                template,
                uppercase,
            } => {
                let ordinal = volume.get() - 1;
                if ordinal > 99 {
                    return Ok(None);
                }
                let letter = if *uppercase { 'R' } else { 'r' };
                let mut path = template.clone();
                path.set_extension(format!("{letter}{ordinal:02}"));
                Ok(Some(path))
            },
            Self::ZipSplit {
                terminal,
                uppercase,
                terminal_volume,
            } => {
                if volume.get() > *terminal_volume {
                    return Ok(None);
                }
                if volume.get() == *terminal_volume {
                    return Ok(Some(terminal.clone()));
                }
                let physical = volume
                    .get()
                    .checked_add(1)
                    .ok_or_else(|| std::io::Error::other("ZIP disk number overflow"))?;
                let letter = if *uppercase { 'Z' } else { 'z' };
                let mut path = terminal.clone();
                path.set_extension(format!("{letter}{physical:02}"));
                Ok(Some(path))
            },
        }
    }
}

fn adjacent_path_error(context: &'static str) -> StreamError {
    ArchiveError::new(ErrorKind::Capability)
        .with_context(context)
        .into()
}

impl<F, C> ArchiveEngine<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    /// Replaces parser, codec, inspection, and extraction budgets.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces the immutable snapshot's memory threshold and total byte cap.
    #[must_use]
    pub const fn with_spool_limits(mut self, memory_threshold: usize, maximum: u64) -> Self {
        self.spool_memory_threshold = memory_threshold;
        self.spool_maximum = maximum;
        self
    }

    /// Prepends one compile-time format provider to this engine.
    #[doc(hidden)]
    #[must_use]
    pub fn with_format_provider<P>(self, provider: P) -> ArchiveEngine<FormatProviderNode<P, F>, C>
    where
        P: FormatProvider,
    {
        ArchiveEngine {
            limits: self.limits,
            spool_memory_threshold: self.spool_memory_threshold,
            spool_maximum: self.spool_maximum,
            backend: self.backend,
            providers: self.providers.with_format_provider(provider),
        }
    }

    /// Prepends one compile-time outer-codec provider to this engine.
    #[doc(hidden)]
    #[must_use]
    pub fn with_codec_provider<P>(self, provider: P) -> ArchiveEngine<F, CodecProviderNode<P, C>>
    where
        P: CodecProvider,
    {
        ArchiveEngine {
            limits: self.limits,
            spool_memory_threshold: self.spool_memory_threshold,
            spool_maximum: self.spool_maximum,
            backend: self.backend,
            providers: self.providers.with_codec_provider(provider),
        }
    }

    /// Resource budgets used for new sessions.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Providers available to new sessions.
    #[doc(hidden)]
    #[must_use]
    pub fn providers(self) -> ProviderSet<F, C> {
        self.providers
    }

    /// Creates a sequential writer through this engine's registered provider chains.
    pub fn create_registered<W: Write>(
        self,
        output: W,
        options: CreateOptions,
    ) -> Result<ProviderArchiveWriter<W, F, C>, StreamError> {
        if options.format_options.is_some() {
            return Err(writer_error(
                ErrorKind::Capability,
                "format-specific writer options are available only for built-in writers",
            ));
        }
        let limits = options.limits.unwrap_or(self.limits);
        ProviderArchiveWriter::with_providers(
            output,
            options.format,
            options.filter,
            limits,
            self.providers,
        )
        .map_err(StreamError::archive)
    }

    /// Opens a true streaming reader without implicitly spooling the input.
    #[must_use]
    pub fn open<R: Read>(self, input: R) -> ArchiveReader<R, F, C> {
        ArchiveReader::with_providers(input, self.limits, self.providers)
    }

    /// Opens a true streaming reader with an explicit sequential format.
    ///
    /// This is the safe entry point for signatureless formats such as raw
    /// single-entry streams; automatic detection is never allowed to guess
    /// them.
    ///
    /// # Errors
    ///
    /// Returns an error if the identifier is not a readable sequential format
    /// in this engine's provider set.
    pub fn open_with_format<R: Read>(
        self,
        input: R,
        format: FormatId,
    ) -> Result<ArchiveReader<R, F, C>, ArchiveError> {
        ArchiveReader::with_providers_and_format(input, format, self.limits, self.providers)
    }

    /// Explicitly spools input and opens an inspect/plan/apply session.
    pub fn prepare(self, input: impl Read) -> Result<ArchiveSession<F, C>, StreamError> {
        let options = OpenOptions::new().with_limits(self.limits);
        self.prepare_with_options(input, &options)
    }

    /// Explicitly spools input and opens a password-capable ZIP/7z session.
    ///
    /// This does not change [`Self::open`]: ordinary readers remain true
    /// streaming readers and never spool implicitly. A supplied password is
    /// rejected for formats other than seek-native ZIP and 7z.
    pub fn prepare_with_password(
        self,
        input: impl Read,
        password: SecretBytes,
    ) -> Result<ArchiveSession<F, C>, StreamError> {
        let options = OpenOptions::new()
            .with_limits(self.limits)
            .with_password_provider(Arc::new(PasswordCandidates::new([password])));
        self.prepare_with_options(input, &options)
    }

    /// Explicitly spools input and opens a session for one archive format.
    ///
    /// Signatureless formats such as [`FormatId::Raw`] require this path.
    ///
    /// # Errors
    ///
    /// Returns an error if spooling fails or the requested identifier is not a readable format in this engine's provider set.
    pub fn prepare_with_format(
        self,
        input: impl Read,
        format: FormatId,
    ) -> Result<ArchiveSession<F, C>, StreamError> {
        let options = OpenOptions::new()
            .with_format(Some(format))
            .with_limits(self.limits);
        self.prepare_with_options(input, &options)
    }

    /// Explicitly spools input and opens a session with the common read options.
    ///
    /// The encoded input is bounded by both this engine's spool maximum and [`crate::SourceLimits::source_bytes`].
    /// Caller-owned volume sets and adjacent-volume discovery use [`ArchiveEngine::open_volumes`] and [`ArchiveEngine::open_path_with_options`] instead.
    pub fn prepare_with_options(
        self,
        input: impl Read,
        options: &OpenOptions,
    ) -> Result<ArchiveSession<F, C>, StreamError> {
        validate_prepared_options(options)?;
        let source_maximum = options.source_limits().source_bytes();
        let source_limit_applies =
            source_maximum.is_some_and(|maximum| maximum <= self.spool_maximum);
        let maximum = source_maximum.map_or(self.spool_maximum, |maximum| {
            maximum.min(self.spool_maximum)
        });
        let prepared =
            match PreparedArchive::spool_with_limits(input, self.spool_memory_threshold, maximum) {
                Ok(prepared) => prepared,
                Err(error)
                    if source_limit_applies
                        && error.io_error().is_some_and(|error| {
                            error.kind() == std::io::ErrorKind::FileTooLarge
                        }) =>
                {
                    return Err(StreamError::archive(
                        ArchiveError::new(ErrorKind::Limit).with_context(
                            "encoded input exceeds the prepared-session source limit",
                        ),
                    ));
                },
                Err(error) => return Err(error),
            };
        self.open_prepared_with_options(prepared, options)
    }

    /// Opens an inspect/plan/apply session over a previously prepared snapshot.
    pub fn open_prepared(
        self,
        prepared: PreparedArchive,
    ) -> Result<ArchiveSession<F, C>, StreamError> {
        let options = OpenOptions::new().with_limits(self.limits);
        self.open_prepared_with_options(prepared, &options)
    }

    /// Opens a prepared snapshot as a password-capable ZIP/7z session.
    ///
    /// The secret remains in zeroizing storage for the session lifetime so
    /// [`ArchiveSession::rewind`] can reconstruct the authenticated reader.
    /// Other formats reject the password instead of ignoring it.
    pub fn open_prepared_with_password(
        self,
        prepared: PreparedArchive,
        password: SecretBytes,
    ) -> Result<ArchiveSession<F, C>, StreamError> {
        let options = OpenOptions::new()
            .with_limits(self.limits)
            .with_password_provider(Arc::new(PasswordCandidates::new([password])));
        self.open_prepared_with_options(prepared, &options)
    }

    /// Opens a prepared snapshot with an explicit archive format.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested identifier is not a readable format in this engine's provider set.
    pub fn open_prepared_with_format(
        self,
        prepared: PreparedArchive,
        format: FormatId,
    ) -> Result<ArchiveSession<F, C>, StreamError> {
        let options = OpenOptions::new()
            .with_format(Some(format))
            .with_limits(self.limits);
        self.open_prepared_with_options(prepared, &options)
    }

    /// Opens a prepared snapshot with the common synchronous/async/range options.
    pub fn open_prepared_with_options(
        self,
        prepared: PreparedArchive,
        options: &OpenOptions,
    ) -> Result<ArchiveSession<F, C>, StreamError> {
        validate_prepared_options(options)?;
        if options
            .source_limits()
            .source_bytes()
            .is_some_and(|maximum| prepared.len() > maximum)
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Limit)
                    .with_context("prepared input exceeds the configured source limit"),
            ));
        }
        let reader = SessionReader::open_with_options(prepared.snapshot, options, self.providers)?;
        let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        Ok(ArchiveSession {
            id,
            digest: prepared.digest,
            limits: options.limits(),
            reader: Some(reader),
            open_options: Box::new(options.clone()),
            applied: false,
        })
    }
}

fn validate_prepared_options(options: &OpenOptions) -> Result<(), StreamError> {
    if options.volumes().is_some() {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Capability)
                .with_context("prepared stream input cannot be combined with a VolumeSet"),
        ));
    }
    if options.adjacent_volume_discovery() {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Capability).with_context(
                "adjacent volume discovery is available only for path-based open operations",
            ),
        ));
    }
    Ok(())
}

impl Default for ArchiveEngine<BuiltinFormatProviders, BuiltinCodecProviders> {
    fn default() -> Self {
        Self::new()
    }
}
/// High-level archive creation choices.
#[derive(Debug, Clone, Copy)]
pub struct CreateOptions {
    format: FormatId,
    filter: Option<FilterId>,
    limits: Option<Limits>,
    format_options: Option<FormatWriteOptions>,
}

impl CreateOptions {
    /// Creates uncompressed tar with the engine's limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            format: FormatId::Tar,
            filter: None,
            limits: None,
            format_options: None,
        }
    }

    /// Selects the archive container.
    #[must_use]
    pub const fn with_format(mut self, format: FormatId) -> Self {
        self.format = format;
        self
    }

    /// Selects an outer compression filter.
    #[must_use]
    pub const fn with_filter(mut self, filter: Option<FilterId>) -> Self {
        self.filter = filter;
        self
    }

    /// Overrides the engine limits for this writer.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Selects format-specific compression, solid, filter, and encryption options.
    #[must_use]
    pub const fn with_format_options(mut self, options: Option<FormatWriteOptions>) -> Self {
        self.format_options = options;
        self
    }

    /// Selected format.
    #[must_use]
    pub const fn format(self) -> FormatId {
        self.format
    }

    /// Selected outer filter.
    #[must_use]
    pub const fn filter(self) -> Option<FilterId> {
        self.filter
    }

    /// Explicit writer limits, or `None` to inherit the engine limits.
    #[must_use]
    pub const fn limits(self) -> Option<Limits> {
        self.limits
    }

    /// Selected format-specific options.
    #[must_use]
    pub const fn format_options(self) -> Option<FormatWriteOptions> {
        self.format_options
    }
}

fn validate_format_options(
    format: FormatId,
    options: FormatWriteOptions,
) -> Result<(), StreamError> {
    let matches = matches!(
        (format, options),
        (FormatId::Zip, FormatWriteOptions::Zip(_))
            | (FormatId::SevenZip, FormatWriteOptions::SevenZip(_))
            | (FormatId::Xar, FormatWriteOptions::Xar(_))
    );
    if matches {
        Ok(())
    } else {
        Err(writer_error(
            ErrorKind::Capability,
            "format-specific writer options do not match the selected container",
        ))
    }
}

fn validate_xar_write_options(options: XarWriteOptions) -> Result<(), StreamError> {
    let implemented = match options.compression() {
        XarCompression::Store | XarCompression::Zlib => true,
        #[cfg(feature = "bzip2")]
        XarCompression::Bzip2 => true,
        #[allow(unreachable_patterns)]
        _ => false,
    };
    if implemented {
        Ok(())
    } else {
        Err(writer_error(
            ErrorKind::Unsupported,
            "XAR writer compression method is disabled in this build",
        ))
    }
}

fn validate_sevenz_write_options(options: SevenZipWriteOptions) -> Result<(), StreamError> {
    // The fallback covers feature-disabled BZip2/Zstd variants; with both features it is intentionally unreachable because this enum is crate-owned and currently exhaustive.
    #[allow(unreachable_patterns)]
    let compression_implemented = match options.compression() {
        SevenZipCompression::Store
        | SevenZipCompression::Lzma
        | SevenZipCompression::Lzma2
        | SevenZipCompression::Ppmd7
        | SevenZipCompression::Deflate => true,
        #[cfg(feature = "bzip2")]
        SevenZipCompression::Bzip2 => true,
        #[cfg(feature = "zstd")]
        SevenZipCompression::Zstd => true,
        _ => false,
    };
    let filter_implemented = match options.filter() {
        None
        | Some(
            SevenZipFilter::Delta(1..=256)
            | SevenZipFilter::BcjX86
            | SevenZipFilter::BcjPowerPc
            | SevenZipFilter::BcjIa64
            | SevenZipFilter::BcjArm
            | SevenZipFilter::BcjArmThumb
            | SevenZipFilter::BcjArm64
            | SevenZipFilter::BcjSparc
            | SevenZipFilter::BcjRiscV,
        ) => true,
        Some(SevenZipFilter::Delta(_)) => {
            return Err(writer_error(
                ErrorKind::Malformed,
                "7z Delta distance must be in 1..=256",
            ));
        },
    };
    if compression_implemented && filter_implemented {
        Ok(())
    } else {
        Err(writer_error(
            ErrorKind::Unsupported,
            "requested 7z writer profile is not implemented",
        ))
    }
}

fn zip_method(compression: ZipCompression) -> Result<ZipMethod, StreamError> {
    match compression {
        ZipCompression::Store => Ok(ZipMethod::Store),
        ZipCompression::Deflate => Ok(ZipMethod::Deflate),
        #[cfg(feature = "bzip2")]
        ZipCompression::Bzip2 => Ok(ZipMethod::Bzip2),
        #[cfg(feature = "zstd")]
        ZipCompression::Zstd => Ok(ZipMethod::Zstd),
        #[cfg(feature = "xz")]
        ZipCompression::Lzma => Ok(ZipMethod::Lzma),
        #[cfg(feature = "xz")]
        ZipCompression::Xz => Ok(ZipMethod::Xz),
        #[cfg(feature = "ppmd")]
        ZipCompression::Ppmd8 => Ok(ZipMethod::Ppmd8),
        _ => Err(writer_error(
            ErrorKind::Unsupported,
            "requested ZIP compression method is not available in this build",
        )),
    }
}

#[cfg(feature = "aes")]
fn encrypted_zip_compression_supported(compression: ZipCompression) -> bool {
    #[allow(unreachable_patterns)]
    match compression {
        ZipCompression::Store | ZipCompression::Deflate => true,
        #[cfg(feature = "bzip2")]
        ZipCompression::Bzip2 => true,
        #[cfg(feature = "zstd")]
        ZipCompression::Zstd => true,
        #[cfg(feature = "xz")]
        ZipCompression::Lzma | ZipCompression::Xz => true,
        #[cfg(feature = "ppmd")]
        ZipCompression::Ppmd8 => true,
        _ => false,
    }
}

fn writer_error(kind: ErrorKind, context: &'static str) -> StreamError {
    StreamError::archive(ArchiveError::new(kind).with_context(context))
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Owned metadata descriptor used by inspections and plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryDescriptor {
    metadata: EntryMetadata,
}

impl EntryDescriptor {
    /// Full typed and extension-preserving entry metadata.
    #[must_use]
    pub const fn metadata(&self) -> &EntryMetadata {
        &self.metadata
    }
}

/// Bounded collected inspection of one immutable input.
#[derive(Debug)]
pub struct ArchiveInspection {
    digest: InputDigest,
    format: FormatId,
    archive_metadata: Option<ArchiveMetadata>,
    entries: Vec<EntryDescriptor>,
}

impl ArchiveInspection {
    /// Encoded input identity.
    #[must_use]
    pub const fn digest(&self) -> InputDigest {
        self.digest
    }

    /// Detected archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.format
    }

    /// Archive-level metadata, when present.
    #[must_use]
    pub const fn archive_metadata(&self) -> Option<&ArchiveMetadata> {
        self.archive_metadata.as_ref()
    }

    /// Entries in archive order.
    #[must_use]
    pub fn entries(&self) -> &[EntryDescriptor] {
        &self.entries
    }
}

/// Planned handling for one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlanDisposition {
    /// Apply through the capability filesystem adapter.
    Materialize,
    /// Do not materialize this structural entry.
    Skip,
    /// Policy or capability rejects this entry.
    Reject(RejectionReason),
}

/// One entry in an extraction plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedEntry {
    descriptor: EntryDescriptor,
    disposition: PlanDisposition,
    destination: Option<DestinationKey>,
    link_target: Option<DestinationKey>,
}

impl PlannedEntry {
    /// Entry descriptor.
    #[must_use]
    pub const fn descriptor(&self) -> &EntryDescriptor {
        &self.descriptor
    }

    /// Planned handling.
    #[must_use]
    pub const fn disposition(&self) -> PlanDisposition {
        self.disposition
    }

    pub(crate) const fn destination(&self) -> Option<&DestinationKey> {
        self.destination.as_ref()
    }

    pub(crate) const fn link_target(&self) -> Option<&DestinationKey> {
        self.link_target.as_ref()
    }
}

/// Non-serializable plan tied to one open session and encoded input digest.
#[derive(Debug)]
pub struct ExtractionPlan {
    session_id: u64,
    digest: InputDigest,
    format: FormatId,
    policy: Policy,
    entries: Vec<PlannedEntry>,
}

impl ExtractionPlan {
    /// Encoded input identity.
    #[must_use]
    pub const fn digest(&self) -> InputDigest {
        self.digest
    }

    /// Archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.format
    }

    /// Planned entries in archive order.
    #[must_use]
    pub fn entries(&self) -> &[PlannedEntry] {
        &self.entries
    }
}

/// Result of applying a session-bound plan.
#[derive(Debug)]
pub struct ApplyReport {
    digest: InputDigest,
    format: FormatId,
    extraction: ExtractionReport,
    findings: Vec<FilesystemFinding>,
}

impl ApplyReport {
    /// Applied encoded input identity.
    #[must_use]
    pub const fn digest(&self) -> InputDigest {
        self.digest
    }

    /// Applied archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.format
    }

    /// Per-entry materialization and rejection results.
    #[must_use]
    pub const fn extraction(&self) -> &ExtractionReport {
        &self.extraction
    }

    /// Typed filesystem capability, refusal, partial-application, and OS-error findings.
    #[must_use]
    pub fn filesystem_findings(&self) -> &[FilesystemFinding] {
        &self.findings
    }

    /// Whether any requested filesystem operation was not completely applied.
    #[must_use]
    pub fn has_filesystem_findings(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.kind() != crate::filesystem::FilesystemFindingKind::Applied)
    }

    /// Consumes this report and returns the low-level extraction report.
    ///
    /// Use [`Self::into_parts`] when filesystem fidelity evidence is also needed.
    #[must_use]
    pub fn into_extraction(self) -> ExtractionReport {
        self.extraction
    }

    /// Consumes the report into materialization outcomes and filesystem findings.
    #[must_use]
    pub fn into_parts(self) -> (ExtractionReport, Vec<FilesystemFinding>) {
        (self.extraction, self.findings)
    }
}

enum SessionReader<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    Sequential(Box<ArchiveReader<SpoolReader, F, C>>),
    Seek {
        reader: Box<SeekArchiveReader<SpoolReader>>,
        providers: ProviderSet<F, C>,
    },
    Volume {
        reader: Box<VolumeArchiveReader>,
        options: Box<crate::OpenOptions>,
    },
}

impl<F, C> fmt::Debug for SessionReader<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Sequential(_) => "SessionReader::Sequential(..)",
            Self::Seek { .. } => "SessionReader::Seek(..)",
            Self::Volume { .. } => "SessionReader::Volume(..)",
        })
    }
}

impl<F, C> SessionReader<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    fn open_with_options(
        mut snapshot: SpoolReader,
        options: &OpenOptions,
        providers: ProviderSet<F, C>,
    ) -> Result<Self, StreamError> {
        validate_prepared_options(options)?;
        if options.has_password_provider()
            && options.format().is_some_and(|format| {
                !matches!(
                    format,
                    FormatId::Zip | FormatId::SevenZip | FormatId::RarLegacy | FormatId::Rar5
                )
            })
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability).with_context(
                    "password supplied for an archive that is not ZIP, 7z, RAR 3.x/4.x, or RAR5",
                ),
            ));
        }
        if options.has_password_provider() && options.filter().is_some() {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability).with_context(
                    "password-protected archives cannot currently use an explicit outer filter",
                ),
            ));
        }

        let mut prefix = vec![0; FORMAT_PROBE_BYTES];
        let mut read = 0;
        while read < prefix.len() {
            let count = snapshot
                .read(&mut prefix[read..])
                .map_err(StreamError::io)?;
            if count == 0 {
                break;
            }
            read += count;
        }
        snapshot.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        let probed = FormatId::probe(&prefix[..read]);
        if options.has_password_provider()
            && options.format().is_none()
            && !matches!(
                probed,
                ProbeResult::Match(
                    FormatId::Zip | FormatId::SevenZip | FormatId::RarLegacy | FormatId::Rar5
                )
            )
        {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Capability).with_context(
                    "password supplied for an archive that is not ZIP, 7z, RAR 3.x/4.x, or RAR5",
                ),
            ));
        }

        let password_requires_seek = options.has_password_provider()
            && match options.format() {
                Some(format) => matches!(format, FormatId::Zip | FormatId::SevenZip),
                None => matches!(
                    probed,
                    ProbeResult::Match(FormatId::Zip | FormatId::SevenZip)
                ),
            };

        let explicit_seek = options.format().is_some_and(|format| {
            matches!(
                providers.format_capability(format),
                ProviderCapability::Available(capability)
                    if capability.requires_seek(libarchive_oxide_core::Direction::Read)
            )
        });
        let lha_sfx = options.format().is_none()
            && prefix[..read].starts_with(b"MZ")
            && matches!(
                providers.format_capability(FormatId::Lha),
                ProviderCapability::Available(capability)
                    if capability.requires_seek(libarchive_oxide_core::Direction::Read)
            );
        let detected_seek = options.format().is_none()
            && matches!(
                probed,
                ProbeResult::Match(format)
                    if matches!(
                        providers.format_capability(format),
                        ProviderCapability::Available(capability)
                            if capability.requires_seek(libarchive_oxide_core::Direction::Read)
                    )
            );
        if explicit_seek || detected_seek || lha_sfx || password_requires_seek {
            let reader = SeekArchiveReader::with_options(snapshot, options)?;
            return Ok(Self::Seek {
                reader: Box::new(reader),
                providers,
            });
        }

        let reader = ArchiveReader::with_providers_and_options(snapshot, options, providers)?;
        Ok(Self::Sequential(Box::new(reader)))
    }

    fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        match self {
            Self::Sequential(reader) => reader.next_event(),
            Self::Seek { reader, .. } => reader.next_event(),
            Self::Volume { reader, .. } => reader.next_event(),
        }
    }

    fn format(&self) -> Option<FormatId> {
        match self {
            Self::Sequential(reader) => reader.format(),
            Self::Seek { reader, .. } => Some(reader.format()),
            Self::Volume { reader, .. } => Some(reader.format()),
        }
    }

    fn into_parts(self) -> Result<(SpoolReader, ProviderSet<F, C>), StreamError> {
        match self {
            Self::Sequential(reader) => (*reader).into_parts().map_err(StreamError::archive),
            Self::Seek { reader, providers } => (*reader)
                .into_inner()
                .map(|reader| (reader, providers))
                .map_err(StreamError::archive),
            Self::Volume { .. } => Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("volume session has no spool snapshot"),
            )),
        }
    }
}
/// Open session over an immutable encoded input snapshot.
pub struct ArchiveSession<F = BuiltinFormatProviders, C = BuiltinCodecProviders>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    id: u64,
    digest: InputDigest,
    limits: Limits,
    reader: Option<SessionReader<F, C>>,
    open_options: Box<OpenOptions>,
    applied: bool,
}

impl<F, C> fmt::Debug for ArchiveSession<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArchiveSession")
            .field("id", &self.id)
            .field("digest", &self.digest)
            .field("limits", &self.limits)
            .field("reader", &self.reader)
            .field("open_options", &self.open_options)
            .field("applied", &self.applied)
            .finish()
    }
}

impl<F, C> ArchiveSession<F, C>
where
    F: StaticFormatProviders,
    C: StaticCodecProviders,
{
    /// Encoded input identity.
    #[must_use]
    pub const fn digest(&self) -> InputDigest {
        self.digest
    }

    /// Resource budgets used by this session.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// Detected format once enough events have been read.
    #[must_use]
    pub fn format(&self) -> Option<FormatId> {
        self.reader.as_ref().and_then(SessionReader::format)
    }

    /// Rewinds to a fresh event stream over the same immutable snapshot.
    pub fn rewind(&mut self) -> Result<(), StreamError> {
        let reader = self.reader.take().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("archive session reader is unavailable"),
            )
        })?;
        self.reader = Some(match reader {
            SessionReader::Volume { options, .. } => SessionReader::Volume {
                reader: Box::new(VolumeArchiveReader::with_options(&options)?),
                options,
            },
            reader => {
                let (mut snapshot, providers) = reader.into_parts()?;
                snapshot.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
                SessionReader::open_with_options(snapshot, &self.open_options, providers)?
            },
        });
        Ok(())
    }

    /// Produces one bounded event. Data is valid until the next mutable call.
    pub fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.reader
            .as_mut()
            .ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Protocol)
                        .with_context("archive session reader is unavailable"),
                )
            })?
            .next_event()
    }

    /// Collects metadata within the configured entry and metadata budgets.
    pub fn inspect(&mut self) -> Result<ArchiveInspection, StreamError> {
        self.rewind()?;
        let mut archive_metadata = None;
        let mut entries = Vec::new();
        let mut metadata_bytes = 0_usize;
        loop {
            match self.next_event()? {
                ReaderEvent::ArchiveMetadata(metadata) => {
                    metadata_bytes = checked_metadata_total(
                        metadata_bytes,
                        archive_metadata_cost(&metadata),
                        self.limits,
                    )?;
                    archive_metadata = Some(metadata);
                },
                ReaderEvent::Entry(metadata) => {
                    metadata_bytes = checked_metadata_total(
                        metadata_bytes,
                        entry_metadata_cost(&metadata),
                        self.limits,
                    )?;
                    entries.push(EntryDescriptor { metadata });
                },
                ReaderEvent::Data(_) | ReaderEvent::EndEntry => {},
                ReaderEvent::Done => {
                    let format = self.format().ok_or_else(|| {
                        StreamError::archive(
                            ArchiveError::new(ErrorKind::Protocol)
                                .with_context("archive completed without a detected format"),
                        )
                    })?;
                    return Ok(ArchiveInspection {
                        digest: self.digest,
                        format,
                        archive_metadata,
                        entries,
                    });
                },
            }
        }
    }

    /// Builds a non-serializable extraction plan for this session.
    pub fn plan(&mut self, policy: Policy) -> Result<ExtractionPlan, StreamError> {
        let inspection = self.inspect()?;
        let mut claimed = DestinationClaims::default();
        let mut committed = BTreeSet::new();
        let entries = inspection
            .entries
            .into_iter()
            .map(|descriptor| {
                let (disposition, destination, link_target) =
                    plan_entry(descriptor.metadata(), policy, &mut claimed, &mut committed);
                PlannedEntry {
                    descriptor,
                    disposition,
                    destination,
                    link_target,
                }
            })
            .collect();
        Ok(ExtractionPlan {
            session_id: self.id,
            digest: self.digest,
            format: inspection.format,
            policy,
            entries,
        })
    }

    /// Applies a plan exactly once through the built-in `cap-std` adapter.
    ///
    /// This source-compatible shortcut delegates to [`Self::apply_with_adapter`].
    #[allow(clippy::needless_pass_by_value)] // Ownership is the single-use plan contract.
    pub fn apply(&mut self, plan: ExtractionPlan, root: Dir) -> Result<ApplyReport, StreamError> {
        let mut adapter = CapStdFilesystemAdapter::new(root);
        self.apply_with_adapter(plan, &mut adapter)
    }

    /// Applies a plan exactly once through a capability-reporting adapter.
    ///
    /// Session identity and replay checks run before the adapter is touched.
    /// The shared driver retains path policy, resource limits, hardlink order,
    /// and archive parser state; the adapter only receives normalized relative
    /// operations.
    #[allow(clippy::needless_pass_by_value)] // Ownership is the single-use plan contract.
    pub fn apply_with_adapter<A: FilesystemAdapter>(
        &mut self,
        plan: ExtractionPlan,
        adapter: &mut A,
    ) -> Result<ApplyReport, StreamError> {
        let ExtractionPlan {
            session_id,
            digest,
            format,
            policy,
            entries,
        } = plan;
        if session_id != self.id || digest != self.digest {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("extraction plan belongs to a different archive session"),
            ));
        }
        if self.applied {
            return Err(StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("archive session has already applied a plan"),
            ));
        }
        // `ExtractionPlan` has no public constructor or mutable fields. Its
        // session identity is checked above, so these destinations are the
        // authoritative result of the one whole-archive preflight.
        self.applied = true;
        self.rewind()?;
        let applied = match self.reader.as_mut().ok_or_else(|| {
            StreamError::archive(
                ArchiveError::new(ErrorKind::Protocol)
                    .with_context("archive session reader is unavailable"),
            )
        })? {
            SessionReader::Sequential(reader) => {
                apply_registered_plan(reader, adapter, policy, self.limits, &entries)?
            },
            SessionReader::Seek { reader, .. } => {
                apply_seek_plan(reader, adapter, policy, self.limits, &entries)?
            },
            SessionReader::Volume { reader, .. } => {
                apply_volume_plan(reader, adapter, policy, self.limits, &entries)?
            },
        };
        Ok(ApplyReport {
            digest: self.digest,
            format,
            extraction: applied.extraction,
            findings: applied.findings,
        })
    }
}

fn digest_snapshot(snapshot: &mut SpoolReader) -> Result<InputDigest, StreamError> {
    snapshot.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; DIGEST_BUFFER_BYTES];
    loop {
        let read = snapshot.read(&mut buffer).map_err(StreamError::io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    snapshot.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
    Ok(InputDigest(hasher.finalize().into()))
}

fn digest_volume_set(volumes: &VolumeSet) -> Result<InputDigest, StreamError> {
    let sources = volumes.snapshot_sources().map_err(StreamError::io)?;
    let count = u64::try_from(sources.len()).map_err(|_| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Limit).with_context("volume count exceeds u64"),
        )
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"libarchive_oxide-volume-set-v1\0");
    hasher.update(count.to_le_bytes());
    let mut buffer = vec![0; DIGEST_BUFFER_BYTES];
    for (id, source) in sources {
        let identity = source.identity().clone();
        let length = source.len();
        crate::range_source::validate_read_at_snapshot(source.as_ref(), &identity, length)
            .map_err(StreamError::io)?;
        hasher.update(id.get().to_le_bytes());
        hasher.update(length.to_le_bytes());
        let mut offset = 0_u64;
        while offset < length {
            let remaining = length - offset;
            let count =
                usize::try_from(remaining.min(DIGEST_BUFFER_BYTES as u64)).map_err(|_| {
                    StreamError::archive(
                        ArchiveError::new(ErrorKind::Limit)
                            .with_context("volume digest chunk exceeds address space"),
                    )
                })?;
            source
                .read_exact_at(offset, &mut buffer[..count])
                .map_err(StreamError::io)?;
            hasher.update(&buffer[..count]);
            offset = offset.checked_add(count as u64).ok_or_else(|| {
                StreamError::archive(
                    ArchiveError::new(ErrorKind::Limit)
                        .with_context("volume digest offset overflow"),
                )
            })?;
        }
        crate::range_source::validate_read_at_snapshot(source.as_ref(), &identity, length)
            .map_err(StreamError::io)?;
    }
    Ok(InputDigest(hasher.finalize().into()))
}

fn checked_metadata_total(
    current: usize,
    added: usize,
    limits: Limits,
) -> Result<usize, StreamError> {
    let total = current.checked_add(added).ok_or_else(|| {
        StreamError::archive(
            ArchiveError::new(ErrorKind::Limit)
                .with_context("collected inspection metadata size overflowed"),
        )
    })?;
    if limits
        .metadata_bytes()
        .is_some_and(|maximum| total > maximum)
    {
        return Err(StreamError::archive(
            ArchiveError::new(ErrorKind::Limit)
                .with_context("collected inspection exceeds metadata budget"),
        ));
    }
    Ok(total)
}

fn entry_metadata_cost(metadata: &EntryMetadata) -> usize {
    let mut bytes = size_of::<EntryMetadata>()
        .saturating_add(metadata.path().as_bytes().len())
        .saturating_add(
            metadata
                .link_target()
                .map_or(0, |target| target.as_bytes().len()),
        )
        .saturating_add(metadata.owner().user.as_ref().map_or(0, Vec::len))
        .saturating_add(metadata.owner().group.as_ref().map_or(0, Vec::len))
        .saturating_add(metadata.comment().map_or(0, <[u8]>::len));
    for (name, value) in metadata.xattrs() {
        bytes = bytes.saturating_add(name.len()).saturating_add(value.len());
    }
    for acl in metadata.acl() {
        bytes = bytes.saturating_add(acl.len());
    }
    bytes = bytes.saturating_add(
        metadata
            .sparse_extents()
            .len()
            .saturating_mul(size_of::<libarchive_oxide_core::SparseExtent>()),
    );
    for extension in metadata.extensions() {
        bytes = bytes
            .saturating_add(extension.namespace().len())
            .saturating_add(extension.key().len())
            .saturating_add(extension.value().len());
    }
    bytes
}

fn archive_metadata_cost(metadata: &ArchiveMetadata) -> usize {
    let mut bytes = size_of::<ArchiveMetadata>()
        .saturating_add(
            metadata
                .volume_name()
                .map_or(0, |name| name.as_bytes().len()),
        )
        .saturating_add(metadata.comment().map_or(0, <[u8]>::len));
    for extension in metadata.extensions() {
        bytes = bytes
            .saturating_add(extension.namespace().len())
            .saturating_add(extension.key().len())
            .saturating_add(extension.value().len());
    }
    bytes
}

fn plan_entry(
    metadata: &EntryMetadata,
    policy: Policy,
    claimed: &mut DestinationClaims,
    committed: &mut BTreeSet<DestinationKey>,
) -> (
    PlanDisposition,
    Option<DestinationKey>,
    Option<DestinationKey>,
) {
    if metadata.extensions().iter().any(|extension| {
        extension.namespace() == "ar-thin" && extension.key() == b"external-reference"
    }) {
        return (
            PlanDisposition::Reject(RejectionReason::ExternalReference),
            None,
            None,
        );
    }
    if metadata.kind() == EntryKind::Dir && matches!(metadata.path().as_bytes(), b"." | b"./") {
        return (PlanDisposition::Skip, None, None);
    }
    let Some(destination) = DestinationKey::from_archive_path(metadata.path()) else {
        return (
            PlanDisposition::Reject(RejectionReason::UnsafePath),
            None,
            None,
        );
    };
    if !claimed.claim(&destination, metadata.kind()) {
        return (
            PlanDisposition::Reject(RejectionReason::DestinationCollision),
            Some(destination),
            None,
        );
    }
    let (disposition, link_target) = match metadata.kind() {
        EntryKind::File => {
            committed.insert(destination.clone());
            (PlanDisposition::Materialize, None)
        },
        EntryKind::Dir => (PlanDisposition::Materialize, None),
        EntryKind::Symlink if policy.symlinks() => {
            if let Some(target) = metadata
                .link_target()
                .and_then(DestinationKey::from_archive_path)
            {
                (PlanDisposition::Materialize, Some(target))
            } else {
                (
                    PlanDisposition::Reject(RejectionReason::UnsafeLinkTarget),
                    None,
                )
            }
        },
        EntryKind::Hardlink if policy.hardlinks() => {
            let Some(target) = metadata
                .link_target()
                .and_then(DestinationKey::from_archive_path)
            else {
                return (
                    PlanDisposition::Reject(RejectionReason::UnsafeLinkTarget),
                    Some(destination),
                    None,
                );
            };
            if let Some(committed_target) = committed.get(&target).cloned() {
                committed.insert(destination.clone());
                (PlanDisposition::Materialize, Some(committed_target))
            } else {
                (
                    PlanDisposition::Reject(RejectionReason::UnsafeLinkTarget),
                    None,
                )
            }
        },
        EntryKind::Char | EntryKind::Block | EntryKind::Fifo | EntryKind::Socket
            if policy.special_files() =>
        {
            if cfg!(any(target_os = "linux", target_os = "android")) {
                (PlanDisposition::Materialize, None)
            } else {
                (
                    PlanDisposition::Reject(RejectionReason::UnsupportedRestore),
                    None,
                )
            }
        },
        _ => (PlanDisposition::Reject(RejectionReason::EntryKind), None),
    };
    (disposition, Some(destination), link_target)
}
