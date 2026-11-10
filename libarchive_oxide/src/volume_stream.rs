// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Common bounded reader for seek-native and multi-volume formats.

use std::fmt;
use std::sync::Arc;

use libarchive_oxide_core::{ArchiveError, Direction, ErrorKind, FormatId};

use crate::cab::{CabVolumeProvider, CabVolumeReader};
use crate::range_source::VolumeSet;
use crate::rar_legacy_volume::{RarLegacyVolumeProvider, RarLegacyVolumeReader};
use crate::rar5_volume::{Rar5VolumeProvider, Rar5VolumeReader};
use crate::registry::{RandomAccessArchiveDecoder, RandomAccessFormatProvider};
#[cfg(feature = "sevenz")]
use crate::sevenz_volume::{SevenZipVolumeProvider, SevenZipVolumeReader};
use crate::zip_volume::{ZipVolumeProvider, ZipVolumeReader};
use crate::{OpenOptions, ReaderEvent, StreamError};

/// Statically dispatched decoder for the built-in multi-volume formats.
///
/// This enum is public because it is the default type parameter of [`VolumeArchiveReader`].
/// Applications normally interact with the reader and do not need to name or match this type.
#[doc(hidden)]
#[derive(Debug)]
// Each concrete reader is boxed before entering the closed enum.
// Some codec feature combinations make a reader tens of KiB; keeping the sum type itself pointer-sized avoids stack spikes while preserving static dispatch.
pub enum BuiltinVolumeDecoder {
    /// Microsoft Cabinet set.
    Cab(Box<CabVolumeReader>),
    /// RAR 3.x/4.x volume set.
    RarLegacy(Box<RarLegacyVolumeReader>),
    /// RAR5 volume set.
    Rar5(Box<Rar5VolumeReader>),
    /// Multi-disk ZIP archive.
    Zip(Box<ZipVolumeReader>),
    /// Byte-split 7z archive.
    #[cfg(feature = "sevenz")]
    SevenZip(Box<SevenZipVolumeReader>),
}

impl RandomAccessArchiveDecoder for BuiltinVolumeDecoder {
    fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        match self {
            Self::Cab(reader) => reader.next_event(),
            Self::RarLegacy(reader) => reader.next_event(),
            Self::Rar5(reader) => reader.next_event(),
            Self::Zip(reader) => reader.next_event(),
            #[cfg(feature = "sevenz")]
            Self::SevenZip(reader) => reader.next_event(),
        }
    }

    fn skip_entry(&mut self) -> Result<(), StreamError> {
        match self {
            Self::Cab(reader) => reader.skip_entry(),
            Self::RarLegacy(reader) => reader.skip_entry(),
            Self::Rar5(reader) => reader.skip_entry(),
            Self::Zip(reader) => reader.skip_entry(),
            #[cfg(feature = "sevenz")]
            Self::SevenZip(reader) => reader.skip_entry(),
        }
    }
}

/// Archive reader over an application-owned [`VolumeSet`].
///
/// The default constructor uses a closed enum containing the built-in CAB,
/// ZIP, RAR, and 7z providers.
/// [`Self::with_provider`] returns a reader generic over an application or downstream provider's concrete decoder.
/// No adjacent filesystem or network discovery occurs in this handle-based API.
pub struct VolumeArchiveReader<D = BuiltinVolumeDecoder> {
    format: FormatId,
    inner: D,
}

impl<D> fmt::Debug for VolumeArchiveReader<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VolumeArchiveReader")
            .field("format", &self.format)
            .finish_non_exhaustive()
    }
}

impl VolumeArchiveReader<BuiltinVolumeDecoder> {
    /// Opens the supplied volume set using built-in providers and safe options.
    pub fn new(volumes: Arc<VolumeSet>) -> Result<Self, StreamError> {
        Self::with_options(&OpenOptions::new().with_volumes(volumes))
    }

    /// Opens the supplied volume set using built-in providers.
    pub fn with_options(options: &OpenOptions) -> Result<Self, StreamError> {
        let volumes = validated_volumes(options)?;
        let format = match options.format() {
            Some(format) => format,
            None => detect_builtin(&volumes, options)?.ok_or_else(|| {
                ArchiveError::new(ErrorKind::Unsupported)
                    .with_context("no built-in random-access provider matched the volume set")
            })?,
        };
        let inner = open_builtin(format, volumes, options)?;
        Ok(Self { format, inner })
    }

    /// Opens the volume set with one statically typed downstream provider.
    ///
    /// The returned reader is monomorphized over `P::Decoder`; neither provider nor decoder dispatch requires allocation or a vtable.
    pub fn with_provider<P>(
        options: &OpenOptions,
        provider: &P,
    ) -> Result<VolumeArchiveReader<P::Decoder>, StreamError>
    where
        P: RandomAccessFormatProvider,
    {
        let volumes = validated_volumes(options)?;
        validate_provider(provider)?;
        let format = provider.format();
        if let Some(requested) = options.format() {
            if requested != format {
                return Err(ArchiveError::new(ErrorKind::Unsupported)
                    .with_format(provider.name())
                    .with_context(format!(
                        "provider serves {format:?}, but OpenOptions requested {requested:?}"
                    ))
                    .into());
            }
        } else if !provider.probe(&volumes, options.limits())? {
            return Err(ArchiveError::new(ErrorKind::Unsupported)
                .with_format(provider.name())
                .with_context("random-access provider did not match the volume set")
                .into());
        }
        let inner = provider.open_with_options(volumes, options)?;
        Ok(VolumeArchiveReader { format, inner })
    }
}

impl<D> VolumeArchiveReader<D>
where
    D: RandomAccessArchiveDecoder,
{
    /// Detected or explicitly selected archive format.
    #[must_use]
    pub const fn format(&self) -> FormatId {
        self.format
    }

    /// Produces the next archive event.
    pub fn next_event(&mut self) -> Result<ReaderEvent<'_>, StreamError> {
        self.inner.next_event()
    }

    /// Skips the currently open entry payload.
    pub fn skip_entry(&mut self) -> Result<(), StreamError> {
        self.inner.skip_entry()
    }
}

fn validated_volumes(options: &OpenOptions) -> Result<Arc<VolumeSet>, StreamError> {
    if options.adjacent_volume_discovery() {
        return Err(ArchiveError::new(ErrorKind::Capability)
            .with_context("adjacent volume discovery is available only for path-based opens")
            .into());
    }
    if options.filter().is_some() {
        return Err(ArchiveError::new(ErrorKind::Capability)
            .with_context(
                "outer filters are not supported around random-access multi-volume archives",
            )
            .into());
    }
    let volumes = options.volumes().cloned().ok_or_else(|| {
        ArchiveError::new(ErrorKind::Capability)
            .with_context("VolumeArchiveReader requires OpenOptions containing VolumeSet")
    })?;
    validate_source_limits(options, &volumes)?;
    Ok(volumes)
}

fn validate_provider<P>(provider: &P) -> Result<(), StreamError>
where
    P: RandomAccessFormatProvider,
{
    let capabilities = provider.capabilities();
    if !capabilities.can_decode() || !capabilities.requires_seek(Direction::Read) {
        return Err(ArchiveError::new(ErrorKind::Capability)
            .with_format(provider.name())
            .with_context("random-access provider must advertise seek-native read capability")
            .into());
    }
    Ok(())
}

fn detect_builtin(
    volumes: &VolumeSet,
    options: &OpenOptions,
) -> Result<Option<FormatId>, StreamError> {
    let mut matched = None;
    record_match(&CabVolumeProvider::new(), volumes, options, &mut matched)?;
    record_match(
        &RarLegacyVolumeProvider::new(),
        volumes,
        options,
        &mut matched,
    )?;
    record_match(&Rar5VolumeProvider::new(), volumes, options, &mut matched)?;
    record_match(&ZipVolumeProvider::new(), volumes, options, &mut matched)?;
    #[cfg(feature = "sevenz")]
    record_match(
        &SevenZipVolumeProvider::new(),
        volumes,
        options,
        &mut matched,
    )?;
    Ok(matched)
}

fn record_match<P>(
    provider: &P,
    volumes: &VolumeSet,
    options: &OpenOptions,
    matched: &mut Option<FormatId>,
) -> Result<(), StreamError>
where
    P: RandomAccessFormatProvider,
{
    validate_provider(provider)?;
    if provider.probe(volumes, options.limits())? && matched.replace(provider.format()).is_some() {
        return Err(ArchiveError::new(ErrorKind::Protocol)
            .with_context("multiple built-in random-access format providers matched the source")
            .into());
    }
    Ok(())
}

fn open_builtin(
    format: FormatId,
    volumes: Arc<VolumeSet>,
    options: &OpenOptions,
) -> Result<BuiltinVolumeDecoder, StreamError> {
    if format == FormatId::Cab {
        return CabVolumeProvider::new()
            .open_with_options(volumes, options)
            .map(|reader| BuiltinVolumeDecoder::Cab(Box::new(reader)));
    }
    if format == FormatId::RarLegacy {
        return RarLegacyVolumeProvider::new()
            .open_with_options(volumes, options)
            .map(|reader| BuiltinVolumeDecoder::RarLegacy(Box::new(reader)));
    }
    if format == FormatId::Rar5 {
        return Rar5VolumeProvider::new()
            .open_with_options(volumes, options)
            .map(|reader| BuiltinVolumeDecoder::Rar5(Box::new(reader)));
    }
    if format == FormatId::Zip {
        return ZipVolumeProvider::new()
            .open_with_options(volumes, options)
            .map(|reader| BuiltinVolumeDecoder::Zip(Box::new(reader)));
    }
    #[cfg(feature = "sevenz")]
    if format == FormatId::SevenZip {
        return SevenZipVolumeProvider::new()
            .open_with_options(volumes, options)
            .map(|reader| BuiltinVolumeDecoder::SevenZip(Box::new(reader)));
    }
    Err(ArchiveError::new(ErrorKind::Unsupported)
        .with_context(format!(
            "no built-in random-access provider for format {format:?}"
        ))
        .into())
}

fn validate_source_limits(options: &OpenOptions, volumes: &VolumeSet) -> Result<(), StreamError> {
    if options.source_limits() != volumes.limits() {
        return Err(ArchiveError::new(ErrorKind::Capability)
            .with_context(
                "OpenOptions source limits must match the limits already enforced by VolumeSet",
            )
            .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    #[test]
    fn built_in_volume_dispatch_stays_pointer_sized() {
        assert!(
            size_of::<BuiltinVolumeDecoder>() <= 2 * size_of::<usize>(),
            "closed volume dispatch grew to {} bytes",
            size_of::<BuiltinVolumeDecoder>()
        );
    }
}
