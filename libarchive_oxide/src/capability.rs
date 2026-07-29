// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build-aware views over the canonical core capability ledger.

use libarchive_oxide_core::{
    ArchiveError, CapabilityRecord, CapabilitySubject, DirectionSet, ErrorKind,
};

/// Codec backend represented by the capability matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Backend {
    /// Safe-Rust portable implementation.
    Portable,
    /// Platform-native implementation.
    Native,
}

/// Runtime preference used when more than one codec backend is compiled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BackendPreference {
    /// Prefer native when compiled, otherwise use portable.
    #[default]
    Auto,
    /// Require a portable implementation.
    Portable,
    /// Require a native implementation.
    Native,
}

impl BackendPreference {
    /// Resolves this preference against the backends compiled into the crate.
    pub fn resolve(self) -> Result<Backend, ArchiveError> {
        match self {
            Self::Auto | Self::Native if cfg!(feature = "native-codecs") => Ok(Backend::Native),
            Self::Auto => Ok(Backend::Portable),
            Self::Portable
                if cfg!(feature = "portable-codecs") || !cfg!(feature = "native-codecs") =>
            {
                Ok(Backend::Portable)
            },
            Self::Portable => Err(backend_disabled("portable")),
            Self::Native => Err(backend_disabled("native")),
        }
    }
}

/// Build-specific state of one ledger record and backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CapabilityState {
    /// This build can perform the contained directions.
    Available(DirectionSet),
    /// The ledger knows the capability, but this build lacks a required feature
    /// or backend.
    Disabled,
    /// The method is recognized but deliberately has no implementation yet.
    Unsupported,
}

/// Resolves one canonical record against the features compiled into this crate.
#[must_use]
pub fn capability_state(record: CapabilityRecord, backend: Backend) -> CapabilityState {
    if !requirements_enabled(record.requirements()) || !backend_enabled(record, backend) {
        return CapabilityState::Disabled;
    }
    let directions = match backend {
        Backend::Portable => record.portable(),
        Backend::Native => record.native(),
    };
    if directions.is_empty() {
        CapabilityState::Unsupported
    } else {
        CapabilityState::Available(directions)
    }
}

/// Whether every named Cargo feature required by a ledger record is enabled.
#[must_use]
pub fn requirements_enabled(requirements: &[&str]) -> bool {
    requirements
        .iter()
        .all(|requirement| requirement_enabled(requirement))
}

fn requirement_enabled(requirement: &str) -> bool {
    if requirement == "gzip" {
        return cfg!(feature = "gzip");
    }
    if requirement == "bzip2" {
        return cfg!(feature = "bzip2");
    }
    if requirement == "zstd" {
        return cfg!(feature = "zstd");
    }
    if requirement == "xz" {
        return cfg!(feature = "xz");
    }
    if requirement == "lz4" {
        return cfg!(feature = "lz4");
    }
    if requirement == "compress" {
        return cfg!(feature = "compress");
    }
    if requirement == "lzip" {
        return cfg!(feature = "lzip");
    }
    if requirement == "sevenz" {
        return cfg!(feature = "sevenz");
    }
    if requirement == "aes" {
        return cfg!(feature = "aes");
    }
    if requirement == "cab-lzx" {
        return cfg!(feature = "cab-lzx");
    }
    if requirement == "cab-quantum" {
        return cfg!(feature = "cab-quantum");
    }
    false
}

fn backend_enabled(record: CapabilityRecord, backend: Backend) -> bool {
    if matches!(record.subject(), CapabilitySubject::Format(_)) {
        return true;
    }
    if matches!(
        record.subject(),
        CapabilitySubject::Filter(libarchive_oxide_core::FilterId::Lzip)
    ) && matches!(backend, Backend::Portable)
    {
        return cfg!(feature = "lzip");
    }
    match backend {
        Backend::Portable => cfg!(feature = "portable-codecs") || !cfg!(feature = "native-codecs"),
        Backend::Native => cfg!(feature = "native-codecs"),
    }
}

fn backend_disabled(backend: &'static str) -> ArchiveError {
    ArchiveError::new(ErrorKind::Capability)
        .with_format(backend)
        .with_context("requested codec backend is not compiled into this build")
}

#[cfg(test)]
mod tests {
    use libarchive_oxide_core::{CAPABILITY_LEDGER, Direction};

    use super::*;

    #[test]
    fn cab_lzx_tracks_its_additive_feature() {
        let record = CAPABILITY_LEDGER
            .iter()
            .find(|record| record.key() == "method.cab.lzx")
            .expect("ledger record");
        assert_eq!(
            matches!(
                capability_state(*record, Backend::Portable),
                CapabilityState::Available(DirectionSet::READ)
            ),
            cfg!(feature = "cab-lzx")
                && (cfg!(feature = "portable-codecs") || !cfg!(feature = "native-codecs"))
        );
        assert_eq!(
            matches!(
                capability_state(*record, Backend::Native),
                CapabilityState::Available(DirectionSet::READ)
            ),
            cfg!(feature = "cab-lzx") && cfg!(feature = "native-codecs")
        );
    }

    #[test]
    fn cab_quantum_tracks_its_additive_feature() {
        let record = CAPABILITY_LEDGER
            .iter()
            .find(|record| record.key() == "method.cab.quantum")
            .expect("ledger record");
        assert_eq!(
            matches!(
                capability_state(*record, Backend::Portable),
                CapabilityState::Available(DirectionSet::READ)
            ),
            cfg!(feature = "cab-quantum")
                && (cfg!(feature = "portable-codecs") || !cfg!(feature = "native-codecs"))
        );
        assert_eq!(
            matches!(
                capability_state(*record, Backend::Native),
                CapabilityState::Available(DirectionSet::READ)
            ),
            cfg!(feature = "cab-quantum") && cfg!(feature = "native-codecs")
        );
    }

    #[test]
    fn zip_store_is_available_for_read_and_write_on_the_selected_backend() {
        let record = CAPABILITY_LEDGER
            .iter()
            .find(|record| record.key() == "method.zip.store")
            .expect("ledger record");
        let selected = BackendPreference::Auto
            .resolve()
            .expect("the build always has a default backend");
        let CapabilityState::Available(directions) = capability_state(*record, selected) else {
            panic!("ZIP Store must be available on the selected backend");
        };
        assert!(directions.contains(Direction::Read));
        assert!(directions.contains(Direction::Write));
    }
}
