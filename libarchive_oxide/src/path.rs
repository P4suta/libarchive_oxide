// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Safe conversion of archive entry paths into relative filesystem paths.
//!
//! Extracting untrusted archives is a classic path-traversal vector (`../../etc/passwd`,
//! absolute paths, Windows drive letters). [`sanitize`] rejects anything that could escape the
//! destination directory and yields only a safe relative path.

#[cfg(not(target_os = "wasi"))]
use std::cmp::Ordering;
#[cfg(not(target_os = "wasi"))]
use std::collections::BTreeSet;
use std::path::PathBuf;
#[cfg(not(target_os = "wasi"))]
use std::path::{Component, Path};

#[cfg(not(target_os = "wasi"))]
use libarchive_oxide_core::EntryKind;
use libarchive_oxide_core::{ArchivePath, PathEncoding};
#[cfg(windows)]
use unicode_normalization::UnicodeNormalization;

/// A validated relative destination and its host-specific filesystem identity.
///
/// The retained path is the spelling passed to the filesystem. Equality and
/// ordering use the identity by which the host resolves that spelling: Unix
/// paths remain byte-for-byte distinct, while Windows components are
/// case-folded and NFC-normalized. This lets extraction planners reject two
/// archive entries that would address the same destination before publishing
/// either spelling.
#[derive(Debug, Clone)]
#[cfg(not(target_os = "wasi"))]
pub(crate) struct DestinationKey {
    path: PathBuf,
    #[cfg(windows)]
    identity: Vec<String>,
    #[cfg(not(windows))]
    identity: PathBuf,
}

#[cfg(not(target_os = "wasi"))]
impl DestinationKey {
    /// Validates an archive-native path and constructs its host destination
    /// identity without lossy transcoding.
    pub(crate) fn from_archive_path(path: &ArchivePath) -> Option<Self> {
        Self::from_relative_path(sanitize_archive_path(path)?)
    }

    /// Constructs an identity for an already relative host path.
    pub(crate) fn from_relative_path(path: PathBuf) -> Option<Self> {
        if path.as_os_str().is_empty()
            || !path
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            return None;
        }

        #[cfg(windows)]
        let identity = path
            .components()
            .map(|component| match component {
                Component::Normal(part) => {
                    let text = part.to_str()?;
                    windows_component_identity(text)
                },
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;

        #[cfg(not(windows))]
        let identity = path.clone();

        Some(Self { path, identity })
    }

    /// The validated relative spelling to pass to a capability filesystem.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn ancestors(&self) -> Vec<Self> {
        self.path
            .ancestors()
            .skip(1)
            .filter(|ancestor| !ancestor.as_os_str().is_empty())
            .filter_map(|ancestor| Self::from_relative_path(ancestor.to_path_buf()))
            .collect()
    }
}

#[cfg(not(target_os = "wasi"))]
impl PartialEq for DestinationKey {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

#[cfg(not(target_os = "wasi"))]
impl Eq for DestinationKey {}

#[cfg(not(target_os = "wasi"))]
impl PartialOrd for DestinationKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(not(target_os = "wasi"))]
impl Ord for DestinationKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.identity.cmp(&other.identity)
    }
}

/// Session-local destination topology used by every extraction planner.
///
/// Besides exact aliases, this rejects a non-directory used as an ancestor and
/// a later non-directory that would replace an implicit directory established
/// by an earlier descendant.
#[derive(Debug, Default)]
#[cfg(not(target_os = "wasi"))]
pub(crate) struct DestinationClaims {
    claimed: BTreeSet<DestinationKey>,
    directory_prefixes: BTreeSet<DestinationKey>,
    non_directories: BTreeSet<DestinationKey>,
}

#[cfg(not(target_os = "wasi"))]
impl DestinationClaims {
    /// Claims one destination if it does not conflict with an earlier host
    /// identity or with the already established directory topology.
    pub(crate) fn claim(&mut self, destination: &DestinationKey, kind: EntryKind) -> bool {
        let ancestors = destination.ancestors();
        if self.claimed.contains(destination)
            || ancestors
                .iter()
                .any(|ancestor| self.non_directories.contains(ancestor))
            || (kind != EntryKind::Dir && self.directory_prefixes.contains(destination))
        {
            return false;
        }

        self.claimed.insert(destination.clone());
        for ancestor in ancestors {
            self.directory_prefixes.insert(ancestor);
        }
        if kind != EntryKind::Dir {
            self.non_directories.insert(destination.clone());
        }
        true
    }
}

/// Turns a raw archive path into a safe relative [`PathBuf`], or `None` if it is unsafe or empty.
///
/// Rejects absolute paths and `..` components on every platform. Unix preserves
/// non-UTF-8 bytes. Windows additionally rejects unrepresentable bytes, UNC
/// paths, device names, drive prefixes, and alternate-data-stream syntax.
#[must_use]
pub fn sanitize(raw: &[u8]) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        if raw.starts_with(b"/") || raw.contains(&0) {
            return None;
        }
        let mut output = PathBuf::new();
        let mut pushed = false;
        for component in raw.split(|byte| *byte == b'/') {
            match component {
                b"" | b"." => {},
                b".." => return None,
                _ => {
                    output.push(OsString::from_vec(component.to_vec()));
                    pushed = true;
                },
            }
        }
        pushed.then_some(output)
    }

    #[cfg(not(unix))]
    sanitize_text(std::str::from_utf8(raw).ok()?)
}

/// Converts an archive-native path to a safe host path without lossy
/// transcoding.
#[must_use]
pub fn sanitize_archive_path(path: &ArchivePath) -> Option<PathBuf> {
    match path.encoding() {
        PathEncoding::Bytes | PathEncoding::Utf8 => sanitize(path.as_bytes()),
        PathEncoding::Utf16Le => {
            let mut chunks = path.as_bytes().chunks_exact(2);
            let units: Vec<u16> = chunks
                .by_ref()
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                .collect();
            if !chunks.remainder().is_empty() {
                return None;
            }
            let text = String::from_utf16(&units).ok()?;
            #[cfg(unix)]
            {
                sanitize(text.as_bytes())
            }
            #[cfg(not(unix))]
            {
                sanitize_text(&text)
            }
        },
        _ => None,
    }
}

#[cfg(not(unix))]
fn sanitize_text(text: &str) -> Option<PathBuf> {
    if text.starts_with(['/', '\\']) || text.contains('\0') {
        return None;
    }
    let mut out = PathBuf::new();
    let mut pushed = false;

    for part in text.split(['/', '\\']) {
        match part {
            "" | "." => {},
            ".." => return None,
            #[cfg(windows)]
            _ if windows_component_identity(part).is_none() => return None,
            _ => {
                out.push(part);
                pushed = true;
            },
        }
    }

    pushed.then_some(out)
}

/// Non-numbered Windows reserved DOS device names.
#[cfg(windows)]
const RESERVED_DEVICES: [&str; 7] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"];

/// Returns the Windows destination identity for one component.
///
/// Win32 strips trailing ASCII dots/spaces and interprets `:` as alternate
/// data-stream syntax. Accepting either would make the displayed archive name
/// differ from the object actually opened, so extraction rejects them rather
/// than silently rewriting the path. The remaining identity is canonical
/// Unicode plus an invariant, conservative Unicode uppercase fold.
#[cfg(windows)]
fn windows_component_identity(part: &str) -> Option<String> {
    if part.is_empty()
        || part.ends_with(['.', ' '])
        || part.chars().any(|character| {
            character <= '\u{1f}' || matches!(character, '<' | '>' | '"' | ':' | '|' | '?' | '*')
        })
        || is_reserved_device_name(part)
    {
        return None;
    }

    let normalized = part.nfc().collect::<String>();
    Some(
        normalized
            .chars()
            .flat_map(char::to_uppercase)
            .collect::<String>()
            .nfc()
            .collect(),
    )
}

/// Whether a path component is (or, with an extension, aliases) a Windows reserved DOS device
/// name. On Windows such names resolve to a device regardless of the parent directory, so a file
/// entry named `NUL` or `aux.h` would escape the destination or abort extraction.
#[cfg(windows)]
fn is_reserved_device_name(part: &str) -> bool {
    // The device name is matched against the stem, ignoring any extension and trailing dots/spaces.
    let stem = part
        .split('.')
        .next()
        .unwrap_or(part)
        .trim_end_matches([' ', '.']);
    if RESERVED_DEVICES
        .iter()
        .any(|r| stem.eq_ignore_ascii_case(r))
    {
        return true;
    }
    // COM1-9 and LPT1-9 (COM0/LPT0 are not reserved). Win32 also treats the
    // superscript digits ¹, ², and ³ as the corresponding DOS device suffix.
    let is_numbered = |prefix: &str| {
        let Some(suffix) = stem.get(prefix.len()..) else {
            return false;
        };
        stem.get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
            && (matches!(suffix.as_bytes(), [b'1'..=b'9'])
                || matches!(suffix, "\u{00b9}" | "\u{00b2}" | "\u{00b3}"))
    };
    is_numbered("COM") || is_numbered("LPT")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::sanitize;
    #[cfg(not(target_os = "wasi"))]
    use super::{DestinationClaims, DestinationKey};
    #[cfg(not(target_os = "wasi"))]
    use libarchive_oxide_core::{ArchivePath, EntryKind};
    use std::path::Path;

    #[test]
    fn accepts_normal_relative_paths() {
        assert_eq!(
            sanitize(b"usr/bin/app"),
            Some(Path::new("usr/bin/app").to_path_buf())
        );
    }

    #[test]
    fn rejects_absolute_paths() {
        assert_eq!(sanitize(b"/etc/passwd"), None);
        #[cfg(windows)]
        assert_eq!(sanitize(br"\server\share"), None);
        assert_eq!(sanitize(b"./a/./b"), Some(Path::new("a/b").to_path_buf()));
    }

    #[test]
    fn rejects_traversal_and_drives() {
        assert_eq!(sanitize(b"../etc/passwd"), None);
        assert_eq!(sanitize(b"a/../../b"), None);
        #[cfg(windows)]
        assert_eq!(sanitize(b"C:/Windows"), None);
        assert_eq!(sanitize(b""), None);
        assert_eq!(sanitize(b"/"), None);
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_reserved_device_names() {
        for bad in [
            &b"NUL"[..],
            b"nul",
            b"CON",
            b"aux.h",
            b"COM1",
            b"lpt9.txt",
            "COM\u{00b9}.log".as_bytes(),
            b"CONIN$",
            b"sub/NUL",
        ] {
            assert_eq!(sanitize(bad), None, "should reject {bad:?}");
        }
        // Similar-looking but NOT reserved names remain valid.
        assert!(sanitize(b"com0").is_some());
        assert!(sanitize(b"console").is_some());
        assert!(sanitize(b"nulls.txt").is_some());
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_trailing_aliases_ads_and_forbidden_characters() {
        for bad in [
            &b"name."[..],
            b"name ",
            b"nested/name. ",
            b"name:stream",
            b"name?",
            b"nested/a|b",
        ] {
            assert_eq!(sanitize(bad), None, "should reject {bad:?}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn destination_identity_collapses_case_and_canonical_unicode() {
        let lower = DestinationKey::from_archive_path(&ArchivePath::from_utf8("folder/file"))
            .expect("lowercase destination");
        let upper = DestinationKey::from_archive_path(&ArchivePath::from_utf8("FOLDER/FILE"))
            .expect("uppercase destination");
        assert_eq!(lower, upper);

        let nfc = DestinationKey::from_archive_path(&ArchivePath::from_utf8("caf\u{00e9}.txt"))
            .expect("NFC destination");
        let nfd = DestinationKey::from_archive_path(&ArchivePath::from_utf8("cafe\u{0301}.txt"))
            .expect("NFD destination");
        assert_eq!(nfc, nfd);
    }

    #[cfg(unix)]
    #[test]
    fn destination_identity_preserves_unix_case_and_bytes() {
        let lower = DestinationKey::from_archive_path(&ArchivePath::from_bytes(b"file"))
            .expect("lowercase destination");
        let upper = DestinationKey::from_archive_path(&ArchivePath::from_bytes(b"FILE"))
            .expect("uppercase destination");
        assert_ne!(lower, upper);

        let composed =
            DestinationKey::from_archive_path(&ArchivePath::from_utf8("caf\u{00e9}.txt"))
                .expect("composed destination");
        let decomposed =
            DestinationKey::from_archive_path(&ArchivePath::from_utf8("cafe\u{0301}.txt"))
                .expect("decomposed destination");
        assert_ne!(composed, decomposed);
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn destination_claims_reject_non_directory_topology_conflicts() {
        let file = DestinationKey::from_archive_path(&ArchivePath::from_utf8("node"))
            .expect("file destination");
        let child = DestinationKey::from_archive_path(&ArchivePath::from_utf8("node/child"))
            .expect("child destination");
        let mut claims = DestinationClaims::default();
        assert!(claims.claim(&file, EntryKind::File));
        assert!(!claims.claim(&child, EntryKind::File));

        let parent = DestinationKey::from_archive_path(&ArchivePath::from_utf8("tree"))
            .expect("parent destination");
        let descendant = DestinationKey::from_archive_path(&ArchivePath::from_utf8("tree/leaf"))
            .expect("descendant destination");
        let mut reverse = DestinationClaims::default();
        assert!(reverse.claim(&descendant, EntryKind::File));
        assert!(!reverse.claim(&parent, EntryKind::File));

        let mut directories = DestinationClaims::default();
        assert!(directories.claim(&parent, EntryKind::Dir));
        assert!(directories.claim(&descendant, EntryKind::File));
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_unix_names() {
        use std::os::unix::ffi::OsStrExt;

        let path = sanitize(b"dir/\xff.bin").unwrap();
        assert_eq!(path.as_os_str().as_bytes(), b"dir/\xff.bin");
    }
}
