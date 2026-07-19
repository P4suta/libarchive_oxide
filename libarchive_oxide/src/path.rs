// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Safe conversion of archive entry paths into relative filesystem paths.
//!
//! Extracting untrusted archives is a classic path-traversal vector (`../../etc/passwd`,
//! absolute paths, Windows drive letters). [`sanitize`] rejects anything that could escape the
//! destination directory and yields only a safe relative path.

use std::path::PathBuf;

use libarchive_oxide_core::{ArchivePath, PathEncoding};

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
    if text.starts_with(['/', '\\']) {
        return None;
    }
    let mut out = PathBuf::new();
    let mut pushed = false;

    for part in text.split(['/', '\\']) {
        match part {
            "" | "." => {},
            ".." => return None,
            _ if part.contains(':') => return None,
            _ if is_reserved_device_name(part) => return None,
            _ => {
                out.push(part);
                pushed = true;
            },
        }
    }

    pushed.then_some(out)
}

/// Non-numbered Windows reserved DOS device names.
#[cfg(not(unix))]
const RESERVED_DEVICES: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];

/// Whether a path component is (or, with an extension, aliases) a Windows reserved DOS device
/// name. On Windows such names resolve to a device regardless of the parent directory, so a file
/// entry named `NUL` or `aux.h` would escape the destination or abort extraction.
#[cfg(not(unix))]
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
    // COM1-9 and LPT1-9 (COM0/LPT0 are not reserved).
    let is_numbered = |prefix: &str| {
        stem.len() == prefix.len() + 1
            && stem[..prefix.len()].eq_ignore_ascii_case(prefix)
            && matches!(stem.as_bytes()[prefix.len()], b'1'..=b'9')
    };
    is_numbered("COM") || is_numbered("LPT")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::sanitize;
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
            b"sub/NUL",
        ] {
            assert_eq!(sanitize(bad), None, "should reject {bad:?}");
        }
        // Similar-looking but NOT reserved names remain valid.
        assert!(sanitize(b"com0").is_some());
        assert!(sanitize(b"console").is_some());
        assert!(sanitize(b"nulls.txt").is_some());
    }

    #[cfg(unix)]
    #[test]
    fn preserves_non_utf8_unix_names() {
        use std::os::unix::ffi::OsStrExt;

        let path = sanitize(b"dir/\xff.bin").unwrap();
        assert_eq!(path.as_os_str().as_bytes(), b"dir/\xff.bin");
    }
}
