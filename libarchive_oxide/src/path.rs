//! Safe conversion of archive entry paths into relative filesystem paths.
//!
//! Extracting untrusted archives is a classic path-traversal vector (`../../etc/passwd`,
//! absolute paths, Windows drive letters). [`sanitize`] rejects anything that could escape the
//! destination directory and yields only a safe relative path.

use std::path::PathBuf;

/// Turns a raw archive path into a safe relative [`PathBuf`], or `None` if it is unsafe or empty.
///
/// Rejects: non-UTF-8 names, any `..` component, and components containing `:` (Windows drive or
/// alternate data stream). Leading slashes and `.` components are dropped, so absolute paths are
/// neutralized into relative ones. The result never escapes the directory it is joined onto.
#[must_use]
pub fn sanitize(raw: &[u8]) -> Option<PathBuf> {
    let text = std::str::from_utf8(raw).ok()?;
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
const RESERVED_DEVICES: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];

/// Whether a path component is (or, with an extension, aliases) a Windows reserved DOS device
/// name. On Windows such names resolve to a device regardless of the parent directory, so a file
/// entry named `NUL` or `aux.h` would escape the destination or abort extraction.
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
    fn neutralizes_absolute_paths() {
        assert_eq!(
            sanitize(b"/etc/passwd"),
            Some(Path::new("etc/passwd").to_path_buf())
        );
        assert_eq!(sanitize(b"./a/./b"), Some(Path::new("a/b").to_path_buf()));
    }

    #[test]
    fn rejects_traversal_and_drives() {
        assert_eq!(sanitize(b"../etc/passwd"), None);
        assert_eq!(sanitize(b"a/../../b"), None);
        assert_eq!(sanitize(b"C:/Windows"), None);
        assert_eq!(sanitize(b""), None);
        assert_eq!(sanitize(b"/"), None);
    }

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
}
