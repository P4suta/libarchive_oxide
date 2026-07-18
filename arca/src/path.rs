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
            "" | "." => {}
            ".." => return None,
            _ if part.contains(':') => return None,
            _ => {
                out.push(part);
                pushed = true;
            }
        }
    }

    pushed.then_some(out)
}

#[cfg(test)]
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
}
