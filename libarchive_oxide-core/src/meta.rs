//! Entry metadata. A shared type that upholds the read/write duality at the data layer.
//!
//! The same [`EntryMeta`] is **produced** by [`EntryReader`](crate::EntryReader) and
//! **consumed** by [`EntryWriter`](crate::EntryWriter). This way, read/write symmetry is
//! guaranteed not only by the traits but also in the shape of the data.
//!
//! To stay `no_std`, paths are held as raw byte sequences rather than `std::path` (names
//! inside an archive are not necessarily in the OS-native encoding to begin with). Wherever
//! possible we borrow from the input buffer ([`Cow`]) to avoid per-entry allocation (zero-copy).

use alloc::borrow::Cow;
use alloc::vec::Vec;

/// Entry kind. Replaces C's `mode & S_IFMT` with a typed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryKind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link (carries `link_target`).
    Symlink,
    /// Hard link (`link_target` points at the target).
    Hardlink,
    /// Character device.
    Char,
    /// Block device.
    Block,
    /// Named pipe (FIFO).
    Fifo,
    /// UNIX domain socket.
    Socket,
}

/// A timestamp in seconds and nanoseconds. `SystemTime` is not used, for `no_std`.
///
/// An offset from the epoch. `i64` to allow negative values (before 1970).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    /// Seconds since the UNIX epoch.
    pub secs: i64,
    /// Nanoseconds within the second (`0..1_000_000_000`).
    pub nanos: u32,
}

/// A single PAX record (key, value). Both borrow from the input when possible.
type PaxRecord<'a> = (Cow<'a, [u8]>, Cow<'a, [u8]>);

/// Additional key-values such as PAX extended headers. Borrows from the input where possible.
///
/// In P0 this is a naive association list. It preserves iteration order and assumes a small size.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PaxMap<'a> {
    entries: Vec<PaxRecord<'a>>,
}

impl<'a> PaxMap<'a> {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Returns the value for a key via linear search.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|(k, _)| k.as_ref() == key)
            .map(|(_, v)| v.as_ref())
    }

    /// Appends a key-value pair.
    pub fn insert(&mut self, key: Cow<'a, [u8]>, value: Cow<'a, [u8]>) {
        self.entries.push((key, value));
    }

    /// The number of pairs held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether it is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// A deep, lifetime-independent (`'static`) copy: every borrowed key/value is cloned into an
    /// owned one. Used when a value must outlive the input buffer it was parsed from.
    #[must_use]
    pub fn to_static(&self) -> PaxMap<'static> {
        PaxMap {
            entries: self
                .entries
                .iter()
                .map(|(k, v)| {
                    (
                        Cow::Owned(k.clone().into_owned()),
                        Cow::Owned(v.clone().into_owned()),
                    )
                })
                .collect(),
        }
    }
}

/// Entry metadata. The core of the duality produced by the reader and consumed by the writer.
///
/// The lifetime `'a` refers to the input buffer (on read) or the caller's borrow (on write),
/// expressing zero-copy in the type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMeta<'a> {
    /// Entry kind.
    pub kind: EntryKind,
    /// Path within the archive (raw bytes, borrowed if possible).
    pub path: Cow<'a, [u8]>,
    /// UNIX permission bits (`mode & 0o7777`).
    pub mode: u32,
    /// Owning user ID.
    pub uid: u64,
    /// Owning group ID.
    pub gid: u64,
    /// Modification time. `None` if absent from the format.
    pub mtime: Option<Timestamp>,
    /// Byte length of the file content (0 for non-files).
    pub size: u64,
    /// The target of a symbolic/hard link. `None` otherwise.
    pub link_target: Option<Cow<'a, [u8]>>,
    /// Extended attributes such as PAX.
    pub pax: PaxMap<'a>,
}

impl<'a> EntryMeta<'a> {
    /// Builds the minimal metadata for a given kind and path (other fields at their defaults).
    #[must_use]
    pub fn new(kind: EntryKind, path: Cow<'a, [u8]>) -> Self {
        Self {
            kind,
            path,
            mode: 0,
            uid: 0,
            gid: 0,
            mtime: None,
            size: 0,
            link_target: None,
            pax: PaxMap::new(),
        }
    }

    /// A deep, lifetime-independent (`'static`) copy of this metadata: every borrowed byte string
    /// is cloned into an owned one, so the result no longer borrows the input buffer.
    ///
    /// [`AnyReader`](crate::format::AnyReader) uses this to lift an inner entry's metadata out from
    /// under the transient `&mut self` borrow of the wrapped reader when re-homing.
    #[must_use]
    pub fn to_static(&self) -> EntryMeta<'static> {
        EntryMeta {
            kind: self.kind,
            path: Cow::Owned(self.path.clone().into_owned()),
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            mtime: self.mtime,
            size: self.size,
            link_target: self
                .link_target
                .as_ref()
                .map(|t| Cow::Owned(t.clone().into_owned())),
            pax: self.pax.to_static(),
        }
    }
}
