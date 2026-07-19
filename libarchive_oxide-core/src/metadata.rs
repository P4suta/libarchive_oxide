// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Extensible archive and entry metadata.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::meta::{EntryKind, Timestamp};

/// Encoding of an archive-native path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathEncoding {
    /// An uninterpreted byte sequence, as used by tar and Unix cpio.
    Bytes,
    /// Valid UTF-8.
    Utf8,
    /// UTF-16 little-endian code units stored as bytes.
    Utf16Le,
}

/// An archive path preserving its native representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ArchivePath {
    raw: Vec<u8>,
    encoding: PathEncoding,
}

impl ArchivePath {
    /// Constructs an uninterpreted byte path.
    #[must_use]
    pub fn from_bytes(raw: impl Into<Vec<u8>>) -> Self {
        Self {
            raw: raw.into(),
            encoding: PathEncoding::Bytes,
        }
    }

    /// Constructs a UTF-8 path.
    #[must_use]
    pub fn from_utf8(path: impl Into<String>) -> Self {
        Self {
            raw: path.into().into_bytes(),
            encoding: PathEncoding::Utf8,
        }
    }

    /// Constructs a path from archive-native bytes and an encoding tag.
    #[must_use]
    pub fn from_encoded(raw: impl Into<Vec<u8>>, encoding: PathEncoding) -> Self {
        Self {
            raw: raw.into(),
            encoding,
        }
    }

    /// Archive-native bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Archive-native encoding.
    #[must_use]
    pub const fn encoding(&self) -> PathEncoding {
        self.encoding
    }

    /// A lossy string intended only for diagnostics and display.
    #[must_use]
    pub fn display_lossy(&self) -> String {
        match self.encoding {
            PathEncoding::Utf16Le => {
                let units = self
                    .raw
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]));
                char::decode_utf16(units)
                    .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
                    .collect()
            },
            PathEncoding::Bytes | PathEncoding::Utf8 => {
                String::from_utf8_lossy(&self.raw).to_string()
            },
        }
    }
}

/// Owner identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Owner {
    /// Numeric user id.
    pub uid: Option<u64>,
    /// Numeric group id.
    pub gid: Option<u64>,
    /// User name in archive encoding.
    pub user: Option<Vec<u8>>,
    /// Group name in archive encoding.
    pub group: Option<Vec<u8>>,
}

/// File timestamps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EntryTimes {
    /// Modification time.
    pub modified: Option<Timestamp>,
    /// Access time.
    pub accessed: Option<Timestamp>,
    /// Metadata-change time.
    pub changed: Option<Timestamp>,
    /// Creation/birth time.
    pub created: Option<Timestamp>,
}

/// Device numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Device {
    /// Major device number.
    pub major: u64,
    /// Minor device number.
    pub minor: u64,
}

/// One sparse-file data extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseExtent {
    /// Logical byte offset.
    pub offset: u64,
    /// Number of stored bytes.
    pub length: u64,
}

/// A namespaced raw extension retained for round-tripping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    namespace: String,
    key: Vec<u8>,
    value: Vec<u8>,
}

impl Extension {
    /// Creates an extension.
    #[must_use]
    pub fn new(
        namespace: impl Into<String>,
        key: impl Into<Vec<u8>>,
        value: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            key: key.into(),
            value: value.into(),
        }
    }

    /// Namespace such as `pax`, `zip-extra`, or `rock-ridge`.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Extension key/id bytes.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Raw extension value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Metadata for one archive entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMetadata {
    kind: EntryKind,
    path: ArchivePath,
    size: Option<u64>,
    link_target: Option<ArchivePath>,
    mode: Option<u32>,
    owner: Owner,
    times: EntryTimes,
    inode: Option<u64>,
    links: Option<u64>,
    device: Option<Device>,
    referenced_device: Option<Device>,
    sparse: Vec<SparseExtent>,
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    acl: Vec<Vec<u8>>,
    file_flags: u64,
    checksum: Option<Vec<u8>>,
    encrypted: bool,
    comment: Option<Vec<u8>>,
    extensions: Vec<Extension>,
}

impl EntryMetadata {
    /// Starts a builder with the required kind and path.
    #[must_use]
    pub fn builder(kind: EntryKind, path: ArchivePath) -> EntryMetadataBuilder {
        EntryMetadataBuilder {
            inner: Self {
                kind,
                path,
                size: None,
                link_target: None,
                mode: None,
                owner: Owner::default(),
                times: EntryTimes::default(),
                inode: None,
                links: None,
                device: None,
                referenced_device: None,
                sparse: Vec::new(),
                xattrs: Vec::new(),
                acl: Vec::new(),
                file_flags: 0,
                checksum: None,
                encrypted: false,
                comment: None,
                extensions: Vec::new(),
            },
        }
    }

    /// Entry kind.
    #[must_use]
    pub const fn kind(&self) -> EntryKind {
        self.kind
    }

    /// Entry path.
    #[must_use]
    pub const fn path(&self) -> &ArchivePath {
        &self.path
    }

    /// Declared size, or `None` when not known before streaming.
    #[must_use]
    pub const fn size(&self) -> Option<u64> {
        self.size
    }

    /// Link target.
    #[must_use]
    pub const fn link_target(&self) -> Option<&ArchivePath> {
        self.link_target.as_ref()
    }

    /// Unix permission/mode bits when known.
    #[must_use]
    pub const fn mode(&self) -> Option<u32> {
        self.mode
    }

    /// Owner identity.
    #[must_use]
    pub const fn owner(&self) -> &Owner {
        &self.owner
    }

    /// Timestamps.
    #[must_use]
    pub const fn times(&self) -> EntryTimes {
        self.times
    }

    /// Archive inode number.
    #[must_use]
    pub const fn inode(&self) -> Option<u64> {
        self.inode
    }

    /// Link count.
    #[must_use]
    pub const fn links(&self) -> Option<u64> {
        self.links
    }

    /// Filesystem device containing the entry.
    #[must_use]
    pub const fn device(&self) -> Option<Device> {
        self.device
    }

    /// Referenced device for character/block entries.
    #[must_use]
    pub const fn referenced_device(&self) -> Option<Device> {
        self.referenced_device
    }

    /// Sparse extents.
    #[must_use]
    pub fn sparse_extents(&self) -> &[SparseExtent] {
        &self.sparse
    }

    /// Extended attributes.
    #[must_use]
    pub fn xattrs(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.xattrs
    }

    /// Raw ACL records.
    #[must_use]
    pub fn acl(&self) -> &[Vec<u8>] {
        &self.acl
    }

    /// Filesystem flags.
    #[must_use]
    pub const fn file_flags(&self) -> u64 {
        self.file_flags
    }

    /// Archive checksum bytes, if present.
    #[must_use]
    pub fn checksum(&self) -> Option<&[u8]> {
        self.checksum.as_deref()
    }

    /// Whether the payload is encrypted.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    /// File comment.
    #[must_use]
    pub fn comment(&self) -> Option<&[u8]> {
        self.comment.as_deref()
    }

    /// Preserved format extensions.
    #[must_use]
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// Converts this value back into a builder without losing typed or raw
    /// metadata.
    ///
    /// Format readers use this after a bounded second pass discovers metadata
    /// that is stored in an entry payload, such as a ZIP symbolic-link target.
    #[must_use]
    pub fn into_builder(self) -> EntryMetadataBuilder {
        EntryMetadataBuilder { inner: self }
    }
}

/// Builder for [`EntryMetadata`].
#[derive(Debug)]
pub struct EntryMetadataBuilder {
    inner: EntryMetadata,
}

impl EntryMetadataBuilder {
    /// Replaces the entry kind while preserving every other field.
    #[must_use]
    pub const fn kind(mut self, kind: EntryKind) -> Self {
        self.inner.kind = kind;
        self
    }

    /// Replaces the archive path while preserving every other field.
    #[must_use]
    pub fn path(mut self, path: ArchivePath) -> Self {
        self.inner.path = path;
        self
    }

    /// Sets declared size.
    #[must_use]
    pub const fn size(mut self, size: Option<u64>) -> Self {
        self.inner.size = size;
        self
    }

    /// Sets mode bits.
    #[must_use]
    pub const fn mode(mut self, mode: Option<u32>) -> Self {
        self.inner.mode = mode;
        self
    }

    /// Sets owner identity.
    #[must_use]
    pub fn owner(mut self, owner: Owner) -> Self {
        self.inner.owner = owner;
        self
    }

    /// Sets timestamps.
    #[must_use]
    pub const fn times(mut self, times: EntryTimes) -> Self {
        self.inner.times = times;
        self
    }

    /// Sets link target.
    #[must_use]
    pub fn link_target(mut self, target: Option<ArchivePath>) -> Self {
        self.inner.link_target = target;
        self
    }

    /// Sets archive inode and link count.
    #[must_use]
    pub const fn inode_and_links(mut self, inode: Option<u64>, links: Option<u64>) -> Self {
        self.inner.inode = inode;
        self.inner.links = links;
        self
    }

    /// Sets filesystem and referenced device numbers.
    #[must_use]
    pub const fn devices(
        mut self,
        device: Option<Device>,
        referenced_device: Option<Device>,
    ) -> Self {
        self.inner.device = device;
        self.inner.referenced_device = referenced_device;
        self
    }

    /// Adds one sparse data extent.
    #[must_use]
    pub fn sparse_extent(mut self, extent: SparseExtent) -> Self {
        self.inner.sparse.push(extent);
        self
    }

    /// Adds one extended attribute.
    #[must_use]
    pub fn xattr(mut self, name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        self.inner.xattrs.push((name.into(), value.into()));
        self
    }

    /// Adds one raw ACL record.
    #[must_use]
    pub fn acl(mut self, value: impl Into<Vec<u8>>) -> Self {
        self.inner.acl.push(value.into());
        self
    }

    /// Sets filesystem flags.
    #[must_use]
    pub const fn file_flags(mut self, flags: u64) -> Self {
        self.inner.file_flags = flags;
        self
    }

    /// Sets checksum bytes.
    #[must_use]
    pub fn checksum(mut self, checksum: Option<Vec<u8>>) -> Self {
        self.inner.checksum = checksum;
        self
    }

    /// Sets encryption state.
    #[must_use]
    pub const fn encrypted(mut self, encrypted: bool) -> Self {
        self.inner.encrypted = encrypted;
        self
    }

    /// Sets a file comment.
    #[must_use]
    pub fn comment(mut self, comment: Option<Vec<u8>>) -> Self {
        self.inner.comment = comment;
        self
    }

    /// Adds a preserved format extension.
    #[must_use]
    pub fn extension(mut self, extension: Extension) -> Self {
        self.inner.extensions.push(extension);
        self
    }

    /// Completes the metadata.
    #[must_use]
    pub fn build(self) -> EntryMetadata {
        self.inner
    }
}

/// Archive-level metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArchiveMetadata {
    volume_name: Option<ArchivePath>,
    comment: Option<Vec<u8>>,
    extensions: Vec<Extension>,
}

impl ArchiveMetadata {
    /// Empty archive metadata.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            volume_name: None,
            comment: None,
            extensions: Vec::new(),
        }
    }

    /// Volume name.
    #[must_use]
    pub const fn volume_name(&self) -> Option<&ArchivePath> {
        self.volume_name.as_ref()
    }

    /// Archive comment.
    #[must_use]
    pub fn comment(&self) -> Option<&[u8]> {
        self.comment.as_deref()
    }

    /// Preserved archive-level extensions.
    #[must_use]
    pub fn extensions(&self) -> &[Extension] {
        &self.extensions
    }

    /// Sets the volume name.
    #[must_use]
    pub fn with_volume_name(mut self, volume_name: ArchivePath) -> Self {
        self.volume_name = Some(volume_name);
        self
    }

    /// Sets the archive comment.
    #[must_use]
    pub fn with_comment(mut self, comment: impl Into<Vec<u8>>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Adds a preserved archive property.
    #[must_use]
    pub fn with_extension(mut self, extension: Extension) -> Self {
        self.extensions.push(extension);
        self
    }
}
