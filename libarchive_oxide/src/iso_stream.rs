// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Payload-streaming ISO 9660/Joliet/Rock Ridge writer.

use std::collections::VecDeque;
use std::io::{Seek, SeekFrom, Write};

use libarchive_oxide_core::{
    ArchiveError, ArchiveMetadata, ArchivePath, EntryKind, EntryMetadata, EntryTimes, ErrorKind,
    Extension, Limits, Timestamp,
};

use crate::stream::StreamError;

const SECTOR: usize = 2048;
const SECTOR_U64: u64 = 2048;
const DESCRIPTOR_START: u64 = 16;
const METADATA_START: u64 = 19;
const DIRECTORY_RECORD_BASE: usize = 33;
const PATH_TABLE_RECORD_BASE: usize = 8;
const DIRECTORY_FLAG: u8 = 0x02;
const RECORDING_TIME: [u8; 7] = [120, 1, 1, 0, 0, 0, 0];

#[derive(Debug)]
struct IsoNode {
    name: Vec<u8>,
    kind: EntryKind,
    metadata: Option<EntryMetadata>,
    children: Vec<usize>,
    parent: usize,
    directory_number: u16,
    parent_number: u16,
    primary_lba: u32,
    primary_size: u32,
    joliet_lba: u32,
    joliet_size: u32,
    file_lba: u32,
    file_size: u32,
}

impl IsoNode {
    fn root() -> Self {
        Self {
            name: Vec::new(),
            kind: EntryKind::Dir,
            metadata: None,
            children: Vec::new(),
            parent: 0,
            directory_number: 1,
            parent_number: 1,
            primary_lba: 0,
            primary_size: 0,
            joliet_lba: 0,
            joliet_size: 0,
            file_lba: 0,
            file_size: 0,
        }
    }

    fn implicit_directory(name: Vec<u8>, parent: usize) -> Self {
        Self {
            name,
            kind: EntryKind::Dir,
            metadata: None,
            children: Vec::new(),
            parent,
            directory_number: 0,
            parent_number: 0,
            primary_lba: 0,
            primary_size: 0,
            joliet_lba: 0,
            joliet_size: 0,
            file_lba: 0,
            file_size: 0,
        }
    }

    fn is_directory(&self) -> bool {
        self.kind == EntryKind::Dir
    }
}

#[derive(Debug)]
struct PendingEntry {
    components: Vec<Vec<u8>>,
    metadata: EntryMetadata,
    size: u64,
    file_lba: u32,
}

/// ISO writer which streams file payloads and retains only bounded tree metadata.
#[derive(Debug)]
pub(crate) struct IsoSeekWriter<W: Write + Seek> {
    output: W,
    nodes: Vec<IsoNode>,
    pending: Option<PendingEntry>,
    limits: Limits,
    metadata_used: usize,
    decoded_total: u64,
    archive_metadata: ArchiveMetadata,
}

impl<W: Write + Seek> IsoSeekWriter<W> {
    pub(crate) fn new(mut output: W, limits: Limits) -> Result<Self, StreamError> {
        output.seek(SeekFrom::Start(0)).map_err(StreamError::io)?;
        let zero_sector = [0_u8; SECTOR];
        for _ in 0..METADATA_START {
            output.write_all(&zero_sector).map_err(StreamError::io)?;
        }
        Ok(Self {
            output,
            nodes: vec![IsoNode::root()],
            pending: None,
            limits,
            metadata_used: core::mem::size_of::<IsoNode>(),
            decoded_total: 0,
            archive_metadata: ArchiveMetadata::new(),
        })
    }

    pub(crate) fn set_archive_metadata(
        &mut self,
        metadata: &ArchiveMetadata,
    ) -> Result<(), StreamError> {
        if self.pending.is_some() || self.nodes.len() != 1 || self.decoded_total != 0 {
            return Err(iso_error(
                ErrorKind::Protocol,
                "ISO archive metadata must be set before the first entry",
            ));
        }
        if metadata.comment().is_some()
            || metadata
                .extensions()
                .iter()
                .any(|extension| extension.namespace() != "iso9660-volume")
        {
            return Err(iso_error(
                ErrorKind::Unsupported,
                "ISO archive metadata contains an unrepresentable property",
            ));
        }
        let cost = archive_metadata_cost(metadata)?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|limit| self.metadata_used.saturating_add(cost) > limit)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "ISO archive metadata exceeds configured limit",
            ));
        }
        self.archive_metadata = metadata.clone();
        self.metadata_used = self
            .metadata_used
            .checked_add(cost)
            .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
        Ok(())
    }

    pub(crate) fn start_entry(&mut self, metadata: &EntryMetadata) -> Result<(), StreamError> {
        if self.pending.is_some() {
            return Err(iso_error(
                ErrorKind::Protocol,
                "previous ISO entry is still open",
            ));
        }
        let components = normalize_path(metadata.path(), self.limits)?;
        Self::validate_entry_metadata(metadata)?;
        let missing_nodes = self.validate_tree_path(&components)?;
        let projected_nodes = self
            .nodes
            .len()
            .checked_add(missing_nodes)
            .ok_or_else(|| iso_error(ErrorKind::Limit, "ISO node count overflow"))?;
        if self
            .limits
            .entries()
            .is_some_and(|maximum| projected_nodes.saturating_sub(1) as u64 > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "ISO entry count exceeds configured limit",
            ));
        }
        let accounting = metadata_cost(metadata)?
            .checked_add(
                missing_nodes
                    .checked_mul(core::mem::size_of::<IsoNode>())
                    .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?,
            )
            .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
        self.metadata_used = self
            .metadata_used
            .checked_add(accounting)
            .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
        self.check_metadata_limit()?;

        let position = self.output.stream_position().map_err(StreamError::io)?;
        if !position.is_multiple_of(SECTOR_U64) {
            return Err(iso_error(
                ErrorKind::Protocol,
                "ISO payload cursor is not sector aligned",
            ));
        }
        let file_lba = u32::try_from(position / SECTOR_U64)
            .map_err(|_| iso_error(ErrorKind::Limit, "ISO extent LBA exceeds u32"))?;
        self.pending = Some(PendingEntry {
            components,
            metadata: metadata.clone(),
            size: 0,
            file_lba,
        });
        Ok(())
    }

    pub(crate) fn write_data(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        let pending = self.pending.as_ref().ok_or_else(|| {
            iso_error(
                ErrorKind::Protocol,
                "ISO data was supplied outside an entry",
            )
        })?;
        if bytes.is_empty() {
            return Ok(());
        }
        if pending.metadata.kind() != EntryKind::File {
            return Err(iso_error(
                ErrorKind::Protocol,
                "only regular ISO files accept payload data",
            ));
        }
        let additional = u64::try_from(bytes.len())
            .map_err(|_| iso_error(ErrorKind::Limit, "ISO write size exceeds u64"))?;
        let next_size = pending
            .size
            .checked_add(additional)
            .ok_or_else(|| iso_error(ErrorKind::Limit, "ISO entry size overflow"))?;
        if next_size > u64::from(u32::MAX) {
            return Err(iso_error(
                ErrorKind::Limit,
                "single-extent ISO file exceeds u32",
            ));
        }
        if self
            .limits
            .entry_bytes()
            .is_some_and(|maximum| next_size > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "ISO entry exceeds configured size limit",
            ));
        }
        let total = self
            .decoded_total
            .checked_add(additional)
            .ok_or_else(|| iso_error(ErrorKind::Limit, "ISO decoded total overflow"))?;
        if self
            .limits
            .decoded_total()
            .is_some_and(|maximum| total > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "ISO decoded total exceeds configured limit",
            ));
        }
        self.output.write_all(bytes).map_err(StreamError::io)?;
        self.pending
            .as_mut()
            .ok_or_else(|| iso_error(ErrorKind::Protocol, "ISO pending entry disappeared"))?
            .size = next_size;
        self.decoded_total = total;
        Ok(())
    }

    pub(crate) fn end_entry(&mut self) -> Result<(), StreamError> {
        let pending = self
            .pending
            .take()
            .ok_or_else(|| iso_error(ErrorKind::Protocol, "no ISO entry is open"))?;
        if pending
            .metadata
            .size()
            .is_some_and(|declared| declared != pending.size)
        {
            return Err(iso_error(
                ErrorKind::Protocol,
                "ISO entry size does not match its declared size",
            ));
        }
        if pending.metadata.kind() != EntryKind::File && pending.size != 0 {
            return Err(iso_error(
                ErrorKind::Protocol,
                "non-file ISO entry carried payload",
            ));
        }
        if pending.metadata.kind() == EntryKind::File {
            self.pad_output_to_sector()?;
        }
        self.insert_entry(pending)
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn finish(mut self) -> Result<W, StreamError> {
        if self.pending.is_some() {
            return Err(iso_error(
                ErrorKind::Protocol,
                "ISO entry is open at finish",
            ));
        }
        let order = self.order_directories()?;
        self.validate_identifiers(&order)?;

        for &directory in &order {
            let primary = layout_length(&self.build_directory_records(directory, false)?);
            let joliet = layout_length(&self.build_directory_records(directory, true)?);
            self.nodes[directory].primary_size = u32::try_from(primary)
                .map_err(|_| iso_error(ErrorKind::Limit, "ISO directory extent exceeds u32"))?;
            self.nodes[directory].joliet_size = u32::try_from(joliet)
                .map_err(|_| iso_error(ErrorKind::Limit, "Joliet directory extent exceeds u32"))?;
        }

        let primary_path_size = self.path_table_size(&order, false);
        let joliet_path_size = self.path_table_size(&order, true);
        self.check_final_metadata_size(&order, primary_path_size, joliet_path_size)?;

        let mut lba = self.current_lba()?;
        let primary_l_path = lba;
        lba = advance_lba(lba, primary_path_size)?;
        let primary_m_path = lba;
        lba = advance_lba(lba, primary_path_size)?;
        let joliet_l_path = lba;
        lba = advance_lba(lba, joliet_path_size)?;
        let joliet_m_path = lba;
        lba = advance_lba(lba, joliet_path_size)?;
        for &directory in &order {
            self.nodes[directory].primary_lba = lba;
            lba = advance_lba(
                lba,
                usize::try_from(self.nodes[directory].primary_size)
                    .map_err(|_| iso_error(ErrorKind::Limit, "directory size exceeds usize"))?,
            )?;
        }
        for &directory in &order {
            self.nodes[directory].joliet_lba = lba;
            lba = advance_lba(
                lba,
                usize::try_from(self.nodes[directory].joliet_size)
                    .map_err(|_| iso_error(ErrorKind::Limit, "directory size exceeds usize"))?,
            )?;
        }
        let total_sectors = lba;

        let primary_l = self.build_path_table(&order, false, false)?;
        self.write_padded_region(&primary_l)?;
        let primary_m = self.build_path_table(&order, false, true)?;
        self.write_padded_region(&primary_m)?;
        let joliet_l = self.build_path_table(&order, true, false)?;
        self.write_padded_region(&joliet_l)?;
        let joliet_m = self.build_path_table(&order, true, true)?;
        self.write_padded_region(&joliet_m)?;
        for &directory in &order {
            let records = self.build_directory_records(directory, false)?;
            let extent = layout_records(&records);
            self.output.write_all(&extent).map_err(StreamError::io)?;
        }
        for &directory in &order {
            let records = self.build_directory_records(directory, true)?;
            let extent = layout_records(&records);
            self.output.write_all(&extent).map_err(StreamError::io)?;
        }

        let archive_end = self.output.stream_position().map_err(StreamError::io)?;
        if archive_end != u64::from(total_sectors) * SECTOR_U64 {
            return Err(iso_error(
                ErrorKind::Protocol,
                "ISO layout cursor disagrees with calculated volume size",
            ));
        }
        let primary = volume_descriptor(
            VolumeDescriptor {
                descriptor_type: 1,
                joliet: false,
                root_lba: self.nodes[0].primary_lba,
                root_size: self.nodes[0].primary_size,
                path_table_size: primary_path_size,
                little_path_lba: primary_l_path,
                big_path_lba: primary_m_path,
                total_sectors,
            },
            &self.archive_metadata,
        )?;
        let supplementary = volume_descriptor(
            VolumeDescriptor {
                descriptor_type: 2,
                joliet: true,
                root_lba: self.nodes[0].joliet_lba,
                root_size: self.nodes[0].joliet_size,
                path_table_size: joliet_path_size,
                little_path_lba: joliet_l_path,
                big_path_lba: joliet_m_path,
                total_sectors,
            },
            &self.archive_metadata,
        )?;
        let mut terminator = [0_u8; SECTOR];
        terminator[0] = 255;
        terminator[1..6].copy_from_slice(b"CD001");
        terminator[6] = 1;
        self.output
            .seek(SeekFrom::Start(DESCRIPTOR_START * SECTOR_U64))
            .map_err(StreamError::io)?;
        self.output.write_all(&primary).map_err(StreamError::io)?;
        self.output
            .write_all(&supplementary)
            .map_err(StreamError::io)?;
        self.output
            .write_all(&terminator)
            .map_err(StreamError::io)?;
        self.output
            .seek(SeekFrom::Start(archive_end))
            .map_err(StreamError::io)?;
        self.output.flush().map_err(StreamError::io)?;
        Ok(self.output)
    }

    pub(crate) fn abort(self) -> W {
        self.output
    }

    fn validate_entry_metadata(metadata: &EntryMetadata) -> Result<(), StreamError> {
        match metadata.kind() {
            EntryKind::File | EntryKind::Dir | EntryKind::Fifo | EntryKind::Socket => {},
            EntryKind::Symlink => {
                if metadata.link_target().is_none() {
                    return Err(iso_error(
                        ErrorKind::Protocol,
                        "ISO symbolic link requires a target",
                    ));
                }
            },
            EntryKind::Hardlink => {
                if metadata.link_target().is_none() {
                    return Err(iso_error(
                        ErrorKind::Protocol,
                        "ISO hard link requires a target",
                    ));
                }
            },
            EntryKind::Char | EntryKind::Block => {
                if metadata.referenced_device().is_none() {
                    return Err(iso_error(
                        ErrorKind::Protocol,
                        "ISO device entry requires major/minor numbers",
                    ));
                }
            },
            _ => {
                return Err(iso_error(
                    ErrorKind::Unsupported,
                    "unsupported ISO entry kind",
                ));
            },
        }
        if metadata.kind() != EntryKind::File && metadata.size().is_some_and(|size| size != 0) {
            return Err(iso_error(
                ErrorKind::Protocol,
                "non-file ISO entry must have size zero or unknown",
            ));
        }
        if !metadata.sparse_extents().is_empty()
            || !metadata.xattrs().is_empty()
            || !metadata.acl().is_empty()
            || metadata.is_encrypted()
        {
            return Err(iso_error(
                ErrorKind::Unsupported,
                "ISO writer cannot represent sparse, xattr, ACL, or encrypted metadata",
            ));
        }
        Ok(())
    }

    fn validate_tree_path(&self, components: &[Vec<u8>]) -> Result<usize, StreamError> {
        let mut current = 0;
        let mut missing = 0;
        for (position, component) in components.iter().enumerate() {
            let child = self.nodes[current]
                .children
                .iter()
                .copied()
                .find(|&index| self.nodes[index].name == *component);
            let Some(child) = child else {
                missing += components.len() - position;
                break;
            };
            if position + 1 != components.len() && !self.nodes[child].is_directory() {
                return Err(iso_error(
                    ErrorKind::Protocol,
                    "ISO path traverses a non-directory entry",
                ));
            }
            if position + 1 == components.len() && self.nodes[child].metadata.is_some() {
                return Err(iso_error(ErrorKind::Protocol, "duplicate ISO entry path"));
            }
            current = child;
        }
        Ok(missing)
    }

    fn insert_entry(&mut self, pending: PendingEntry) -> Result<(), StreamError> {
        let (leaf, parents) = pending
            .components
            .split_last()
            .ok_or_else(|| iso_error(ErrorKind::Protocol, "ISO entry path is empty"))?;
        let mut parent = 0;
        for component in parents {
            parent = self.child_directory(parent, component);
        }
        let existing = self.nodes[parent]
            .children
            .iter()
            .copied()
            .find(|&index| self.nodes[index].name == *leaf);
        let index = if let Some(index) = existing {
            index
        } else {
            let index = self.nodes.len();
            self.nodes
                .push(IsoNode::implicit_directory(leaf.clone(), parent));
            self.nodes[parent].children.push(index);
            index
        };
        let (file_lba, file_size) = if pending.metadata.kind() == EntryKind::Hardlink {
            let target = pending
                .metadata
                .link_target()
                .ok_or_else(|| iso_error(ErrorKind::Protocol, "ISO hard link target is missing"))?;
            let target_components = normalize_path(target, self.limits)?;
            let target_index = self.find_path(&target_components).ok_or_else(|| {
                iso_error(
                    ErrorKind::Protocol,
                    "ISO hard link target must precede the link",
                )
            })?;
            let target = &self.nodes[target_index];
            if target.is_directory() {
                return Err(iso_error(
                    ErrorKind::Protocol,
                    "ISO hard link target is a directory",
                ));
            }
            (target.file_lba, target.file_size)
        } else {
            (
                pending.file_lba,
                u32::try_from(pending.size)
                    .map_err(|_| iso_error(ErrorKind::Limit, "ISO file size exceeds u32"))?,
            )
        };
        let node = &mut self.nodes[index];
        node.kind = pending.metadata.kind();
        node.metadata = Some(pending.metadata);
        node.file_lba = file_lba;
        node.file_size = file_size;
        Ok(())
    }

    fn child_directory(&mut self, parent: usize, name: &[u8]) -> usize {
        if let Some(index) = self.nodes[parent]
            .children
            .iter()
            .copied()
            .find(|&index| self.nodes[index].name == name)
        {
            return index;
        }
        let index = self.nodes.len();
        self.nodes
            .push(IsoNode::implicit_directory(name.to_vec(), parent));
        self.nodes[parent].children.push(index);
        index
    }

    fn find_path(&self, components: &[Vec<u8>]) -> Option<usize> {
        let mut current = 0;
        for component in components {
            current = self.nodes[current]
                .children
                .iter()
                .copied()
                .find(|&index| self.nodes[index].name == *component)?;
        }
        Some(current)
    }

    fn order_directories(&mut self) -> Result<Vec<usize>, StreamError> {
        let mut order = Vec::new();
        let mut queue = VecDeque::from([0]);
        let mut number = 2_u16;
        while let Some(directory) = queue.pop_front() {
            order.push(directory);
            let mut children: Vec<usize> = self.nodes[directory]
                .children
                .iter()
                .copied()
                .filter(|&child| self.nodes[child].is_directory())
                .collect();
            children.sort_by(|&left, &right| self.nodes[left].name.cmp(&self.nodes[right].name));
            for child in children {
                self.nodes[child].directory_number = number;
                self.nodes[child].parent_number = self.nodes[directory].directory_number;
                number = number
                    .checked_add(1)
                    .ok_or_else(|| iso_error(ErrorKind::Limit, "too many ISO directories"))?;
                queue.push_back(child);
            }
        }
        Ok(order)
    }

    fn validate_identifiers(&self, order: &[usize]) -> Result<(), StreamError> {
        for &directory in order {
            for joliet in [false, true] {
                validate_identifier(&self.directory_identifier(directory, joliet))?;
                for child in self.sorted_children(directory) {
                    validate_identifier(&self.child_identifier(child, joliet))?;
                    let record = self.directory_record_for_child(child, joliet)?;
                    if record.len() > usize::from(u8::MAX) {
                        return Err(iso_error(
                            ErrorKind::Unsupported,
                            "ISO directory record requires an unsupported continuation area",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn build_directory_records(
        &self,
        directory: usize,
        joliet: bool,
    ) -> Result<Vec<Vec<u8>>, StreamError> {
        let mut records = Vec::new();
        let (own_lba, own_size) = self.directory_extent(directory, joliet);
        let own_system_use = if joliet {
            Vec::new()
        } else {
            self.rock_ridge_system_use(directory, directory == 0, true)?
        };
        records.push(directory_record(
            &[0],
            own_lba,
            own_size,
            true,
            self.recording_time(directory),
            &own_system_use,
        )?);
        let parent = self.nodes[directory].parent;
        let (parent_lba, parent_size) = self.directory_extent(parent, joliet);
        records.push(directory_record(
            &[1],
            parent_lba,
            parent_size,
            true,
            self.recording_time(parent),
            &[],
        )?);
        for child in self.sorted_children(directory) {
            records.push(self.directory_record_for_child(child, joliet)?);
        }
        Ok(records)
    }

    fn directory_record_for_child(
        &self,
        child: usize,
        joliet: bool,
    ) -> Result<Vec<u8>, StreamError> {
        let node = &self.nodes[child];
        let identifier = self.child_identifier(child, joliet);
        let (lba, size) = if node.is_directory() {
            self.directory_extent(child, joliet)
        } else {
            (node.file_lba, node.file_size)
        };
        let system_use = if joliet {
            Vec::new()
        } else {
            self.rock_ridge_system_use(child, false, false)?
        };
        directory_record(
            &identifier,
            lba,
            size,
            node.is_directory(),
            self.recording_time(child),
            &system_use,
        )
    }

    fn rock_ridge_system_use(
        &self,
        node_index: usize,
        root: bool,
        dot_record: bool,
    ) -> Result<Vec<u8>, StreamError> {
        let node = &self.nodes[node_index];
        let mut fields = Vec::new();
        if root {
            fields.extend_from_slice(b"SP\x07\x01\xbe\xef\x00");
        }
        let mut rr_flags = 0x01;
        if !dot_record {
            rr_flags |= 0x08;
        }
        if matches!(node.kind, EntryKind::Char | EntryKind::Block) {
            rr_flags |= 0x02;
        }
        if node.kind == EntryKind::Symlink {
            rr_flags |= 0x04;
        }
        if node
            .metadata
            .as_ref()
            .is_some_and(|metadata| metadata.times() != EntryTimes::default())
        {
            rr_flags |= 0x80;
        }
        push_susp_field(&mut fields, *b"RR", &[rr_flags])?;
        if !dot_record {
            let mut name = vec![0];
            name.extend_from_slice(&node.name);
            push_susp_field(&mut fields, *b"NM", &name)?;
        }
        let metadata = node.metadata.as_ref();
        let mode = full_mode(node.kind, metadata.and_then(EntryMetadata::mode));
        let links = u32_value(
            metadata
                .and_then(EntryMetadata::links)
                .unwrap_or(if node.is_directory() { 2 } else { 1 }),
            "Rock Ridge link count exceeds u32",
        )?;
        let uid = u32_value(
            metadata.and_then(|value| value.owner().uid).unwrap_or(0),
            "Rock Ridge uid exceeds u32",
        )?;
        let gid = u32_value(
            metadata.and_then(|value| value.owner().gid).unwrap_or(0),
            "Rock Ridge gid exceeds u32",
        )?;
        let inode = u32_value(
            metadata
                .and_then(EntryMetadata::inode)
                .unwrap_or(u64::try_from(node_index + 1).unwrap_or(u64::MAX)),
            "Rock Ridge inode exceeds u32",
        )?;
        let mut px = Vec::with_capacity(40);
        for value in [mode, links, uid, gid, inode] {
            px.extend_from_slice(&both_endian_u32(value));
        }
        push_susp_field(&mut fields, *b"PX", &px)?;
        if let Some(device) = metadata.and_then(EntryMetadata::referenced_device) {
            let mut pn = Vec::with_capacity(16);
            pn.extend_from_slice(&both_endian_u32(u32_value(
                device.major,
                "Rock Ridge device major exceeds u32",
            )?));
            pn.extend_from_slice(&both_endian_u32(u32_value(
                device.minor,
                "Rock Ridge device minor exceeds u32",
            )?));
            push_susp_field(&mut fields, *b"PN", &pn)?;
        }
        if node.kind == EntryKind::Symlink {
            let target = metadata
                .and_then(EntryMetadata::link_target)
                .ok_or_else(|| iso_error(ErrorKind::Protocol, "ISO symlink target is missing"))?;
            let sl = symbolic_link_value(target.as_bytes())?;
            push_susp_field(&mut fields, *b"SL", &sl)?;
        }
        if let Some(metadata) = metadata {
            if let Some(tf) = timestamp_field(metadata.times()) {
                push_susp_field(&mut fields, *b"TF", &tf)?;
            }
            for extension in metadata.extensions() {
                append_raw_system_use(&mut fields, extension)?;
            }
        }
        Ok(fields)
    }

    fn build_path_table(
        &self,
        order: &[usize],
        joliet: bool,
        big_endian: bool,
    ) -> Result<Vec<u8>, StreamError> {
        let mut bytes = Vec::new();
        for &directory in order {
            let identifier = self.directory_identifier(directory, joliet);
            bytes.push(u8::try_from(identifier.len()).map_err(|_| {
                iso_error(
                    ErrorKind::Unsupported,
                    "ISO path-table identifier exceeds u8",
                )
            })?);
            bytes.push(0);
            let (lba, _) = self.directory_extent(directory, joliet);
            if big_endian {
                bytes.extend_from_slice(&lba.to_be_bytes());
                bytes.extend_from_slice(&self.nodes[directory].parent_number.to_be_bytes());
            } else {
                bytes.extend_from_slice(&lba.to_le_bytes());
                bytes.extend_from_slice(&self.nodes[directory].parent_number.to_le_bytes());
            }
            bytes.extend_from_slice(&identifier);
            if !identifier.len().is_multiple_of(2) {
                bytes.push(0);
            }
        }
        Ok(bytes)
    }

    fn path_table_size(&self, order: &[usize], joliet: bool) -> usize {
        order
            .iter()
            .map(|&directory| {
                path_table_record_length(self.directory_identifier(directory, joliet).len())
            })
            .sum()
    }

    fn directory_identifier(&self, directory: usize, joliet: bool) -> Vec<u8> {
        if directory == 0 {
            vec![0]
        } else if joliet {
            joliet_name(&self.nodes[directory].name)
        } else {
            primary_name(&self.nodes[directory].name)
        }
    }

    fn child_identifier(&self, child: usize, joliet: bool) -> Vec<u8> {
        let node = &self.nodes[child];
        if joliet {
            joliet_name(&node.name)
        } else if node.is_directory() {
            primary_name(&node.name)
        } else {
            let mut name = primary_name(&node.name);
            name.extend_from_slice(b";1");
            name
        }
    }

    fn directory_extent(&self, directory: usize, joliet: bool) -> (u32, u32) {
        let node = &self.nodes[directory];
        if joliet {
            (node.joliet_lba, node.joliet_size)
        } else {
            (node.primary_lba, node.primary_size)
        }
    }

    fn sorted_children(&self, directory: usize) -> Vec<usize> {
        let mut children = self.nodes[directory].children.clone();
        children.sort_by(|&left, &right| self.nodes[left].name.cmp(&self.nodes[right].name));
        children
    }

    fn recording_time(&self, node: usize) -> [u8; 7] {
        self.nodes[node]
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.times().modified)
            .and_then(short_timestamp)
            .unwrap_or(RECORDING_TIME)
    }

    fn check_metadata_limit(&self) -> Result<(), StreamError> {
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| self.metadata_used > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "ISO metadata exceeds configured limit",
            ));
        }
        Ok(())
    }

    fn check_final_metadata_size(
        &self,
        order: &[usize],
        primary_path_size: usize,
        joliet_path_size: usize,
    ) -> Result<(), StreamError> {
        let directory_bytes = order.iter().try_fold(0_usize, |total, &directory| {
            total
                .checked_add(usize::try_from(self.nodes[directory].primary_size).ok()?)
                .and_then(|value| {
                    value.checked_add(usize::try_from(self.nodes[directory].joliet_size).ok()?)
                })
        });
        let total = primary_path_size
            .checked_mul(2)
            .and_then(|value| value.checked_add(joliet_path_size.checked_mul(2)?))
            .and_then(|value| value.checked_add(directory_bytes?))
            .ok_or_else(|| iso_error(ErrorKind::Limit, "ISO final metadata size overflow"))?;
        if self
            .limits
            .metadata_bytes()
            .is_some_and(|maximum| total > maximum)
        {
            return Err(iso_error(
                ErrorKind::Limit,
                "ISO final index exceeds metadata limit",
            ));
        }
        Ok(())
    }

    fn current_lba(&mut self) -> Result<u32, StreamError> {
        let position = self.output.stream_position().map_err(StreamError::io)?;
        if !position.is_multiple_of(SECTOR_U64) {
            return Err(iso_error(
                ErrorKind::Protocol,
                "ISO output cursor is not sector aligned",
            ));
        }
        u32::try_from(position / SECTOR_U64)
            .map_err(|_| iso_error(ErrorKind::Limit, "ISO image exceeds u32 LBA range"))
    }

    fn pad_output_to_sector(&mut self) -> Result<(), StreamError> {
        let position = self.output.stream_position().map_err(StreamError::io)?;
        let padding = (SECTOR_U64 - position % SECTOR_U64) % SECTOR_U64;
        let zeros = [0_u8; SECTOR];
        self.output
            .write_all(
                &zeros[..usize::try_from(padding)
                    .map_err(|_| iso_error(ErrorKind::Limit, "ISO padding exceeds usize"))?],
            )
            .map_err(StreamError::io)
    }

    fn write_padded_region(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        self.output.write_all(bytes).map_err(StreamError::io)?;
        self.pad_output_to_sector()
    }
}

#[derive(Clone, Copy)]
struct VolumeDescriptor {
    descriptor_type: u8,
    joliet: bool,
    root_lba: u32,
    root_size: u32,
    path_table_size: usize,
    little_path_lba: u32,
    big_path_lba: u32,
    total_sectors: u32,
}

fn volume_descriptor(
    layout: VolumeDescriptor,
    metadata: &ArchiveMetadata,
) -> Result<[u8; SECTOR], StreamError> {
    let mut descriptor = [0_u8; SECTOR];
    descriptor[0] = layout.descriptor_type;
    descriptor[1..6].copy_from_slice(b"CD001");
    descriptor[6] = 1;
    let volume_name = metadata
        .volume_name()
        .map_or(b"LIBARCHIVE_OXIDE".as_slice(), ArchivePath::as_bytes);
    if layout.joliet {
        descriptor[88..91].copy_from_slice(&[0x25, 0x2f, 0x45]);
        let encoded = joliet_name(volume_name);
        let count = encoded.len().min(32);
        descriptor[40..40 + count].copy_from_slice(&encoded[..count]);
    } else {
        descriptor[8..72].fill(b' ');
        if let Some(system_id) = metadata.extensions().iter().find(|extension| {
            extension.namespace() == "iso9660-volume" && extension.key() == b"system-id"
        }) {
            let count = system_id.value().len().min(32);
            descriptor[8..8 + count].copy_from_slice(&system_id.value()[..count]);
        }
        let encoded = primary_name(volume_name);
        let count = encoded.len().min(32);
        descriptor[40..40 + count].copy_from_slice(&encoded[..count]);
        if let Some(application_id) = metadata.extensions().iter().find(|extension| {
            extension.namespace() == "iso9660-volume" && extension.key() == b"application-id"
        }) {
            let count = application_id.value().len().min(128);
            descriptor[574..574 + count].copy_from_slice(&application_id.value()[..count]);
        }
    }
    descriptor[80..88].copy_from_slice(&both_endian_u32(layout.total_sectors));
    descriptor[120..124].copy_from_slice(&both_endian_u16(1));
    descriptor[124..128].copy_from_slice(&both_endian_u16(1));
    descriptor[128..132].copy_from_slice(&both_endian_u16(
        u16::try_from(SECTOR)
            .map_err(|_| iso_error(ErrorKind::Limit, "sector size exceeds u16"))?,
    ));
    let path_size = u32::try_from(layout.path_table_size)
        .map_err(|_| iso_error(ErrorKind::Limit, "ISO path table exceeds u32"))?;
    descriptor[132..140].copy_from_slice(&both_endian_u32(path_size));
    descriptor[140..144].copy_from_slice(&layout.little_path_lba.to_le_bytes());
    descriptor[148..152].copy_from_slice(&layout.big_path_lba.to_be_bytes());
    let root = directory_record(
        &[0],
        layout.root_lba,
        layout.root_size,
        true,
        RECORDING_TIME,
        &[],
    )?;
    descriptor[156..156 + root.len()].copy_from_slice(&root);
    if !layout.joliet {
        descriptor[190..813].fill(b' ');
    }
    descriptor[881] = 1;
    Ok(descriptor)
}

fn archive_metadata_cost(metadata: &ArchiveMetadata) -> Result<usize, StreamError> {
    let mut cost = core::mem::size_of::<ArchiveMetadata>();
    if let Some(volume_name) = metadata.volume_name() {
        cost = cost
            .checked_add(volume_name.as_bytes().len())
            .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
    }
    if let Some(comment) = metadata.comment() {
        cost = cost
            .checked_add(comment.len())
            .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
    }
    for extension in metadata.extensions() {
        cost = cost
            .checked_add(extension.namespace().len())
            .and_then(|value| value.checked_add(extension.key().len()))
            .and_then(|value| value.checked_add(extension.value().len()))
            .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
    }
    Ok(cost)
}

fn directory_record(
    identifier: &[u8],
    lba: u32,
    size: u32,
    directory: bool,
    recording_time: [u8; 7],
    system_use: &[u8],
) -> Result<Vec<u8>, StreamError> {
    let identifier_end = DIRECTORY_RECORD_BASE
        .checked_add(identifier.len())
        .ok_or_else(|| iso_error(ErrorKind::Limit, "ISO directory record length overflow"))?;
    let system_use_start = identifier_end
        .checked_add(usize::from(identifier.len().is_multiple_of(2)))
        .ok_or_else(|| iso_error(ErrorKind::Limit, "ISO directory record length overflow"))?;
    let length = system_use_start
        .checked_add(system_use.len())
        .ok_or_else(|| iso_error(ErrorKind::Limit, "ISO directory record length overflow"))?;
    let record_length = u8::try_from(length).map_err(|_| {
        iso_error(
            ErrorKind::Unsupported,
            "ISO directory record requires an unsupported continuation area",
        )
    })?;
    let mut record = vec![0_u8; length];
    record[0] = record_length;
    record[2..10].copy_from_slice(&both_endian_u32(lba));
    record[10..18].copy_from_slice(&both_endian_u32(size));
    record[18..25].copy_from_slice(&recording_time);
    record[25] = if directory { DIRECTORY_FLAG } else { 0 };
    record[28..32].copy_from_slice(&both_endian_u16(1));
    record[32] = u8::try_from(identifier.len())
        .map_err(|_| iso_error(ErrorKind::Unsupported, "ISO identifier exceeds u8"))?;
    record[DIRECTORY_RECORD_BASE..identifier_end].copy_from_slice(identifier);
    record[system_use_start..].copy_from_slice(system_use);
    Ok(record)
}

fn layout_length(records: &[Vec<u8>]) -> usize {
    let mut position = 0;
    for record in records {
        let sector_offset = position % SECTOR;
        if sector_offset + record.len() > SECTOR {
            position += SECTOR - sector_offset;
        }
        position += record.len();
    }
    position.div_ceil(SECTOR).max(1) * SECTOR
}

fn layout_records(records: &[Vec<u8>]) -> Vec<u8> {
    let mut extent = vec![0; layout_length(records)];
    let mut position = 0;
    for record in records {
        let sector_offset = position % SECTOR;
        if sector_offset + record.len() > SECTOR {
            position += SECTOR - sector_offset;
        }
        extent[position..position + record.len()].copy_from_slice(record);
        position += record.len();
    }
    extent
}

fn path_table_record_length(identifier_length: usize) -> usize {
    let base = PATH_TABLE_RECORD_BASE + identifier_length;
    base + usize::from(!base.is_multiple_of(2))
}

fn advance_lba(lba: u32, bytes: usize) -> Result<u32, StreamError> {
    let sectors = u32::try_from(bytes.div_ceil(SECTOR))
        .map_err(|_| iso_error(ErrorKind::Limit, "ISO region exceeds u32 sectors"))?;
    lba.checked_add(sectors)
        .ok_or_else(|| iso_error(ErrorKind::Limit, "ISO LBA overflow"))
}

fn normalize_path(path: &ArchivePath, limits: Limits) -> Result<Vec<Vec<u8>>, StreamError> {
    let bytes = path.as_bytes();
    if bytes.is_empty() || bytes.starts_with(b"/") || bytes.contains(&0) {
        return Err(iso_error(
            ErrorKind::Protocol,
            "ISO path must be a non-empty relative byte path",
        ));
    }
    if limits
        .path_bytes()
        .is_some_and(|maximum| bytes.len() > maximum)
    {
        return Err(iso_error(
            ErrorKind::Limit,
            "ISO path exceeds configured limit",
        ));
    }
    let components: Vec<Vec<u8>> = bytes
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    if components.is_empty()
        || components
            .iter()
            .any(|component| matches!(component.as_slice(), b"." | b".."))
    {
        return Err(iso_error(
            ErrorKind::Protocol,
            "ISO path contains an invalid component",
        ));
    }
    if limits
        .nesting()
        .is_some_and(|maximum| components.len() > maximum)
    {
        return Err(iso_error(
            ErrorKind::Limit,
            "ISO path nesting exceeds configured limit",
        ));
    }
    Ok(components)
}

fn validate_identifier(identifier: &[u8]) -> Result<(), StreamError> {
    if identifier.len() > usize::from(u8::MAX) {
        return Err(iso_error(
            ErrorKind::Unsupported,
            "ISO identifier exceeds one-byte length",
        ));
    }
    Ok(())
}

fn primary_name(name: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(name.len().max(1));
    for &byte in name {
        let value = if byte.is_ascii_lowercase() {
            byte.to_ascii_uppercase()
        } else if byte.is_ascii_uppercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.')
        {
            byte
        } else {
            b'_'
        };
        result.push(value);
    }
    if result.is_empty() {
        result.push(b'_');
    }
    result
}

fn joliet_name(name: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let display = String::from_utf8_lossy(name);
    for mut unit in display.encode_utf16() {
        if u8::try_from(unit)
            .is_ok_and(|byte| matches!(byte, b'*' | b'/' | b':' | b';' | b'?' | b'\\' | 0..=31))
        {
            unit = u16::from(b'_');
        }
        result.extend_from_slice(&unit.to_be_bytes());
    }
    result
}

fn full_mode(kind: EntryKind, permissions: Option<u32>) -> u32 {
    let file_type = match kind {
        EntryKind::File | EntryKind::Hardlink => 0o100_000,
        EntryKind::Dir => 0o040_000,
        EntryKind::Symlink => 0o120_000,
        EntryKind::Block => 0o060_000,
        EntryKind::Char => 0o020_000,
        EntryKind::Fifo => 0o010_000,
        EntryKind::Socket => 0o140_000,
        _ => 0,
    };
    let default = if kind == EntryKind::Dir { 0o755 } else { 0o644 };
    file_type | permissions.unwrap_or(default) & 0o7777
}

fn push_susp_field(
    output: &mut Vec<u8>,
    signature: [u8; 2],
    value: &[u8],
) -> Result<(), StreamError> {
    let length = value
        .len()
        .checked_add(4)
        .ok_or_else(|| iso_error(ErrorKind::Limit, "system-use field length overflow"))?;
    output.extend_from_slice(&signature);
    output.push(u8::try_from(length).map_err(|_| {
        iso_error(
            ErrorKind::Unsupported,
            "Rock Ridge field requires an unsupported continuation area",
        )
    })?);
    output.push(1);
    output.extend_from_slice(value);
    Ok(())
}

fn append_raw_system_use(output: &mut Vec<u8>, extension: &Extension) -> Result<(), StreamError> {
    if extension.namespace() != "iso-system-use"
        || matches!(
            extension.key(),
            b"SP" | b"RR" | b"NM" | b"PX" | b"PN" | b"SL" | b"TF"
        )
    {
        return Ok(());
    }
    if extension.key().len() != 2 {
        return Err(iso_error(
            ErrorKind::Malformed,
            "raw ISO system-use signature must be two bytes",
        ));
    }
    let value = extension.value();
    if value.len() >= 4 && &value[..2] == extension.key() && usize::from(value[2]) == value.len() {
        output.extend_from_slice(value);
        return Ok(());
    }
    push_susp_field(output, [extension.key()[0], extension.key()[1]], value)
}

fn symbolic_link_value(target: &[u8]) -> Result<Vec<u8>, StreamError> {
    let mut value = vec![0];
    let absolute = target.starts_with(b"/");
    if absolute {
        value.extend_from_slice(&[0x08, 0]);
    }
    for component in target
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty())
    {
        match component {
            b"." => value.extend_from_slice(&[0x02, 0]),
            b".." => value.extend_from_slice(&[0x04, 0]),
            _ => {
                value.push(0);
                value.push(u8::try_from(component.len()).map_err(|_| {
                    iso_error(
                        ErrorKind::Unsupported,
                        "Rock Ridge symlink component exceeds u8",
                    )
                })?);
                value.extend_from_slice(component);
            },
        }
    }
    Ok(value)
}

fn timestamp_field(times: libarchive_oxide_core::EntryTimes) -> Option<Vec<u8>> {
    let mut flags = 0x80;
    let mut values = Vec::new();
    for (bit, timestamp) in [
        (0, times.created),
        (1, times.modified),
        (2, times.accessed),
        (3, times.changed),
    ] {
        if let Some(encoded) = timestamp.and_then(long_timestamp) {
            flags |= 1 << bit;
            values.extend_from_slice(&encoded);
        }
    }
    if flags == 0x80 {
        None
    } else {
        let mut field = vec![flags];
        field.extend_from_slice(&values);
        Some(field)
    }
}

fn long_timestamp(timestamp: Timestamp) -> Option<[u8; 17]> {
    let (year, month, day, hour, minute, second) = timestamp_parts(timestamp)?;
    if !(0..=9999).contains(&year) {
        return None;
    }
    let hundredths = timestamp.nanos / 10_000_000;
    let text = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}{hundredths:02}");
    let mut encoded = [0_u8; 17];
    encoded[..16].copy_from_slice(text.as_bytes());
    Some(encoded)
}

fn short_timestamp(timestamp: Timestamp) -> Option<[u8; 7]> {
    let (year, month, day, hour, minute, second) = timestamp_parts(timestamp)?;
    if !(1900..=2155).contains(&year) {
        return None;
    }
    Some([
        u8::try_from(year - 1900).ok()?,
        month,
        day,
        hour,
        minute,
        second,
        0,
    ])
}

fn timestamp_parts(timestamp: Timestamp) -> Option<(i32, u8, u8, u8, u8, u8)> {
    if timestamp.nanos >= 1_000_000_000 {
        return None;
    }
    let days = timestamp.secs.div_euclid(86_400);
    let seconds = timestamp.secs.rem_euclid(86_400);
    let shifted = days.checked_add(719_468)?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096)
        .div_euclid(365);
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2).div_euclid(153);
    let day = day_of_year - (153 * month_prime + 2).div_euclid(5) + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Some((
        i32::try_from(year).ok()?,
        u8::try_from(month).ok()?,
        u8::try_from(day).ok()?,
        u8::try_from(seconds / 3600).ok()?,
        u8::try_from(seconds % 3600 / 60).ok()?,
        u8::try_from(seconds % 60).ok()?,
    ))
}

fn both_endian_u32(value: u32) -> [u8; 8] {
    let little = value.to_le_bytes();
    let big = value.to_be_bytes();
    [
        little[0], little[1], little[2], little[3], big[0], big[1], big[2], big[3],
    ]
}

fn both_endian_u16(value: u16) -> [u8; 4] {
    let little = value.to_le_bytes();
    let big = value.to_be_bytes();
    [little[0], little[1], big[0], big[1]]
}

fn u32_value(value: u64, context: &'static str) -> Result<u32, StreamError> {
    u32::try_from(value).map_err(|_| iso_error(ErrorKind::Unsupported, context))
}

fn metadata_cost(metadata: &EntryMetadata) -> Result<usize, StreamError> {
    let mut total = metadata
        .path()
        .as_bytes()
        .len()
        .checked_add(
            metadata
                .link_target()
                .map_or(0, |target| target.as_bytes().len()),
        )
        .and_then(|value| value.checked_add(core::mem::size_of::<EntryMetadata>()))
        .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
    for extension in metadata.extensions() {
        total = total
            .checked_add(extension.namespace().len())
            .and_then(|value| value.checked_add(extension.key().len()))
            .and_then(|value| value.checked_add(extension.value().len()))
            .ok_or_else(|| iso_error(ErrorKind::Limit, "metadata accounting overflow"))?;
    }
    Ok(total)
}

fn iso_error(kind: ErrorKind, context: &'static str) -> StreamError {
    StreamError::archive(
        ArchiveError::new(kind)
            .with_format("iso9660")
            .with_context(context),
    )
}
