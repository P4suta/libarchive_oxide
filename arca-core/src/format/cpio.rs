//! cpio format (SVR4 "newc" / POSIX "odc" / old binary).
//!
//! **Proof of orthogonality**: adding a new format only requires "adding a type that implements
//! the same [`EntryReader`]"; neither the existing traits nor the tar implementation change by a single line. In P0 we freeze that typing.

use crate::format::{ArchiveFormat, Detection, Entry, EntryReader};
use crate::Result;

/// Detection anchor for the cpio format (zero-sized type).
#[derive(Debug, Clone, Copy, Default)]
pub struct Cpio;

const NEWC_MAGIC: &[u8] = b"070701";
const NEWC_CRC_MAGIC: &[u8] = b"070702";
const ODC_MAGIC: &[u8] = b"070707";
/// Magic for the old binary format (supports both host byte orders).
const BIN_MAGIC_LE: [u8; 2] = [0xc7, 0x71];
const BIN_MAGIC_BE: [u8; 2] = [0x71, 0xc7];

impl ArchiveFormat for Cpio {
    const NAME: &'static str = "cpio";

    fn sniff(prefix: &[u8]) -> Detection {
        if prefix.len() < 2 {
            return Detection::NeedMore;
        }
        let head2 = [prefix[0], prefix[1]];
        if head2 == BIN_MAGIC_LE || head2 == BIN_MAGIC_BE {
            return Detection::Match;
        }
        if prefix.len() < 6 {
            return Detection::NeedMore;
        }
        let head6 = &prefix[..6];
        if head6 == NEWC_MAGIC || head6 == NEWC_CRC_MAGIC || head6 == ODC_MAGIC {
            Detection::Match
        } else {
            Detection::NoMatch
        }
    }
}

/// Streaming reader for cpio.
#[derive(Debug)]
pub struct CpioReader<S> {
    #[allow(dead_code)] // Used in P4.
    source: S,
}

impl<S> CpioReader<S> {
    /// Creates a reader from a byte source.
    pub fn new(source: S) -> Self {
        Self { source }
    }
}

impl<S> EntryReader for CpioReader<S> {
    fn next_entry(&mut self) -> Result<Option<Entry<'_>>> {
        // P4: header dispatch for newc (hex) / odc (octal) / old binary, and TRAILER!!! end-of-stream detection.
        todo!("P4: cpio header parsing")
    }
}
