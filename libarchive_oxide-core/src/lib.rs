//! `libarchive_oxide-core` — a frozen trait algebra and sans-IO core.
//!
//! What this crate delivers is not a "working extraction tool" but **the trait algebra itself**.
//! The top-level design criterion is the symmetry, orthogonality, and purity of the abstractions;
//! implementation coverage is subordinate to that.
//!
//! # Invariants of beauty (this crate's acceptance criteria)
//!
//! - **A single sans-IO substrate**: every transformation rides on [`Transform`]. It holds no I/O,
//!   and the caller drives the bytes (caller-owned buffers, never forcing an allocation).
//! - **Orthogonal (format ⊥ filter)**: adding compression does not change a single line of the
//!   [`format`] layer's code. The converse holds too. format knows nothing of filter, filter nothing of format.
//! - **Dual (read ⇄ write, decode ⇄ encode)**: [`EntryReader`]/[`EntryWriter`] and
//!   [`Decoder`]/[`Encoder`] are symmetric at the type level.
//!   The design of one side forces the other.
//! - **Purity**: all trait definitions are `no_std`. Only specific impls pull in `std`/`alloc`.
//! - **Origin-opaque**: whether an impl is hand-written or an adapter over a reused crate never leaks into the caller's types.
//!
//! # Implementation status
//!
//! The abstractions (traits and types) are **frozen in their finished form**. Both write and new formats
//! land without any trait change (the [`format::tar`]/[`format::cpio`] stubs prove at the type level
//! that they are implementable under the same traits). Implementation breadth grows later, beneath the frozen abstractions.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod error;
pub mod filter;
pub mod format;
pub mod io;
pub mod meta;
pub mod transform;

pub use error::{Error, Result};
pub use filter::{Decoder, Encoder, Filter};
pub use format::{
    AnyEntryData, AnyReader, ArchiveFormat, Detection, Entry, EntryData, EntryDataSink,
    EntryReader, EntrySink, EntrySource, EntryWriter, OwnedData, SliceData, SourceEvent,
};
pub use io::Sink;
pub use meta::{EntryKind, EntryMeta, PaxMap, Timestamp};
pub use transform::{decode_to_vec, decode_to_vec_capped, Status, Step, Transform};
