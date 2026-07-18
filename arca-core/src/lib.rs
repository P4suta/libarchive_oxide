//! `arca-core` — 凍結されたトレイト代数と sans-IO コア。
//!
//! このクレートの成果物は「動く展開ツール」ではなく **トレイト代数そのもの** である。
//! 設計の最上位基準は、抽象の対称性・直交性・純度であり、実装の網羅はその下位に置く。
//!
//! # 美の不変条件（このクレートの受入基準）
//!
//! - **単一の sans-IO 基層**: すべての変換は [`Transform`] の上に乗る。I/O を持たず、
//!   呼び出し側がバイトを駆動する（caller-owned buffers、割当を強制しない）。
//! - **直交（format ⊥ filter）**: 圧縮を足しても [`format`] 層のコードは 1 行も変わらない。
//!   その逆も同様。format は filter を、filter は format を一切知らない。
//! - **双対（read ⇄ write, decode ⇄ encode）**: [`EntryReader`]/[`EntryWriter`] と
//!   [`Decoder`](filter::Decoder)/[`Encoder`](filter::Encoder) は型レベルで対称。
//!   片方の設計がもう片方を強制する。
//! - **純度**: トレイト定義はすべて `no_std`。`std`/`alloc` を引くのは特定 impl のみ。
//! - **出自不可視**: 自作実装か再利用クレートのアダプタかが、呼び出し側の型に漏れない。
//!
//! # 実装状況
//!
//! 抽象（トレイト・型）は **完成形で凍結** されている。write も新フォーマットも
//! トレイト変更なしに載る（[`format::tar`]/[`format::cpio`] のスタブが同一トレイトで
//! 実装可能であることを型として証明する）。実装幅は凍結された抽象の下で後から伸ばす。

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod error;
pub mod filter;
pub mod format;
pub mod meta;
pub mod transform;

pub use error::{Error, Result};
pub use filter::{Decoder, Encoder, Filter};
pub use format::{
    ArchiveFormat, Detection, Entry, EntryData, EntryDataSink, EntryReader, EntrySink, EntryWriter,
};
pub use meta::{EntryKind, EntryMeta, PaxMap, Timestamp};
pub use transform::{Status, Step, Transform};
