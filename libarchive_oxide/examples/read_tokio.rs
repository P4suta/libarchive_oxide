// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tokio reading through the thin runtime adapter.

#[cfg(feature = "tokio")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use libarchive_oxide::{ArchiveWriter, ReaderEvent, TokioArchiveReader};
    use tokio::io::AsyncWriteExt;

    let archive = ArchiveWriter::new(Vec::new()).finish()?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        let (mut sender, receiver) = tokio::io::duplex(archive.len().max(1));
        sender.write_all(&archive).await?;
        drop(sender);

        let mut reader = TokioArchiveReader::new(receiver);
        loop {
            match reader.next_event().await? {
                ReaderEvent::Entry(metadata) => {
                    println!("{}", metadata.path().display_lossy());
                },
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!("enable the `tokio` feature to run this example");
}
