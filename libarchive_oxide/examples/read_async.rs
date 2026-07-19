// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Runtime-neutral futures-io reading over the shared archive state machine.

#[cfg(feature = "async")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use futures_lite::future::block_on;
    use futures_lite::io::Cursor;
    use libarchive_oxide::{ArchiveWriter, AsyncArchiveReader, ReaderEvent};

    let archive = ArchiveWriter::new(Vec::new()).finish()?;
    block_on(async {
        let mut reader = AsyncArchiveReader::new(Cursor::new(archive));
        loop {
            match reader.next_event().await? {
                ReaderEvent::Entry(metadata) => {
                    println!("{}", metadata.path().display_lossy());
                },
                ReaderEvent::Done => break,
                _ => {},
            }
        }
        Ok::<_, libarchive_oxide::StreamError>(())
    })?;
    Ok(())
}

#[cfg(not(feature = "async"))]
fn main() {
    eprintln!("enable the `async` feature to run this example");
}
