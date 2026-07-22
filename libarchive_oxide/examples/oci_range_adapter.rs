// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Byte/range source adapters for OCI layer blobs, with **no** registry
//! networking, authentication, or cloud SDK dependencies.
//!
//! An OCI image layer is an immutable blob addressed by digest. Object stores
//! and HTTP servers can serve any sub-range of such a blob, which is exactly the
//! shape the [`RangeSource`] contract expects. This example shows how to bridge
//! *any* ranged-fetch mechanism to the OCI layer engine without embedding a
//! single HTTP client or cloud SDK.
//!
//! The bridge is one generic type, [`FetchRange`], parameterized over a fetch
//! closure `FnMut(offset, len) -> io::Result<Vec<u8>>`. Static dispatch only:
//! there are no trait objects. The closure is where a real deployment would call
//! its transport of choice. The transport is injected, never depended upon:
//!
//! * **HTTP / HTTPS** — issue `GET` with header `Range: bytes=<a>-<b>` and read
//!   the `206 Partial Content` body. Use the strong `ETag` as the source
//!   identity so a changed blob is detected.
//! * **Amazon S3** — call `GetObject` with the `Range: bytes=<a>-<b>` parameter.
//!   Use the object `VersionId` (or `ETag`) as the identity.
//! * **Google Cloud Storage** — download media with a `Range: bytes=<a>-<b>`
//!   header. Use the object `generation` number as the identity.
//! * **Azure Blob Storage** — `Get Blob` with the `x-ms-range: bytes=<a>-<b>`
//!   header. Use the blob `ETag` as the identity.
//!
//! Every adapter below reuses the same [`FetchRange`]; only the identity source
//! and the request framing differ, and the framing is documented rather than
//! implemented. No bytes leave the process: the `main` function drives the whole
//! flow against an in-memory blob served through the same range interface a
//! remote store would expose.
//!
//! The resulting [`RangeReader`] is `Read + Seek`, so the same source feeds both
//! [`OciLayerEngine::open`] (streaming inspection and digests) and
//! [`OciLayerApplier`] (which additionally requires `Seek`).

use std::io;

use libarchive_oxide::libarchive_oxide_core::{
    ArchivePath, EntryKind, EntryMetadata, FilterId, FormatId,
};
use libarchive_oxide::{
    ArchiveEngine, CreateOptions, IdentityOwnership, LayerDigests, OciLayerApplier, OciLayerEngine,
    Policy, RangeReader, RangeSource, SourceIdentity,
};

/// An immutable [`RangeSource`] backed by an injected ranged-fetch closure.
///
/// `F` performs one ranged read: given a byte `offset` and a maximum length, it
/// returns the bytes actually available at that offset. Returning fewer bytes
/// than requested is fine; [`RangeReader`] reissues the fetch to make progress.
/// The closure is the single seam a caller wires to HTTP, S3, GCS, Azure, or any
/// other transport, so this type never depends on a networking or cloud crate.
struct FetchRange<F> {
    fetch: F,
    length: u64,
    identity: SourceIdentity,
}

impl<F> FetchRange<F>
where
    F: FnMut(u64, usize) -> io::Result<Vec<u8>>,
{
    /// Builds a range source of `length` bytes with an opaque `identity`.
    fn new(length: u64, identity: SourceIdentity, fetch: F) -> Self {
        Self {
            fetch,
            length,
            identity,
        }
    }
}

impl<F> RangeSource for FetchRange<F>
where
    F: FnMut(u64, usize) -> io::Result<Vec<u8>>,
{
    fn len(&self) -> u64 {
        self.length
    }

    fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    fn read_range(&mut self, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let chunk = (self.fetch)(offset, output.len())?;
        // A well-behaved transport returns at most `output.len()` bytes; clamp
        // defensively so an over-eager provider can never overflow the buffer.
        let count = chunk.len().min(output.len());
        output[..count].copy_from_slice(&chunk[..count]);
        Ok(count)
    }
}

/// Formats an inclusive HTTP byte-range value, e.g. `bytes=0-1023`.
///
/// Every adapter here shares this value; the protocols differ only in which
/// header or request field carries it. `len` is always at least one because
/// [`RangeReader`] never issues an empty fetch.
fn byte_range_value(offset: u64, len: usize) -> String {
    let last = offset + len as u64 - 1;
    format!("bytes={offset}-{last}")
}

/// Range source over an **HTTP/HTTPS** endpoint that honors `Range: bytes=`.
///
/// `transport` performs one ranged `GET`: given the `bytes=<a>-<b>` value it
/// must set the `Range` request header, and return the `206 Partial Content`
/// body. The strong `ETag` is used as the immutable identity. No request is
/// made here — wire `transport` to any HTTP client.
fn http_range_source<T>(
    length: u64,
    etag: &[u8],
    mut transport: T,
) -> FetchRange<impl FnMut(u64, usize) -> io::Result<Vec<u8>>>
where
    T: FnMut(&str) -> io::Result<Vec<u8>>,
{
    let identity = SourceIdentity::new(etag.to_vec());
    FetchRange::new(length, identity, move |offset, len| {
        transport(&byte_range_value(offset, len))
    })
}

/// Range source over an **Amazon S3** object via `GetObject`.
///
/// `transport` issues one `GetObject` whose `Range` parameter is the supplied
/// `bytes=<a>-<b>` value and returns the response body. The object `VersionId`
/// (or `ETag`) is the immutable identity. No AWS SDK is linked — `transport`
/// stands in for `aws_sdk_s3::Client::get_object(...).range(...)`.
fn s3_range_source<T>(
    length: u64,
    version_id: &[u8],
    mut transport: T,
) -> FetchRange<impl FnMut(u64, usize) -> io::Result<Vec<u8>>>
where
    T: FnMut(&str) -> io::Result<Vec<u8>>,
{
    let identity = SourceIdentity::new(version_id.to_vec());
    FetchRange::new(length, identity, move |offset, len| {
        transport(&byte_range_value(offset, len))
    })
}

/// Range source over **Google Cloud Storage** media downloads.
///
/// `transport` performs one media download with the supplied `bytes=<a>-<b>`
/// value carried in the `Range` header, returning the partial body. The object
/// `generation` number is the immutable identity, so a rewritten object with a
/// new generation is rejected. No GCS SDK is linked.
fn gcs_range_source<T>(
    length: u64,
    generation: &[u8],
    mut transport: T,
) -> FetchRange<impl FnMut(u64, usize) -> io::Result<Vec<u8>>>
where
    T: FnMut(&str) -> io::Result<Vec<u8>>,
{
    let identity = SourceIdentity::new(generation.to_vec());
    FetchRange::new(length, identity, move |offset, len| {
        transport(&byte_range_value(offset, len))
    })
}

/// Range source over **Azure Blob Storage** via `Get Blob`.
///
/// `transport` issues one `Get Blob` request carrying the supplied
/// `bytes=<a>-<b>` value in the `x-ms-range` header and returns the body. The
/// blob `ETag` is the immutable identity. No Azure SDK is linked.
fn azure_range_source<T>(
    length: u64,
    etag: &[u8],
    mut transport: T,
) -> FetchRange<impl FnMut(u64, usize) -> io::Result<Vec<u8>>>
where
    T: FnMut(&str) -> io::Result<Vec<u8>>,
{
    let identity = SourceIdentity::new(etag.to_vec());
    FetchRange::new(length, identity, move |offset, len| {
        transport(&byte_range_value(offset, len))
    })
}

/// Serves a `bytes=<a>-<b>` range from an in-memory blob.
///
/// This stands in for a remote store during the example. A real transport would
/// perform the network request instead; the parsing here proves the header the
/// adapters build is well-formed and inclusive.
fn serve_range(blob: &[u8], range: &str) -> io::Result<Vec<u8>> {
    let spec = range.strip_prefix("bytes=").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "range must start with bytes=")
    })?;
    let (start, end) = spec
        .split_once('-')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "range must be start-end"))?;
    let start: usize = start
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad range start"))?;
    let end: usize = end
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad range end"))?;
    let slice = blob
        .get(start..=end)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "range out of bounds"))?;
    Ok(slice.to_vec())
}

/// Builds a small in-memory tar+gzip layer blob to exercise the adapters.
fn build_demo_layer() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let entries: [(&[u8], EntryKind, &[u8]); 3] = [
        (b"etc/", EntryKind::Dir, b""),
        (b"etc/hostname", EntryKind::File, b"oxide-node\n"),
        (b"usr/bin/tool", EntryKind::File, b"ELF binary payload"),
    ];
    let mut writer = ArchiveEngine::new().create(
        Vec::new(),
        CreateOptions::new()
            .with_format(FormatId::Tar)
            .with_filter(Some(FilterId::Gzip)),
    )?;
    for (path, kind, body) in entries {
        let metadata = EntryMetadata::builder(kind, ArchivePath::from_bytes(path.to_vec()))
            .size(Some(body.len() as u64))
            .build();
        writer.start_entry(&metadata)?;
        if !body.is_empty() {
            writer.write_data(body)?;
        }
        writer.end_entry()?;
    }
    Ok(writer.finish()?)
}

/// Streams every entry from a range-backed layer and returns its digests.
fn inspect<S: RangeSource>(
    source: S,
    label: &str,
) -> Result<LayerDigests, Box<dyn std::error::Error>> {
    // `RangeReader` gives the engine a `Read` view over the ranged source.
    let reader = RangeReader::new(source);
    let mut session = OciLayerEngine::new().open(reader)?;
    println!("--- {label} ---");
    while let Some(entry) = session.next_entry()? {
        println!(
            "  {} ({:?}, {} bytes)",
            String::from_utf8_lossy(entry.path()),
            entry.kind(),
            entry.size().unwrap_or(0),
        );
    }
    let digests = session.digests()?;
    println!("  compressed: {}", digests.compressed_descriptor());
    println!("  diffID:     {}", digests.diff_id_descriptor());
    Ok(digests)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let blob = build_demo_layer()?;
    let length = blob.len() as u64;
    println!("in-memory layer blob: {length} bytes\n");

    // Inspect the same blob through each cloud-flavored adapter. In production
    // the transport would hit HTTP, S3, GCS, or Azure; here it reads the local
    // blob so the example runs offline.
    let http = http_range_source(length, b"\"etag-http-v1\"", {
        let blob = blob.clone();
        move |range| serve_range(&blob, range)
    });
    let http_digests = inspect(http, "HTTP Range")?;

    let s3 = s3_range_source(length, b"s3-version-id-abc123", {
        let blob = blob.clone();
        move |range| serve_range(&blob, range)
    });
    let s3_digests = inspect(s3, "Amazon S3 GetObject")?;

    let gcs = gcs_range_source(length, b"1699999999000001", {
        let blob = blob.clone();
        move |range| serve_range(&blob, range)
    });
    let gcs_digests = inspect(gcs, "Google Cloud Storage")?;

    let azure = azure_range_source(length, b"0x8DABCDEF0123456", {
        let blob = blob.clone();
        move |range| serve_range(&blob, range)
    });
    let azure_digests = inspect(azure, "Azure Blob Storage")?;

    // Every adapter reads the identical bytes, so every digest pair must match.
    if s3_digests != http_digests || gcs_digests != http_digests || azure_digests != http_digests {
        return Err("range adapters disagreed on the layer digests".into());
    }
    println!("\nall four range adapters agree on the layer digests");

    // The same range source is `Read + Seek`, so it also feeds the applier,
    // which plans (and, given a filesystem adapter, would apply) the layer. The
    // plan is bound to the digests computed above and touches no filesystem.
    let planning_source = s3_range_source(length, b"s3-version-id-abc123", {
        let blob = blob.clone();
        move |range| serve_range(&blob, range)
    });
    let mut applier = OciLayerApplier::new(RangeReader::new(planning_source));
    let plan = applier.plan(http_digests, Policy::safe(), &IdentityOwnership)?;
    println!(
        "planned {} operation(s) from the range-backed blob (no filesystem touched)",
        plan.operations().len(),
    );

    Ok(())
}
