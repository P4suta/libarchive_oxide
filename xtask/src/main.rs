// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable repository checks that would otherwise require shell-specific scripts.

#![forbid(unsafe_code)]

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const CRATES: &[&str] = &[
    "libarchive_oxide-core",
    "libarchive_oxide-codecs",
    "libarchive_oxide",
    "libarchive_oxide-package",
    "libarchive_oxide-cli",
];
const LICENSES: &[&str] = &["Apache-2.0.txt", "MIT.txt"];
const PORTABLE_CODEC_FEATURES: &str = "portable-codecs,aes,sevenz,async,tokio";
const NATIVE_CODEC_FEATURES: &str = "native-codecs,aes,sevenz,async,tokio";
const FUZZ_NIGHTLY_TOOLCHAIN: &str = "+nightly-2026-07-29";
const BIG_ENDIAN_FEATURES: &str = "libarchive_oxide/portable-codecs,\
libarchive_oxide/aes,libarchive_oxide/sevenz,libarchive_oxide/async,\
libarchive_oxide/tokio";

const DEFLATE64_WRITE_NEGATIVE: &str = r"use libarchive_oxide::ZipMethod;

fn main() {
    let _ = ZipMethod::Deflate64;
}
";

const PACKAGE_CONSUMER_MAIN: &str = r#"use std::io::Cursor;

use libarchive_oxide::{
    ArchiveEngine, ArchiveReader, FilesystemAdapter, FilesystemAdapterError,
    FilesystemCapabilities, FilesystemEntry, FilesystemEntryReport, FilesystemFinding,
    FilesystemMaterialization, ReaderEvent, SeekArchiveReader,
};
use libarchive_oxide::advanced::{
    CodecCapabilities, FormatCapabilities, IncrementalCodecProvider,
    IncrementalFormatProvider, ProviderArchiveEncoder, Registry,
};
use libarchive_oxide_core::{
    AccessMode, ArchiveDecoder, ArchiveEncoder, ArchiveError, Codec, CodecStep, DecodeStep,
    DirectionSet, EncodeCommand, EncodeStep, EndOfInput, ErrorKind, FilterId, FormatId, Limits,
    ProbeResult,
};
use libarchive_oxide_package::{PackageVerifier, TrustPolicy};

struct ExternalDecoder;
impl ArchiveDecoder for ExternalDecoder {
    fn step<'a>(
        &'a mut self,
        _input: &'a [u8],
        _output: &'a mut [u8],
        _end: EndOfInput,
    ) -> Result<DecodeStep<'a>, ArchiveError> {
        Err(ArchiveError::new(libarchive_oxide_core::ErrorKind::Protocol))
    }
}

struct ExternalEncoder;
impl ArchiveEncoder for ExternalEncoder {
    fn step(
        &mut self,
        _command: EncodeCommand<'_>,
        _output: &mut [u8],
    ) -> Result<EncodeStep, ArchiveError> {
        Err(ArchiveError::new(libarchive_oxide_core::ErrorKind::Protocol))
    }
}
impl ProviderArchiveEncoder for ExternalEncoder {}

struct ExternalFormat;
impl IncrementalFormatProvider for ExternalFormat {
    fn format(&self) -> FormatId { FormatId::Tar }
    fn name(&self) -> &'static str { "package-smoke-format" }
    fn probe(&self, _prefix: &[u8]) -> ProbeResult<()> { ProbeResult::NoMatch }
    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities::uniform(DirectionSet::READ_WRITE, AccessMode::Sequential)
    }
    fn decoder(
        &self,
        _limits: Limits,
    ) -> Result<Box<dyn ArchiveDecoder + Send>, ArchiveError> {
        Ok(Box::new(ExternalDecoder))
    }
    fn encoder(
        &self,
        _limits: Limits,
    ) -> Result<Box<dyn ProviderArchiveEncoder + Send>, ArchiveError> {
        Ok(Box::new(ExternalEncoder))
    }
}

struct ExternalCodec;
impl Codec for ExternalCodec {
    fn process(
        &mut self,
        _input: &[u8],
        _output: &mut [u8],
        _end: EndOfInput,
    ) -> Result<CodecStep, ArchiveError> {
        Err(ArchiveError::new(libarchive_oxide_core::ErrorKind::Protocol))
    }
}
impl IncrementalCodecProvider for ExternalCodec {
    fn filter(&self) -> FilterId { FilterId::Gzip }
    fn name(&self) -> &'static str { "package-smoke-codec" }
    fn probe(&self, _prefix: &[u8]) -> ProbeResult<()> { ProbeResult::NoMatch }
    fn capabilities(&self) -> CodecCapabilities {
        CodecCapabilities::new(DirectionSet::READ_WRITE)
    }
    fn decoder(&self, _limits: Limits) -> Result<Box<dyn Codec + Send>, ArchiveError> {
        Ok(Box::new(ExternalCodec))
    }
    fn encode_frame(&self, input: &[u8], _limits: Limits) -> Result<Vec<u8>, ArchiveError> {
        Ok(input.to_vec())
    }
}

struct ExternalFilesystem;
impl FilesystemAdapter for ExternalFilesystem {
    fn capabilities(&self) -> FilesystemCapabilities {
        FilesystemCapabilities::none().with_atomic_commit(true)
    }
    fn begin_session(&mut self) -> Result<(), FilesystemAdapterError> { Ok(()) }
    fn begin_entry(&mut self, _entry: FilesystemEntry<'_>) -> Result<(), FilesystemAdapterError> {
        Ok(())
    }
    fn write_data(&mut self, _data: &[u8]) -> Result<(), FilesystemAdapterError> { Ok(()) }
    fn finish_entry(&mut self) -> Result<FilesystemEntryReport, FilesystemAdapterError> {
        Ok(FilesystemEntryReport::new(FilesystemMaterialization::Failed, Vec::new()))
    }
    fn abort_entry(&mut self) {}
    fn finish_session(&mut self) -> Result<Vec<FilesystemFinding>, FilesystemAdapterError> {
        Ok(Vec::new())
    }
}

fn method9_zip() -> Vec<u8> {
    let name = b"feature-off.bin";
    let compressed = [1_u8, 0, 0, 0xff, 0xff];
    let mut archive = Vec::new();
    archive.extend_from_slice(b"PK\x03\x04");
    archive.extend_from_slice(&21_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&9_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(name);
    archive.extend_from_slice(&compressed);

    let central_offset = archive.len() as u32;
    archive.extend_from_slice(b"PK\x01\x02");
    archive.extend_from_slice(&0x031e_u16.to_le_bytes());
    archive.extend_from_slice(&21_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&9_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.extend_from_slice(&0_u32.to_le_bytes());
    archive.extend_from_slice(name);

    let central_size = archive.len() as u32 - central_offset;
    archive.extend_from_slice(b"PK\x05\x06");
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive.extend_from_slice(&1_u16.to_le_bytes());
    archive.extend_from_slice(&1_u16.to_le_bytes());
    archive.extend_from_slice(&central_size.to_le_bytes());
    archive.extend_from_slice(&central_offset.to_le_bytes());
    archive.extend_from_slice(&0_u16.to_le_bytes());
    archive
}

fn assert_deflate64_is_listable_without_gzip() {
    let mut reader =
        SeekArchiveReader::new(Cursor::new(method9_zip())).expect("method-9 index must be readable");
    assert!(matches!(
        reader.next_event().expect("archive metadata"),
        ReaderEvent::ArchiveMetadata(_)
    ));
    let ReaderEvent::Entry(metadata) = reader.next_event().expect("method-9 entry") else {
        panic!("method-9 member must enumerate before decoding");
    };
    assert_eq!(metadata.path().as_bytes(), b"feature-off.bin");
    let error = reader
        .next_event()
        .expect_err("feature-off method 9 must be Unsupported");
    assert_eq!(
        error.archive_error().map(ArchiveError::kind),
        Some(ErrorKind::Unsupported)
    );
    reader.skip_entry().expect("unsupported entry remains skippable");
}

fn main() {
    let _filesystem = ExternalFilesystem;
    let mut registry = Registry::builder();
    registry.register_format(Box::new(ExternalFormat)).expect("register format");
    registry.register_codec(Box::new(ExternalCodec)).expect("register codec");
    let registry = registry.build();
    let _engine = ArchiveEngine::from_registry(&registry);
    let limits = Limits::safe();
    let _closed = registry.pipeline(limits);
    let mut reader = ArchiveReader::with_limits(Cursor::new(Vec::<u8>::new()), limits);
    let _event: Result<ReaderEvent<'_>, _> = reader.next_event();
    let verifier = PackageVerifier::new(TrustPolicy::offline());
    assert!(!verifier.trust_policy().allows_unsigned());
    #[cfg(any(feature = "portable-codecs", feature = "native-codecs"))]
    let _portable_codec = libarchive_oxide_codecs::gzip::GzipDecoder::new(limits);
    assert_deflate64_is_listable_without_gzip();
}
"#;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        },
    }
}

fn run() -> Result {
    let root = workspace_root()?;
    match env::args().nth(1).as_deref() {
        Some("license-sync") => check_license_sync(&root),
        Some("package-licenses") => check_package_licenses(&root),
        Some("package-smoke") => check_package_smoke(&root),
        Some("codec-policy") => check_codec_policy(&root),
        Some("capability-docs") => check_capability_docs(&root),
        Some("capability-docs-write") => write_capability_docs(&root),
        Some("release-policy") => check_release_policy(&root),
        Some("fuzz-ci") => run_fuzz_ci(&root),
        Some("big-endian-ci-compile") => compile_big_endian_ci(&root),
        Some("big-endian-ci") => run_big_endian_ci(&root),
        Some(command) => Err(format!("unknown command {command:?}").into()),
        None => Err(
            "expected one of: license-sync, package-licenses, package-smoke, \
             codec-policy, capability-docs, capability-docs-write, release-policy, fuzz-ci, \
             big-endian-ci-compile, big-endian-ci"
                .into(),
        ),
    }
}

fn check_capability_docs(root: &Path) -> Result {
    let path = root.join("docs/support-matrix.md");
    let expected = render_capability_docs()?;
    let actual = fs::read_to_string(&path)?;
    if actual == expected {
        println!("capability-docs: OK ({})", path.display());
        Ok(())
    } else {
        Err("docs/support-matrix.md is stale; run `just capability-docs-write`".into())
    }
}

fn write_capability_docs(root: &Path) -> Result {
    let path = root.join("docs/support-matrix.md");
    fs::write(&path, render_capability_docs()?)?;
    println!("capability-docs: wrote {}", path.display());
    Ok(())
}

fn render_capability_docs() -> Result<String> {
    use libarchive_oxide_core::{CAPABILITY_LEDGER, CapabilitySubject};

    let mut output = String::from(
        "# Support matrix\n\n\
         <!-- This file is generated by `just capability-docs-write`. Do not edit it manually. -->\n\n\
         This matrix is generated from the machine-readable `CAPABILITY_LEDGER` in\n\
         `libarchive_oxide-core`. A format or method is supported only in the directions shown;\n\
         an empty direction is a recognized, structured `Unsupported` path rather than a claim of\n\
         implementation. Cargo requirements must also be enabled in the consuming build.\n\n\
         ## Archive formats\n\n\
         | Format | Read access | Write access | Portable | Native | Requirements | Notes |\n\
         |---|---|---|---|---|---|---|\n",
    );
    for record in CAPABILITY_LEDGER {
        if !matches!(record.subject(), CapabilitySubject::Format(_)) {
            continue;
        }
        writeln!(
            output,
            "| {} | {} | {} | {} | {} | {} | {} |",
            record.name(),
            access_name(record.access().read()),
            access_name(record.access().write()),
            direction_name(record.portable()),
            direction_name(record.native()),
            requirement_name(record.requirements()),
            note_name(record.note()),
        )?;
    }

    output.push_str(
        "\n## Container methods\n\n\
         | Format | Method | Identifier | Read access | Write access | Portable | Native | Requirements | Notes |\n\
         |---|---|---|---|---|---|---|---|---|\n",
    );
    for record in CAPABILITY_LEDGER {
        let CapabilitySubject::Method { format, id } = record.subject() else {
            continue;
        };
        let format_name = libarchive_oxide_core::capability::format_capability(format)
            .map_or("custom", |format_record| format_record.name());
        writeln!(
            output,
            "| {format_name} | {} | {} | {} | {} | {} | {} | {} | {} |",
            record.name(),
            method_id_name(id),
            access_name(record.access().read()),
            access_name(record.access().write()),
            direction_name(record.portable()),
            direction_name(record.native()),
            requirement_name(record.requirements()),
            note_name(record.note()),
        )?;
    }

    output.push_str(
        "\n## Outer compression filters\n\n\
         | Filter | Read access | Write access | Portable | Native | Requirements | Notes |\n\
         |---|---|---|---|---|---|---|\n",
    );
    for record in CAPABILITY_LEDGER {
        if !matches!(record.subject(), CapabilitySubject::Filter(_)) {
            continue;
        }
        writeln!(
            output,
            "| {} | {} | {} | {} | {} | {} | {} |",
            record.name(),
            access_name(record.access().read()),
            access_name(record.access().write()),
            direction_name(record.portable()),
            direction_name(record.native()),
            requirement_name(record.requirements()),
            note_name(record.note()),
        )?;
    }
    output.push_str(
        "\nDirection values are `read`, `write`, `read/write`, or `—`. The portable and native\n\
         columns describe backend capability, not which Cargo features happen to be enabled in one\n\
         particular binary. Use `oxarchive capabilities --json` for build-specific `available`,\n\
         `disabled`, and `unsupported` states.\n",
    );
    Ok(output)
}

fn direction_name(directions: libarchive_oxide_core::DirectionSet) -> &'static str {
    use libarchive_oxide_core::Direction;

    match (
        directions.contains(Direction::Read),
        directions.contains(Direction::Write),
    ) {
        (true, true) => "read/write",
        (true, false) => "read",
        (false, true) => "write",
        (false, false) => "—",
    }
}

fn access_name(access: Option<libarchive_oxide_core::AccessMode>) -> &'static str {
    use libarchive_oxide_core::AccessMode;

    match access {
        Some(AccessMode::Sequential) => "sequential",
        Some(AccessMode::Seek) => "seek",
        Some(AccessMode::Filter) => "filter",
        Some(_) => "unknown",
        None => "—",
    }
}

fn method_id_name(id: libarchive_oxide_core::MethodId) -> String {
    use libarchive_oxide_core::MethodId;

    match id {
        MethodId::Numeric(value) => value.to_string(),
        MethodId::Bytes(bytes) => bytes
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(" "),
        MethodId::Name(name) => format!("`{name}`"),
        _ => "unknown".to_string(),
    }
}

fn requirement_name(requirements: &[&str]) -> String {
    if requirements.is_empty() {
        "—".to_string()
    } else {
        requirements
            .iter()
            .map(|requirement| format!("`{requirement}`"))
            .collect::<Vec<_>>()
            .join(" + ")
    }
}

fn note_name(note: &str) -> &str {
    if note.is_empty() { "—" } else { note }
}

fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask manifest has no workspace parent".into())
}

fn check_license_sync(root: &Path) -> Result {
    for crate_name in CRATES {
        let readme = root.join(crate_name).join("README.md");
        if fs::read_to_string(&readme)?.contains("](../") {
            return Err(format!(
                "published README escapes its crate tarball: {crate_name}/README.md"
            )
            .into());
        }
        for license in LICENSES {
            let canonical = fs::read(root.join("LICENSES").join(license))?;
            let copy_path = root.join(crate_name).join("LICENSES").join(license);
            let copy = fs::read(&copy_path).map_err(|error| {
                format!("cannot read license copy {}: {error}", copy_path.display())
            })?;
            if canonical != copy {
                return Err(
                    format!("license copy is stale: {crate_name}/LICENSES/{license}").into(),
                );
            }
        }
    }
    println!("all crate license copies match the repository license texts");
    Ok(())
}

fn check_package_licenses(root: &Path) -> Result {
    for crate_name in CRATES {
        let output = Command::new(cargo())
            .current_dir(root)
            .args(["package", "-p", crate_name, "--list", "--allow-dirty"])
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "cargo package --list failed for {crate_name}:\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        let listing = String::from_utf8(output.stdout)?;
        for license in LICENSES {
            let expected = format!("LICENSES/{license}");
            if !listing
                .lines()
                .any(|line| line.replace('\\', "/") == expected)
            {
                return Err(format!("{crate_name} package omits {expected}").into());
            }
        }
    }
    println!("all published crates package both canonical license texts");
    Ok(())
}

fn check_package_smoke(root: &Path) -> Result {
    let version = workspace_version(root)?;
    let status = Command::new(cargo())
        .current_dir(root)
        .args([
            "package",
            "--workspace",
            "--exclude",
            "xtask",
            "--allow-dirty",
            "--no-verify",
        ])
        .status()?;
    if !status.success() {
        return Err("cargo package failed for the publishable workspace".into());
    }

    let target = root.join("target");
    let smoke = target.join("package-consumer-smoke");
    if smoke.exists() {
        if !smoke.starts_with(&target) || smoke == target {
            return Err("refusing to replace package smoke directory outside target".into());
        }
        fs::remove_dir_all(&smoke)?;
    }
    let packages = smoke.join("packages");
    fs::create_dir_all(smoke.join("consumer").join("src"))?;
    fs::create_dir_all(&packages)?;
    for crate_name in CRATES {
        unpack_package(root, &packages, crate_name, &version)?;
    }

    let workspace_package_path =
        |name: &str| format!("packages/{name}-{version}").replace('\\', "/");
    let consumer_package_path =
        |name: &str| format!("../packages/{name}-{version}").replace('\\', "/");
    let core = workspace_package_path("libarchive_oxide-core");
    let codecs = workspace_package_path("libarchive_oxide-codecs");
    let flagship = workspace_package_path("libarchive_oxide");
    let package = workspace_package_path("libarchive_oxide-package");
    let cli = workspace_package_path("libarchive_oxide-cli");
    let consumer_core = consumer_package_path("libarchive_oxide-core");
    let consumer_codecs = consumer_package_path("libarchive_oxide-codecs");
    let consumer_flagship = consumer_package_path("libarchive_oxide");
    let consumer_package = consumer_package_path("libarchive_oxide-package");
    let workspace_manifest = format!(
        r#"[workspace]
resolver = "2"
members = ["consumer", "{core}", "{codecs}", "{flagship}", "{package}", "{cli}"]

[patch.crates-io]
libarchive_oxide-core = {{ path = "{core}" }}
libarchive_oxide-codecs = {{ path = "{codecs}" }}
libarchive_oxide = {{ path = "{flagship}" }}
libarchive_oxide-package = {{ path = "{package}" }}
"#
    );
    fs::write(smoke.join("Cargo.toml"), workspace_manifest)?;
    fs::write(
        smoke.join("consumer").join("Cargo.toml"),
        format!(
            r#"[package]
name = "libarchive_oxide-package-consumer"
version = "0.0.0"
edition = "2024"
publish = false

[features]
default = ["portable-codecs"]
portable-codecs = ["libarchive_oxide/portable-codecs", "libarchive_oxide-package/portable-codecs", "libarchive_oxide-codecs/gzip"]
native-codecs = ["libarchive_oxide/native-codecs", "libarchive_oxide-package/native-codecs", "libarchive_oxide-codecs/gzip"]

[dependencies]
libarchive_oxide = {{ path = "{consumer_flagship}", default-features = false }}
libarchive_oxide-package = {{ path = "{consumer_package}", default-features = false }}
libarchive_oxide-core = {{ path = "{consumer_core}" }}
libarchive_oxide-codecs = {{ path = "{consumer_codecs}" }}
"#
        ),
    )?;
    fs::write(
        smoke.join("consumer").join("src").join("main.rs"),
        PACKAGE_CONSUMER_MAIN,
    )?;

    check_packaged_profiles(&smoke)?;
    Ok(())
}

fn check_packaged_profiles(smoke: &Path) -> Result {
    for (profile, features) in [
        (
            "portable",
            "libarchive_oxide-package-consumer/portable-codecs,\
             libarchive_oxide-cli/portable-codecs,libarchive_oxide/async,libarchive_oxide/tokio",
        ),
        (
            "native",
            "libarchive_oxide-package-consumer/native-codecs,\
             libarchive_oxide-cli/native-codecs,libarchive_oxide/async,libarchive_oxide/tokio",
        ),
    ] {
        let status = Command::new(cargo())
            .current_dir(smoke)
            .args([
                "check",
                "--workspace",
                "--all-targets",
                "--no-default-features",
                "--features",
                features,
            ])
            .status()?;
        if !status.success() {
            return Err(format!(
                "external consumer failed to compile packaged crates with the {profile} profile"
            )
            .into());
        }
    }
    let feature_off = Command::new(cargo())
        .current_dir(smoke)
        .args([
            "run",
            "--package",
            "libarchive_oxide-package-consumer",
            "--no-default-features",
        ])
        .status()?;
    if !feature_off.success() {
        return Err(
            "external consumer failed the no-default-features Deflate64 runtime contract".into(),
        );
    }
    let examples = smoke.join("consumer").join("examples");
    fs::create_dir_all(&examples)?;
    fs::write(
        examples.join("deflate64_write.rs"),
        DEFLATE64_WRITE_NEGATIVE,
    )?;
    let no_write_surface = Command::new(cargo())
        .current_dir(smoke)
        .args([
            "check",
            "--package",
            "libarchive_oxide-package-consumer",
            "--example",
            "deflate64_write",
            "--no-default-features",
            "--features",
            "portable-codecs",
        ])
        .output()?;
    let no_write_stderr = String::from_utf8_lossy(&no_write_surface.stderr);
    if no_write_surface.status.success()
        || !no_write_stderr.contains("named `Deflate64` found for enum `ZipMethod`")
    {
        return Err(format!(
            "packaged Deflate64 write surface did not fail with the expected missing-variant \
             contract:\n{no_write_stderr}"
        )
        .into());
    }
    let combined = Command::new(cargo())
        .current_dir(smoke)
        .args([
            "check",
            "-p",
            "libarchive_oxide",
            "--features",
            "native-codecs",
        ])
        .status()?;
    if !combined.success() {
        return Err("packaged codec profiles are not additive in an external consumer".into());
    }
    println!(
        "packaged crates compile in portable and native profiles; no-default Deflate64 is listable \
         then Unsupported, Deflate64 has no write-method surface, and both backend profiles compile \
         together"
    );
    Ok(())
}
fn unpack_package(root: &Path, destination: &Path, crate_name: &str, version: &str) -> Result {
    let package_root = root.join("target").join("package");
    let target = root.join("target");
    if !destination.starts_with(&target) || destination == target {
        return Err("refusing to unpack package outside a target subdirectory".into());
    }
    let directory = destination.join(format!("{crate_name}-{version}"));
    if directory.exists() {
        if !directory.starts_with(destination) || directory == destination {
            return Err("refusing to replace staged package outside destination".into());
        }
        fs::remove_dir_all(&directory)?;
    }
    let archive = package_root.join(format!("{crate_name}-{version}.crate"));
    let status = Command::new("tar")
        .args(["-xzf"])
        .arg(&archive)
        .arg("-C")
        .arg(destination)
        .status()?;
    if !status.success() {
        return Err(format!("failed to unpack {}", archive.display()).into());
    }
    if !directory.join("Cargo.toml").is_file() {
        return Err(format!("package did not contain {crate_name}-{version}/Cargo.toml").into());
    }
    Ok(())
}

fn workspace_version(root: &Path) -> Result<String> {
    let manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    let mut in_workspace_package = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_workspace_package = trimmed == "[workspace.package]";
            continue;
        }
        if in_workspace_package && let Some(value) = trimmed.strip_prefix("version = ") {
            let version = value.trim().trim_matches('"');
            if !version.is_empty() {
                return Ok(version.to_owned());
            }
        }
    }
    Err("workspace.package version is missing".into())
}

fn check_codec_policy(root: &Path) -> Result {
    const PORTABLE_FORBIDDEN: &[&str] = &[
        "libz-sys",
        "libz-ng-sys",
        "bzip2-sys",
        "zstd",
        "zstd-safe",
        "zstd-sys",
        "xz2",
        "lzma-sys",
        "lz4",
        "lz4-sys",
    ];
    for (codec, profiles, required) in [
        (
            "gzip",
            ["gzip", "gzip,async,tokio"],
            &["miniz_oxide", "deflate64"][..],
        ),
        (
            "bzip2",
            ["bzip2", "bzip2,async,tokio"],
            &["libbz2-rs-sys"][..],
        ),
        ("zstd", ["zstd", "zstd,async,tokio"], &["ruzstd"][..]),
        ("xz", ["xz", "xz,async,tokio"], &["lzma-rust2"][..]),
        ("lz4", ["lz4", "lz4,async,tokio"], &["lz4_flex"][..]),
    ] {
        for features in profiles {
            require_dependency_profile(
                root,
                &format!("compatible portable {codec} ({features})"),
                features,
                required,
                PORTABLE_FORBIDDEN,
            )?;
        }
    }
    require_dependency_profile(
        root,
        "maximal portable-codecs",
        "portable-codecs,aes,sevenz,async,tokio",
        &[
            "miniz_oxide",
            "deflate64",
            "libbz2-rs-sys",
            "ruzstd",
            "lzma-rust2",
            "lz4_flex",
        ],
        PORTABLE_FORBIDDEN,
    )?;
    require_dependency_profile(
        root,
        "maximal native-codecs",
        "native-codecs,aes,sevenz,async,tokio",
        &[
            "deflate64",
            "libz-sys",
            "bzip2-sys",
            "zstd-sys",
            "lzma-sys",
            "lz4-sys",
        ],
        &[],
    )?;
    println!(
        "portable codec graphs exclude C/FFI packages; both profiles select the pure-Rust \
         Deflate64 decoder and the explicit native graph selects all five native backends"
    );
    Ok(())
}

fn require_dependency_profile(
    root: &Path,
    label: &str,
    features: &str,
    required: &[&str],
    forbidden: &[&str],
) -> Result {
    let output = Command::new(cargo())
        .current_dir(root)
        .args([
            "tree",
            "-p",
            "libarchive_oxide",
            "--no-default-features",
            "--features",
            features,
            "--edges",
            "normal,build",
            "--prefix",
            "none",
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo tree failed for {label}:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let tree = String::from_utf8(output.stdout)?;
    let package_names: Vec<&str> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    for package in required {
        if !package_names.contains(package) {
            return Err(format!("{label} does not select required package {package}").into());
        }
    }
    if let Some(package) = forbidden
        .iter()
        .find(|package| package_names.contains(package))
    {
        return Err(format!("{label} selected forbidden package {package}").into());
    }
    Ok(())
}
fn check_release_policy(root: &Path) -> Result {
    let release = fs::read_to_string(root.join(".github/workflows/release.yml"))?;
    let assets = fs::read_to_string(root.join(".github/workflows/release-assets.yml"))?;
    let bootstrap = fs::read_to_string(root.join(".github/workflows/bootstrap-publish.yml"))?;
    let release_plz = fs::read_to_string(root.join("release-plz.toml"))?;
    let contributing = fs::read_to_string(root.join("CONTRIBUTING.md"))?;
    let workspace_manifest = fs::read_to_string(root.join("Cargo.toml"))?;

    check_release_policy_contents(
        &release,
        &assets,
        &bootstrap,
        &release_plz,
        &contributing,
        &workspace_manifest,
    )?;
    println!(
        "release policy is version-frozen for development, manual-only, and \
         draft-before-final-publication"
    );
    Ok(())
}

fn check_release_policy_contents(
    release: &str,
    assets: &str,
    bootstrap: &str,
    release_plz: &str,
    contributing: &str,
    workspace_manifest: &str,
) -> Result {
    check_manual_only_workflow("release.yml", release)?;
    check_manual_only_workflow("release-assets.yml", assets)?;
    check_manual_only_workflow("bootstrap-publish.yml", bootstrap)?;
    require_all(
        "release.yml",
        release,
        &[
            "Type PREPARE or RELEASE",
            "inputs.operation == 'prepare'",
            "inputs.operation == 'publish'",
            "environment: release",
            "leaves the GitHub Release as a draft",
        ],
    )?;
    require_all(
        "release-assets.yml",
        assets,
        &[
            "Type PREFLIGHT without upload, or ASSETS with upload",
            "if: inputs.upload",
            "ref: refs/tags/${{ inputs.ref }}",
            "draft GitHub Release",
        ],
    )?;
    require_all(
        "bootstrap-publish.yml",
        bootstrap,
        &[
            "Type \"publish-0.2.0\"",
            "inputs.confirmation == 'publish-0.2.0'",
            "environment: release",
        ],
    )?;
    require_toml_assignment(
        "release-plz.toml",
        release_plz,
        "workspace",
        "semver_check",
        "false",
    )?;
    require_toml_assignment(
        "Cargo.toml",
        workspace_manifest,
        "workspace.package",
        "version",
        "\"0.2.0\"",
    )?;
    require_all(
        "release-plz.toml",
        release_plz,
        &[
            "git_release_enable = true",
            "git_release_draft = true",
            "git_tag_enable = true",
        ],
    )?;
    require_all(
        "CONTRIBUTING.md",
        contributing,
        &[
            "verify every draft asset",
            "Publish the completed draft Release manually",
            "Never automate",
        ],
    )?;
    Ok(())
}

fn check_manual_only_workflow(name: &str, workflow: &str) -> Result {
    let trigger = section_between(workflow, "\non:\n", "\npermissions:")
        .ok_or_else(|| format!("{name} has no recognizable trigger section"))?;
    if !trigger.trim_start().starts_with("workflow_dispatch:") {
        return Err(format!("{name} must start with workflow_dispatch").into());
    }

    for line in trigger.lines() {
        let without_comment = line.split_once('#').map_or(line, |(before, _)| before);
        let indent = without_comment
            .chars()
            .take_while(char::is_ascii_whitespace)
            .count();
        if indent == 2
            && let Some((event, _)) = without_comment.trim().split_once(':')
            && event != "workflow_dispatch"
        {
            return Err(format!("{name} contains non-manual trigger {event:?}").into());
        }
    }
    Ok(())
}

fn require_toml_assignment(
    name: &str,
    text: &str,
    section: &str,
    key: &str,
    expected: &str,
) -> Result {
    let mut current_section = "";
    for line in text.lines() {
        let without_comment = line.split_once('#').map_or(line, |(before, _)| before);
        let trimmed = without_comment.trim();
        if let Some(header) = trimmed
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            current_section = header.trim();
            continue;
        }
        if current_section == section
            && let Some((candidate, value)) = trimmed.split_once('=')
            && candidate.trim() == key
        {
            let actual = value.trim();
            if actual == expected {
                return Ok(());
            }
            return Err(
                format!("{name} [{section}].{key} must be {expected}, found {actual}").into(),
            );
        }
    }
    Err(format!("{name} is missing required [{section}].{key} = {expected}").into())
}

fn section_between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let after_start = text.split_once(start)?.1;
    Some(after_start.split_once(end)?.0)
}

fn require_all(name: &str, text: &str, required: &[&str]) -> Result {
    for needle in required {
        if !text.contains(needle) {
            return Err(format!("{name} is missing required policy marker {needle:?}").into());
        }
    }
    Ok(())
}

fn run_fuzz_ci(root: &Path) -> Result {
    let fuzz_target = env::var("FUZZ_TARGET")
        .map_err(|_| "FUZZ_TARGET must name the libFuzzer compilation target")?;

    for (profile, features) in [
        ("portable", PORTABLE_CODEC_FEATURES),
        ("native", NATIVE_CODEC_FEATURES),
    ] {
        run_command(
            root,
            cargo(),
            &[
                FUZZ_NIGHTLY_TOOLCHAIN,
                "test",
                "-Z",
                "panic-abort-tests",
                "-p",
                "libarchive_oxide",
                "--no-default-features",
                "--features",
                features,
                "--test",
                "filtered_io_v2",
                "malformed_zstd_block_does_not_panic",
            ],
            &format!("{profile} malformed-codec panic-abort regression"),
        )?;
    }

    run_command(
        root,
        cargo(),
        &[
            FUZZ_NIGHTLY_TOOLCHAIN,
            "fuzz",
            "build",
            "--target",
            &fuzz_target,
        ],
        "portable libFuzzer build",
    )?;
    run_command(
        root,
        cargo(),
        &[
            FUZZ_NIGHTLY_TOOLCHAIN,
            "fuzz",
            "build",
            "--no-default-features",
            "--features",
            "native-codecs",
            "--target",
            &fuzz_target,
        ],
        "native libFuzzer build",
    )?;

    let targets = fuzz_targets(root)?;
    for (profile, features, budget) in [
        ("portable", None, "30"),
        ("native", Some("native-codecs"), "10"),
    ] {
        for target in &targets {
            let mut arguments = vec![
                FUZZ_NIGHTLY_TOOLCHAIN.to_owned(),
                "fuzz".to_owned(),
                "run".to_owned(),
                target.clone(),
            ];
            if let Some(features) = features {
                arguments.extend([
                    "--no-default-features".to_owned(),
                    "--features".to_owned(),
                    features.to_owned(),
                ]);
            }
            arguments.extend([
                "--target".to_owned(),
                fuzz_target.clone(),
                "--".to_owned(),
                format!("-max_total_time={budget}"),
                "-rss_limit_mb=4096".to_owned(),
            ]);
            run_owned_command(
                root,
                cargo(),
                &arguments,
                &format!("{profile} fuzz {target}"),
            )?;
        }
    }
    Ok(())
}

fn fuzz_targets(root: &Path) -> Result<Vec<String>> {
    let output = Command::new(cargo())
        .current_dir(root)
        .args([FUZZ_NIGHTLY_TOOLCHAIN, "fuzz", "list"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo fuzz list failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let targets: Vec<String> = String::from_utf8(output.stdout)?
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    if targets.is_empty() {
        return Err("cargo fuzz list returned no targets".into());
    }
    Ok(targets)
}

fn compile_big_endian_ci(root: &Path) -> Result {
    run_command(
        root,
        if cfg!(windows) { "cross.exe" } else { "cross" },
        &[
            "test",
            "-p",
            "libarchive_oxide-core",
            "-p",
            "libarchive_oxide",
            "--no-default-features",
            "--features",
            BIG_ENDIAN_FEATURES,
            "--target",
            "s390x-unknown-linux-gnu",
            "--no-run",
        ],
        "compile big-endian s390x test binaries",
    )
}

fn run_big_endian_ci(root: &Path) -> Result {
    run_command(
        root,
        if cfg!(windows) { "cross.exe" } else { "cross" },
        &[
            "test",
            "-p",
            "libarchive_oxide-core",
            "-p",
            "libarchive_oxide",
            "--no-default-features",
            "--features",
            BIG_ENDIAN_FEATURES,
            "--target",
            "s390x-unknown-linux-gnu",
            "--",
            "--test-threads=1",
            "--nocapture",
            "--skip",
            "generated_256_mib_archive_streams_in_bounded_chunks",
            "--skip",
            "linux_reference_adapter_restores_mode_time_xattr_acl_and_sparse_layout",
            "--skip",
            "selected_xz_writer_is_deterministic_and_interoperable",
            "--skip",
            "corpus_files_replay_without_panic",
            "--skip",
            "arbitrary_seeds_uphold_invariants",
            "--skip",
            "seed_mutants_uphold_invariants",
            // The OCI layer tests measure compression throughput and multi-filter
            // rebuilds, not byte order: a multi-megabyte streaming hash and the
            // determinism batch that rebuilds every filter push the 15-minute
            // qemu gate over budget while the native OS jobs already run them for
            // real. Skip the heavy cases; the lighter uncompressed byte-order and
            // PAX checks still run here.
            "--skip",
            "large_layer_is_hashed_by_streaming",
            "--skip",
            "gzip_build_is_byte_identical_and_matches_reference",
            "--skip",
            "zstd_build_is_byte_identical_and_matches_reference",
            "--skip",
            "build_digests_round_trip_through_the_reader",
            "--skip",
            "entry_order_and_padding_are_reproducible_across_filters",
            "--skip",
            "unset_timestamps_never_inject_wall_clock",
        ],
        "big-endian s390x suite",
    )
}

fn run_command(root: &Path, program: &str, arguments: &[&str], description: &str) -> Result {
    run_command_with_env(root, program, arguments, &[], description)
}

fn run_command_with_env(
    root: &Path,
    program: &str,
    arguments: &[&str],
    environment: &[(&str, &str)],
    description: &str,
) -> Result {
    println!("xtask: {description}");
    let status = Command::new(program)
        .current_dir(root)
        .args(arguments)
        .envs(environment.iter().copied())
        .status()?;
    if !status.success() {
        return Err(format!("{description} failed with {status}").into());
    }
    Ok(())
}

fn run_owned_command(
    root: &Path,
    program: &str,
    arguments: &[String],
    description: &str,
) -> Result {
    println!("xtask: {description}");
    let status = Command::new(program)
        .current_dir(root)
        .args(arguments)
        .status()?;
    if !status.success() {
        return Err(format!("{description} failed with {status}").into());
    }
    Ok(())
}

fn cargo() -> &'static str {
    if cfg!(windows) { "cargo.exe" } else { "cargo" }
}

#[cfg(test)]
mod tests {
    use super::{
        check_manual_only_workflow, check_release_policy_contents, require_toml_assignment,
        section_between,
    };

    const VALID_RELEASE: &str = r"name: release
on:
  workflow_dispatch:
permissions:
  contents: read
description: Type PREPARE or RELEASE
prepare: inputs.operation == 'prepare'
publish: inputs.operation == 'publish'
environment: release
# leaves the GitHub Release as a draft
";
    const VALID_ASSETS: &str = r"name: assets
on:
  workflow_dispatch:
permissions:
  contents: read
description: Type PREFLIGHT without upload, or ASSETS with upload
if: inputs.upload
ref: refs/tags/${{ inputs.ref }}
# draft GitHub Release
";
    const VALID_BOOTSTRAP: &str = r#"name: bootstrap
on:
  workflow_dispatch:
    inputs:
      confirmation:
        description: Type "publish-0.2.0"
permissions:
  contents: read
if: inputs.confirmation == 'publish-0.2.0'
environment: release
"#;
    const VALID_RELEASE_PLZ: &str = r"[workspace]
semver_check = false

[[package]]
git_release_enable = true
git_release_draft = true
git_tag_enable = true
";
    const VALID_CONTRIBUTING: &str =
        "verify every draft asset\nPublish the completed draft Release manually\nNever automate\n";
    const VALID_WORKSPACE_MANIFEST: &str = r#"[workspace.package]
version = "0.2.0"
"#;

    #[test]
    fn workflow_trigger_section_is_bounded() {
        let workflow = "name: x\non:\n  workflow_dispatch:\npermissions:\n  contents: read\n";
        assert_eq!(
            section_between(workflow, "\non:\n", "\npermissions:"),
            Some("  workflow_dispatch:")
        );
        assert!(check_manual_only_workflow("test.yml", workflow).is_ok());
    }

    #[test]
    fn automatic_release_trigger_is_rejected() {
        let workflow = "name: x\non:\n  workflow_dispatch:\n  release:\n    types: [published]\npermissions:\n";
        assert!(check_manual_only_workflow("test.yml", workflow).is_err());
    }

    #[test]
    fn release_policy_fixture_is_accepted() {
        assert!(
            check_release_policy_contents(
                VALID_RELEASE,
                VALID_ASSETS,
                VALID_BOOTSTRAP,
                VALID_RELEASE_PLZ,
                VALID_CONTRIBUTING,
                VALID_WORKSPACE_MANIFEST,
            )
            .is_ok()
        );
    }

    #[test]
    fn semver_freeze_is_rejected() {
        let release_plz = VALID_RELEASE_PLZ.replace("semver_check = false", "semver_check = true");
        assert!(
            check_release_policy_contents(
                VALID_RELEASE,
                VALID_ASSETS,
                VALID_BOOTSTRAP,
                &release_plz,
                VALID_CONTRIBUTING,
                VALID_WORKSPACE_MANIFEST,
            )
            .is_err()
        );
    }

    #[test]
    fn workspace_version_bump_is_rejected() {
        let manifest = VALID_WORKSPACE_MANIFEST.replace("0.2.0", "0.3.0");
        assert!(
            check_release_policy_contents(
                VALID_RELEASE,
                VALID_ASSETS,
                VALID_BOOTSTRAP,
                VALID_RELEASE_PLZ,
                VALID_CONTRIBUTING,
                &manifest,
            )
            .is_err()
        );
    }

    #[test]
    fn automatic_bootstrap_trigger_is_rejected() {
        let bootstrap =
            VALID_BOOTSTRAP.replace("  workflow_dispatch:", "  workflow_dispatch:\n  push:");
        assert!(
            check_release_policy_contents(
                VALID_RELEASE,
                VALID_ASSETS,
                &bootstrap,
                VALID_RELEASE_PLZ,
                VALID_CONTRIBUTING,
                VALID_WORKSPACE_MANIFEST,
            )
            .is_err()
        );
    }

    #[test]
    fn bootstrap_without_typed_confirmation_is_rejected() {
        let bootstrap = VALID_BOOTSTRAP.replace(
            "inputs.confirmation == 'publish-0.2.0'",
            "inputs.confirmation != ''",
        );
        assert!(
            check_release_policy_contents(
                VALID_RELEASE,
                VALID_ASSETS,
                &bootstrap,
                VALID_RELEASE_PLZ,
                VALID_CONTRIBUTING,
                VALID_WORKSPACE_MANIFEST,
            )
            .is_err()
        );
    }

    #[test]
    fn bootstrap_without_protected_environment_is_rejected() {
        let bootstrap = VALID_BOOTSTRAP.replace("environment: release", "environment: staging");
        assert!(
            check_release_policy_contents(
                VALID_RELEASE,
                VALID_ASSETS,
                &bootstrap,
                VALID_RELEASE_PLZ,
                VALID_CONTRIBUTING,
                VALID_WORKSPACE_MANIFEST,
            )
            .is_err()
        );
    }

    #[test]
    fn commented_policy_assignment_does_not_count() {
        let config = "[workspace]\n# semver_check = false\nsemver_check = true\n";
        assert!(
            require_toml_assignment(
                "release-plz.toml",
                config,
                "workspace",
                "semver_check",
                "false",
            )
            .is_err()
        );
    }
}
