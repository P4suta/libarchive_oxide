// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable repository checks that would otherwise require shell-specific scripts.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fmt::{self, Display, Formatter, Write as _};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::string::FromUtf8Error;

use sha2::{Digest, Sha256};

type Result<T = ()> = std::result::Result<T, XtaskError>;

#[derive(Debug)]
enum XtaskError {
    Message(String),
    Io(std::io::Error),
    Format(fmt::Error),
    Utf8(FromUtf8Error),
}

impl Display for XtaskError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(message) => formatter.write_str(message),
            Self::Io(error) => Display::fmt(error, formatter),
            Self::Format(error) => Display::fmt(error, formatter),
            Self::Utf8(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for XtaskError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Message(_) => None,
            Self::Io(error) => Some(error),
            Self::Format(error) => Some(error),
            Self::Utf8(error) => Some(error),
        }
    }
}

impl From<&str> for XtaskError {
    fn from(message: &str) -> Self {
        Self::Message(message.to_owned())
    }
}

impl From<String> for XtaskError {
    fn from(message: String) -> Self {
        Self::Message(message)
    }
}

impl From<std::io::Error> for XtaskError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<fmt::Error> for XtaskError {
    fn from(error: fmt::Error) -> Self {
        Self::Format(error)
    }
}

impl From<FromUtf8Error> for XtaskError {
    fn from(error: FromUtf8Error) -> Self {
        Self::Utf8(error)
    }
}

const CRATES: &[&str] = &[
    "libarchive_oxide-protocol",
    "libarchive_oxide-core",
    "libarchive_oxide-codecs",
    "libarchive_oxide-ppmd",
    "libarchive_oxide-rar-crypto",
    "libarchive_oxide-rarvm",
    "libarchive_oxide-rar",
    "libarchive_oxide",
    "libarchive_oxide-package",
    "libarchive_oxide-cli",
];
const VENDORED_DELHARC_PACKAGE: &str = "libarchive_oxide-delharc";
const VENDORED_DELHARC_VERSION: &str = "0.8.0";
const DUAL_LICENSES: &[&str] = &["Apache-2.0.txt", "MIT.txt"];
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

#[cfg(feature = "aes-only")]
use std::sync::Arc;

use libarchive_oxide::{
    ArchiveEngine, ArchiveReader, ArchiveTranscoder, FilesystemAdapter, FilesystemAdapterError,
    FilesystemCapabilities, FilesystemEntry, FilesystemEntryReport, FilesystemFinding,
    FilesystemMaterialization, ReaderEvent, SeekArchiveBuilder, SeekArchiveReader,
};
#[cfg(feature = "aes-only")]
use libarchive_oxide::{OpenOptions, PasswordCandidates, SecretBytes};
use libarchive_oxide::advanced::{
    CodecCapabilities, CodecProvider, FormatCapabilities, FormatProvider, Pipeline,
    ProviderArchiveEncoder, ProviderSet,
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
impl FormatProvider for ExternalFormat {
    type Decoder = ExternalDecoder;
    type Encoder = ExternalEncoder;

    fn format(&self) -> FormatId { FormatId::Tar }
    fn name(&self) -> &'static str { "package-smoke-format" }
    fn probe(&self, _prefix: &[u8]) -> ProbeResult<()> { ProbeResult::NoMatch }
    fn capabilities(&self) -> FormatCapabilities {
        FormatCapabilities::uniform(DirectionSet::READ_WRITE, AccessMode::Sequential)
    }
    fn decoder(&self, _limits: Limits) -> Result<Self::Decoder, ArchiveError> {
        Ok(ExternalDecoder)
    }
    fn encoder(
        &self,
        _limits: Limits,
    ) -> Result<Self::Encoder, ArchiveError> {
        Ok(ExternalEncoder)
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
impl CodecProvider for ExternalCodec {
    type Decoder = ExternalCodec;

    fn filter(&self) -> FilterId { FilterId::Gzip }
    fn name(&self) -> &'static str { "package-smoke-codec" }
    fn probe(&self, _prefix: &[u8]) -> ProbeResult<()> { ProbeResult::NoMatch }
    fn capabilities(&self) -> CodecCapabilities {
        CodecCapabilities::new(DirectionSet::READ_WRITE)
    }
    fn decoder(&self, _limits: Limits) -> Result<Self::Decoder, ArchiveError> {
        Ok(ExternalCodec)
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

#[cfg(feature = "aes-only")]
fn assert_zipcrypto_deflate64_is_unsupported_without_gzip() {
    let mut archive = method9_zip();
    archive[6..8].copy_from_slice(&1_u16.to_le_bytes());
    let eocd = archive
        .windows(4)
        .rposition(|window| window == b"PK\x05\x06")
        .expect("method-9 EOCD");
    let central = usize::try_from(u32::from_le_bytes(
        archive[eocd + 16..eocd + 20]
            .try_into()
            .expect("method-9 central offset"),
    ))
    .expect("method-9 central offset fits usize");
    archive[central + 8..central + 10].copy_from_slice(&1_u16.to_le_bytes());
    let options = OpenOptions::new()
        .with_format(Some(FormatId::Zip))
        .with_password_provider(Arc::new(PasswordCandidates::new([SecretBytes::from(
            b"feature-off password".as_slice(),
        )])));
    let mut reader =
        ArchiveReader::with_options(Cursor::new(archive), &options).expect("encrypted reader");
    let error = reader
        .next_event()
        .expect_err("feature-off encrypted method 9 must be Unsupported");
    assert_eq!(error.kind(), ErrorKind::Unsupported);
}

fn main() {
    let _filesystem = ExternalFilesystem;
    let providers = ProviderSet::empty()
        .with_format_provider(ExternalFormat)
        .with_codec_provider(ExternalCodec);
    let _engine = ArchiveEngine::new()
        .with_format_provider(ExternalFormat)
        .with_codec_provider(ExternalCodec);
    let limits = Limits::safe();
    let _: libarchive_oxide_protocol::Limits = limits;
    let _closed = Pipeline::with_providers(limits, providers);
    let mut reader = ArchiveReader::with_limits(Cursor::new(Vec::<u8>::new()), limits);
    let _event: Result<ReaderEvent<'_>, _> = reader.next_event();
    let _seek_builder = SeekArchiveBuilder::new(
        Cursor::new(Vec::<u8>::new()),
        FormatId::Xar,
        limits,
    )
    .expect("packaged XAR seek builder");
    let _transcoder = ArchiveTranscoder::new();
    let verifier = PackageVerifier::new(TrustPolicy::offline());
    assert!(!verifier.trust_policy().allows_unsigned());
    #[cfg(any(feature = "portable-codecs", feature = "native-codecs"))]
    let _portable_codec = libarchive_oxide_codecs::gzip::GzipDecoder::new(limits);
    assert_deflate64_is_listable_without_gzip();
    #[cfg(feature = "aes-only")]
    assert_zipcrypto_deflate64_is_unsupported_without_gzip();
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
        Some("architecture") => check_architecture(&root),
        Some("ci-efficiency") => check_ci_efficiency(&root),
        Some("feature-matrix") => run_feature_matrix(&root),
        Some("codec-policy") => check_codec_policy(&root),
        Some("capability-docs") => check_capability_docs(&root),
        Some("capability-docs-write") => write_capability_docs(&root),
        Some("release-policy") => check_release_policy(&root),
        Some("fuzz-ci") => run_fuzz_ci(&root),
        Some("big-endian-ci-compile") => compile_big_endian_ci(&root),
        Some("big-endian-ci") => run_big_endian_ci(&root),
        Some(command) => Err(format!("unknown command {command:?}").into()),
        None => Err(
            "expected one of: license-sync, package-licenses, package-smoke, architecture, ci-efficiency, \
             feature-matrix, codec-policy, capability-docs, capability-docs-write, release-policy, \
             fuzz-ci, big-endian-ci-compile, big-endian-ci"
                .into(),
        ),
    }
}

fn check_ci_efficiency(root: &Path) -> Result {
    let justfile = fs::read_to_string(root.join("Justfile"))?;
    let feature_matrix_recipe = justfile
        .split_once("\nfeature-matrix:\n")
        .and_then(|(_, tail)| tail.split_once("\n\n"))
        .map(|(recipe, _)| recipe)
        .ok_or("missing feature-matrix recipe")?;
    if feature_matrix_recipe.trim() != "cargo run --quiet -p xtask -- feature-matrix" {
        return Err(
            "feature-matrix must use the source-derived xtask plan as its single entry point"
                .into(),
        );
    }
    if feature_matrix_recipe.contains("--feature-powerset") {
        return Err("feature-matrix must not restore the unrelated depth-two powerset".into());
    }
    let xtask = fs::read_to_string(root.join("xtask/src/main.rs"))?;
    if !xtask.contains(".env(\"CARGO_INCREMENTAL\", \"0\")") {
        return Err(
            "package smoke must share the workspace target without accumulating incrementals"
                .into(),
        );
    }
    if !justfile.contains("nextest_filter := \"not binary(fuzz_replay)\"") {
        return Err("nextest must exclude the separately optimized fuzz-replay binary".into());
    }
    for recipe in ["test: fuzz-replay", "test-ci: fuzz-replay"] {
        if !justfile.contains(recipe) {
            return Err(format!("missing mandatory optimized fuzz coverage: {recipe}").into());
        }
    }

    let nextest_lines = justfile
        .lines()
        .filter(|line| line.trim_start().starts_with("cargo nextest run"))
        .collect::<Vec<_>>();
    if nextest_lines.len() != 4
        || nextest_lines
            .iter()
            .any(|line| !line.contains("-E '{{nextest_filter}}'"))
    {
        return Err("every nextest profile must use the shared fuzz-replay exclusion".into());
    }

    let fuzz_recipe = justfile
        .split_once("\nfuzz-replay:\n")
        .and_then(|(_, tail)| tail.split_once("\n\n"))
        .map(|(recipe, _)| recipe)
        .ok_or("missing fuzz-replay recipe")?;
    if !justfile.contains("fuzz_test_threads := env_var_or_default(\"RUST_TEST_THREADS\", \"4\")") {
        return Err(
            "fuzz replay must default to four threads while honoring RUST_TEST_THREADS".into(),
        );
    }
    let fuzz_commands = fuzz_recipe
        .lines()
        .filter(|line| line.trim_start().starts_with("cargo test"))
        .collect::<Vec<_>>();
    if fuzz_commands.len() != 2
        || fuzz_commands
            .iter()
            .any(|line| !line.contains("-- --test-threads={{fuzz_test_threads}}"))
    {
        return Err("both fuzz replay profiles must use the bounded thread count".into());
    }
    for profile in [
        "portable-codecs,aes,sevenz,async,tokio",
        "native-codecs,aes,sevenz,async,tokio",
    ] {
        if !fuzz_recipe.contains("cargo test --release")
            || !fuzz_recipe.contains("--test fuzz_replay")
            || !fuzz_recipe.contains(profile)
        {
            return Err(format!("fuzz-replay must cover release profile {profile}").into());
        }
    }

    println!(
        "ci-efficiency: source-derived feature seams, all-target maximal profiles, nextest tests, and optimized portable/native fuzz replay remain automatic"
    );
    Ok(())
}

fn feature_seam_cells_from_text(source: &str, manifest: &str) -> Result<Vec<String>> {
    let implications = manifest_feature_implications(manifest)?;
    let mut cells = BTreeSet::new();
    for expression in cfg_attribute_expressions(source)? {
        let mut parser = CfgParser::new(expression);
        for mut cell in parser.parse()? {
            let redundant = cell
                .iter()
                .filter(|feature| {
                    cell.iter().any(|other| {
                        other != *feature
                            && feature_implies(other, feature, &implications, &mut BTreeSet::new())
                    })
                })
                .cloned()
                .collect::<Vec<_>>();
            for feature in redundant {
                cell.remove(&feature);
            }
            if cell.len() > 1 {
                cells.insert(cell.into_iter().collect::<Vec<_>>().join(","));
            }
        }
    }
    Ok(cells.into_iter().collect())
}

fn run_feature_matrix(root: &Path) -> Result {
    run_command(
        root,
        cargo(),
        &[
            "hack",
            "check",
            "--workspace",
            "--lib",
            "--each-feature",
            "--exclude",
            "xtask",
            "--exclude",
            "libarchive_oxide",
        ],
        "individual non-facade workspace features",
    )?;
    run_command(
        root,
        cargo(),
        &[
            "hack",
            "check",
            "-p",
            "libarchive_oxide",
            "--lib",
            "--each-feature",
            "--exclude-all-features",
        ],
        "individual facade features",
    )?;

    let source = read_rust_tree(&root.join("libarchive_oxide/src"))?;
    let manifest = fs::read_to_string(root.join("libarchive_oxide/Cargo.toml"))?;
    let seams = feature_seam_cells_from_text(&source, &manifest)?;
    println!(
        "xtask: {} source-derived facade feature seams: {}",
        seams.len(),
        seams.join("; ")
    );
    for seam in seams {
        run_owned_command(
            root,
            cargo(),
            &[
                "check".to_owned(),
                "-p".to_owned(),
                "libarchive_oxide".to_owned(),
                "--lib".to_owned(),
                "--no-default-features".to_owned(),
                "--features".to_owned(),
                seam.clone(),
            ],
            &format!("facade feature seam {seam}"),
        )?;
    }

    run_command(
        root,
        cargo(),
        &[
            "check",
            "--workspace",
            "--all-targets",
            "--no-default-features",
            "--features",
            "libarchive_oxide/portable-codecs,libarchive_oxide/native-codecs,libarchive_oxide/aes,libarchive_oxide/sevenz,libarchive_oxide/async,libarchive_oxide/tokio,libarchive_oxide-cli/portable-codecs,libarchive_oxide-cli/native-codecs",
        ],
        "combined portable/native all-target profile",
    )
}

fn read_rust_tree(directory: &Path) -> Result<String> {
    let mut entries = fs::read_dir(directory)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    let mut source = String::new();
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            source.push_str(&read_rust_tree(&path)?);
        } else if file_type.is_file() && path.extension().is_some_and(|extension| extension == "rs")
        {
            source.push_str(&fs::read_to_string(path)?);
            source.push('\n');
        }
    }
    Ok(source)
}

fn cfg_attribute_expressions(source: &str) -> Result<Vec<&str>> {
    const PREFIX: &str = "#[cfg(";
    let mut expressions = Vec::new();
    let mut offset = 0;
    while let Some(relative) = source[offset..].find(PREFIX) {
        let start = offset + relative + PREFIX.len();
        let mut depth = 1_usize;
        let mut quoted = false;
        let mut escaped = false;
        let mut end = start;
        for (relative, character) in source[start..].char_indices() {
            if quoted {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    quoted = false;
                }
            } else {
                match character {
                    '"' => quoted = true,
                    '(' => depth = depth.saturating_add(1),
                    ')' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            end = start + relative;
                            break;
                        }
                    },
                    _ => {},
                }
            }
        }
        if depth != 0 {
            return Err("unterminated #[cfg(...)] attribute".into());
        }
        expressions.push(&source[start..end]);
        offset = end + 1;
    }
    Ok(expressions)
}

type FeatureCell = BTreeSet<String>;

struct CfgParser<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> CfgParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            position: 0,
        }
    }

    fn parse(&mut self) -> Result<Vec<FeatureCell>> {
        let cells = self.parse_expression()?;
        self.skip_whitespace();
        if self.position != self.input.len() {
            return Err(format!(
                "unexpected trailing cfg expression at byte {}",
                self.position
            )
            .into());
        }
        Ok(cells)
    }

    fn parse_expression(&mut self) -> Result<Vec<FeatureCell>> {
        self.skip_whitespace();
        let name = self.parse_identifier()?;
        self.skip_whitespace();
        if self.consume(b'=') {
            self.skip_whitespace();
            let value = self.parse_string()?;
            if name == "feature" {
                return Ok(vec![BTreeSet::from([value])]);
            }
            return Ok(vec![BTreeSet::new()]);
        }
        if !self.consume(b'(') {
            return Ok(vec![BTreeSet::new()]);
        }

        if name == "not" {
            let _ = self.parse_expression()?;
            self.skip_whitespace();
            self.expect(b')')?;
            return Ok(vec![BTreeSet::new()]);
        }

        let mut arguments = Vec::new();
        loop {
            self.skip_whitespace();
            if self.consume(b')') {
                break;
            }
            arguments.push(self.parse_expression()?);
            self.skip_whitespace();
            if self.consume(b')') {
                break;
            }
            self.expect(b',')?;
        }

        match name.as_str() {
            "all" => {
                let mut product = vec![BTreeSet::new()];
                for alternatives in arguments {
                    let mut expanded = Vec::new();
                    for prefix in &product {
                        for alternative in &alternatives {
                            let mut cell = prefix.clone();
                            cell.extend(alternative.iter().cloned());
                            expanded.push(cell);
                        }
                    }
                    product = expanded;
                }
                Ok(product)
            },
            "any" => Ok(arguments.into_iter().flatten().collect()),
            _ => Ok(vec![BTreeSet::new()]),
        }
    }

    fn parse_identifier(&mut self) -> Result<String> {
        let start = self.position;
        while self.position < self.input.len()
            && (self.input[self.position].is_ascii_alphanumeric()
                || matches!(self.input[self.position], b'_' | b'-'))
        {
            self.position += 1;
        }
        if self.position == start {
            return Err(format!("expected cfg identifier at byte {start}").into());
        }
        Ok(String::from_utf8(
            self.input[start..self.position].to_vec(),
        )?)
    }

    fn parse_string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut value = Vec::new();
        let mut escaped = false;
        while self.position < self.input.len() {
            let byte = self.input[self.position];
            self.position += 1;
            if escaped {
                value.push(byte);
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                return Ok(String::from_utf8(value)?);
            } else {
                value.push(byte);
            }
        }
        Err("unterminated cfg string".into())
    }

    fn skip_whitespace(&mut self) {
        while self
            .input
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.input.get(self.position) == Some(&expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: u8) -> Result {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(format!(
                "expected {:?} in cfg expression at byte {}",
                char::from(expected),
                self.position
            )
            .into())
        }
    }
}

fn manifest_feature_implications(manifest: &str) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let mut values = BTreeMap::<String, Vec<String>>::new();
    let mut in_features = false;
    let mut current = None::<(String, String)>;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if current.is_none() && trimmed.starts_with('[') {
            if trimmed == "[features]" {
                in_features = true;
                continue;
            }
            if in_features {
                break;
            }
        }
        if !in_features || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((_, body)) = current.as_mut() {
            body.push_str(trimmed);
            if trimmed.contains(']') {
                let Some((name, body)) = current.take() else {
                    return Err("feature assignment state was lost".into());
                };
                values.insert(name, quoted_values(&body)?);
            }
            continue;
        }
        let Some((name, body)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name.trim().to_owned();
        let body = body.trim().to_owned();
        if body.contains(']') {
            values.insert(name, quoted_values(&body)?);
        } else {
            current = Some((name, body));
        }
    }
    if current.is_some() {
        return Err("unterminated feature array in manifest".into());
    }
    let names = values.keys().cloned().collect::<BTreeSet<_>>();
    Ok(values
        .into_iter()
        .map(|(name, dependencies)| {
            let local = dependencies
                .into_iter()
                .filter(|dependency| names.contains(dependency))
                .collect();
            (name, local)
        })
        .collect())
}

fn quoted_values(text: &str) -> Result<Vec<String>> {
    let mut values = Vec::new();
    let mut bytes = text.bytes().enumerate();
    while let Some((_, byte)) = bytes.next() {
        if byte != b'"' {
            continue;
        }
        let mut value = Vec::new();
        let mut escaped = false;
        let mut terminated = false;
        for (_, byte) in bytes.by_ref() {
            if escaped {
                value.push(byte);
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                terminated = true;
                break;
            } else {
                value.push(byte);
            }
        }
        if !terminated {
            return Err("unterminated quoted feature value".into());
        }
        values.push(String::from_utf8(value)?);
    }
    Ok(values)
}

fn feature_implies(
    feature: &str,
    target: &str,
    implications: &BTreeMap<String, BTreeSet<String>>,
    visited: &mut BTreeSet<String>,
) -> bool {
    if !visited.insert(feature.to_owned()) {
        return false;
    }
    implications.get(feature).is_some_and(|dependencies| {
        dependencies.contains(target)
            || dependencies
                .iter()
                .any(|dependency| feature_implies(dependency, target, implications, visited))
    })
}

fn check_architecture(root: &Path) -> Result {
    check_protocol_and_siblings(root)?;
    check_facade_layers(root)?;
    check_no_boxed_trait_objects(root)?;

    let core_root = fs::read_to_string(root.join("libarchive_oxide-core/src/lib.rs"))?;
    for required in ["ArchiveError", "Codec", "Limits"] {
        if !core_root.contains(required) {
            return Err(
                format!("core compatibility surface no longer re-exports {required}").into(),
            );
        }
    }

    println!(
        "architecture: protocol, PPMd, RAR crypto, and RARVM primitives remain isolated; format core, generic codecs, and RAR codecs remain separated; package and CLI use public facades; project-owned Rust has no boxed trait objects"
    );
    Ok(())
}

fn check_no_boxed_trait_objects(root: &Path) -> Result {
    for crate_directory in [
        "libarchive_oxide-protocol",
        "libarchive_oxide-core",
        "libarchive_oxide-codecs",
        "libarchive_oxide-ppmd",
        "libarchive_oxide-rar-crypto",
        "libarchive_oxide-rarvm",
        "libarchive_oxide-rar",
        "libarchive_oxide",
        "libarchive_oxide-package",
        "libarchive_oxide-cli",
        "fuzz/fuzz_lib",
        "fuzz/fuzz_targets",
        "xtask",
    ] {
        for source_directory in ["src", "tests", "examples", "benches"] {
            let path = root.join(crate_directory).join(source_directory);
            if !path.is_dir() {
                continue;
            }
            if let Some(found) = rust_tree_contains_boxed_trait_object(&path)? {
                return Err(format!(
                    "project-owned Rust must use enums, generics, or associated types instead of boxed trait objects: {}",
                    found.display()
                )
                .into());
            }
        }
    }
    for readme in [
        root.join("README.md"),
        root.join("libarchive_oxide/README.md"),
        root.join("libarchive_oxide-package/README.md"),
        root.join("libarchive_oxide-cli/README.md"),
    ] {
        if !readme.is_file() {
            continue;
        }
        let compact: String = fs::read_to_string(&readme)?
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        if compact.contains(concat!("Box<", "dynstd::error::Error>")) {
            return Err(format!(
                "public examples must use concrete errors instead of boxed trait objects: {}",
                readme.display()
            )
            .into());
        }
    }
    Ok(())
}

fn rust_tree_contains_boxed_trait_object(directory: &Path) -> Result<Option<PathBuf>> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            if let Some(found) = rust_tree_contains_boxed_trait_object(&path)? {
                return Ok(Some(found));
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let compact: String = fs::read_to_string(&path)?
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            if compact.contains(concat!("Box<", "dyn"))
                || compact.contains(concat!("Box::<", "dyn"))
            {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
}

fn check_protocol_and_siblings(root: &Path) -> Result {
    let protocol = root.join("libarchive_oxide-protocol");
    if !protocol.join("Cargo.toml").is_file() || !protocol.join("src/lib.rs").is_file() {
        return Err("missing standalone libarchive_oxide-protocol crate".into());
    }
    check_workspace_sibling_members(root)?;

    let protocol_manifest = fs::read_to_string(protocol.join("Cargo.toml"))?;
    reject_manifest_references(
        &protocol_manifest,
        "protocol crate",
        &[
            "libarchive_oxide-core",
            "libarchive_oxide-codecs",
            "libarchive_oxide-ppmd",
            "libarchive_oxide-rar-crypto",
            "libarchive_oxide-rarvm",
            "libarchive_oxide-rar",
            "libarchive_oxide =",
            "libarchive_oxide-package",
            "libarchive_oxide-cli",
        ],
    )?;
    reject_rust_references(
        &protocol.join("src"),
        "protocol source",
        &[
            "libarchive_oxide_core",
            "libarchive_oxide_codecs",
            "libarchive_oxide_ppmd",
            "libarchive_oxide_rar_crypto",
            "libarchive_oxide_rarvm",
            "libarchive_oxide_rar",
            "libarchive_oxide::",
            "libarchive_oxide_package",
            "libarchive_oxide_cli",
        ],
    )?;

    let core_manifest = fs::read_to_string(root.join("libarchive_oxide-core/Cargo.toml"))?;
    if !core_manifest.contains("libarchive_oxide-protocol") {
        return Err("format core must depend on the protocol crate".into());
    }
    reject_manifest_references(
        &core_manifest,
        "format core",
        &[
            "libarchive_oxide-codecs",
            "libarchive_oxide-ppmd",
            "libarchive_oxide-rar-crypto",
            "libarchive_oxide-rarvm",
            "libarchive_oxide-rar",
            "libarchive_oxide =",
            "libarchive_oxide-package",
            "libarchive_oxide-cli",
        ],
    )?;

    let codecs_manifest = fs::read_to_string(root.join("libarchive_oxide-codecs/Cargo.toml"))?;
    if !codecs_manifest.contains("libarchive_oxide-protocol") {
        return Err("codec crate must depend on the protocol crate".into());
    }
    reject_manifest_references(
        &codecs_manifest,
        "codec crate",
        &[
            "libarchive_oxide-core",
            "libarchive_oxide-ppmd",
            "libarchive_oxide-rar-crypto",
            "libarchive_oxide-rarvm",
            "libarchive_oxide =",
            "libarchive_oxide-package",
            "libarchive_oxide-cli",
        ],
    )?;
    reject_rust_references(
        &root.join("libarchive_oxide-codecs"),
        "codec crate",
        &[
            "libarchive_oxide_core",
            "libarchive_oxide_ppmd",
            "libarchive_oxide_rar_crypto",
            "libarchive_oxide_rarvm",
            "libarchive_oxide_rar",
        ],
    )?;

    if codecs_manifest.contains("compcol/rar3")
        || codecs_manifest.contains("compcol/rar5")
        || root.join("libarchive_oxide-codecs/src/rar.rs").exists()
    {
        return Err("generic codec crate must not own format-specific RAR algorithms".into());
    }

    check_ppmd_sibling(root)?;
    check_rar_crypto_sibling(root)?;
    check_rarvm_sibling(root)?;
    check_rar_sibling(root)
}

fn check_workspace_sibling_members(root: &Path) -> Result {
    let root_manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    for crate_name in [
        "libarchive_oxide-protocol",
        "libarchive_oxide-ppmd",
        "libarchive_oxide-rar-crypto",
        "libarchive_oxide-rarvm",
        "libarchive_oxide-rar",
    ] {
        if !root_manifest.contains(&format!("\"{crate_name}\"")) {
            return Err(format!("workspace must include {crate_name} explicitly").into());
        }
    }
    Ok(())
}

fn check_ppmd_sibling(root: &Path) -> Result {
    let ppmd = root.join("libarchive_oxide-ppmd");
    if !ppmd.join("Cargo.toml").is_file() || !ppmd.join("src/lib.rs").is_file() {
        return Err("missing standalone libarchive_oxide-ppmd crate".into());
    }
    let manifest = fs::read_to_string(ppmd.join("Cargo.toml"))?;
    reject_manifest_references(
        &manifest,
        "PPMd primitive crate",
        &[
            "libarchive_oxide-protocol",
            "libarchive_oxide-core",
            "libarchive_oxide-codecs",
            "libarchive_oxide-rar-crypto",
            "libarchive_oxide-rarvm",
            "libarchive_oxide-rar",
            "libarchive_oxide =",
            "libarchive_oxide-package",
            "libarchive_oxide-cli",
        ],
    )?;
    reject_rust_references(
        &ppmd.join("src"),
        "PPMd primitive crate",
        &[
            "libarchive_oxide_protocol",
            "libarchive_oxide_core",
            "libarchive_oxide_codecs",
            "libarchive_oxide_rar_crypto",
            "libarchive_oxide_rarvm",
            "libarchive_oxide_rar",
            "libarchive_oxide::",
        ],
    )?;
    Ok(())
}

fn check_rar_crypto_sibling(root: &Path) -> Result {
    let crypto = root.join("libarchive_oxide-rar-crypto");
    if !crypto.join("Cargo.toml").is_file() || !crypto.join("src/lib.rs").is_file() {
        return Err("missing standalone libarchive_oxide-rar-crypto crate".into());
    }
    let manifest = fs::read_to_string(crypto.join("Cargo.toml"))?;
    if !manifest.contains("license = \"ISC\"") {
        return Err("RAR crypto primitive crate must keep its separated ISC license".into());
    }
    reject_manifest_references(
        &manifest,
        "RAR crypto primitive crate",
        &[
            "libarchive_oxide-protocol",
            "libarchive_oxide-core",
            "libarchive_oxide-codecs",
            "libarchive_oxide-ppmd",
            "libarchive_oxide-rarvm",
            "libarchive_oxide =",
            "libarchive_oxide-package",
            "libarchive_oxide-cli",
        ],
    )?;
    reject_rust_references(
        &crypto.join("src"),
        "RAR crypto primitive crate",
        &[
            "libarchive_oxide_protocol",
            "libarchive_oxide_core",
            "libarchive_oxide_codecs",
            "libarchive_oxide_ppmd",
            "libarchive_oxide_rarvm",
            "libarchive_oxide_rar",
            "libarchive_oxide::",
        ],
    )?;
    Ok(())
}

fn check_rarvm_sibling(root: &Path) -> Result {
    let rarvm = root.join("libarchive_oxide-rarvm");
    if !rarvm.join("Cargo.toml").is_file() || !rarvm.join("src/lib.rs").is_file() {
        return Err("missing standalone libarchive_oxide-rarvm crate".into());
    }
    let manifest = fs::read_to_string(rarvm.join("Cargo.toml"))?;
    if !manifest.contains("license = \"BSD-2-Clause\"") {
        return Err("RARVM primitive crate must keep its separated BSD-2-Clause license".into());
    }
    reject_manifest_references(
        &manifest,
        "RARVM primitive crate",
        &[
            "libarchive_oxide-protocol",
            "libarchive_oxide-core",
            "libarchive_oxide-codecs",
            "libarchive_oxide-ppmd",
            "libarchive_oxide-rar-crypto",
            "libarchive_oxide =",
            "libarchive_oxide-package",
            "libarchive_oxide-cli",
        ],
    )?;
    reject_rust_references(
        &rarvm.join("src"),
        "RARVM primitive crate",
        &[
            "libarchive_oxide_protocol",
            "libarchive_oxide_core",
            "libarchive_oxide_codecs",
            "libarchive_oxide_ppmd",
            "libarchive_oxide_rar_crypto",
            "libarchive_oxide_rar",
            "libarchive_oxide::",
        ],
    )?;
    Ok(())
}

fn check_rar_sibling(root: &Path) -> Result {
    let rar = root.join("libarchive_oxide-rar");
    if !rar.join("Cargo.toml").is_file() || !rar.join("src/lib.rs").is_file() {
        return Err("missing standalone libarchive_oxide-rar crate".into());
    }
    let rar_manifest = fs::read_to_string(rar.join("Cargo.toml"))?;
    if !rar_manifest.contains("libarchive_oxide-protocol") {
        return Err("RAR codec crate must depend on the protocol crate".into());
    }
    if !rar_manifest.contains("libarchive_oxide-ppmd") {
        return Err("RAR codec crate must depend on the isolated PPMd primitive crate".into());
    }
    if !rar_manifest.contains("libarchive_oxide-rarvm") {
        return Err("RAR codec crate must depend on the isolated RARVM primitive crate".into());
    }
    if rar_manifest.contains("\"rar5\"") || !rar.join("src/rar5/decoder.rs").is_file() {
        return Err("RAR5 must remain locally owned instead of enabling compcol/rar5".into());
    }
    if rar_manifest.contains("features = [\"rar3\"]") || !rar.join("src/rar3/decoder.rs").is_file()
    {
        return Err("RAR3 must remain locally owned instead of enabling compcol/rar3".into());
    }
    if rar_manifest.contains("compcol") {
        return Err("RAR codec crate must not depend on the generic compcol collection".into());
    }
    reject_manifest_references(
        &rar_manifest,
        "RAR codec crate",
        &[
            "libarchive_oxide-core",
            "libarchive_oxide-codecs",
            "libarchive_oxide =",
            "libarchive_oxide-package",
            "libarchive_oxide-cli",
        ],
    )?;
    reject_rust_references(
        &rar.join("src"),
        "RAR codec crate",
        &["libarchive_oxide_core", "libarchive_oxide_codecs"],
    )?;
    Ok(())
}

fn check_facade_layers(root: &Path) -> Result {
    let flagship_manifest = fs::read_to_string(root.join("libarchive_oxide/Cargo.toml"))?;
    reject_manifest_references(
        &flagship_manifest,
        "flagship crate",
        &["libarchive_oxide-package", "libarchive_oxide-cli"],
    )?;

    let package_manifest = fs::read_to_string(root.join("libarchive_oxide-package/Cargo.toml"))?;
    if !package_manifest.contains("libarchive_oxide =") {
        return Err("package verification must compose through the flagship crate".into());
    }
    reject_manifest_references(
        &package_manifest,
        "package verification",
        &[
            "libarchive_oxide-protocol",
            "libarchive_oxide-core",
            "libarchive_oxide-codecs",
            "libarchive_oxide-ppmd",
            "libarchive_oxide-rar-crypto",
            "libarchive_oxide-rarvm",
            "libarchive_oxide-rar",
            "libarchive_oxide-cli",
        ],
    )?;
    reject_rust_references(
        &root.join("libarchive_oxide-package"),
        "package verification",
        &[
            "libarchive_oxide_core",
            "libarchive_oxide_codecs",
            "libarchive_oxide_ppmd",
            "libarchive_oxide_rar_crypto",
            "libarchive_oxide_rarvm",
            "libarchive_oxide_rar",
        ],
    )?;

    let cli_manifest = fs::read_to_string(root.join("libarchive_oxide-cli/Cargo.toml"))?;
    for required in ["libarchive_oxide =", "libarchive_oxide-package"] {
        if !cli_manifest.contains(required) {
            return Err(format!("CLI must compose through {required}").into());
        }
    }
    reject_manifest_references(
        &cli_manifest,
        "CLI",
        &[
            "libarchive_oxide-protocol",
            "libarchive_oxide-core",
            "libarchive_oxide-codecs",
            "libarchive_oxide-ppmd",
            "libarchive_oxide-rar-crypto",
            "libarchive_oxide-rarvm",
            "libarchive_oxide-rar",
        ],
    )?;
    reject_rust_references(
        &root.join("libarchive_oxide-cli"),
        "CLI",
        &[
            "libarchive_oxide_core",
            "libarchive_oxide_codecs",
            "libarchive_oxide_ppmd",
            "libarchive_oxide_rar_crypto",
            "libarchive_oxide_rarvm",
            "libarchive_oxide_rar",
        ],
    )?;
    Ok(())
}

fn reject_manifest_references(manifest: &str, layer: &str, forbidden: &[&str]) -> Result {
    for reference in forbidden {
        if manifest.contains(reference) {
            return Err(format!("{layer} contains forbidden dependency {reference}").into());
        }
    }
    Ok(())
}

fn reject_rust_references(directory: &Path, layer: &str, forbidden: &[&str]) -> Result {
    for reference in forbidden {
        if let Some(path) = rust_tree_contains(directory, reference)? {
            return Err(format!(
                "{layer} contains forbidden import {reference}: {}",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn rust_tree_contains(directory: &Path, needle: &str) -> Result<Option<PathBuf>> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            if let Some(found) = rust_tree_contains(&path, needle)? {
                return Ok(Some(found));
            }
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && fs::read_to_string(&path)?.contains(needle)
        {
            return Ok(Some(path));
        }
    }
    Ok(None)
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
        for license in crate_license_files(root, crate_name)? {
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

fn crate_license_files(root: &Path, crate_name: &str) -> Result<&'static [&'static str]> {
    let manifest = fs::read_to_string(root.join(crate_name).join("Cargo.toml"))?;
    if manifest.contains("license = \"BSD-2-Clause\"") {
        Ok(&["BSD-2-Clause.txt"])
    } else if manifest.contains("license = \"ISC\"") {
        Ok(&["ISC.txt"])
    } else if manifest.contains("license = \"Apache-2.0\"") {
        Ok(&["Apache-2.0.txt"])
    } else {
        Ok(DUAL_LICENSES)
    }
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
        for license in crate_license_files(root, crate_name)? {
            let expected = format!("LICENSES/{license}");
            if !listing
                .lines()
                .any(|line| line.replace('\\', "/") == expected)
            {
                return Err(format!("{crate_name} package omits {expected}").into());
            }
        }
    }
    let vendor_manifest = root.join("libarchive_oxide/vendor/delharc/Cargo.toml");
    let output = Command::new(cargo())
        .current_dir(root)
        .arg("package")
        .arg("--manifest-path")
        .arg(&vendor_manifest)
        .args(["--list", "--allow-dirty"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "cargo package --list failed for {VENDORED_DELHARC_PACKAGE}:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let listing = String::from_utf8(output.stdout)?;
    for license in ["LICENSE-APACHE", "LICENSE-MIT"] {
        if !listing
            .lines()
            .any(|line| line.replace('\\', "/") == license)
        {
            return Err(
                format!("{VENDORED_DELHARC_PACKAGE} package omits upstream {license}").into(),
            );
        }
    }
    println!(
        "published workspace crates package the canonical texts required by each manifest; the vendored LHA helper packages both upstream license texts"
    );
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
            "--exclude",
            "sevenz-rust2",
            "--allow-dirty",
            "--no-verify",
        ])
        .status()?;
    if !status.success() {
        return Err("cargo package failed for the publishable workspace".into());
    }

    let target = root.join("target");
    let smoke = target.join("package-consumer-smoke");
    let build_target = package_smoke_build_target(&smoke)?;
    if smoke.exists() {
        remove_package_smoke_workspace(&smoke, &build_target)?;
    }
    let packages_name = unpack_publishable_packages(root, &smoke, &version)?;

    let workspace_package_path =
        |name: &str| format!("{packages_name}/{name}-{version}").replace('\\', "/");
    let consumer_package_path =
        |name: &str| format!("../{packages_name}/{name}-{version}").replace('\\', "/");
    let protocol = workspace_package_path("libarchive_oxide-protocol");
    let core = workspace_package_path("libarchive_oxide-core");
    let codecs = workspace_package_path("libarchive_oxide-codecs");
    let ppmd = workspace_package_path("libarchive_oxide-ppmd");
    let rar_crypto = workspace_package_path("libarchive_oxide-rar-crypto");
    let rarvm = workspace_package_path("libarchive_oxide-rarvm");
    let rar = workspace_package_path("libarchive_oxide-rar");
    let flagship = workspace_package_path("libarchive_oxide");
    let package = workspace_package_path("libarchive_oxide-package");
    let cli = workspace_package_path("libarchive_oxide-cli");
    let delharc = format!("{packages_name}/{VENDORED_DELHARC_PACKAGE}-{VENDORED_DELHARC_VERSION}")
        .replace('\\', "/");
    let consumer_protocol = consumer_package_path("libarchive_oxide-protocol");
    let consumer_core = consumer_package_path("libarchive_oxide-core");
    let consumer_codecs = consumer_package_path("libarchive_oxide-codecs");
    let consumer_ppmd = consumer_package_path("libarchive_oxide-ppmd");
    let consumer_rar_crypto = consumer_package_path("libarchive_oxide-rar-crypto");
    let consumer_rarvm = consumer_package_path("libarchive_oxide-rarvm");
    let consumer_rar = consumer_package_path("libarchive_oxide-rar");
    let consumer_flagship = consumer_package_path("libarchive_oxide");
    let consumer_package = consumer_package_path("libarchive_oxide-package");
    let workspace_manifest = format!(
        r#"[workspace]
resolver = "2"
members = ["consumer", "{protocol}", "{core}", "{codecs}", "{ppmd}", "{rar_crypto}", "{rarvm}", "{rar}", "{flagship}", "{package}", "{cli}", "{delharc}"]

[patch.crates-io]
libarchive_oxide-delharc = {{ path = "{delharc}" }}
libarchive_oxide-protocol = {{ path = "{protocol}" }}
libarchive_oxide-core = {{ path = "{core}" }}
libarchive_oxide-codecs = {{ path = "{codecs}" }}
libarchive_oxide-ppmd = {{ path = "{ppmd}" }}
libarchive_oxide-rar-crypto = {{ path = "{rar_crypto}" }}
libarchive_oxide-rarvm = {{ path = "{rarvm}" }}
libarchive_oxide-rar = {{ path = "{rar}" }}
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
aes-only = ["libarchive_oxide/aes"]

[dependencies]
libarchive_oxide = {{ path = "{consumer_flagship}", default-features = false }}
libarchive_oxide-package = {{ path = "{consumer_package}", default-features = false }}
libarchive_oxide-protocol = {{ path = "{consumer_protocol}" }}
libarchive_oxide-core = {{ path = "{consumer_core}" }}
libarchive_oxide-codecs = {{ path = "{consumer_codecs}" }}
libarchive_oxide-ppmd = {{ path = "{consumer_ppmd}" }}
libarchive_oxide-rar-crypto = {{ path = "{consumer_rar_crypto}" }}
libarchive_oxide-rarvm = {{ path = "{consumer_rarvm}" }}
libarchive_oxide-rar = {{ path = "{consumer_rar}" }}
"#
        ),
    )?;
    fs::write(
        smoke.join("consumer").join("src").join("main.rs"),
        PACKAGE_CONSUMER_MAIN,
    )?;

    check_packaged_profiles(&smoke, &build_target)?;
    remove_package_smoke_workspace(&smoke, &build_target)?;
    Ok(())
}

fn package_smoke_build_target(smoke: &Path) -> Result<PathBuf> {
    if smoke.file_name().and_then(|name| name.to_str()) != Some("package-consumer-smoke") {
        return Err("package smoke workspace has an unexpected directory name".into());
    }
    smoke
        .parent()
        .filter(|parent| parent.file_name().and_then(|name| name.to_str()) == Some("target"))
        .map(Path::to_path_buf)
        .ok_or_else(|| "package smoke workspace must be a direct child of target".into())
}

fn remove_package_smoke_workspace(smoke: &Path, build_target: &Path) -> Result {
    if package_smoke_build_target(smoke)? != build_target {
        return Err("refusing to remove package smoke workspace outside its build target".into());
    }
    if smoke.exists() {
        fs::remove_dir_all(smoke)?;
    }
    Ok(())
}

fn packaged_cargo(smoke: &Path, build_target: &Path) -> Command {
    let mut command = Command::new(cargo());
    command
        .current_dir(smoke)
        .env("CARGO_TARGET_DIR", build_target)
        .env("CARGO_INCREMENTAL", "0");
    command
}

fn check_packaged_profiles(smoke: &Path, build_target: &Path) -> Result {
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
        let status = packaged_cargo(smoke, build_target)
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
    run_packaged_consumer(smoke, build_target, None, "no-default-features Deflate64")?;
    run_packaged_consumer(smoke, build_target, Some("aes-only"), "aes-only Deflate64")?;
    let examples = smoke.join("consumer").join("examples");
    fs::create_dir_all(&examples)?;
    fs::write(
        examples.join("deflate64_write.rs"),
        DEFLATE64_WRITE_NEGATIVE,
    )?;
    let no_write_surface = packaged_cargo(smoke, build_target)
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
    let combined = packaged_cargo(smoke, build_target)
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
         then Unsupported, aes-only ZipCrypto Deflate64 is also Unsupported, Deflate64 has no \
         write-method surface, the Safe-Rust LHA helper remains locally resolved, and both backend \
         profiles compile together"
    );
    Ok(())
}

fn run_packaged_consumer(
    smoke: &Path,
    build_target: &Path,
    features: Option<&str>,
    contract: &str,
) -> Result {
    let mut command = packaged_cargo(smoke, build_target);
    command.args([
        "run",
        "--package",
        "libarchive_oxide-package-consumer",
        "--no-default-features",
    ]);
    if let Some(features) = features {
        command.args(["--features", features]);
    }
    if !command.status()?.success() {
        return Err(format!("external consumer failed the {contract} runtime contract").into());
    }
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

fn unpack_publishable_packages(root: &Path, smoke: &Path, version: &str) -> Result<String> {
    let package_cache_key = package_archive_fingerprint(root, version)?;
    let packages_name = format!("packages-{package_cache_key}");
    let packages = smoke.join(&packages_name);
    fs::create_dir_all(smoke.join("consumer").join("src"))?;
    fs::create_dir_all(&packages)?;
    for crate_name in CRATES {
        unpack_package(root, &packages, crate_name, version)?;
    }
    unpack_package(
        root,
        &packages,
        VENDORED_DELHARC_PACKAGE,
        VENDORED_DELHARC_VERSION,
    )?;
    Ok(packages_name)
}

fn package_archive_fingerprint(root: &Path, version: &str) -> Result<String> {
    let package_root = root.join("target").join("package");
    let mut fingerprint = Sha256::new();
    for (crate_name, crate_version) in
        CRATES
            .iter()
            .map(|name| (*name, version))
            .chain(core::iter::once((
                VENDORED_DELHARC_PACKAGE,
                VENDORED_DELHARC_VERSION,
            )))
    {
        let archive = package_root.join(format!("{crate_name}-{crate_version}.crate"));
        let bytes = fs::read(&archive).map_err(|error| {
            format!(
                "cannot fingerprint packaged archive {}: {error}",
                archive.display()
            )
        })?;
        fingerprint_bytes(&mut fingerprint, crate_name.as_bytes());
        fingerprint_bytes(&mut fingerprint, crate_version.as_bytes());
        fingerprint_bytes(&mut fingerprint, &bytes);
    }
    finish_fingerprint(fingerprint)
}

fn fingerprint_bytes(fingerprint: &mut Sha256, bytes: &[u8]) {
    // Include the length so adjacent archive/name boundaries cannot alias a different sequence of byte strings with the same concatenation.
    fingerprint.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    fingerprint.update(bytes);
}

fn finish_fingerprint(fingerprint: Sha256) -> Result<String> {
    let digest = fingerprint.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(encoded)
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
    check_vendored_deflate64(root)?;
    check_vendored_delharc(root)?;
    check_vendored_sevenz_rust2(root)?;
    for (codec, profiles, required) in [
        ("gzip", ["gzip", "gzip,async,tokio"], &["miniz_oxide"][..]),
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
        &["libz-sys", "bzip2-sys", "zstd-sys", "lzma-sys", "lz4-sys"],
        &[],
    )?;
    println!(
        "portable codec graphs exclude C/FFI packages; both profiles compile the pinned vendored \
         pure-Rust Deflate64 decoder and the explicit native graph selects all five native backends"
    );
    Ok(())
}

fn check_vendored_deflate64(root: &Path) -> Result {
    let vendor = root.join("libarchive_oxide/vendor/deflate64");
    for relative in [
        "LICENSE",
        "UPSTREAM.md",
        "src/lib.rs",
        "src/inflater_managed.rs",
    ] {
        if !vendor.join(relative).is_file() {
            return Err(format!("vendored Deflate64 source is missing {relative}").into());
        }
    }
    let provenance = fs::read_to_string(vendor.join("UPSTREAM.md"))?;
    for required in [
        "deflate64` 0.1.12",
        "ac6b926516df9c60bfa16e107b21086399f8285a44ca9711344b9e553c5146e2",
        "License: MIT",
    ] {
        if !provenance.contains(required) {
            return Err(format!("vendored Deflate64 provenance is missing {required:?}").into());
        }
    }
    Ok(())
}

fn check_vendored_delharc(root: &Path) -> Result {
    let vendor = root.join("libarchive_oxide/vendor/delharc");
    for relative in [
        "Cargo.toml",
        "LICENSE-APACHE",
        "LICENSE-MIT",
        "UPSTREAM.md",
        "src/lib.rs",
        "src/decode/pmarc/pm1.rs",
        "src/decode/pmarc/pm2.rs",
    ] {
        if !vendor.join(relative).is_file() {
            return Err(format!("vendored delharc source is missing {relative}").into());
        }
    }
    let provenance = fs::read_to_string(vendor.join("UPSTREAM.md"))?;
    for required in [
        "delharc` 0.8.0",
        "ea1d90f1febb75e3aa9b53c45f170127074a0fba",
        "9cfdcd2bee8dc367afd9064f3b0849156a4c29fc70d98370dae62773594d04dd",
        "License: MIT OR Apache-2.0",
        "Rust 1.88",
    ] {
        if !provenance.contains(required) {
            return Err(format!("vendored delharc provenance is missing {required:?}").into());
        }
    }
    let manifest = fs::read_to_string(vendor.join("Cargo.toml"))?;
    for required in [
        "name = \"libarchive_oxide-delharc\"",
        "name = \"delharc\"",
        "rust-version = \"1.88\"",
    ] {
        if !manifest.contains(required) {
            return Err(format!("vendored delharc manifest is missing {required:?}").into());
        }
    }
    let crate_root = fs::read_to_string(vendor.join("src/lib.rs"))?;
    if !crate_root.contains("#![forbid(unsafe_code)]") {
        return Err("vendored delharc must forbid unsafe code".into());
    }
    if !crate_root.contains("#![allow(clippy::all)]") {
        return Err("vendored delharc must isolate upstream Clippy style".into());
    }
    for (relative, forbidden) in [
        ("src/stub_io.rs", ".assume_init_mut("),
        ("src/header/parser.rs", ".assume_init_mut("),
        ("src/header/parser.rs", ".as_array::<"),
        ("src/decode/lhv2.rs", ".strict_shl("),
    ] {
        let source = fs::read_to_string(vendor.join(relative))?;
        if source.contains(forbidden) {
            return Err(format!(
                "vendored delharc {relative} reintroduced post-MSRV API {forbidden}"
            )
            .into());
        }
    }
    Ok(())
}

fn check_vendored_sevenz_rust2(root: &Path) -> Result {
    let vendor = root.join("libarchive_oxide/vendor/sevenz-rust2");
    for relative in [
        "Cargo.toml",
        "LICENSE",
        "UPSTREAM.md",
        "src/lib.rs",
        "src/reader.rs",
        "src/writer.rs",
    ] {
        if !vendor.join(relative).is_file() {
            return Err(format!("vendored sevenz-rust2 source is missing {relative}").into());
        }
    }
    let provenance = fs::read_to_string(vendor.join("UPSTREAM.md"))?;
    for required in [
        "sevenz-rust2` 0.21.3",
        "e5d33dbe62c698d71ecd31f705de0e5a9fc45520",
        "0b5d71c87d24cb22976f3f6e6c2c9296ef1f6958394e2b868d56ca01b082798a",
        "License: Apache-2.0",
        "Rust 1.88",
        "nt-time` 0.13.0",
    ] {
        if !provenance.contains(required) {
            return Err(format!("vendored sevenz-rust2 provenance is missing {required:?}").into());
        }
    }
    let manifest = fs::read_to_string(vendor.join("Cargo.toml"))?;
    for required in [
        "rust-version = \"1.88\"",
        "nt-time = { version = \"=0.13.0\"",
    ] {
        if !manifest.contains(required) {
            return Err(format!("vendored sevenz-rust2 manifest is missing {required:?}").into());
        }
    }
    let crate_root = fs::read_to_string(vendor.join("src/lib.rs"))?;
    if !crate_root.contains("#![forbid(unsafe_code)]") {
        return Err("vendored sevenz-rust2 must forbid unsafe code".into());
    }
    if !crate_root.contains("#![allow(clippy::all)]") {
        return Err("vendored sevenz-rust2 must isolate upstream Clippy style".into());
    }
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
            "seed_mutants_",
            // The OCI layer tests measure compression throughput and multi-filter rebuilds, not byte order: a multi-megabyte streaming hash and the determinism batch that rebuilds every filter push the 15-minute qemu gate over budget while the native OS jobs already run them for real.
            // Skip the heavy cases; the lighter uncompressed byte-order and PAX checks still run here.
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
    use std::io::Write as _;
    use std::path::Path;
    use std::process::{Command, Stdio};

    use super::{
        check_manual_only_workflow, check_release_policy_contents, feature_seam_cells_from_text,
        fingerprint_bytes, finish_fingerprint, package_smoke_build_target, packaged_cargo,
        require_toml_assignment, section_between,
    };
    use sha2::Sha256;

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

    #[test]
    fn package_source_fingerprint_tracks_contents_and_boundaries() {
        let fingerprint = |parts: &[&[u8]]| {
            let mut digest = Sha256::default();
            for part in parts {
                fingerprint_bytes(&mut digest, part);
            }
            finish_fingerprint(digest).unwrap()
        };
        let first = fingerprint(&[b"ab", b"c"]);
        let different_boundary = fingerprint(&[b"a", b"bc"]);
        let different_content = fingerprint(&[b"ab", b"d"]);
        assert_ne!(first, different_boundary);
        assert_ne!(first, different_content);
        assert_eq!(first, fingerprint(&[b"ab", b"c"]));
    }
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

    fn assert_summary(payload: &str, expected_count: usize, expected: &str, accepted: bool) {
        let predicate =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/required-results.jq");
        let mut child = Command::new("jq")
            .args(["-e", "--arg", "expected_result", expected])
            .args(["--argjson", "expected_count", &expected_count.to_string()])
            .arg("-f")
            .arg(predicate)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the pinned jq");
        let mut input = child.stdin.take().expect("piped summary input");
        input
            .write_all(payload.as_bytes())
            .expect("write summary input");
        drop(input);
        let output = child.wait_with_output().expect("collect summary verdict");
        assert_eq!(
            output.status.code(),
            Some(i32::from(!accepted)),
            "count={expected_count}, expected={expected}, input={payload}, stderr={}",
            std::str::from_utf8(&output.stderr).expect("jq diagnostics are UTF-8")
        );
    }

    #[test]
    fn required_summary_rejects_missing_failed_and_skipped_work() {
        assert_summary(r#"["success","success"]"#, 2, "success", true);
        for payload in [
            "[]",
            r#"["success"]"#,
            r#"["success","success","success"]"#,
            r#"["success","failure"]"#,
            r#"["success","cancelled"]"#,
            r#"["success","skipped"]"#,
            r#"["success",null]"#,
            r#"["success","unknown"]"#,
            "null",
            "true",
            "{}",
            r#"{"fast":"success","ci-required":"success"}"#,
        ] {
            assert_summary(payload, 2, "success", false);
        }
    }

    #[test]
    fn full_summary_requires_every_job_to_match_its_phase() {
        for expected in ["success", "skipped"] {
            let mut states = vec![format!("\"{expected}\""); 19];
            assert_summary(&format!("[{}]", states.join(",")), 19, expected, true);
            for index in 0..states.len() {
                for invalid in ["failure", "cancelled", "unknown", "success", "skipped"] {
                    if invalid == expected {
                        continue;
                    }
                    states[index] = format!("\"{invalid}\"");
                    assert_summary(&format!("[{}]", states.join(",")), 19, expected, false);
                }
                states[index] = format!("\"{expected}\"");
            }
        }
    }

    #[test]
    fn feature_seams_follow_positive_cfg_conjunctions_and_manifest_implications() {
        let source = r#"
#[cfg(all(feature = "aes", any(feature = "bzip2", feature = "xz")))]
struct EncryptedCodec;
#[cfg(all(feature = "rar", feature = "aes"))]
struct EncryptedRar;
#[cfg(all(feature = "native-codecs", feature = "zstd"))]
struct NativeZstd;
#[cfg(all(not(feature = "rar"), feature = "aes"))]
struct AesWithoutRar;
#[cfg(any(feature = "cab-lzx", feature = "cab-quantum"))]
struct EitherCabCodec;
#[cfg(all(feature = "gamma", feature = "alpha", feature = "beta"))]
struct ThreeWaySeam;
"#;
        let manifest = r#"
[features]
default = ["portable-codecs"]
native-codecs = ["native-backend", "dep:native-zstd", "native-zstd/zstd"]
native-backend = ["zstd"]
zstd = []
portable-codecs = ["zstd"]
"#;

        assert_eq!(
            feature_seam_cells_from_text(source, manifest).unwrap(),
            ["aes,bzip2", "aes,rar", "aes,xz", "alpha,beta,gamma",]
        );
    }

    #[test]
    fn malformed_cfg_attributes_fail_closed() {
        let malformed = r#"#[cfg(all(feature = "aes", feature = "gzip")"#;
        assert!(feature_seam_cells_from_text(malformed, "[features]\naes = []\n").is_err());
    }

    #[test]
    fn package_smoke_reuses_only_its_parent_target_directory() {
        assert_eq!(
            package_smoke_build_target(Path::new("repo/target/package-consumer-smoke"))
                .expect("canonical smoke path"),
            Path::new("repo/target")
        );
        assert!(
            package_smoke_build_target(Path::new("repo/target/not-the-smoke-workspace")).is_err()
        );
        assert!(package_smoke_build_target(Path::new("package-consumer-smoke")).is_err());

        let command = packaged_cargo(
            Path::new("repo/target/package-consumer-smoke"),
            Path::new("repo/target"),
        );
        assert!(command.get_envs().any(|(name, value)| {
            name == "CARGO_TARGET_DIR"
                && value.is_some_and(|value| value == Path::new("repo/target"))
        }));
        assert!(command.get_envs().any(|(name, value)| {
            name == "CARGO_INCREMENTAL" && value.is_some_and(|value| value == "0")
        }));
    }

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
