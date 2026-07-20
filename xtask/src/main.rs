// SPDX-FileCopyrightText: 2026 libarchive_oxide contributors
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Portable repository checks that would otherwise require shell-specific scripts.

#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const CRATES: &[&str] = &[
    "libarchive_oxide-core",
    "libarchive_oxide",
    "libarchive_oxide-cli",
];
const LICENSES: &[&str] = &["Apache-2.0.txt", "MIT.txt"];
const SOURCE_TREES: &[&str] = &[
    "libarchive_oxide-core/src",
    "libarchive_oxide/src",
    "libarchive_oxide-cli/src",
];
const PORTABLE_CODEC_FEATURES: &str = "portable-codecs,aes,sevenz,async,tokio";
const NATIVE_CODEC_FEATURES: &str = "native-codecs,aes,sevenz,async,tokio";
const BIG_ENDIAN_FEATURES: &str = "libarchive_oxide/portable-codecs,\
libarchive_oxide/aes,libarchive_oxide/sevenz,libarchive_oxide/async,\
libarchive_oxide/tokio";

const PACKAGE_CONSUMER_MAIN: &str = r#"use std::io::Cursor;

use libarchive_oxide::{
    ArchiveEngine, ArchiveReader, CodecCapabilities, CodecProvider, FilesystemAdapter,
    FilesystemAdapterError, FilesystemCapabilities, FilesystemEntry, FilesystemEntryReport,
    FilesystemFinding, FilesystemMaterialization, FormatCapabilities, FormatProvider,
    ProviderArchiveEncoder, ProviderSet, ReaderEvent,
};
use libarchive_oxide_core::{
    ArchiveDecoder, ArchiveEncoder, ArchiveError, Codec, CodecStep, DecodeStep, EncodeCommand,
    EncodeStep, EndOfInput, FilterId, FormatId, Limits, ProbeResult,
};

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
        FormatCapabilities::new(true, true, false)
    }
    fn decoder(&self, _limits: Limits) -> Result<Self::Decoder, ArchiveError> {
        Ok(ExternalDecoder)
    }
    fn encoder(&self, _limits: Limits) -> Result<Self::Encoder, ArchiveError> {
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
    type Decoder = Self;

    fn filter(&self) -> FilterId { FilterId::Gzip }
    fn name(&self) -> &'static str { "package-smoke-codec" }
    fn probe(&self, _prefix: &[u8]) -> ProbeResult<()> { ProbeResult::NoMatch }
    fn capabilities(&self) -> CodecCapabilities { CodecCapabilities::new(true, true) }
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

fn main() {
    let _filesystem = ExternalFilesystem;
    let _engine = ArchiveEngine::new()
        .with_format_provider(ExternalFormat)
        .with_codec_provider(ExternalCodec);
    let _closed = ProviderSet::empty()
        .with_format_provider(ExternalFormat)
        .with_codec_provider(ExternalCodec);
    let limits = Limits::safe();
    let mut reader = ArchiveReader::with_limits(Cursor::new(Vec::<u8>::new()), limits);
    let _event: Result<ReaderEvent<'_>, _> = reader.next_event();
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
        Some("no-dyn") => check_no_dyn(&root),
        Some("license-sync") => check_license_sync(&root),
        Some("package-licenses") => check_package_licenses(&root),
        Some("package-smoke") => check_package_smoke(&root),
        Some("codec-policy") => check_codec_policy(&root),
        Some("release-policy") => check_release_policy(&root),
        Some("fuzz-ci") => run_fuzz_ci(&root),
        Some("big-endian-ci") => run_big_endian_ci(&root),
        Some(command) => Err(format!("unknown command {command:?}").into()),
        None => Err(
            "expected one of: no-dyn, license-sync, package-licenses, package-smoke, \
             codec-policy, release-policy, fuzz-ci, big-endian-ci"
                .into(),
        ),
    }
}

fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask manifest has no workspace parent".into())
}

fn check_no_dyn(root: &Path) -> Result {
    let mut rust_files = Vec::new();
    for tree in SOURCE_TREES {
        collect_rust_files(&root.join(tree), &mut rust_files)?;
    }
    rust_files.sort();

    let mut violations = Vec::new();
    for path in rust_files {
        let source = fs::read_to_string(&path)?;
        for (index, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let inspected =
                if line.contains("fn source(&self)") && line.contains("dyn std::error::Error") {
                    line.replacen("dyn std::error::Error", "std::error::Error", 1)
                } else {
                    line.to_owned()
                };
            if contains_word(&inspected, "dyn") {
                let relative = path.strip_prefix(root).unwrap_or(&path);
                violations.push(format!("{}:{}:{line}", relative.display(), index + 1));
            }
        }
    }

    if violations.is_empty() {
        println!(
            "check-no-dyn: OK (static dispatch; only std::error::Error::source signatures use dyn)"
        );
        return Ok(());
    }
    for violation in violations {
        eprintln!("{violation}");
    }
    Err("found dyn outside std::error::Error::source".into())
}

fn collect_rust_files(directory: &Path, output: &mut Vec<PathBuf>) -> Result {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_rust_files(&path, output)?;
        } else if path.extension() == Some(OsStr::new("rs")) {
            output.push(path);
        }
    }
    Ok(())
}

fn contains_word(text: &str, needle: &str) -> bool {
    text.match_indices(needle).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + needle.len()..].chars().next();
        !before.is_some_and(is_identifier_character) && !after.is_some_and(is_identifier_character)
    })
}

fn is_identifier_character(character: char) -> bool {
    character == '_' || character.is_alphanumeric()
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
            if !listing.lines().any(|line| line == expected) {
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
    let flagship = workspace_package_path("libarchive_oxide");
    let cli = workspace_package_path("libarchive_oxide-cli");
    let consumer_core = consumer_package_path("libarchive_oxide-core");
    let consumer_flagship = consumer_package_path("libarchive_oxide");
    let workspace_manifest = format!(
        r#"[workspace]
resolver = "2"
members = ["consumer", "{core}", "{flagship}", "{cli}"]

[patch.crates-io]
libarchive_oxide-core = {{ path = "{core}" }}
libarchive_oxide = {{ path = "{flagship}" }}
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
portable-codecs = ["libarchive_oxide/portable-codecs"]
native-codecs = ["libarchive_oxide/native-codecs"]

[dependencies]
libarchive_oxide = {{ path = "{consumer_flagship}", default-features = false }}
libarchive_oxide-core = {{ path = "{consumer_core}" }}
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
    let conflict = Command::new(cargo())
        .current_dir(smoke)
        .args([
            "check",
            "-p",
            "libarchive_oxide",
            "--features",
            "native-codecs",
        ])
        .output()?;
    if conflict.status.success()
        || !String::from_utf8_lossy(&conflict.stderr).contains("mutually exclusive")
    {
        return Err("packaged codec profiles did not fail with the documented conflict".into());
    }
    println!(
        "packaged crates compile in portable and native profiles; their combination fails closed"
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
        ("gzip", ["gzip", "gzip,async,tokio"], "miniz_oxide"),
        ("bzip2", ["bzip2", "bzip2,async,tokio"], "libbz2-rs-sys"),
        ("zstd", ["zstd", "zstd,async,tokio"], "ruzstd"),
        ("xz", ["xz", "xz,async,tokio"], "lzma-rust2"),
        ("lz4", ["lz4", "lz4,async,tokio"], "lz4_flex"),
    ] {
        for features in profiles {
            require_dependency_profile(
                root,
                &format!("compatible portable {codec} ({features})"),
                features,
                &[required],
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
        "portable codec graphs exclude C/FFI packages; the explicit native graph selects all five native backends"
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
    let release_plz = fs::read_to_string(root.join("release-plz.toml"))?;
    let contributing = fs::read_to_string(root.join("CONTRIBUTING.md"))?;

    check_manual_only_workflow("release.yml", &release)?;
    check_manual_only_workflow("release-assets.yml", &assets)?;
    require_all(
        "release.yml",
        &release,
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
        &assets,
        &[
            "Type PREFLIGHT without upload, or ASSETS with upload",
            "if: inputs.upload",
            "ref: refs/tags/${{ inputs.ref }}",
            "draft GitHub Release",
        ],
    )?;
    require_all(
        "release-plz.toml",
        &release_plz,
        &[
            "git_release_enable = true",
            "git_release_draft = true",
            "git_tag_enable = true",
        ],
    )?;
    require_all(
        "CONTRIBUTING.md",
        &contributing,
        &[
            "verify every draft asset",
            "Publish the completed draft Release manually",
            "Never automate",
        ],
    )?;
    println!("release policy is manual-only and draft-before-final-publication");
    Ok(())
}

fn check_manual_only_workflow(name: &str, workflow: &str) -> Result {
    let trigger = section_between(workflow, "\non:\n", "\npermissions:")
        .ok_or_else(|| format!("{name} has no recognizable trigger section"))?;
    if !trigger.trim_start().starts_with("workflow_dispatch:") {
        return Err(format!("{name} must start with workflow_dispatch").into());
    }
    for forbidden in [
        "\n  push:",
        "\n  pull_request:",
        "\n  schedule:",
        "\n  release:",
    ] {
        if trigger.contains(forbidden) {
            return Err(
                format!("{name} contains forbidden automatic trigger {forbidden:?}").into(),
            );
        }
    }
    Ok(())
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
                "+nightly",
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
        &["+nightly", "fuzz", "build", "--target", &fuzz_target],
        "portable libFuzzer build",
    )?;
    run_command(
        root,
        cargo(),
        &[
            "+nightly",
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
                "+nightly".to_owned(),
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
        .args(["+nightly", "fuzz", "list"])
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
            "--release",
            "--target",
            "s390x-unknown-linux-gnu",
            "--",
            "--skip",
            "corpus_files_replay_without_panic",
            "--skip",
            "arbitrary_seeds_uphold_invariants",
            "--skip",
            "seed_mutants_uphold_invariants",
        ],
        "big-endian s390x suite",
    )
}

fn run_command(root: &Path, program: &str, arguments: &[&str], description: &str) -> Result {
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
    use super::{check_manual_only_workflow, contains_word, section_between};

    #[test]
    fn dyn_is_matched_only_as_a_complete_identifier() {
        assert!(contains_word("Box<dyn Error>", "dyn"));
        assert!(contains_word("(dyn Error)", "dyn"));
        assert!(!contains_word("dynamic", "dyn"));
        assert!(!contains_word("some_dyn_type", "dyn"));
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
}
