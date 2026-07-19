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
        Some("release-policy") => check_release_policy(&root),
        Some(command) => Err(format!("unknown command {command:?}").into()),
        None => Err(
            "expected one of: no-dyn, license-sync, package-licenses, package-smoke, release-policy"
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
    for crate_name in CRATES {
        let status = Command::new(cargo())
            .current_dir(root)
            .args(["package", "-p", crate_name, "--allow-dirty", "--no-verify"])
            .status()?;
        if !status.success() {
            return Err(format!("cargo package failed for {crate_name}").into());
        }
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

[dependencies]
libarchive_oxide = {{ path = "{consumer_flagship}" }}
libarchive_oxide-core = {{ path = "{consumer_core}" }}
"#
        ),
    )?;
    fs::write(
        smoke.join("consumer").join("src").join("main.rs"),
        r"use std::io::Cursor;

use libarchive_oxide::{ArchiveReader, ReaderEvent};
use libarchive_oxide_core::Limits;

fn main() {
    let limits = Limits::safe();
    let mut reader = ArchiveReader::with_limits(Cursor::new(Vec::<u8>::new()), limits);
    let _event: Result<ReaderEvent<'_>, _> = reader.next_event();
}
",
    )?;

    let status = Command::new(cargo())
        .current_dir(&smoke)
        .args(["check", "--workspace", "--all-targets", "--all-features"])
        .status()?;
    if !status.success() {
        return Err("external consumer failed to compile packaged crates".into());
    }
    println!("packaged crates compile together in an external consumer workspace");
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
