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
        Some(command) => Err(format!("unknown command {command:?}").into()),
        None => Err("expected one of: no-dyn, license-sync, package-licenses".into()),
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

fn cargo() -> &'static str {
    if cfg!(windows) { "cargo.exe" } else { "cargo" }
}

#[cfg(test)]
mod tests {
    use super::contains_word;

    #[test]
    fn dyn_is_matched_only_as_a_complete_identifier() {
        assert!(contains_word("Box<dyn Error>", "dyn"));
        assert!(contains_word("(dyn Error)", "dyn"));
        assert!(!contains_word("dynamic", "dyn"));
        assert!(!contains_word("some_dyn_type", "dyn"));
    }
}
