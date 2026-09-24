//! Build identity for `capabilities.build` and query receipts (reality-check
//! bead H1): the git commit, whether tracked files differed from it, the
//! target, profile and rustc. A live proof compares it against HEAD so it cannot
//! silently exercise a stale binary.
//!
//! Sources, in order: `FSNOW_BUILD_SHA` / `FSNOW_BUILD_DIRTY` (set by dsr and the
//! live-proof script, which may build where `.git` is absent), then `git`, then
//! `unknown`. Never fails the build.
//!
//! A remote build worker can carry a stale `.git`, so the git sha alone can
//! name the wrong commit. The source digest does not depend on git: SHA-256
//! over `sha256sum`-format lines (`<hex>  <path>\n`) for every
//! `crates/**/*.rs`, `crates/**/Cargo.toml`, `Cargo.toml` and `Cargo.lock`,
//! sorted by path, which a script recomputes with
//! `find ... | LC_ALL=C sort | xargs sha256sum | sha256sum`.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn command_stdout(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn collect_sources(dir: &Path, relative: &str, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = format!("{relative}/{name}");
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if name != "target" {
                collect_sources(&path, &rel, out);
            }
        } else if kind.is_file() && (name.ends_with(".rs") || name == "Cargo.toml") {
            out.push((rel, path));
        }
    }
}

/// See the module docs; `unknown` when the workspace layout is not there.
fn source_digest(root: &Path) -> Option<String> {
    let mut files = Vec::new();
    collect_sources(&root.join("crates"), "crates", &mut files);
    if files.is_empty() {
        return None;
    }
    for top in ["Cargo.toml", "Cargo.lock"] {
        files.push((top.to_owned(), root.join(top)));
    }
    files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut listing = String::new();
    for (rel, path) in &files {
        let bytes = std::fs::read(path).ok()?;
        listing.push_str(&hex(&Sha256::digest(&bytes)));
        listing.push_str("  ");
        listing.push_str(rel);
        listing.push('\n');
    }
    Some(hex(&Sha256::digest(listing.as_bytes())))
}

fn main() {
    for var in ["FSNOW_BUILD_SHA", "FSNOW_BUILD_DIRTY"] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    // Recompute when the commit, the index, or any workspace source changes.
    for path in [
        "../../.git/HEAD",
        "../../.git/index",
        "../../crates",
        "../../Cargo.lock",
        "../../Cargo.toml",
    ] {
        if std::path::Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let unknown = || "unknown".to_owned();
    let git_sha = env("FSNOW_BUILD_SHA")
        .or_else(|| command_stdout("git", &["rev-parse", "HEAD"]))
        .unwrap_or_else(unknown);
    // `--no-optional-locks`: status must not rewrite .git/index, which would
    // retrigger this script on every build.
    let dirty = env("FSNOW_BUILD_DIRTY")
        .or_else(|| {
            command_stdout(
                "git",
                &[
                    "--no-optional-locks",
                    "status",
                    "--porcelain",
                    "--untracked-files=no",
                ],
            )
            .map(|changes| (!changes.is_empty()).to_string())
        })
        .unwrap_or_else(unknown);
    let rustc = env("RUSTC")
        .and_then(|rustc| command_stdout(&rustc, &["--version"]))
        .unwrap_or_else(unknown);
    println!("cargo:rustc-env=FSNOW_BUILD_GIT_SHA={git_sha}");
    println!("cargo:rustc-env=FSNOW_BUILD_DIRTY={dirty}");
    println!(
        "cargo:rustc-env=FSNOW_BUILD_TARGET={}",
        env("TARGET").unwrap_or_else(unknown)
    );
    println!(
        "cargo:rustc-env=FSNOW_BUILD_PROFILE={}",
        env("PROFILE").unwrap_or_else(unknown)
    );
    println!("cargo:rustc-env=FSNOW_BUILD_RUSTC={rustc}");
    let digest = source_digest(Path::new("../..")).unwrap_or_else(unknown);
    println!("cargo:rustc-env=FSNOW_BUILD_SOURCE_DIGEST={digest}");
}
