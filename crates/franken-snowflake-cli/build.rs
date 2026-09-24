//! Build identity for `capabilities.build` and query receipts (reality-check
//! bead H1): the git commit, whether tracked files differed from it, the
//! target, profile and rustc. A live proof compares it against HEAD so it cannot
//! silently exercise a stale binary.
//!
//! Sources, in order: `FSNOW_BUILD_SHA` / `FSNOW_BUILD_DIRTY` (set by dsr and the
//! live-proof script, which may build where `.git` is absent), then `git`, then
//! `unknown`. Never fails the build.

use std::process::Command;

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
}
