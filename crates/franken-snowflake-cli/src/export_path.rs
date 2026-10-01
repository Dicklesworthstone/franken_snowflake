//! Output-path safety for `export run` and the MCP `export_run` tool.
//!
//! Before 2026-09-24 the export wrote with `std::fs::write(out)`: any path,
//! silently overwriting existing files and following symlinks. Through MCP the
//! `out` argument is caller-controlled, so an agent (or, with the HTTP transport
//! unprotected, a web page) could write query-controlled bytes anywhere the user
//! can, e.g. append-shaped content to `~/.ssh/authorized_keys`.
//!
//! Rules:
//! - Never overwrite implicitly: new files are created with `create_new`
//!   (`O_EXCL`); `--overwrite` replaces only a regular, non-symlink file, via a
//!   temp file in the same directory and an atomic rename.
//! - Never write through a symlink at the target.
//! - Sandbox mode (the MCP tool always requests it): `out` must be a relative
//!   path without `..` or a drive/root prefix, resolved under
//!   `<data_dir>/exports`, and no component of it may be a symlink.

use std::io::Write;
use std::path::{Component, Path, PathBuf};

/// A validated export destination.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportTarget {
    pub path: PathBuf,
    pub overwrite: bool,
}

/// Resolve and validate `out`. In sandbox mode `sandbox_root` is the directory
/// the path must stay inside (created if missing).
///
/// # Errors
/// A message naming the rule the path broke.
pub fn resolve_out(
    out: &str,
    sandbox_root: Option<&Path>,
    overwrite: bool,
) -> Result<ExportTarget, String> {
    let out = out.trim();
    if out.is_empty() {
        return Err("`--out` is empty".to_owned());
    }
    let path = match sandbox_root {
        None => PathBuf::from(out),
        Some(root) => confined_path(out, root)?,
    };
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "refusing to write through the symlink `{}`",
                path.display()
            ));
        }
        if !meta.is_file() {
            return Err(format!(
                "`{}` exists and is not a regular file",
                path.display()
            ));
        }
        if !overwrite {
            return Err(format!(
                "`{}` already exists; pass --overwrite to replace it",
                path.display()
            ));
        }
    }
    Ok(ExportTarget { path, overwrite })
}

fn confined_path(out: &str, root: &Path) -> Result<PathBuf, String> {
    let relative = Path::new(out);
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(
                    "`out` may not contain `..` (it is confined to the export directory)"
                        .to_owned(),
                );
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "`out` must be a path relative to the export directory `{}`; absolute and drive paths are refused",
                    root.display()
                ));
            }
        }
    }
    let Some(file_name) = parts.pop() else {
        return Err("`out` names no file".to_owned());
    };
    std::fs::create_dir_all(root).map_err(|error| {
        format!(
            "cannot create the export directory `{}`: {error}",
            root.display()
        )
    })?;
    let canonical_root = root
        .canonicalize()
        .map_err(|error| format!("cannot resolve the export directory: {error}"))?;
    // Walk the parent components, refusing symlinks and creating directories.
    let mut current = canonical_root.clone();
    for part in parts {
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "`out` passes through the symlink `{}`; symlinks are refused inside the export directory",
                    current.display()
                ));
            }
            Ok(meta) if !meta.is_dir() => {
                return Err(format!("`{}` is not a directory", current.display()));
            }
            Ok(_) => {}
            Err(_) => std::fs::create_dir(&current)
                .map_err(|error| format!("cannot create `{}`: {error}", current.display()))?,
        }
    }
    let parent = current
        .canonicalize()
        .map_err(|error| format!("cannot resolve `{}`: {error}", current.display()))?;
    if !parent.starts_with(&canonical_root) {
        return Err("`out` escapes the export directory".to_owned());
    }
    Ok(parent.join(file_name))
}

/// Write `bytes` to a validated target: `create_new` for new files, or a
/// same-directory temp file plus atomic rename for `--overwrite`.
///
/// # Errors
/// The I/O error, rendered.
pub fn write_artifact(target: &ExportTarget, bytes: &[u8]) -> Result<(), String> {
    let write_new = |path: &Path| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    };
    if !target.overwrite {
        return write_new(&target.path).map_err(|error| error.to_string());
    }
    let file_name = target
        .path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = target
        .path
        .with_file_name(format!(".{file_name}.fsnow-tmp-{}", std::process::id()));
    write_new(&temp).map_err(|error| error.to_string())?;
    std::fs::rename(&temp, &target.path).map_err(|error| {
        let _ = std::fs::remove_file(&temp);
        error.to_string()
    })
}

/// A streaming export file (reality-check bead E5) with the same rules as
/// [`write_artifact`]: without `--overwrite` the target is reserved with
/// create-new before anything runs; rows go to a temporary file beside it,
/// which replaces the target only on [`ArtifactFile::commit`]. An export that
/// fails or is dropped removes its temporary file (and the empty reservation),
/// so a failed run never leaves a partial target.
pub struct ArtifactFile {
    temp: PathBuf,
    target: PathBuf,
    reserved: bool,
    file: Option<std::io::BufWriter<std::fs::File>>,
}

/// Open a streaming export for `target`.
///
/// # Errors
/// The target exists without `--overwrite`, or a file cannot be created.
pub fn open_artifact(target: &ExportTarget) -> Result<ArtifactFile, String> {
    let reserved = if target.overwrite {
        false
    } else {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target.path)
            .map_err(|error| error.to_string())?;
        true
    };
    let file_name = target
        .path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = target
        .path
        .with_file_name(format!(".{file_name}.fsnow-tmp-{}", std::process::id()));
    let mut artifact = ArtifactFile {
        temp,
        target: target.path.clone(),
        reserved,
        file: None,
    };
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&artifact.temp)
        .map_err(|error| error.to_string())?;
    artifact.file = Some(std::io::BufWriter::new(file));
    Ok(artifact)
}

impl ArtifactFile {
    /// Flush, sync and move the temporary file onto the target.
    ///
    /// # Errors
    /// A flush, sync or rename failure (the temporary file is then removed).
    pub fn commit(mut self) -> Result<(), String> {
        let Some(writer) = self.file.take() else {
            return Err("the export file was already closed".to_owned());
        };
        let file = writer
            .into_inner()
            .map_err(|error| error.error().to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        std::fs::rename(&self.temp, &self.target).map_err(|error| error.to_string())?;
        self.reserved = false;
        Ok(())
    }
}

impl Drop for ArtifactFile {
    /// An uncommitted export leaves nothing behind: its own temporary file and
    /// the empty reservation it created are removed; nothing else is touched.
    fn drop(&mut self) {
        if self.file.take().is_some() || self.temp.exists() {
            let _ = std::fs::remove_file(&self.temp);
        }
        if self.reserved {
            let _ = std::fs::remove_file(&self.target);
        }
    }
}

impl franken_snowflake_export::ExportByteSink for ArtifactFile {
    fn write_chunk(&mut self, chunk: &[u8]) -> franken_snowflake_export::ExportResult<()> {
        let Some(writer) = self.file.as_mut() else {
            return Err(franken_snowflake_export::ExportError::Sink {
                message: "the export file is closed".to_owned(),
            });
        };
        writer
            .write_all(chunk)
            .map_err(|error| franken_snowflake_export::ExportError::Sink {
                message: error.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reality-check bead E5: a committed streaming export becomes the target;
    /// an uncommitted one leaves neither the target nor a temporary file, and
    /// an existing target still needs --overwrite.
    #[test]
    fn streaming_artifacts_commit_or_leave_nothing() -> Result<(), String> {
        use franken_snowflake_export::ExportByteSink as _;
        let dir = scratch("stream");
        let path = dir.join("s.csv");
        let target = resolve_out(&path.to_string_lossy(), None, false)?;
        let mut file = open_artifact(&target)?;
        file.write_chunk(b"a\n").map_err(|e| e.to_string())?;
        file.commit()?;
        assert_eq!(std::fs::read(&path).map_err(|e| e.to_string())?, b"a\n");
        // Without --overwrite the existing target is refused up front.
        assert!(open_artifact(&target).is_err());

        let other = dir.join("t.csv");
        let target = resolve_out(&other.to_string_lossy(), None, false)?;
        let mut file = open_artifact(&target)?;
        file.write_chunk(b"partial\n").map_err(|e| e.to_string())?;
        drop(file);
        assert!(!other.exists(), "an uncommitted export leaves no target");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .map_err(|e| e.to_string())?
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().contains("fsnow-tmp"))
            .collect();
        assert!(leftovers.is_empty(), "no temporary file is left behind");

        // With --overwrite a failed export keeps the old contents.
        let target = resolve_out(&path.to_string_lossy(), None, true)?;
        let mut file = open_artifact(&target)?;
        file.write_chunk(b"new\n").map_err(|e| e.to_string())?;
        drop(file);
        assert_eq!(std::fs::read(&path).map_err(|e| e.to_string())?, b"a\n");
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    fn scratch(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fsnow-export-path-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)
            .map(|()| dir.clone())
            .unwrap_or(dir)
    }

    #[test]
    fn new_files_are_created_and_existing_ones_need_overwrite() -> Result<(), String> {
        let dir = scratch("create");
        let path = dir.join("a.csv");
        let target = resolve_out(&path.to_string_lossy(), None, false)?;
        write_artifact(&target, b"x\n")?;
        let again = resolve_out(&path.to_string_lossy(), None, false);
        assert!(again.is_err_and(|e| e.contains("--overwrite")));
        let replace = resolve_out(&path.to_string_lossy(), None, true)?;
        write_artifact(&replace, b"y\n")?;
        assert_eq!(std::fs::read(&path).map_err(|e| e.to_string())?, b"y\n");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_targets_are_refused_even_with_overwrite() -> Result<(), String> {
        let dir = scratch("symlink");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"keep").map_err(|e| e.to_string())?;
        let link = dir.join("link");
        std::os::unix::fs::symlink(&victim, &link).map_err(|e| e.to_string())?;
        let refused = resolve_out(&link.to_string_lossy(), None, true);
        assert!(refused.is_err_and(|e| e.contains("symlink")));
        assert_eq!(std::fs::read(&victim).map_err(|e| e.to_string())?, b"keep");
        Ok(())
    }

    #[test]
    fn sandbox_refuses_absolute_parent_and_empty_paths() {
        let root = scratch("sandbox-refuse").join("exports");
        for bad in ["/etc/passwd", "../x.csv", "a/../../x.csv", "", "."] {
            assert!(resolve_out(bad, Some(&root), false).is_err(), "{bad:?}");
        }
    }

    /// UNC and drive forms are refused on Windows (a `Prefix` component); on
    /// Unix they are plain file names. Either way nothing lands outside the root.
    #[test]
    fn sandbox_never_resolves_unc_or_drive_paths_outside_the_root() -> Result<(), String> {
        let root = scratch("sandbox-unc").join("exports");
        for odd in [
            r"\\server\share\x.csv",
            "C:x.csv",
            r"C:\x.csv",
            "//server/share/x.csv",
        ] {
            if let Ok(target) = resolve_out(odd, Some(&root), false) {
                let canonical_root = root.canonicalize().map_err(|e| e.to_string())?;
                assert!(
                    target.path.starts_with(&canonical_root),
                    "{odd:?} -> {}",
                    target.path.display()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn sandbox_resolves_relative_paths_inside_the_root() -> Result<(), String> {
        let root = scratch("sandbox-ok").join("exports");
        let target = resolve_out("runs/2026/a.csv", Some(&root), false)?;
        let canonical_root = root.canonicalize().map_err(|e| e.to_string())?;
        assert!(
            target.path.starts_with(&canonical_root),
            "{:?}",
            target.path
        );
        write_artifact(&target, b"ok")?;
        Ok(())
    }

    /// The naive fix (a string-prefix check without resolving symlinks) passes
    /// this case; the component walk must refuse it.
    #[cfg(unix)]
    #[test]
    fn sandbox_refuses_a_symlinked_directory_component() -> Result<(), String> {
        let base = scratch("sandbox-link");
        let root = base.join("exports");
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).map_err(|e| e.to_string())?;
        std::os::unix::fs::symlink(&outside, root.join("escape")).map_err(|e| e.to_string())?;
        let refused = resolve_out("escape/x.csv", Some(&root), false);
        assert!(refused.is_err_and(|e| e.contains("symlink")));
        Ok(())
    }
}
