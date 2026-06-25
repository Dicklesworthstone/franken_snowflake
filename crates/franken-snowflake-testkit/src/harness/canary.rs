//! Canary-secret leak guard.
//!
//! Two complementary detections, run across every output channel a CLI/MCP run
//! can write to — stdout, stderr, and files (receipts, logs, exports):
//!
//! 1. **Planted canaries.** A test plants a fake-but-detectable sentinel (e.g.
//!    [`DEFAULT_CANARY`]) into a fixture, an env var, or a profile, then asserts
//!    it never appears in any output. A hit means a value that should have been
//!    held back leaked through.
//! 2. **Secret-shape detection.** Each whitespace-delimited token is checked
//!    against the **single shared needle list** in
//!    `franken_snowflake_core::redact` — the exact same constant the production
//!    redactor uses, so the guard and the redactor cannot drift
//!    (`docs/security_model.md`, "one needle list"). The matched token is stored
//!    only in redacted form, never raw.
//!
//! Any hit fails the build (`docs/proof_lanes.md`, Lane 4). The guard is generic:
//! it has no Snowflake knowledge and performs no IO beyond reading the files it
//! is handed.

use std::fmt;
use std::path::Path;

use franken_snowflake_core::redact::{contains_secret, redact};
use serde::Serialize;

/// A planted sentinel a test can inject and then assert never leaks. It is not a
/// real secret and does not match any production secret shape, so a hit is
/// unambiguously "this exact planted value escaped".
pub const DEFAULT_CANARY: &str = "FSNOW_CANARY_a1b2c3d4_DO_NOT_EMIT";

/// The output channel a hit was found on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Channel {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// A file at the given path.
    File(String),
    /// A named channel (receipt, export, custom buffer).
    Named(String),
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stdout => f.write_str("stdout"),
            Self::Stderr => f.write_str("stderr"),
            Self::File(path) => write!(f, "file:{path}"),
            Self::Named(name) => f.write_str(name),
        }
    }
}

/// Why a hit fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HitKind {
    /// A planted canary sentinel was found verbatim.
    PlantedCanary,
    /// A token matched a production secret shape.
    SecretShape,
}

/// A single detection. For [`HitKind::SecretShape`] hits, `needle` is the
/// **redacted** rendering of the offending token — the raw secret is never
/// stored, surfaced, or logged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanaryHit {
    /// The channel the hit was found on.
    pub channel: Channel,
    /// Why it fired.
    pub kind: HitKind,
    /// The planted canary (safe) or a redacted secret-shape rendering.
    pub needle: String,
    /// Byte offset of the hit within the channel's content.
    pub byte_offset: usize,
}

impl fmt::Display for CanaryHit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            HitKind::PlantedCanary => "planted canary",
            HitKind::SecretShape => "secret shape",
        };
        write!(
            f,
            "{} on {} at byte {} ({})",
            kind, self.channel, self.byte_offset, self.needle
        )
    }
}

/// The leak guard: a set of planted canaries plus an optional secret-shape scan.
#[derive(Clone, Debug)]
pub struct CanaryGuard {
    planted: Vec<String>,
    scan_shapes: bool,
}

impl Default for CanaryGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl CanaryGuard {
    /// A guard with no planted canaries and secret-shape scanning enabled.
    #[must_use]
    pub fn new() -> Self {
        Self { planted: Vec::new(), scan_shapes: true }
    }

    /// A guard pre-seeded with [`DEFAULT_CANARY`].
    #[must_use]
    pub fn with_default_canary() -> Self {
        let mut guard = Self::new();
        guard.plant(DEFAULT_CANARY);
        guard
    }

    /// Register a canary sentinel that must never appear in output.
    pub fn plant(&mut self, canary: impl Into<String>) -> &mut Self {
        self.planted.push(canary.into());
        self
    }

    /// Enable or disable secret-shape scanning (planted-canary scanning is
    /// always on).
    #[must_use]
    pub fn scan_shapes(mut self, enabled: bool) -> Self {
        self.scan_shapes = enabled;
        self
    }

    /// Scan one channel's text, returning every hit.
    #[must_use]
    pub fn scan_text(&self, channel: Channel, text: &str) -> Vec<CanaryHit> {
        let mut hits = Vec::new();
        for canary in &self.planted {
            if canary.is_empty() {
                continue;
            }
            for (offset, _) in text.match_indices(canary.as_str()) {
                hits.push(CanaryHit {
                    channel: channel.clone(),
                    kind: HitKind::PlantedCanary,
                    needle: canary.clone(),
                    byte_offset: offset,
                });
            }
        }
        if self.scan_shapes {
            for (offset, token) in tokens_with_offsets(text) {
                if contains_secret(token) {
                    hits.push(CanaryHit {
                        channel: channel.clone(),
                        kind: HitKind::SecretShape,
                        needle: redact(token).into_owned(),
                        byte_offset: offset,
                    });
                }
            }
        }
        hits
    }

    /// Read `path` and scan its contents.
    ///
    /// # Errors
    /// Returns [`CanaryError::Io`] if the file cannot be read, or
    /// [`CanaryError::Utf8`] if it is not valid UTF-8.
    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<Vec<CanaryHit>, CanaryError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(CanaryError::Io)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| CanaryError::Utf8)?;
        Ok(self.scan_text(Channel::File(path.display().to_string()), text))
    }

    /// Scan stdout, stderr, and a set of files together, returning a combined
    /// report.
    ///
    /// # Errors
    /// Returns [`CanaryError`] if any file cannot be read or decoded.
    pub fn scan(
        &self,
        stdout: &str,
        stderr: &str,
        files: &[&Path],
    ) -> Result<CanaryReport, CanaryError> {
        let mut hits = self.scan_text(Channel::Stdout, stdout);
        hits.extend(self.scan_text(Channel::Stderr, stderr));
        for path in files {
            hits.extend(self.scan_file(path)?);
        }
        Ok(CanaryReport { hits })
    }
}

/// Split `text` into maximal non-whitespace runs, each paired with its byte
/// offset, so secret-shape hits carry a meaningful location.
fn tokens_with_offsets(text: &str) -> Vec<(usize, &str)> {
    let mut tokens = Vec::new();
    let mut start: Option<usize> = None;
    for (offset, ch) in text.char_indices() {
        if ch.is_whitespace() {
            if let Some(begin) = start.take() {
                tokens.push((begin, &text[begin..offset]));
            }
        } else if start.is_none() {
            start = Some(offset);
        }
    }
    if let Some(begin) = start {
        tokens.push((begin, &text[begin..]));
    }
    tokens
}

/// The combined result of a scan across channels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanaryReport {
    /// Every hit found, in channel order.
    pub hits: Vec<CanaryHit>,
}

impl CanaryReport {
    /// Whether any channel leaked.
    #[must_use]
    pub fn leaked(&self) -> bool {
        !self.hits.is_empty()
    }

    /// Consume the report, succeeding only if nothing leaked.
    ///
    /// # Errors
    /// Returns [`CanaryLeak`] listing every hit when one or more channels leaked.
    pub fn assert_clean(self) -> Result<(), CanaryLeak> {
        if self.hits.is_empty() {
            Ok(())
        } else {
            Err(CanaryLeak { hits: self.hits })
        }
    }
}

/// The error returned when a scan detects one or more leaks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanaryLeak {
    /// The hits that fired.
    pub hits: Vec<CanaryHit>,
}

impl fmt::Display for CanaryLeak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "canary leak guard tripped: {} hit(s)", self.hits.len())?;
        for hit in &self.hits {
            write!(f, "\n  - {hit}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CanaryLeak {}

/// An error from scanning a file channel.
#[derive(Debug)]
pub enum CanaryError {
    /// The file could not be read.
    Io(std::io::Error),
    /// The file was not valid UTF-8.
    Utf8,
}

impl fmt::Display for CanaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "canary scan io error: {error}"),
            Self::Utf8 => write!(f, "canary scan target is not valid UTF-8"),
        }
    }
}

impl std::error::Error for CanaryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planted_canary_trips_across_stdout_stderr_and_files() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join("fsnow-harness-canary");
        std::fs::create_dir_all(&dir)?;
        let receipt = dir.join("receipt.json");
        std::fs::write(&receipt, format!("{{\"note\":\"{DEFAULT_CANARY}\"}}"))?;

        let guard = CanaryGuard::with_default_canary();

        // Leak on stdout.
        let report = guard.scan(
            &format!("ok {DEFAULT_CANARY}"),
            "clean stderr",
            &[],
        )?;
        assert!(report.leaked());

        // Leak on stderr.
        let report = guard.scan("clean", &format!("oops {DEFAULT_CANARY}"), &[])?;
        assert!(report.leaked());

        // Leak in a file channel.
        let report = guard.scan("clean", "clean", &[receipt.as_path()])?;
        assert!(report.leaked());
        match report.assert_clean() {
            Ok(()) => return Err("file leak should not be clean".into()),
            Err(leak) => assert_eq!(leak.hits.len(), 1),
        }

        // Fully clean run passes.
        let clean = guard.scan("all good", "no secrets", &[])?;
        assert!(!clean.leaked());
        clean.assert_clean()?;

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn secret_shape_hits_are_stored_redacted() {
        let guard = CanaryGuard::new();
        // A GitHub-PAT-shaped token (matches the shared needle list). It must be
        // a whitespace-delimited token so it lands on a secret-prefix boundary.
        let hits = guard.scan_text(Channel::Stdout, "leaked token: ghp_0123456789abcdefABCDEF here");
        let shape: Vec<&CanaryHit> = hits
            .iter()
            .filter(|hit| hit.kind == HitKind::SecretShape)
            .collect();
        assert_eq!(shape.len(), 1);
        // The raw secret is never retained; only the redacted form is.
        assert!(!shape[0].needle.contains("ghp_0123456789"));
        assert!(shape[0].needle.contains("[REDACTED]"));
    }

    #[test]
    fn disabling_shape_scan_only_keeps_planted_hits() {
        let guard = CanaryGuard::with_default_canary().scan_shapes(false);
        let hits = guard.scan_text(
            Channel::Stderr,
            &format!("ghp_0123456789abcdefABCDEF and {DEFAULT_CANARY}"),
        );
        // The real-shaped token is ignored; only the planted canary trips.
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, HitKind::PlantedCanary);
    }

    #[test]
    fn multiple_shape_hits_carry_distinct_offsets() {
        let guard = CanaryGuard::new();
        let text = "AKIAIOSFODNN7EXAMPLE then xoxb-abcdEFGH";
        let hits = guard.scan_text(Channel::Stdout, text);
        let shapes: Vec<&CanaryHit> = hits
            .iter()
            .filter(|hit| hit.kind == HitKind::SecretShape)
            .collect();
        assert_eq!(shapes.len(), 2);
        assert_ne!(shapes[0].byte_offset, shapes[1].byte_offset);
        // Offsets point at the token starts.
        assert_eq!(shapes[0].byte_offset, 0);
        assert_eq!(shapes[1].byte_offset, text.find("xoxb-").unwrap_or(usize::MAX));
    }

    #[test]
    fn multiple_planted_canaries_are_all_scanned() {
        let mut guard = CanaryGuard::new();
        guard.plant("CANARY_ONE").plant("CANARY_TWO");
        let hits = guard.scan_text(Channel::Stdout, "x CANARY_ONE y CANARY_TWO z");
        assert_eq!(hits.iter().filter(|h| h.kind == HitKind::PlantedCanary).count(), 2);
    }

    #[test]
    fn scan_file_rejects_non_utf8() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join("fsnow-harness-canary-utf8");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("blob.bin");
        std::fs::write(&path, [0xff_u8, 0xfe, 0x00])?;
        let guard = CanaryGuard::with_default_canary();
        match guard.scan_file(&path) {
            Err(CanaryError::Utf8) => {}
            other => return Err(format!("expected Utf8 error, got {other:?}").into()),
        }
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn leak_display_lists_each_hit() -> Result<(), String> {
        let guard = CanaryGuard::with_default_canary();
        let report = CanaryReport {
            hits: guard.scan_text(Channel::Stdout, DEFAULT_CANARY),
        };
        let leak = report
            .assert_clean()
            .err()
            .ok_or_else(|| "planted canary must trip".to_owned())?;
        let rendered = leak.to_string();
        assert!(rendered.contains("planted canary"));
        assert!(rendered.contains("stdout"));
        Ok(())
    }

    #[test]
    fn fully_clean_channels_pass_assert_clean() -> Result<(), Box<dyn std::error::Error>> {
        // Negative case: even with a canary armed and shape scanning on, output
        // that contains no planted sentinel and no secret shape is clean.
        let guard = CanaryGuard::with_default_canary();
        let report = guard.scan("clean stdout output", "clean stderr output", &[])?;
        assert!(!report.leaked());
        report.assert_clean()?;
        Ok(())
    }
}
