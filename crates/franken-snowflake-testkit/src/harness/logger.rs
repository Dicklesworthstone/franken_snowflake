//! Structured JSON-line run logger.
//!
//! Every test (and every proof-lane step) emits **one JSON object per line** to
//! `‹artifacts_root›/‹trace_id›/events.jsonl`, carrying the `trace_id`, the
//! per-command `command_id`, a monotonic `seq`, the step name, an outcome, the
//! elapsed milliseconds, and — on failure — the expected-vs-actual renderings.
//! A failed run is therefore legible and replayable from its artifacts without
//! re-instrumentation (`docs/proof_lanes.md`, "Cross-Cutting Standards").
//!
//! [`RunLogger::finish`] writes a machine-readable `summary.json` and a
//! human-readable `summary.txt` next to the events, and returns the
//! [`RunSummary`] (pass/fail/skip counts + duration).
//!
//! The wall-clock `elapsed_ms` is real, not deterministic — it is a volatile
//! field the golden framework zeroes ([`super::golden`]). The deterministic
//! ordering guarantees come from [`super::clock`], not from this logger.

use std::fmt;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Schema version of the JSON-line event objects.
pub const LOG_SCHEMA_VERSION: u32 = 1;

/// The outcome of a single logged step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    /// The step's assertion held.
    Pass,
    /// The step's assertion failed (carries expected-vs-actual).
    Fail,
    /// The step was intentionally skipped (e.g. live-only without credentials).
    Skip,
    /// An informational marker, not an assertion.
    Info,
}

impl StepOutcome {
    /// A short upper-case label for the human-readable summary.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
            Self::Info => "INFO",
        }
    }
}

/// One JSON-line event: a single step within a run.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepEvent {
    /// Event schema version.
    pub schema_version: u32,
    /// Run-wide correlation id.
    pub trace_id: String,
    /// Stable identifier of the command/operation under test.
    pub command_id: String,
    /// Monotonic 1-based step counter within the run.
    pub seq: u64,
    /// Human step name.
    pub step: String,
    /// Step outcome.
    pub outcome: StepOutcome,
    /// Milliseconds elapsed since the run started (volatile; zeroed in goldens).
    pub elapsed_ms: u64,
    /// Optional human detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Expected rendering, present on failures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// Actual rendering, present on failures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
}

/// An error from the logger's filesystem or serialization path.
#[derive(Debug)]
pub enum LogError {
    /// A filesystem operation failed.
    Io(std::io::Error),
    /// An event could not be serialized to JSON.
    Serialize(serde_json::Error),
}

impl fmt::Display for LogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "logger io error: {error}"),
            Self::Serialize(error) => write!(f, "logger serialize error: {error}"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<std::io::Error> for LogError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for LogError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialize(error)
    }
}

/// A per-run structured logger writing JSON lines to a per-run artifacts dir.
pub struct RunLogger {
    trace_id: String,
    artifacts_dir: PathBuf,
    writer: BufWriter<File>,
    start: Instant,
    seq: u64,
    passed: u64,
    failed: u64,
    skipped: u64,
    info: u64,
}

impl RunLogger {
    /// Open a run logger. Creates `artifacts_root/‹trace_id›/` and truncates a
    /// fresh `events.jsonl` inside it.
    ///
    /// # Errors
    /// Returns [`LogError::Io`] if the directory or events file cannot be created.
    pub fn new(artifacts_root: impl AsRef<Path>, trace_id: impl Into<String>) -> Result<Self, LogError> {
        let trace_id = trace_id.into();
        let artifacts_dir = artifacts_root.as_ref().join(&trace_id);
        fs::create_dir_all(&artifacts_dir)?;
        let file = File::create(artifacts_dir.join("events.jsonl"))?;
        Ok(Self {
            trace_id,
            artifacts_dir,
            writer: BufWriter::new(file),
            start: Instant::now(),
            seq: 0,
            passed: 0,
            failed: 0,
            skipped: 0,
            info: 0,
        })
    }

    /// The run's trace id.
    #[must_use]
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// The per-run artifacts directory.
    #[must_use]
    pub fn artifacts_dir(&self) -> &Path {
        &self.artifacts_dir
    }

    /// Emit a fully-specified step event (the others delegate here).
    ///
    /// # Errors
    /// Returns [`LogError`] if the event cannot be serialized or written.
    pub fn emit(
        &mut self,
        command_id: impl Into<String>,
        step: impl Into<String>,
        outcome: StepOutcome,
        detail: Option<String>,
        expected: Option<String>,
        actual: Option<String>,
    ) -> Result<(), LogError> {
        let seq = self.seq + 1;
        let event = StepEvent {
            schema_version: LOG_SCHEMA_VERSION,
            trace_id: self.trace_id.clone(),
            command_id: command_id.into(),
            seq,
            step: step.into(),
            outcome,
            elapsed_ms: self.elapsed_ms(),
            detail,
            expected,
            actual,
        };
        let line = serde_json::to_string(&event)?;
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        self.seq = seq;
        match outcome {
            StepOutcome::Pass => self.passed += 1,
            StepOutcome::Fail => self.failed += 1,
            StepOutcome::Skip => self.skipped += 1,
            StepOutcome::Info => self.info += 1,
        }
        Ok(())
    }

    /// Log a passing step.
    ///
    /// # Errors
    /// Returns [`LogError`] on a write failure.
    pub fn pass(
        &mut self,
        command_id: impl Into<String>,
        step: impl Into<String>,
    ) -> Result<(), LogError> {
        self.emit(command_id, step, StepOutcome::Pass, None, None, None)
    }

    /// Log a failing step with its expected-vs-actual renderings.
    ///
    /// # Errors
    /// Returns [`LogError`] on a write failure.
    pub fn fail(
        &mut self,
        command_id: impl Into<String>,
        step: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Result<(), LogError> {
        self.emit(
            command_id,
            step,
            StepOutcome::Fail,
            None,
            Some(expected.into()),
            Some(actual.into()),
        )
    }

    /// Log a skipped step with a reason.
    ///
    /// # Errors
    /// Returns [`LogError`] on a write failure.
    pub fn skip(
        &mut self,
        command_id: impl Into<String>,
        step: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<(), LogError> {
        self.emit(command_id, step, StepOutcome::Skip, Some(reason.into()), None, None)
    }

    /// Log an informational marker.
    ///
    /// # Errors
    /// Returns [`LogError`] on a write failure.
    pub fn info(
        &mut self,
        command_id: impl Into<String>,
        step: impl Into<String>,
        detail: impl Into<String>,
    ) -> Result<(), LogError> {
        self.emit(command_id, step, StepOutcome::Info, Some(detail.into()), None, None)
    }

    /// Flush the events, write `summary.json` + `summary.txt`, and return the
    /// [`RunSummary`].
    ///
    /// # Errors
    /// Returns [`LogError`] if the summary cannot be written.
    pub fn finish(mut self) -> Result<RunSummary, LogError> {
        self.writer.flush()?;
        let summary = RunSummary {
            trace_id: self.trace_id.clone(),
            total: self.seq,
            passed: self.passed,
            failed: self.failed,
            skipped: self.skipped,
            info: self.info,
            duration_ms: self.elapsed_ms(),
            artifacts_dir: self.artifacts_dir.display().to_string(),
        };
        let json = serde_json::to_string(&summary)?;
        fs::write(self.artifacts_dir.join("summary.json"), json)?;
        fs::write(self.artifacts_dir.join("summary.txt"), summary.to_string())?;
        Ok(summary)
    }

    fn elapsed_ms(&self) -> u64 {
        let millis = self.start.elapsed().as_millis();
        u64::try_from(millis).unwrap_or(u64::MAX)
    }
}

/// The roll-up of a finished run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunSummary {
    /// Run-wide correlation id.
    pub trace_id: String,
    /// Total steps logged.
    pub total: u64,
    /// Passing steps.
    pub passed: u64,
    /// Failing steps.
    pub failed: u64,
    /// Skipped steps.
    pub skipped: u64,
    /// Informational markers.
    pub info: u64,
    /// Wall-clock run duration in milliseconds (volatile; zeroed in goldens).
    pub duration_ms: u64,
    /// The per-run artifacts directory.
    pub artifacts_dir: String,
}

impl RunSummary {
    /// Whether the run had zero failing steps.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.failed == 0
    }
}

impl fmt::Display for RunSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "run {}: {} steps, {} passed, {} failed, {} skipped, {} info ({} ms)",
            self.trace_id, self.total, self.passed, self.failed, self.skipped, self.info, self.duration_ms
        )?;
        writeln!(f, "artifacts: {}", self.artifacts_dir)?;
        write!(f, "status: {}", if self.ok() { "PASS" } else { "FAIL" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("fsnow-harness-logger-{name}"))
    }

    #[test]
    fn run_logs_events_and_summary_to_artifacts_dir() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("smoke");
        let mut logger = RunLogger::new(&root, "trace-smoke")?;
        logger.pass("query.run", "submit")?;
        logger.fail("query.run", "poll", "200", "202")?;
        logger.skip("query.run", "live-smoke", "no credentials")?;
        let summary = logger.finish()?;

        assert_eq!(summary.total, 3);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.skipped, 1);
        assert!(!summary.ok());

        let events = fs::read_to_string(root.join("trace-smoke").join("events.jsonl"))?;
        let lines: Vec<&str> = events.lines().collect();
        assert_eq!(lines.len(), 3);
        // Failure line carries expected-vs-actual.
        let failure: StepEvent = serde_json::from_str(lines[1])?;
        assert_eq!(failure.outcome, StepOutcome::Fail);
        assert_eq!(failure.expected.as_deref(), Some("200"));
        assert_eq!(failure.actual.as_deref(), Some("202"));

        assert!(root.join("trace-smoke").join("summary.json").exists());
        assert!(root.join("trace-smoke").join("summary.txt").exists());

        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn all_pass_run_is_ok_and_counts_every_outcome() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("counts");
        let mut logger = RunLogger::new(&root, "trace-counts")?;
        logger.pass("cmd", "a")?;
        logger.pass("cmd", "b")?;
        logger.info("cmd", "note", "fyi")?;
        logger.skip("cmd", "live", "no creds")?;
        let summary = logger.finish()?;

        assert!(summary.ok());
        assert_eq!(summary.total, 4);
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.info, 1);

        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn summary_json_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("summary");
        let mut logger = RunLogger::new(&root, "trace-summary")?;
        logger.pass("cmd", "only")?;
        let summary = logger.finish()?;

        let json = fs::read_to_string(root.join("trace-summary").join("summary.json"))?;
        let parsed: RunSummary = serde_json::from_str(&json)?;
        assert_eq!(parsed, summary);

        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn event_lines_are_lf_only_and_individually_valid_json() -> Result<(), Box<dyn std::error::Error>> {
        let root = temp_root("lf");
        let mut logger = RunLogger::new(&root, "trace-lf")?;
        logger.pass("cmd", "first")?;
        logger.fail("cmd", "second", "x", "y")?;
        logger.finish()?;

        let events = fs::read_to_string(root.join("trace-lf").join("events.jsonl"))?;
        // No carriage returns; the goldens-discipline rule applies to logs too.
        assert!(!events.contains('\r'));
        for line in events.lines() {
            let _event: StepEvent = serde_json::from_str(line)?;
        }

        fs::remove_dir_all(&root)?;
        Ok(())
    }

    #[test]
    fn step_outcome_serializes_to_stable_snake_case() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(serde_json::to_string(&StepOutcome::Pass)?, "\"pass\"");
        assert_eq!(serde_json::to_string(&StepOutcome::Fail)?, "\"fail\"");
        assert_eq!(serde_json::to_string(&StepOutcome::Skip)?, "\"skip\"");
        assert_eq!(serde_json::to_string(&StepOutcome::Info)?, "\"info\"");
        Ok(())
    }

    #[test]
    fn pass_event_schema_is_stable() -> Result<(), Box<dyn std::error::Error>> {
        // Pin the JSON-line wire shape: a passing step carries exactly the
        // mandatory key set and omits the failure-only fields.
        let event = StepEvent {
            schema_version: LOG_SCHEMA_VERSION,
            trace_id: "t".to_owned(),
            command_id: "c".to_owned(),
            seq: 1,
            step: "s".to_owned(),
            outcome: StepOutcome::Pass,
            elapsed_ms: 0,
            detail: None,
            expected: None,
            actual: None,
        };
        let value = serde_json::to_value(&event)?;
        let object = value.as_object().ok_or("event must serialize to an object")?;
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "command_id",
                "elapsed_ms",
                "outcome",
                "schema_version",
                "seq",
                "step",
                "trace_id",
            ]
        );
        assert_eq!(
            object.get("schema_version").and_then(serde_json::Value::as_u64),
            Some(u64::from(LOG_SCHEMA_VERSION))
        );
        Ok(())
    }

    #[test]
    fn failure_event_schema_adds_expected_and_actual() -> Result<(), Box<dyn std::error::Error>> {
        let event = StepEvent {
            schema_version: LOG_SCHEMA_VERSION,
            trace_id: "t".to_owned(),
            command_id: "c".to_owned(),
            seq: 2,
            step: "s".to_owned(),
            outcome: StepOutcome::Fail,
            elapsed_ms: 0,
            detail: None,
            expected: Some("200".to_owned()),
            actual: Some("202".to_owned()),
        };
        let value = serde_json::to_value(&event)?;
        let object = value.as_object().ok_or("event must serialize to an object")?;
        assert_eq!(object.get("outcome").and_then(serde_json::Value::as_str), Some("fail"));
        assert_eq!(object.get("expected").and_then(serde_json::Value::as_str), Some("200"));
        assert_eq!(object.get("actual").and_then(serde_json::Value::as_str), Some("202"));
        // detail stays absent when not set.
        assert!(!object.contains_key("detail"));
        Ok(())
    }
}
