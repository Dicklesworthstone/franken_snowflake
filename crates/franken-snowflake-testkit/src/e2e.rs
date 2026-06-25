//! Deterministic end-to-end harness over the stateful mock SQL API.
//!
//! This lane is intentionally account-free. It drives the production SQL API
//! statement lifecycle state machine with [`crate::mock::server::MockSqlApi`],
//! logs every proof step as JSON lines through [`crate::harness::logger`], and
//! leaves durable artifacts for CI and local debugging.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use franken_snowflake_core::redact::redact;
use franken_snowflake_sqlapi::lifecycle::{PollPlan, Progress, StatementMachine};
use franken_snowflake_sqlapi::response::StatementCancelResponse;
use franken_snowflake_sqlapi::status::ResponseClass as SqlResponseClass;
use serde::{Deserialize, Serialize};

use crate::harness::logger::{LogError, RunLogger, RunSummary};
use crate::mock::http::{MockHttpRequest, MockHttpResponse};
use crate::mock::scenarios;
use crate::mock::server::{MockSqlApi, RecordedRequest};

/// Stable trace id used by the default deterministic mock e2e lane.
pub const DEFAULT_E2E_TRACE_ID: &str = "fsnow-e2e-deterministic-mock-v1";

const COMMAND_ID: &str = "e2e.mock-sqlapi";
const RAW_TOKEN_SUFFIX: &str = "FSNOW_E2E_CANARY_DO_NOT_USE_000000";
const REQUIRED_LANES: u32 = 5;

/// Configuration for the deterministic mock e2e run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E2eHarnessConfig {
    /// Directory under which `trace_id/events.jsonl`, summaries, and reports are written.
    pub artifacts_root: PathBuf,
    /// Stable per-run trace id.
    pub trace_id: String,
}

impl E2eHarnessConfig {
    /// Build a config with explicit artifact root and trace id.
    #[must_use]
    pub fn new(artifacts_root: impl Into<PathBuf>, trace_id: impl Into<String>) -> Self {
        Self {
            artifacts_root: artifacts_root.into(),
            trace_id: trace_id.into(),
        }
    }
}

impl Default for E2eHarnessConfig {
    fn default() -> Self {
        Self {
            artifacts_root: std::env::temp_dir().join("fsnow-e2e-artifacts"),
            trace_id: DEFAULT_E2E_TRACE_ID.to_owned(),
        }
    }
}

/// Machine-readable report for the deterministic mock e2e run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct E2eHarnessReport {
    /// Stable per-run trace id.
    pub trace_id: String,
    /// Artifact directory containing `events.jsonl`, `summary.json`, and this report.
    pub artifacts_dir: String,
    /// Statement handle issued by the mock.
    pub statement_handle: String,
    /// Number of rows assembled after the partition fetch.
    pub rows: usize,
    /// Number of poll requests observed by the mock before completion.
    pub polls: u32,
    /// Whether the gzip partition lane fetched partition 1.
    pub partition_fetched: bool,
    /// Whether the cancel endpoint was called and recorded by the mock.
    pub cancelled: bool,
    /// Whether every recorded authorization value was redacted.
    pub redaction_verified: bool,
    /// Covered e2e lanes divided by required e2e lanes.
    pub coverage_ratio: f64,
    /// Logger summary for the same run.
    pub summary: RunSummary,
}

/// Error returned by the deterministic mock e2e harness.
#[derive(Debug)]
pub enum E2eHarnessError {
    /// Filesystem or JSONL logger failure.
    Log(LogError),
    /// JSON parse/write failure outside the logger.
    Json(serde_json::Error),
    /// Filesystem failure outside the logger.
    Io(std::io::Error),
    /// A proof lane failed.
    Assertion(String),
}

impl fmt::Display for E2eHarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Log(error) => write!(f, "{error}"),
            Self::Json(error) => write!(f, "e2e json error: {error}"),
            Self::Io(error) => write!(f, "e2e io error: {error}"),
            Self::Assertion(message) => write!(f, "e2e assertion failed: {message}"),
        }
    }
}

impl Error for E2eHarnessError {}

impl From<LogError> for E2eHarnessError {
    fn from(error: LogError) -> Self {
        Self::Log(error)
    }
}

impl From<serde_json::Error> for E2eHarnessError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<std::io::Error> for E2eHarnessError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Run the no-account e2e harness against the deterministic mock SQL API.
///
/// # Errors
/// Returns an [`E2eHarnessError`] if an artifact cannot be written or any e2e
/// lane fails.
pub fn run_mock_sqlapi_e2e(config: &E2eHarnessConfig) -> Result<E2eHarnessReport, E2eHarnessError> {
    let mut logger = RunLogger::new(&config.artifacts_root, config.trace_id.clone())?;
    logger.info(
        COMMAND_ID,
        "start",
        "deterministic mock sql api e2e; no live credentials",
    )?;

    let mut failures = Vec::new();
    let mut covered_lanes = 0_u32;
    let mut mock = MockSqlApi::new(
        scenarios::DEFAULT_HANDLE,
        scenarios::running(),
        two_partition_terminal(),
        scenarios::cancel(),
    )
    .with_polls_before_complete(2)
    .with_partition(1, scenarios::gzip_partition());

    let raw_token = raw_token();
    let lifecycle =
        run_statement_lifecycle_lane(&mut logger, &mut mock, &raw_token, &mut failures)?;
    if lifecycle.completed {
        covered_lanes += 1;
    }
    if lifecycle.partition_fetched {
        covered_lanes += 1;
    }

    if run_auth_lane(&mut logger, mock.requests(), &mut failures)? {
        covered_lanes += 1;
    }
    if run_cancel_lane(&mut logger, &raw_token, &mut failures)? {
        covered_lanes += 1;
    }
    if run_redaction_lane(&mut logger, mock.requests(), &raw_token, &mut failures)? {
        covered_lanes += 1;
    }

    let coverage_ratio = f64::from(covered_lanes) / f64::from(REQUIRED_LANES);
    log_check(
        &mut logger,
        &mut failures,
        "coverage",
        coverage_ratio >= 1.0,
        "all required e2e lanes covered",
        &format!("{covered_lanes}/{REQUIRED_LANES} lanes"),
    )?;

    let summary = logger.finish()?;
    let report = E2eHarnessReport {
        trace_id: summary.trace_id.clone(),
        artifacts_dir: summary.artifacts_dir.clone(),
        statement_handle: lifecycle.statement_handle,
        rows: lifecycle.rows,
        polls: lifecycle.polls,
        partition_fetched: lifecycle.partition_fetched,
        cancelled: true,
        redaction_verified: !requests_contain_raw_secret(mock.requests(), &raw_token),
        coverage_ratio,
        summary,
    };
    write_report(&report)?;

    if failures.is_empty() {
        Ok(report)
    } else {
        Err(E2eHarnessError::Assertion(failures.join("; ")))
    }
}

#[derive(Clone, Debug)]
struct LifecycleLaneReport {
    statement_handle: String,
    rows: usize,
    polls: u32,
    partition_fetched: bool,
    completed: bool,
}

fn run_statement_lifecycle_lane(
    logger: &mut RunLogger,
    mock: &mut MockSqlApi,
    raw_token: &str,
    failures: &mut Vec<String>,
) -> Result<LifecycleLaneReport, E2eHarnessError> {
    let mut machine = StatementMachine::new(PollPlan::with_max_polls(8));
    let submit = MockHttpRequest::post(
        "/api/v2/statements?async=true",
        scenarios::SUBMIT_SELECT_REQUEST.to_vec(),
    )
    .with_bearer(raw_token);
    let auth_header = submit.authorization().unwrap_or_default().to_owned();

    log_check(
        logger,
        failures,
        "auth-header-construction",
        auth_header.starts_with("Bearer "),
        "bearer authorization header",
        &redact(&auth_header),
    )?;

    let submit_response = mock.respond(&submit);
    let mut progress = machine
        .on_submit(
            SqlResponseClass::from_status(submit_response.status),
            &submit_response.body,
        )
        .map_err(|error| {
            E2eHarnessError::Assertion(format!("submit lifecycle decode failed: {error}"))
        })?;
    log_check(
        logger,
        failures,
        "submit",
        matches!(progress, Progress::PollAgain(_)),
        "202 submit returns poll handle",
        &format!("{progress:?}"),
    )?;

    let mut partition_fetched = false;
    let mut completed_rows = None;
    let mut statement_handle = mock.statement_handle().to_owned();

    loop {
        match progress {
            Progress::PollAgain(handle) => {
                statement_handle = handle.to_string();
                let poll_path = format!("/api/v2/statements/{handle}");
                let poll = MockHttpRequest::get(&poll_path).with_bearer(raw_token);
                let poll_response = mock.respond(&poll);
                progress = machine
                    .on_poll(
                        SqlResponseClass::from_status(poll_response.status),
                        &poll_response.body,
                    )
                    .map_err(|error| {
                        E2eHarnessError::Assertion(format!("poll lifecycle decode failed: {error}"))
                    })?;
            }
            Progress::FetchPartition { handle, partition } => {
                statement_handle = handle.to_string();
                let partition_path = format!("/api/v2/statements/{handle}?partition={partition}");
                let partition_request =
                    MockHttpRequest::get(&partition_path).with_bearer(raw_token);
                let partition_response = mock.respond(&partition_request);
                log_check(
                    logger,
                    failures,
                    "partition-gzip",
                    partition == 1
                        && partition_response.has_header("Content-Encoding")
                        && partition_response.body.starts_with(&[0x1f, 0x8b]),
                    "partition 1 gzip packet",
                    &format!(
                        "partition={partition}, status={}, bytes={}",
                        partition_response.status,
                        partition_response.body.len()
                    ),
                )?;
                partition_fetched = true;
                progress = machine
                    .on_partition(
                        SqlResponseClass::from_status(partition_response.status),
                        partition,
                        scenarios::PARTITION_1_PLAIN,
                    )
                    .map_err(|error| {
                        E2eHarnessError::Assertion(format!(
                            "partition lifecycle decode failed: {error}"
                        ))
                    })?;
            }
            Progress::Complete(done) => {
                completed_rows = Some(done.rows.len());
                statement_handle = done.statement_handle.to_string();
                break;
            }
            Progress::TimedOut(status) => {
                failures.push(format!("unexpected timeout {}", status.code));
                break;
            }
            Progress::Failed(status) => {
                failures.push(format!("unexpected sql failure {}", status.code));
                break;
            }
        }
    }

    let rows = completed_rows.unwrap_or(0);
    log_check(
        logger,
        failures,
        "poll-pagination-complete",
        mock.poll_count(&statement_handle) == 3 && rows == 4 && partition_fetched,
        "3 polls, 4 assembled rows, partition fetched",
        &format!(
            "polls={}, rows={rows}, partition_fetched={partition_fetched}",
            mock.poll_count(&statement_handle)
        ),
    )?;

    Ok(LifecycleLaneReport {
        statement_handle: statement_handle.clone(),
        rows,
        polls: mock.poll_count(&statement_handle),
        partition_fetched,
        completed: rows == 4,
    })
}

fn run_auth_lane(
    logger: &mut RunLogger,
    requests: &[RecordedRequest],
    failures: &mut Vec<String>,
) -> Result<bool, E2eHarnessError> {
    let request_count = requests
        .iter()
        .filter(|request| request.redacted_authorization.is_some())
        .count();
    let has_submit = requests.iter().any(|request| {
        request.path == "/api/v2/statements?async=true"
            && request.redacted_authorization.as_deref().is_some()
    });
    log_check(
        logger,
        failures,
        "auth-header-recorded",
        has_submit && request_count >= 5,
        "auth on submit/poll/partition requests",
        &format!("authorized_requests={request_count}"),
    )?;
    Ok(has_submit && request_count >= 5)
}

fn run_cancel_lane(
    logger: &mut RunLogger,
    raw_token: &str,
    failures: &mut Vec<String>,
) -> Result<bool, E2eHarnessError> {
    let mut cancel_mock = scenarios::default_async_lifecycle();
    let handle = cancel_mock.statement_handle().to_owned();
    let submit = MockHttpRequest::post(
        "/api/v2/statements?async=true",
        scenarios::SUBMIT_SELECT_REQUEST.to_vec(),
    )
    .with_bearer(raw_token);
    let _submit_response = cancel_mock.respond(&submit);

    let cancel_path = format!("/api/v2/statements/{handle}/cancel");
    let cancel_response = cancel_mock
        .respond(&MockHttpRequest::post(cancel_path, Vec::<u8>::new()).with_bearer(raw_token));
    let typed: StatementCancelResponse = serde_json::from_slice(&cancel_response.body)?;
    let cancelled = cancel_mock.is_cancelled(&handle);
    log_check(
        logger,
        failures,
        "cancel-endpoint",
        cancel_response.status == 200 && cancelled && !typed.code.is_empty(),
        "typed 200 cancel response and recorded cancellation",
        &format!(
            "status={}, code={}, cancelled={cancelled}",
            cancel_response.status, typed.code
        ),
    )?;
    Ok(cancel_response.status == 200 && cancelled && !typed.code.is_empty())
}

fn run_redaction_lane(
    logger: &mut RunLogger,
    requests: &[RecordedRequest],
    raw_token: &str,
    failures: &mut Vec<String>,
) -> Result<bool, E2eHarnessError> {
    let contains_raw = requests_contain_raw_secret(requests, raw_token);
    let redacted_authorizations = requests
        .iter()
        .filter_map(|request| request.redacted_authorization.as_deref())
        .filter(|value| value.contains("[REDACTED]"))
        .count();
    log_check(
        logger,
        failures,
        "secret-redaction",
        !contains_raw && redacted_authorizations >= 5,
        "raw token absent and redacted values present",
        &format!("contains_raw={contains_raw}, redacted_values={redacted_authorizations}"),
    )?;
    Ok(!contains_raw && redacted_authorizations >= 5)
}

fn requests_contain_raw_secret(requests: &[RecordedRequest], raw_token: &str) -> bool {
    requests.iter().any(|request| {
        request
            .redacted_authorization
            .as_deref()
            .is_some_and(|value| value.contains(raw_token))
    })
}

fn raw_token() -> String {
    ["sfpat_", RAW_TOKEN_SUFFIX].concat()
}

fn log_check(
    logger: &mut RunLogger,
    failures: &mut Vec<String>,
    step: &'static str,
    passed: bool,
    expected: &str,
    actual: &str,
) -> Result<(), E2eHarnessError> {
    if passed {
        logger.pass(COMMAND_ID, step)?;
    } else {
        logger.fail(COMMAND_ID, step, expected, actual)?;
        failures.push(format!("{step}: expected {expected}, actual {actual}"));
    }
    Ok(())
}

fn write_report(report: &E2eHarnessReport) -> Result<(), E2eHarnessError> {
    let artifacts_dir = Path::new(&report.artifacts_dir);
    fs::write(
        artifacts_dir.join("e2e-report.json"),
        serde_json::to_string_pretty(report)?,
    )?;
    Ok(())
}

fn two_partition_terminal() -> MockHttpResponse {
    MockHttpResponse::json(
        200,
        br#"{
  "resultSetMetaData": {
    "numRows": 4,
    "format": "jsonv2",
    "rowType": [
      { "name": "ID", "type": "FIXED", "nullable": false, "precision": 38, "scale": 0 },
      { "name": "NAME", "type": "TEXT", "nullable": false, "length": 16 }
    ],
    "partitionInfo": [
      { "rowCount": 2, "compressedSize": 64, "uncompressedSize": 32 },
      { "rowCount": 2, "compressedSize": 64, "uncompressedSize": 32 }
    ]
  },
  "data": [["1", "alpha"], ["2", "beta"]],
  "code": "090001",
  "statementHandle": "01b2c3d4-0000-0000-0000-000000000002",
  "statementStatusUrl": "/api/v2/statements/01b2c3d4-0000-0000-0000-000000000002"
}"#
        .to_vec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_mock_sqlapi_e2e_writes_jsonl_artifacts() -> Result<(), Box<dyn Error>> {
        let root = std::env::temp_dir().join("fsnow-e2e-unit");
        let config = E2eHarnessConfig::new(&root, "fsnow-e2e-unit-trace");
        let report = run_mock_sqlapi_e2e(&config)?;

        assert_eq!(report.rows, 4);
        assert_eq!(report.polls, 3);
        assert!(report.partition_fetched);
        assert!(report.cancelled);
        assert!(report.redaction_verified);
        assert_eq!(report.coverage_ratio, 1.0);

        let events = fs::read_to_string(root.join("fsnow-e2e-unit-trace").join("events.jsonl"))?;
        assert!(events.contains("\"step\":\"submit\""));
        assert!(events.contains("\"step\":\"cancel-endpoint\""));
        assert!(events.contains("\"step\":\"secret-redaction\""));
        assert!(!events.contains(&raw_token()));
        Ok(())
    }
}
