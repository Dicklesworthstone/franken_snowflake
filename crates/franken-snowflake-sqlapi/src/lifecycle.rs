//! The statement lifecycle state machine: submit -> poll/await -> partition
//! assembly, as a **pure, synchronous** Mealy machine.
//!
//! Implements bead `fsnow-statement-lifecycle-ofl`. The machine holds *all* the
//! lifecycle logic — status routing, the bounded poll loop, and multi-partition
//! row assembly — but performs **no IO**: a caller feeds it each response
//! (status class + body bytes) and it returns the next [`Progress`] step. That
//! makes the whole flow testable end-to-end against the deterministic, no-socket
//! `franken_snowflake_testkit::mock::MockSqlApi` without a runtime.
//!
//! The async glue that pumps this machine against the live
//! `franken-snowflake-http` transport (and fires the remote cancel endpoint on
//! local cancellation) lives in [`crate::driver`]. Gzip partition bodies are
//! decompressed by the transport, so the machine always receives **decoded**
//! partition bytes.

use franken_snowflake_core::error::{SnowflakeError, SnowflakeErrorCode};
use franken_snowflake_core::ids::StatementHandle;

use crate::response::{QueryFailureStatus, QueryStatus, ResultSet};
use crate::status::ResponseClass;

/// How long to poll a `202` handle before giving up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollPlan {
    /// Maximum number of poll `GET`s before [`LifecycleErrorCode::PollQuotaExhausted`].
    pub max_polls: u32,
}

impl Default for PollPlan {
    fn default() -> Self {
        Self { max_polls: 120 }
    }
}

impl PollPlan {
    /// A plan with an explicit poll ceiling (clamped to at least 1).
    #[must_use]
    pub fn with_max_polls(max_polls: u32) -> Self {
        Self {
            max_polls: max_polls.max(1),
        }
    }
}

/// The fully-assembled result of a completed statement: the parsed terminal
/// [`ResultSet`] (metadata + inline partition-0 rows) plus every row across all
/// fetched partitions, concatenated in partition order.
#[derive(Clone, Debug, PartialEq)]
pub struct CompletedStatement {
    /// The statement handle (also the re-fetch / cancel id).
    pub statement_handle: StatementHandle,
    /// The terminal `200` result set, including column metadata.
    pub result_set: ResultSet,
    /// All rows across every partition (`data` ++ each fetched partition).
    pub rows: Vec<Vec<Option<String>>>,
}

/// The next step a caller should take after feeding the machine a response.
#[derive(Clone, Debug, PartialEq)]
pub enum Progress {
    /// Poll this handle again (the statement is still running).
    PollAgain(StatementHandle),
    /// Fetch this result partition next (multi-partition assembly in progress).
    FetchPartition {
        /// The statement handle to fetch from.
        handle: StatementHandle,
        /// The 1-based partition index to fetch.
        partition: u32,
    },
    /// The statement completed and all partitions are assembled.
    Complete(CompletedStatement),
    /// Terminal: the statement hit its server-side `STATEMENT_TIMEOUT` (`408`).
    TimedOut(QueryFailureStatus),
    /// Terminal: the statement failed to compile or execute (`422`).
    Failed(QueryFailureStatus),
}

/// A lifecycle-orchestration error (distinct from a *protocol* timeout/failure,
/// which are [`Progress::TimedOut`] / [`Progress::Failed`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleError {
    /// Stable error class.
    pub code: LifecycleErrorCode,
    /// A value-free explanation (never echoes row data).
    pub message: String,
}

/// Stable [`LifecycleError`] classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LifecycleErrorCode {
    /// A response body did not parse into its expected schema.
    DecodeFailed,
    /// A response carried a status the current phase cannot accept.
    UnexpectedStatus,
    /// The poll quota was exhausted while the statement was still running.
    PollQuotaExhausted,
    /// Assembled row count did not match `resultSetMetaData.numRows`.
    PartitionRowMismatch,
}

impl LifecycleError {
    fn new(code: LifecycleErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Map to the shared connector error registry for the CLI/MCP edge.
    #[must_use]
    pub fn into_snowflake_error(self) -> SnowflakeError {
        let code = match self.code {
            LifecycleErrorCode::DecodeFailed
            | LifecycleErrorCode::UnexpectedStatus
            | LifecycleErrorCode::PartitionRowMismatch => SnowflakeErrorCode::UpstreamError,
            LifecycleErrorCode::PollQuotaExhausted => SnowflakeErrorCode::RetryBudgetExhausted,
        };
        SnowflakeError::new(code, self.message)
    }
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for LifecycleError {}

/// Internal phase of the lifecycle.
#[derive(Clone, Debug)]
enum Phase {
    /// Before submit, or polling a `202` handle.
    Pending,
    /// Completed; fetching the non-inline partitions `next..total`.
    Assembling {
        result_set: ResultSet,
        handle: StatementHandle,
        total: u32,
        next: u32,
        rows: Vec<Vec<Option<String>>>,
    },
    /// Terminal (completed, failed, timed out, or errored).
    Done,
}

/// The pure statement lifecycle driver. Construct with [`StatementMachine::new`],
/// then feed each response with [`StatementMachine::on_submit`] /
/// [`StatementMachine::on_poll`] / [`StatementMachine::on_partition`].
#[derive(Clone, Debug)]
pub struct StatementMachine {
    poll_plan: PollPlan,
    polls_done: u32,
    phase: Phase,
}

impl StatementMachine {
    /// A fresh machine awaiting the submit response.
    #[must_use]
    pub fn new(poll_plan: PollPlan) -> Self {
        Self {
            poll_plan,
            polls_done: 0,
            phase: Phase::Pending,
        }
    }

    /// Number of poll `GET`s consumed so far.
    #[must_use]
    pub const fn polls_done(&self) -> u32 {
        self.polls_done
    }

    /// Feed the response to `POST /api/v2/statements`.
    ///
    /// # Errors
    /// [`LifecycleError`] if the body fails to decode or the status is one a
    /// submit can never legitimately return.
    pub fn on_submit(
        &mut self,
        class: ResponseClass,
        body: &[u8],
    ) -> Result<Progress, LifecycleError> {
        match class {
            ResponseClass::Completed => self.enter_terminal_result(parse_result_set(body)?),
            ResponseClass::Running => {
                let status = parse_query_status(body)?;
                Ok(Progress::PollAgain(status.statement_handle))
            }
            ResponseClass::StatementTimeout => Ok(Progress::TimedOut(parse_failure(body)?)),
            ResponseClass::StatementFailed => Ok(Progress::Failed(parse_failure(body)?)),
            ResponseClass::RateLimited | ResponseClass::Other(_) => Err(LifecycleError::new(
                LifecycleErrorCode::UnexpectedStatus,
                "submit returned a non-terminal, non-running status",
            )),
        }
    }

    /// Feed the response to a poll `GET /api/v2/statements/{handle}`.
    ///
    /// # Errors
    /// [`LifecycleError`] on decode failure, an unexpected status, or an
    /// exhausted poll quota.
    pub fn on_poll(
        &mut self,
        class: ResponseClass,
        body: &[u8],
    ) -> Result<Progress, LifecycleError> {
        self.polls_done = self.polls_done.saturating_add(1);
        match class {
            ResponseClass::Completed => self.enter_terminal_result(parse_result_set(body)?),
            ResponseClass::StatementTimeout => Ok(Progress::TimedOut(parse_failure(body)?)),
            ResponseClass::StatementFailed => Ok(Progress::Failed(parse_failure(body)?)),
            // Still running, or a transient 429 the transport will have backed off
            // on: keep polling unless the quota is spent.
            ResponseClass::Running | ResponseClass::RateLimited => {
                if self.polls_done > self.poll_plan.max_polls {
                    return Err(LifecycleError::new(
                        LifecycleErrorCode::PollQuotaExhausted,
                        format!(
                            "statement still running after {} polls",
                            self.poll_plan.max_polls
                        ),
                    ));
                }
                let status = parse_query_status(body)?;
                Ok(Progress::PollAgain(status.statement_handle))
            }
            ResponseClass::Other(_) => Err(LifecycleError::new(
                LifecycleErrorCode::UnexpectedStatus,
                "poll returned an unexpected status",
            )),
        }
    }

    /// Feed the response to a partition `GET ...?partition=N`. `body` is the
    /// **decoded** (post-gzip) partition payload: a bare JSON array of rows.
    ///
    /// # Errors
    /// [`LifecycleError`] on decode failure, a non-`200` status, an out-of-order
    /// partition, or a final row count that disagrees with `numRows`.
    pub fn on_partition(
        &mut self,
        class: ResponseClass,
        partition: u32,
        body: &[u8],
    ) -> Result<Progress, LifecycleError> {
        if !matches!(class, ResponseClass::Completed) {
            self.phase = Phase::Done;
            return Err(LifecycleError::new(
                LifecycleErrorCode::UnexpectedStatus,
                format!("partition {partition} returned a non-200 status"),
            ));
        }
        let Phase::Assembling {
            result_set,
            handle,
            total,
            next,
            mut rows,
        } = std::mem::replace(&mut self.phase, Phase::Done)
        else {
            return Err(LifecycleError::new(
                LifecycleErrorCode::UnexpectedStatus,
                "partition response arrived outside the assembling phase",
            ));
        };
        if partition != next {
            self.phase = Phase::Assembling {
                result_set,
                handle,
                total,
                next,
                rows,
            };
            return Err(LifecycleError::new(
                LifecycleErrorCode::UnexpectedStatus,
                format!("expected partition {next}, received {partition}"),
            ));
        }

        rows.append(&mut parse_partition_rows(body)?);
        let upcoming = next.saturating_add(1);
        if upcoming >= total {
            let expected = result_set.result_set_meta_data.num_rows;
            if expected >= 0 && rows.len() as i64 != expected {
                return Err(LifecycleError::new(
                    LifecycleErrorCode::PartitionRowMismatch,
                    format!("assembled {} rows but numRows is {expected}", rows.len()),
                ));
            }
            Ok(Progress::Complete(CompletedStatement {
                statement_handle: handle,
                result_set,
                rows,
            }))
        } else {
            let resume = handle.clone();
            self.phase = Phase::Assembling {
                result_set,
                handle,
                total,
                next: upcoming,
                rows,
            };
            Ok(Progress::FetchPartition {
                handle: resume,
                partition: upcoming,
            })
        }
    }

    /// Enter partition assembly (or finish immediately for a single partition).
    fn enter_terminal_result(&mut self, result_set: ResultSet) -> Result<Progress, LifecycleError> {
        let handle = result_set.statement_handle.clone();
        let total = partition_total(&result_set);
        let rows = result_set.data.clone();
        if total <= 1 {
            self.phase = Phase::Done;
            Ok(Progress::Complete(CompletedStatement {
                statement_handle: handle,
                result_set,
                rows,
            }))
        } else {
            let resume = handle.clone();
            self.phase = Phase::Assembling {
                result_set,
                handle,
                total,
                next: 1,
                rows,
            };
            Ok(Progress::FetchPartition {
                handle: resume,
                partition: 1,
            })
        }
    }
}

/// Total partitions for a result set (partition 0 is the inline `data`). An
/// absent or single-entry `partitionInfo` means everything is inline.
#[must_use]
fn partition_total(result_set: &ResultSet) -> u32 {
    u32::try_from(result_set.result_set_meta_data.partition_info.len().max(1)).unwrap_or(u32::MAX)
}

fn parse_result_set(body: &[u8]) -> Result<ResultSet, LifecycleError> {
    serde_json::from_slice(body)
        .map_err(|error| LifecycleError::new(LifecycleErrorCode::DecodeFailed, error.to_string()))
}

fn parse_query_status(body: &[u8]) -> Result<QueryStatus, LifecycleError> {
    serde_json::from_slice(body)
        .map_err(|error| LifecycleError::new(LifecycleErrorCode::DecodeFailed, error.to_string()))
}

fn parse_failure(body: &[u8]) -> Result<QueryFailureStatus, LifecycleError> {
    serde_json::from_slice(body)
        .map_err(|error| LifecycleError::new(LifecycleErrorCode::DecodeFailed, error.to_string()))
}

/// Decode a non-inline partition body: a bare JSON array of rows.
///
/// # Errors
/// [`LifecycleErrorCode::DecodeFailed`] if the body is not a JSON row array.
pub fn parse_partition_rows(body: &[u8]) -> Result<Vec<Vec<Option<String>>>, LifecycleError> {
    serde_json::from_slice(body)
        .map_err(|error| LifecycleError::new(LifecycleErrorCode::DecodeFailed, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_total_treats_absent_or_single_info_as_inline() -> Result<(), String> {
        let body = br#"{"resultSetMetaData":{"numRows":0,"format":"jsonv2","rowType":[]},
            "data":[],"code":"090001","statementHandle":"h"}"#;
        let result_set = parse_result_set(body).map_err(|error| error.to_string())?;
        assert_eq!(partition_total(&result_set), 1);
        Ok(())
    }

    #[test]
    fn single_partition_completes_immediately() -> Result<(), String> {
        let body = br#"{"resultSetMetaData":{"numRows":1,"format":"jsonv2",
            "rowType":[{"name":"A","type":"TEXT","nullable":false}],
            "partitionInfo":[{"rowCount":1,"compressedSize":1,"uncompressedSize":1}]},
            "data":[["x"]],"code":"090001","statementHandle":"h"}"#;
        let mut machine = StatementMachine::new(PollPlan::default());
        match machine.on_submit(ResponseClass::Completed, body) {
            Ok(Progress::Complete(done)) => {
                assert_eq!(done.rows.len(), 1);
                assert_eq!(done.statement_handle, StatementHandle::new("h"));
                Ok(())
            }
            other => Err(format!("expected Complete, got {other:?}")),
        }
    }

    #[test]
    fn running_then_completed_polls_then_finishes() -> Result<(), String> {
        let running = br#"{"code":"333334","statementHandle":"h2"}"#;
        let completed = br#"{"resultSetMetaData":{"numRows":0,"format":"jsonv2","rowType":[]},
            "data":[],"code":"090001","statementHandle":"h2"}"#;
        let mut machine = StatementMachine::new(PollPlan::default());
        match machine.on_submit(ResponseClass::Running, running) {
            Ok(Progress::PollAgain(h)) => assert_eq!(h, StatementHandle::new("h2")),
            other => return Err(format!("expected PollAgain, got {other:?}")),
        }
        match machine.on_poll(ResponseClass::Completed, completed) {
            Ok(Progress::Complete(_)) => Ok(()),
            other => Err(format!("expected Complete, got {other:?}")),
        }
    }

    #[test]
    fn poll_quota_is_enforced() -> Result<(), String> {
        let running = br#"{"code":"333334","statementHandle":"h3"}"#;
        let mut machine = StatementMachine::new(PollPlan::with_max_polls(2));
        machine
            .on_poll(ResponseClass::Running, running)
            .map_err(|e| e.to_string())?;
        machine
            .on_poll(ResponseClass::Running, running)
            .map_err(|e| e.to_string())?;
        match machine.on_poll(ResponseClass::Running, running) {
            Err(error) => {
                assert_eq!(error.code, LifecycleErrorCode::PollQuotaExhausted);
                Ok(())
            }
            Ok(progress) => Err(format!("expected quota error, got {progress:?}")),
        }
    }

    #[test]
    fn timeout_and_failure_are_distinct_terminal_states() -> Result<(), String> {
        let timeout = br#"{"code":"000630","message":"timed out","statementHandle":"h"}"#;
        let failure = br#"{"code":"001003","message":"bad sql","statementHandle":"h"}"#;
        let mut machine = StatementMachine::new(PollPlan::default());
        assert!(matches!(
            machine.on_submit(ResponseClass::StatementTimeout, timeout),
            Ok(Progress::TimedOut(_))
        ));
        let mut other = StatementMachine::new(PollPlan::default());
        assert!(matches!(
            other.on_submit(ResponseClass::StatementFailed, failure),
            Ok(Progress::Failed(_))
        ));
        Ok(())
    }

    #[test]
    fn multi_partition_assembles_rows_in_order() -> Result<(), String> {
        // 3 partitions, numRows 5: 2 inline + 2 (partition 1) + 1 (partition 2).
        let terminal = br#"{"resultSetMetaData":{"numRows":5,"format":"jsonv2",
            "rowType":[{"name":"ID","type":"FIXED","nullable":false},
                       {"name":"NAME","type":"TEXT","nullable":false}],
            "partitionInfo":[{"rowCount":2,"compressedSize":1,"uncompressedSize":1},
                             {"rowCount":2,"compressedSize":1,"uncompressedSize":1},
                             {"rowCount":1,"compressedSize":1,"uncompressedSize":1}]},
            "data":[["1","a"],["2","b"]],"code":"090001","statementHandle":"hp"}"#;
        let mut machine = StatementMachine::new(PollPlan::default());
        let first = machine.on_submit(ResponseClass::Completed, terminal);
        let handle = match first {
            Ok(Progress::FetchPartition { handle, partition: 1 }) => handle,
            other => return Err(format!("expected FetchPartition 1, got {other:?}")),
        };
        assert_eq!(handle, StatementHandle::new("hp"));
        match machine.on_partition(ResponseClass::Completed, 1, br#"[["3","c"],["4","d"]]"#) {
            Ok(Progress::FetchPartition { partition: 2, .. }) => {}
            other => return Err(format!("expected FetchPartition 2, got {other:?}")),
        }
        match machine.on_partition(ResponseClass::Completed, 2, br#"[["5","e"]]"#) {
            Ok(Progress::Complete(done)) => {
                assert_eq!(done.rows.len(), 5);
                assert_eq!(done.rows[4], vec![Some("5".to_owned()), Some("e".to_owned())]);
                Ok(())
            }
            other => Err(format!("expected Complete, got {other:?}")),
        }
    }

    #[test]
    fn row_count_mismatch_is_rejected() {
        let terminal = br#"{"resultSetMetaData":{"numRows":99,"format":"jsonv2",
            "rowType":[{"name":"A","type":"TEXT","nullable":false}],
            "partitionInfo":[{"rowCount":1,"compressedSize":1,"uncompressedSize":1},
                             {"rowCount":1,"compressedSize":1,"uncompressedSize":1}]},
            "data":[["x"]],"code":"090001","statementHandle":"hp"}"#;
        let mut machine = StatementMachine::new(PollPlan::default());
        let _ = machine.on_submit(ResponseClass::Completed, terminal);
        let result = machine.on_partition(ResponseClass::Completed, 1, br#"[["y"]]"#);
        assert!(matches!(
            result,
            Err(LifecycleError {
                code: LifecycleErrorCode::PartitionRowMismatch,
                ..
            })
        ));
    }
}
