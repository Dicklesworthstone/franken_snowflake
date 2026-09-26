//! The stateful, transport-agnostic mock SQL API server.
//!
//! [`MockSqlApi`] models the statement lifecycle the connector drives:
//!
//! ```text
//! POST /api/v2/statements            -> 202 running (async) | 200 terminal (immediate)
//!      ?requestId=R&retry=true, R seen -> the statement's current status, not run again
//! GET  /api/v2/statements/{handle}   -> 202 running ×N, then the terminal response
//! POST /api/v2/statements/{handle}/cancel -> cancel response
//! ```
//!
//! It is pure request→response state (a `fastapi_rust` handler would just call
//! [`MockSqlApi::respond`]), and it records every request with the
//! `Authorization` header **already redacted** through the shared
//! `franken_snowflake_core::redact` needle list, so an auth-leak inspection test
//! never has to hold a raw token.

use std::collections::{BTreeMap, BTreeSet};

use franken_snowflake_core::redact::redact;

use super::http::{Method, MockHttpRequest, MockHttpResponse};

const SUBMIT_PATH: &str = "/api/v2/statements";

/// A request the mock observed, captured for inspection. The authorization value
/// is stored redacted; the raw token is never retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedRequest {
    /// The method.
    pub method: Method,
    /// The request path (query string included), redacted through the shared
    /// needle list.
    pub path: String,
    /// The `Authorization` header, redacted through the shared needle list.
    pub redacted_authorization: Option<String>,
    /// How many headers the request carried.
    pub header_count: usize,
}

/// What a parsed path resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Route {
    Submit,
    Statement(String),
    Partition { handle: String, partition: u32 },
    Cancel(String),
    Unknown,
}

fn route(path: &str) -> Route {
    let mut pieces = path.splitn(2, '?');
    let route_path = pieces.next().unwrap_or(path);
    let query = pieces.next();
    if route_path == SUBMIT_PATH {
        return Route::Submit;
    }
    if let Some(rest) = route_path.strip_prefix("/api/v2/statements/") {
        if let Some(handle) = rest.strip_suffix("/cancel") {
            if !handle.is_empty() && !handle.contains('/') {
                return Route::Cancel(handle.to_owned());
            }
        } else if !rest.is_empty() && !rest.contains('/') {
            if let Some(partition) = partition_query_value(query) {
                return Route::Partition {
                    handle: rest.to_owned(),
                    partition,
                };
            }
            return Route::Statement(rest.to_owned());
        }
    }
    Route::Unknown
}

fn partition_query_value(query: Option<&str>) -> Option<u32> {
    query_value(query, "partition").and_then(|value| value.parse::<u32>().ok())
}

fn query_value<'q>(query: Option<&'q str>, name: &str) -> Option<&'q str> {
    query?.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then_some(value)
    })
}

/// A deterministic, no-account mock of the Snowflake SQL API statement lifecycle.
#[derive(Clone, Debug)]
pub struct MockSqlApi {
    statement_handle: String,
    running: MockHttpResponse,
    terminal: MockHttpResponse,
    cancel: MockHttpResponse,
    polls_before_complete: u32,
    immediate: bool,
    partitions: BTreeMap<u32, MockHttpResponse>,
    poll_counts: BTreeMap<String, u32>,
    cancelled: BTreeMap<String, bool>,
    log: Vec<RecordedRequest>,
    /// Times the statement was started (a submit Snowflake would execute).
    executions: u32,
    /// Every `requestId` a submit carried.
    request_ids: BTreeSet<String>,
    /// Replaces the answer to the first execution (it ran, the answer was lost).
    lost_submit_answer: Option<MockHttpResponse>,
}

impl MockSqlApi {
    /// Build a mock that issues `statement_handle` on submit, replies `running`
    /// while a poll count is below the threshold, then `terminal`, and answers a
    /// cancel with `cancel`. Defaults to one `202` poll before completion.
    #[must_use]
    pub fn new(
        statement_handle: impl Into<String>,
        running: MockHttpResponse,
        terminal: MockHttpResponse,
        cancel: MockHttpResponse,
    ) -> Self {
        Self {
            statement_handle: statement_handle.into(),
            running,
            terminal,
            cancel,
            polls_before_complete: 1,
            immediate: false,
            partitions: BTreeMap::new(),
            poll_counts: BTreeMap::new(),
            cancelled: BTreeMap::new(),
            log: Vec::new(),
            executions: 0,
            request_ids: BTreeSet::new(),
            lost_submit_answer: None,
        }
    }

    /// Number of `202` polls returned before the terminal response (builder).
    #[must_use]
    pub fn with_polls_before_complete(mut self, polls: u32) -> Self {
        self.polls_before_complete = polls;
        self
    }

    /// Make `POST /statements` return the terminal response directly (a
    /// synchronous submit) rather than a `202` handle (builder).
    #[must_use]
    pub fn immediate(mut self) -> Self {
        self.immediate = true;
        self
    }

    /// Register a deterministic partition-fetch response (builder). Snowflake
    /// fetches non-inline partitions with `GET /api/v2/statements/{handle}?partition=N`.
    #[must_use]
    pub fn with_partition(mut self, partition: u32, response: MockHttpResponse) -> Self {
        self.partitions.insert(partition, response);
        self
    }

    /// The first submit starts the statement but is answered with `response`
    /// (an answer lost after the statement ran, e.g. a `500`), so the client's
    /// resubmit meets a statement that already exists (builder).
    #[must_use]
    pub fn with_lost_submit_answer(mut self, response: MockHttpResponse) -> Self {
        self.lost_submit_answer = Some(response);
        self
    }

    /// The handle this mock issues.
    #[must_use]
    pub fn statement_handle(&self) -> &str {
        &self.statement_handle
    }

    /// Dispatch a request to the lifecycle state machine and record it.
    pub fn respond(&mut self, request: &MockHttpRequest) -> MockHttpResponse {
        self.log.push(RecordedRequest {
            method: request.method.clone(),
            path: redact(&request.path).into_owned(),
            redacted_authorization: request
                .authorization()
                .map(|value| redact(value).into_owned()),
            header_count: request.headers.len(),
        });

        let query = request.path.split_once('?').map(|(_, query)| query);
        match (&request.method, route(&request.path)) {
            (Method::Post, Route::Submit) => self.on_submit(query),
            (Method::Get, Route::Statement(handle)) => self.on_poll(&handle),
            (Method::Get, Route::Partition { handle, partition }) => {
                self.on_partition(&handle, partition)
            }
            (Method::Post, Route::Cancel(handle)) => self.on_cancel(&handle),
            _ => not_found(),
        }
    }

    /// Snowflake does not execute a statement again when a request with the same
    /// `requestId` is resubmitted with `retry=true` (SQL API docs, "Resubmitting
    /// a request to execute SQL statements", consulted 2026-09-25:
    /// <https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests#resubmitting-a-request-to-execute-sql-statements>).
    /// The docs do not say what such a resubmit returns; this mock answers with
    /// the statement's current status, as a poll of its handle would. Without
    /// `retry=true` the same `requestId` runs the statement again, which is the
    /// double execution the docs warn about.
    fn on_submit(&mut self, query: Option<&str>) -> MockHttpResponse {
        let request_id = query_value(query, "requestId").filter(|id| !id.is_empty());
        let retry = query_value(query, "retry") == Some("true");
        if let Some(request_id) = request_id {
            if retry && self.request_ids.contains(request_id) {
                return self.current_status();
            }
            self.request_ids.insert(request_id.to_owned());
        }
        self.executions = self.executions.saturating_add(1);
        if let Some(lost) = self.lost_submit_answer.take() {
            return lost;
        }
        if self.immediate {
            self.terminal.clone()
        } else {
            self.running.clone()
        }
    }

    /// The statement's status, without counting a poll.
    fn current_status(&self) -> MockHttpResponse {
        if self.is_cancelled(&self.statement_handle) {
            cancelled_status(&self.statement_handle)
        } else if self.immediate
            || self.poll_count(&self.statement_handle) > self.polls_before_complete
        {
            self.terminal.clone()
        } else {
            self.running.clone()
        }
    }

    fn on_poll(&mut self, handle: &str) -> MockHttpResponse {
        if handle != self.statement_handle {
            return not_found();
        }
        if self.is_cancelled(handle) {
            return cancelled_status(handle);
        }
        let count = self.poll_counts.entry(handle.to_owned()).or_insert(0);
        *count += 1;
        if *count > self.polls_before_complete {
            self.terminal.clone()
        } else {
            self.running.clone()
        }
    }

    fn on_partition(&self, handle: &str, partition: u32) -> MockHttpResponse {
        if handle != self.statement_handle {
            return not_found();
        }
        if self.is_cancelled(handle) {
            return cancelled_status(handle);
        }
        self.partitions
            .get(&partition)
            .cloned()
            .unwrap_or_else(not_found)
    }

    fn on_cancel(&mut self, handle: &str) -> MockHttpResponse {
        if handle != self.statement_handle {
            return not_found();
        }
        self.cancelled.insert(handle.to_owned(), true);
        self.cancel.clone()
    }

    /// How many times a submit started the statement.
    #[must_use]
    pub const fn executions(&self) -> u32 {
        self.executions
    }

    /// How many times `handle` has been polled.
    #[must_use]
    pub fn poll_count(&self, handle: &str) -> u32 {
        self.poll_counts.get(handle).copied().unwrap_or(0)
    }

    /// Whether `handle` has been cancelled.
    #[must_use]
    pub fn is_cancelled(&self, handle: &str) -> bool {
        self.cancelled.get(handle).copied().unwrap_or(false)
    }

    /// Every request the mock has handled, in order.
    #[must_use]
    pub fn requests(&self) -> &[RecordedRequest] {
        &self.log
    }

    /// The redacted `Authorization` values observed, in order.
    #[must_use]
    pub fn observed_authorizations(&self) -> Vec<&str> {
        self.log
            .iter()
            .filter_map(|request| request.redacted_authorization.as_deref())
            .collect()
    }
}

fn not_found() -> MockHttpResponse {
    MockHttpResponse::json(
        404,
        br#"{"code":"390404","message":"Statement handle not found."}"#.to_vec(),
    )
}

fn cancelled_status(handle: &str) -> MockHttpResponse {
    // Snowflake SQL API reference consulted 2026-06-25:
    // https://docs.snowflake.com/en/developer-guide/sql-api/reference
    // Cancel returns code 000604 / SQLSTATE 57014; later status checks must not
    // turn a locally cancelled handle into a successful ResultSet.
    let body = serde_json::json!({
        "code": "000604",
        "sqlState": "57014",
        "message": "SQL execution canceled",
        "statementHandle": handle,
        "statementStatusUrl": format!("/api/v2/statements/{handle}"),
    })
    .to_string()
    .into_bytes();
    MockHttpResponse::json(422, body)
}

#[cfg(test)]
mod tests {
    use super::super::scenarios;
    use super::*;

    #[test]
    fn route_parses_the_three_lifecycle_paths() {
        assert_eq!(route("/api/v2/statements"), Route::Submit);
        assert_eq!(route("/api/v2/statements?async=true"), Route::Submit);
        assert_eq!(
            route("/api/v2/statements/abc-123"),
            Route::Statement("abc-123".to_owned())
        );
        assert_eq!(
            route("/api/v2/statements/abc-123?partition=1"),
            Route::Partition {
                handle: "abc-123".to_owned(),
                partition: 1,
            }
        );
        assert_eq!(
            route("/api/v2/statements/abc-123/cancel"),
            Route::Cancel("abc-123".to_owned())
        );
        assert_eq!(route("/api/v2/other"), Route::Unknown);
    }

    #[test]
    fn async_lifecycle_runs_then_completes_then_cancels() -> Result<(), String> {
        let mut mock = scenarios::default_async_lifecycle();
        let handle = mock.statement_handle().to_owned();

        // Submit -> 202 running with a handle.
        let submit = mock.respond(&MockHttpRequest::post(
            "/api/v2/statements?async=true",
            scenarios::SUBMIT_SELECT_REQUEST.to_vec(),
        ));
        assert_eq!(submit.status, 202);

        // Two polls stay 202, the third completes (polls_before_complete = 2).
        let poll_path = format!("/api/v2/statements/{handle}");
        assert_eq!(mock.respond(&MockHttpRequest::get(&poll_path)).status, 202);
        assert_eq!(mock.respond(&MockHttpRequest::get(&poll_path)).status, 202);
        assert_eq!(mock.respond(&MockHttpRequest::get(&poll_path)).status, 200);
        assert_eq!(mock.poll_count(&handle), 3);

        // Partition fetch is independent from polling and can return gzip bytes.
        let partition_path = format!("/api/v2/statements/{handle}?partition=1");
        let partition = mock.respond(&MockHttpRequest::get(&partition_path));
        assert_eq!(partition.status, 200);
        assert!(partition.has_header("Content-Encoding"));

        // Cancel is acknowledged.
        let cancel_path = format!("/api/v2/statements/{handle}/cancel");
        let cancel = mock.respond(&MockHttpRequest::post(&cancel_path, Vec::new()));
        assert_eq!(cancel.status, 200);
        assert!(mock.is_cancelled(&handle));

        // An unknown handle is a clean 404, never a panic or a wrong-state reply.
        assert_eq!(
            mock.respond(&MockHttpRequest::get("/api/v2/statements/nope"))
                .status,
            404
        );
        Ok(())
    }

    /// Bead o2o: a resubmit with the same `requestId` and `retry=true` meets the
    /// statement already running (same handle) and starts nothing new; a new
    /// `requestId` is a new statement.
    #[test]
    fn a_retry_resubmit_of_a_known_request_id_runs_nothing_again() {
        let mut mock = scenarios::default_async_lifecycle();
        let submit = |id: &str| {
            MockHttpRequest::post(
                format!("/api/v2/statements?requestId={id}&retry=true"),
                scenarios::SUBMIT_SELECT_REQUEST.to_vec(),
            )
        };
        let first = mock.respond(&submit("r-1"));
        assert_eq!((first.status, mock.executions()), (202, 1));
        let again = mock.respond(&submit("r-1"));
        assert_eq!((again.status, mock.executions()), (202, 1));
        assert!(String::from_utf8_lossy(&again.body).contains(mock.statement_handle()));
        // Answered from the statement's status: no poll was counted.
        assert_eq!(mock.poll_count(mock.statement_handle()), 0);
        mock.respond(&submit("r-2"));
        assert_eq!(mock.executions(), 2);
    }

    /// The negative the docs warn about: the same `requestId` without
    /// `retry=true` (or with no `requestId` at all) runs the statement again.
    #[test]
    fn a_resubmit_without_retry_true_runs_the_statement_again() {
        let mut mock = scenarios::default_async_lifecycle();
        let body = scenarios::SUBMIT_SELECT_REQUEST.to_vec();
        let with_id = "/api/v2/statements?requestId=r-1";
        mock.respond(&MockHttpRequest::post(with_id, body.clone()));
        mock.respond(&MockHttpRequest::post(with_id, body.clone()));
        assert_eq!(mock.executions(), 2);
        mock.respond(&MockHttpRequest::post("/api/v2/statements", body.clone()));
        mock.respond(&MockHttpRequest::post("/api/v2/statements", body));
        assert_eq!(mock.executions(), 4);
    }

    /// A lost answer: the statement ran, the client saw a `500`; its resubmit
    /// finds the statement (completed once polled past the threshold) instead
    /// of running it twice.
    #[test]
    fn a_lost_submit_answer_is_recovered_by_the_retry_resubmit() {
        let mut mock = scenarios::default_async_lifecycle()
            .with_lost_submit_answer(MockHttpResponse::json(500, b"{}".to_vec()));
        let submit = MockHttpRequest::post(
            "/api/v2/statements?requestId=r-1&retry=true",
            scenarios::SUBMIT_SELECT_REQUEST.to_vec(),
        );
        assert_eq!(mock.respond(&submit).status, 500);
        assert_eq!(mock.respond(&submit).status, 202);
        let poll = format!("/api/v2/statements/{}", mock.statement_handle());
        for _ in 0..3 {
            mock.respond(&MockHttpRequest::get(&poll));
        }
        assert_eq!(mock.respond(&submit).status, 200);
        assert_eq!(mock.executions(), 1);
    }

    #[test]
    fn authorization_is_recorded_redacted() -> Result<(), String> {
        let mut mock = scenarios::default_async_lifecycle();
        // A JWT-shaped bearer token must never be stored raw.
        let request = MockHttpRequest::post("/api/v2/statements", Vec::new())
            .with_bearer("eyJhbGciOiJSUzI1NiJ9.payload.signature");
        mock.respond(&request);
        let observed = mock.observed_authorizations();
        assert_eq!(observed.len(), 1);
        assert!(observed[0].contains("[REDACTED]"));
        assert!(!observed[0].contains("eyJhbGciOiJSUzI1NiJ9"));
        Ok(())
    }

    #[test]
    fn request_path_is_recorded_redacted() -> Result<(), String> {
        let mut mock = scenarios::default_async_lifecycle();
        mock.respond(&MockHttpRequest::get(
            "/api/v2/statements/abc-123?token=sfpat_SECRET123",
        ));
        let recorded = mock
            .requests()
            .first()
            .ok_or_else(|| "request should be recorded".to_string())?;
        assert!(recorded.path.contains("[REDACTED]"));
        assert!(!recorded.path.contains("sfpat_SECRET123"));
        Ok(())
    }

    #[test]
    fn cancelled_handle_no_longer_completes_or_serves_partitions() -> Result<(), String> {
        let mut mock = scenarios::default_async_lifecycle();
        let handle = mock.statement_handle().to_owned();
        let cancel_path = format!("/api/v2/statements/{handle}/cancel");
        assert_eq!(
            mock.respond(&MockHttpRequest::post(cancel_path, Vec::new()))
                .status,
            200
        );

        let poll_path = format!("/api/v2/statements/{handle}");
        let poll = mock.respond(&MockHttpRequest::get(&poll_path));
        assert_eq!(poll.status, 422);
        let poll_body = std::str::from_utf8(&poll.body).map_err(|error| error.to_string())?;
        assert!(poll_body.contains("\"code\":\"000604\""));
        assert!(poll_body.contains("\"sqlState\":\"57014\""));
        assert!(poll_body.contains("SQL execution canceled"));

        let partition_path = format!("/api/v2/statements/{handle}?partition=1");
        let partition = mock.respond(&MockHttpRequest::get(&partition_path));
        assert_eq!(partition.status, 422);
        Ok(())
    }
}
