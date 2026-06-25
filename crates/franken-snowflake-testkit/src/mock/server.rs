//! The stateful, transport-agnostic mock SQL API server.
//!
//! [`MockSqlApi`] models the statement lifecycle the connector drives:
//!
//! ```text
//! POST /api/v2/statements            -> 202 running (async) | 200 terminal (immediate)
//! GET  /api/v2/statements/{handle}   -> 202 running ×N, then the terminal response
//! POST /api/v2/statements/{handle}/cancel -> cancel response
//! ```
//!
//! It is pure request→response state (a `fastapi_rust` handler would just call
//! [`MockSqlApi::respond`]), and it records every request with the
//! `Authorization` header **already redacted** through the shared
//! `franken_snowflake_core::redact` needle list, so an auth-leak inspection test
//! never has to hold a raw token.

use std::collections::BTreeMap;

use franken_snowflake_core::redact::redact;

use super::http::{Method, MockHttpRequest, MockHttpResponse};

const SUBMIT_PATH: &str = "/api/v2/statements";

/// A request the mock observed, captured for inspection. The authorization value
/// is stored redacted; the raw token is never retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedRequest {
    /// The method.
    pub method: Method,
    /// The request path (query string included).
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
    query.and_then(|query| {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            if key == "partition" {
                value.parse::<u32>().ok()
            } else {
                None
            }
        })
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

    /// The handle this mock issues.
    #[must_use]
    pub fn statement_handle(&self) -> &str {
        &self.statement_handle
    }

    /// Dispatch a request to the lifecycle state machine and record it.
    pub fn respond(&mut self, request: &MockHttpRequest) -> MockHttpResponse {
        self.log.push(RecordedRequest {
            method: request.method.clone(),
            path: request.path.clone(),
            redacted_authorization: request
                .authorization()
                .map(|value| redact(value).into_owned()),
            header_count: request.headers.len(),
        });

        match (&request.method, route(&request.path)) {
            (Method::Post, Route::Submit) => self.on_submit(),
            (Method::Get, Route::Statement(handle)) => self.on_poll(&handle),
            (Method::Get, Route::Partition { handle, partition }) => {
                self.on_partition(&handle, partition)
            }
            (Method::Post, Route::Cancel(handle)) => self.on_cancel(&handle),
            _ => not_found(),
        }
    }

    fn on_submit(&mut self) -> MockHttpResponse {
        if self.immediate {
            self.terminal.clone()
        } else {
            self.running.clone()
        }
    }

    fn on_poll(&mut self, handle: &str) -> MockHttpResponse {
        if handle != self.statement_handle {
            return not_found();
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
            mock.respond(&MockHttpRequest::get("/api/v2/statements/nope")).status,
            404
        );
        Ok(())
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
}
