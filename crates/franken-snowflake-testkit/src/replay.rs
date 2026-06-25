//! Deterministic replay harness for no-account SQL API protocol packets.
//!
//! The replay layer drives [`crate::mock::server::MockSqlApi`] through the
//! statement lifecycle and freezes the observable protocol surface: request
//! method/path, response status/class, headers, body bytes, and full HTTP/1.1
//! wire bytes. The packet records are JSON-serializable so tests can compare
//! them with committed goldens using [`crate::harness::golden`].

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::mock::http::{MockHttpRequest, MockHttpResponse, ResponseClass};
use crate::mock::{scenarios, server::MockSqlApi};

/// A replay failure.
#[derive(Debug)]
pub enum ReplayError {
    /// A response body was not valid JSON when a JSON golden was requested.
    Json(serde_json::Error),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(f, "replay json error: {error}"),
        }
    }
}

impl std::error::Error for ReplayError {}

impl From<serde_json::Error> for ReplayError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// A single deterministic HTTP protocol packet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolPacket {
    /// Stable step name.
    pub name: String,
    /// Request method token.
    pub request_method: String,
    /// Request path, including query string.
    pub request_path: String,
    /// Response status code.
    pub status: u16,
    /// SQL API response class label.
    pub response_class: String,
    /// Response headers in emit order.
    pub headers: Vec<(String, String)>,
    /// Hex-encoded response body bytes.
    pub body_hex: String,
    /// Hex-encoded full HTTP/1.1 response packet.
    pub wire_hex: String,
}

impl ProtocolPacket {
    /// Build a packet from a request/response pair.
    #[must_use]
    pub fn from_exchange(name: impl Into<String>, request: &MockHttpRequest, response: &MockHttpResponse) -> Self {
        Self {
            name: name.into(),
            request_method: request.method.as_str().to_owned(),
            request_path: request.path.clone(),
            status: response.status,
            response_class: response_class_label(response).to_owned(),
            headers: response.headers.clone(),
            body_hex: hex(&response.body),
            wire_hex: hex(&response.to_wire()),
        }
    }

    /// Decode the JSON response body for structured golden comparison.
    ///
    /// # Errors
    /// Returns [`ReplayError::Json`] when the packet body is not JSON.
    pub fn body_json(&self) -> Result<Value, ReplayError> {
        let bytes = unhex(&self.body_hex);
        Ok(serde_json::from_slice(&bytes)?)
    }
}

/// A replayed request/response step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayStep {
    /// Stable step name.
    pub name: String,
    /// The packet captured for this step.
    pub packet: ProtocolPacket,
}

/// A deterministic replay summary suitable for golden comparison.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySummary {
    /// Summary schema version.
    pub schema_version: u32,
    /// Scenario name.
    pub scenario: String,
    /// Statement handle issued by the fixture.
    pub statement_handle: String,
    /// Number of poll requests observed for the handle.
    pub poll_count: u32,
    /// Whether the handle was cancelled during the replay.
    pub cancelled: bool,
    /// Captured protocol packets.
    pub steps: Vec<ReplayStep>,
}

/// A deterministic state-machine driver over [`MockSqlApi`].
#[derive(Clone, Debug)]
pub struct ReplayHarness {
    scenario: String,
    mock: MockSqlApi,
    steps: Vec<ReplayStep>,
}

impl ReplayHarness {
    /// Create a replay harness for `mock`.
    #[must_use]
    pub fn new(scenario: impl Into<String>, mock: MockSqlApi) -> Self {
        Self {
            scenario: scenario.into(),
            mock,
            steps: Vec::new(),
        }
    }

    /// The statement handle for the current scenario.
    #[must_use]
    pub fn statement_handle(&self) -> &str {
        self.mock.statement_handle()
    }

    /// Send a request through the mock and capture the deterministic packet.
    pub fn send(&mut self, name: impl Into<String>, request: MockHttpRequest) -> MockHttpResponse {
        let name = name.into();
        let response = self.mock.respond(&request);
        let packet = ProtocolPacket::from_exchange(name.clone(), &request, &response);
        self.steps.push(ReplayStep { name, packet });
        response
    }

    /// Submit the default select request asynchronously.
    pub fn submit_default_select(&mut self) -> MockHttpResponse {
        self.send(
            "submit",
            MockHttpRequest::post(
                "/api/v2/statements?async=true",
                scenarios::SUBMIT_SELECT_REQUEST.to_vec(),
            ),
        )
    }

    /// Poll the current handle once.
    pub fn poll(&mut self, name: impl Into<String>) -> MockHttpResponse {
        let path = format!("/api/v2/statements/{}", self.statement_handle());
        self.send(name, MockHttpRequest::get(path))
    }

    /// Fetch a result partition for the current handle.
    pub fn fetch_partition(&mut self, partition: u32) -> MockHttpResponse {
        let path = format!(
            "/api/v2/statements/{}?partition={partition}",
            self.statement_handle()
        );
        self.send(format!("partition-{partition}"), MockHttpRequest::get(path))
    }

    /// Cancel the current handle.
    pub fn cancel(&mut self) -> MockHttpResponse {
        let path = format!("/api/v2/statements/{}/cancel", self.statement_handle());
        self.send("cancel", MockHttpRequest::post(path, Vec::new()))
    }

    /// Finish the replay and return a serializable summary.
    #[must_use]
    pub fn finish(self) -> ReplaySummary {
        let handle = self.mock.statement_handle().to_owned();
        ReplaySummary {
            schema_version: 1,
            scenario: self.scenario,
            poll_count: self.mock.poll_count(&handle),
            cancelled: self.mock.is_cancelled(&handle),
            statement_handle: handle,
            steps: self.steps,
        }
    }
}

/// Replay the default no-account async lifecycle:
/// submit -> 202 poll -> 202 poll -> 200 poll -> gzip partition fetch -> cancel.
#[must_use]
pub fn default_protocol_replay() -> ReplaySummary {
    let mut replay = ReplayHarness::new(
        "default-async-select-with-partition-and-cancel",
        scenarios::default_async_lifecycle(),
    );
    replay.submit_default_select();
    replay.poll("poll-1-running");
    replay.poll("poll-2-running");
    replay.poll("poll-3-complete");
    replay.fetch_partition(1);
    replay.cancel();
    replay.finish()
}

fn response_class_label(response: &MockHttpResponse) -> &'static str {
    match response.class() {
        ResponseClass::Completed => "completed",
        ResponseClass::Running => "running",
        ResponseClass::StatementTimeout => "statement_timeout",
        ResponseClass::StatementFailed => "statement_failed",
        ResponseClass::RateLimited => "rate_limited",
        ResponseClass::Other(_) => "other",
    }
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

fn unhex(hex_text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hex_text.len() / 2);
    let mut chars = hex_text.as_bytes().chunks_exact(2);
    for pair in &mut chars {
        if let (Some(high), Some(low)) = (hex_value(pair[0]), hex_value(pair[1])) {
            out.push((high << 4) | low);
        }
    }
    out
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::golden::{
        GoldenConfig, assert_no_cr, check_golden_file, to_canonical_json,
    };

    #[test]
    fn default_replay_captures_lifecycle_partition_and_cancel() {
        let replay = default_protocol_replay();
        assert_eq!(replay.steps.len(), 6);
        assert_eq!(replay.poll_count, 3);
        assert!(replay.cancelled);
        assert_eq!(replay.steps[0].packet.status, 202);
        assert_eq!(replay.steps[3].packet.status, 200);
        assert_eq!(replay.steps[4].packet.response_class, "completed");
        assert!(
            replay.steps[4]
                .packet
                .headers
                .iter()
                .any(|(name, value)| name == "Content-Encoding" && value == "gzip")
        );
    }

    #[test]
    fn default_protocol_packets_match_committed_golden() -> Result<(), Box<dyn std::error::Error>> {
        let replay = default_protocol_replay();
        let value = serde_json::to_value(replay)?;
        let cfg = GoldenConfig::strict();
        let canonical = to_canonical_json(&value, &cfg);
        assert_no_cr(&canonical)?;
        let path = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/golden/default_protocol_replay.golden.json"
        ));
        check_golden_file(path, &value, &cfg)?;
        Ok(())
    }
}
