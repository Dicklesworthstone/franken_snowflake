//! The canned response catalog.
//!
//! The 200 / 202 / 408 / 422 bodies are the **kx6 protocol goldens** embedded
//! verbatim with [`include_bytes!`] — a single source of truth shared with the
//! `franken-snowflake-sqlapi` round-trip proofs, so the mock can never drift
//! from the schemas under test. The 429 backoff body and the gzip partition
//! packet are testkit-owned fixtures (Snowflake returns no canonical 429 body,
//! and the gzip fixture is built with `gzip -n` for byte-deterministic bytes).
//!
//! Each `pub fn` returns a fresh [`MockHttpResponse`]; the typed accessors parse
//! a body into its `franken-snowflake-sqlapi` schema for assertions.

use serde_json::Value;

use super::http::MockHttpResponse;
use super::server::MockSqlApi;

/// Path to a kx6 fixture under the sibling `franken-snowflake-sqlapi` crate.
macro_rules! kx6_fixture {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../franken-snowflake-sqlapi/tests/fixtures/",
            $name
        ))
    };
}

/// `POST /statements` select request body (kx6 golden).
pub const SUBMIT_SELECT_REQUEST: &[u8] = kx6_fixture!("submit_select_request.json");
/// `POST /statements` request body with positional bindings (kx6 golden).
pub const SUBMIT_WITH_BINDINGS_REQUEST: &[u8] = kx6_fixture!("submit_with_bindings_request.json");
/// `200` single-partition result set (kx6 golden).
pub const RESP_200_SINGLE: &[u8] = kx6_fixture!("resp_200_resultset_single_partition.json");
/// `200` multi-partition result set (kx6 golden).
pub const RESP_200_MULTI: &[u8] = kx6_fixture!("resp_200_resultset_multi_partition.json");
/// `200` multi-statement fan-out result (kx6 golden).
pub const RESP_200_MULTI_STATEMENT: &[u8] = kx6_fixture!("resp_200_multi_statement.json");
/// `202` still-running status (kx6 golden).
pub const RESP_202_RUNNING: &[u8] = kx6_fixture!("resp_202_running.json");
/// `408` statement-timeout failure (kx6 golden).
pub const RESP_408_TIMEOUT: &[u8] = kx6_fixture!("resp_408_statement_timeout.json");
/// `422` statement-failed body (kx6 golden).
pub const RESP_422_FAILURE: &[u8] = kx6_fixture!("resp_422_failure.json");
/// `POST /statements/{handle}/cancel` response (kx6 golden).
pub const CANCEL_RESPONSE: &[u8] = kx6_fixture!("cancel_response.json");

/// Testkit-owned `429` rate-limit body (no canonical Snowflake fixture exists).
pub const RESP_429_RATE_LIMITED: &[u8] =
    br#"{"code":"429","message":"Request rate limit exceeded. Back off and retry."}"#;

/// Testkit-owned gzip partition packet (`gzip -n`, byte-deterministic).
pub const PARTITION_1_GZIP: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/fixtures/packets/partition_1.json.gz"
));
/// The decompressed bytes of [`PARTITION_1_GZIP`], for round-trip verification.
pub const PARTITION_1_PLAIN: &[u8] = br#"[["3","gamma"],["4","delta"]]"#;

/// The handle issued by [`default_async_lifecycle`] — matches the `202` golden.
pub const DEFAULT_HANDLE: &str = "01b2c3d4-0000-0000-0000-000000000002";

/// `200` completed, single inline partition.
#[must_use]
pub fn ok_single_partition() -> MockHttpResponse {
    MockHttpResponse::json(200, RESP_200_SINGLE.to_vec())
}

/// `200` completed, multiple partitions.
#[must_use]
pub fn ok_multi_partition() -> MockHttpResponse {
    MockHttpResponse::json(200, RESP_200_MULTI.to_vec())
}

/// `200` multi-statement fan-out.
#[must_use]
pub fn multi_statement() -> MockHttpResponse {
    MockHttpResponse::json(200, RESP_200_MULTI_STATEMENT.to_vec())
}

/// `202` still running — poll again.
#[must_use]
pub fn running() -> MockHttpResponse {
    MockHttpResponse::json(202, RESP_202_RUNNING.to_vec())
}

/// `408` statement timeout (terminal, typed — not a generic failure).
#[must_use]
pub fn statement_timeout() -> MockHttpResponse {
    MockHttpResponse::json(408, RESP_408_TIMEOUT.to_vec())
}

/// `422` statement failed (terminal SQL error).
#[must_use]
pub fn statement_failed() -> MockHttpResponse {
    MockHttpResponse::json(422, RESP_422_FAILURE.to_vec())
}

/// `429` rate limited — back off and retry. No guaranteed `Retry-After`.
#[must_use]
pub fn rate_limited() -> MockHttpResponse {
    MockHttpResponse::json(429, RESP_429_RATE_LIMITED.to_vec())
}

/// `200` gzip-compressed partition body (`Content-Encoding: gzip`).
#[must_use]
pub fn gzip_partition() -> MockHttpResponse {
    MockHttpResponse::gzip_json(200, PARTITION_1_GZIP.to_vec())
}

/// The cancel acknowledgement.
#[must_use]
pub fn cancel() -> MockHttpResponse {
    MockHttpResponse::json(200, CANCEL_RESPONSE.to_vec())
}

/// The default async lifecycle: issues [`DEFAULT_HANDLE`], returns `202` for two
/// polls then the single-partition `200`, and answers a cancel.
#[must_use]
pub fn default_async_lifecycle() -> MockSqlApi {
    MockSqlApi::new(DEFAULT_HANDLE, running(), ok_single_partition(), cancel())
        .with_polls_before_complete(2)
        .with_partition(1, gzip_partition())
}

/// The scripted reply sequence for a single connection driving a `202 → 202 →
/// 200` poll progression — what the codec lane replays over a `VirtualTcpStream`.
#[must_use]
pub fn poll_progression() -> Vec<MockHttpResponse> {
    vec![running(), running(), ok_single_partition()]
}

/// Parse the single-partition `200` body into its typed schema.
///
/// # Errors
/// Returns the `serde_json` error if the embedded fixture fails to parse.
pub fn ok_single_partition_typed() -> Result<Value, serde_json::Error> {
    serde_json::from_slice(RESP_200_SINGLE)
}

/// Parse the `202` running body into its typed schema.
///
/// # Errors
/// Returns the `serde_json` error if the embedded fixture fails to parse.
pub fn running_typed() -> Result<Value, serde_json::Error> {
    serde_json::from_slice(RESP_202_RUNNING)
}

/// Parse the `408`/`422` failure body into its typed schema.
///
/// # Errors
/// Returns the `serde_json` error if the embedded fixture fails to parse.
pub fn failure_typed(body: &[u8]) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(body)
}

/// Parse the cancel body into its typed schema.
///
/// # Errors
/// Returns the `serde_json` error if the embedded fixture fails to parse.
pub fn cancel_typed() -> Result<Value, serde_json::Error> {
    serde_json::from_slice(CANCEL_RESPONSE)
}

#[cfg(test)]
mod tests {
    use super::super::http::ResponseClass;
    use super::*;

    #[test]
    fn embedded_kx6_bodies_parse_into_their_schemas() -> Result<(), String> {
        let result = ok_single_partition_typed().map_err(|e| e.to_string())?;
        assert_eq!(result["resultSetMetaData"]["numRows"], 2);
        let status = running_typed().map_err(|e| e.to_string())?;
        assert_eq!(status["statementHandle"], DEFAULT_HANDLE);
        let timeout = failure_typed(RESP_408_TIMEOUT).map_err(|e| e.to_string())?;
        assert!(timeout["message"].as_str().is_some_and(|message| !message.is_empty()));
        cancel_typed().map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn status_codes_classify_distinctly() {
        assert_eq!(running().class(), ResponseClass::Running);
        assert_eq!(ok_single_partition().class(), ResponseClass::Completed);
        assert_eq!(statement_timeout().class(), ResponseClass::StatementTimeout);
        assert_eq!(statement_failed().class(), ResponseClass::StatementFailed);
        assert_eq!(rate_limited().class(), ResponseClass::RateLimited);
    }

    #[test]
    fn gzip_partition_packet_is_deterministic_and_advertised() {
        let response = gzip_partition();
        assert!(response.has_header("Content-Encoding"));
        // gzip magic + a zeroed mtime (bytes 4..8) prove `gzip -n` determinism.
        assert_eq!(&response.body[0..2], &[0x1f, 0x8b]);
        assert_eq!(&response.body[4..8], &[0x00, 0x00, 0x00, 0x00]);
    }
}
