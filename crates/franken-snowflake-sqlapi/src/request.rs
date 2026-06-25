//! The `POST /api/v2/statements` request body and its query parameters.
//!
//! Snowflake JSON keys are camelCase, so the structs use
//! `#[serde(rename_all = "camelCase")]`; absent optionals are omitted on the
//! wire (`skip_serializing_if`) so a minimal request serializes to just
//! `{"statement":"..."}`. Identifier fields reuse the `franken-snowflake-core`
//! newtypes, which serialize transparently as bare strings.

use std::collections::BTreeMap;

use franken_snowflake_core::ids::{DatabaseName, RoleName, SchemaName, WarehouseName};
use serde::{Deserialize, Serialize};

/// The body of a `POST /api/v2/statements` submit.
///
/// The idempotency `requestId`, `retry`, and `async` controls are **query
/// parameters** (see [`SubmitQueryParams`]), not body fields. `bindings` are not
/// permitted together with multi-statement requests — that refusal is enforced
/// by the planner, not the schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitStatementRequest {
    /// The SQL text. A single statement unless `MULTI_STATEMENT_COUNT` is set in
    /// [`SubmitStatementRequest::parameters`].
    pub statement: String,

    /// Server-side statement timeout in seconds (`STATEMENT_TIMEOUT_IN_SECONDS`).
    /// The enforceable cost/runtime guardrail; the client `Budget` is advisory.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub timeout: Option<u32>,

    /// Default database for the statement's session.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub database: Option<DatabaseName>,

    /// Default schema for the statement's session.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub schema: Option<SchemaName>,

    /// Warehouse that runs the statement.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub warehouse: Option<WarehouseName>,

    /// Role the statement runs as.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub role: Option<RoleName>,

    /// Positional typed bind values, keyed by 1-based **string** indices.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bindings: Option<BTreeMap<String, Binding>>,

    /// Session parameters pinned for deterministic output (e.g. `TIMEZONE`, the
    /// `*_OUTPUT_FORMAT` params, `USE_CACHED_RESULT`, `MULTI_STATEMENT_COUNT`).
    /// Values are strings on the wire.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parameters: Option<BTreeMap<String, String>>,
}

impl SubmitStatementRequest {
    /// A bare single-statement request with no session overrides.
    #[must_use]
    pub fn new(statement: impl Into<String>) -> Self {
        Self {
            statement: statement.into(),
            timeout: None,
            database: None,
            schema: None,
            warehouse: None,
            role: None,
            bindings: None,
            parameters: None,
        }
    }
}

/// A single positional, typed bind value.
///
/// Snowflake keys bindings by 1-based string index and the `value` is **always**
/// a JSON string regardless of the logical type (e.g. a number bind is
/// `{"type":"FIXED","value":"42"}`). The type name is uppercase on the wire and
/// kept as a `String` for lossless round-trips across Snowflake's open type set;
/// see [`bind_type`] for the common names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// The Snowflake binding type name (uppercase), e.g. `TEXT`, `FIXED`,
    /// `BOOLEAN`, `TIMESTAMP_NTZ`.
    #[serde(rename = "type")]
    pub value_type: String,
    /// The bound value, JSON-string-encoded.
    pub value: String,
}

impl Binding {
    /// Construct a binding from a type name and string-encoded value.
    #[must_use]
    pub fn new(value_type: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            value_type: value_type.into(),
            value: value.into(),
        }
    }
}

/// Common Snowflake binding type names (the `type` field of a [`Binding`]).
pub mod bind_type {
    /// Text / VARCHAR.
    pub const TEXT: &str = "TEXT";
    /// Fixed-point numeric (NUMBER).
    pub const FIXED: &str = "FIXED";
    /// Floating point.
    pub const REAL: &str = "REAL";
    /// Boolean.
    pub const BOOLEAN: &str = "BOOLEAN";
    /// Calendar date.
    pub const DATE: &str = "DATE";
    /// Wall-clock time.
    pub const TIME: &str = "TIME";
    /// Timestamp without time zone.
    pub const TIMESTAMP_NTZ: &str = "TIMESTAMP_NTZ";
    /// Timestamp with local time zone.
    pub const TIMESTAMP_LTZ: &str = "TIMESTAMP_LTZ";
    /// Timestamp with time zone.
    pub const TIMESTAMP_TZ: &str = "TIMESTAMP_TZ";
    /// Binary.
    pub const BINARY: &str = "BINARY";
}

/// The submit-time **query parameters** that ride on the `POST` URL rather than
/// the body. They are the idempotency contract: a stable [`SubmitQueryParams::request_id`]
/// plus `retry=true` makes a resubmit safe (the original result is returned
/// instead of re-running). This struct is a typed carrier for the transport
/// crate to render into a query string; it is not serialized into the body.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SubmitQueryParams {
    /// Client-generated UUID; the SQL API idempotency `requestId`.
    pub request_id: Option<String>,
    /// `retry=true` marks a safe resubmit of a previously-sent `requestId`.
    pub retry: bool,
    /// `async=true` returns a handle immediately instead of waiting.
    pub asynchronous: bool,
    /// `nullable=false` renders SQL NULL as the string `"null"` instead of JSON
    /// `null`. Unrelated to `rowType[].nullable`.
    pub nullable: Option<bool>,
}

impl SubmitQueryParams {
    /// Render the non-default parameters as `(key, value)` query pairs, in a
    /// stable order, for the transport crate to URL-encode.
    #[must_use]
    pub fn to_query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(id) = &self.request_id {
            pairs.push(("requestId", id.clone()));
        }
        if self.retry {
            pairs.push(("retry", "true".to_owned()));
        }
        if self.asynchronous {
            pairs.push(("async", "true".to_owned()));
        }
        if let Some(nullable) = self.nullable {
            pairs.push(("nullable", nullable.to_string()));
        }
        pairs
    }
}
