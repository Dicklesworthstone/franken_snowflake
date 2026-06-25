//! The SQL API response bodies, one type per HTTP status class.
//!
//! Snowflake returns a *different JSON shape per status code*: a `200` carries a
//! [`ResultSet`], a `202` a [`QueryStatus`] (poll again), and a `408`/`422` a
//! [`QueryFailureStatus`]. See [`crate::status::ResponseClass`] for the routing.
//!
//! `data` cells stay `Option<String>` at the schema layer: every non-null cell
//! is a `jsonv2` JSON **string** decoded later by [`crate::wire`] per its
//! [`ColumnType`]; a SQL `NULL` is JSON `null` → `None`.

use franken_snowflake_core::ids::{RequestId, StatementHandle};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A `200 OK` completed result. Partition 0 arrives inline in `data`; later
/// partitions are fetched separately (see [`PartitionInfo`]).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultSet {
    /// Column types, row count, and partition layout.
    pub result_set_meta_data: ResultSetMetaData,
    /// Inline partition-0 rows: a row is a vector of nullable `jsonv2` strings.
    pub data: Vec<Vec<Option<String>>>,
    /// Snowflake response code (e.g. a success code like `090001`).
    pub code: String,
    /// The statement handle (also the query id for re-fetch / cancel).
    pub statement_handle: StatementHandle,
    /// Relative URL to re-`GET` for status/partitions.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub statement_status_url: Option<String>,
    /// Per-sub-statement handles when `MULTI_STATEMENT_COUNT` fans out.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub statement_handles: Option<Vec<StatementHandle>>,
    /// SQLSTATE, when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sql_state: Option<String>,
    /// Human-readable message, when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub message: Option<String>,
    /// Echoed idempotency request id.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub request_id: Option<RequestId>,
    /// Server creation time (epoch millis), when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub created_on: Option<i64>,
    /// Opaque execution statistics, preserved verbatim.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub stats: Option<Value>,
}

impl ResultSet {
    /// Total rows across **all** partitions (not just the inline `data`).
    #[must_use]
    pub const fn total_rows(&self) -> i64 {
        self.result_set_meta_data.num_rows
    }

    /// Number of result partitions (≥ 1; partition 0 is inline).
    #[must_use]
    pub fn partition_count(&self) -> usize {
        self.result_set_meta_data.partition_info.len()
    }

    /// True when the response fanned out into multiple sub-statements.
    #[must_use]
    pub fn is_multi_statement(&self) -> bool {
        self.statement_handles
            .as_ref()
            .is_some_and(|handles| !handles.is_empty())
    }
}

/// Metadata describing the columns, total row count, and partition layout of a
/// [`ResultSet`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultSetMetaData {
    /// Total rows across every partition.
    pub num_rows: i64,
    /// Result encoding; `jsonv2` for the JSON result format.
    pub format: String,
    /// One entry per column, in column order.
    pub row_type: Vec<ColumnType>,
    /// Partition sizes; index 0 corresponds to the inline `data`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partition_info: Vec<PartitionInfo>,
}

/// A single column's authoritative type metadata — the source of truth for
/// decoding (`type` + `scale` + `precision`), never row inspection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ColumnType {
    /// Column name.
    pub name: String,
    /// Snowflake logical type (`FIXED`, `REAL`, `TEXT`, `BOOLEAN`, `DATE`,
    /// `TIME`, `TIMESTAMP_*`, `VARIANT`, `OBJECT`, `ARRAY`, `BINARY`, ...).
    #[serde(rename = "type")]
    pub column_type: String,
    /// Decimal scale (digits after the point) for `FIXED`/`NUMBER`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scale: Option<i32>,
    /// Total precision for `FIXED`/`NUMBER`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub precision: Option<i32>,
    /// Whether the column is nullable (distinct from the `nullable` query param).
    pub nullable: bool,
    /// Declared character length for `TEXT`-family columns.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub length: Option<i64>,
    /// Declared byte length.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub byte_length: Option<i64>,
    /// Source database, when reported.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub database: Option<String>,
    /// Source schema, when reported.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub schema: Option<String>,
    /// Source table, when reported.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub table: Option<String>,
    /// Collation specifier, when set.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub collation: Option<String>,
}

/// The size of one result partition. `numRows` on the parent
/// [`ResultSetMetaData`] is the total; these are per-partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartitionInfo {
    /// Rows in this partition.
    pub row_count: i64,
    /// Compressed (gzip) byte size.
    pub compressed_size: i64,
    /// Uncompressed byte size.
    pub uncompressed_size: i64,
}

/// A `202 Accepted` still-running status — the poll-again signal. Re-`GET` the
/// handle (or [`QueryStatus::statement_status_url`]) until it returns `200`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryStatus {
    /// Snowflake status code.
    pub code: String,
    /// SQLSTATE, when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sql_state: Option<String>,
    /// Human-readable message, when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub message: Option<String>,
    /// The statement handle to keep polling.
    pub statement_handle: StatementHandle,
    /// Relative URL to re-`GET`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub statement_status_url: Option<String>,
}

/// A `408` (statement timeout) or `422` (statement failed) body. The HTTP status
/// distinguishes the two — `408` is a typed timeout, `422` a SQL
/// compile/execution failure — so the same shape carries both.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryFailureStatus {
    /// Snowflake error code.
    pub code: String,
    /// SQLSTATE, when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sql_state: Option<String>,
    /// Human-readable failure message.
    pub message: String,
    /// The statement handle, when one was assigned before failure.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub statement_handle: Option<StatementHandle>,
}

/// The body returned by `POST /api/v2/statements/{handle}/cancel`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatementCancelResponse {
    /// Snowflake status code for the cancel.
    pub code: String,
    /// Human-readable message, when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub message: Option<String>,
    /// The cancelled statement's handle, when echoed.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub statement_handle: Option<StatementHandle>,
}
