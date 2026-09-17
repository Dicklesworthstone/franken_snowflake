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
        self.result_set_meta_data.partition_info.len().max(1)
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
    /// Compressed (gzip) byte size. **Optional**: the live SQL API omits
    /// `compressedSize` for inline/uncompressed partition 0 (observed against a
    /// real account, 2026-06-25 — a `SELECT` returns `{"rowCount":N,
    /// "uncompressedSize":B}` with no `compressedSize`). A required field here
    /// made every live response fail to decode (`missing field compressedSize`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compressed_size: Option<i64>,
    /// Uncompressed byte size. Optional for the same reason (Snowflake omits
    /// either size field depending on partition encoding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncompressed_size: Option<i64>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_count_is_at_least_one() {
        let result_empty = ResultSet {
            result_set_meta_data: ResultSetMetaData {
                num_rows: 0,
                format: "jsonv2".to_owned(),
                row_type: vec![],
                partition_info: vec![],
            },
            data: vec![],
            code: "090001".to_owned(),
            statement_handle: StatementHandle::new("h1"),
            statement_status_url: None,
            statement_handles: None,
            sql_state: None,
            message: None,
            request_id: None,
            created_on: None,
            stats: None,
        };
        assert_eq!(result_empty.partition_count(), 1);

        let mut result_multi = result_empty;
        result_multi.result_set_meta_data.partition_info = vec![
            PartitionInfo {
                row_count: 5,
                uncompressed_size: Some(100),
                compressed_size: Some(50),
            },
            PartitionInfo {
                row_count: 5,
                uncompressed_size: Some(100),
                compressed_size: Some(50),
            },
        ];
        assert_eq!(result_multi.partition_count(), 2);
    }

    #[test]
    fn result_set_helpers_and_flags() {
        let mut rs = ResultSet {
            result_set_meta_data: ResultSetMetaData {
                num_rows: 42,
                format: "jsonv2".to_owned(),
                row_type: vec![ColumnType {
                    name: "ID".to_owned(),
                    column_type: "FIXED".to_owned(),
                    scale: Some(0),
                    precision: Some(38),
                    nullable: false,
                    length: None,
                    byte_length: None,
                    database: None,
                    schema: None,
                    table: None,
                    collation: None,
                }],
                partition_info: vec![],
            },
            data: vec![],
            code: "090001".to_owned(),
            statement_handle: StatementHandle::new("h1"),
            statement_status_url: None,
            statement_handles: None,
            sql_state: None,
            message: None,
            request_id: None,
            created_on: None,
            stats: None,
        };

        assert_eq!(rs.total_rows(), 42);
        assert!(!rs.is_multi_statement());

        rs.statement_handles = Some(vec![]);
        assert!(!rs.is_multi_statement());

        rs.statement_handles = Some(vec![
            StatementHandle::new("sub-1"),
            StatementHandle::new("sub-2"),
        ]);
        assert!(rs.is_multi_statement());
    }

    #[test]
    fn partition_info_serde_matrix() -> Result<(), serde_json::Error> {
        // Minimal: rowCount only
        let minimal_json = r#"{"rowCount":100}"#;
        let p1: PartitionInfo = serde_json::from_str(minimal_json)?;
        assert_eq!(p1.row_count, 100);
        assert_eq!(p1.compressed_size, None);
        assert_eq!(p1.uncompressed_size, None);

        // Partition 0 inline pattern: rowCount + uncompressedSize (missing compressedSize)
        let inline_json = r#"{"rowCount":50,"uncompressedSize":2048}"#;
        let p2: PartitionInfo = serde_json::from_str(inline_json)?;
        assert_eq!(p2.row_count, 50);
        assert_eq!(p2.uncompressed_size, Some(2048));
        assert_eq!(p2.compressed_size, None);

        // Both sizes present
        let full_json = r#"{"rowCount":50,"compressedSize":512,"uncompressedSize":2048}"#;
        let p3: PartitionInfo = serde_json::from_str(full_json)?;
        assert_eq!(p3.row_count, 50);
        assert_eq!(p3.compressed_size, Some(512));
        assert_eq!(p3.uncompressed_size, Some(2048));

        let reserialized = serde_json::to_string(&p3)?;
        let roundtrip: PartitionInfo = serde_json::from_str(&reserialized)?;
        assert_eq!(roundtrip, p3);
        Ok(())
    }

    #[test]
    fn query_status_serde_roundtrip() -> Result<(), serde_json::Error> {
        let json = r#"{
            "code": "333334",
            "message": "Asynchronous execution in progress.",
            "statementHandle": "01b5a2e4-0000-0123-0000-000000000001",
            "statementStatusUrl": "/api/v2/statements/01b5a2e4-0000-0123-0000-000000000001",
            "sqlState": "00000"
        }"#;
        let qs: QueryStatus = serde_json::from_str(json)?;
        assert_eq!(qs.code, "333334");
        assert_eq!(
            qs.statement_handle.as_str(),
            "01b5a2e4-0000-0123-0000-000000000001"
        );
        assert_eq!(
            qs.statement_status_url.as_deref(),
            Some("/api/v2/statements/01b5a2e4-0000-0123-0000-000000000001")
        );
        assert_eq!(qs.sql_state.as_deref(), Some("00000"));
        assert_eq!(
            qs.message.as_deref(),
            Some("Asynchronous execution in progress.")
        );

        let reserialized = serde_json::to_string(&qs)?;
        let roundtrip: QueryStatus = serde_json::from_str(&reserialized)?;
        assert_eq!(roundtrip, qs);
        Ok(())
    }

    #[test]
    fn query_failure_status_serde_roundtrip() -> Result<(), serde_json::Error> {
        let json = r#"{
            "code": "002003",
            "sqlState": "42S02",
            "message": "SQL compilation error: Table 'DOES_NOT_EXIST' does not exist",
            "statementHandle": "01b5a2e4-0000-0123-0000-000000000002"
        }"#;
        let failure: QueryFailureStatus = serde_json::from_str(json)?;
        assert_eq!(failure.code, "002003");
        assert_eq!(failure.sql_state.as_deref(), Some("42S02"));
        assert_eq!(
            failure.statement_handle.as_ref().map(|h| h.as_str()),
            Some("01b5a2e4-0000-0123-0000-000000000002")
        );

        let reserialized = serde_json::to_string(&failure)?;
        let roundtrip: QueryFailureStatus = serde_json::from_str(&reserialized)?;
        assert_eq!(roundtrip, failure);
        Ok(())
    }

    #[test]
    fn statement_cancel_response_serde_roundtrip() -> Result<(), serde_json::Error> {
        let json = r#"{
            "code": "090001",
            "message": "Statement cancelled successfully.",
            "statementHandle": "01b5a2e4-0000-0123-0000-000000000003"
        }"#;
        let cancel: StatementCancelResponse = serde_json::from_str(json)?;
        assert_eq!(cancel.code, "090001");
        assert_eq!(
            cancel.message.as_deref(),
            Some("Statement cancelled successfully.")
        );
        assert_eq!(
            cancel.statement_handle.as_ref().map(|h| h.as_str()),
            Some("01b5a2e4-0000-0123-0000-000000000003")
        );

        let reserialized = serde_json::to_string(&cancel)?;
        let roundtrip: StatementCancelResponse = serde_json::from_str(&reserialized)?;
        assert_eq!(roundtrip, cancel);
        Ok(())
    }

    #[test]
    fn full_result_set_serde_roundtrip() -> Result<(), serde_json::Error> {
        let json = r#"{
            "resultSetMetaData": {
                "numRows": 2,
                "format": "jsonv2",
                "rowType": [
                    {
                        "name": "ID",
                        "type": "FIXED",
                        "scale": 0,
                        "precision": 38,
                        "nullable": false,
                        "database": "TEST_DB",
                        "schema": "PUBLIC",
                        "table": "USERS"
                    },
                    {
                        "name": "NAME",
                        "type": "TEXT",
                        "nullable": true,
                        "length": 16777216,
                        "byteLength": 16777216,
                        "collation": "en-ci"
                    }
                ],
                "partitionInfo": [
                    {"rowCount": 2, "uncompressedSize": 128}
                ]
            },
            "data": [
                ["1", "Alice"],
                ["2", null]
            ],
            "code": "090001",
            "statementHandle": "stmt-abc",
            "statementStatusUrl": "/api/v2/statements/stmt-abc",
            "statementHandles": ["stmt-abc"],
            "sqlState": "00000",
            "message": "Statement executed successfully.",
            "requestId": "req-xyz",
            "createdOn": 1700000000000,
            "stats": {"scanBytes": 1024}
        }"#;

        let rs: ResultSet = serde_json::from_str(json)?;
        assert_eq!(rs.total_rows(), 2);
        assert_eq!(rs.partition_count(), 1);
        assert!(rs.is_multi_statement());
        assert_eq!(rs.data.len(), 2);
        assert_eq!(
            rs.data[0],
            vec![Some("1".to_owned()), Some("Alice".to_owned())]
        );
        assert_eq!(rs.data[1], vec![Some("2".to_owned()), None]);
        assert_eq!(rs.created_on, Some(1700000000000));
        assert!(rs.stats.is_some());

        let reserialized = serde_json::to_string(&rs)?;
        let roundtrip: ResultSet = serde_json::from_str(&reserialized)?;
        assert_eq!(roundtrip, rs);
        Ok(())
    }
}
