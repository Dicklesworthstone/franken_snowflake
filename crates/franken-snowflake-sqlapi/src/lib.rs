//! `franken-snowflake-sqlapi` — the Snowflake SQL API protocol heart.
//!
//! This crate owns the *protocol data*: the request/response schemas, the
//! `jsonv2` wire codec, and the HTTP-status response classification. It is pure
//! and `serde`-driven — **no `asupersync`, no live network**. The cancel-correct
//! statement lifecycle (`bracket` over submit/poll/partition/cancel) and the
//! HTTPS transport land in the sibling beads `fsnow-statement-lifecycle-ofl` and
//! `fsnow-asupersync-native-https-ofq`; this crate gives them the typed payloads
//! and the status state machine to act on.
//!
//! Modules:
//!
//! - [`request`] — `POST /api/v2/statements` body: [`request::SubmitStatementRequest`],
//!   positional typed [`request::Binding`]s, and session [`request::SubmitQueryParams`].
//! - [`response`] — the response bodies, one per HTTP status: a 200
//!   [`response::ResultSet`], a 202 [`response::QueryStatus`], a 408/422
//!   [`response::QueryFailureStatus`], and the [`response::StatementCancelResponse`],
//!   plus [`response::ResultSetMetaData`] / [`response::ColumnType`] /
//!   [`response::PartitionInfo`].
//! - [`status`] — [`status::ResponseClass`]: the 200/202/408/422/429 routing
//!   state machine, kept distinct so no two states are ever conflated.
//! - [`wire`] — the [`wire::CellValue`] `jsonv2` codec: every `data` cell is a
//!   JSON string decoded per its [`response::ColumnType`], never by JSON shape.
//!
//! ## Protocol references
//!
//! Behavioral source: Snowflake's official SQL API docs (clean-room — docs +
//! live observation + our own fixtures only). Consulted 2026-06-24:
//! `developer-guide/sql-api/{index,reference,submitting-requests,handling-responses}`.
//! See `docs/protocol/schema_draft.md` for the field-by-field rationale and
//! `docs/proof_lanes.md` (Lane 1) for the proof obligations these types satisfy.

pub mod driver;
pub mod lifecycle;
pub mod request;
pub mod response;
pub mod status;
pub mod wire;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The SQL API base paths, relative to the account host
/// (`<account>.snowflakecomputing.com`). The transport crate joins these with the
/// host and the query string (`requestId`, `retry`, `async`, `partition`,
/// `nullable`).
pub mod endpoints {
    /// `POST` here to submit a statement.
    pub const SUBMIT: &str = "/api/v2/statements";

    /// Build the per-handle status/result path: `GET` for poll/fetch.
    #[must_use]
    pub fn statement(handle: &str) -> String {
        format!("/api/v2/statements/{handle}")
    }

    /// Build the per-handle cancel path: `POST` to cancel.
    #[must_use]
    pub fn cancel(handle: &str) -> String {
        format!("/api/v2/statements/{handle}/cancel")
    }
}
