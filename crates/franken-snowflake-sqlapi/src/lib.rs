//! `franken-snowflake-sqlapi` — the Snowflake SQL API protocol heart.
//!
//! Owns the request/response schemas (`SubmitStatementRequest`,
//! `SubmitStatementResponse`, `QueryStatus`, `QueryFailureStatus`, `ResultSet`,
//! `ResultSetMetaData` with `rowType[]`, `PartitionInfo`,
//! `StatementCancelResponse`), typed positional bindings, session parameters,
//! query tags, nullable handling, the `jsonv2` wire codec, and request IDs for
//! idempotent resubmit.
//!
//! The statement lifecycle is modeled as an Asupersync `bracket` so the remote
//! cancel endpoint (`POST /api/v2/statements/{handle}/cancel`) always fires on
//! drop/cancel and no Snowflake statement is orphaned. HTTP status codes are
//! distinct signals (200 done / 202 poll-again / 408 timeout / 422 failure /
//! 429 backoff), never conflated. The crate is testable against canned JSON and
//! the deterministic codec harness before any live account exists.
//!
//! Status: Phase 0 skeleton. Schemas/goldens land in
//! `fsnow-sqlapi-protocol-schemas-kx6`; the submit/poll/partition/cancel
//! lifecycle in `fsnow-statement-lifecycle-ofl`. The Asupersync-native HTTPS
//! transport (`fsnow-asupersync-native-https-ofq`) may start inside this crate
//! before splitting into `franken-snowflake-http`.

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
