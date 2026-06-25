//! `franken-snowflake-core` — shared foundational vocabulary for the
//! franken_snowflake Snowflake SQL API connector.
//!
//! This crate owns the types the rest of the workspace shares: identifier
//! newtypes (`AccountIdentifier`, `ProfileName`, `StatementHandle`, `QueryId`,
//! `DatasetId`, `ReceiptHash`, ...), the deterministic JSON envelope metadata,
//! the `SnowflakeOutcome<T>` built on Asupersync's four-valued `Outcome`, the
//! `OutcomeKind`/`DataSource` enums, stable error-code ranges and their default
//! `safe_next_commands`/`repair_commands`, the single-source redaction helpers,
//! the exit-code dictionary, and the feature-flag surface.
//!
//! It must contain **no live network code**. See the "franken-snowflake-core"
//! section of `COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md`,
//! `docs/security_model.md`, and `docs/agent_cli_contract.md` for the contracts
//! this crate enforces.
//!
//! Status: Phase 0 skeleton. Core types land in Phase 1
//! (`fsnow-sqlapi-protocol-schemas-kx6`); the Asupersync
//! `Budget`/`Outcome`/`CancelReason`/capability semantics are adopted in
//! `fsnow-native-snowflake-connector-w0i.6`.

/// Crate version string, surfaced in the `capabilities` / `agent-handbook`
/// envelopes once those commands exist.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
