//! `franken-snowflake-core` — shared foundational vocabulary for the
//! franken_snowflake Snowflake SQL API connector.
//!
//! This crate owns the types the rest of the workspace shares and **contains no
//! live network code**:
//!
//! - [`ids`] — identifier newtypes (`AccountIdentifier`, `ProfileName`,
//!   `StatementHandle`, `QueryId`, `DatasetId`, `ReceiptHash`, ...).
//! - [`outcome`] — the [`outcome::OutcomeKind`] / [`outcome::DataSource`] enums
//!   and the [`outcome::SnowflakeOutcome`] result carrier.
//! - [`error`] — [`error::SnowflakeErrorCode`], the stable `FSNOW-*` error-code
//!   registry, and [`error::SnowflakeError`] with auto-populated recovery paths.
//! - [`exit`] — the process [`exit::ExitCode`] dictionary.
//! - [`redact`] — the single shared secret-needle list and the composable
//!   redactor (so the redactor and the last-mile output scanner cannot drift).
//! - [`envelope`] — the deterministic, versioned JSON envelope metadata.
//!
//! See `docs/agent_cli_contract.md` (envelope + exit codes) and
//! `docs/security_model.md` (redaction + fail-closed rights) for the normative
//! contracts these types implement.
//!
//! ## Asupersync seam
//!
//! [`outcome::SnowflakeOutcome`] and [`outcome::CancelReason`] are drafted here
//! as local enums shaped to map cleanly onto Asupersync's four-valued
//! `Outcome<T, E>` / `CancelReason`. Re-basing them onto Asupersync proper
//! (adding the dependency once the `[patch.crates-io]` unification from the
//! toolchain bead is in place) is the job of bead
//! `fsnow-native-snowflake-connector-w0i.6`. This file is the code-first draft;
//! the batch test lane lands with that adoption.

pub mod envelope;
pub mod error;
pub mod exit;
pub mod ids;
pub mod outcome;
pub mod redact;

/// Crate version string, surfaced in the `capabilities` / `agent-handbook`
/// envelopes once those commands exist.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Convenient re-exports of the most commonly used core types.
pub mod prelude {
    pub use crate::envelope::{BudgetConsumed, EnvelopeMeta, SCHEMA_VERSION};
    pub use crate::error::{SnowflakeError, SnowflakeErrorCode};
    pub use crate::exit::ExitCode;
    pub use crate::ids::{
        AccountIdentifier, DatabaseName, DatasetId, ProfileName, QueryId, ReceiptHash, RequestId,
        RoleName, SchemaName, StatementHandle, WarehouseName,
    };
    pub use crate::outcome::{CancelReason, DataSource, OutcomeKind, SnowflakeOutcome};
}
