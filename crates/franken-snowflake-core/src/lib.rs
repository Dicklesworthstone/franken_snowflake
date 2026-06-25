//! `franken-snowflake-core` — shared foundational vocabulary for the
//! franken_snowflake Snowflake SQL API connector.
//!
//! This crate owns the types the rest of the workspace shares and **contains no
//! live network code**:
//!
//! - [`ids`] — identifier newtypes (`AccountIdentifier`, `ProfileName`,
//!   `StatementHandle`, `QueryId`, `DatasetId`, `ReceiptHash`, ...).
//! - [`outcome`] — the [`outcome::OutcomeKind`] / [`outcome::DataSource`] enums
//!   and the [`outcome::SnowflakeOutcome`] result carrier built on Asupersync's
//!   four-valued `Outcome`, with [`outcome::SnowflakeOutcomeExt`] projections.
//! - [`cancel`] — Asupersync `CancelReason`/`CancelKind` re-exports plus the
//!   [`cancel::CancelPolicy`] routing keyed off `reason.kind`.
//! - [`budget`] — query [`budget::Budget`] (deadline + poll quota + advisory cost
//!   quota) with `meet()` propagation to partition fetchers.
//! - [`capabilities`] — the type-level capability rows for the planner / transport
//!   / write-intent layers, with compile-time `SubsetOf` layering proofs.
//! - [`error`] — [`error::SnowflakeErrorCode`], the stable `FSNOW-*` error-code
//!   registry, and [`error::SnowflakeError`] with auto-populated recovery paths.
//! - [`exit`] — the process [`exit::ExitCode`] dictionary.
//! - [`redact`] — the single shared secret-needle list and the composable
//!   redactor (so the redactor and the last-mile output scanner cannot drift).
//! - [`guardrails`] — fail-closed rights, read-only mutation refusal, provenance,
//!   redaction, canary scanning, and enforceable/advisory query cost limits.
//! - [`write_intent`] — non-executing deferred write ladder types, dry-run
//!   planning receipts, exact confirmation tokens, and append-only audit gates.
//! - [`envelope`] — the deterministic, versioned JSON envelope metadata.
//! - [`adapter`] — public downstream extension points and optional
//!   `adapter-fixtures` contract tests.
//!
//! See `docs/agent_cli_contract.md` (envelope + exit codes),
//! `docs/security_model.md` (redaction + fail-closed rights),
//! `docs/write_intent_ladder.md` (future mutation ladder), and
//! `docs/asupersync_leverage.md` (the Budget/Outcome/capability control plane)
//! for the normative contracts these types implement.
//!
//! ## Asupersync control plane
//!
//! Bead `fsnow-native-snowflake-connector-w0i.6` adopts Asupersync's control
//! plane here: [`outcome::SnowflakeOutcome`] *is* `asupersync::Outcome<T,
//! SnowflakeError>` (all four states preserved to the edge), [`cancel`] keys
//! policy off `CancelReason.kind`, [`budget`] uses `asupersync::Budget`, and
//! [`capabilities`] pins read-only at the type level. The batch test lane lands
//! separately (`— code-first, batch-test pending`).

pub mod adapter;
pub mod budget;
pub mod cancel;
pub mod capabilities;
pub mod envelope;
pub mod error;
pub mod exit;
pub mod guardrails;
pub mod ids;
pub mod outcome;
pub mod redact;
pub mod write_intent;

/// Crate version string, surfaced in the `capabilities` / `agent-handbook`
/// envelopes once those commands exist.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Convenient re-exports of the most commonly used core types.
pub mod prelude {
    pub use crate::adapter::{
        AdapterOutputContract, AdapterResult, AdapterSafetyFacet, ContentAddressRef,
        SnowflakeDataLakeAdapter,
    };
    pub use crate::budget::Budget;
    pub use crate::cancel::{CancelKind, CancelPolicy, CancelReason};
    pub use crate::capabilities::{PlannerCaps, TransportCaps, WriteCaps};
    pub use crate::envelope::{BudgetConsumed, EnvelopeMeta, SCHEMA_VERSION};
    pub use crate::error::{SnowflakeError, SnowflakeErrorCode};
    pub use crate::exit::ExitCode;
    pub use crate::guardrails::{
        BoundedQueryPlan, CostVector, MutationPolicy, QueryPlanGuard, QuerySafetyLimits,
        RightsClass, RightsEntitlement,
    };
    pub use crate::ids::{
        AccountIdentifier, DatabaseName, DatasetId, ProfileName, QueryId, ReceiptHash, RequestId,
        RoleName, SchemaName, StatementHandle, WarehouseName,
    };
    pub use crate::outcome::{DataSource, OutcomeKind, SnowflakeOutcome, SnowflakeOutcomeExt};
    pub use crate::write_intent::{
        AppendOnlyAuditIntent, ConfirmationToken, StatementAllowlistEntry, WriteIntentDecision,
        WriteIntentMode, WriteIntentPlan, WriteIntentPolicy, WriteIntentReceipt,
        WriteIntentRefusal, WriteIntentRefusalCode, WriteIntentRequest, WriteIntentStage,
        WriteSafetyClass, WriteStatementKind,
    };
}
