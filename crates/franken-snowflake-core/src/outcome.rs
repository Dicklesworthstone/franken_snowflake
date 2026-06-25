//! Outcome and provenance vocabulary, built on Asupersync's four-valued `Outcome`.
//!
//! [`OutcomeKind`] and [`DataSource`] are the envelope-facing enums (wire contract
//! in `docs/agent_cli_contract.md`). [`SnowflakeOutcome`] **is** Asupersync's
//! `Outcome<T, E>` specialized to [`SnowflakeError`], so all four states
//! (`Ok`/`Err`/`Cancelled`/`Panicked`) survive to the CLI/MCP edge and collapse
//! only at the policy boundary via [`SnowflakeOutcomeExt`].

use asupersync::Outcome;
use serde::{Deserialize, Serialize};

use crate::cancel::{cancel_exit_code, cancel_outcome_kind};
use crate::error::SnowflakeError;
use crate::exit::ExitCode;

/// The finer-grained outcome class carried in the JSON envelope, independent of
/// `ok` and of the process exit code. A cancelled query is `Cancelled`, never an
/// error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeKind {
    /// Fully successful.
    Success,
    /// Succeeded with caveats (e.g. some partitions degraded).
    PartialSuccess,
    /// A policy/safety refusal — the connector declined to act.
    Refusal,
    /// Cooperatively cancelled.
    Cancelled,
    /// A deadline or statement timeout elapsed.
    Timeout,
    /// An error occurred.
    Error,
}

/// Provenance of a payload. Omitted from the envelope when [`DataSource::Unspecified`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSource {
    /// Produced by a live Snowflake call.
    Live,
    /// Produced by a no-account fixture/testkit.
    Fixture,
    /// A valid but empty result.
    Empty,
    /// Not stamped (serialized as absent).
    Unspecified,
}

impl DataSource {
    /// Whether the provenance is [`DataSource::Unspecified`] (and so omitted from
    /// the envelope). Takes `&self` so it can be used as a serde
    /// `skip_serializing_if` predicate.
    #[must_use]
    pub const fn is_unspecified(&self) -> bool {
        matches!(self, Self::Unspecified)
    }
}

impl Default for DataSource {
    fn default() -> Self {
        Self::Unspecified
    }
}

/// The connector's result carrier: Asupersync's four-valued `Outcome` specialized
/// to [`SnowflakeError`].
///
/// Preserve all four variants to the edge; project to the envelope vocabulary with
/// [`SnowflakeOutcomeExt`] only at the policy boundary (exit code / MCP error /
/// receipt status).
pub type SnowflakeOutcome<T> = Outcome<T, SnowflakeError>;

/// Projections from the four-valued [`SnowflakeOutcome`] to the envelope/exit
/// vocabulary. Implemented for the `Outcome` alias so callers keep Asupersync's
/// native methods (`is_ok`, `map`, ...) and gain these.
pub trait SnowflakeOutcomeExt {
    /// The envelope `outcome_kind` this outcome projects to.
    fn outcome_kind(&self) -> OutcomeKind;
    /// The process exit code this outcome projects to.
    fn exit_code(&self) -> ExitCode;
    /// Whether `ok` should be true in the envelope (a plain `Ok`).
    fn is_success(&self) -> bool;
}

impl<T> SnowflakeOutcomeExt for SnowflakeOutcome<T> {
    fn outcome_kind(&self) -> OutcomeKind {
        match self {
            Outcome::Ok(_) => OutcomeKind::Success,
            Outcome::Err(_) => OutcomeKind::Error,
            Outcome::Cancelled(reason) => cancel_outcome_kind(reason.kind),
            Outcome::Panicked(_) => OutcomeKind::Error,
        }
    }

    fn exit_code(&self) -> ExitCode {
        match self {
            Outcome::Ok(_) => ExitCode::Success,
            Outcome::Err(error) => error.exit_code(),
            Outcome::Cancelled(reason) => cancel_exit_code(reason.kind),
            // A panic collapses to an internal/I/O-class failure at the boundary.
            Outcome::Panicked(_) => ExitCode::Io,
        }
    }

    fn is_success(&self) -> bool {
        matches!(self, Outcome::Ok(_))
    }
}
