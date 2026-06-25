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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cancel::{cancel_policy, CancelPolicy};
    use crate::error::{SnowflakeError, SnowflakeErrorCode};
    use asupersync::{CancelKind, CancelReason, Outcome, PanicPayload};

    #[test]
    fn ok_maps_to_success_exit_zero() {
        let outcome: SnowflakeOutcome<u32> = Outcome::ok(7);
        assert_eq!(outcome.outcome_kind(), OutcomeKind::Success);
        assert_eq!(outcome.exit_code(), ExitCode::Success);
        assert!(outcome.is_success());
    }

    #[test]
    fn empty_ok_is_still_success_exit_zero() {
        // empty result = exit 0, never an error
        let outcome: SnowflakeOutcome<Vec<u8>> = Outcome::ok(Vec::new());
        assert_eq!(outcome.outcome_kind(), OutcomeKind::Success);
        assert_eq!(outcome.exit_code(), ExitCode::Success);
    }

    #[test]
    fn err_maps_to_error_and_registry_exit() {
        let err = SnowflakeError::new(SnowflakeErrorCode::UpstreamError, "boom");
        let outcome: SnowflakeOutcome<u32> = Outcome::err(err);
        assert_eq!(outcome.outcome_kind(), OutcomeKind::Error);
        assert_eq!(outcome.exit_code(), ExitCode::UpstreamError);
        assert!(!outcome.is_success());
    }

    #[test]
    fn deadline_cancel_reads_as_timeout() {
        let outcome: SnowflakeOutcome<u32> = Outcome::cancelled(CancelReason::deadline());
        assert_eq!(outcome.outcome_kind(), OutcomeKind::Timeout);
        assert_eq!(outcome.exit_code(), ExitCode::NetworkBudgetExhausted);
    }

    #[test]
    fn cost_budget_cancel_is_distinct_from_timeout() {
        let outcome: SnowflakeOutcome<u32> = Outcome::cancelled(CancelReason::cost_budget());
        // distinct outcome_kind ...
        assert_eq!(outcome.outcome_kind(), OutcomeKind::Cancelled);
        // ... and distinct exit code vs Deadline/Timeout's NetworkBudgetExhausted.
        assert_eq!(outcome.exit_code(), ExitCode::SafetyRefusal);
    }

    #[test]
    fn user_cancel_is_success_exit() {
        let outcome: SnowflakeOutcome<u32> = Outcome::cancelled(CancelReason::user("stop"));
        assert_eq!(outcome.outcome_kind(), OutcomeKind::Cancelled);
        assert_eq!(outcome.exit_code(), ExitCode::Success);
    }

    #[test]
    fn panicked_collapses_to_error() {
        let outcome: SnowflakeOutcome<u32> = Outcome::panicked(PanicPayload::new("oops"));
        assert_eq!(outcome.outcome_kind(), OutcomeKind::Error);
        assert_eq!(outcome.exit_code(), ExitCode::Io);
    }

    #[test]
    fn all_four_outcome_states_survive_projection() {
        let states: [SnowflakeOutcome<u32>; 4] = [
            Outcome::ok(1),
            Outcome::err(SnowflakeError::new(SnowflakeErrorCode::Internal, "x")),
            Outcome::cancelled(CancelReason::shutdown()),
            Outcome::panicked(PanicPayload::new("x")),
        ];
        let kinds: Vec<OutcomeKind> = states.iter().map(|o| o.outcome_kind()).collect();
        assert_eq!(
            kinds,
            vec![
                OutcomeKind::Success,
                OutcomeKind::Error,
                OutcomeKind::Cancelled,
                OutcomeKind::Error,
            ]
        );
    }

    #[test]
    fn cancel_policy_routes_by_kind() {
        assert_eq!(
            cancel_policy(CancelKind::Deadline),
            CancelPolicy::RetryOrDegrade
        );
        assert_eq!(
            cancel_policy(CancelKind::CostBudget),
            CancelPolicy::RetryOrDegrade
        );
        assert_eq!(
            cancel_policy(CancelKind::Timeout),
            CancelPolicy::RetryOrDegrade
        );
        assert_eq!(
            cancel_policy(CancelKind::PollQuota),
            CancelPolicy::RetryOrDegrade
        );
        assert_eq!(
            cancel_policy(CancelKind::User),
            CancelPolicy::RemoteCancelAndReceipt
        );
        assert_eq!(
            cancel_policy(CancelKind::Shutdown),
            CancelPolicy::BoundedDrain
        );
        assert_eq!(
            cancel_policy(CancelKind::RaceLost),
            CancelPolicy::QuietDrain
        );
        assert_eq!(
            cancel_policy(CancelKind::ParentCancelled),
            CancelPolicy::QuietDrain
        );
    }
}
