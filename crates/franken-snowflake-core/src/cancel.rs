//! Cancellation policy: map Asupersync's `CancelKind` to connector routing and to
//! the envelope/exit projection.
//!
//! `CancelReason` is a **struct**; policy keys off its `kind` field
//! ([`CancelKind`]). Budget exhaustion (`Deadline`/`CostBudget`/`PollQuota`) and an
//! explicit `Timeout` are routed like a timeout (retry or degrade). `User` issues
//! the remote cancel and writes a receipt; `Shutdown` drains within budget;
//! `RaceLost`/`ParentCancelled`/`FailFast` drain quietly. See
//! `docs/asupersync_leverage.md`.

pub use asupersync::{CancelKind, CancelReason};

use crate::exit::ExitCode;
use crate::outcome::OutcomeKind;

/// How the connector reacts to a cancellation, keyed off `reason.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CancelPolicy {
    /// Budget/time exhaustion (`Deadline`/`CostBudget`/`PollQuota`) or an explicit
    /// `Timeout`: retry or degrade.
    RetryOrDegrade,
    /// `User`-initiated: issue the remote cancel and write a receipt.
    RemoteCancelAndReceipt,
    /// Runtime `Shutdown` / resource pressure: drain within the cleanup budget.
    BoundedDrain,
    /// Lost a race / parent cancelled / sibling failed / linked exit: drain quietly.
    QuietDrain,
}

/// The routing policy for a cancellation kind.
#[must_use]
pub fn cancel_policy(kind: CancelKind) -> CancelPolicy {
    match kind {
        CancelKind::Deadline
        | CancelKind::CostBudget
        | CancelKind::Timeout
        | CancelKind::PollQuota => CancelPolicy::RetryOrDegrade,
        CancelKind::User => CancelPolicy::RemoteCancelAndReceipt,
        CancelKind::Shutdown | CancelKind::ResourceUnavailable => CancelPolicy::BoundedDrain,
        CancelKind::FailFast
        | CancelKind::RaceLost
        | CancelKind::ParentCancelled
        | CancelKind::LinkedExit => CancelPolicy::QuietDrain,
    }
}

/// Whether a cancellation policy still attempts the bounded remote cancel of a
/// submitted statement handle. `docs/transport_design.md`: once a handle exists,
/// user, deadline/budget, and shutdown cancellation must attempt a bounded
/// remote cancel; only the quiet-drain kinds (`RaceLost`, `ParentCancelled`,
/// `FailFast`, `LinkedExit`) skip it. "Retry or degrade" describes what the
/// caller does next, not whether the orphaned statement gets cancelled.
#[must_use]
pub const fn attempts_remote_cancel(policy: CancelPolicy) -> bool {
    !matches!(policy, CancelPolicy::QuietDrain)
}

/// The envelope `outcome_kind` for a cancellation. `Deadline`/`Timeout` read as
/// [`OutcomeKind::Timeout`]; every other cancellation (including `CostBudget`)
/// reads as [`OutcomeKind::Cancelled`], keeping `CostBudget` distinct from the
/// timeout group.
#[must_use]
pub fn cancel_outcome_kind(kind: CancelKind) -> OutcomeKind {
    match kind {
        CancelKind::Deadline | CancelKind::Timeout => OutcomeKind::Timeout,
        _ => OutcomeKind::Cancelled,
    }
}

/// The process exit code for a cancellation.
///
/// `CostBudget` maps to a **distinct** code from the `Deadline`/`Timeout`
/// budget-exhaustion code — a cost breach is a cost-safety boundary. A `User`
/// cancel is success: the caller asked to cancel.
#[must_use]
pub fn cancel_exit_code(kind: CancelKind) -> ExitCode {
    match kind {
        CancelKind::Deadline | CancelKind::Timeout | CancelKind::PollQuota => {
            ExitCode::NetworkBudgetExhausted
        }
        CancelKind::CostBudget => ExitCode::SafetyRefusal,
        CancelKind::User => ExitCode::Success,
        CancelKind::Shutdown
        | CancelKind::ResourceUnavailable
        | CancelKind::FailFast
        | CancelKind::RaceLost
        | CancelKind::ParentCancelled
        | CancelKind::LinkedExit => ExitCode::NetworkBudgetExhausted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_and_user_cancellations_attempt_the_remote_cancel() {
        for kind in [
            CancelKind::Deadline,
            CancelKind::CostBudget,
            CancelKind::PollQuota,
            CancelKind::Timeout,
            CancelKind::User,
            CancelKind::Shutdown,
            CancelKind::ResourceUnavailable,
        ] {
            assert!(
                attempts_remote_cancel(cancel_policy(kind)),
                "{kind:?} must attempt a bounded remote cancel (transport_design.md)"
            );
        }
        for kind in [
            CancelKind::RaceLost,
            CancelKind::ParentCancelled,
            CancelKind::FailFast,
            CancelKind::LinkedExit,
        ] {
            assert!(
                !attempts_remote_cancel(cancel_policy(kind)),
                "{kind:?} drains quietly"
            );
        }
    }

    #[test]
    fn cancel_outcome_kind_maps_timeouts_and_cancellations() {
        assert_eq!(
            cancel_outcome_kind(CancelKind::Deadline),
            OutcomeKind::Timeout
        );
        assert_eq!(
            cancel_outcome_kind(CancelKind::Timeout),
            OutcomeKind::Timeout
        );

        for other_kind in [
            CancelKind::CostBudget,
            CancelKind::PollQuota,
            CancelKind::User,
            CancelKind::Shutdown,
            CancelKind::ResourceUnavailable,
            CancelKind::FailFast,
            CancelKind::RaceLost,
            CancelKind::ParentCancelled,
            CancelKind::LinkedExit,
        ] {
            assert_eq!(
                cancel_outcome_kind(other_kind),
                OutcomeKind::Cancelled,
                "{other_kind:?} must map to OutcomeKind::Cancelled"
            );
        }
    }

    #[test]
    fn cancel_exit_codes_distinguish_cost_safety_and_user_requests() {
        // Cost budget breach is a distinct safety boundary (SafetyRefusal = 2)
        assert_eq!(
            cancel_exit_code(CancelKind::CostBudget),
            ExitCode::SafetyRefusal
        );

        // User-initiated cancel is success (0)
        assert_eq!(cancel_exit_code(CancelKind::User), ExitCode::Success);

        // Network/budget/timeout exhaustions map to NetworkBudgetExhausted (5)
        assert_eq!(
            cancel_exit_code(CancelKind::Deadline),
            ExitCode::NetworkBudgetExhausted
        );
        assert_eq!(
            cancel_exit_code(CancelKind::Timeout),
            ExitCode::NetworkBudgetExhausted
        );
        assert_eq!(
            cancel_exit_code(CancelKind::PollQuota),
            ExitCode::NetworkBudgetExhausted
        );
        assert_eq!(
            cancel_exit_code(CancelKind::Shutdown),
            ExitCode::NetworkBudgetExhausted
        );
        assert_eq!(
            cancel_exit_code(CancelKind::FailFast),
            ExitCode::NetworkBudgetExhausted
        );
    }

    #[test]
    fn cancel_policy_mappings() {
        assert_eq!(
            cancel_policy(CancelKind::User),
            CancelPolicy::RemoteCancelAndReceipt
        );
        assert_eq!(
            cancel_policy(CancelKind::Deadline),
            CancelPolicy::RetryOrDegrade
        );
        assert_eq!(
            cancel_policy(CancelKind::CostBudget),
            CancelPolicy::RetryOrDegrade
        );
        assert_eq!(
            cancel_policy(CancelKind::Shutdown),
            CancelPolicy::BoundedDrain
        );
        assert_eq!(
            cancel_policy(CancelKind::ResourceUnavailable),
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
