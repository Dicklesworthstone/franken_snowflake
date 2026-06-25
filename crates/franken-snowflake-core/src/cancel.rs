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
