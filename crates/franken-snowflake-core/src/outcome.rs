//! Outcome and provenance vocabulary.
//!
//! [`OutcomeKind`] and [`DataSource`] are the envelope-facing enums; they mirror
//! the wire contract in `docs/agent_cli_contract.md`. [`SnowflakeOutcome`] is the
//! in-process result carrier.
//!
//! **Asupersync seam:** [`SnowflakeOutcome`] and [`CancelReason`] are shaped to
//! map onto Asupersync's four-valued `Outcome<T, E>` / `CancelReason`. Bead
//! `fsnow-native-snowflake-connector-w0i.6` re-bases them onto Asupersync once the
//! dependency is unified via the toolchain bead's `[patch.crates-io]` block.

use serde::{Deserialize, Serialize};

use crate::error::SnowflakeError;

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
    /// Cooperatively cancelled (see [`CancelReason`]).
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

/// Why a [`SnowflakeOutcome`] was cancelled. Maps onto Asupersync `CancelReason`
/// in bead `w0i.6`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    /// The caller (CLI signal / MCP disconnect) requested cancellation.
    Client,
    /// A wall-clock deadline elapsed.
    Deadline,
    /// The advisory client-side cost budget was exceeded.
    CostBudget,
    /// The poll-count quota was exhausted.
    PollQuota,
    /// Cancellation propagated from an upstream/parent region.
    Upstream,
}

/// The in-process result carrier for connector operations.
///
/// This is a faithful draft of the Asupersync `Outcome<T, E>` shape, specialized
/// to [`SnowflakeError`]. The [`SnowflakeOutcome::kind`] method projects it to the
/// envelope's [`OutcomeKind`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnowflakeOutcome<T> {
    /// Fully successful, carrying the value.
    Success(T),
    /// Succeeded with non-fatal warnings.
    PartialSuccess {
        /// The (degraded but usable) value.
        value: T,
        /// Human-readable warnings.
        warnings: Vec<String>,
    },
    /// A policy/safety refusal.
    Refusal(SnowflakeError),
    /// Cooperatively cancelled.
    Cancelled(CancelReason),
    /// A deadline/statement timeout elapsed after `after_ms`.
    Timeout {
        /// Milliseconds elapsed before the timeout fired.
        after_ms: u64,
    },
    /// An error occurred.
    Error(SnowflakeError),
}

impl<T> SnowflakeOutcome<T> {
    /// Project to the envelope's [`OutcomeKind`].
    #[must_use]
    pub const fn kind(&self) -> OutcomeKind {
        match self {
            Self::Success(_) => OutcomeKind::Success,
            Self::PartialSuccess { .. } => OutcomeKind::PartialSuccess,
            Self::Refusal(_) => OutcomeKind::Refusal,
            Self::Cancelled(_) => OutcomeKind::Cancelled,
            Self::Timeout { .. } => OutcomeKind::Timeout,
            Self::Error(_) => OutcomeKind::Error,
        }
    }

    /// Whether `ok` should be true in the envelope (success or partial success).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        matches!(self, Self::Success(_) | Self::PartialSuccess { .. })
    }

    /// Borrow the success value, if present.
    #[must_use]
    pub const fn value(&self) -> Option<&T> {
        match self {
            Self::Success(value) | Self::PartialSuccess { value, .. } => Some(value),
            _ => None,
        }
    }

    /// Map the success value, preserving the outcome shape.
    #[must_use]
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> SnowflakeOutcome<U> {
        match self {
            Self::Success(value) => SnowflakeOutcome::Success(f(value)),
            Self::PartialSuccess { value, warnings } => SnowflakeOutcome::PartialSuccess {
                value: f(value),
                warnings,
            },
            Self::Refusal(e) => SnowflakeOutcome::Refusal(e),
            Self::Cancelled(r) => SnowflakeOutcome::Cancelled(r),
            Self::Timeout { after_ms } => SnowflakeOutcome::Timeout { after_ms },
            Self::Error(e) => SnowflakeOutcome::Error(e),
        }
    }
}
