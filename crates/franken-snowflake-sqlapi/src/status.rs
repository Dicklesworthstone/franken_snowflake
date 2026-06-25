//! The SQL API response-status state machine.
//!
//! HTTP status codes are *distinct protocol signals*, never interchangeable. The
//! single most common connector bug is conflating them — treating a `429`
//! (overloaded) as a query status, or a `408` (statement timeout) as a generic
//! failure. [`ResponseClass`] makes each a separate, exhaustively-matched state,
//! and the lifecycle bead acts on it. This module is pure classification: no IO.

use franken_snowflake_core::outcome::OutcomeKind;

/// The classification of a SQL API HTTP response by status code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseClass {
    /// `200`: completed; body is a [`crate::response::ResultSet`].
    Completed,
    /// `202`: still running / accepted async; body is a
    /// [`crate::response::QueryStatus`]. Poll again.
    Running,
    /// `408`: statement exceeded `STATEMENT_TIMEOUT_IN_SECONDS`; body is a
    /// [`crate::response::QueryFailureStatus`]. A typed timeout, not a SQL error.
    StatementTimeout,
    /// `422`: SQL compilation/execution failure; body is a
    /// [`crate::response::QueryFailureStatus`].
    StatementFailed,
    /// `429`: server overloaded / rate limited. Back off and retry; `Retry-After`
    /// is **not** guaranteed. Never a query-status code.
    RateLimited,
    /// Any other status (e.g. `5xx` transport error), carried verbatim.
    Other(u16),
}

impl ResponseClass {
    /// Classify a raw HTTP status code.
    #[must_use]
    pub const fn from_status(code: u16) -> Self {
        match code {
            200 => Self::Completed,
            202 => Self::Running,
            408 => Self::StatementTimeout,
            422 => Self::StatementFailed,
            429 => Self::RateLimited,
            other => Self::Other(other),
        }
    }

    /// Whether this state means "poll the handle again" (`202` only).
    #[must_use]
    pub const fn should_poll(self) -> bool {
        matches!(self, Self::Running)
    }

    /// Whether this state is transient and should be retried under backoff
    /// (`429`; `5xx` transport). `408`/`422` are terminal failures, not retries.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::RateLimited | Self::Other(500..=599))
    }

    /// Whether this state terminates the statement lifecycle (success or a typed
    /// failure). `Running`/`RateLimited` are non-terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::StatementTimeout | Self::StatementFailed
        )
    }

    /// The envelope [`OutcomeKind`] for a terminal state, or `None` while the
    /// statement is still in flight (`Running`/`RateLimited`/non-5xx `Other`).
    #[must_use]
    pub const fn terminal_outcome(self) -> Option<OutcomeKind> {
        match self {
            Self::Completed => Some(OutcomeKind::Success),
            Self::StatementTimeout => Some(OutcomeKind::Timeout),
            Self::StatementFailed => Some(OutcomeKind::Error),
            Self::Running | Self::RateLimited | Self::Other(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_map_to_distinct_states() {
        assert_eq!(ResponseClass::from_status(200), ResponseClass::Completed);
        assert_eq!(ResponseClass::from_status(202), ResponseClass::Running);
        assert_eq!(
            ResponseClass::from_status(408),
            ResponseClass::StatementTimeout
        );
        assert_eq!(
            ResponseClass::from_status(422),
            ResponseClass::StatementFailed
        );
        assert_eq!(ResponseClass::from_status(429), ResponseClass::RateLimited);
        assert_eq!(ResponseClass::from_status(503), ResponseClass::Other(503));
    }

    #[test]
    fn poll_retry_and_terminal_are_not_conflated() {
        // 202 polls but is neither retryable-by-backoff nor terminal.
        assert!(ResponseClass::Running.should_poll());
        assert!(!ResponseClass::Running.is_retryable());
        assert!(!ResponseClass::Running.is_terminal());

        // 429 retries under backoff but never polls and is never terminal.
        assert!(ResponseClass::RateLimited.is_retryable());
        assert!(!ResponseClass::RateLimited.should_poll());
        assert!(!ResponseClass::RateLimited.is_terminal());

        // 408 is a terminal *timeout*, distinct from a 422 *error*.
        assert!(ResponseClass::StatementTimeout.is_terminal());
        assert!(!ResponseClass::StatementTimeout.is_retryable());
        assert_eq!(
            ResponseClass::StatementTimeout.terminal_outcome(),
            Some(OutcomeKind::Timeout)
        );
        assert_eq!(
            ResponseClass::StatementFailed.terminal_outcome(),
            Some(OutcomeKind::Error)
        );
    }

    #[test]
    fn completed_is_success_and_5xx_retries() {
        assert_eq!(
            ResponseClass::Completed.terminal_outcome(),
            Some(OutcomeKind::Success)
        );
        assert!(ResponseClass::from_status(500).is_retryable());
        assert!(!ResponseClass::from_status(404).is_retryable());
        assert_eq!(ResponseClass::Running.terminal_outcome(), None);
    }
}
