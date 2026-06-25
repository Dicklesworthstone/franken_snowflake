//! The process exit-code dictionary.
//!
//! Exit codes are a coarse, stable signal kept deliberately separate from the
//! richer [`crate::outcome::OutcomeKind`] in the JSON envelope. An empty result
//! is success (`0`), never a non-zero exit. Pinned by `docs/agent_cli_contract.md`.

/// Stable process exit codes for the `franken-snowflake` CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(i32)]
pub enum ExitCode {
    /// Success, including empty-but-valid results.
    Success = 0,
    /// Completed with non-fatal findings/warnings needing attention.
    Findings = 1,
    /// Safety refusal.
    SafetyRefusal = 2,
    /// Credential / profile error.
    CredentialError = 3,
    /// Upstream Snowflake error.
    UpstreamError = 4,
    /// Network error or retry budget exhausted.
    NetworkBudgetExhausted = 5,
    /// Query still running (async handle returned, not yet complete).
    QueryStillRunning = 6,
    /// Local cache or metadata error.
    LocalCacheError = 7,
    /// Usage error (bad arguments).
    Usage = 64,
    /// I/O error.
    Io = 74,
}

impl ExitCode {
    /// The numeric code passed to `std::process::exit`.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// Whether this code denotes a successful run (exit 0).
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

impl From<ExitCode> for i32 {
    fn from(value: ExitCode) -> Self {
        value.code()
    }
}
