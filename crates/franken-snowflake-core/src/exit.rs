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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_have_stable_numeric_values() {
        assert_eq!(ExitCode::Success.code(), 0);
        assert_eq!(ExitCode::Findings.code(), 1);
        assert_eq!(ExitCode::SafetyRefusal.code(), 2);
        assert_eq!(ExitCode::CredentialError.code(), 3);
        assert_eq!(ExitCode::UpstreamError.code(), 4);
        assert_eq!(ExitCode::NetworkBudgetExhausted.code(), 5);
        assert_eq!(ExitCode::QueryStillRunning.code(), 6);
        assert_eq!(ExitCode::LocalCacheError.code(), 7);
        assert_eq!(ExitCode::Usage.code(), 64);
        assert_eq!(ExitCode::Io.code(), 74);
    }

    #[test]
    fn exit_code_success_predicate_and_into_i32() {
        assert!(ExitCode::Success.is_success());
        assert!(!ExitCode::Findings.is_success());
        assert!(!ExitCode::SafetyRefusal.is_success());
        assert!(!ExitCode::CredentialError.is_success());
        assert!(!ExitCode::UpstreamError.is_success());
        assert!(!ExitCode::NetworkBudgetExhausted.is_success());
        assert!(!ExitCode::QueryStillRunning.is_success());
        assert!(!ExitCode::LocalCacheError.is_success());
        assert!(!ExitCode::Usage.is_success());
        assert!(!ExitCode::Io.is_success());

        let code_i32: i32 = ExitCode::Usage.into();
        assert_eq!(code_i32, 64);
        let success_i32: i32 = ExitCode::Success.into();
        assert_eq!(success_i32, 0);
    }
}
