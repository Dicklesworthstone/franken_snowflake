//! Stable error codes and the central error registry.
//!
//! Every error code is a stable `FSNOW-<range><n>` string mapped — once, here —
//! to its exit code, retryability, policy-boundary flag, a one-line summary, and
//! default `safe_next_commands` / `repair_commands`. Because the registry is the
//! single source, **every error code ships a default recovery path**: a
//! [`SnowflakeError::new`] with no caller-supplied hints is still actionable.
//!
//! Ranges: `1xxx` usage, `2xxx` credential/profile, `3xxx` safety refusal,
//! `4xxx` upstream Snowflake, `5xxx` network/retry, `6xxx` async, `7xxx` local
//! cache/metadata, `9xxx` internal.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::exit::ExitCode;

/// A stable, enumerable connector error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SnowflakeErrorCode {
    /// Unknown CLI command.
    UnknownCommand,
    /// Malformed arguments / usage error.
    UsageError,
    /// The named profile does not exist.
    ProfileNotFound,
    /// The profile exists but is structurally invalid.
    ProfileInvalid,
    /// A required credential (env var / secret handle) is absent.
    CredentialMissing,
    /// A credential is present but expired.
    CredentialExpired,
    /// A mutation was attempted without the write-intent ladder.
    MutationRefused,
    /// A multi-statement request was refused by default policy.
    MultiStatementRefused,
    /// `--require-live` refused a fixture/empty substitution.
    RequireLiveRefused,
    /// A result exceeded the row cap without `--export`/`--max-rows`.
    RowCapExceeded,
    /// A statement/result safety bound was exceeded.
    SafetyLimitExceeded,
    /// Warehouse policy refused the requested warehouse.
    WarehouseRefused,
    /// An upstream Snowflake SQL API error.
    UpstreamError,
    /// A statement failed upstream (422 / SQL error).
    StatementFailed,
    /// A statement exceeded `STATEMENT_TIMEOUT_IN_SECONDS` (408).
    StatementTimeout,
    /// A network/transport error.
    NetworkError,
    /// The retry budget was exhausted.
    RetryBudgetExhausted,
    /// Rate limited upstream (429).
    RateLimited,
    /// An async query is still running (handle returned, not complete).
    QueryStillRunning,
    /// A local cache error.
    CacheError,
    /// A local metadata error.
    MetadataError,
    /// An internal invariant was violated.
    Internal,
    /// A command surface is reserved but its handler is not implemented yet.
    /// A deliberate refusal (exit 2), not an I/O fault — distinct from `Internal`.
    SurfaceReserved,
}

/// One row of the error registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorEntry {
    /// The code this row describes.
    pub code: SnowflakeErrorCode,
    /// The stable wire string, e.g. `FSNOW-2001`.
    pub stable_code: &'static str,
    /// Process exit code for this error.
    pub exit_code: ExitCode,
    /// Whether retrying may succeed.
    pub retryable: bool,
    /// Whether this is a policy/safety boundary (vs. a transient/technical fault).
    pub policy_boundary: bool,
    /// One-line human summary.
    pub summary: &'static str,
    /// Suggested safe follow-up commands.
    pub safe_next_commands: &'static [&'static str],
    /// Suggested repair commands.
    pub repair_commands: &'static [&'static str],
}

impl SnowflakeErrorCode {
    /// Every code, in range order (used by `agent-handbook` to emit the registry).
    pub const ALL: &'static [SnowflakeErrorCode] = &[
        Self::UnknownCommand,
        Self::UsageError,
        Self::ProfileNotFound,
        Self::ProfileInvalid,
        Self::CredentialMissing,
        Self::CredentialExpired,
        Self::MutationRefused,
        Self::MultiStatementRefused,
        Self::RequireLiveRefused,
        Self::RowCapExceeded,
        Self::SafetyLimitExceeded,
        Self::WarehouseRefused,
        Self::UpstreamError,
        Self::StatementFailed,
        Self::StatementTimeout,
        Self::NetworkError,
        Self::RetryBudgetExhausted,
        Self::RateLimited,
        Self::QueryStillRunning,
        Self::CacheError,
        Self::MetadataError,
        Self::Internal,
        Self::SurfaceReserved,
    ];

    /// The full registry row for this code.
    #[must_use]
    pub const fn entry(self) -> ErrorEntry {
        match self {
            Self::UnknownCommand => ErrorEntry {
                code: self,
                stable_code: "FSNOW-1001",
                exit_code: ExitCode::Usage,
                retryable: false,
                policy_boundary: false,
                summary: "Unknown command.",
                safe_next_commands: &["franken-snowflake capabilities --json"],
                repair_commands: &["franken-snowflake agent-handbook --json"],
            },
            Self::UsageError => ErrorEntry {
                code: self,
                stable_code: "FSNOW-1002",
                exit_code: ExitCode::Usage,
                retryable: false,
                policy_boundary: false,
                summary: "Malformed arguments.",
                safe_next_commands: &["franken-snowflake <command> --help"],
                repair_commands: &["franken-snowflake capabilities --json"],
            },
            Self::ProfileNotFound => ErrorEntry {
                code: self,
                stable_code: "FSNOW-2001",
                exit_code: ExitCode::CredentialError,
                retryable: false,
                policy_boundary: false,
                summary: "The requested profile does not exist.",
                safe_next_commands: &["franken-snowflake profile validate <profile> --json"],
                repair_commands: &["franken-snowflake profile validate <profile> --json"],
            },
            Self::ProfileInvalid => ErrorEntry {
                code: self,
                stable_code: "FSNOW-2002",
                exit_code: ExitCode::CredentialError,
                retryable: false,
                policy_boundary: false,
                summary: "The profile is structurally invalid.",
                safe_next_commands: &["franken-snowflake profile validate <profile> --json"],
                repair_commands: &["franken-snowflake profile doctor <profile> --json"],
            },
            Self::CredentialMissing => ErrorEntry {
                code: self,
                stable_code: "FSNOW-2003",
                exit_code: ExitCode::CredentialError,
                retryable: false,
                policy_boundary: false,
                summary: "A required credential environment variable is unset.",
                safe_next_commands: &["franken-snowflake profile validate <profile> --json"],
                repair_commands: &["franken-snowflake profile doctor <profile> --json"],
            },
            Self::CredentialExpired => ErrorEntry {
                code: self,
                stable_code: "FSNOW-2004",
                exit_code: ExitCode::CredentialError,
                retryable: false,
                policy_boundary: false,
                summary: "The credential is present but expired.",
                safe_next_commands: &["franken-snowflake profile doctor <profile> --json"],
                repair_commands: &["franken-snowflake profile doctor <profile> --online --json"],
            },
            Self::MutationRefused => ErrorEntry {
                code: self,
                stable_code: "FSNOW-3001",
                exit_code: ExitCode::SafetyRefusal,
                retryable: false,
                policy_boundary: true,
                summary: "Mutation refused: read-only by default.",
                safe_next_commands: &[
                    "franken-snowflake query plan --profile <profile> --sql <sql> --json",
                ],
                repair_commands: &["franken-snowflake agent-handbook --json"],
            },
            Self::MultiStatementRefused => ErrorEntry {
                code: self,
                stable_code: "FSNOW-3002",
                exit_code: ExitCode::SafetyRefusal,
                retryable: false,
                policy_boundary: true,
                summary: "Multi-statement request refused by default policy.",
                safe_next_commands: &[
                    "franken-snowflake query run --profile <profile> --sql <single-statement> --json",
                ],
                repair_commands: &["franken-snowflake agent-handbook --json"],
            },
            Self::RequireLiveRefused => ErrorEntry {
                code: self,
                stable_code: "FSNOW-3003",
                exit_code: ExitCode::SafetyRefusal,
                retryable: false,
                policy_boundary: true,
                summary: "--require-live refused a fixture/empty substitution.",
                safe_next_commands: &["franken-snowflake profile doctor <profile> --online --json"],
                repair_commands: &["franken-snowflake profile validate <profile> --json"],
            },
            Self::RowCapExceeded => ErrorEntry {
                code: self,
                stable_code: "FSNOW-3004",
                exit_code: ExitCode::SafetyRefusal,
                retryable: false,
                policy_boundary: true,
                summary: "Result exceeded the row cap; use export or raise the cap.",
                safe_next_commands: &[
                    "franken-snowflake query run --profile <profile> --sql <sql> --max-rows <n> --json",
                ],
                repair_commands: &["franken-snowflake export --profile <profile> --sql <sql>"],
            },
            Self::SafetyLimitExceeded => ErrorEntry {
                code: self,
                stable_code: "FSNOW-3005",
                exit_code: ExitCode::SafetyRefusal,
                retryable: false,
                policy_boundary: true,
                summary: "Statement or result safety bound exceeded.",
                safe_next_commands: &[
                    "franken-snowflake query plan --profile <profile> --sql <sql> --json",
                ],
                repair_commands: &[
                    "franken-snowflake query plan --profile <profile> --sql <bounded-sql> --json",
                ],
            },
            Self::WarehouseRefused => ErrorEntry {
                code: self,
                stable_code: "FSNOW-3006",
                exit_code: ExitCode::SafetyRefusal,
                retryable: false,
                policy_boundary: true,
                summary: "Warehouse guardrail refused the requested warehouse.",
                safe_next_commands: &["franken-snowflake profile validate <profile> --json"],
                repair_commands: &["franken-snowflake profile doctor <profile> --json"],
            },
            Self::UpstreamError => ErrorEntry {
                code: self,
                stable_code: "FSNOW-4001",
                exit_code: ExitCode::UpstreamError,
                retryable: false,
                policy_boundary: false,
                summary: "Upstream Snowflake SQL API error.",
                safe_next_commands: &["franken-snowflake profile doctor <profile> --online --json"],
                repair_commands: &["franken-snowflake doctor --json"],
            },
            Self::StatementFailed => ErrorEntry {
                code: self,
                stable_code: "FSNOW-4002",
                exit_code: ExitCode::UpstreamError,
                retryable: false,
                policy_boundary: false,
                summary: "Statement failed upstream.",
                safe_next_commands: &[
                    "franken-snowflake query plan --profile <profile> --sql <sql> --json",
                ],
                repair_commands: &[
                    "franken-snowflake query plan --profile <profile> --sql <sql> --json",
                ],
            },
            Self::StatementTimeout => ErrorEntry {
                code: self,
                stable_code: "FSNOW-4003",
                exit_code: ExitCode::UpstreamError,
                retryable: true,
                policy_boundary: false,
                summary: "Statement exceeded STATEMENT_TIMEOUT_IN_SECONDS.",
                safe_next_commands: &[
                    "franken-snowflake query run --profile <profile> --sql <sql> --json",
                ],
                repair_commands: &[
                    "franken-snowflake query plan --profile <profile> --sql <sql> --json",
                ],
            },
            Self::NetworkError => ErrorEntry {
                code: self,
                stable_code: "FSNOW-5001",
                exit_code: ExitCode::NetworkBudgetExhausted,
                retryable: true,
                policy_boundary: false,
                summary: "Network/transport error.",
                safe_next_commands: &["franken-snowflake doctor --json"],
                repair_commands: &["franken-snowflake profile doctor <profile> --online --json"],
            },
            Self::RetryBudgetExhausted => ErrorEntry {
                code: self,
                stable_code: "FSNOW-5002",
                exit_code: ExitCode::NetworkBudgetExhausted,
                retryable: false,
                policy_boundary: false,
                summary: "Retry budget exhausted.",
                safe_next_commands: &["franken-snowflake doctor --json"],
                repair_commands: &["franken-snowflake query cancel <statement-handle> --json"],
            },
            Self::RateLimited => ErrorEntry {
                code: self,
                stable_code: "FSNOW-5003",
                exit_code: ExitCode::NetworkBudgetExhausted,
                retryable: true,
                policy_boundary: false,
                summary: "Rate limited upstream (429).",
                safe_next_commands: &["franken-snowflake doctor --json"],
                repair_commands: &[
                    "franken-snowflake query run --profile <profile> --sql <sql> --json",
                ],
            },
            Self::QueryStillRunning => ErrorEntry {
                code: self,
                stable_code: "FSNOW-6001",
                exit_code: ExitCode::QueryStillRunning,
                retryable: true,
                policy_boundary: false,
                summary: "Async query still running; poll the handle.",
                safe_next_commands: &["franken-snowflake query cancel <statement-handle> --json"],
                repair_commands: &["franken-snowflake receipt show <receipt-hash> --json"],
            },
            Self::CacheError => ErrorEntry {
                code: self,
                stable_code: "FSNOW-7001",
                exit_code: ExitCode::LocalCacheError,
                retryable: false,
                policy_boundary: false,
                summary: "Local cache error.",
                safe_next_commands: &["franken-snowflake doctor --json"],
                repair_commands: &["franken-snowflake doctor --json"],
            },
            Self::MetadataError => ErrorEntry {
                code: self,
                stable_code: "FSNOW-7002",
                exit_code: ExitCode::LocalCacheError,
                retryable: false,
                policy_boundary: false,
                summary: "Local metadata error.",
                safe_next_commands: &["franken-snowflake catalog scan <profile> --json"],
                repair_commands: &["franken-snowflake doctor --json"],
            },
            Self::Internal => ErrorEntry {
                code: self,
                stable_code: "FSNOW-9001",
                exit_code: ExitCode::Io,
                retryable: false,
                policy_boundary: false,
                summary: "Internal invariant violated.",
                safe_next_commands: &["franken-snowflake doctor --json"],
                repair_commands: &["franken-snowflake selftest --json"],
            },
            Self::SurfaceReserved => ErrorEntry {
                code: self,
                stable_code: "FSNOW-9002",
                exit_code: ExitCode::SafetyRefusal,
                retryable: false,
                policy_boundary: true,
                summary: "Command surface is reserved; its handler is pending lower-level beads.",
                safe_next_commands: &["franken-snowflake capabilities --json"],
                repair_commands: &["franken-snowflake doctor --json"],
            },
        }
    }

    /// The stable wire string for this code.
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        self.entry().stable_code
    }

    /// The process exit code for this error.
    #[must_use]
    pub const fn exit_code(self) -> ExitCode {
        self.entry().exit_code
    }

    /// Whether retrying may succeed.
    #[must_use]
    pub const fn retryable(self) -> bool {
        self.entry().retryable
    }

    /// Whether this is a policy/safety boundary.
    #[must_use]
    pub const fn policy_boundary(self) -> bool {
        self.entry().policy_boundary
    }

    /// Resolve a code from its stable wire string.
    #[must_use]
    pub fn from_stable_code(code: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.stable_code() == code)
    }
}

impl Serialize for SnowflakeErrorCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.stable_code())
    }
}

impl<'de> Deserialize<'de> for SnowflakeErrorCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_stable_code(&raw)
            .ok_or_else(|| D::Error::custom(format!("unknown error code: {raw}")))
    }
}

/// A connector error with its registry-sourced default recovery path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnowflakeError {
    /// The stable error code.
    pub code: SnowflakeErrorCode,
    /// A human-readable, already-redacted message.
    pub message: String,
    /// Safe follow-up commands (defaulted from the registry).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub safe_next_commands: Vec<String>,
    /// Repair commands (defaulted from the registry).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repair_commands: Vec<String>,
}

impl SnowflakeError {
    /// Build an error, auto-populating recovery commands from the registry.
    ///
    /// The caller is responsible for passing an already-redacted `message`.
    #[must_use]
    pub fn new(code: SnowflakeErrorCode, message: impl Into<String>) -> Self {
        let entry = code.entry();
        Self {
            code,
            message: message.into(),
            safe_next_commands: entry
                .safe_next_commands
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            repair_commands: entry
                .repair_commands
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        }
    }

    /// Whether retrying may succeed.
    #[must_use]
    pub fn retryable(&self) -> bool {
        self.code.retryable()
    }

    /// Whether this is a policy/safety boundary.
    #[must_use]
    pub fn policy_boundary(&self) -> bool {
        self.code.policy_boundary()
    }

    /// The process exit code for this error.
    #[must_use]
    pub fn exit_code(&self) -> ExitCode {
        self.code.exit_code()
    }

    /// The stable wire code string.
    #[must_use]
    pub fn stable_code(&self) -> &'static str {
        self.code.stable_code()
    }
}

impl core::fmt::Display for SnowflakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{}] {}", self.stable_code(), self.message)
    }
}

impl std::error::Error for SnowflakeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_complete_recovery_paths() {
        for code in SnowflakeErrorCode::ALL {
            let entry = code.entry();
            assert!(!entry.stable_code.is_empty(), "{code:?} stable_code");
            assert!(!entry.summary.is_empty(), "{code:?} summary");
            assert!(
                !entry.safe_next_commands.is_empty(),
                "{code:?} has no safe_next_commands"
            );
            assert!(
                !entry.repair_commands.is_empty(),
                "{code:?} has no repair_commands"
            );
        }
    }

    #[test]
    fn stable_codes_unique_and_roundtrip() {
        let mut seen = std::collections::BTreeSet::new();
        for code in SnowflakeErrorCode::ALL {
            let stable = code.stable_code();
            assert!(seen.insert(stable), "duplicate stable_code {stable}");
            assert!(stable.starts_with("FSNOW-"), "{code:?} not FSNOW-prefixed");
            assert_eq!(SnowflakeErrorCode::from_stable_code(stable), Some(*code));
        }
        assert_eq!(seen.len(), SnowflakeErrorCode::ALL.len());
    }

    #[test]
    fn error_code_serializes_as_stable_string() -> Result<(), serde_json::Error> {
        let json = serde_json::to_string(&SnowflakeErrorCode::ProfileNotFound)?;
        assert_eq!(json, "\"FSNOW-2001\"");
        let back: SnowflakeErrorCode = serde_json::from_str("\"FSNOW-2001\"")?;
        assert_eq!(back, SnowflakeErrorCode::ProfileNotFound);
        Ok(())
    }

    #[test]
    fn unknown_stable_code_is_none() {
        assert_eq!(SnowflakeErrorCode::from_stable_code("FSNOW-0000"), None);
    }

    #[test]
    fn new_error_autopopulates_recovery() {
        let err = SnowflakeError::new(SnowflakeErrorCode::ProfileNotFound, "no such profile");
        assert!(!err.safe_next_commands.is_empty());
        assert!(!err.repair_commands.is_empty());
        assert_eq!(err.exit_code(), ExitCode::CredentialError);
        assert_eq!(err.stable_code(), "FSNOW-2001");
        assert!(!err.retryable());
    }

    #[test]
    fn policy_boundary_and_retryable_flags() {
        assert!(SnowflakeErrorCode::MutationRefused.policy_boundary());
        assert!(!SnowflakeErrorCode::NetworkError.policy_boundary());
        assert!(SnowflakeErrorCode::NetworkError.retryable());
        assert!(!SnowflakeErrorCode::ProfileNotFound.retryable());
    }
}
