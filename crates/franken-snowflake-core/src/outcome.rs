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
use crate::error::{SnowflakeError, SnowflakeErrorCode};
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSource {
    /// Produced by a live Snowflake call.
    Live,
    /// Produced by a no-account fixture/testkit.
    Fixture,
    /// A valid but empty result.
    Empty,
    /// Not stamped (serialized as absent).
    #[default]
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

/// Project a registry-backed error into the envelope outcome vocabulary.
#[must_use]
pub fn error_outcome_kind(error: &SnowflakeError) -> OutcomeKind {
    if let Some(kind) = error.cancel_kind {
        cancel_outcome_kind(kind)
    } else if error.policy_boundary() {
        OutcomeKind::Refusal
    } else if error.code == SnowflakeErrorCode::StatementTimeout {
        OutcomeKind::Timeout
    } else {
        OutcomeKind::Error
    }
}

impl<T> SnowflakeOutcomeExt for SnowflakeOutcome<T> {
    fn outcome_kind(&self) -> OutcomeKind {
        match self {
            Outcome::Ok(_) => OutcomeKind::Success,
            Outcome::Err(error) => error_outcome_kind(error),
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

/// Deterministic Asupersync [`asupersync::trace::crashpack::CrashPack`] pointer
/// recorded alongside terminal failure receipts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureCrashPackPointer {
    /// Crash pack schema version (`crashpack-v1`).
    pub schema_version: u32,
    /// Stable equivalence-class fingerprint (`format!("{:016x}", fingerprint)`).
    pub fingerprint: String,
    /// Replay command lines embedded in the crash pack.
    pub replay_command: Vec<String>,
    /// Filesystem path where the crash pack JSON was persisted, if written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
}

fn fnv1a_u64(chunks: &[&[u8]]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for chunk in chunks {
        for &byte in *chunk {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    hash
}

fn parse_cancel_kind(name: Option<&str>, outcome_kind: &str) -> asupersync::CancelKind {
    use asupersync::CancelKind;
    match name {
        Some("User") => CancelKind::User,
        Some("Timeout") => CancelKind::Timeout,
        Some("Deadline") => CancelKind::Deadline,
        Some("PollQuota") => CancelKind::PollQuota,
        Some("CostBudget") => CancelKind::CostBudget,
        Some("FailFast") => CancelKind::FailFast,
        Some("RaceLost") => CancelKind::RaceLost,
        Some("ParentCancelled") => CancelKind::ParentCancelled,
        Some("Shutdown") => CancelKind::Shutdown,
        _ if outcome_kind == "timeout" => CancelKind::Deadline,
        _ => CancelKind::User,
    }
}

/// Build and optionally persist an Asupersync [`asupersync::trace::crashpack::CrashPack`]
/// for a terminal statement failure (`error`, `timeout`, or `cancelled`).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn build_and_write_failure_crashpack(
    crashpack_dir: Option<&std::path::Path>,
    command_id: &str,
    profile_id: &str,
    trace_id: &str,
    outcome_kind: &str,
    error_code: &str,
    message: &str,
    cancel_kind: Option<&str>,
    created_at_ms: u64,
    replay_args: Vec<String>,
) -> FailureCrashPackPointer {
    use asupersync::trace::crashpack::{
        CRASHPACK_SCHEMA_VERSION, CrashPack, CrashPackConfig, CrashPackWriter, FailureInfo,
        FailureOutcome, FileCrashPackWriter, ReplayCommand,
    };
    use asupersync::types::{RegionId, TaskId, Time};

    let seed = fnv1a_u64(&[trace_id.as_bytes()]);
    let config_hash = fnv1a_u64(&[profile_id.as_bytes(), b"|", command_id.as_bytes()]);
    let fingerprint_u64 = fnv1a_u64(&[
        command_id.as_bytes(),
        b"|",
        outcome_kind.as_bytes(),
        b"|",
        error_code.as_bytes(),
        b"|",
        cancel_kind.unwrap_or("").as_bytes(),
    ]);
    let config = CrashPackConfig {
        seed,
        config_hash,
        worker_count: 1,
        max_steps: None,
        test_name: Some(command_id.to_owned()),
        commit_hash: None,
    };
    let failure_outcome = match outcome_kind {
        "cancelled" | "timeout" => FailureOutcome::Cancelled {
            cancel_kind: parse_cancel_kind(cancel_kind, outcome_kind),
        },
        _ => FailureOutcome::Err,
    };
    let failure = FailureInfo {
        task: TaskId::testing_default(),
        region: RegionId::testing_default(),
        outcome: failure_outcome,
        virtual_time: Time::from_millis(created_at_ms),
    };
    let replay_command_vec: Vec<String> = std::iter::once("franken-snowflake".to_owned())
        .chain(replay_args.clone())
        .collect();
    let replay = ReplayCommand {
        program: "franken-snowflake".to_owned(),
        args: replay_args,
        env: Vec::new(),
        command_line: replay_command_vec.join(" "),
    };
    let Ok(pack) = CrashPack::builder(config)
        .failure(failure)
        .fingerprint(fingerprint_u64)
        .created_at(created_at_ms.saturating_mul(1_000_000))
        .oracle_violations(vec![format!("{command_id}:{error_code}:{message}")])
        .replay(replay)
        .build()
    else {
        return FailureCrashPackPointer {
            schema_version: CRASHPACK_SCHEMA_VERSION,
            fingerprint: format!("{fingerprint_u64:016x}"),
            replay_command: replay_command_vec,
            artifact_path: None,
        };
    };
    let fingerprint = format!("{:016x}", pack.fingerprint());
    let artifact_path = crashpack_dir.and_then(|dir| {
        std::fs::create_dir_all(dir).ok()?;
        let writer = FileCrashPackWriter::new(dir.to_path_buf());
        let id = writer.write(&pack).ok()?;
        Some(id.path().to_owned())
    });
    FailureCrashPackPointer {
        schema_version: CRASHPACK_SCHEMA_VERSION,
        fingerprint,
        replay_command: replay_command_vec,
        artifact_path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cancel::{CancelPolicy, cancel_policy};
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
    fn policy_boundary_err_maps_to_refusal_and_registry_exit() {
        let err = SnowflakeError::new(SnowflakeErrorCode::MutationRefused, "read-only");
        let outcome: SnowflakeOutcome<u32> = Outcome::err(err);
        assert_eq!(outcome.outcome_kind(), OutcomeKind::Refusal);
        assert_eq!(outcome.exit_code(), ExitCode::SafetyRefusal);
        assert!(!outcome.is_success());
    }

    #[test]
    fn statement_timeout_err_maps_to_timeout_outcome() {
        let err = SnowflakeError::new(SnowflakeErrorCode::StatementTimeout, "statement timed out");
        let outcome: SnowflakeOutcome<u32> = Outcome::err(err);
        assert_eq!(outcome.outcome_kind(), OutcomeKind::Timeout);
        assert_eq!(outcome.exit_code(), ExitCode::UpstreamError);
        assert!(!outcome.is_success());
    }

    #[test]
    fn cancelled_error_projects_like_the_cancel_it_carries() {
        let user = SnowflakeError::cancelled(CancelKind::User, "stopped");
        assert_eq!(error_outcome_kind(&user), OutcomeKind::Cancelled);
        let deadline = SnowflakeError::cancelled(CancelKind::Deadline, "late");
        assert_eq!(error_outcome_kind(&deadline), OutcomeKind::Timeout);
        // The same code without a kind is an ordinary error.
        let bare = SnowflakeError::new(SnowflakeErrorCode::Cancelled, "x");
        assert_eq!(error_outcome_kind(&bare), OutcomeKind::Error);
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
