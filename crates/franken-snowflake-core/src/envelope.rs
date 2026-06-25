//! The deterministic, versioned JSON envelope metadata.
//!
//! Every CLI/MCP response is `{ ...envelope metadata, "data": <payload> }`. This
//! module owns the metadata half ([`EnvelopeMeta`]) and a generic [`Envelope`]
//! that flattens it alongside a typed payload. Field order is fixed by struct
//! declaration, so output is deterministic; `schema_version` /
//! `output_contract_id` identify the shape. Keys mirror `docs/agent_cli_contract.md`.

use serde::{Deserialize, Serialize};

use crate::error::{SnowflakeError, SnowflakeErrorCode};
use crate::ids::{ProfileName, QueryId, ReceiptHash, RequestId, StatementHandle};
use crate::outcome::{DataSource, OutcomeKind};

/// The current envelope schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Advisory budget usage reported in the envelope.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetConsumed {
    /// Milliseconds remaining against the deadline, if a deadline was set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline_ms_remaining: Option<u64>,
    /// Polls performed so far.
    pub polls_used: u32,
    /// Poll-count quota, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_quota: Option<u32>,
    /// Advisory client-side cost-quota units consumed, if tracked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_quota_used: Option<u64>,
}

/// The error block attached to error envelopes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeError {
    /// The stable error code (serialized as e.g. `FSNOW-2001`).
    pub code: SnowflakeErrorCode,
    /// A human-readable, already-redacted message.
    pub message: String,
    /// Whether retrying may succeed.
    pub retryable: bool,
    /// Whether this is a policy/safety boundary.
    pub policy_boundary: bool,
    /// Safe follow-up commands.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub safe_next_commands: Vec<String>,
    /// Repair commands.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repair_commands: Vec<String>,
    /// `did_you_mean` suggestions (Levenshtein over known names).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub did_you_mean: Vec<String>,
    /// Opaque evidence handles (never raw secrets).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

impl From<SnowflakeError> for EnvelopeError {
    fn from(error: SnowflakeError) -> Self {
        let retryable = error.retryable();
        let policy_boundary = error.policy_boundary();
        Self {
            code: error.code,
            message: error.message,
            retryable,
            policy_boundary,
            safe_next_commands: error.safe_next_commands,
            repair_commands: error.repair_commands,
            did_you_mean: Vec::new(),
            evidence: Vec::new(),
        }
    }
}

/// The metadata half of every response envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeMeta {
    /// Boolean success flag.
    pub ok: bool,
    /// Finer-grained outcome class (independent of `ok` and exit code).
    pub outcome_kind: OutcomeKind,
    /// Stable command identifier.
    pub command_id: String,
    /// Identifies the payload shape.
    pub output_contract_id: String,
    /// Envelope schema version.
    pub schema_version: u32,
    /// Payload provenance; omitted when unspecified.
    #[serde(skip_serializing_if = "DataSource::is_unspecified")]
    pub data_source: DataSource,
    /// Profile used (never a secret).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<ProfileName>,
    /// Client-generated request id / SQL API idempotency key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<RequestId>,
    /// Snowflake `query_id`, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_id: Option<QueryId>,
    /// SQL API statement handle, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_handle: Option<StatementHandle>,
    /// Receipt content address, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_hash: Option<ReceiptHash>,
    /// RFC3339 start time (stamped by the caller).
    pub started_at: String,
    /// RFC3339 finish time (stamped by the caller).
    pub finished_at: String,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Non-fatal findings.
    #[serde(default)]
    pub warnings: Vec<String>,
    /// Suggested follow-up commands.
    #[serde(default)]
    pub safe_next_commands: Vec<String>,
    /// Redaction markers applied to this payload.
    #[serde(default)]
    pub redactions_applied: Vec<String>,
    /// Advisory budget usage, when tracked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_consumed: Option<BudgetConsumed>,
    /// Error block, present only on error envelopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<EnvelopeError>,
}

impl EnvelopeMeta {
    /// A minimal envelope for `command_id` / `output_contract_id` with the given
    /// success flag and outcome class. Timing and ids default to empty/absent and
    /// are filled by the caller via the `with_*` setters.
    #[must_use]
    pub fn new(
        command_id: impl Into<String>,
        output_contract_id: impl Into<String>,
        ok: bool,
        outcome_kind: OutcomeKind,
    ) -> Self {
        Self {
            ok,
            outcome_kind,
            command_id: command_id.into(),
            output_contract_id: output_contract_id.into(),
            schema_version: SCHEMA_VERSION,
            data_source: DataSource::Unspecified,
            profile_id: None,
            request_id: None,
            query_id: None,
            statement_handle: None,
            receipt_hash: None,
            started_at: String::new(),
            finished_at: String::new(),
            duration_ms: 0,
            warnings: Vec::new(),
            safe_next_commands: Vec::new(),
            redactions_applied: Vec::new(),
            budget_consumed: None,
            error: None,
        }
    }

    /// A successful envelope (`ok = true`, `outcome_kind = success`).
    #[must_use]
    pub fn success(
        command_id: impl Into<String>,
        output_contract_id: impl Into<String>,
    ) -> Self {
        Self::new(command_id, output_contract_id, true, OutcomeKind::Success)
    }

    /// An error envelope built from a [`SnowflakeError`]: `ok = false`,
    /// `outcome_kind = error`, error block attached.
    #[must_use]
    pub fn error(
        command_id: impl Into<String>,
        output_contract_id: impl Into<String>,
        error: SnowflakeError,
    ) -> Self {
        let mut meta = Self::new(command_id, output_contract_id, false, OutcomeKind::Error);
        meta.error = Some(error.into());
        meta
    }

    /// Set the payload provenance.
    #[must_use]
    pub fn with_data_source(mut self, data_source: DataSource) -> Self {
        self.data_source = data_source;
        self
    }

    /// Set the profile id.
    #[must_use]
    pub fn with_profile(mut self, profile: ProfileName) -> Self {
        self.profile_id = Some(profile);
        self
    }

    /// Set start/finish timestamps and duration.
    #[must_use]
    pub fn with_timing(
        mut self,
        started_at: impl Into<String>,
        finished_at: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        self.started_at = started_at.into();
        self.finished_at = finished_at.into();
        self.duration_ms = duration_ms;
        self
    }

    /// Serialize to a compact JSON string.
    ///
    /// # Errors
    /// Returns the underlying `serde_json` error on failure (not expected for
    /// these always-serializable types).
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// A full response envelope: flattened [`EnvelopeMeta`] plus a typed payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    /// The envelope metadata (flattened into the top-level object).
    #[serde(flatten)]
    pub meta: EnvelopeMeta,
    /// The typed payload.
    pub data: T,
}

impl<T: Serialize> Envelope<T> {
    /// Wrap `data` with `meta`.
    pub fn new(meta: EnvelopeMeta, data: T) -> Self {
        Self { meta, data }
    }

    /// Serialize the whole envelope to a compact JSON string.
    ///
    /// # Errors
    /// Returns the underlying `serde_json` error on failure.
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{SnowflakeError, SnowflakeErrorCode};
    use crate::outcome::{DataSource, OutcomeKind};

    #[test]
    fn schema_version_is_pinned() {
        let meta = EnvelopeMeta::success("capabilities", "capabilities.v1");
        assert_eq!(meta.schema_version, SCHEMA_VERSION);
        assert_eq!(SCHEMA_VERSION, 1);
    }

    #[test]
    fn serialization_is_deterministic_and_ordered() -> Result<(), serde_json::Error> {
        let meta =
            EnvelopeMeta::success("doctor", "doctor.v1").with_data_source(DataSource::Live);
        let first = meta.to_json_string()?;
        let second = meta.to_json_string()?;
        assert_eq!(first, second, "serialization must be deterministic");
        // Field order is fixed by struct declaration, so the prefix is stable.
        assert!(
            first.starts_with("{\"ok\":true,\"outcome_kind\":\"success\",\"command_id\":\"doctor\""),
            "unexpected key order: {first}"
        );
        assert!(first.contains("\"schema_version\":1"));
        assert!(first.contains("\"data_source\":\"live\""));
        Ok(())
    }

    #[test]
    fn unspecified_data_source_and_absent_ids_are_omitted() -> Result<(), serde_json::Error> {
        let json = EnvelopeMeta::success("doctor", "doctor.v1").to_json_string()?;
        assert!(!json.contains("data_source"));
        assert!(!json.contains("profile_id"));
        assert!(!json.contains("request_id"));
        assert!(!json.contains("statement_handle"));
        Ok(())
    }

    #[test]
    fn error_envelope_carries_error_block() -> Result<(), serde_json::Error> {
        let err = SnowflakeError::new(SnowflakeErrorCode::ProfileNotFound, "missing");
        let meta = EnvelopeMeta::error("profile-validate", "profile.v1", err);
        assert!(!meta.ok);
        assert_eq!(meta.outcome_kind, OutcomeKind::Error);
        let json = meta.to_json_string()?;
        assert!(json.contains("\"ok\":false"));
        assert!(json.contains("\"code\":\"FSNOW-2001\""));
        assert!(json.contains("\"retryable\":false"));
        Ok(())
    }

    #[test]
    fn full_envelope_flattens_meta_and_data() -> Result<(), serde_json::Error> {
        let envelope = Envelope::new(
            EnvelopeMeta::success("query-run", "rows.v1"),
            serde_json::json!({ "rows": [] }),
        );
        let json = envelope.to_json_string()?;
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"data\":{"));
        assert!(json.contains("\"rows\":[]"));
        Ok(())
    }
}
