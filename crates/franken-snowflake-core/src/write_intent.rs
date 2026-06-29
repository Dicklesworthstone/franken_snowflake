//! Write-intent ladder types.
//!
//! This module models the only path that may widen from read-only query
//! planning to mutating Snowflake operations. It is transport-free: it
//! *authorizes* a mutation once every required rung is satisfied, but it never
//! submits SQL itself. The authorized [`WriteIntentDecision::ExecutionAuthorized`]
//! plan is handed to the transport layer (the CLI `live` executor) which runs the
//! statement over the SQL API. The ladder still produces non-executing dry-run
//! plans and typed refusals for every path that is not fully satisfied.

use serde::{Deserialize, Serialize};

use crate::ids::RequestId;
use crate::redact::redact;

/// Write-intent schema version carried by dry-run plans and receipts.
pub const WRITE_INTENT_SCHEMA_VERSION: u16 = 1;

/// Future write path mode being evaluated.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteIntentMode {
    /// Produce a non-executing dry-run plan.
    PlanDryRun,
    /// Run the execution preflight. When every rung is satisfied this authorizes
    /// execution (returning [`WriteIntentDecision::ExecutionAuthorized`]); the
    /// core authorizes but does not submit SQL — the transport layer does.
    PrepareExecution,
}

/// Fixed rungs in the deferred write-intent ladder.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteIntentStage {
    /// Default connector posture: read-only, no mutation authority.
    ReadOnlyDefault,
    /// Caller requested an explicit dry-run plan.
    DryRunPlan,
    /// SQL was classified into a write safety class.
    SafetyClassified,
    /// The statement matched a configured allowlist entry.
    StatementAllowlisted,
    /// The request is bound to an idempotency request id.
    IdempotencyBound,
    /// The caller supplied the exact confirmation token.
    ConfirmationMatched,
    /// A future execution receipt would be required here.
    ExecutionReceipt,
    /// A future append-only audit record would be required here.
    AppendOnlyAudit,
}

/// Typed classification for future mutating statements.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteStatementKind {
    /// `INSERT ...`
    Insert,
    /// `MERGE ...`
    Merge,
    /// `UPDATE ...`
    Update,
    /// `DELETE ...`
    Delete,
    /// `COPY INTO <table> ...`
    CopyIntoTable,
    /// `COPY INTO @stage ...`
    CopyIntoStage,
    /// `CREATE ...`
    Create,
    /// `ALTER ...`
    Alter,
    /// `DROP ...`
    Drop,
    /// `TRUNCATE ...`
    Truncate,
    /// `GRANT ...`
    Grant,
    /// `REVOKE ...`
    Revoke,
    /// `CALL ...`
    Call,
    /// `PUT ...`
    Put,
    /// `REMOVE ...`
    Remove,
    /// `USE ...`
    Use,
    /// Read-only or unknown statements are not valid write-intent statements.
    Unknown,
}

impl WriteStatementKind {
    /// Coarse safety class for this statement kind.
    #[must_use]
    pub const fn safety_class(self) -> WriteSafetyClass {
        match self {
            Self::Insert | Self::Merge | Self::Update | Self::Delete | Self::CopyIntoTable => {
                WriteSafetyClass::Dml
            }
            Self::Create
            | Self::Alter
            | Self::Drop
            | Self::Truncate
            | Self::Grant
            | Self::Revoke => WriteSafetyClass::Ddl,
            Self::Call => WriteSafetyClass::Procedure,
            Self::Put | Self::Remove | Self::CopyIntoStage => WriteSafetyClass::ExternalFile,
            Self::Use => WriteSafetyClass::SessionState,
            Self::Unknown => WriteSafetyClass::Unknown,
        }
    }

    /// Stable lowercase token used in confirmation phrases.
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Insert => "insert",
            Self::Merge => "merge",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::CopyIntoTable => "copy_into_table",
            Self::CopyIntoStage => "copy_into_stage",
            Self::Create => "create",
            Self::Alter => "alter",
            Self::Drop => "drop",
            Self::Truncate => "truncate",
            Self::Grant => "grant",
            Self::Revoke => "revoke",
            Self::Call => "call",
            Self::Put => "put",
            Self::Remove => "remove",
            Self::Use => "use",
            Self::Unknown => "unknown",
        }
    }
}

/// Coarse mutation safety class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteSafetyClass {
    /// Row/table data mutation.
    Dml,
    /// Schema, privilege, or object mutation. Refused by default.
    Ddl,
    /// Stored procedure execution.
    Procedure,
    /// Stage/file-side mutation.
    ExternalFile,
    /// Session state mutation such as `USE`.
    SessionState,
    /// Not accepted as a write-intent statement.
    Unknown,
}

/// A configured allowlist row. The id is non-secret and should be stable enough
/// to appear in dry-run envelopes, receipts, and audit records.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StatementAllowlistEntry {
    /// Stable allowlist id, e.g. `staging_insert_v1`.
    pub id: String,
    /// Statement kind this row allows.
    pub statement_kind: WriteStatementKind,
}

impl StatementAllowlistEntry {
    /// Build an allowlist row.
    #[must_use]
    pub fn new(id: impl Into<String>, statement_kind: WriteStatementKind) -> Self {
        Self {
            id: id.into(),
            statement_kind,
        }
    }
}

/// Policy gates for the deferred write-intent ladder.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WriteIntentPolicy {
    /// Global mutation opt-in. Defaults to false.
    pub enabled: bool,
    /// DDL stays disabled until a separate, documented public use case exists.
    pub allow_ddl: bool,
    /// Every write path must begin with `--dry-run`.
    pub require_dry_run: bool,
    /// Future execution must provide the exact confirmation token.
    pub require_exact_confirmation: bool,
    /// Future execution and dry-run receipts bind to a request id.
    pub require_idempotency_request_id: bool,
    /// Future execution must append an audit record, never update/delete one.
    pub require_append_only_audit: bool,
    /// Explicit allowlist of statement families permitted by this profile.
    pub statement_allowlist: Vec<StatementAllowlistEntry>,
}

impl Default for WriteIntentPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_ddl: false,
            require_dry_run: true,
            require_exact_confirmation: true,
            require_idempotency_request_id: true,
            require_append_only_audit: true,
            statement_allowlist: Vec::new(),
        }
    }
}

impl WriteIntentPolicy {
    /// Construct an enabled dry-run policy for an explicit statement allowlist.
    ///
    /// This still does not execute anything; it only permits dry-run planning
    /// and future preflight checks to advance past the read-only default rung.
    #[must_use]
    pub fn dry_run_only(statement_allowlist: Vec<StatementAllowlistEntry>) -> Self {
        Self {
            enabled: true,
            statement_allowlist,
            ..Self::default()
        }
    }
}

/// Exact confirmation token required before any future execution preflight can
/// leave the dry-run ladder.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ConfirmationToken(String);

impl ConfirmationToken {
    /// Wrap a confirmation token.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Build the deterministic confirmation phrase for a dry-run plan.
    #[must_use]
    pub fn for_request(request_id: &RequestId, statement_kind: WriteStatementKind) -> Self {
        Self(format!(
            "confirm:{}:{}",
            statement_kind.as_token(),
            request_id.as_str()
        ))
    }

    /// Borrow the token string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for ConfirmationToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Future append-only audit requirement supplied by a caller preflight.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AppendOnlyAuditIntent {
    /// Stable audit stream/table/log id.
    pub stream_id: String,
    /// Must be true. The ladder never permits update/delete audit modes.
    pub append_only: bool,
}

impl AppendOnlyAuditIntent {
    /// Build an append-only audit intent.
    #[must_use]
    pub fn append_only(stream_id: impl Into<String>) -> Self {
        Self {
            stream_id: stream_id.into(),
            append_only: true,
        }
    }
}

/// Caller facts presented to the write-intent ladder.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WriteIntentRequest {
    /// Dry-run planning or future execution preflight.
    pub mode: WriteIntentMode,
    /// Redacted SQL preview. The constructor applies the core secret redactor.
    pub redacted_sql_preview: String,
    /// Whether the caller explicitly requested `--dry-run`.
    pub dry_run: bool,
    /// Explicit allowlist id selected by the caller/profile.
    pub allowlist_id: Option<String>,
    /// SQL API idempotency request id.
    pub request_id: Option<RequestId>,
    /// Caller-supplied confirmation token for future execution preflight.
    pub confirmation_token: Option<ConfirmationToken>,
    /// Caller-supplied append-only audit intent for future execution preflight.
    pub audit_intent: Option<AppendOnlyAuditIntent>,
}

impl WriteIntentRequest {
    /// Build a write-intent request and redact secret-shaped SQL preview text.
    #[must_use]
    pub fn new(mode: WriteIntentMode, sql_preview: impl AsRef<str>) -> Self {
        Self {
            mode,
            redacted_sql_preview: redact(sql_preview.as_ref()).into_owned(),
            dry_run: false,
            allowlist_id: None,
            request_id: None,
            confirmation_token: None,
            audit_intent: None,
        }
    }
}

/// Stable idempotency receipt emitted by a dry-run plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WriteIntentReceipt {
    /// Schema version for the receipt shape.
    pub schema_version: u16,
    /// SQL API request id / idempotency key.
    pub request_id: RequestId,
    /// Statement kind this receipt covers.
    pub statement_kind: WriteStatementKind,
    /// True for a dry-run receipt; false on an execution-authorized receipt.
    pub dry_run: bool,
    /// True once the ladder has authorized execution for this receipt; false on a
    /// dry-run receipt. The transport layer only submits SQL when this is true.
    pub execution_enabled: bool,
}

/// A non-executing dry-run write plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WriteIntentPlan {
    /// Schema version for the plan shape.
    pub schema_version: u16,
    /// Redacted SQL preview accepted into the dry-run ladder.
    pub redacted_sql_preview: String,
    /// Typed statement kind.
    pub statement_kind: WriteStatementKind,
    /// Coarse safety class.
    pub safety_class: WriteSafetyClass,
    /// Matched allowlist row.
    pub allowlist_entry: StatementAllowlistEntry,
    /// Idempotency receipt for the dry-run plan.
    pub receipt: WriteIntentReceipt,
    /// Exact token required by any future execution preflight.
    pub required_confirmation_token: ConfirmationToken,
    /// Remaining rungs the executor must satisfy. A dry-run plan still lists the
    /// confirmation/receipt/audit rungs; an authorized plan lists only the
    /// execution-receipt rung the transport layer records.
    pub next_required_stages: Vec<WriteIntentStage>,
    /// False on a dry-run plan; true on an execution-authorized plan.
    pub execution_enabled: bool,
}

/// Refusal reason emitted by the ladder.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteIntentRefusalCode {
    /// Global policy keeps the connector read-only.
    MutationsDisabled,
    /// The caller omitted `--dry-run`.
    MissingDryRun,
    /// DDL is outside the supported write ladder.
    DdlRefused,
    /// No explicit allowlist row matched the statement.
    StatementNotAllowlisted,
    /// The caller omitted the idempotency request id.
    MissingIdempotencyRequestId,
    /// The caller omitted the exact confirmation token.
    MissingConfirmationToken,
    /// The caller's confirmation token did not match the dry-run token.
    ConfirmationTokenMismatch,
    /// The caller omitted an append-only audit intent.
    MissingAppendOnlyAudit,
    /// Reserved: every ladder rung passed but the calling surface has no live
    /// execution transport linked. The ladder itself now authorizes execution
    /// (see [`WriteIntentDecision::ExecutionAuthorized`]); this code is for a
    /// transport-less surface to report a clean refusal after authorization.
    ExecutionUnavailable,
}

/// Typed write-intent refusal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WriteIntentRefusal {
    /// Machine-stable refusal code.
    pub code: WriteIntentRefusalCode,
    /// Ladder rung that refused the request.
    pub stage: WriteIntentStage,
    /// Human-readable diagnostic.
    pub message: String,
}

impl WriteIntentRefusal {
    fn new(
        code: WriteIntentRefusalCode,
        stage: WriteIntentStage,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            stage,
            message: message.into(),
        }
    }
}

/// Result of evaluating a write-intent request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum WriteIntentDecision {
    /// Request stopped at a safety rung.
    Refused {
        /// Typed refusal details.
        refusal: WriteIntentRefusal,
    },
    /// Request produced a non-executing dry-run plan.
    DryRunPlanned {
        /// Dry-run plan and receipt.
        plan: WriteIntentPlan,
    },
    /// Every required rung passed: the transport layer is authorized to submit
    /// this mutation. The core does not submit SQL; it only authorizes. The plan
    /// and receipt carry `execution_enabled = true`.
    ExecutionAuthorized {
        /// Execution-authorized plan and receipt.
        plan: WriteIntentPlan,
    },
}

/// Evaluate a request against the deferred write-intent ladder.
#[must_use]
pub fn evaluate_write_intent(
    request: &WriteIntentRequest,
    policy: &WriteIntentPolicy,
) -> WriteIntentDecision {
    if !policy.enabled {
        return refused(
            WriteIntentRefusalCode::MutationsDisabled,
            WriteIntentStage::ReadOnlyDefault,
            "mutating operations are disabled by default",
        );
    }

    if policy.require_dry_run && !request.dry_run {
        return refused(
            WriteIntentRefusalCode::MissingDryRun,
            WriteIntentStage::DryRunPlan,
            "write-intent requests must begin with --dry-run",
        );
    }

    let statement_kind = classify_write_statement(&request.redacted_sql_preview);
    let safety_class = statement_kind.safety_class();
    if safety_class == WriteSafetyClass::Ddl && !policy.allow_ddl {
        return refused(
            WriteIntentRefusalCode::DdlRefused,
            WriteIntentStage::SafetyClassified,
            "DDL is disabled by the write-intent ladder",
        );
    }

    let Some(allowlist_entry) = matching_allowlist_entry(request, policy, statement_kind) else {
        return refused(
            WriteIntentRefusalCode::StatementNotAllowlisted,
            WriteIntentStage::StatementAllowlisted,
            "statement did not match an explicit write allowlist entry",
        );
    };

    let Some(request_id) = request.request_id.clone() else {
        return refused(
            WriteIntentRefusalCode::MissingIdempotencyRequestId,
            WriteIntentStage::IdempotencyBound,
            "write-intent requests require an idempotency request id",
        );
    };

    let required_confirmation_token =
        ConfirmationToken::for_request(&request_id, allowlist_entry.statement_kind);
    let receipt = WriteIntentReceipt {
        schema_version: WRITE_INTENT_SCHEMA_VERSION,
        request_id,
        statement_kind: allowlist_entry.statement_kind,
        dry_run: true,
        execution_enabled: false,
    };
    let plan = WriteIntentPlan {
        schema_version: WRITE_INTENT_SCHEMA_VERSION,
        redacted_sql_preview: request.redacted_sql_preview.clone(),
        statement_kind: allowlist_entry.statement_kind,
        safety_class,
        allowlist_entry,
        receipt,
        required_confirmation_token,
        next_required_stages: vec![
            WriteIntentStage::ConfirmationMatched,
            WriteIntentStage::ExecutionReceipt,
            WriteIntentStage::AppendOnlyAudit,
        ],
        execution_enabled: false,
    };

    if request.mode == WriteIntentMode::PlanDryRun {
        return WriteIntentDecision::DryRunPlanned { plan };
    }

    if policy.require_exact_confirmation {
        match request.confirmation_token.as_ref() {
            Some(token) if token == &plan.required_confirmation_token => {}
            Some(_) => {
                return refused(
                    WriteIntentRefusalCode::ConfirmationTokenMismatch,
                    WriteIntentStage::ConfirmationMatched,
                    "confirmation token did not match the dry-run plan",
                );
            }
            None => {
                return refused(
                    WriteIntentRefusalCode::MissingConfirmationToken,
                    WriteIntentStage::ConfirmationMatched,
                    "future execution preflight requires the exact confirmation token",
                );
            }
        }
    }

    if policy.require_append_only_audit
        && !request
            .audit_intent
            .as_ref()
            .is_some_and(|audit| audit.append_only)
    {
        return refused(
            WriteIntentRefusalCode::MissingAppendOnlyAudit,
            WriteIntentStage::AppendOnlyAudit,
            "execution preflight requires an append-only audit intent",
        );
    }

    // Every required rung is satisfied. Authorize execution: the core stamps the
    // receipt/plan as execution-enabled and hands it to the transport layer. The
    // ladder never submits SQL itself.
    let receipt = WriteIntentReceipt {
        dry_run: false,
        execution_enabled: true,
        ..plan.receipt.clone()
    };
    let authorized = WriteIntentPlan {
        receipt,
        next_required_stages: vec![WriteIntentStage::ExecutionReceipt],
        execution_enabled: true,
        ..plan
    };
    WriteIntentDecision::ExecutionAuthorized { plan: authorized }
}

/// Classify a SQL preview into a write statement kind.
#[must_use]
pub fn classify_write_statement(sql: &str) -> WriteStatementKind {
    let words = sql_words(sql);
    match words.first().map(String::as_str) {
        Some("insert") => WriteStatementKind::Insert,
        Some("merge") => WriteStatementKind::Merge,
        Some("update") => WriteStatementKind::Update,
        Some("delete") => WriteStatementKind::Delete,
        Some("copy") if looks_like_copy_into_stage(sql) => WriteStatementKind::CopyIntoStage,
        Some("copy") => WriteStatementKind::CopyIntoTable,
        Some("create") => WriteStatementKind::Create,
        Some("alter") => WriteStatementKind::Alter,
        Some("drop") => WriteStatementKind::Drop,
        Some("truncate") => WriteStatementKind::Truncate,
        Some("grant") => WriteStatementKind::Grant,
        Some("revoke") => WriteStatementKind::Revoke,
        Some("call") => WriteStatementKind::Call,
        Some("put") => WriteStatementKind::Put,
        Some("remove") => WriteStatementKind::Remove,
        Some("use") => WriteStatementKind::Use,
        _ => WriteStatementKind::Unknown,
    }
}

fn matching_allowlist_entry(
    request: &WriteIntentRequest,
    policy: &WriteIntentPolicy,
    statement_kind: WriteStatementKind,
) -> Option<StatementAllowlistEntry> {
    let allowlist_id = request.allowlist_id.as_ref()?;
    policy
        .statement_allowlist
        .iter()
        .find(|entry| entry.id == *allowlist_id && entry.statement_kind == statement_kind)
        .cloned()
}

fn refused(
    code: WriteIntentRefusalCode,
    stage: WriteIntentStage,
    message: &'static str,
) -> WriteIntentDecision {
    WriteIntentDecision::Refused {
        refusal: WriteIntentRefusal::new(code, stage, message),
    }
}

fn looks_like_copy_into_stage(sql: &str) -> bool {
    sql.to_ascii_lowercase().contains("copy into @")
}

fn sql_words(sql: &str) -> Vec<String> {
    sql.lines()
        .map(|line| line.split_once("--").map_or(line, |(before, _)| before))
        .collect::<Vec<_>>()
        .join(" ")
        .trim_start()
        .trim_start_matches(';')
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_policy() -> WriteIntentPolicy {
        WriteIntentPolicy::dry_run_only(vec![StatementAllowlistEntry::new(
            "staging_insert_v1",
            WriteStatementKind::Insert,
        )])
    }

    fn request(mode: WriteIntentMode, sql: &str) -> WriteIntentRequest {
        let mut request = WriteIntentRequest::new(mode, sql);
        request.dry_run = true;
        request.allowlist_id = Some("staging_insert_v1".to_string());
        request.request_id = Some(RequestId::new("req-123"));
        request
    }

    #[test]
    fn default_policy_refuses_all_mutation_planning() {
        let decision = evaluate_write_intent(
            &request(WriteIntentMode::PlanDryRun, "insert into t values (1)"),
            &WriteIntentPolicy::default(),
        );
        assert_eq!(
            decision,
            WriteIntentDecision::Refused {
                refusal: WriteIntentRefusal::new(
                    WriteIntentRefusalCode::MutationsDisabled,
                    WriteIntentStage::ReadOnlyDefault,
                    "mutating operations are disabled by default",
                ),
            }
        );
    }

    #[test]
    fn dry_run_plan_is_non_executing_and_binds_receipt() {
        let decision = evaluate_write_intent(
            &request(WriteIntentMode::PlanDryRun, "insert into t values (1)"),
            &enabled_policy(),
        );
        assert!(matches!(
            decision,
            WriteIntentDecision::DryRunPlanned { .. }
        ));
        if let WriteIntentDecision::DryRunPlanned { plan } = decision {
            assert_eq!(plan.statement_kind, WriteStatementKind::Insert);
            assert_eq!(plan.safety_class, WriteSafetyClass::Dml);
            assert!(!plan.execution_enabled);
            assert!(!plan.receipt.execution_enabled);
            assert_eq!(plan.receipt.request_id.as_str(), "req-123");
            assert_eq!(
                plan.required_confirmation_token.as_str(),
                "confirm:insert:req-123"
            );
            assert!(
                plan.next_required_stages
                    .contains(&WriteIntentStage::AppendOnlyAudit)
            );
        }
    }

    #[test]
    fn missing_dry_run_is_refused() {
        let mut req = request(WriteIntentMode::PlanDryRun, "insert into t values (1)");
        req.dry_run = false;
        let decision = evaluate_write_intent(&req, &enabled_policy());
        assert!(matches!(
            decision,
            WriteIntentDecision::Refused {
                refusal: WriteIntentRefusal {
                    code: WriteIntentRefusalCode::MissingDryRun,
                    stage: WriteIntentStage::DryRunPlan,
                    ..
                }
            }
        ));
    }

    #[test]
    fn ddl_is_refused_even_with_enabled_dry_run_policy() {
        let mut req = request(WriteIntentMode::PlanDryRun, "create table t(id int)");
        req.allowlist_id = Some("ddl_v1".to_string());
        let mut policy = enabled_policy();
        policy
            .statement_allowlist
            .push(StatementAllowlistEntry::new(
                "ddl_v1",
                WriteStatementKind::Create,
            ));

        let decision = evaluate_write_intent(&req, &policy);
        assert!(matches!(
            decision,
            WriteIntentDecision::Refused {
                refusal: WriteIntentRefusal {
                    code: WriteIntentRefusalCode::DdlRefused,
                    stage: WriteIntentStage::SafetyClassified,
                    ..
                }
            }
        ));
    }

    #[test]
    fn prepare_execution_requires_exact_confirmation_and_append_only_audit() {
        let mut req = request(
            WriteIntentMode::PrepareExecution,
            "insert into t values (1)",
        );
        let decision = evaluate_write_intent(&req, &enabled_policy());
        assert!(matches!(
            decision,
            WriteIntentDecision::Refused {
                refusal: WriteIntentRefusal {
                    code: WriteIntentRefusalCode::MissingConfirmationToken,
                    stage: WriteIntentStage::ConfirmationMatched,
                    ..
                }
            }
        ));

        req.confirmation_token = Some(ConfirmationToken::new("wrong-token"));
        let decision = evaluate_write_intent(&req, &enabled_policy());
        assert!(matches!(
            decision,
            WriteIntentDecision::Refused {
                refusal: WriteIntentRefusal {
                    code: WriteIntentRefusalCode::ConfirmationTokenMismatch,
                    stage: WriteIntentStage::ConfirmationMatched,
                    ..
                }
            }
        ));

        req.confirmation_token = Some(ConfirmationToken::new("confirm:insert:req-123"));
        let decision = evaluate_write_intent(&req, &enabled_policy());
        assert!(matches!(
            decision,
            WriteIntentDecision::Refused {
                refusal: WriteIntentRefusal {
                    code: WriteIntentRefusalCode::MissingAppendOnlyAudit,
                    stage: WriteIntentStage::AppendOnlyAudit,
                    ..
                }
            }
        ));

        req.audit_intent = Some(AppendOnlyAuditIntent::append_only("write_audit"));
        let decision = evaluate_write_intent(&req, &enabled_policy());
        assert!(matches!(
            decision,
            WriteIntentDecision::ExecutionAuthorized { .. }
        ));
        if let WriteIntentDecision::ExecutionAuthorized { plan } = decision {
            assert!(plan.execution_enabled, "authorized plan must enable execution");
            assert!(plan.receipt.execution_enabled);
            assert!(!plan.receipt.dry_run, "authorized receipt is no longer dry-run");
            assert_eq!(plan.statement_kind, WriteStatementKind::Insert);
            assert_eq!(plan.safety_class, WriteSafetyClass::Dml);
            assert_eq!(plan.receipt.request_id.as_str(), "req-123");
            assert_eq!(
                plan.next_required_stages,
                vec![WriteIntentStage::ExecutionReceipt]
            );
        }
    }

    #[test]
    fn fully_satisfied_request_without_append_only_audit_is_authorized() {
        // The routine data-write path the CLI uses: dry-run + exact confirmation
        // token, with the append-only audit rung left as an optional policy knob.
        let mut policy = enabled_policy();
        policy.require_append_only_audit = false;
        let mut req = request(
            WriteIntentMode::PrepareExecution,
            "insert into t values (1)",
        );
        req.confirmation_token = Some(ConfirmationToken::new("confirm:insert:req-123"));
        let decision = evaluate_write_intent(&req, &policy);
        assert!(
            matches!(decision, WriteIntentDecision::ExecutionAuthorized { .. }),
            "write-enabled profile + dry-run + confirm token must authorize without audit ceremony"
        );
    }

    #[test]
    fn dry_run_plan_is_not_execution_authorized() {
        let decision = evaluate_write_intent(
            &request(WriteIntentMode::PlanDryRun, "insert into t values (1)"),
            &enabled_policy(),
        );
        assert!(matches!(
            decision,
            WriteIntentDecision::DryRunPlanned { .. }
        ));
        if let WriteIntentDecision::DryRunPlanned { plan } = decision {
            assert!(!plan.execution_enabled, "dry-run plan never enables execution");
            assert!(plan.receipt.dry_run);
        }
    }

    #[test]
    fn sql_preview_is_secret_redacted() {
        let req = WriteIntentRequest::new(
            WriteIntentMode::PlanDryRun,
            "insert into t values ('AKIAEXAMPLE0001')",
        );
        assert!(!req.redacted_sql_preview.contains("AKIAEXAMPLE0001"));
    }
}
