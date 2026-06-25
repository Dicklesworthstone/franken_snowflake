//! Security and cost-safety guardrails shared by CLI, MCP, SQL planning, and
//! receipt code.
//!
//! This module is deliberately transport-free. It refuses unsafe plans before a
//! live Snowflake call exists, and it emits typed metadata the later CLI/MCP
//! surfaces can serialize into envelopes, receipts, logs, and export records.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{SnowflakeError, SnowflakeErrorCode};
use crate::outcome::{DataSource, OutcomeKind};
use crate::redact::{contains_secret, redact, redact_with_account};

/// Guardrail structured log schema version.
pub const GUARDRAIL_LOG_SCHEMA_VERSION: u16 = 1;

/// Default maximum SQL statement size in bytes for interactive query paths.
pub const DEFAULT_MAX_STATEMENT_BYTES: usize = 1_000_000;

/// Default maximum result rows unless the caller explicitly chooses export or a
/// narrower limit.
pub const DEFAULT_MAX_RESULT_ROWS: u64 = 10_000;

/// Default maximum result bytes retained locally without export.
pub const DEFAULT_MAX_RESULT_BYTES: u64 = 100 * 1024 * 1024;

/// Default enforceable server-side statement timeout.
pub const DEFAULT_STATEMENT_TIMEOUT_SECONDS: u32 = 300;

/// Snowflake bills a 60-second minimum on warehouse start/resume.
pub const WAREHOUSE_BILLING_MINIMUM_SECONDS: u64 = 60;

/// Mutating operation policy. Mutation is disabled until the future
/// write-intent ladder opts in explicitly.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationPolicy {
    ReadOnly,
    WriteIntentRequired,
}

/// Parsed SQL operation class.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlOperationClass {
    Read,
    Mutating,
}

/// Fail-closed rights class. Higher variants are more restrictive.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RightsClass {
    Public,
    Internal,
    Private,
    Restricted,
}

impl RightsClass {
    /// Parse a manifest/profile rights label. Unknown labels are deliberately
    /// the most restrictive class.
    #[must_use]
    pub fn parse_fail_closed(label: &str) -> Self {
        match normalize_label(label).as_str() {
            "public" => Self::Public,
            "internal" | "organization" | "org" => Self::Internal,
            "private" | "confidential" => Self::Private,
            "restricted" | "secret" | "highly_restricted" => Self::Restricted,
            _ => Self::Restricted,
        }
    }
}

impl fmt::Display for RightsClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public => f.write_str("public"),
            Self::Internal => f.write_str("internal"),
            Self::Private => f.write_str("private"),
            Self::Restricted => f.write_str("restricted"),
        }
    }
}

/// Time-bounded entitlement to a maximum rights class.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RightsEntitlement {
    pub max_rights_class: RightsClass,
    pub expires_at_unix_seconds: Option<i64>,
}

impl RightsEntitlement {
    /// Expired entitlements are missing, not default-allow.
    #[must_use]
    pub fn active_at(&self, now_unix_seconds: i64) -> Option<RightsClass> {
        match self.expires_at_unix_seconds {
            Some(expires_at) if expires_at <= now_unix_seconds => None,
            _ => Some(self.max_rights_class),
        }
    }

    #[must_use]
    pub fn permits(&self, required: RightsClass, now_unix_seconds: i64) -> bool {
        self.active_at(now_unix_seconds)
            .is_some_and(|allowed| allowed >= required)
    }
}

/// Enforceable and advisory query guardrails.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuerySafetyLimits {
    pub max_statement_bytes: usize,
    pub max_result_rows: u64,
    pub max_result_bytes: u64,
    pub statement_timeout_seconds: u32,
    pub require_warehouse: bool,
    pub allowed_warehouses: Vec<String>,
    pub mutation_policy: MutationPolicy,
}

impl Default for QuerySafetyLimits {
    fn default() -> Self {
        Self {
            max_statement_bytes: DEFAULT_MAX_STATEMENT_BYTES,
            max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            max_result_bytes: DEFAULT_MAX_RESULT_BYTES,
            statement_timeout_seconds: DEFAULT_STATEMENT_TIMEOUT_SECONDS,
            require_warehouse: true,
            allowed_warehouses: Vec::new(),
            mutation_policy: MutationPolicy::ReadOnly,
        }
    }
}

/// Caller-supplied query plan facts before a statement is submitted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueryPlanGuard {
    pub sql: String,
    pub statement_timeout_seconds: Option<u32>,
    pub result_row_cap: Option<u64>,
    pub result_byte_cap: Option<u64>,
    pub warehouse: Option<String>,
    pub export_mode: bool,
}

impl QueryPlanGuard {
    #[must_use]
    pub fn new(sql: impl Into<String>) -> Self {
        Self {
            sql: sql.into(),
            statement_timeout_seconds: None,
            result_row_cap: None,
            result_byte_cap: None,
            warehouse: None,
            export_mode: false,
        }
    }
}

/// Safe query plan after defaults are applied and policy has accepted it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BoundedQueryPlan {
    pub sql: String,
    pub statement_timeout_seconds: u32,
    pub result_row_cap: u64,
    pub result_byte_cap: u64,
    pub warehouse: String,
    pub warnings: Vec<GuardrailWarning>,
}

/// Non-fatal guardrail warning.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuardrailWarning {
    pub code: String,
    pub message: String,
}

/// Cost vector carried on receipts. Credit estimates are explicitly advisory.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CostVector {
    pub statements_run: u64,
    pub partitions_fetched: u64,
    pub bytes_scanned: u64,
    pub warehouse_credits_estimate_micros: u64,
    pub warehouse_credits_estimate_is_advisory: bool,
    pub warehouse_billing_seconds: u64,
}

impl CostVector {
    /// Estimate Snowflake warehouse credits with the 60-second billing floor.
    ///
    /// `credits_per_hour_micros` is the warehouse-size rate expressed in
    /// micro-credits/hour; the output remains advisory.
    #[must_use]
    pub fn estimate_warehouse(
        statements_run: u64,
        partitions_fetched: u64,
        bytes_scanned: u64,
        elapsed_seconds: u64,
        credits_per_hour_micros: u64,
    ) -> Self {
        let billed_seconds = elapsed_seconds.max(WAREHOUSE_BILLING_MINIMUM_SECONDS);
        let estimate = credits_per_hour_micros.saturating_mul(billed_seconds) / 3_600;
        Self {
            statements_run,
            partitions_fetched,
            bytes_scanned,
            warehouse_credits_estimate_micros: estimate,
            warehouse_credits_estimate_is_advisory: true,
            warehouse_billing_seconds: billed_seconds,
        }
    }

    #[must_use]
    pub fn breaches_advisory_budget(&self, cost_quota_micros: u64) -> bool {
        self.warehouse_credits_estimate_micros > cost_quota_micros
    }
}

/// Output channels scanned by the canary leak guard.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputChannel {
    Stdout,
    Stderr,
    Receipt,
    Log,
    Export,
}

/// Leak finding for a specific output channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanaryLeakFinding {
    pub channel: OutputChannel,
    pub message: String,
}

/// Structured JSON-line guardrail event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GuardrailLogLine {
    pub schema_version: u16,
    pub event: String,
    pub outcome_kind: OutcomeKind,
    pub message: String,
    pub redactions_applied: Vec<String>,
}

impl GuardrailLogLine {
    #[must_use]
    pub fn new(
        event: impl Into<String>,
        outcome_kind: OutcomeKind,
        message: impl Into<String>,
        redactions_applied: Vec<String>,
    ) -> Self {
        Self {
            schema_version: GUARDRAIL_LOG_SCHEMA_VERSION,
            event: event.into(),
            outcome_kind,
            message: message.into(),
            redactions_applied,
        }
    }
}

/// Redact secrets everywhere, and redact account identifiers only when requested.
#[must_use]
pub fn redact_for_output(
    input: &str,
    account_identifiers: &[&str],
    redact_account: bool,
) -> String {
    let secret_redacted = redact(input);
    if redact_account {
        redact_with_account(secret_redacted.as_ref(), account_identifiers)
    } else {
        secret_redacted.into_owned()
    }
}

/// Refuse fixture/empty/unspecified data when `--require-live` is active.
pub fn enforce_require_live(
    require_live: bool,
    data_source: DataSource,
) -> Result<(), SnowflakeError> {
    if require_live && data_source != DataSource::Live {
        Err(SnowflakeError::new(
            SnowflakeErrorCode::RequireLiveRefused,
            format!("--require-live requires live data; got {data_source:?}"),
        ))
    } else {
        Ok(())
    }
}

/// Require every public envelope to carry concrete provenance.
pub fn enforce_data_source_stamped(data_source: DataSource) -> Result<(), SnowflakeError> {
    if data_source.is_unspecified() {
        Err(SnowflakeError::new(
            SnowflakeErrorCode::Internal,
            "envelope missing data_source provenance stamp",
        ))
    } else {
        Ok(())
    }
}

/// Apply all query safety defaults and refusals.
pub fn enforce_query_safety(
    plan: QueryPlanGuard,
    limits: &QuerySafetyLimits,
) -> Result<BoundedQueryPlan, SnowflakeError> {
    if plan.sql.as_bytes().len() > limits.max_statement_bytes {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::SafetyLimitExceeded,
            format!(
                "statement is {} bytes; max_statement_bytes is {}",
                plan.sql.as_bytes().len(),
                limits.max_statement_bytes
            ),
        ));
    }

    let operation = classify_sql_operation(&plan.sql);
    if operation == SqlOperationClass::Mutating
        && limits.mutation_policy == MutationPolicy::ReadOnly
    {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::MutationRefused,
            "mutating SQL is disabled by default; use the future write-intent ladder",
        ));
    }

    let warehouse = match plan.warehouse {
        Some(warehouse) if !warehouse.trim().is_empty() => warehouse,
        _ if limits.require_warehouse => {
            return Err(SnowflakeError::new(
                SnowflakeErrorCode::WarehouseRefused,
                "warehouse is required for cost attribution and guardrails",
            ));
        }
        _ => String::new(),
    };

    if !limits.allowed_warehouses.is_empty()
        && !limits
            .allowed_warehouses
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&warehouse))
    {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::WarehouseRefused,
            "warehouse is not in the profile allowlist",
        ));
    }

    let mut warnings = Vec::new();
    let statement_timeout_seconds = match plan.statement_timeout_seconds {
        Some(timeout) if timeout > 0 => timeout.min(limits.statement_timeout_seconds),
        _ => {
            warnings.push(GuardrailWarning {
                code: "auto_statement_timeout".to_string(),
                message: format!(
                    "applied STATEMENT_TIMEOUT_IN_SECONDS={}",
                    limits.statement_timeout_seconds
                ),
            });
            limits.statement_timeout_seconds
        }
    };

    let result_row_cap = match plan.result_row_cap {
        Some(rows) if rows > 0 => rows.min(limits.max_result_rows),
        _ if plan.export_mode => limits.max_result_rows,
        _ => {
            warnings.push(GuardrailWarning {
                code: "auto_row_cap".to_string(),
                message: format!("applied result row cap {}", limits.max_result_rows),
            });
            limits.max_result_rows
        }
    };

    let result_byte_cap = match plan.result_byte_cap {
        Some(bytes) if bytes > 0 => bytes.min(limits.max_result_bytes),
        _ => {
            warnings.push(GuardrailWarning {
                code: "auto_byte_cap".to_string(),
                message: format!("applied result byte cap {}", limits.max_result_bytes),
            });
            limits.max_result_bytes
        }
    };

    if looks_unconstrained(&plan.sql) {
        warnings.push(GuardrailWarning {
            code: "unconstrained_query".to_string(),
            message: "query appears unconstrained; row and byte caps remain enforced".to_string(),
        });
    }

    Ok(BoundedQueryPlan {
        sql: plan.sql,
        statement_timeout_seconds,
        result_row_cap,
        result_byte_cap,
        warehouse,
        warnings,
    })
}

/// Convert an advisory cost budget breach into the connector's distinct
/// cancellation projection.
#[must_use]
pub fn cost_budget_breach_log(cost: &CostVector, quota_micros: u64) -> Option<GuardrailLogLine> {
    cost.breaches_advisory_budget(quota_micros).then(|| {
        GuardrailLogLine::new(
            "cost_budget_breach",
            OutcomeKind::Cancelled,
            "advisory cost quota breached; surface as Cancelled(CostBudget)",
            vec![],
        )
    })
}

/// Scan last-mile output channels for canary secrets using the single core
/// redaction needle list.
#[must_use]
pub fn scan_canary_outputs(outputs: &[(OutputChannel, &str)]) -> Vec<CanaryLeakFinding> {
    outputs
        .iter()
        .filter_map(|(channel, output)| {
            contains_secret(output).then(|| CanaryLeakFinding {
                channel: *channel,
                message: "secret-shaped canary found in output channel".to_string(),
            })
        })
        .collect()
}

/// Classify a SQL string enough to enforce read-only by default.
#[must_use]
pub fn classify_sql_operation(sql: &str) -> SqlOperationClass {
    let first = first_sql_keyword(sql);
    match first.as_deref() {
        Some(
            "alter" | "call" | "copy" | "create" | "delete" | "drop" | "grant" | "insert" | "merge"
            | "put" | "remove" | "revoke" | "truncate" | "update" | "use",
        ) => SqlOperationClass::Mutating,
        _ => SqlOperationClass::Read,
    }
}

fn first_sql_keyword(sql: &str) -> Option<String> {
    let without_comments = sql
        .lines()
        .map(|line| line.split_once("--").map_or(line, |(before, _)| before))
        .collect::<Vec<_>>()
        .join(" ");
    without_comments
        .trim_start()
        .trim_start_matches(';')
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .find(|part| !part.is_empty())
        .map(|part| part.to_ascii_lowercase())
}

fn looks_unconstrained(sql: &str) -> bool {
    let lowered = sql.to_ascii_lowercase();
    lowered.contains("select")
        && !contains_word(&lowered, "limit")
        && !contains_word(&lowered, "where")
        && !contains_word(&lowered, "qualify")
        && !contains_word(&lowered, "fetch")
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    haystack
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .any(|part| part == needle)
}

fn normalize_label(label: &str) -> String {
    label
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[must_use]
pub fn dedupe_redaction_markers(markers: impl IntoIterator<Item = String>) -> Vec<String> {
    markers
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cancel::{CancelKind, cancel_exit_code, cancel_outcome_kind};
    use crate::exit::ExitCode;
    use crate::redact::REDACTION_PLACEHOLDER;

    #[test]
    fn redacts_secret_prefixes_in_headers_and_query_params() {
        let input =
            "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.sig&token=ghp_abcdEFGH0123&key=sk-live";
        let redacted = redact_for_output(input, &[], false);
        assert!(!redacted.contains("eyJhbGci"));
        assert!(!redacted.contains("ghp_abcd"));
        assert!(!redacted.contains("sk-live"));
        assert_eq!(redacted.matches(REDACTION_PLACEHOLDER).count(), 3);
    }

    #[test]
    fn redacts_account_only_when_requested() {
        let input = "account=xy12345.us-east-1 token=AKIAEXAMPLE0001";
        let unredacted_account = redact_for_output(input, &["xy12345.us-east-1"], false);
        assert!(unredacted_account.contains("xy12345.us-east-1"));
        assert!(!unredacted_account.contains("AKIAEXAMPLE0001"));

        let redacted_account = redact_for_output(input, &["xy12345.us-east-1"], true);
        assert!(!redacted_account.contains("xy12345.us-east-1"));
    }

    #[test]
    fn rights_fail_closed_and_expired_entitlement_is_missing() {
        assert_eq!(
            RightsClass::parse_fail_closed("unexpected-label"),
            RightsClass::Restricted
        );
        let entitlement = RightsEntitlement {
            max_rights_class: RightsClass::Private,
            expires_at_unix_seconds: Some(99),
        };
        assert_eq!(entitlement.active_at(100), None);
        assert!(!entitlement.permits(RightsClass::Public, 100));
    }

    #[test]
    fn mutating_ops_disabled_by_default() {
        let limits = QuerySafetyLimits::default();
        let mut plan = QueryPlanGuard::new("delete from table_x");
        plan.warehouse = Some("SNOWFLAKE_XS".to_string());
        let error = enforce_query_safety(plan, &limits).expect_err("mutation must be refused");
        assert_eq!(error.code, SnowflakeErrorCode::MutationRefused);
    }

    #[test]
    fn query_without_bounds_is_auto_bounded_and_warned() {
        let limits = QuerySafetyLimits {
            allowed_warehouses: vec!["SNOWFLAKE_XS".to_string()],
            ..QuerySafetyLimits::default()
        };
        let mut plan = QueryPlanGuard::new("select * from events");
        plan.warehouse = Some("snowflake_xs".to_string());
        let bounded = enforce_query_safety(plan, &limits).expect("query should be auto-bounded");
        assert_eq!(
            bounded.statement_timeout_seconds,
            DEFAULT_STATEMENT_TIMEOUT_SECONDS
        );
        assert_eq!(bounded.result_row_cap, DEFAULT_MAX_RESULT_ROWS);
        assert_eq!(bounded.result_byte_cap, DEFAULT_MAX_RESULT_BYTES);
        assert!(bounded.warnings.iter().any(|w| w.code == "auto_row_cap"));
        assert!(
            bounded
                .warnings
                .iter()
                .any(|w| w.code == "unconstrained_query")
        );
    }

    #[test]
    fn statement_size_and_warehouse_guardrails_refuse() {
        let limits = QuerySafetyLimits {
            max_statement_bytes: 8,
            allowed_warehouses: vec!["ALLOWED_XS".to_string()],
            ..QuerySafetyLimits::default()
        };
        let mut too_large = QueryPlanGuard::new("select 1 from table");
        too_large.warehouse = Some("ALLOWED_XS".to_string());
        assert_eq!(
            enforce_query_safety(too_large, &limits)
                .expect_err("large statement refused")
                .code,
            SnowflakeErrorCode::SafetyLimitExceeded
        );

        let mut bad_warehouse = QueryPlanGuard::new("select 1");
        bad_warehouse.warehouse = Some("XL_BAD".to_string());
        assert_eq!(
            enforce_query_safety(bad_warehouse, &limits)
                .expect_err("bad warehouse refused")
                .code,
            SnowflakeErrorCode::WarehouseRefused
        );
    }

    #[test]
    fn cost_vector_is_advisory_and_uses_sixty_second_floor() {
        let vector = CostVector::estimate_warehouse(1, 2, 3_000, 5, 1_000_000);
        assert!(vector.warehouse_credits_estimate_is_advisory);
        assert_eq!(
            vector.warehouse_billing_seconds,
            WAREHOUSE_BILLING_MINIMUM_SECONDS
        );
        assert_eq!(vector.warehouse_credits_estimate_micros, 16_666);
        assert!(vector.breaches_advisory_budget(1_000));
        assert!(cost_budget_breach_log(&vector, 1_000).is_some());
        assert_eq!(
            cancel_outcome_kind(CancelKind::CostBudget),
            OutcomeKind::Cancelled
        );
        assert_eq!(
            cancel_exit_code(CancelKind::CostBudget),
            ExitCode::SafetyRefusal
        );
    }

    #[test]
    fn require_live_and_data_source_stamp_are_enforced() {
        assert!(enforce_require_live(true, DataSource::Live).is_ok());
        assert_eq!(
            enforce_require_live(true, DataSource::Fixture)
                .expect_err("fixture refused")
                .code,
            SnowflakeErrorCode::RequireLiveRefused
        );
        assert!(enforce_data_source_stamped(DataSource::Empty).is_ok());
        assert!(enforce_data_source_stamped(DataSource::Unspecified).is_err());
    }

    #[test]
    fn canary_scans_all_output_channels() {
        let outputs = [
            (OutputChannel::Stdout, "ok"),
            (OutputChannel::Stderr, "err ghp_secret000"),
            (OutputChannel::Receipt, "receipt sk-secret000"),
            (OutputChannel::Log, "log"),
            (OutputChannel::Export, "export eyJsecret"),
        ];
        let findings = scan_canary_outputs(&outputs);
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().any(|f| f.channel == OutputChannel::Stderr));
        assert!(findings.iter().any(|f| f.channel == OutputChannel::Receipt));
        assert!(findings.iter().any(|f| f.channel == OutputChannel::Export));
    }

    #[test]
    fn structured_guardrail_logs_are_serializable() -> Result<(), serde_json::Error> {
        let log = GuardrailLogLine::new(
            "query_guardrail",
            OutcomeKind::Refusal,
            "mutation refused",
            vec!["authorization".to_string()],
        );
        let json = serde_json::to_string(&log)?;
        assert!(json.contains("\"schema_version\":1"));
        assert!(json.contains("\"event\":\"query_guardrail\""));
        Ok(())
    }
}
