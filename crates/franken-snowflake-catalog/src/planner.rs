//! Dataset-mode query planner.

use std::collections::BTreeMap;

use franken_snowflake_core::error::SnowflakeErrorCode;
use franken_snowflake_core::guardrails::{
    DEFAULT_MAX_RESULT_BYTES, DEFAULT_MAX_RESULT_ROWS, QueryPlanGuard, QuerySafetyLimits,
    enforce_query_safety,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{
    ColumnCatalogEntry, DatasetManifest, DtypeClass, FieldRole, normalize_identifier,
};
use crate::operator::OperatorCatalogEntry;
use crate::predicate::{
    CompoundPredicate, LeafPredicate, PredicateAst, PredicateRefusal, PredicateRefusalCode,
    validate_predicate,
};

const PLANNER_LOG_SCHEMA_VERSION: u16 = 1;
const DATASET_STATEMENT_TIMEOUT_SECONDS: u32 = 60;

/// Dataset query mode. The caller supplies catalog artifacts; this planner
/// never discovers metadata or contacts Snowflake.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DatasetQueryRequest {
    /// Dataset ID.
    pub dataset_id: String,
    /// Projection. Empty means manifest safe default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub select: Vec<String>,
    /// Optional entity filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity: Option<String>,
    /// Inclusive start of the time range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Inclusive end of the time range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Optional Snowflake Time Travel timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_of: Option<String>,
    /// Structural predicate AST.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<PredicateAst>,
    /// Explicit row limit. If absent, the manifest default is used and a warning
    /// is emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Whether this plan is for an export path.
    pub export_mode: bool,
    /// Explicit confirmation token for large non-export plans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_token: Option<String>,
    /// Optional warehouse selected by the resolved profile. The pure catalog
    /// planner accepts `None`; profile validation can require one earlier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warehouse: Option<String>,
    /// Secret-free profile fingerprint used in the deterministic plan ID.
    pub profile_fingerprint: String,
    /// CLI/MCP command identifier.
    pub command_id: String,
    /// Trace identifier; also used as the Snowflake `QUERY_TAG` when present.
    pub trace_id: String,
}

/// Raw SQL dry-run request. Raw mode is expert-only and still read-only: the
/// planner accepts a single safe `SELECT`, applies guardrails, and returns a
/// plan without executing it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RawSqlPlanRequest {
    /// Caller-authored SQL. Must be one read-only `SELECT`.
    pub sql: String,
    /// Optional explicit row limit to push down if the SQL has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Whether this plan is for an export path.
    pub export_mode: bool,
    /// Explicit confirmation token for large non-export raw scans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_token: Option<String>,
    /// Optional warehouse selected by the resolved profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warehouse: Option<String>,
    /// Secret-free profile fingerprint used in the deterministic plan ID.
    pub profile_fingerprint: String,
    /// CLI/MCP command identifier.
    pub command_id: String,
    /// Trace identifier; also used as the Snowflake `QUERY_TAG` when present.
    pub trace_id: String,
}

/// Planned query mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanMode {
    /// Dataset manifest mode.
    Dataset,
    /// Raw SQL mode, implemented by the future raw SQL safety checker.
    RawSql,
}

/// A typed positional SQL API binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedBinding {
    /// Snowflake SQL API binding type.
    #[serde(rename = "type")]
    pub binding_type: String,
    /// Wire value as a string.
    pub value: String,
}

/// Server-enforced guardrails attached to every plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanGuardrails {
    /// `STATEMENT_TIMEOUT_IN_SECONDS` value.
    pub statement_timeout_seconds: u32,
    /// Result row cap.
    pub result_row_cap: u64,
    /// Result byte cap retained locally before export.
    pub result_byte_cap: u64,
    /// Snowflake `QUERY_TAG`.
    pub query_tag: String,
}

/// Advisory planner warning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanWarning {
    /// Stable warning code.
    pub code: String,
    /// Redacted message.
    pub message: String,
}

/// Predicate and projection pushdown evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicatePushdownPlan {
    /// Number of projection columns pushed into the `SELECT` list.
    pub projected_columns: usize,
    /// Number of role-based axis filters pushed into `WHERE`.
    pub axis_filters: usize,
    /// Number of predicate AST leaves pushed into `WHERE`.
    pub predicate_filters: usize,
    /// True only when every validated predicate leaf was compiled into SQL.
    pub all_predicates_pushed_down: bool,
}

/// Dataset query plan output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryPlan {
    /// Deterministic normalized-plan hash.
    pub plan_id: String,
    /// Planning mode.
    pub mode: PlanMode,
    /// SQL text with placeholders only for values.
    pub sql: String,
    /// Positional typed bindings, keyed from 1.
    pub bindings: BTreeMap<String, TypedBinding>,
    /// Server-enforced guardrails.
    pub guardrails: PlanGuardrails,
    /// Predicate/projection pushdown evidence.
    pub pushdown: PredicatePushdownPlan,
    /// Advisory warnings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<PlanWarning>,
}

/// Planner refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanRefusal {
    /// Stable refusal code.
    pub code: String,
    /// Redacted message.
    pub message: String,
    /// Suggestions where safe.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub did_you_mean: Vec<String>,
}

/// Structured JSON-line log event emitted by planner callers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerLogLine {
    /// Schema version for planner log lines.
    pub schema_version: u16,
    /// Event name.
    pub event: String,
    /// `ok` or `refusal`.
    pub outcome: String,
    /// Planning mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<PlanMode>,
    /// Deterministic plan ID on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
    /// Stable refusal or warning code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Redacted diagnostic.
    pub message: String,
    /// CLI/MCP command identifier.
    pub command_id: String,
    /// End-to-end trace ID.
    pub trace_id: String,
    /// Redaction markers applied before logging.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redactions_applied: Vec<String>,
}

/// Build the success log line for a plan.
#[must_use]
pub fn plan_success_log_line(
    plan: &QueryPlan,
    command_id: impl Into<String>,
    trace_id: impl Into<String>,
) -> PlannerLogLine {
    PlannerLogLine {
        schema_version: PLANNER_LOG_SCHEMA_VERSION,
        event: "query_plan".to_owned(),
        outcome: "ok".to_owned(),
        mode: Some(plan.mode),
        plan_id: Some(plan.plan_id.clone()),
        code: None,
        message: "query plan accepted".to_owned(),
        command_id: command_id.into(),
        trace_id: trace_id.into(),
        redactions_applied: Vec::new(),
    }
}

/// Build the refusal log line for a planner refusal.
#[must_use]
pub fn plan_refusal_log_line(
    refusal: &PlanRefusal,
    mode: PlanMode,
    command_id: impl Into<String>,
    trace_id: impl Into<String>,
) -> PlannerLogLine {
    PlannerLogLine {
        schema_version: PLANNER_LOG_SCHEMA_VERSION,
        event: "query_plan".to_owned(),
        outcome: "refusal".to_owned(),
        mode: Some(mode),
        plan_id: None,
        code: Some(refusal.code.clone()),
        message: refusal.message.clone(),
        command_id: command_id.into(),
        trace_id: trace_id.into(),
        redactions_applied: Vec::new(),
    }
}

/// Plan a dataset-mode query.
pub fn plan_dataset_query(
    manifest: &DatasetManifest,
    columns: &[ColumnCatalogEntry],
    operators: &[OperatorCatalogEntry],
    request: &DatasetQueryRequest,
) -> Result<QueryPlan, Vec<PlanRefusal>> {
    let mut refusals = Vec::new();

    if manifest.id != request.dataset_id {
        return Err(vec![PlanRefusal {
            code: "FSNOW_DATASET_UNKNOWN".to_owned(),
            message: format!("unknown dataset {:?}", request.dataset_id),
            did_you_mean: vec![manifest.id.clone()],
        }]);
    }

    let dataset_columns = sorted_dataset_columns(&manifest.id, columns);
    let dataset_columns_owned = dataset_columns
        .iter()
        .map(|column| (*column).clone())
        .collect::<Vec<_>>();
    let projection = resolve_projection(manifest, &dataset_columns, request, &mut refusals);
    validate_axes(manifest, &dataset_columns, request, &mut refusals);

    if let Some(predicate) = &request.filter {
        if let Err(predicate_refusals) =
            validate_predicate(predicate, &dataset_columns_owned, operators)
        {
            refusals.extend(predicate_refusals.into_iter().map(PlanRefusal::from));
        }
    }

    let effective_limit = request.limit.unwrap_or(manifest.default_limit);
    enforce_interactive_row_policy(
        effective_limit,
        manifest.max_rows_without_export,
        request.export_mode,
        request.confirmation_token.as_deref(),
        &mut refusals,
    );

    if !refusals.is_empty() {
        return Err(refusals);
    }

    let mut bindings = BTreeMap::new();
    let mut next_binding = 1usize;
    let mut sql = String::new();
    sql.push_str("SELECT ");
    sql.push_str(
        &projection
            .iter()
            .map(|column| quote_identifier(&column.column))
            .collect::<Vec<_>>()
            .join(", "),
    );
    sql.push_str(" FROM ");
    sql.push_str(&quote_qualified_object(
        &manifest.database,
        &manifest.schema,
        &manifest.object,
    ));

    if let Some(as_of) = &request.as_of {
        sql.push_str(" AT(TIMESTAMP => ");
        sql.push_str(&time_travel_timestamp_literal(as_of));
        sql.push(')');
    }

    let mut where_clauses = Vec::new();
    let axis_filters = add_axis_filters(
        manifest,
        &dataset_columns,
        request,
        &mut bindings,
        &mut next_binding,
        &mut where_clauses,
    );
    let predicate_filters = request.filter.as_ref().map_or(0, count_predicate_leaves);
    let mut pushed_predicate_filters = 0usize;
    if let Some(predicate) = &request.filter {
        if let Some(compiled) = compile_predicate(
            predicate,
            &dataset_columns,
            &mut bindings,
            &mut next_binding,
        )
        .map_err(|refusal| vec![refusal])?
        {
            where_clauses.push(compiled.sql);
            pushed_predicate_filters = compiled.leaf_count;
        }
    }

    if !where_clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&where_clauses.join(" AND "));
    }

    sql.push_str(" LIMIT ");
    sql.push_str(&push_binding(
        &mut bindings,
        &mut next_binding,
        DtypeClass::Number,
        effective_limit.to_string(),
    ));

    let (guardrails, mut warnings) = planner_guardrails(
        &sql,
        effective_limit,
        request.export_mode,
        request.warehouse.clone(),
        query_tag(request),
    )
    .map_err(|refusal| vec![refusal])?;
    warnings.extend(warnings_for_request(request));
    let plan_id = plan_id(&sql, &bindings, &guardrails, manifest, request);

    Ok(QueryPlan {
        plan_id,
        mode: PlanMode::Dataset,
        sql,
        bindings,
        guardrails,
        pushdown: PredicatePushdownPlan {
            projected_columns: projection.len(),
            axis_filters,
            predicate_filters,
            all_predicates_pushed_down: pushed_predicate_filters == predicate_filters,
        },
        warnings,
    })
}

/// Plan a raw SQL dry-run. Raw mode accepts one conservative read-only `SELECT`
/// and never executes it; callers submit the returned plan through the same
/// receipt/guardrail path as dataset plans.
pub fn plan_raw_sql_dry_run(request: &RawSqlPlanRequest) -> Result<QueryPlan, Vec<PlanRefusal>> {
    let mut warnings = Vec::new();
    let mut sql = match normalize_raw_select(&request.sql) {
        Ok(sql) => sql,
        Err(refusal) => return Err(vec![refusal]),
    };

    let has_sql_limit = has_result_limit(&sql);
    let pushed_limit = if has_sql_limit {
        request.limit
    } else {
        request.limit.or_else(|| {
            if request.export_mode || request.confirmation_token.is_some() {
                None
            } else {
                warnings.push(PlanWarning {
                    code: "FSNOW_UNCONSTRAINED_QUERY_ADVISORY".to_owned(),
                    message: "raw SELECT had no LIMIT; planner pushed down the default row cap"
                        .to_owned(),
                });
                Some(DEFAULT_MAX_RESULT_ROWS)
            }
        })
    };

    let mut bindings = BTreeMap::new();
    let mut next_binding = 1usize;
    if !has_sql_limit {
        if let Some(limit) = pushed_limit {
            sql.push_str(" LIMIT ");
            sql.push_str(&push_binding(
                &mut bindings,
                &mut next_binding,
                DtypeClass::Number,
                limit.to_string(),
            ));
        }
    }

    let result_row_cap = pushed_limit.unwrap_or(DEFAULT_MAX_RESULT_ROWS);
    let (guardrails, mut guardrail_warnings) = planner_guardrails(
        &sql,
        result_row_cap,
        request.export_mode,
        request.warehouse.clone(),
        raw_query_tag(request),
    )
    .map_err(|refusal| vec![refusal])?;
    warnings.append(&mut guardrail_warnings);
    let plan_id = raw_plan_id(&sql, &bindings, &guardrails, request);

    Ok(QueryPlan {
        plan_id,
        mode: PlanMode::RawSql,
        sql,
        bindings,
        guardrails,
        pushdown: PredicatePushdownPlan {
            projected_columns: 0,
            axis_filters: 0,
            predicate_filters: 0,
            all_predicates_pushed_down: true,
        },
        warnings,
    })
}

fn enforce_interactive_row_policy(
    effective_limit: u64,
    manifest_max_rows_without_export: u64,
    export_mode: bool,
    confirmation_token: Option<&str>,
    refusals: &mut Vec<PlanRefusal>,
) {
    let interactive_cap = manifest_max_rows_without_export.min(DEFAULT_MAX_RESULT_ROWS);
    if !export_mode && confirmation_token.is_none() && effective_limit > interactive_cap {
        refusals.push(PlanRefusal {
            code: "FSNOW_RESULT_TOO_LARGE".to_owned(),
            message: format!(
                "limit {effective_limit} exceeds interactive row cap {interactive_cap}; use export mode, a narrower limit, or confirmation"
            ),
            did_you_mean: Vec::new(),
        });
    }
    if effective_limit > manifest_max_rows_without_export && !export_mode {
        refusals.push(PlanRefusal {
            code: "FSNOW_RESULT_TOO_LARGE".to_owned(),
            message: format!(
                "limit {effective_limit} exceeds max_rows_without_export {manifest_max_rows_without_export}"
            ),
            did_you_mean: Vec::new(),
        });
    }
}

fn planner_guardrails(
    sql: &str,
    result_row_cap: u64,
    export_mode: bool,
    warehouse: Option<String>,
    query_tag: String,
) -> Result<(PlanGuardrails, Vec<PlanWarning>), PlanRefusal> {
    let limits = QuerySafetyLimits {
        max_result_rows: result_row_cap,
        statement_timeout_seconds: DATASET_STATEMENT_TIMEOUT_SECONDS,
        require_warehouse: false,
        ..QuerySafetyLimits::default()
    };
    let mut guard = QueryPlanGuard::new(sql.to_owned());
    guard.statement_timeout_seconds = Some(DATASET_STATEMENT_TIMEOUT_SECONDS);
    guard.result_row_cap = Some(result_row_cap);
    guard.result_byte_cap = Some(DEFAULT_MAX_RESULT_BYTES);
    guard.warehouse = warehouse;
    guard.export_mode = export_mode;

    let bounded = enforce_query_safety(guard, &limits).map_err(plan_refusal_from_core_error)?;
    let warnings = bounded
        .warnings
        .into_iter()
        .map(|warning| PlanWarning {
            code: warning.code,
            message: warning.message,
        })
        .collect();

    Ok((
        PlanGuardrails {
            statement_timeout_seconds: bounded.statement_timeout_seconds,
            result_row_cap: bounded.result_row_cap,
            result_byte_cap: bounded.result_byte_cap,
            query_tag,
        },
        warnings,
    ))
}

fn plan_refusal_from_core_error(
    error: franken_snowflake_core::error::SnowflakeError,
) -> PlanRefusal {
    let code = match error.code {
        SnowflakeErrorCode::MutationRefused | SnowflakeErrorCode::MultiStatementRefused => {
            "FSNOW_RAW_SQL_UNSAFE"
        }
        SnowflakeErrorCode::RowCapExceeded | SnowflakeErrorCode::SafetyLimitExceeded => {
            "FSNOW_RESULT_TOO_LARGE"
        }
        SnowflakeErrorCode::WarehouseRefused => "FSNOW_WAREHOUSE_REFUSED",
        _ => "FSNOW_QUERY_GUARDRAIL",
    };
    PlanRefusal {
        code: code.to_owned(),
        message: error.message,
        did_you_mean: Vec::new(),
    }
}

fn normalize_raw_select(sql: &str) -> Result<String, PlanRefusal> {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return Err(raw_sql_refusal("raw SQL must be a single SELECT statement"));
    }
    let without_trailing_semicolon = trimmed.strip_suffix(';').unwrap_or(trimmed).trim_end();
    if has_statement_separator(without_trailing_semicolon) {
        return Err(raw_sql_refusal(
            "raw SQL dry-run accepts one statement; semicolon chaining is refused",
        ));
    }
    if first_keyword(without_trailing_semicolon).as_deref() != Some("select") {
        return Err(raw_sql_refusal("raw SQL dry-run accepts SELECT only"));
    }
    for keyword in [
        "alter", "call", "copy", "create", "delete", "drop", "grant", "insert", "merge", "put",
        "remove", "revoke", "truncate", "update", "use",
    ] {
        if contains_word(without_trailing_semicolon, keyword) {
            return Err(raw_sql_refusal(
                "raw SQL dry-run refused a mutating or session-changing keyword",
            ));
        }
    }
    Ok(without_trailing_semicolon.to_owned())
}

fn raw_sql_refusal(message: impl Into<String>) -> PlanRefusal {
    PlanRefusal {
        code: "FSNOW_RAW_SQL_UNSAFE".to_owned(),
        message: message.into(),
        did_you_mean: Vec::new(),
    }
}

fn sorted_dataset_columns<'a>(
    dataset_id: &str,
    columns: &'a [ColumnCatalogEntry],
) -> Vec<&'a ColumnCatalogEntry> {
    let mut dataset_columns = columns
        .iter()
        .filter(|column| column.dataset_id == dataset_id)
        .collect::<Vec<_>>();
    dataset_columns.sort_by_key(|column| column.ordinal);
    dataset_columns
}

fn resolve_projection<'a>(
    manifest: &DatasetManifest,
    columns: &[&'a ColumnCatalogEntry],
    request: &DatasetQueryRequest,
    refusals: &mut Vec<PlanRefusal>,
) -> Vec<&'a ColumnCatalogEntry> {
    if request.select.is_empty() {
        let mut projection = Vec::new();
        for field in &manifest.fields {
            if let Some(column) = find_column_in_refs(&field.column, columns) {
                projection.push(column);
            }
        }
        if projection.is_empty() {
            projection.extend(columns.iter().copied());
        }
        return projection;
    }

    let mut projection = Vec::new();
    for requested in &request.select {
        if let Some(column) = find_column_in_refs(requested, columns) {
            projection.push(column);
        } else {
            refusals.push(PlanRefusal {
                code: "FSNOW_COLUMN_UNKNOWN".to_owned(),
                message: format!("unknown projection column {requested:?}"),
                did_you_mean: crate::predicate::did_you_mean_columns(
                    requested,
                    &columns
                        .iter()
                        .map(|column| (*column).clone())
                        .collect::<Vec<_>>(),
                ),
            });
        }
    }
    projection
}

fn validate_axes(
    manifest: &DatasetManifest,
    columns: &[&ColumnCatalogEntry],
    request: &DatasetQueryRequest,
    refusals: &mut Vec<PlanRefusal>,
) {
    if request.entity.is_some() {
        validate_axis(
            manifest,
            columns,
            FieldRole::EntityKey,
            "entity_key",
            refusals,
        );
    }
    if request.from.is_some() || request.to.is_some() {
        validate_axis(
            manifest,
            columns,
            FieldRole::TimeIndex,
            "time_index",
            refusals,
        );
    }
    if request.as_of.is_some()
        && manifest.field_by_role(FieldRole::KnownAt).is_none()
        && manifest.field_by_role(FieldRole::TimeIndex).is_none()
    {
        refusals.push(PlanRefusal {
            code: "FSNOW_AS_OF_UNSUPPORTED".to_owned(),
            message: "as_of requires a known_at or time_index field".to_owned(),
            did_you_mean: Vec::new(),
        });
    }
}

fn validate_axis(
    manifest: &DatasetManifest,
    columns: &[&ColumnCatalogEntry],
    role: FieldRole,
    role_name: &str,
    refusals: &mut Vec<PlanRefusal>,
) {
    let Some(field) = manifest.field_by_role(role) else {
        refusals.push(PlanRefusal {
            code: "FSNOW_COLUMN_UNKNOWN".to_owned(),
            message: format!("dataset has no {role_name} field"),
            did_you_mean: Vec::new(),
        });
        return;
    };
    if find_column_in_refs(&field.column, columns).is_none() {
        refusals.push(PlanRefusal {
            code: "FSNOW_COLUMN_UNKNOWN".to_owned(),
            message: format!(
                "{role_name} field {:?} is absent from column catalog",
                field.column
            ),
            did_you_mean: Vec::new(),
        });
    }
}

fn add_axis_filters(
    manifest: &DatasetManifest,
    columns: &[&ColumnCatalogEntry],
    request: &DatasetQueryRequest,
    bindings: &mut BTreeMap<String, TypedBinding>,
    next_binding: &mut usize,
    where_clauses: &mut Vec<String>,
) -> usize {
    let mut pushed = 0usize;
    if let Some(entity) = &request.entity {
        if let Some(column) = axis_column(manifest, columns, FieldRole::EntityKey) {
            where_clauses.push(format!(
                "{} = {}",
                quote_identifier(&column.column),
                push_binding(bindings, next_binding, column.dtype_class, entity.clone())
            ));
            pushed += 1;
        }
    }
    if let Some(from) = &request.from {
        if let Some(column) = axis_column(manifest, columns, FieldRole::TimeIndex) {
            where_clauses.push(format!(
                "{} >= {}",
                quote_identifier(&column.column),
                push_binding(bindings, next_binding, column.dtype_class, from.clone())
            ));
            pushed += 1;
        }
    }
    if let Some(to) = &request.to {
        if let Some(column) = axis_column(manifest, columns, FieldRole::TimeIndex) {
            where_clauses.push(format!(
                "{} <= {}",
                quote_identifier(&column.column),
                push_binding(bindings, next_binding, column.dtype_class, to.clone())
            ));
            pushed += 1;
        }
    }
    pushed
}

fn axis_column<'a>(
    manifest: &DatasetManifest,
    columns: &[&'a ColumnCatalogEntry],
    role: FieldRole,
) -> Option<&'a ColumnCatalogEntry> {
    manifest
        .field_by_role(role)
        .and_then(|field| find_column_in_refs(&field.column, columns))
}

fn compile_predicate(
    predicate: &PredicateAst,
    columns: &[&ColumnCatalogEntry],
    bindings: &mut BTreeMap<String, TypedBinding>,
    next_binding: &mut usize,
) -> Result<Option<CompiledPredicate>, PlanRefusal> {
    match predicate {
        PredicateAst::Compound(compound) => {
            compile_compound(compound, columns, bindings, next_binding)
        }
        PredicateAst::Leaf(leaf) => compile_leaf(leaf, columns, bindings, next_binding).map(Some),
    }
}

struct CompiledPredicate {
    sql: String,
    leaf_count: usize,
}

fn count_predicate_leaves(predicate: &PredicateAst) -> usize {
    match predicate {
        PredicateAst::Leaf(_) => 1,
        PredicateAst::Compound(compound) => {
            compound
                .and
                .iter()
                .map(count_predicate_leaves)
                .sum::<usize>()
                + compound
                    .or
                    .iter()
                    .map(count_predicate_leaves)
                    .sum::<usize>()
                + compound.not.as_deref().map_or(0, count_predicate_leaves)
        }
    }
}

fn compile_compound(
    compound: &CompoundPredicate,
    columns: &[&ColumnCatalogEntry],
    bindings: &mut BTreeMap<String, TypedBinding>,
    next_binding: &mut usize,
) -> Result<Option<CompiledPredicate>, PlanRefusal> {
    let mut parts = Vec::new();
    let mut leaf_count = 0usize;
    let and = compile_many(" AND ", &compound.and, columns, bindings, next_binding)?;
    if let Some(compiled) = and {
        leaf_count += compiled.leaf_count;
        parts.push(compiled.sql);
    }
    let or = compile_many(" OR ", &compound.or, columns, bindings, next_binding)?;
    if let Some(compiled) = or {
        leaf_count += compiled.leaf_count;
        parts.push(compiled.sql);
    }
    if let Some(not) = &compound.not {
        if let Some(compiled) = compile_predicate(not, columns, bindings, next_binding)? {
            leaf_count += compiled.leaf_count;
            parts.push(format!("NOT ({})", compiled.sql));
        }
    }
    if parts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(CompiledPredicate {
            sql: parts.join(" AND "),
            leaf_count,
        }))
    }
}

fn compile_many(
    joiner: &str,
    predicates: &[PredicateAst],
    columns: &[&ColumnCatalogEntry],
    bindings: &mut BTreeMap<String, TypedBinding>,
    next_binding: &mut usize,
) -> Result<Option<CompiledPredicate>, PlanRefusal> {
    let mut compiled_sql = Vec::new();
    let mut leaf_count = 0usize;
    for predicate in predicates {
        if let Some(compiled) = compile_predicate(predicate, columns, bindings, next_binding)? {
            leaf_count += compiled.leaf_count;
            compiled_sql.push(compiled.sql);
        }
    }
    if compiled_sql.is_empty() {
        Ok(None)
    } else {
        Ok(Some(CompiledPredicate {
            sql: format!("({})", compiled_sql.join(joiner)),
            leaf_count,
        }))
    }
}

fn compile_leaf(
    leaf: &LeafPredicate,
    columns: &[&ColumnCatalogEntry],
    bindings: &mut BTreeMap<String, TypedBinding>,
    next_binding: &mut usize,
) -> Result<CompiledPredicate, PlanRefusal> {
    let Some(column) = find_column_in_refs(&leaf.column, columns) else {
        return Err(PlanRefusal {
            code: "FSNOW_COLUMN_UNKNOWN".to_owned(),
            message: format!("unknown predicate column {:?}", leaf.column),
            did_you_mean: crate::predicate::did_you_mean_columns(
                &leaf.column,
                &columns
                    .iter()
                    .map(|column| (*column).clone())
                    .collect::<Vec<_>>(),
            ),
        });
    };
    let identifier = quote_identifier(&column.column);
    let values = value_strings(&leaf.value);
    let mut bind = |value: String| push_binding(bindings, next_binding, column.dtype_class, value);

    let sql = match leaf.op.as_str() {
        "eq" => Some(format!("{identifier} = {}", bind(first_value(&values)))),
        "neq" => Some(format!("{identifier} != {}", bind(first_value(&values)))),
        "lt" => Some(format!("{identifier} < {}", bind(first_value(&values)))),
        "lte" => Some(format!("{identifier} <= {}", bind(first_value(&values)))),
        "gt" => Some(format!("{identifier} > {}", bind(first_value(&values)))),
        "gte" => Some(format!("{identifier} >= {}", bind(first_value(&values)))),
        "between" => {
            let left = bind(value_at(&values, 0));
            let right = bind(value_at(&values, 1));
            Some(format!("{identifier} BETWEEN {left} AND {right}"))
        }
        "in" => {
            let placeholders = values.into_iter().map(&mut bind).collect::<Vec<_>>();
            Some(format!("{identifier} IN ({})", placeholders.join(", ")))
        }
        "is_null" => Some(format!("{identifier} IS NULL")),
        "is_not_null" => Some(format!("{identifier} IS NOT NULL")),
        "contains" => Some(format!(
            "POSITION({} IN {identifier}) > 0",
            bind(first_value(&values))
        )),
        _ => None,
    };
    sql.map(|sql| CompiledPredicate { sql, leaf_count: 1 })
        .ok_or_else(|| PlanRefusal {
            code: "FSNOW_FILTER_OPERATOR_UNSUPPORTED".to_owned(),
            message: format!(
                "operator {:?} is present in the catalog but unsupported by the SQL compiler",
                leaf.op
            ),
            did_you_mean: Vec::new(),
        })
}

fn first_value(values: &[String]) -> String {
    value_at(values, 0)
}

fn value_at(values: &[String], index: usize) -> String {
    values.get(index).cloned().unwrap_or_default()
}

fn value_strings(value: &Option<Value>) -> Vec<String> {
    match value {
        None => Vec::new(),
        Some(Value::Array(values)) => values.iter().map(value_to_string).collect(),
        Some(value) => vec![value_to_string(value)],
    }
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

fn time_travel_timestamp_literal(value: &str) -> String {
    format!("'{}'::TIMESTAMP_TZ", escape_snowflake_literal(value))
}

fn escape_snowflake_literal(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '\'' => escaped.push_str("''"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn find_column_in_refs<'a>(
    column: &str,
    columns: &[&'a ColumnCatalogEntry],
) -> Option<&'a ColumnCatalogEntry> {
    let normalized = normalize_identifier(column);
    columns
        .iter()
        .copied()
        .find(|candidate| normalize_identifier(&candidate.column) == normalized)
}

fn push_binding(
    bindings: &mut BTreeMap<String, TypedBinding>,
    next_binding: &mut usize,
    dtype: DtypeClass,
    value: String,
) -> String {
    let key = next_binding.to_string();
    bindings.insert(
        key,
        TypedBinding {
            binding_type: dtype.default_binding_type().to_owned(),
            value,
        },
    );
    *next_binding += 1;
    "?".to_owned()
}

/// Quote one Snowflake identifier part. Embedded quotes are doubled.
#[must_use]
pub fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

/// Quote a three-part Snowflake object.
#[must_use]
pub fn quote_qualified_object(database: &str, schema: &str, object: &str) -> String {
    [
        quote_identifier(database),
        quote_identifier(schema),
        quote_identifier(object),
    ]
    .join(".")
}

fn query_tag(request: &DatasetQueryRequest) -> String {
    if !request.trace_id.is_empty() {
        request.trace_id.clone()
    } else if !request.command_id.is_empty() {
        request.command_id.clone()
    } else {
        "franken-snowflake.query-plan".to_owned()
    }
}

fn raw_query_tag(request: &RawSqlPlanRequest) -> String {
    if !request.trace_id.is_empty() {
        request.trace_id.clone()
    } else if !request.command_id.is_empty() {
        request.command_id.clone()
    } else {
        "franken-snowflake.raw-query-plan".to_owned()
    }
}

fn warnings_for_request(request: &DatasetQueryRequest) -> Vec<PlanWarning> {
    if request.limit.is_some() {
        Vec::new()
    } else {
        vec![PlanWarning {
            code: "FSNOW_UNCONSTRAINED_QUERY_ADVISORY".to_owned(),
            message: "no explicit limit supplied; manifest default_limit was applied".to_owned(),
        }]
    }
}

fn has_result_limit(sql: &str) -> bool {
    contains_word(sql, "limit") || contains_word(sql, "fetch")
}

fn first_keyword(sql: &str) -> Option<String> {
    executable_sql_tokens(sql).words.into_iter().next()
}

fn contains_word(sql: &str, needle: &str) -> bool {
    executable_sql_tokens(sql)
        .words
        .into_iter()
        .any(|part| part == needle)
}

fn has_statement_separator(sql: &str) -> bool {
    executable_sql_tokens(sql).has_semicolon
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ExecutableSqlTokens {
    words: Vec<String>,
    has_semicolon: bool,
}

fn executable_sql_tokens(sql: &str) -> ExecutableSqlTokens {
    let mut tokens = ExecutableSqlTokens::default();
    let mut word = String::new();
    let mut chars = sql.chars().peekable();
    let mut state = SqlScanState::Normal;

    while let Some(ch) = chars.next() {
        match state {
            SqlScanState::Normal => match ch {
                '-' if chars.peek() == Some(&'-') => {
                    chars.next();
                    flush_word(&mut word, &mut tokens.words);
                    state = SqlScanState::LineComment;
                }
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    flush_word(&mut word, &mut tokens.words);
                    state = SqlScanState::BlockComment;
                }
                '\'' => {
                    flush_word(&mut word, &mut tokens.words);
                    state = SqlScanState::SingleQuoted;
                }
                '"' => {
                    flush_word(&mut word, &mut tokens.words);
                    state = SqlScanState::DoubleQuoted;
                }
                ';' => {
                    flush_word(&mut word, &mut tokens.words);
                    tokens.has_semicolon = true;
                }
                _ if ch.is_ascii_alphanumeric() || ch == '_' => {
                    word.push(ch.to_ascii_lowercase());
                }
                _ => flush_word(&mut word, &mut tokens.words),
            },
            SqlScanState::SingleQuoted => match ch {
                '\\' => {
                    chars.next();
                }
                '\'' if chars.peek() == Some(&'\'') => {
                    chars.next();
                }
                '\'' => state = SqlScanState::Normal,
                _ => {}
            },
            SqlScanState::DoubleQuoted => match ch {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                }
                '"' => state = SqlScanState::Normal,
                _ => {}
            },
            SqlScanState::LineComment => {
                if matches!(ch, '\n' | '\r') {
                    state = SqlScanState::Normal;
                }
            }
            SqlScanState::BlockComment => {
                if ch == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    state = SqlScanState::Normal;
                }
            }
        }
    }

    flush_word(&mut word, &mut tokens.words);
    tokens
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SqlScanState {
    Normal,
    SingleQuoted,
    DoubleQuoted,
    LineComment,
    BlockComment,
}

fn flush_word(word: &mut String, words: &mut Vec<String>) {
    if !word.is_empty() {
        words.push(std::mem::take(word));
    }
}

fn plan_id(
    sql: &str,
    bindings: &BTreeMap<String, TypedBinding>,
    guardrails: &PlanGuardrails,
    manifest: &DatasetManifest,
    request: &DatasetQueryRequest,
) -> String {
    let mut normalized = String::new();
    normalized.push_str(sql);
    normalized.push('|');
    normalized.push_str(&request.profile_fingerprint);
    normalized.push('|');
    normalized.push_str(&manifest.id);
    normalized.push('|');
    normalized.push_str(&request.from.clone().unwrap_or_default());
    normalized.push('|');
    normalized.push_str(&request.to.clone().unwrap_or_default());
    normalized.push('|');
    normalized.push_str(&request.as_of.clone().unwrap_or_default());
    normalized.push('|');
    normalized.push_str(&guardrails.statement_timeout_seconds.to_string());
    normalized.push('|');
    normalized.push_str(&guardrails.result_row_cap.to_string());
    normalized.push('|');
    normalized.push_str(&guardrails.result_byte_cap.to_string());
    normalized.push('|');
    normalized.push_str(&guardrails.query_tag);
    for (position, binding) in bindings {
        normalized.push('|');
        normalized.push_str(position);
        normalized.push(':');
        normalized.push_str(&binding.binding_type);
        normalized.push('=');
        normalized.push_str(&binding.value);
    }
    format!("plan:{:016x}", fnv1a64(normalized.as_bytes()))
}

fn raw_plan_id(
    sql: &str,
    bindings: &BTreeMap<String, TypedBinding>,
    guardrails: &PlanGuardrails,
    request: &RawSqlPlanRequest,
) -> String {
    let mut normalized = String::new();
    normalized.push_str(sql);
    normalized.push('|');
    normalized.push_str(&request.profile_fingerprint);
    normalized.push_str("|raw|");
    normalized.push_str(&guardrails.statement_timeout_seconds.to_string());
    normalized.push('|');
    normalized.push_str(&guardrails.result_row_cap.to_string());
    normalized.push('|');
    normalized.push_str(&guardrails.result_byte_cap.to_string());
    normalized.push('|');
    normalized.push_str(&guardrails.query_tag);
    for (position, binding) in bindings {
        normalized.push('|');
        normalized.push_str(position);
        normalized.push(':');
        normalized.push_str(&binding.binding_type);
        normalized.push('=');
        normalized.push_str(&binding.value);
    }
    format!("plan:{:016x}", fnv1a64(normalized.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

impl From<PredicateRefusal> for PlanRefusal {
    fn from(value: PredicateRefusal) -> Self {
        let code = match value.code {
            PredicateRefusalCode::ColumnUnknown => "FSNOW_COLUMN_UNKNOWN",
            PredicateRefusalCode::OperatorUnknown => "FSNOW_OPERATOR_UNKNOWN",
            PredicateRefusalCode::FilterOperatorDtype => "FSNOW_FILTER_OPERATOR_DTYPE",
            PredicateRefusalCode::FilterArity => "FSNOW_FILTER_ARITY",
        };
        Self {
            code: code.to_owned(),
            message: value.message,
            did_you_mean: value.did_you_mean,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::model::{
        DataSourceClass, DatasetField, DatasetKind, Provenance, ProvenanceSource, RightsClass,
        RoleConfidence,
    };
    use crate::operator::{OperatorArity, OutputDtypeRule, built_in_operator_catalog};

    #[test]
    fn dataset_plan_pushes_safe_predicates_with_typed_bindings() {
        let request = DatasetQueryRequest {
            dataset_id: "events_daily".to_owned(),
            select: vec![
                "EVENT_DATE".to_owned(),
                "ENTITY_ID".to_owned(),
                "VALUE".to_owned(),
            ],
            entity: Some("ENTITY'; DROP TABLE X; --".to_owned()),
            from: Some("2024-01-01".to_owned()),
            to: Some("2024-12-31".to_owned()),
            as_of: Some("2024-12-31T23:59:59Z".to_owned()),
            filter: Some(PredicateAst::Leaf(LeafPredicate::new(
                "VALUE",
                "gt",
                json!("0 OR 1=1"),
            ))),
            limit: Some(1_000),
            export_mode: false,
            confirmation_token: None,
            warehouse: None,
            profile_fingerprint: "profile:fixture".to_owned(),
            command_id: "query.plan".to_owned(),
            trace_id: "trace-abc".to_owned(),
        };

        let plan = plan_dataset_query(
            &fixture_manifest("events_daily"),
            &fixture_columns("events_daily"),
            &built_in_operator_catalog(),
            &request,
        );

        assert!(plan.is_ok());
        if let Ok(plan) = plan {
            assert_eq!(
                plan.sql,
                "SELECT \"EVENT_DATE\", \"ENTITY_ID\", \"VALUE\" FROM \"ANALYTICS\".\"PUBLIC\".\"EVENTS_DAILY\" AT(TIMESTAMP => '2024-12-31T23:59:59Z'::TIMESTAMP_TZ) WHERE \"ENTITY_ID\" = ? AND \"EVENT_DATE\" >= ? AND \"EVENT_DATE\" <= ? AND \"VALUE\" > ? LIMIT ?"
            );
            assert!(!plan.sql.contains("DROP TABLE"));
            assert!(!plan.sql.contains("0 OR 1=1"));
            assert_eq!(
                plan.bindings.get("1").map(|binding| binding.value.as_str()),
                Some("ENTITY'; DROP TABLE X; --")
            );
            assert_eq!(
                plan.bindings.get("4").map(|binding| binding.value.as_str()),
                Some("0 OR 1=1")
            );
            assert_eq!(
                plan.bindings
                    .get("4")
                    .map(|binding| binding.binding_type.as_str()),
                Some("FIXED")
            );
            assert_eq!(plan.guardrails.query_tag, "trace-abc");
            assert_eq!(plan.guardrails.statement_timeout_seconds, 60);
            assert_eq!(plan.guardrails.result_row_cap, 1_000);
            assert_eq!(plan.pushdown.predicate_filters, 1);
            assert!(plan.pushdown.all_predicates_pushed_down);
        }
    }

    #[test]
    fn time_travel_timestamp_literal_escapes_backslash_and_quote() {
        // Snowflake AT | BEFORE docs consulted 2026-06-25:
        // https://docs.snowflake.com/en/sql-reference/constructs/at-before
        // TIMESTAMP must be a constant expression, so as_of is a cast literal,
        // not a SQL API bind placeholder.
        assert_eq!(
            time_travel_timestamp_literal("2024-12-31T23:59:59Z\\' OR 1=1 --"),
            "'2024-12-31T23:59:59Z\\\\'' OR 1=1 --'::TIMESTAMP_TZ"
        );
    }

    #[test]
    fn identifier_quoting_contains_identifier_injection() {
        let mut manifest = fixture_manifest("events_daily");
        manifest.database = "ANA\"LYTICS".to_owned();
        manifest.object = "EVENTS\"; DROP TABLE X; --".to_owned();
        let mut columns = fixture_columns("events_daily");
        for column in &mut columns {
            column.database.clone_from(&manifest.database);
            column.object.clone_from(&manifest.object);
        }
        let request = base_dataset_request(Some(10));

        let plan = plan_dataset_query(&manifest, &columns, &built_in_operator_catalog(), &request);

        assert!(plan.is_ok());
        if let Ok(plan) = plan {
            assert!(
                plan.sql
                    .contains("FROM \"ANA\"\"LYTICS\".\"PUBLIC\".\"EVENTS\"\"; DROP TABLE X; --\"")
            );
            assert!(plan.sql.ends_with(" LIMIT ?"));
            assert_eq!(
                plan.bindings.get("1").map(|binding| binding.value.as_str()),
                Some("10")
            );
        }
    }

    #[test]
    fn large_interactive_dataset_plan_requires_export_or_confirmation() {
        let mut request = base_dataset_request(Some(DEFAULT_MAX_RESULT_ROWS + 1));
        request.confirmation_token = None;
        request.export_mode = false;

        let refused = plan_dataset_query(
            &fixture_manifest("events_daily"),
            &fixture_columns("events_daily"),
            &built_in_operator_catalog(),
            &request,
        );
        assert!(matches!(
            refused,
            Err(refusals) if refusals.iter().any(|refusal| refusal.code == "FSNOW_RESULT_TOO_LARGE")
        ));

        request.confirmation_token = Some("confirm-large-result".to_owned());
        assert!(
            plan_dataset_query(
                &fixture_manifest("events_daily"),
                &fixture_columns("events_daily"),
                &built_in_operator_catalog(),
                &request,
            )
            .is_ok()
        );
    }

    #[test]
    fn unsupported_catalog_operator_is_refused_not_silently_dropped() {
        let mut operators = built_in_operator_catalog();
        operators.push(OperatorCatalogEntry {
            id: "adapter_only_numeric".to_owned(),
            arity: OperatorArity::Exact { count: 1 },
            accepted_dtype_classes: vec![DtypeClass::Number],
            output_dtype_rule: OutputDtypeRule::Boolean,
            refusal_code: "FSNOW_FILTER_OPERATOR_DTYPE".to_owned(),
            json_schema_contract_id: "franken_snowflake.operator.adapter_only_numeric.v1"
                .to_owned(),
        });
        let mut request = base_dataset_request(Some(100));
        request.filter = Some(PredicateAst::Compound(CompoundPredicate {
            and: vec![
                PredicateAst::Leaf(LeafPredicate::new("VALUE", "gt", json!(0))),
                PredicateAst::Leaf(LeafPredicate::new(
                    "VALUE",
                    "adapter_only_numeric",
                    json!(42),
                )),
            ],
            ..CompoundPredicate::default()
        }));

        let refused = plan_dataset_query(
            &fixture_manifest("events_daily"),
            &fixture_columns("events_daily"),
            &operators,
            &request,
        );

        assert!(matches!(
            refused,
            Err(refusals)
                if refusals.iter().any(|refusal| refusal.code == "FSNOW_FILTER_OPERATOR_UNSUPPORTED")
        ));
    }

    #[test]
    fn raw_sql_dry_run_refuses_mutation_and_statement_chaining() {
        let mut request = base_raw_request("delete from events_daily");
        let mutation = plan_raw_sql_dry_run(&request);
        assert!(matches!(
            mutation,
            Err(refusals) if refusals[0].code == "FSNOW_RAW_SQL_UNSAFE"
        ));

        request.sql = "select * from events_daily; drop table events_daily".to_owned();
        let chained = plan_raw_sql_dry_run(&request);
        assert!(matches!(
            chained,
            Err(refusals) if refusals[0].code == "FSNOW_RAW_SQL_UNSAFE"
        ));
    }

    #[test]
    fn raw_sql_dry_run_ignores_denylisted_words_inside_literals() {
        let request =
            base_raw_request("select * from events_daily where action = 'delete; drop table x'");

        let plan = plan_raw_sql_dry_run(&request);

        assert!(plan.is_ok());
        if let Ok(plan) = plan {
            assert_eq!(
                plan.sql,
                "select * from events_daily where action = 'delete; drop table x' LIMIT ?"
            );
            assert_eq!(
                plan.bindings.get("1").map(|binding| binding.value.as_str()),
                Some("10000")
            );
        }
    }

    #[test]
    fn raw_sql_dry_run_ignores_denylisted_words_inside_quoted_identifiers() {
        let request = base_raw_request("select \"delete\" from events_daily limit 1");

        let plan = plan_raw_sql_dry_run(&request);

        assert!(plan.is_ok());
        if let Ok(plan) = plan {
            assert_eq!(plan.sql, "select \"delete\" from events_daily limit 1");
            assert!(plan.bindings.is_empty());
        }
    }

    #[test]
    fn raw_sql_dry_run_pushes_default_limit_and_warns() {
        let request = base_raw_request("select * from events_daily");

        let plan = plan_raw_sql_dry_run(&request);

        assert!(plan.is_ok());
        if let Ok(plan) = plan {
            assert_eq!(plan.mode, PlanMode::RawSql);
            assert_eq!(plan.sql, "select * from events_daily LIMIT ?");
            assert_eq!(
                plan.bindings.get("1").map(|binding| binding.value.as_str()),
                Some("10000")
            );
            assert_eq!(plan.guardrails.query_tag, "trace-raw");
            assert!(
                plan.warnings
                    .iter()
                    .any(|warning| warning.code == "FSNOW_UNCONSTRAINED_QUERY_ADVISORY")
            );
        }
    }

    #[test]
    fn plan_ids_and_structured_logs_are_deterministic() -> Result<(), serde_json::Error> {
        let request = base_dataset_request(Some(100));
        let left = plan_dataset_query(
            &fixture_manifest("events_daily"),
            &fixture_columns("events_daily"),
            &built_in_operator_catalog(),
            &request,
        );
        let right = plan_dataset_query(
            &fixture_manifest("events_daily"),
            &fixture_columns("events_daily"),
            &built_in_operator_catalog(),
            &request,
        );

        assert!(left.is_ok());
        assert!(right.is_ok());
        if let (Ok(left), Ok(right)) = (left, right) {
            assert_eq!(left.plan_id, right.plan_id);
            let log = plan_success_log_line(&left, &request.command_id, &request.trace_id);
            let line = serde_json::to_string(&log)?;
            assert!(line.contains("\"event\":\"query_plan\""));
            assert!(line.contains("\"outcome\":\"ok\""));
            assert!(line.contains("\"plan_id\""));
        }
        Ok(())
    }

    fn base_dataset_request(limit: Option<u64>) -> DatasetQueryRequest {
        DatasetQueryRequest {
            dataset_id: "events_daily".to_owned(),
            select: Vec::new(),
            entity: None,
            from: None,
            to: None,
            as_of: None,
            filter: None,
            limit,
            export_mode: false,
            confirmation_token: None,
            warehouse: None,
            profile_fingerprint: "profile:fixture".to_owned(),
            command_id: "query.plan".to_owned(),
            trace_id: "trace-dataset".to_owned(),
        }
    }

    fn base_raw_request(sql: &str) -> RawSqlPlanRequest {
        RawSqlPlanRequest {
            sql: sql.to_owned(),
            limit: None,
            export_mode: false,
            confirmation_token: None,
            warehouse: None,
            profile_fingerprint: "profile:fixture".to_owned(),
            command_id: "query.plan".to_owned(),
            trace_id: "trace-raw".to_owned(),
        }
    }

    fn fixture_manifest(dataset_id: &str) -> DatasetManifest {
        DatasetManifest {
            id: dataset_id.to_owned(),
            profile: "demo".to_owned(),
            database: "ANALYTICS".to_owned(),
            schema: "PUBLIC".to_owned(),
            object: "EVENTS_DAILY".to_owned(),
            kind: DatasetKind::Table,
            rights_class: RightsClass::Private,
            default_limit: 1_000,
            max_rows_without_export: 50_000,
            description: None,
            provenance: fixture_provenance(),
            fields: vec![
                field("ENTITY_ID", FieldRole::EntityKey, DtypeClass::String),
                field("EVENT_DATE", FieldRole::TimeIndex, DtypeClass::Date),
                field("VALUE", FieldRole::Feature, DtypeClass::Number),
            ],
        }
    }

    fn field(column: &str, role: FieldRole, dtype: DtypeClass) -> DatasetField {
        DatasetField {
            column: column.to_owned(),
            role,
            dtype,
            required: matches!(role, FieldRole::EntityKey | FieldRole::TimeIndex),
            role_confidence: RoleConfidence::Confirmed,
        }
    }

    fn fixture_columns(dataset_id: &str) -> Vec<ColumnCatalogEntry> {
        vec![
            column(dataset_id, "ENTITY_ID", 1, "TEXT", DtypeClass::String),
            column(dataset_id, "EVENT_DATE", 2, "DATE", DtypeClass::Date),
            column(dataset_id, "VALUE", 3, "NUMBER", DtypeClass::Number),
        ]
    }

    fn column(
        dataset_id: &str,
        column: &str,
        ordinal: u32,
        snowflake_type: &str,
        dtype_class: DtypeClass,
    ) -> ColumnCatalogEntry {
        ColumnCatalogEntry {
            dataset_id: dataset_id.to_owned(),
            database: "ANALYTICS".to_owned(),
            schema: "PUBLIC".to_owned(),
            object: "EVENTS_DAILY".to_owned(),
            column: column.to_owned(),
            ordinal,
            snowflake_type: snowflake_type.to_owned(),
            dtype_class,
            nullable: false,
            precision: None,
            scale: None,
            length: None,
            aliases: Vec::new(),
            comment: None,
            tags: Vec::new(),
            provenance: Some(fixture_provenance()),
        }
    }

    fn fixture_provenance() -> Provenance {
        Provenance {
            source: ProvenanceSource::Fixture,
            data_source: DataSourceClass::Fixture,
            snapshot_id: "snapshot-fixture".to_owned(),
            discovered_at: "2026-06-25T00:00:00Z".to_owned(),
            profile_fingerprint: "profile:fixture".to_owned(),
            object_fingerprint: "snowflake-object:ANALYTICS.PUBLIC.EVENTS_DAILY".to_owned(),
            command_id: "catalog.fixture".to_owned(),
            trace_id: "trace-fixture".to_owned(),
            redactions_applied: Vec::new(),
        }
    }
}
