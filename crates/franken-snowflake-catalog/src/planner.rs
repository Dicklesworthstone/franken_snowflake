//! Dataset-mode query planner.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::model::{
    normalize_identifier, ColumnCatalogEntry, DatasetManifest, DtypeClass, FieldRole,
};
use crate::operator::OperatorCatalogEntry;
use crate::predicate::{
    validate_predicate, CompoundPredicate, LeafPredicate, PredicateAst, PredicateRefusal,
    PredicateRefusalCode,
};

/// Dataset-mode planner request.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
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
    /// Secret-free profile fingerprint used in the deterministic plan ID.
    pub profile_fingerprint: String,
    /// CLI/MCP command identifier.
    pub command_id: String,
    /// Trace identifier; also used as the Snowflake `QUERY_TAG` when present.
    pub trace_id: String,
}

/// Planned query mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanMode {
    /// Dataset manifest mode.
    Dataset,
    /// Raw SQL mode, implemented by the future raw SQL safety checker.
    RawSql,
}

/// A typed positional SQL API binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TypedBinding {
    /// Snowflake SQL API binding type.
    #[serde(rename = "type")]
    pub binding_type: String,
    /// Wire value as a string.
    pub value: String,
}

/// Server-enforced guardrails attached to every plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanGuardrails {
    /// `STATEMENT_TIMEOUT_IN_SECONDS` value.
    pub statement_timeout_seconds: u32,
    /// Result row cap.
    pub result_row_cap: u64,
    /// Snowflake `QUERY_TAG`.
    pub query_tag: String,
}

/// Advisory planner warning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanWarning {
    /// Stable warning code.
    pub code: String,
    /// Redacted message.
    pub message: String,
}

/// Dataset query plan output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
    /// Advisory warnings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<PlanWarning>,
}

/// Planner refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanRefusal {
    /// Stable refusal code.
    pub code: String,
    /// Redacted message.
    pub message: String,
    /// Suggestions where safe.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub did_you_mean: Vec<String>,
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
    if !request.export_mode
        && request.confirmation_token.is_none()
        && effective_limit > manifest.max_rows_without_export
    {
        refusals.push(PlanRefusal {
            code: "FSNOW_RESULT_TOO_LARGE".to_owned(),
            message: format!(
                "limit {effective_limit} exceeds max_rows_without_export {}",
                manifest.max_rows_without_export
            ),
            did_you_mean: Vec::new(),
        });
    }

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
        sql.push_str(&push_binding(
            &mut bindings,
            &mut next_binding,
            DtypeClass::Timestamp,
            as_of.clone(),
        ));
        sql.push(')');
    }

    let mut where_clauses = Vec::new();
    add_axis_filters(
        manifest,
        &dataset_columns,
        request,
        &mut bindings,
        &mut next_binding,
        &mut where_clauses,
    );
    if let Some(predicate) = &request.filter {
        if let Some(compiled) = compile_predicate(
            predicate,
            &dataset_columns,
            &mut bindings,
            &mut next_binding,
        ) {
            where_clauses.push(compiled);
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

    let guardrails = PlanGuardrails {
        statement_timeout_seconds: 60,
        result_row_cap: effective_limit,
        query_tag: query_tag(request),
    };
    let warnings = warnings_for_request(request);
    let plan_id = plan_id(&sql, &bindings, &guardrails, manifest, request);

    Ok(QueryPlan {
        plan_id,
        mode: PlanMode::Dataset,
        sql,
        bindings,
        guardrails,
        warnings,
    })
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
) {
    if let Some(entity) = &request.entity {
        if let Some(column) = axis_column(manifest, columns, FieldRole::EntityKey) {
            where_clauses.push(format!(
                "{} = {}",
                quote_identifier(&column.column),
                push_binding(bindings, next_binding, column.dtype_class, entity.clone())
            ));
        }
    }
    if let Some(from) = &request.from {
        if let Some(column) = axis_column(manifest, columns, FieldRole::TimeIndex) {
            where_clauses.push(format!(
                "{} >= {}",
                quote_identifier(&column.column),
                push_binding(bindings, next_binding, column.dtype_class, from.clone())
            ));
        }
    }
    if let Some(to) = &request.to {
        if let Some(column) = axis_column(manifest, columns, FieldRole::TimeIndex) {
            where_clauses.push(format!(
                "{} <= {}",
                quote_identifier(&column.column),
                push_binding(bindings, next_binding, column.dtype_class, to.clone())
            ));
        }
    }
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
) -> Option<String> {
    match predicate {
        PredicateAst::Compound(compound) => {
            compile_compound(compound, columns, bindings, next_binding)
        }
        PredicateAst::Leaf(leaf) => compile_leaf(leaf, columns, bindings, next_binding),
    }
}

fn compile_compound(
    compound: &CompoundPredicate,
    columns: &[&ColumnCatalogEntry],
    bindings: &mut BTreeMap<String, TypedBinding>,
    next_binding: &mut usize,
) -> Option<String> {
    let mut parts = Vec::new();
    let and = compile_many(" AND ", &compound.and, columns, bindings, next_binding);
    if let Some(compiled) = and {
        parts.push(compiled);
    }
    let or = compile_many(" OR ", &compound.or, columns, bindings, next_binding);
    if let Some(compiled) = or {
        parts.push(compiled);
    }
    if let Some(not) = &compound.not {
        if let Some(compiled) = compile_predicate(not, columns, bindings, next_binding) {
            parts.push(format!("NOT ({compiled})"));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" AND "))
    }
}

fn compile_many(
    joiner: &str,
    predicates: &[PredicateAst],
    columns: &[&ColumnCatalogEntry],
    bindings: &mut BTreeMap<String, TypedBinding>,
    next_binding: &mut usize,
) -> Option<String> {
    let compiled = predicates
        .iter()
        .filter_map(|predicate| compile_predicate(predicate, columns, bindings, next_binding))
        .collect::<Vec<_>>();
    if compiled.is_empty() {
        None
    } else {
        Some(format!("({})", compiled.join(joiner)))
    }
}

fn compile_leaf(
    leaf: &LeafPredicate,
    columns: &[&ColumnCatalogEntry],
    bindings: &mut BTreeMap<String, TypedBinding>,
    next_binding: &mut usize,
) -> Option<String> {
    let column = find_column_in_refs(&leaf.column, columns)?;
    let identifier = quote_identifier(&column.column);
    let values = value_strings(&leaf.value);
    let mut bind = |value: String| push_binding(bindings, next_binding, column.dtype_class, value);

    match leaf.op.as_str() {
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
    }
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
