//! Dataset-mode queries: `query plan|run --dataset <id> [--entity] [--from]
//! [--to] [--as-of] [--select a,b] [--filter <predicate-json>] [--limit N]`.
//!
//! The catalog crate's planner compiles a named dataset plus axis hints into
//! pushed-down SQL with positional typed bindings (never interpolated values),
//! a Time Travel `AT(TIMESTAMP => ...)` clause for `--as-of`, an enforced row
//! limit, and server-side guardrails. This module resolves the dataset from the
//! local store (populated by `catalog scan`), runs the planner, and shapes the
//! plan for the envelope; the live module executes it with the same bindings.

use franken_snowflake_catalog::planner::{
    DatasetQueryRequest, PlanRefusal, QueryPlan, plan_dataset_query,
};
use franken_snowflake_catalog::predicate::PredicateAst;
use franken_snowflake_core::error::SnowflakeErrorCode;
use franken_snowflake_core::exit::ExitCode as CoreExitCode;

use crate::catalog_surface::{DATA_SOURCE_CACHE, StoredDataset, load_dataset};
use crate::local_store;
use crate::{
    Body, Json, Outcome, OutputFormat, base_envelope, error_info, json_array, json_object,
    json_object_owned, json_string, option_json,
};

/// Parsed dataset-mode flags.
#[derive(Clone, Debug, Default)]
pub struct DatasetQuerySpec {
    pub dataset_id: String,
    /// `--profile`; defaults to the profile the dataset was scanned under.
    pub profile: Option<String>,
    pub entity: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub as_of: Option<String>,
    pub select: Vec<String>,
    /// Predicate AST as JSON (`{"column":..,"op":..,"value":..}` or `{"and":[..]}`).
    pub filter: Option<String>,
    pub limit: Option<String>,
}

/// A compiled dataset plan plus the store artifacts it came from.
pub struct PlannedDataset {
    pub plan: QueryPlan,
    pub dataset: StoredDataset,
    /// The profile the query will run under.
    pub profile: String,
}

/// Map a planner refusal code to the CLI's stable error code.
fn refusal_error_code(code: &str) -> SnowflakeErrorCode {
    match code {
        "FSNOW_RESULT_TOO_LARGE" => SnowflakeErrorCode::RowCapExceeded,
        "FSNOW_QUERY_GUARDRAIL" => SnowflakeErrorCode::SafetyLimitExceeded,
        "FSNOW_WAREHOUSE_REFUSED" => SnowflakeErrorCode::WarehouseRefused,
        _ => SnowflakeErrorCode::UsageError,
    }
}

fn refusals_outcome(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    profile: String,
    dataset_id: &str,
    refusals: Vec<PlanRefusal>,
) -> Outcome {
    let first = refusals.first();
    let code = first.map_or(SnowflakeErrorCode::UsageError, |refusal| {
        refusal_error_code(&refusal.code)
    });
    let message = refusals
        .iter()
        .map(|refusal| format!("{}: {}", refusal.code, refusal.message))
        .collect::<Vec<_>>()
        .join("; ");
    let did_you_mean = first
        .map(|refusal| refusal.did_you_mean.clone())
        .unwrap_or_default();
    let mut envelope = base_envelope(
        false,
        if matches!(code, SnowflakeErrorCode::UsageError) {
            "error"
        } else {
            "refusal"
        },
        command_id,
        output_contract_id,
        request_id,
        json_object(vec![
            ("dataset_id", json_string(dataset_id)),
            (
                "refusals",
                json_array(refusals.iter().map(Json::from_value).collect()),
            ),
        ]),
    );
    envelope.profile_id = Some(profile);
    envelope.error = Some(error_info(
        code,
        format!("dataset planner refused the request: {message}"),
        vec![json_string("catalog planner")],
    ));
    envelope.did_you_mean = did_you_mean;
    envelope.safe_next_commands = vec![format!(
        "franken-snowflake dataset inspect {dataset_id} --json"
    )];
    envelope.repair_commands = vec![format!(
        "franken-snowflake dataset inspect {dataset_id} --json"
    )];
    Outcome {
        status: code.exit_code(),
        body: Body::Envelope { envelope, format },
    }
}

/// Resolve the dataset and compile the plan, or the typed error/refusal
/// envelope for the given command surface.
pub fn plan_dataset(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: &str,
    spec: &DatasetQuerySpec,
) -> Result<PlannedDataset, Outcome> {
    let usage = |message: String| {
        let mut envelope = base_envelope(
            false,
            "error",
            command_id,
            output_contract_id,
            request_id.to_owned(),
            json_object(vec![("dataset_id", json_string(spec.dataset_id.clone()))]),
        );
        envelope.profile_id = spec.profile.clone();
        envelope.error = Some(error_info(SnowflakeErrorCode::UsageError, message, vec![]));
        envelope.safe_next_commands = vec![format!(
            "franken-snowflake dataset inspect {} --json",
            spec.dataset_id
        )];
        envelope.repair_commands =
            vec!["franken-snowflake dataset describe-operator between --jsonschema".to_string()];
        Outcome {
            status: CoreExitCode::Usage,
            body: Body::Envelope { envelope, format },
        }
    };

    let limit = match spec.limit.as_deref() {
        None => None,
        Some(raw) => match raw.parse::<u64>() {
            Ok(value) if value > 0 => Some(value),
            _ => {
                return Err(usage(format!(
                    "--limit must be a positive row count (got `{raw}`)"
                )));
            }
        },
    };
    let filter = match spec.filter.as_deref() {
        None => None,
        Some(raw) => match serde_json::from_str::<PredicateAst>(raw) {
            Ok(ast) => Some(ast),
            Err(error) => {
                return Err(usage(format!(
                    "--filter must be a predicate JSON object ({{\"column\",\"op\",\"value\"}} or {{\"and\":[...]}}): {error}"
                )));
            }
        },
    };

    let store = local_store::open_store().map_err(|error| {
        let mut envelope = base_envelope(
            false,
            "error",
            command_id,
            output_contract_id,
            request_id.to_owned(),
            json_object(vec![]),
        );
        envelope.error = Some(error_info(
            SnowflakeErrorCode::CacheError,
            error.message(),
            vec![json_string("local store")],
        ));
        envelope.repair_commands = vec!["franken-snowflake doctor --json".to_string()];
        Outcome {
            status: SnowflakeErrorCode::CacheError.exit_code(),
            body: Body::Envelope { envelope, format },
        }
    })?;
    let dataset = load_dataset(&store, &spec.dataset_id).map_err(|error| {
        crate::catalog_surface::dataset_lookup_error_outcome(
            format,
            command_id,
            output_contract_id,
            request_id.to_owned(),
            error,
        )
    })?;
    let profile = spec
        .profile
        .clone()
        .unwrap_or_else(|| dataset.manifest.profile.clone());

    let request = DatasetQueryRequest {
        dataset_id: dataset.manifest.id.clone(),
        select: spec.select.clone(),
        entity: spec.entity.clone(),
        from: spec.from.clone(),
        to: spec.to.clone(),
        as_of: spec.as_of.clone(),
        filter,
        limit,
        export_mode: false,
        confirmation_token: None,
        warehouse: None,
        profile_fingerprint: format!("profile:{profile}"),
        command_id: command_id.to_owned(),
        trace_id: request_id.to_owned(),
    };
    let columns: Vec<_> = dataset
        .snapshot
        .columns_for_dataset(&dataset.manifest.id)
        .into_iter()
        .cloned()
        .collect();
    let plan = plan_dataset_query(
        &dataset.manifest,
        &columns,
        &dataset.snapshot.operators,
        &request,
    )
    .map_err(|refusals| {
        refusals_outcome(
            format,
            command_id,
            output_contract_id,
            request_id.to_owned(),
            profile.clone(),
            &spec.dataset_id,
            refusals,
        )
    })?;
    Ok(PlannedDataset {
        plan,
        dataset,
        profile,
    })
}

/// The `data` fields describing a compiled dataset plan.
pub fn plan_json(planned: &PlannedDataset) -> Vec<(&'static str, Json)> {
    let plan = &planned.plan;
    let bindings = plan
        .bindings
        .iter()
        .map(|(position, binding)| {
            (
                position.clone(),
                json_object(vec![
                    ("type", json_string(binding.binding_type.clone())),
                    ("value", json_string(binding.value.clone())),
                ]),
            )
        })
        .collect();
    vec![
        ("mode", json_string("dataset")),
        (
            "dataset_id",
            json_string(planned.dataset.manifest.id.clone()),
        ),
        ("profile_id", json_string(planned.profile.clone())),
        ("plan_id", json_string(plan.plan_id.clone())),
        ("sql", json_string(plan.sql.clone())),
        ("bindings", json_object_owned(bindings)),
        ("guardrails", Json::from_value(&plan.guardrails)),
        ("pushdown", Json::from_value(&plan.pushdown)),
        (
            "planner_warnings",
            json_array(plan.warnings.iter().map(Json::from_value).collect()),
        ),
        (
            "object",
            json_string(format!(
                "{}.{}.{}",
                planned.dataset.manifest.database,
                planned.dataset.manifest.schema,
                planned.dataset.manifest.object
            )),
        ),
        (
            "roles_used",
            json_object(vec![
                (
                    "entity_key",
                    option_json(
                        planned
                            .dataset
                            .manifest
                            .field_by_role(franken_snowflake_catalog::model::FieldRole::EntityKey)
                            .map(|field| field.column.clone()),
                    ),
                ),
                (
                    "time_index",
                    option_json(
                        planned
                            .dataset
                            .manifest
                            .field_by_role(franken_snowflake_catalog::model::FieldRole::TimeIndex)
                            .map(|field| field.column.clone()),
                    ),
                ),
            ]),
        ),
    ]
}

/// `query plan --dataset ...`: compile and explain the plan offline.
pub fn dataset_plan_outcome(
    format: OutputFormat,
    request_id: String,
    spec: DatasetQuerySpec,
) -> Outcome {
    let planned = match plan_dataset(
        format,
        "query.plan",
        "fsnow.query.plan.v1",
        &request_id,
        &spec,
    ) {
        Ok(planned) => planned,
        Err(outcome) => return outcome,
    };
    let mut data = plan_json(&planned);
    data.push(("provider_network", Json::Bool(false)));
    data.push(("will_submit", Json::Bool(false)));
    let run_command = run_command_for(&spec, &planned.profile);
    let mut envelope = base_envelope(
        true,
        "success",
        "query.plan",
        "fsnow.query.plan.v1",
        request_id,
        json_object(data),
    );
    envelope.data_source = DATA_SOURCE_CACHE;
    envelope.profile_id = Some(planned.profile.clone());
    envelope.warnings = planned
        .plan
        .warnings
        .iter()
        .map(|warning| json_string(format!("{}: {}", warning.code, warning.message)))
        .collect();
    envelope.safe_next_commands = vec![run_command];
    Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

/// The copy-pasteable `query run --dataset ...` form of a spec.
pub fn run_command_for(spec: &DatasetQuerySpec, profile: &str) -> String {
    let mut command = format!(
        "franken-snowflake query run --profile {profile} --dataset {}",
        spec.dataset_id
    );
    for (flag, value) in [
        ("--entity", &spec.entity),
        ("--from", &spec.from),
        ("--to", &spec.to),
        ("--as-of", &spec.as_of),
        ("--limit", &spec.limit),
    ] {
        if let Some(value) = value {
            command.push_str(&format!(" {flag} {value}"));
        }
    }
    if !spec.select.is_empty() {
        command.push_str(&format!(" --select {}", spec.select.join(",")));
    }
    if let Some(filter) = &spec.filter {
        command.push_str(&format!(" --filter '{filter}'"));
    }
    command.push_str(" --json");
    command
}

/// `select` list helper shared by the parser: comma-separated column names.
pub fn parse_select(raw: Option<&str>) -> Vec<String> {
    raw.map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect()
    })
    .unwrap_or_default()
}
