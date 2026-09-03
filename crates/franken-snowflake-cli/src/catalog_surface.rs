//! Offline catalog, dataset, export, and receipt surfaces, built directly on the
//! library crates (`franken-snowflake-catalog`, `-graph`, `-export`, `-cache`)
//! instead of hand-rolled copies. Everything here works with no credentials:
//! it reads the local store that `catalog scan` populates and the built-in
//! operator catalog. The live build reuses the same renderers after a scan.

use franken_snowflake_cache::{CacheBackend, CacheError, CatalogSnapshotRecord};
use franken_snowflake_catalog::model::{
    CatalogSnapshot, ColumnCatalogEntry, DatasetManifest, DtypeClass, FieldRole,
};
use franken_snowflake_catalog::operator::{
    OperatorArity, OperatorCatalogEntry, built_in_operator_catalog, describe_operator_json_schema,
};
use franken_snowflake_catalog::planner::{quote_identifier, quote_qualified_object};
use franken_snowflake_core::error::SnowflakeErrorCode;
use franken_snowflake_core::exit::ExitCode as CoreExitCode;
use franken_snowflake_export::{
    CopyCompression, CopyIntoOptions, CopyIntoPlan, CopySource, ExportFormat,
    LOCAL_BACKENDS_ENABLED,
};
use franken_snowflake_graph::graph_from_snapshot;

use crate::local_store::{self, Store};
use crate::{
    Body, GraphOutput, Json, Outcome, OutputFormat, base_envelope, did_you_mean, error_info,
    json_array, json_object, json_object_owned, json_string, option_json, string_array,
    success_with_profile,
};

/// Envelope `data_source` label for payloads served from the local store.
/// Distinct from `live` (a scan just ran) and `empty` (nothing to return) so an
/// agent can tell cached metadata from a fresh scan.
pub const DATA_SOURCE_CACHE: &str = "cache";

/// Cap on profiled columns per `dataset profile` statement so one pushdown
/// query stays bounded on wide tables.
pub const PROFILE_COLUMN_CAP: usize = 50;

// ---------------------------------------------------------------------------
// Shared error envelope
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn typed_error(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    profile_id: Option<String>,
    code: SnowflakeErrorCode,
    message: String,
    evidence: Vec<Json>,
    safe_next_commands: Vec<String>,
    repair_commands: Vec<String>,
    did_you_mean_values: Vec<String>,
) -> Outcome {
    let mut envelope = base_envelope(
        false,
        "error",
        command_id,
        output_contract_id,
        request_id,
        json_object(vec![]),
    );
    envelope.profile_id = profile_id;
    envelope.error = Some(error_info(code, message, evidence));
    envelope.safe_next_commands = safe_next_commands;
    envelope.repair_commands = repair_commands;
    envelope.did_you_mean = did_you_mean_values;
    Outcome {
        status: code.exit_code(),
        body: Body::Envelope { envelope, format },
    }
}

fn store_error(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    profile_id: Option<String>,
    error: &local_store::StoreError,
) -> Outcome {
    typed_error(
        format,
        command_id,
        output_contract_id,
        request_id,
        profile_id,
        SnowflakeErrorCode::CacheError,
        error.message(),
        vec![json_string("local store")],
        vec!["franken-snowflake doctor --json".to_string()],
        vec![format!(
            "export {}=<writable-dir>",
            franken_snowflake_cache::DATA_DIR_ENV
        )],
        vec![],
    )
}

fn cache_error(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    profile_id: Option<String>,
    error: &CacheError,
) -> Outcome {
    typed_error(
        format,
        command_id,
        output_contract_id,
        request_id,
        profile_id,
        SnowflakeErrorCode::CacheError,
        error.to_string(),
        vec![json_string("local store")],
        vec!["franken-snowflake doctor --json".to_string()],
        vec![],
        vec![],
    )
}

#[allow(clippy::too_many_arguments)]
fn usage(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    profile_id: Option<String>,
    message: String,
    repair_commands: Vec<String>,
    did_you_mean_values: Vec<String>,
) -> Outcome {
    typed_error(
        format,
        command_id,
        output_contract_id,
        request_id,
        profile_id,
        SnowflakeErrorCode::UsageError,
        message,
        vec![],
        vec!["franken-snowflake capabilities --json".to_string()],
        repair_commands,
        did_you_mean_values,
    )
}

// ---------------------------------------------------------------------------
// dataset describe-operator
// ---------------------------------------------------------------------------

/// Friendly aliases an agent might type for a catalog operator id.
fn operator_alias(input: &str) -> &str {
    match input {
        "equals" | "eq_" | "=" | "==" => "eq",
        "not_equals" | "ne" | "!=" | "<>" => "neq",
        "<" => "lt",
        "<=" => "lte",
        ">" => "gt",
        ">=" => "gte",
        "in_list" | "one_of" => "in",
        "null" | "isnull" => "is_null",
        "not_null" | "isnotnull" => "is_not_null",
        "like" | "substring" => "contains",
        other => other,
    }
}

fn example_value(arity: OperatorArity) -> Option<Json> {
    match arity {
        OperatorArity::Exact { count: 0 } => None,
        OperatorArity::Exact { count: 1 } => Some(json_string("<value>")),
        OperatorArity::Exact { count } => Some(json_array(
            (1..=count)
                .map(|index| json_string(format!("<value_{index}>")))
                .collect(),
        )),
        OperatorArity::Variadic { .. } => Some(json_array(vec![
            json_string("<value_1>"),
            json_string("<value_2>"),
        ])),
    }
}

fn operator_summary_json(entry: &OperatorCatalogEntry) -> Json {
    json_object(vec![
        ("id", json_string(entry.id.clone())),
        ("arity", json_string(entry.arity.label())),
        (
            "accepted_dtype_classes",
            Json::from_value(&entry.accepted_dtype_classes),
        ),
    ])
}

/// `dataset describe-operator <operator> --jsonschema`: the real catalog entry
/// plus its JSON Schema 2020-12 projection and a copy-pasteable example.
pub fn describe_operator_outcome(
    format: OutputFormat,
    request_id: String,
    operator: String,
) -> Outcome {
    let catalog = built_in_operator_catalog();
    let wanted = operator_alias(&operator.trim().to_ascii_lowercase()).to_owned();
    let ids: Vec<&str> = catalog.iter().map(|entry| entry.id.as_str()).collect();
    let Some(entry) = catalog.iter().find(|entry| entry.id == wanted) else {
        return usage(
            format,
            "dataset.describe_operator",
            "fsnow.dataset.operator_schema.v1",
            request_id,
            None,
            format!(
                "Unknown operator `{operator}`. Known operators: {}.",
                ids.join(", ")
            ),
            vec!["franken-snowflake dataset describe-operator between --jsonschema".to_string()],
            did_you_mean(&wanted, &ids),
        );
    };

    let mut example = vec![
        ("column".to_string(), json_string("<column>")),
        ("op".to_string(), json_string(entry.id.clone())),
    ];
    if let Some(value) = example_value(entry.arity) {
        example.push(("value".to_string(), value));
    }
    let schema = describe_operator_json_schema(entry);
    success_with_profile(
        format,
        "dataset.describe_operator",
        "fsnow.dataset.operator_schema.v1",
        request_id,
        None,
        json_object(vec![
            ("operator", json_string(entry.id.clone())),
            ("requested_as", json_string(operator)),
            ("arity", Json::from_value(&entry.arity)),
            ("arity_label", json_string(entry.arity.label())),
            (
                "accepted_dtype_classes",
                Json::from_value(&entry.accepted_dtype_classes),
            ),
            (
                "output_dtype_rule",
                Json::from_value(&entry.output_dtype_rule),
            ),
            ("refusal_code", json_string(entry.refusal_code.clone())),
            (
                "json_schema_contract_id",
                json_string(entry.json_schema_contract_id.clone()),
            ),
            ("json_schema", Json::from_serde(schema)),
            ("example_predicate", json_object_owned(example)),
            (
                "all_operators",
                json_array(catalog.iter().map(operator_summary_json).collect()),
            ),
        ]),
        vec![],
        vec![
            "franken-snowflake dataset inspect <dataset-id> --json".to_string(),
            "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                .to_string(),
        ],
    )
}

// ---------------------------------------------------------------------------
// Store lookups shared by dataset inspect / profile / graph
// ---------------------------------------------------------------------------

/// A dataset resolved from the local store: its manifest record, the parsed
/// manifest, and the snapshot it came from (for columns and operators).
pub struct StoredDataset {
    pub manifest: DatasetManifest,
    pub snapshot: CatalogSnapshot,
    pub snapshot_record: CatalogSnapshotRecord,
}

/// Why a dataset could not be resolved offline.
pub enum DatasetLookupError {
    Cache(CacheError),
    NotFound {
        dataset_id: String,
        known: Vec<String>,
    },
    Corrupt(String),
}

/// Resolve a dataset id (exact, or case-insensitive readable-slug prefix) from
/// the local store.
pub fn load_dataset(store: &Store, dataset_id: &str) -> Result<StoredDataset, DatasetLookupError> {
    let record = match store
        .cache
        .dataset_manifest(dataset_id)
        .map_err(DatasetLookupError::Cache)?
    {
        Some(record) => record,
        None => {
            return Err(DatasetLookupError::NotFound {
                dataset_id: dataset_id.to_owned(),
                known: known_dataset_ids(store),
            });
        }
    };
    let manifest: DatasetManifest = serde_json::from_str(&record.manifest.canonical)
        .map_err(|error| DatasetLookupError::Corrupt(format!("manifest payload: {error}")))?;
    let snapshot_id = record
        .snapshot_id
        .clone()
        .ok_or_else(|| DatasetLookupError::Corrupt("manifest has no snapshot id".to_owned()))?;
    let snapshot_record = store
        .cache
        .catalog_snapshot(&snapshot_id)
        .map_err(DatasetLookupError::Cache)?
        .ok_or_else(|| {
            DatasetLookupError::Corrupt(format!("snapshot {snapshot_id} is missing from the store"))
        })?;
    let snapshot: CatalogSnapshot = serde_json::from_str(&snapshot_record.payload.canonical)
        .map_err(|error| DatasetLookupError::Corrupt(format!("snapshot payload: {error}")))?;
    Ok(StoredDataset {
        manifest,
        snapshot,
        snapshot_record,
    })
}

/// Every dataset id in the store (for `did_you_mean` and not-found messages).
/// The file backend folds its log in memory, so this walks the audit-free
/// manifest table only.
fn known_dataset_ids(store: &Store) -> Vec<String> {
    store.cache.dataset_ids().unwrap_or_default()
}

pub fn dataset_lookup_error_outcome(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    error: DatasetLookupError,
) -> Outcome {
    match error {
        DatasetLookupError::Cache(error) => cache_error(
            format,
            command_id,
            output_contract_id,
            request_id,
            None,
            &error,
        ),
        DatasetLookupError::Corrupt(detail) => typed_error(
            format,
            command_id,
            output_contract_id,
            request_id,
            None,
            SnowflakeErrorCode::MetadataError,
            format!("local catalog metadata is unreadable: {detail}"),
            vec![json_string("local store")],
            vec![
                "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                    .to_string(),
            ],
            vec!["franken-snowflake doctor --json".to_string()],
            vec![],
        ),
        DatasetLookupError::NotFound { dataset_id, known } => {
            let known_refs: Vec<&str> = known.iter().map(String::as_str).collect();
            let suggestions = did_you_mean(&dataset_id, &known_refs);
            typed_error(
                format,
                command_id,
                output_contract_id,
                request_id,
                None,
                SnowflakeErrorCode::MetadataError,
                format!(
                    "dataset `{dataset_id}` is not in the local store ({} known); run a catalog scan for its database/schema first",
                    known.len()
                ),
                vec![json_string("local store")],
                vec![
                    "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                        .to_string(),
                ],
                vec![
                    "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                        .to_string(),
                ],
                suggestions,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// dataset inspect
// ---------------------------------------------------------------------------

fn roles_json(manifest: &DatasetManifest) -> Json {
    let role_columns = |role: FieldRole| {
        string_array(
            manifest
                .fields
                .iter()
                .filter(|field| field.role == role)
                .map(|field| field.column.clone())
                .collect(),
        )
    };
    json_object(vec![
        ("entity_key", role_columns(FieldRole::EntityKey)),
        ("time_index", role_columns(FieldRole::TimeIndex)),
        ("known_at", role_columns(FieldRole::KnownAt)),
        ("feature", role_columns(FieldRole::Feature)),
        ("label", role_columns(FieldRole::Label)),
        ("metadata", role_columns(FieldRole::Metadata)),
    ])
}

fn snapshot_meta_json(record: &CatalogSnapshotRecord, served_from: &str) -> Json {
    json_object(vec![
        ("snapshot_id", json_string(record.snapshot_id.clone())),
        ("profile_id", json_string(record.profile_id.clone())),
        ("source_kind", json_string(record.source_kind.clone())),
        ("database", option_json(record.database_name.clone())),
        ("schema", option_json(record.schema_name.clone())),
        (
            "captured_at_ms",
            Json::Number(i64::try_from(record.captured_at_ms).unwrap_or(i64::MAX)),
        ),
        (
            "captured_at",
            json_string(local_store::rfc3339_utc(
                i64::try_from(record.captured_at_ms / 1000).unwrap_or(0),
            )),
        ),
        ("served_from", json_string(served_from)),
        (
            "payload_hash",
            json_string(record.payload.address.digest_hex.clone()),
        ),
    ])
}

/// `dataset inspect <dataset-id> --json`: manifest + column catalog + operator
/// catalog from the local store. Offline.
pub fn dataset_inspect_outcome(
    format: OutputFormat,
    request_id: String,
    dataset_id: String,
) -> Outcome {
    let store = match local_store::open_store() {
        Ok(store) => store,
        Err(error) => {
            return store_error(
                format,
                "dataset.inspect",
                "fsnow.dataset.inspect.v1",
                request_id,
                None,
                &error,
            );
        }
    };
    let stored = match load_dataset(&store, &dataset_id) {
        Ok(stored) => stored,
        Err(error) => {
            return dataset_lookup_error_outcome(
                format,
                "dataset.inspect",
                "fsnow.dataset.inspect.v1",
                request_id,
                error,
            );
        }
    };
    let columns = stored.snapshot.columns_for_dataset(&stored.manifest.id);
    let profile = stored.manifest.profile.clone();
    let example_sql = format!(
        "select * from {} limit {}",
        quote_qualified_object(
            &stored.manifest.database,
            &stored.manifest.schema,
            &stored.manifest.object
        ),
        stored.manifest.default_limit
    );
    let mut envelope = base_envelope(
        true,
        "success",
        "dataset.inspect",
        "fsnow.dataset.inspect.v1",
        request_id,
        json_object(vec![
            ("dataset_id", json_string(stored.manifest.id.clone())),
            ("manifest", Json::from_value(&stored.manifest)),
            ("roles", roles_json(&stored.manifest)),
            ("column_count", Json::Number(columns.len() as i64)),
            (
                "columns",
                json_array(columns.iter().map(Json::from_value).collect()),
            ),
            (
                "operators",
                json_array(
                    stored
                        .snapshot
                        .operators
                        .iter()
                        .map(operator_summary_json)
                        .collect(),
                ),
            ),
            (
                "snapshot",
                snapshot_meta_json(&stored.snapshot_record, "local_store"),
            ),
            (
                "store",
                json_object(vec![(
                    "data_dir",
                    json_string(store.dir.display().to_string()),
                )]),
            ),
            (
                "query_example",
                json_string(format!(
                    "franken-snowflake query run --profile {profile} --sql \"{example_sql}\" --json"
                )),
            ),
        ]),
    );
    envelope.data_source = DATA_SOURCE_CACHE;
    envelope.profile_id = Some(profile.clone());
    envelope.safe_next_commands = vec![
        format!(
            "franken-snowflake dataset profile {} --json",
            stored.manifest.id
        ),
        format!("franken-snowflake query run --profile {profile} --sql \"{example_sql}\" --json"),
        "franken-snowflake dataset describe-operator between --jsonschema".to_string(),
    ];
    Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

// ---------------------------------------------------------------------------
// dataset profile (APPROX_* pushdown plan)
// ---------------------------------------------------------------------------

/// A pushdown profiling plan: one statement computing row count, approximate
/// distinct counts, null counts, and min/max per column, executed Snowflake-
/// side (never local statistics).
pub struct ProfilePlan {
    pub sql: String,
    pub dataset_id: String,
    pub profile: String,
    pub database: String,
    pub schema: String,
    pub object: String,
    pub profiled_columns: Vec<String>,
    pub skipped_columns: Vec<String>,
    pub statement_timeout_seconds: u32,
}

/// Build the profiling statement for a dataset. Columns beyond
/// [`PROFILE_COLUMN_CAP`] are skipped (reported), and semi-structured or
/// unknown-typed columns get null/distinct counts only.
pub fn build_profile_plan(
    manifest: &DatasetManifest,
    columns: &[&ColumnCatalogEntry],
) -> ProfilePlan {
    let mut select = vec!["COUNT(*) AS \"ROW_COUNT\"".to_string()];
    let mut profiled = Vec::new();
    let mut skipped = Vec::new();
    for column in columns {
        if profiled.len() >= PROFILE_COLUMN_CAP {
            skipped.push(column.column.clone());
            continue;
        }
        let ident = quote_identifier(&column.column);
        let alias = |suffix: &str| quote_identifier(&format!("{}__{suffix}", column.column));
        select.push(format!(
            "APPROX_COUNT_DISTINCT({ident}) AS {}",
            alias("approx_distinct")
        ));
        select.push(format!(
            "COUNT_IF({ident} IS NULL) AS {}",
            alias("null_count")
        ));
        if matches!(
            column.dtype_class,
            DtypeClass::Number
                | DtypeClass::Date
                | DtypeClass::Time
                | DtypeClass::Timestamp
                | DtypeClass::String
                | DtypeClass::Boolean
        ) {
            select.push(format!("MIN({ident}) AS {}", alias("min")));
            select.push(format!("MAX({ident}) AS {}", alias("max")));
        }
        profiled.push(column.column.clone());
    }
    let sql = format!(
        "SELECT {} FROM {}",
        select.join(", "),
        quote_qualified_object(&manifest.database, &manifest.schema, &manifest.object)
    );
    ProfilePlan {
        sql,
        dataset_id: manifest.id.clone(),
        profile: manifest.profile.clone(),
        database: manifest.database.clone(),
        schema: manifest.schema.clone(),
        object: manifest.object.clone(),
        profiled_columns: profiled,
        skipped_columns: skipped,
        statement_timeout_seconds: 60,
    }
}

/// The `data` payload describing a profile plan (shared by the plan-only and
/// executed forms).
pub fn profile_plan_json(plan: &ProfilePlan, executed: bool) -> Vec<(&'static str, Json)> {
    vec![
        ("dataset_id", json_string(plan.dataset_id.clone())),
        ("profile_id", json_string(plan.profile.clone())),
        (
            "object",
            json_string(quote_qualified_object(
                &plan.database,
                &plan.schema,
                &plan.object,
            )),
        ),
        ("pushdown", Json::Bool(true)),
        ("local_stats_computation", Json::Bool(false)),
        ("executed", Json::Bool(executed)),
        ("sql", json_string(plan.sql.clone())),
        (
            "statement_timeout_seconds",
            Json::Number(i64::from(plan.statement_timeout_seconds)),
        ),
        (
            "profiled_columns",
            string_array(plan.profiled_columns.clone()),
        ),
        (
            "skipped_columns",
            string_array(plan.skipped_columns.clone()),
        ),
        (
            "column_cap",
            Json::Number(i64::try_from(PROFILE_COLUMN_CAP).unwrap_or(i64::MAX)),
        ),
    ]
}

/// Resolve the dataset and build its profiling plan, or the typed error.
pub fn resolve_profile_plan(
    format: OutputFormat,
    request_id: &str,
    dataset_id: &str,
) -> Result<ProfilePlan, Outcome> {
    let store = local_store::open_store().map_err(|error| {
        store_error(
            format,
            "dataset.profile",
            "fsnow.dataset.profile.v1",
            request_id.to_owned(),
            None,
            &error,
        )
    })?;
    let stored = load_dataset(&store, dataset_id).map_err(|error| {
        dataset_lookup_error_outcome(
            format,
            "dataset.profile",
            "fsnow.dataset.profile.v1",
            request_id.to_owned(),
            error,
        )
    })?;
    let columns = stored.snapshot.columns_for_dataset(&stored.manifest.id);
    Ok(build_profile_plan(&stored.manifest, &columns))
}

/// `dataset profile <dataset-id> --json` without execution: the pushdown plan.
pub fn dataset_profile_plan_outcome(
    format: OutputFormat,
    request_id: String,
    dataset_id: String,
    execute_requested_but_unavailable: bool,
) -> Outcome {
    let plan = match resolve_profile_plan(format, &request_id, &dataset_id) {
        Ok(plan) => plan,
        Err(outcome) => return outcome,
    };
    let profile = plan.profile.clone();
    let mut data = profile_plan_json(&plan, false);
    data.push(("will_submit", Json::Bool(false)));
    let mut warnings = Vec::new();
    if execute_requested_but_unavailable {
        warnings.push(json_string(
            "--execute was requested but this build has no live transport; returning the plan only (rebuild with --features live)",
        ));
    }
    if !plan.skipped_columns.is_empty() {
        warnings.push(json_string(format!(
            "{} columns beyond the {PROFILE_COLUMN_CAP}-column cap were skipped",
            plan.skipped_columns.len()
        )));
    }
    let mut envelope = base_envelope(
        true,
        "success",
        "dataset.profile",
        "fsnow.dataset.profile.v1",
        request_id,
        json_object(data),
    );
    envelope.data_source = DATA_SOURCE_CACHE;
    envelope.profile_id = Some(profile.clone());
    envelope.warnings = warnings;
    envelope.safe_next_commands = vec![
        format!("franken-snowflake dataset profile {dataset_id} --execute --json"),
        format!(
            "franken-snowflake query run --profile {profile} --sql \"{}\" --json",
            plan.sql
        ),
    ];
    Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

// ---------------------------------------------------------------------------
// catalog scan summary + catalog graph rendering (shared with the live path)
// ---------------------------------------------------------------------------

/// Deterministic summary of a snapshot for the `catalog scan` envelope.
#[cfg(feature = "live")]
pub fn snapshot_summary_json(snapshot: &CatalogSnapshot) -> Vec<(&'static str, Json)> {
    let datasets = snapshot
        .datasets
        .iter()
        .map(|dataset| {
            let column_count = snapshot
                .columns
                .iter()
                .filter(|column| column.dataset_id == dataset.id)
                .count();
            json_object(vec![
                ("dataset_id", json_string(dataset.id.clone())),
                ("database", json_string(dataset.database.clone())),
                ("schema", json_string(dataset.schema.clone())),
                ("object", json_string(dataset.object.clone())),
                ("kind", Json::from_value(&dataset.kind)),
                (
                    "approx_row_count",
                    dataset.approx_row_count.map_or(Json::Null, |value| {
                        Json::Number(i64::try_from(value).unwrap_or(i64::MAX))
                    }),
                ),
                (
                    "bytes",
                    dataset.bytes.map_or(Json::Null, |value| {
                        Json::Number(i64::try_from(value).unwrap_or(i64::MAX))
                    }),
                ),
                ("column_count", Json::Number(column_count as i64)),
                ("roles", roles_json(dataset)),
                ("description", option_json(dataset.description.clone())),
            ])
        })
        .collect();
    vec![
        (
            "schema_version",
            json_string(snapshot.schema_version.clone()),
        ),
        (
            "snapshot_id",
            json_string(snapshot.provenance.snapshot_id.clone()),
        ),
        (
            "discovered_at",
            json_string(snapshot.provenance.discovered_at.clone()),
        ),
        (
            "dataset_count",
            Json::Number(snapshot.datasets.len() as i64),
        ),
        ("column_count", Json::Number(snapshot.columns.len() as i64)),
        (
            "operator_count",
            Json::Number(snapshot.operators.len() as i64),
        ),
        ("datasets", json_array(datasets)),
    ]
}

/// Render a snapshot as the requested `catalog graph` output. `served_from` is
/// `live_scan` or `local_store`; `data_source` is the envelope label to stamp.
#[allow(clippy::too_many_arguments)]
pub fn render_graph_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    database: Option<String>,
    schema: Option<String>,
    snapshot: &CatalogSnapshot,
    snapshot_record: &CatalogSnapshotRecord,
    served_from: &str,
    data_source: &'static str,
    graph_output: GraphOutput,
) -> Outcome {
    let graph = graph_from_snapshot(snapshot);
    match graph_output {
        GraphOutput::Mermaid => Outcome {
            status: CoreExitCode::Success,
            body: Body::Raw {
                data: graph.to_mermaid(),
            },
        },
        GraphOutput::Svg => Outcome {
            status: CoreExitCode::Success,
            body: Body::Raw {
                data: graph.to_svg(),
            },
        },
        GraphOutput::Json | GraphOutput::Toon => {
            let out_format = if matches!(graph_output, GraphOutput::Toon) {
                OutputFormat::Toon
            } else {
                format
            };
            let nodes = graph
                .nodes
                .values()
                .map(|node| {
                    json_object(vec![
                        ("key", json_string(node.key.clone())),
                        ("kind", json_string(node.kind.as_str())),
                        ("label", json_string(node.label.clone())),
                        ("qualified_name", option_json(node.qualified_name.clone())),
                    ])
                })
                .collect();
            let edges = graph
                .edges
                .iter()
                .map(|edge| {
                    json_object(vec![
                        ("source", json_string(edge.source.clone())),
                        ("target", json_string(edge.target.clone())),
                        ("kind", json_string(edge.kind.as_str())),
                        ("detail", option_json(edge.detail.clone())),
                    ])
                })
                .collect();
            let cycles = graph.cycles();
            let mut envelope = base_envelope(
                true,
                "success",
                "catalog.graph",
                "fsnow.catalog.graph.v1",
                request_id,
                json_object(vec![
                    ("profile_id", json_string(profile.clone())),
                    ("database", option_json(database)),
                    ("schema", option_json(schema)),
                    ("snapshot", snapshot_meta_json(snapshot_record, served_from)),
                    ("node_count", Json::Number(graph.node_count() as i64)),
                    ("edge_count", Json::Number(graph.edge_count() as i64)),
                    ("cycle_count", Json::Number(cycles.len() as i64)),
                    ("nodes", json_array(nodes)),
                    ("edges", json_array(edges)),
                    ("mermaid", json_string(graph.to_mermaid())),
                ]),
            );
            envelope.data_source = data_source;
            envelope.profile_id = Some(profile);
            envelope.safe_next_commands = vec![
                "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                    .to_string(),
                "franken-snowflake dataset inspect <dataset-id> --json".to_string(),
            ];
            if served_from == "local_store" {
                envelope.warnings = vec![json_string(
                    "rendered from the local catalog snapshot; run `catalog scan` to refresh",
                )];
            }
            Outcome {
                status: CoreExitCode::Success,
                body: Body::Envelope {
                    envelope,
                    format: out_format,
                },
            }
        }
    }
}

/// `catalog graph` from the local store (no transport): render the newest
/// snapshot captured for this scope, or a typed "scan first" error.
#[cfg(not(feature = "live"))]
pub fn catalog_graph_from_store_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    database: Option<String>,
    schema: Option<String>,
    graph_output: GraphOutput,
) -> Outcome {
    let store = match local_store::open_store() {
        Ok(store) => store,
        Err(error) => {
            return store_error(
                format,
                "catalog.graph",
                "fsnow.catalog.graph.v1",
                request_id,
                Some(profile),
                &error,
            );
        }
    };
    let record = match store.cache.latest_catalog_snapshot(
        &profile,
        database.as_deref(),
        schema.as_deref(),
    ) {
        Ok(Some(record)) => record,
        Ok(None) => {
            let scan = format!(
                "franken-snowflake catalog scan {profile} --database {} --schema {} --json",
                database.as_deref().unwrap_or("<db>"),
                schema.as_deref().unwrap_or("<schema>")
            );
            return typed_error(
                format,
                "catalog.graph",
                "fsnow.catalog.graph.v1",
                request_id,
                Some(profile.clone()),
                SnowflakeErrorCode::MetadataError,
                format!(
                    "no catalog snapshot for profile `{profile}` (database={}, schema={}) in the local store; run a catalog scan first (needs the live feature and credentials)",
                    database.as_deref().unwrap_or("*"),
                    schema.as_deref().unwrap_or("*")
                ),
                vec![json_string("local store")],
                vec![scan.clone()],
                vec![scan],
                vec![],
            );
        }
        Err(error) => {
            return cache_error(
                format,
                "catalog.graph",
                "fsnow.catalog.graph.v1",
                request_id,
                Some(profile),
                &error,
            );
        }
    };
    let snapshot: CatalogSnapshot = match serde_json::from_str(&record.payload.canonical) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return typed_error(
                format,
                "catalog.graph",
                "fsnow.catalog.graph.v1",
                request_id,
                Some(profile),
                SnowflakeErrorCode::MetadataError,
                format!("stored snapshot is unreadable: {error}"),
                vec![json_string("local store")],
                vec![],
                vec!["franken-snowflake doctor --json".to_string()],
                vec![],
            );
        }
    };
    render_graph_outcome(
        format,
        request_id,
        profile,
        database,
        schema,
        &snapshot,
        &record,
        "local_store",
        DATA_SOURCE_CACHE,
        graph_output,
    )
}

// ---------------------------------------------------------------------------
// export plan (COPY INTO <location>)
// ---------------------------------------------------------------------------

/// Parsed `export plan` flags.
#[derive(Debug, Default)]
pub struct ExportPlanSpec {
    pub profile: Option<String>,
    pub sql: Option<String>,
    pub query_id: Option<String>,
    pub location: Option<String>,
    pub format: Option<String>,
    pub compression: Option<String>,
    pub header: Option<String>,
    pub overwrite: bool,
    pub single: bool,
    pub max_file_size: Option<String>,
}

const EXPORT_PLAN_EXAMPLE: &str = "franken-snowflake export plan --profile <profile> --sql \"select * from events\" --location @my_stage/exports/run_001 --format csv --json";

/// `export plan`: build a deterministic, content-addressed `COPY INTO <stage>`
/// plan through the export crate and hand it to `query write` for execution.
pub fn export_plan_outcome(
    format: OutputFormat,
    request_id: String,
    spec: ExportPlanSpec,
) -> Outcome {
    let usage_err = |message: String| {
        usage(
            format,
            "export.plan",
            "fsnow.export.plan.v1",
            request_id.clone(),
            spec.profile.clone(),
            message,
            vec![EXPORT_PLAN_EXAMPLE.to_string()],
            vec![],
        )
    };
    let Some(location) = spec.location.clone() else {
        return usage_err(
            "Missing --location for `export plan` (a Snowflake stage path such as @my_stage/exports/run_001)."
                .to_string(),
        );
    };
    let source = match (spec.sql.clone(), spec.query_id.clone()) {
        (Some(sql), None) => CopySource::Query { sql },
        (None, Some(query_id)) => CopySource::ResultScan { query_id },
        (None, None) => {
            return usage_err(
                "Provide exactly one source: --sql <select> or --query-id <snowflake-query-id> (RESULT_SCAN)."
                    .to_string(),
            );
        }
        (Some(_), Some(_)) => {
            return usage_err("Choose either --sql or --query-id, not both.".to_string());
        }
    };
    let export_format = match spec
        .format
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("csv") => ExportFormat::Csv,
        Some("jsonl") | Some("json") => ExportFormat::Jsonl,
        Some(other) => {
            return usage_err(format!("Unknown --format `{other}`; use csv or jsonl."));
        }
    };
    let compression = match spec
        .compression
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("none") => CopyCompression::None,
        Some("gzip") => CopyCompression::Gzip,
        Some(other) => {
            return usage_err(format!(
                "Unknown --compression `{other}`; use none or gzip."
            ));
        }
    };
    let header = match spec
        .header
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("true") => true,
        Some("false") => false,
        Some(other) => {
            return usage_err(format!("--header must be true or false (got `{other}`)."));
        }
    };
    let max_file_size = match spec.max_file_size.as_deref() {
        None => CopyIntoOptions::default().max_file_size,
        Some(raw) => match raw.parse::<u64>() {
            Ok(value) if value > 0 => Some(value),
            _ => {
                return usage_err(format!(
                    "--max-file-size must be a positive byte count (got `{raw}`)."
                ));
            }
        },
    };
    let options = CopyIntoOptions {
        format: export_format,
        compression,
        header,
        overwrite: spec.overwrite,
        single: spec.single,
        max_file_size,
    };
    let mut plan = CopyIntoPlan::new(location, source).with_options(options);
    if let Some(profile) = &spec.profile {
        plan = plan.with_profile_ref_redacted(profile.clone());
    }
    let sql = match plan.to_sql() {
        Ok(sql) => sql,
        Err(error) => return usage_err(format!("export plan refused: {error}")),
    };
    let plan_hash = match plan.plan_hash() {
        Ok(hash) => hash,
        Err(error) => return usage_err(format!("export plan refused: {error}")),
    };
    let receipt = match plan.plan_receipt(local_store::now_unix_ms()) {
        Ok(receipt) => receipt,
        Err(error) => return usage_err(format!("export plan refused: {error}")),
    };
    let profile_label = spec
        .profile
        .clone()
        .unwrap_or_else(|| "<profile>".to_string());
    let write_command = format!(
        "franken-snowflake query write --profile {profile_label} --sql \"{}\" --json",
        sql.replace('"', "\\\"")
    );
    let env_prefix = crate::profile_env_prefix(&profile_label);
    let mut envelope = base_envelope(
        true,
        "success",
        "export.plan",
        "fsnow.export.plan.v1",
        request_id,
        json_object(vec![
            (
                "plan_contract_id",
                json_string(franken_snowflake_export::COPY_INTO_PLAN_CONTRACT_ID),
            ),
            ("plan_sql", json_string(sql)),
            ("plan_hash", json_string(plan_hash)),
            ("location", json_string(plan.location.clone())),
            ("source", Json::from_value(&plan.source)),
            ("options", Json::from_value(&plan.options)),
            ("receipt", Json::from_value(&receipt)),
            ("execution_enabled", Json::Bool(false)),
            ("will_submit", Json::Bool(false)),
            (
                "execute_with",
                json_object(vec![
                    ("command", json_string(write_command.clone())),
                    ("statement_kind", json_string("copy_into_location")),
                    ("safety_class", json_string("external_file")),
                    (
                        "requires",
                        string_array(vec![
                            format!("{env_prefix}_WRITE_ENABLED=true"),
                            "a binary built with --features live".to_string(),
                            "the profile's credential handles".to_string(),
                        ]),
                    ),
                ]),
            ),
            (
                "local_export",
                json_object(vec![
                    ("backends_enabled", Json::Bool(LOCAL_BACKENDS_ENABLED)),
                    (
                        "command",
                        json_string(
                            "franken-snowflake export run --profile <profile> --sql <select> --format csv --out <path> --json",
                        ),
                    ),
                ]),
            ),
        ]),
    );
    envelope.profile_id = spec.profile.clone();
    envelope.safe_next_commands = vec![
        write_command.replace(" --json", " --dry-run --json"),
        write_command,
    ];
    Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

// ---------------------------------------------------------------------------
// receipt show
// ---------------------------------------------------------------------------

/// `receipt show <hash>`: the content-addressed receipt, its partition evidence,
/// and the audit events that reference it, from the local store.
pub fn receipt_show_outcome(
    format: OutputFormat,
    request_id: String,
    receipt_hash: String,
) -> Outcome {
    let receipt_id = receipt_hash
        .trim()
        .strip_prefix("blake3:")
        .unwrap_or(receipt_hash.trim())
        .to_ascii_lowercase();
    let store = match local_store::open_store() {
        Ok(store) => store,
        Err(error) => {
            return store_error(
                format,
                "receipt.show",
                "fsnow.receipt.show.v1",
                request_id,
                None,
                &error,
            );
        }
    };
    let record = match store.cache.query_receipt(&receipt_id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return typed_error(
                format,
                "receipt.show",
                "fsnow.receipt.show.v1",
                request_id,
                None,
                SnowflakeErrorCode::MetadataError,
                format!(
                    "receipt `{receipt_id}` is not in the local store at {}",
                    store.dir.display()
                ),
                vec![json_string("local store")],
                vec![
                    "franken-snowflake query run --profile <profile> --sql <sql> --json"
                        .to_string(),
                ],
                vec!["franken-snowflake doctor --json".to_string()],
                vec![],
            );
        }
        Err(error) => {
            return cache_error(
                format,
                "receipt.show",
                "fsnow.receipt.show.v1",
                request_id,
                None,
                &error,
            );
        }
    };
    let receipt_body = serde_json::from_str::<serde_json::Value>(&record.receipt.canonical)
        .map_or_else(
            |_| json_string(record.receipt.canonical.clone()),
            Json::from_serde,
        );
    let partitions = store
        .cache
        .partitions_for_receipt(&record.receipt_id)
        .unwrap_or_default();
    let audit_events: Vec<Json> = store
        .cache
        .audit_events()
        .unwrap_or_default()
        .into_iter()
        .filter(|event| event.receipt_id.as_deref() == Some(record.receipt_id.as_str()))
        .map(|event| Json::from_value(&event))
        .collect();
    let mut envelope = base_envelope(
        true,
        "success",
        "receipt.show",
        "fsnow.receipt.show.v1",
        request_id,
        json_object(vec![
            ("receipt_id", json_string(record.receipt_id.clone())),
            ("plan_id", json_string(record.plan_id.clone())),
            ("profile_id", json_string(record.profile_id.clone())),
            ("command_id", json_string(record.command_id.clone())),
            ("trace_id", json_string(record.trace_id.clone())),
            ("outcome_kind", json_string(record.outcome_kind.clone())),
            ("receipt_state", json_string(record.receipt_state.clone())),
            (
                "statement_handle",
                option_json(record.statement_handle.clone()),
            ),
            (
                "snowflake_query_id",
                option_json(record.snowflake_query_id.clone()),
            ),
            ("sql_api_request_id", option_json(record.request_id.clone())),
            (
                "row_count",
                record.row_count.map_or(Json::Null, |value| {
                    Json::Number(i64::try_from(value).unwrap_or(i64::MAX))
                }),
            ),
            (
                "created_at_ms",
                Json::Number(i64::try_from(record.created_at_ms).unwrap_or(i64::MAX)),
            ),
            (
                "created_at",
                json_string(local_store::rfc3339_utc(
                    i64::try_from(record.created_at_ms / 1000).unwrap_or(0),
                )),
            ),
            ("content_address", Json::from_value(&record.receipt.address)),
            ("receipt", receipt_body),
            (
                "partitions",
                json_array(partitions.iter().map(Json::from_value).collect()),
            ),
            ("audit_events", json_array(audit_events)),
            (
                "store",
                json_object(vec![(
                    "data_dir",
                    json_string(store.dir.display().to_string()),
                )]),
            ),
        ]),
    );
    envelope.data_source = DATA_SOURCE_CACHE;
    envelope.profile_id = Some(record.profile_id.clone());
    envelope.receipt_hash = Some(record.receipt_id.clone());
    envelope.statement_handle = record.statement_handle.clone();
    envelope.query_id = record.snowflake_query_id.clone();
    envelope.safe_next_commands = vec![format!(
        "franken-snowflake query run --profile {} --sql \"select * from table(result_scan('{}'))\" --json",
        record.profile_id,
        record.snowflake_query_id.clone().unwrap_or_default()
    )];
    Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}
