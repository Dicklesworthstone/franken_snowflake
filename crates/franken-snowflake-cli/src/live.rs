//! Live SQL API transport wiring for the CLI (`feature = "live"`).
//!
//! Only compiled with `--features live`. It reuses the crate-root envelope
//! machinery and the published transport stack (`franken-snowflake-{auth,http,
//! sqlapi}` + Asupersync), driving the exact submit -> poll -> partition ->
//! assemble flow the opt-in `live_proof` integration test proves end-to-end.
//!
//! What every live command does after a successful execution:
//! - stamps `data_source = "live"`, the real statement handle, and the
//!   poll/row budget it consumed;
//! - writes a content-addressed (BLAKE3) receipt, partition evidence, and an
//!   append-only audit event to the local store, and puts the receipt hash on
//!   the envelope (a store failure is a warning, never a fabricated hash);
//! - caps the rows it *emits* (default [`ROW_EMIT_CAP`], `--limit` overrides)
//!   with an explicit `truncated` flag.
//!
//! Provenance and safety contract:
//! - a missing credential env handle is a typed error (exit 3), never a silent
//!   empty result;
//! - secrets are never read into any message; auth/transport errors arrive
//!   already redacted and the crate-root `sanitize_envelope` pass runs the
//!   secret-leak redactor over the whole envelope before output.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use asupersync::runtime::RuntimeBuilder;
use asupersync::{Cx, Outcome};
use franken_snowflake_auth::{
    AuthMechanism, AuthProfile, KEYPAIR_JWT_TOKEN_TYPE, OAUTH_TOKEN_TYPE,
    PROGRAMMATIC_ACCESS_TOKEN_TYPE, ProcessSecretResolver, ReauthDecision, SecretSource,
    SnowflakeAuth,
};
use franken_snowflake_cache::{
    CacheBackend, CatalogSnapshotRecord, ContentAddress as CacheAddress, ExportKind, ExportRecord,
    VerifiedPayload,
};
use franken_snowflake_catalog::discovery::{
    CatalogDiscoveryInput, CatalogDiscoveryTables, DiscoveryStatementKind,
    build_information_schema_requests, build_snapshot_from_information_schema, persist_snapshot,
};
use franken_snowflake_catalog::model::{CatalogSnapshot, DataSourceClass};
use franken_snowflake_core::cancel::CancelKind;
use franken_snowflake_core::guardrails::enforce_require_live;
use franken_snowflake_core::outcome::DataSource;
use franken_snowflake_core::error::{SnowflakeError, SnowflakeErrorCode};
use franken_snowflake_core::exit::ExitCode as CoreExitCode;
use franken_snowflake_core::ids::{
    DatabaseName, RoleName, SchemaName, StatementHandle, WarehouseName,
};
use franken_snowflake_core::redact::redact;
use franken_snowflake_export::{
    CopySource, ExportColumn, LocalExportInput, ResultPartition, export_csv, export_jsonl,
};
use franken_snowflake_http::{
    AuthorizationDescriptor, CancelHttpRequest, SnowflakeAuthTokenType, SnowflakeEndpoint,
    SnowflakeHttpClient, StatusClass, TransportConfig,
};
use franken_snowflake_sqlapi::driver::{AuthProvider, DriverStats, run_statement_with_auth};
use franken_snowflake_sqlapi::lifecycle::{
    CompletedStatement, DEFAULT_PARTITION_CONCURRENCY, MAX_PARTITION_CONCURRENCY, PollPlan,
};
use franken_snowflake_sqlapi::request::{Binding, SubmitQueryParams, SubmitStatementRequest};

use crate::catalog_surface::{self, DATA_SOURCE_CACHE, ExportPlanSpec};
use crate::local_store::{self, ExecutionFacts, Store};
use crate::{
    Body, GraphOutput, Json, OutputFormat, QueryRunOptions, base_envelope, error_info, json_array,
    json_object, json_object_owned, json_string, option_json,
};

/// Default SQL API statement timeout (seconds) requested per submit; a profile
/// overrides it with `<PREFIX>_STATEMENT_TIMEOUT_SECONDS`, a run with
/// `--statement-timeout`.
const DEFAULT_STATEMENT_TIMEOUT_SECONDS: u32 = 60;
/// Upper bound on a requested statement timeout (one day).
const MAX_STATEMENT_TIMEOUT_SECONDS: u32 = 86_400;
/// Poll budget if a profile does not override `<PREFIX>_MAX_POLLS`.
const DEFAULT_MAX_POLLS: u32 = 120;
/// Maximum rows materialized into a single response envelope by default. The
/// driver still assembles the full result; this only bounds the JSON payload an
/// agent sees. `--limit` overrides it up to [`MAX_ROW_EMIT_CAP`].
pub const ROW_EMIT_CAP: usize = 1000;
/// Hard ceiling for `--limit`.
const MAX_ROW_EMIT_CAP: usize = 100_000;
/// Keep caller-supplied bind payloads bounded before parsing or transport.
const MAX_BINDINGS_JSON_BYTES: usize = 1_048_576;
/// The connector materializes at most this many positional binds in one request.
const MAX_BINDING_COUNT: usize = 1_000;
/// Snowflake documents QUERY_TAG as a bounded session string.
const MAX_QUERY_TAG_BYTES: usize = 2_000;
/// Longest cancel-endpoint body preview echoed into an envelope.
const CANCEL_BODY_PREVIEW_BYTES: usize = 512;

#[derive(Default)]
struct QueryRequestOptions {
    bindings: Option<BTreeMap<String, Binding>>,
    query_tag: Option<String>,
    /// Stop fetching partitions once this many rows are assembled (the
    /// envelope's emit cap); `None` downloads every partition.
    row_cap: Option<usize>,
}

/// Per-run session overrides resolved from flags (validated) on top of the
/// profile's env handles.
#[derive(Clone, Debug, Default)]
struct SessionOverrides {
    database: Option<String>,
    schema: Option<String>,
    role: Option<String>,
    warehouse: Option<String>,
    statement_timeout: Option<u32>,
}

/// A column's name/type/nullability, projected from the result-set metadata.
struct LiveColumn {
    name: String,
    type_name: String,
    nullable: bool,
}

/// The assembled rows plus the metadata an agent needs to interpret them.
struct LiveRows {
    statement_handle: String,
    sql_api_request_id: String,
    columns: Vec<LiveColumn>,
    rows: Vec<Vec<Option<String>>>,
    total_rows: i64,
    partition_count: usize,
    /// Partitions actually downloaded (inline partition 0 included); fewer than
    /// `partition_count` when the row cap stopped the fetch early.
    fetched_partitions: u32,
    partitions: Vec<(u32, u64, Option<u64>, Option<u64>)>,
    stats: DriverStats,
    /// The full completed statement (metadata + rows) for consumers that read
    /// the SQL API shape directly (the catalog crate's row normalizer).
    completed: CompletedStatement,
}

impl LiveRows {
    fn column_pairs(&self) -> Vec<(String, String)> {
        self.columns
            .iter()
            .map(|column| (column.name.clone(), column.type_name.clone()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// query run
// ---------------------------------------------------------------------------

/// Run one read-only statement live and return a `query run` envelope. Caller
/// guarantees `profile` is present and `sql` already passed the local read-only
/// safety check; credential and transport failures collapse to typed errors.
pub fn run_query_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    sql: &str,
    options: &QueryRunOptions,
) -> crate::Outcome {
    let fail = |error: &SnowflakeError, profile: String| {
        failure_outcome(
            format,
            "query.run",
            "fsnow.query.run.v1",
            request_id.clone(),
            profile,
            error,
        )
    };
    let mut request_options = match query_request_options(
        options.bindings_env.as_deref(),
        options.query_tag.as_deref(),
    ) {
        Ok(request_options) => request_options,
        Err(error) => return fail(&error, profile),
    };
    let emit_cap = match parse_limit(options.limit.as_deref()) {
        Ok(cap) => cap,
        Err(error) => return fail(&error, profile),
    };
    // Do not download partitions the envelope will never show.
    request_options.row_cap = Some(emit_cap);
    let overrides = match session_overrides(options, None, None) {
        Ok(overrides) => overrides,
        Err(error) => return fail(&error, profile),
    };
    let conn = match LiveConn::resolve(&profile, &overrides) {
        Ok(conn) => conn,
        Err(error) => return fail(&error, profile),
    };
    match execute(&conn, sql, request_options) {
        Ok(rows) => {
            if let Err(error) = enforce_require_live(options.require_live, DataSource::Live) {
                return fail(&error, profile);
            }
            let (receipt_hash, warnings) = record_receipt(
                "query.run",
                &conn,
                &request_id,
                sql,
                &rows,
                "statement_executed",
                serde_json::json!({}),
            );
            rows_success(
                format,
                request_id,
                profile,
                "query.run",
                "fsnow.query.run.v1",
                Vec::new(),
                &rows,
                emit_cap,
                receipt_hash,
                warnings,
                vec![
                    "franken-snowflake receipt show <receipt-hash> --json".to_string(),
                    "franken-snowflake query plan --profile <profile> --sql <sql> --json"
                        .to_string(),
                ],
            )
        }
        Err(error) => fail(&error, profile),
    }
}

// ---------------------------------------------------------------------------
// query run --dataset (planned, typed bindings)
// ---------------------------------------------------------------------------

/// Execute a dataset-mode plan live: the catalog planner's SQL runs with its
/// positional typed bindings and guardrails (statement timeout, QUERY_TAG),
/// under the dataset's database/schema and the requested session overrides.
pub fn run_dataset_query_outcome(
    format: OutputFormat,
    request_id: String,
    spec: crate::dataset_mode::DatasetQuerySpec,
    options: &QueryRunOptions,
) -> crate::Outcome {
    let planned = match crate::dataset_mode::plan_dataset(
        format,
        "query.run",
        "fsnow.query.run.v1",
        &request_id,
        &spec,
    ) {
        Ok(planned) => planned,
        Err(outcome) => return outcome,
    };
    let profile = planned.profile.clone();
    let fail = |error: &SnowflakeError| {
        failure_outcome(
            format,
            "query.run",
            "fsnow.query.run.v1",
            request_id.clone(),
            profile.clone(),
            error,
        )
    };
    let manifest = &planned.dataset.manifest;
    let mut overrides =
        match session_overrides(options, Some(&manifest.database), Some(&manifest.schema)) {
            Ok(overrides) => overrides,
            Err(error) => return fail(&error),
        };
    if overrides.statement_timeout.is_none() {
        overrides.statement_timeout = Some(planned.plan.guardrails.statement_timeout_seconds);
    }
    let conn = match LiveConn::resolve(&profile, &overrides) {
        Ok(conn) => conn,
        Err(error) => return fail(&error),
    };
    // Every planner binding becomes a positional SQL API binding; values never
    // enter the SQL text.
    let bindings: BTreeMap<String, Binding> = planned
        .plan
        .bindings
        .iter()
        .map(|(position, binding)| {
            (
                position.clone(),
                Binding::new(binding.binding_type.clone(), binding.value.clone()),
            )
        })
        .collect();
    let request_options = QueryRequestOptions {
        row_cap: None,
        bindings: (!bindings.is_empty()).then_some(bindings),
        query_tag: Some(planned.plan.guardrails.query_tag.clone()),
    };
    let rows = match execute(&conn, &planned.plan.sql, request_options) {
        Ok(rows) => {
            if let Err(error) = enforce_require_live(options.require_live, DataSource::Live) {
                return fail(&error);
            }
            rows
        }
        Err(error) => return fail(&error),
    };
    let (receipt_hash, warnings) = record_receipt(
        "query.run",
        &conn,
        &request_id,
        &planned.plan.sql,
        &rows,
        "statement_executed",
        serde_json::json!({
            "mode": "dataset",
            "dataset_id": manifest.id,
            "plan_id": planned.plan.plan_id,
        }),
    );
    let emit_cap = match parse_limit(options.limit.as_deref()) {
        Ok(cap) => cap,
        Err(error) => return fail(&error),
    };
    rows_success(
        format,
        request_id,
        profile,
        "query.run",
        "fsnow.query.run.v1",
        crate::dataset_mode::plan_json(&planned),
        &rows,
        emit_cap,
        receipt_hash,
        warnings,
        vec![
            "franken-snowflake receipt show <receipt-hash> --json".to_string(),
            format!("franken-snowflake dataset inspect {} --json", manifest.id),
        ],
    )
}

// ---------------------------------------------------------------------------
// query write
// ---------------------------------------------------------------------------

/// The authorized-write facts the live executor stamps into the execution
/// receipt. Built by the CLI from a core `WriteIntentDecision::ExecutionAuthorized`
/// plan; the core authorized the mutation, this struct carries the (non-secret)
/// identifiers the receipt envelope surfaces. No SQL is submitted until the CLI
/// has the authorized plan in hand.
pub struct AuthorizedWrite<'a> {
    /// The exact mutating statement the ladder authorized.
    pub sql: &'a str,
    /// Stable statement-kind token (e.g. `insert`, `copy_into_table`).
    pub statement_kind: &'a str,
    /// Coarse safety class token (e.g. `dml`, `external_file`).
    pub safety_class: &'a str,
    /// The write-intent ladder receipt / idempotency id (non-secret).
    pub idempotency_request_id: String,
    /// Optional session database/schema overrides (else the profile env applies).
    pub database: Option<String>,
    /// Optional session schema override.
    pub schema: Option<String>,
}

/// Execute an authorized mutating statement live and return an execution-receipt
/// envelope. The caller guarantees the write-intent ladder already authorized this
/// statement and that the profile is write-enabled. Reuses the exact submit ->
/// poll -> assemble transport as the read path; the SQL API does not distinguish
/// read from write. Credential/transport failures collapse to typed errors and
/// never claim `data_source = "live"`.
pub fn run_write_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    write: &AuthorizedWrite<'_>,
) -> crate::Outcome {
    let overrides = SessionOverrides {
        database: write.database.clone(),
        schema: write.schema.clone(),
        ..SessionOverrides::default()
    };
    let conn = match LiveConn::resolve(&profile, &overrides) {
        Ok(conn) => conn,
        Err(error) => {
            return failure_outcome(
                format,
                "query.write",
                "fsnow.query.write.v1",
                request_id,
                profile,
                &error,
            );
        }
    };
    match execute(&conn, write.sql, QueryRequestOptions::default()) {
        Ok(rows) => {
            let (receipt_hash, warnings) = record_receipt(
                "query.write",
                &conn,
                &request_id,
                write.sql,
                &rows,
                "write_executed",
                serde_json::json!({
                    "statement_kind": write.statement_kind,
                    "safety_class": write.safety_class,
                    "idempotency_request_id": write.idempotency_request_id,
                    "rows_affected": dml_rows_affected(&rows),
                }),
            );
            write_success(
                format,
                request_id,
                profile,
                write,
                &rows,
                receipt_hash,
                warnings,
            )
        }
        Err(error) => failure_outcome(
            format,
            "query.write",
            "fsnow.query.write.v1",
            request_id,
            profile,
            &error,
        ),
    }
}

/// Best-effort rows-affected for a DML statement. Snowflake's SQL API returns a
/// single result row whose numeric columns hold the affected counts (e.g. "number
/// of rows inserted"); sum the integer-parseable cells of the first row. Returns
/// `None` when the result is not a count shape (e.g. a stage `PUT`/`COPY` summary).
fn dml_rows_affected(rows: &LiveRows) -> Option<i64> {
    let first = rows.rows.first()?;
    let mut total: i64 = 0;
    let mut saw_count = false;
    for value in first.iter().flatten() {
        if let Ok(parsed) = value.trim().parse::<i64>() {
            saw_count = true;
            total = total.saturating_add(parsed);
        }
    }
    saw_count.then_some(total)
}

fn write_success(
    format: OutputFormat,
    request_id: String,
    profile: String,
    write: &AuthorizedWrite<'_>,
    rows: &LiveRows,
    receipt_hash: Option<String>,
    mut warnings: Vec<Json>,
) -> crate::Outcome {
    let returned = rows.rows.len().min(ROW_EMIT_CAP);
    let truncated = rows.rows.len() > ROW_EMIT_CAP;
    let rows_affected = dml_rows_affected(rows);

    let mut envelope = base_envelope(
        true,
        "success",
        "query.write",
        "fsnow.query.write.v1",
        request_id,
        json_object(vec![
            ("profile_id", json_string(profile.clone())),
            ("execution_enabled", Json::Bool(true)),
            (
                "statement_kind",
                json_string(write.statement_kind.to_string()),
            ),
            ("safety_class", json_string(write.safety_class.to_string())),
            (
                "write_intent_receipt_id",
                json_string(write.idempotency_request_id.clone()),
            ),
            (
                "idempotency_request_id",
                json_string(write.idempotency_request_id.clone()),
            ),
            (
                "rows_affected",
                rows_affected.map_or(Json::Null, Json::Number),
            ),
            ("columns", columns_json(rows)),
            ("rows", rows_json(rows, returned)),
            ("result_row_count", Json::Number(rows.total_rows)),
            ("returned_rows", Json::Number(returned as i64)),
            ("partition_count", Json::Number(rows.partition_count as i64)),
            ("row_emit_cap", Json::Number(ROW_EMIT_CAP as i64)),
            ("truncated", Json::Bool(truncated)),
            (
                "sql_api_request_id",
                json_string(rows.sql_api_request_id.clone()),
            ),
        ]),
    );
    stamp_live(&mut envelope, &profile, rows, receipt_hash);
    envelope.safe_next_commands = vec![
        "franken-snowflake receipt show <receipt-hash> --json".to_string(),
        "franken-snowflake query run --profile <profile> --sql <select-to-verify> --json"
            .to_string(),
    ];
    if truncated {
        warnings.push(json_string(format!(
            "write result truncated to {ROW_EMIT_CAP} rows in this envelope; {} total rows were \
             returned",
            rows.total_rows
        )));
    }
    envelope.warnings = warnings;
    crate::Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

// ---------------------------------------------------------------------------
// catalog scan / catalog graph
// ---------------------------------------------------------------------------

/// A live discovery scan: the snapshot, its store record, the two statements'
/// row sets, and what happened to persistence.
struct ScanResult {
    input: CatalogDiscoveryInput,
    snapshot: CatalogSnapshot,
    record: CatalogSnapshotRecord,
    tables: LiveRows,
    columns: LiveRows,
    store_dir: Option<String>,
    warnings: Vec<Json>,
}

/// Run the catalog crate's bound INFORMATION_SCHEMA discovery statements
/// (TABLES + COLUMNS) live, build the snapshot, and persist it to the local
/// store. `schema = None` scans every schema in the database.
fn scan_catalog(
    conn: &LiveConn,
    profile: &str,
    database: &str,
    schema: Option<&str>,
    trace_id: &str,
) -> Result<ScanResult, SnowflakeError> {
    let now_ms = local_store::now_unix_ms();
    let snapshot_id = format!(
        "snap-{}",
        &local_store::blake3_hex(&format!(
            "{profile}|{database}|{}|{now_ms}",
            schema.unwrap_or("*")
        ))[..24]
    );
    let input = CatalogDiscoveryInput {
        profile_id: profile.to_owned(),
        profile_fingerprint: format!("profile:{}", &local_store::blake3_hex(profile)[..16]),
        database: Some(database.to_owned()),
        schema: schema.map(str::to_owned),
        object: None,
        snapshot_id,
        discovered_at: local_store::rfc3339_utc(local_store::now_unix_seconds()),
        data_source: DataSourceClass::Live,
        command_id: "catalog.scan".to_owned(),
        trace_id: trace_id.to_owned(),
        redactions_applied: Vec::new(),
    };
    let requests = build_information_schema_requests(&input);
    let mut tables = None;
    let mut columns = None;
    for discovery in requests {
        match discovery.kind {
            DiscoveryStatementKind::Tables | DiscoveryStatementKind::Columns => {}
            DiscoveryStatementKind::Databases | DiscoveryStatementKind::Schemas => continue,
        }
        let mut request = discovery.request;
        apply_session(conn, &mut request);
        let (completed, stats, sql_api_request_id) = execute_request(conn, request, None)?;
        let rows = into_rows(completed, stats, sql_api_request_id);
        match discovery.kind {
            DiscoveryStatementKind::Tables => tables = Some(rows),
            DiscoveryStatementKind::Columns => columns = Some(rows),
            DiscoveryStatementKind::Databases | DiscoveryStatementKind::Schemas => {}
        }
    }
    let (Some(tables), Some(columns)) = (tables, columns) else {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::Internal,
            "discovery did not produce both TABLES and COLUMNS statements",
        ));
    };
    let discovery_tables = CatalogDiscoveryTables {
        databases: None,
        schemas: None,
        tables: tables.completed_view(),
        columns: columns.completed_view(),
    };
    let snapshot = build_snapshot_from_information_schema(&input, &discovery_tables);
    let canonical = serde_json::to_string(&snapshot).map_err(|error| {
        SnowflakeError::new(
            SnowflakeErrorCode::Internal,
            format!("snapshot serialization failed: {error}"),
        )
    })?;
    let record = CatalogSnapshotRecord {
        snapshot_id: input.snapshot_id.clone(),
        profile_id: profile.to_owned(),
        source_kind: "information_schema".to_owned(),
        database_name: Some(database.to_owned()),
        schema_name: schema.map(str::to_owned),
        captured_at_ms: now_ms,
        payload: VerifiedPayload {
            address: CacheAddress::blake3(canonical.as_bytes()),
            canonical,
        },
    };
    let mut warnings = Vec::new();
    let store_dir = match local_store::open_store() {
        Ok(store) => match persist_snapshot(&store.cache, &input, &snapshot, now_ms) {
            Ok(()) => Some(store.dir.display().to_string()),
            Err(error) => {
                warnings.push(json_string(format!(
                    "snapshot was not persisted to the local store: {error}"
                )));
                None
            }
        },
        Err(error) => {
            warnings.push(json_string(format!(
                "snapshot was not persisted: {}",
                error.message()
            )));
            None
        }
    };
    Ok(ScanResult {
        input,
        snapshot,
        record,
        tables,
        columns,
        store_dir,
        warnings,
    })
}

/// `catalog scan <profile> --database <db> --schema <schema>`: live discovery
/// through the catalog crate, persisted locally, summarized in the envelope.
pub fn run_catalog_scan_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    database: String,
    schema: String,
    require_live: bool,
) -> crate::Outcome {
    let fail = |error: &SnowflakeError| {
        failure_outcome(
            format,
            "catalog.scan",
            "fsnow.catalog.scan.v1",
            request_id.clone(),
            profile.clone(),
            error,
        )
    };
    if let Err(error) = validate_identifier("--database", &database) {
        return fail(&error);
    }
    if let Err(error) = validate_identifier("--schema", &schema) {
        return fail(&error);
    }
    let overrides = SessionOverrides {
        database: Some(database.clone()),
        schema: Some(schema.clone()),
        ..SessionOverrides::default()
    };
    let conn = match LiveConn::resolve(&profile, &overrides) {
        Ok(conn) => conn,
        Err(error) => return fail(&error),
    };
    let scan = match scan_catalog(&conn, &profile, &database, Some(&schema), &request_id) {
        Ok(scan) => scan,
        Err(error) => return fail(&error),
    };
    if let Err(error) = enforce_require_live(require_live, DataSource::Live) {
        return fail(&error);
    }
    let (receipt_hash, mut warnings) = record_receipt(
        "catalog.scan",
        &conn,
        &request_id,
        "INFORMATION_SCHEMA.TABLES + INFORMATION_SCHEMA.COLUMNS discovery",
        &scan.tables,
        "catalog_scanned",
        serde_json::json!({
            "snapshot_id": scan.input.snapshot_id,
            "columns_statement_handle": scan.columns.statement_handle,
            "dataset_count": scan.snapshot.datasets.len(),
            "column_count": scan.snapshot.columns.len(),
        }),
    );
    warnings.extend(scan.warnings.iter().cloned());

    let mut data = vec![
        ("profile_id", json_string(profile.clone())),
        ("database", json_string(database)),
        ("schema", json_string(schema)),
    ];
    data.extend(catalog_surface::snapshot_summary_json(&scan.snapshot));
    data.push((
        "statements",
        json_object(vec![
            (
                "tables",
                json_object(vec![
                    (
                        "statement_handle",
                        json_string(scan.tables.statement_handle.clone()),
                    ),
                    ("rows", Json::Number(scan.tables.total_rows)),
                    ("polls", Json::Number(i64::from(scan.tables.stats.polls))),
                ]),
            ),
            (
                "columns",
                json_object(vec![
                    (
                        "statement_handle",
                        json_string(scan.columns.statement_handle.clone()),
                    ),
                    ("rows", Json::Number(scan.columns.total_rows)),
                    ("polls", Json::Number(i64::from(scan.columns.stats.polls))),
                ]),
            ),
        ]),
    ));
    data.push((
        "store",
        json_object(vec![
            ("persisted", Json::Bool(scan.store_dir.is_some())),
            ("data_dir", option_json(scan.store_dir.clone())),
            ("snapshot_id", json_string(scan.input.snapshot_id.clone())),
        ]),
    ));
    let mut envelope = base_envelope(
        true,
        "success",
        "catalog.scan",
        "fsnow.catalog.scan.v1",
        request_id,
        json_object(data),
    );
    stamp_live(&mut envelope, &profile, &scan.tables, receipt_hash);
    envelope.budget_consumed = json_object(vec![
        ("deadline_ms", Json::Number(0)),
        (
            "polls",
            Json::Number(i64::from(scan.tables.stats.polls) + i64::from(scan.columns.stats.polls)),
        ),
        (
            "rows",
            Json::Number(
                scan.tables
                    .total_rows
                    .saturating_add(scan.columns.total_rows),
            ),
        ),
    ]);
    envelope.warnings = warnings;
    envelope.safe_next_commands = vec![
        "franken-snowflake dataset inspect <dataset-id> --json".to_string(),
        format!("franken-snowflake catalog graph {profile} --database <db> --mermaid"),
        "franken-snowflake dataset profile <dataset-id> --json".to_string(),
    ];
    crate::Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

/// `catalog graph` in the live build: render from the local snapshot when one
/// exists (and `--refresh` was not passed); otherwise scan live, persist, and
/// render that.
#[allow(clippy::too_many_arguments)]
pub fn run_catalog_graph_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    database: Option<String>,
    schema: Option<String>,
    graph_output: GraphOutput,
    refresh: bool,
) -> crate::Outcome {
    let fail = |error: &SnowflakeError| {
        failure_outcome(
            format,
            "catalog.graph",
            "fsnow.catalog.graph.v1",
            request_id.clone(),
            profile.clone(),
            error,
        )
    };
    if !refresh {
        let cached = local_store::open_store().ok().and_then(|store| {
            store
                .cache
                .latest_catalog_snapshot(&profile, database.as_deref(), schema.as_deref())
                .ok()
                .flatten()
        });
        if let Some(record) = cached
            && let Ok(snapshot) = serde_json::from_str::<CatalogSnapshot>(&record.payload.canonical)
        {
            return catalog_surface::render_graph_outcome(
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
            );
        }
    }
    let Some(database) = database else {
        return fail(&SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            "catalog graph needs --database (and optionally --schema) to scope the live scan; nothing is cached for this profile yet",
        ));
    };
    if let Err(error) = validate_identifier("--database", &database) {
        return fail(&error);
    }
    if let Some(schema_name) = &schema
        && let Err(error) = validate_identifier("--schema", schema_name)
    {
        return fail(&error);
    }
    let overrides = SessionOverrides {
        database: Some(database.clone()),
        schema: schema.clone(),
        ..SessionOverrides::default()
    };
    let conn = match LiveConn::resolve(&profile, &overrides) {
        Ok(conn) => conn,
        Err(error) => return fail(&error),
    };
    let scan = match scan_catalog(&conn, &profile, &database, schema.as_deref(), &request_id) {
        Ok(scan) => scan,
        Err(error) => return fail(&error),
    };
    let _ = record_receipt(
        "catalog.graph",
        &conn,
        &request_id,
        "INFORMATION_SCHEMA.TABLES + INFORMATION_SCHEMA.COLUMNS discovery",
        &scan.tables,
        "catalog_scanned",
        serde_json::json!({ "snapshot_id": scan.input.snapshot_id }),
    );
    let mut outcome = catalog_surface::render_graph_outcome(
        format,
        request_id,
        profile.clone(),
        Some(database),
        schema,
        &scan.snapshot,
        &scan.record,
        "live_scan",
        "live",
        graph_output,
    );
    if let Body::Envelope { envelope, .. } = &mut outcome.body {
        envelope.statement_handle = Some(scan.tables.statement_handle.clone());
        envelope.query_id = Some(scan.tables.statement_handle.clone());
        envelope.warnings.extend(scan.warnings);
    }
    outcome
}

// ---------------------------------------------------------------------------
// query cancel
// ---------------------------------------------------------------------------

/// `query cancel <handle> --profile <profile>`: POST to the SQL API cancel
/// endpoint with the profile's credentials.
pub fn run_query_cancel_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    statement_handle: String,
) -> crate::Outcome {
    let fail = |error: &SnowflakeError| {
        failure_outcome(
            format,
            "query.cancel",
            "fsnow.query.cancel.v1",
            request_id.clone(),
            profile.clone(),
            error,
        )
    };
    if statement_handle.is_empty()
        || statement_handle.len() > 128
        || !statement_handle
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    {
        return fail(&SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            "statement handle must be 1-128 ASCII letters, digits, or dashes",
        ));
    }
    let conn = match LiveConn::resolve(&profile, &SessionOverrides::default()) {
        Ok(conn) => conn,
        Err(error) => return fail(&error),
    };
    let handle = StatementHandle::new(statement_handle.clone());
    let response = match with_runtime(&conn, |cx, client, auth| {
        Box::pin(async move {
            let auth = auth.descriptor()?;
            match client
                .cancel_statement(
                    cx,
                    CancelHttpRequest {
                        auth,
                        statement_handle: handle,
                        reason_kind: CancelKind::User,
                    },
                )
                .await
            {
                Outcome::Ok(response) => Ok(response),
                Outcome::Err(error) => Err(error),
                Outcome::Cancelled(reason) => Err(SnowflakeError::new(
                    SnowflakeErrorCode::Internal,
                    format!("cancel request was cancelled locally: {:?}", reason.kind),
                )),
                Outcome::Panicked(_) => Err(SnowflakeError::new(
                    SnowflakeErrorCode::Internal,
                    "cancel task panicked",
                )),
            }
        })
    }) {
        Ok(response) => response,
        Err(error) => return fail(&error),
    };
    let status_label = status_class_label(response.status);
    let preview = redact(&String::from_utf8_lossy(
        &response.body[..response.body.len().min(CANCEL_BODY_PREVIEW_BYTES)],
    ))
    .into_owned();
    let acknowledged = matches!(response.status, StatusClass::Completed);
    let audit = local_store::open_store().ok().and_then(|store| {
        local_store::append_audit(
            &store,
            "query.cancel",
            &request_id,
            "statement_cancel_requested",
            &serde_json::json!({
                "profile_id": profile,
                "statement_handle": statement_handle,
                "cancel_status": status_label,
                "acknowledged": acknowledged,
            }),
            None,
        )
        .ok()
    });
    let mut envelope = base_envelope(
        acknowledged,
        if acknowledged { "success" } else { "error" },
        "query.cancel",
        "fsnow.query.cancel.v1",
        request_id,
        json_object(vec![
            ("profile_id", json_string(profile.clone())),
            ("statement_handle", json_string(statement_handle.clone())),
            ("cancel_status", json_string(status_label)),
            ("acknowledged", Json::Bool(acknowledged)),
            ("response_preview", json_string(preview.clone())),
            ("audit_event_id", option_json(audit)),
        ]),
    );
    envelope.data_source = "live";
    envelope.profile_id = Some(profile);
    envelope.statement_handle = Some(statement_handle);
    if !acknowledged {
        envelope.error = Some(error_info(
            SnowflakeErrorCode::UpstreamError,
            format!("cancel endpoint returned {status_label}: {preview}"),
            vec![json_string("live SQL API transport")],
        ));
        envelope.repair_commands =
            vec!["franken-snowflake profile doctor <profile> --online --json".to_string()];
    }
    envelope.safe_next_commands =
        vec!["franken-snowflake receipt show <receipt-hash> --json".to_string()];
    crate::Outcome {
        status: if acknowledged {
            CoreExitCode::Success
        } else {
            SnowflakeErrorCode::UpstreamError.exit_code()
        },
        body: Body::Envelope { envelope, format },
    }
}

fn status_class_label(status: StatusClass) -> &'static str {
    match status {
        StatusClass::Completed => "completed",
        StatusClass::Running => "running",
        StatusClass::StatementTimeout => "statement_timeout",
        StatusClass::QueryFailure => "query_failure",
        StatusClass::RateLimited => "rate_limited",
        StatusClass::ServerErrorRetryable => "server_error",
        StatusClass::Unauthorized => "unauthorized",
        StatusClass::Unexpected => "unexpected",
    }
}

// ---------------------------------------------------------------------------
// dataset profile --execute
// ---------------------------------------------------------------------------

/// `dataset profile <id> --execute`: run the pushdown profiling statement live
/// and return per-column statistics.
pub fn dataset_profile_execute_outcome(
    format: OutputFormat,
    request_id: String,
    dataset_id: String,
) -> crate::Outcome {
    let plan = match catalog_surface::resolve_profile_plan(format, &request_id, &dataset_id) {
        Ok(plan) => plan,
        Err(outcome) => return outcome,
    };
    let fail = |error: &SnowflakeError| {
        failure_outcome(
            format,
            "dataset.profile",
            "fsnow.dataset.profile.v1",
            request_id.clone(),
            plan.profile.clone(),
            error,
        )
    };
    let overrides = SessionOverrides {
        database: Some(plan.database.clone()),
        schema: Some(plan.schema.clone()),
        statement_timeout: Some(plan.statement_timeout_seconds),
        ..SessionOverrides::default()
    };
    let conn = match LiveConn::resolve(&plan.profile, &overrides) {
        Ok(conn) => conn,
        Err(error) => return fail(&error),
    };
    let rows = match execute(&conn, &plan.sql, QueryRequestOptions::default()) {
        Ok(rows) => rows,
        Err(error) => return fail(&error),
    };
    let (receipt_hash, warnings) = record_receipt(
        "dataset.profile",
        &conn,
        &request_id,
        &plan.sql,
        &rows,
        "dataset_profiled",
        serde_json::json!({ "dataset_id": plan.dataset_id }),
    );
    let stats: Vec<(String, Json)> = rows
        .rows
        .first()
        .map(|row| {
            rows.columns
                .iter()
                .zip(row.iter())
                .map(|(column, cell)| {
                    (
                        column.name.clone(),
                        cell.clone().map_or(Json::Null, json_string),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let mut data = catalog_surface::profile_plan_json(&plan, true);
    data.push(("stats", json_object_owned(stats)));
    let mut envelope = base_envelope(
        true,
        "success",
        "dataset.profile",
        "fsnow.dataset.profile.v1",
        request_id,
        json_object(data),
    );
    stamp_live(&mut envelope, &plan.profile, &rows, receipt_hash);
    envelope.warnings = warnings;
    envelope.safe_next_commands = vec![
        format!("franken-snowflake dataset inspect {dataset_id} --json"),
        "franken-snowflake receipt show <receipt-hash> --json".to_string(),
    ];
    crate::Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

// ---------------------------------------------------------------------------
// export run (local CSV/JSONL from a live result)
// ---------------------------------------------------------------------------

/// `export run --profile P --sql <select> --format csv|jsonl --out <path>`: run
/// the read live and write a content-addressed local artifact through the export
/// crate's streaming writers; record the export against the query receipt.
pub fn export_run_outcome(
    format: OutputFormat,
    request_id: String,
    spec: ExportPlanSpec,
    out: Option<String>,
) -> crate::Outcome {
    let profile = spec.profile.clone().unwrap_or_default();
    let fail = |error: &SnowflakeError| {
        failure_outcome(
            format,
            "export.run",
            "fsnow.export.run.v1",
            request_id.clone(),
            profile.clone(),
            error,
        )
    };
    let usage = |message: &str| SnowflakeError::new(SnowflakeErrorCode::UsageError, message);
    if profile.is_empty() {
        return fail(&usage(
            "Missing --profile for `export run`. Pass --profile <profile> or set FRANKEN_SNOWFLAKE_DEFAULT_PROFILE.",
        ));
    }
    let Some(out_path) = out else {
        return fail(&usage("Missing --out <path> for `export run`."));
    };
    let sql = match (spec.sql.clone(), spec.query_id.clone()) {
        (Some(sql), None) => sql,
        (None, Some(query_id)) => match (CopySource::ResultScan { query_id }).to_sql() {
            Ok(sql) => sql,
            Err(error) => return fail(&usage(&format!("export run refused: {error}"))),
        },
        (None, None) => return fail(&usage("Provide --sql <select> or --query-id <id>.")),
        (Some(_), Some(_)) => return fail(&usage("Choose either --sql or --query-id, not both.")),
    };
    if !crate::is_select_like(&sql) || crate::has_multiple_statements(&sql) {
        return fail(&SnowflakeError::new(
            SnowflakeErrorCode::MutationRefused,
            "export run only exports a single read statement (SELECT/WITH/SHOW/DESCRIBE/EXPLAIN)",
        ));
    }
    let export_format = match spec
        .format
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None | Some("csv") => "csv",
        Some("jsonl") | Some("json") => "jsonl",
        Some(other) => {
            return fail(&usage(&format!(
                "Unknown --format `{other}`; use csv or jsonl."
            )));
        }
    };
    let conn = match LiveConn::resolve(&profile, &SessionOverrides::default()) {
        Ok(conn) => conn,
        Err(error) => return fail(&error),
    };
    let rows = match execute(&conn, &sql, QueryRequestOptions::default()) {
        Ok(rows) => rows,
        Err(error) => return fail(&error),
    };
    let input = LocalExportInput::new(
        rows.columns
            .iter()
            .map(|column| {
                ExportColumn::new(column.name.clone(), column.type_name.clone())
                    .nullable(column.nullable)
            })
            .collect(),
        vec![ResultPartition::new(0, rows.rows.clone())],
    );
    let created_at_ms = local_store::now_unix_ms();
    let target_label = redact(&out_path).into_owned();
    let artifact = match export_format {
        "csv" => export_csv(&input, target_label.clone(), created_at_ms),
        _ => export_jsonl(&input, target_label.clone(), created_at_ms),
    };
    let artifact = match artifact {
        Ok(artifact) => artifact,
        Err(error) => {
            return fail(&SnowflakeError::new(
                SnowflakeErrorCode::UsageError,
                format!("local export failed: {error}"),
            ));
        }
    };
    if let Err(error) = std::fs::write(&out_path, &artifact.bytes) {
        return fail(&SnowflakeError::new(
            SnowflakeErrorCode::Internal,
            format!("could not write {target_label}: {error}"),
        ));
    }
    let (receipt_hash, mut warnings) = record_receipt(
        "export.run",
        &conn,
        &request_id,
        &sql,
        &rows,
        "export_written",
        serde_json::json!({
            "format": export_format,
            "export_id": artifact.receipt.export_id,
            "content_hash": artifact.receipt.content_address.digest_hex,
            "byte_len": artifact.receipt.content_address.byte_len,
        }),
    );
    if let (Some(receipt_id), Ok(store)) = (receipt_hash.as_ref(), local_store::open_store()) {
        let record = ExportRecord {
            export_id: artifact.receipt.export_id.clone(),
            receipt_id: receipt_id.clone(),
            export_kind: if export_format == "csv" {
                ExportKind::LocalCsv
            } else {
                ExportKind::LocalJsonl
            },
            target_uri_redacted: target_label.clone(),
            content_address: CacheAddress {
                algorithm: artifact.receipt.content_address.algorithm.clone(),
                digest_hex: artifact.receipt.content_address.digest_hex.clone(),
                byte_len: artifact.receipt.content_address.byte_len,
            },
            row_count: artifact.receipt.row_count,
            created_at_ms,
        };
        if let Err(error) = store.cache.append_export(record) {
            warnings.push(json_string(format!("export record not persisted: {error}")));
        }
    }
    let mut envelope = base_envelope(
        true,
        "success",
        "export.run",
        "fsnow.export.run.v1",
        request_id,
        json_object(vec![
            ("profile_id", json_string(profile.clone())),
            ("format", json_string(export_format)),
            ("out", json_string(target_label)),
            (
                "bytes_written",
                Json::Number(i64::try_from(artifact.bytes.len()).unwrap_or(i64::MAX)),
            ),
            ("row_count", Json::Number(rows.total_rows)),
            ("export_receipt", Json::from_value(&artifact.receipt)),
            (
                "export_log_line",
                json_string(artifact.log_line.trim_end().to_string()),
            ),
        ]),
    );
    stamp_live(&mut envelope, &profile, &rows, receipt_hash);
    envelope.warnings = warnings;
    envelope.safe_next_commands =
        vec!["franken-snowflake receipt show <receipt-hash> --json".to_string()];
    crate::Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

// ---------------------------------------------------------------------------
// profile doctor --online
// ---------------------------------------------------------------------------

/// Attempt a real credential/connectivity probe for `profile doctor --online`:
/// run a minimal `SELECT CURRENT_VERSION()` and report whether it succeeded,
/// without ever reading or emitting a secret value. A missing credential handle
/// collapses to a typed error (exit 3), never a silent "healthy".
pub fn profile_doctor_online_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
) -> crate::Outcome {
    const PROBE_SQL: &str = "SELECT CURRENT_VERSION() AS SNOWFLAKE_VERSION";
    let conn = match LiveConn::resolve(&profile, &SessionOverrides::default()) {
        Ok(conn) => conn,
        Err(error) => {
            return failure_outcome(
                format,
                "profile.doctor",
                "fsnow.profile.doctor.v1",
                request_id,
                profile,
                &error,
            );
        }
    };
    match execute(&conn, PROBE_SQL, QueryRequestOptions::default()) {
        Ok(rows) => {
            let version = rows
                .rows
                .first()
                .and_then(|row| row.first())
                .and_then(Clone::clone);
            let (receipt_hash, warnings) = record_receipt(
                "profile.doctor",
                &conn,
                &request_id,
                PROBE_SQL,
                &rows,
                "profile_probed",
                serde_json::json!({ "snowflake_version": version }),
            );
            probe_success(
                format,
                request_id,
                profile,
                version,
                &rows,
                receipt_hash,
                warnings,
            )
        }
        Err(error) => failure_outcome(
            format,
            "profile.doctor",
            "fsnow.profile.doctor.v1",
            request_id,
            profile,
            &error,
        ),
    }
}

fn probe_success(
    format: OutputFormat,
    request_id: String,
    profile: String,
    version: Option<String>,
    rows: &LiveRows,
    receipt_hash: Option<String>,
    warnings: Vec<Json>,
) -> crate::Outcome {
    let data = json_object(vec![
        ("profile_id", json_string(profile.clone())),
        ("live_probe_requested", Json::Bool(true)),
        ("live_probe_attempted", Json::Bool(true)),
        ("live_probe_ok", Json::Bool(true)),
        ("secret_values_read", Json::Bool(false)),
        (
            "snowflake_version",
            match version {
                Some(value) => json_string(value),
                None => Json::Null,
            },
        ),
        (
            "redaction_policy",
            json_string("env var names only; token/private-key values are never emitted"),
        ),
    ]);
    let mut envelope = base_envelope(
        true,
        "success",
        "profile.doctor",
        "fsnow.profile.doctor.v1",
        request_id,
        data,
    );
    stamp_live(&mut envelope, &profile, rows, receipt_hash);
    envelope.warnings = warnings;
    envelope.safe_next_commands = vec![
        "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
            .to_string(),
        "franken-snowflake query run --profile <profile> --sql <sql> --json".to_string(),
    ];
    crate::Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

// ---------------------------------------------------------------------------
// Shared: connection resolution, execution, receipts, envelopes
// ---------------------------------------------------------------------------

/// A profile's resolved live connection inputs (no secret values; the PAT/key is
/// referenced only through a `SecretSource` resolved at request time).
struct LiveConn {
    profile: String,
    account: String,
    user: String,
    warehouse: String,
    database: Option<String>,
    schema: Option<String>,
    role: Option<String>,
    statement_timeout_seconds: u32,
    endpoint: SnowflakeEndpoint,
    auth_profile: AuthProfile,
    max_polls: u32,
    /// Partition fetch window (`<PREFIX>_PARTITION_CONCURRENCY`, default 4).
    partition_concurrency: usize,
    /// Test-only: answers every `execute_request` from a script instead of the
    /// SQL API (see `test_support`). Always `None` in production builds.
    #[cfg(test)]
    script: Option<test_support::Script>,
}

impl LiveConn {
    fn resolve(profile: &str, overrides: &SessionOverrides) -> Result<Self, SnowflakeError> {
        #[cfg(test)]
        if let Some(conn) = test_support::scripted_conn(profile, overrides) {
            return Ok(conn);
        }
        if !crate::is_valid_profile_id(profile) {
            return Err(SnowflakeError::new(
                SnowflakeErrorCode::ProfileInvalid,
                "profile id must be 1-128 ASCII letters, digits, dot, dash, or underscore",
            ));
        }
        let prefix = crate::profile_env_prefix(profile);

        let account = env_value(&name(&prefix, "ACCOUNT"));
        let user = env_value(&name(&prefix, "USER"));
        let auth_lane = env_value(&name(&prefix, "AUTH"));
        let warehouse = overrides
            .warehouse
            .clone()
            .or_else(|| env_value(&name(&prefix, "WAREHOUSE")));

        let mut missing = Vec::new();
        if account.is_none() {
            missing.push(name(&prefix, "ACCOUNT"));
        }
        if user.is_none() {
            missing.push(name(&prefix, "USER"));
        }
        if auth_lane.is_none() {
            missing.push(name(&prefix, "AUTH"));
        }
        if warehouse.is_none() {
            missing.push(name(&prefix, "WAREHOUSE"));
        }

        let lane = auth_lane.clone().unwrap_or_default();
        let secret_env = secret_env_for_lane(&prefix, &lane);
        if let Some(secret_env) = &secret_env
            && env_value(secret_env).is_none()
        {
            missing.push(secret_env.clone());
        }
        if !missing.is_empty() {
            return Err(SnowflakeError::new(
                SnowflakeErrorCode::CredentialMissing,
                format!(
                    "missing required env handles for profile credentials: {}",
                    missing.join(", ")
                ),
            ));
        }
        if secret_env.is_none() {
            return Err(SnowflakeError::new(
                SnowflakeErrorCode::ProfileInvalid,
                format!("auth lane must be one of pat, oauth_bearer, or key_pair_jwt (got {lane})"),
            ));
        }

        let account = account.unwrap_or_default();
        let endpoint = SnowflakeEndpoint::parse(endpoint_url(&account)).map_err(|error| {
            SnowflakeError::new(SnowflakeErrorCode::ProfileInvalid, error.message)
        })?;
        let auth_profile = build_auth_profile(&prefix, &lane)?;
        let statement_timeout_seconds = overrides
            .statement_timeout
            .or_else(|| env_u32(&name(&prefix, "STATEMENT_TIMEOUT_SECONDS")))
            .unwrap_or(DEFAULT_STATEMENT_TIMEOUT_SECONDS)
            .clamp(1, MAX_STATEMENT_TIMEOUT_SECONDS);

        Ok(Self {
            profile: profile.to_owned(),
            account,
            user: user.unwrap_or_default(),
            warehouse: warehouse.unwrap_or_default(),
            database: overrides
                .database
                .clone()
                .or_else(|| env_value(&name(&prefix, "DATABASE"))),
            schema: overrides
                .schema
                .clone()
                .or_else(|| env_value(&name(&prefix, "SCHEMA"))),
            role: overrides
                .role
                .clone()
                .or_else(|| env_value(&name(&prefix, "ROLE"))),
            statement_timeout_seconds,
            endpoint,
            auth_profile,
            max_polls: env_u32(&name(&prefix, "MAX_POLLS")).unwrap_or(DEFAULT_MAX_POLLS),
            partition_concurrency: env_u32(&name(&prefix, "PARTITION_CONCURRENCY"))
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(DEFAULT_PARTITION_CONCURRENCY)
                .clamp(1, MAX_PARTITION_CONCURRENCY),
            #[cfg(test)]
            script: None,
        })
    }
}

/// Validate the `--limit`/`--role`/`--warehouse`/`--statement-timeout` flags a
/// run passed; a bad value is a usage error, never silently ignored.
fn session_overrides(
    options: &QueryRunOptions,
    database: Option<&str>,
    schema: Option<&str>,
) -> Result<SessionOverrides, SnowflakeError> {
    if let Some(role) = &options.role {
        validate_identifier("--role", role)?;
    }
    if let Some(warehouse) = &options.warehouse {
        validate_identifier("--warehouse", warehouse)?;
    }
    let statement_timeout = match options.statement_timeout.as_deref() {
        None => None,
        Some(raw) => match raw.parse::<u32>() {
            Ok(value) if (1..=MAX_STATEMENT_TIMEOUT_SECONDS).contains(&value) => Some(value),
            _ => {
                return Err(SnowflakeError::new(
                    SnowflakeErrorCode::UsageError,
                    format!(
                        "--statement-timeout must be 1..={MAX_STATEMENT_TIMEOUT_SECONDS} seconds (got `{raw}`)"
                    ),
                ));
            }
        },
    };
    Ok(SessionOverrides {
        database: database.map(str::to_owned),
        schema: schema.map(str::to_owned),
        role: options.role.clone(),
        warehouse: options.warehouse.clone(),
        statement_timeout,
    })
}

fn parse_limit(raw: Option<&str>) -> Result<usize, SnowflakeError> {
    match raw {
        None => Ok(ROW_EMIT_CAP),
        Some(raw) => match raw.parse::<usize>() {
            Ok(value) if (1..=MAX_ROW_EMIT_CAP).contains(&value) => Ok(value),
            _ => Err(SnowflakeError::new(
                SnowflakeErrorCode::UsageError,
                format!("--limit must be 1..={MAX_ROW_EMIT_CAP} rows (got `{raw}`)"),
            )),
        },
    }
}

fn validate_identifier(flag: &str, value: &str) -> Result<(), SnowflakeError> {
    if is_safe_sql_identifier(value) {
        Ok(())
    } else {
        Err(SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            format!("{flag} must be a plain SQL identifier (letters, digits, _ or $)"),
        ))
    }
}

/// The resolved auth mechanism as the driver's [`AuthProvider`]: every request
/// re-derives its bearer (so a key-pair JWT is re-signed near expiry while a
/// statement keeps polling) and a `401` re-signs once for the JWT lane.
struct MechanismAuth {
    mechanism: AuthMechanism,
}

impl AuthProvider for MechanismAuth {
    fn descriptor(&mut self) -> Result<AuthorizationDescriptor, SnowflakeError> {
        authorization_descriptor(&mut self.mechanism)
    }

    fn on_unauthorized(&mut self) -> Result<bool, SnowflakeError> {
        match self.mechanism.on_unauthorized_mid_poll(now_unix_seconds()) {
            ReauthDecision::ResignJwt { .. } => Ok(true),
            ReauthDecision::ReauthRequired { .. } | ReauthDecision::NotRequired => Ok(false),
        }
    }
}

/// Run `body` inside a fresh Asupersync runtime with the resolved client + auth.
fn with_runtime<T, F>(conn: &LiveConn, body: F) -> Result<T, SnowflakeError>
where
    F: for<'a> FnOnce(
        &'a Cx,
        &'a SnowflakeHttpClient,
        &'a mut MechanismAuth,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<T, SnowflakeError>> + 'a>,
    >,
{
    let runtime = RuntimeBuilder::current_thread().build().map_err(|error| {
        SnowflakeError::new(
            SnowflakeErrorCode::Internal,
            format!("failed to start the async runtime: {error}"),
        )
    })?;
    runtime.block_on(async move {
        let cx = Cx::current().ok_or_else(|| {
            SnowflakeError::new(
                SnowflakeErrorCode::Internal,
                "async runtime did not install an ambient context",
            )
        })?;
        let client = SnowflakeHttpClient::default_for_runtime(
            TransportConfig::new(conn.endpoint.clone()),
            &cx,
        );
        let mechanism = conn
            .auth_profile
            .resolve(&ProcessSecretResolver, &conn.account, &conn.user)
            .map_err(|error| {
                SnowflakeError::new(SnowflakeErrorCode::CredentialMissing, error.to_string())
            })?;
        let mut auth = MechanismAuth { mechanism };
        // Resolve once up front so a missing/invalid credential fails before
        // any request is built, with the same typed error as before.
        auth.descriptor()?;
        body(&cx, &client, &mut auth).await
    })
}

/// Submit one prepared request and drive it to completion. Returns the completed
/// statement, the driver's poll/partition stats, and the SQL API `requestId`.
fn execute_request(
    conn: &LiveConn,
    request: SubmitStatementRequest,
    row_cap: Option<usize>,
) -> Result<(CompletedStatement, DriverStats, String), SnowflakeError> {
    #[cfg(test)]
    if let Some(script) = &conn.script {
        return script.execute(request, row_cap);
    }
    let sql_api_request_id = unique_request_id();
    let params = SubmitQueryParams {
        request_id: Some(sql_api_request_id.clone()),
        retry: true,
        asynchronous: false,
        nullable: None,
    };
    let max_polls = conn.max_polls;
    let poll_plan = PollPlan::with_max_polls(max_polls)
        .with_partition_concurrency(conn.partition_concurrency)
        .with_row_cap(row_cap);
    let (outcome, stats) = with_runtime(conn, move |cx, client, auth| {
        Box::pin(async move {
            Ok(run_statement_with_auth(cx, client, auth, request, params, poll_plan).await)
        })
    })?;
    match outcome {
        Outcome::Ok(done) => Ok((done, stats, sql_api_request_id)),
        Outcome::Err(error) => Err(error),
        Outcome::Cancelled(reason) => Err(SnowflakeError::new(
            SnowflakeErrorCode::Internal,
            format!(
                "statement was cancelled before completion: {:?}",
                reason.kind
            ),
        )),
        Outcome::Panicked(_) => Err(SnowflakeError::new(
            SnowflakeErrorCode::Internal,
            "statement task panicked before completion",
        )),
    }
}

/// Build the request for `sql` from the resolved connection, run it, assemble rows.
fn execute(
    conn: &LiveConn,
    sql: &str,
    options: QueryRequestOptions,
) -> Result<LiveRows, SnowflakeError> {
    let row_cap = options.row_cap;
    let request = build_request(conn, sql, options);
    let (done, stats, sql_api_request_id) = execute_request(conn, request, row_cap)?;
    Ok(into_rows(done, stats, sql_api_request_id))
}

/// Stamp session context from the connection onto a prepared request (used for
/// the catalog crate's discovery statements, which carry only SQL + bindings).
fn apply_session(conn: &LiveConn, request: &mut SubmitStatementRequest) {
    request.timeout = Some(conn.statement_timeout_seconds);
    request.warehouse = Some(WarehouseName::new(conn.warehouse.clone()));
    if request.database.is_none() {
        request.database = conn.database.clone().map(DatabaseName::new);
    }
    if request.schema.is_none() {
        request.schema = conn.schema.clone().map(SchemaName::new);
    }
    request.role = conn.role.clone().map(RoleName::new);
    let mut parameters = deterministic_session_parameters();
    if let Some(existing) = request.parameters.take() {
        parameters.extend(existing);
    }
    request.parameters = Some(parameters);
}

/// Write the receipt/audit trail for a completed execution. Returns the receipt
/// hash and any warnings (a store failure is a warning, never a fake hash).
fn record_receipt(
    command_id: &str,
    conn: &LiveConn,
    trace_id: &str,
    sql: &str,
    rows: &LiveRows,
    event_kind: &str,
    extra: serde_json::Value,
) -> (Option<String>, Vec<Json>) {
    let store: Store = match local_store::open_store() {
        Ok(store) => store,
        Err(error) => {
            return (
                None,
                vec![json_string(format!(
                    "receipt not recorded: {}",
                    error.message()
                ))],
            );
        }
    };
    let preview = crate::compact_sql(&redact(sql));
    let columns = rows.column_pairs();
    let facts = ExecutionFacts {
        command_id,
        profile: &conn.profile,
        trace_id,
        sql_preview_redacted: &preview,
        statement_handle: &rows.statement_handle,
        sql_api_request_id: Some(&rows.sql_api_request_id),
        row_count: u64::try_from(rows.total_rows).unwrap_or(0),
        partitions: &rows.partitions,
        columns: &columns,
        warehouse: Some(&conn.warehouse),
        database: conn.database.as_deref(),
        schema: conn.schema.as_deref(),
        role: conn.role.as_deref(),
        statement_timeout_seconds: conn.statement_timeout_seconds,
        polls: u64::from(rows.stats.polls),
        event_kind,
        extra,
    };
    match local_store::record_execution(&store, &facts) {
        Ok(hash) => (Some(hash), Vec::new()),
        Err(error) => (
            None,
            vec![json_string(format!("receipt not recorded: {error}"))],
        ),
    }
}

/// Stamp the live provenance fields shared by every successful live envelope.
fn stamp_live(
    envelope: &mut crate::Envelope,
    profile: &str,
    rows: &LiveRows,
    receipt_hash: Option<String>,
) {
    envelope.data_source = "live";
    envelope.profile_id = Some(profile.to_owned());
    envelope.statement_handle = Some(rows.statement_handle.clone());
    envelope.query_id = Some(rows.statement_handle.clone());
    envelope.receipt_hash = receipt_hash;
    envelope.budget_consumed = json_object(vec![
        ("deadline_ms", Json::Number(0)),
        ("polls", Json::Number(i64::from(rows.stats.polls))),
        ("rows", Json::Number(rows.total_rows)),
    ]);
}

/// The secret env-var name a given auth lane requires, or `None` for an
/// unknown/unsupported lane.
fn secret_env_for_lane(prefix: &str, lane: &str) -> Option<String> {
    match lane {
        "pat" | "programmatic_access_token" => Some(name(prefix, "PAT")),
        "oauth" | "oauth_bearer" | "oauth_bearer_token" => Some(name(prefix, "OAUTH_BEARER")),
        "key_pair_jwt" | "jwt" => Some(name(prefix, "PRIVATE_KEY_PEM")),
        _ => None,
    }
}

fn build_auth_profile(prefix: &str, lane: &str) -> Result<AuthProfile, SnowflakeError> {
    let credential =
        |detail: String| SnowflakeError::new(SnowflakeErrorCode::CredentialMissing, detail);
    match lane {
        "pat" | "programmatic_access_token" => Ok(AuthProfile::pat(
            SecretSource::env_var(name(prefix, "PAT"))
                .map_err(|error| credential(error.to_string()))?,
        )),
        "oauth" | "oauth_bearer" | "oauth_bearer_token" => Ok(AuthProfile::oauth_bearer(
            SecretSource::env_var(name(prefix, "OAUTH_BEARER"))
                .map_err(|error| credential(error.to_string()))?,
        )),
        "key_pair_jwt" | "jwt" => Ok(AuthProfile::key_pair_jwt(
            SecretSource::env_var(name(prefix, "PRIVATE_KEY_PEM"))
                .map_err(|error| credential(error.to_string()))?,
            env_value(&name(prefix, "PRIVATE_KEY_PASSPHRASE"))
                .map(|_| SecretSource::env_var(name(prefix, "PRIVATE_KEY_PASSPHRASE")))
                .transpose()
                .map_err(|error| credential(error.to_string()))?,
            env_u64(&name(prefix, "JWT_VALIDITY_SECONDS")).unwrap_or(3600),
        )),
        other => Err(SnowflakeError::new(
            SnowflakeErrorCode::ProfileInvalid,
            format!("auth lane must be one of pat, oauth_bearer, or key_pair_jwt (got {other})"),
        )),
    }
}

fn build_request(
    conn: &LiveConn,
    sql: &str,
    options: QueryRequestOptions,
) -> SubmitStatementRequest {
    let mut request = SubmitStatementRequest::new(sql);
    apply_session(conn, &mut request);
    apply_query_request_options(&mut request, options);
    request
}

fn apply_query_request_options(request: &mut SubmitStatementRequest, options: QueryRequestOptions) {
    request.bindings = options.bindings;
    if let Some(query_tag) = options.query_tag {
        request
            .parameters
            .get_or_insert_with(BTreeMap::new)
            .insert("QUERY_TAG".to_owned(), query_tag);
    }
}

fn query_request_options(
    bindings_env: Option<&str>,
    query_tag: Option<&str>,
) -> Result<QueryRequestOptions, SnowflakeError> {
    let bindings = bindings_env.map(parse_bindings_env).transpose()?;
    let query_tag = query_tag.map(validate_query_tag).transpose()?;
    Ok(QueryRequestOptions {
        row_cap: None,
        bindings,
        query_tag,
    })
}

fn parse_bindings_env(env_name: &str) -> Result<BTreeMap<String, Binding>, SnowflakeError> {
    if !is_safe_env_name(env_name) {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            "--bindings-env must name a 1-128 byte ASCII environment variable",
        ));
    }
    let encoded = std::env::var(env_name).map_err(|_| {
        SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            format!("bindings environment variable `{env_name}` is unset or unreadable"),
        )
    })?;
    if encoded.len() > MAX_BINDINGS_JSON_BYTES {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            format!("bindings payload exceeds {MAX_BINDINGS_JSON_BYTES} bytes"),
        ));
    }
    let bindings =
        serde_json::from_str::<BTreeMap<String, Binding>>(&encoded).map_err(|error| {
            SnowflakeError::new(
                SnowflakeErrorCode::UsageError,
                format!("bindings payload is not a typed positional binding object: {error}"),
            )
        })?;
    validate_bindings(&bindings)?;
    Ok(bindings)
}

fn validate_bindings(bindings: &BTreeMap<String, Binding>) -> Result<(), SnowflakeError> {
    if bindings.is_empty() || bindings.len() > MAX_BINDING_COUNT {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            format!("bindings must contain 1..={MAX_BINDING_COUNT} positional values"),
        ));
    }
    let mut positions = bindings
        .keys()
        .map(|key| {
            key.parse::<usize>().map_err(|_| {
                SnowflakeError::new(
                    SnowflakeErrorCode::UsageError,
                    "binding keys must be 1-based decimal positions",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    positions.sort_unstable();
    if positions.iter().copied().ne(1..=bindings.len()) {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            "binding keys must be contiguous 1-based positions",
        ));
    }
    if bindings
        .values()
        .any(|binding| !is_safe_binding_type(&binding.value_type))
    {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            "binding type names must be uppercase Snowflake type tokens",
        ));
    }
    Ok(())
}

fn validate_query_tag(query_tag: &str) -> Result<String, SnowflakeError> {
    if query_tag.is_empty()
        || query_tag.len() > MAX_QUERY_TAG_BYTES
        || query_tag.chars().any(char::is_control)
    {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            format!(
                "--query-tag must be 1..={MAX_QUERY_TAG_BYTES} bytes without control characters"
            ),
        ));
    }
    Ok(query_tag.to_owned())
}

fn is_safe_env_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    value.len() <= 128
        && (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn is_safe_binding_type(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    value.len() <= 64
        && first.is_ascii_uppercase()
        && chars.all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
}

fn authorization_descriptor(
    mechanism: &mut impl SnowflakeAuth,
) -> Result<AuthorizationDescriptor, SnowflakeError> {
    let headers = mechanism.headers_at(now_unix_seconds()).map_err(|error| {
        SnowflakeError::new(SnowflakeErrorCode::CredentialMissing, error.to_string())
    })?;
    let bearer = headers
        .authorization_value()
        .strip_prefix("Bearer ")
        .ok_or_else(|| {
            SnowflakeError::new(
                SnowflakeErrorCode::Internal,
                "authorization header did not contain a bearer token",
            )
        })?;
    let token_type = match headers.token_type_value() {
        PROGRAMMATIC_ACCESS_TOKEN_TYPE => SnowflakeAuthTokenType::ProgrammaticAccessToken,
        KEYPAIR_JWT_TOKEN_TYPE => SnowflakeAuthTokenType::KeypairJwt,
        OAUTH_TOKEN_TYPE => SnowflakeAuthTokenType::OAuth,
        other => {
            return Err(SnowflakeError::new(
                SnowflakeErrorCode::Internal,
                format!("unsupported auth token type: {other}"),
            ));
        }
    };
    Ok(AuthorizationDescriptor::bearer(
        token_type,
        bearer,
        mechanism
            .credential_handle()
            .unwrap_or("cred_resolved_without_handle"),
    ))
}

impl LiveRows {
    /// A lightweight `CompletedStatement` view for the catalog crate's row
    /// normalizer (which reads `rows` and `result_set.result_set_meta_data`).
    fn completed_view(&self) -> CompletedStatement {
        self.completed.clone()
    }
}

fn into_rows(done: CompletedStatement, stats: DriverStats, sql_api_request_id: String) -> LiveRows {
    let columns = done
        .result_set
        .result_set_meta_data
        .row_type
        .iter()
        .map(|column| LiveColumn {
            name: column.name.clone(),
            type_name: column.column_type.clone(),
            nullable: column.nullable,
        })
        .collect();
    let total_rows = done.result_set.total_rows();
    let partition_count = done.result_set.partition_count();
    let partitions = done
        .result_set
        .result_set_meta_data
        .partition_info
        .iter()
        .enumerate()
        .map(|(index, info)| {
            (
                u32::try_from(index).unwrap_or(u32::MAX),
                u64::try_from(info.row_count).unwrap_or(0),
                info.compressed_size.and_then(|v| u64::try_from(v).ok()),
                info.uncompressed_size.and_then(|v| u64::try_from(v).ok()),
            )
        })
        .collect();
    let statement_handle = done.statement_handle.as_str().to_string();
    LiveRows {
        statement_handle,
        sql_api_request_id,
        columns,
        total_rows,
        partition_count,
        fetched_partitions: done.fetched_partitions,
        partitions,
        stats,
        rows: done.rows.clone(),
        completed: done,
    }
}

fn columns_json(rows: &LiveRows) -> Json {
    json_array(
        rows.columns
            .iter()
            .map(|column| {
                json_object(vec![
                    ("name", json_string(column.name.clone())),
                    ("type", json_string(column.type_name.clone())),
                    ("nullable", Json::Bool(column.nullable)),
                ])
            })
            .collect(),
    )
}

fn rows_json(rows: &LiveRows, returned: usize) -> Json {
    json_array(
        rows.rows
            .iter()
            .take(returned)
            .map(|row| {
                json_array(
                    row.iter()
                        .map(|cell| match cell {
                            Some(value) => json_string(value.clone()),
                            None => Json::Null,
                        })
                        .collect(),
                )
            })
            .collect(),
    )
}

/// Build a `data_source = "live"` success envelope carrying assembled rows. The
/// rows are projected positionally (matching the `columns` order, the jsonv2
/// shape) and capped at `emit_cap` with an explicit `truncated` flag.
#[allow(clippy::too_many_arguments)]
fn rows_success(
    format: OutputFormat,
    request_id: String,
    profile: String,
    command_id: &'static str,
    output_contract_id: &'static str,
    mut leading: Vec<(&'static str, Json)>,
    rows: &LiveRows,
    emit_cap: usize,
    receipt_hash: Option<String>,
    mut warnings: Vec<Json>,
    safe_next_commands: Vec<String>,
) -> crate::Outcome {
    let returned = rows.rows.len().min(emit_cap);
    let truncated = rows.rows.len() > emit_cap;
    leading.extend(vec![
        ("columns", columns_json(rows)),
        ("rows", rows_json(rows, returned)),
        ("row_count", Json::Number(rows.total_rows)),
        ("returned_rows", Json::Number(returned as i64)),
        ("partition_count", Json::Number(rows.partition_count as i64)),
        (
            "partitions_fetched",
            Json::Number(i64::from(rows.fetched_partitions)),
        ),
        ("row_emit_cap", Json::Number(emit_cap as i64)),
        ("truncated", Json::Bool(truncated)),
        (
            "sql_api_request_id",
            json_string(rows.sql_api_request_id.clone()),
        ),
    ]);

    let mut envelope = base_envelope(
        true,
        "success",
        command_id,
        output_contract_id,
        request_id,
        json_object(leading),
    );
    stamp_live(&mut envelope, &profile, rows, receipt_hash);
    envelope.safe_next_commands = safe_next_commands;
    if truncated {
        warnings.push(json_string(format!(
            "result truncated to {emit_cap} rows in this envelope; {} total rows were \
             returned (raise --limit up to {MAX_ROW_EMIT_CAP}, or use a Snowflake-side LIMIT / COPY INTO)",
            rows.total_rows
        )));
    }
    if usize::try_from(rows.fetched_partitions).unwrap_or(usize::MAX) < rows.partition_count {
        warnings.push(json_string(format!(
            "partition fetch stopped after {} of {} partitions once the row emit cap \
             ({emit_cap}) was reached; row_count is the server-side total and rows are a prefix",
            rows.fetched_partitions, rows.partition_count
        )));
    }
    envelope.warnings = warnings;

    crate::Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

fn failure_outcome(
    format: OutputFormat,
    command_id: &'static str,
    output_contract_id: &'static str,
    request_id: String,
    profile: String,
    error: &SnowflakeError,
) -> crate::Outcome {
    let mut envelope = base_envelope(
        false,
        outcome_kind_for(error.code),
        command_id,
        output_contract_id,
        request_id,
        json_object(vec![]),
    );
    envelope.profile_id = Some(profile);
    envelope.error = Some(error_info(
        error.code,
        error.message.clone(),
        vec![json_string("live SQL API transport")],
    ));
    envelope.safe_next_commands = error.safe_next_commands.clone();
    envelope.repair_commands = error.repair_commands.clone();
    crate::Outcome {
        status: error.exit_code(),
        body: Body::Envelope { envelope, format },
    }
}

/// Map a connector error code to the envelope's `outcome_kind` string.
fn outcome_kind_for(code: SnowflakeErrorCode) -> &'static str {
    match code {
        SnowflakeErrorCode::StatementTimeout => "timeout",
        SnowflakeErrorCode::MutationRefused
        | SnowflakeErrorCode::MultiStatementRefused
        | SnowflakeErrorCode::RequireLiveRefused
        | SnowflakeErrorCode::RowCapExceeded
        | SnowflakeErrorCode::SafetyLimitExceeded
        | SnowflakeErrorCode::WarehouseRefused
        | SnowflakeErrorCode::WriteDisabled
        | SnowflakeErrorCode::WriteConfirmationRequired
        | SnowflakeErrorCode::WriteDdlRefused => "refusal",
        _ => "error",
    }
}

/// Deterministic session output formats so live results are stable across runs
/// (UTC, fixed date/time/timestamp/binary formats, result cache disabled).
fn deterministic_session_parameters() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("TIMEZONE".to_string(), "UTC".to_string()),
        ("DATE_OUTPUT_FORMAT".to_string(), "YYYY-MM-DD".to_string()),
        (
            "TIME_OUTPUT_FORMAT".to_string(),
            "HH24:MI:SS.FF9".to_string(),
        ),
        (
            "TIMESTAMP_NTZ_OUTPUT_FORMAT".to_string(),
            "YYYY-MM-DD HH24:MI:SS.FF9".to_string(),
        ),
        (
            "TIMESTAMP_LTZ_OUTPUT_FORMAT".to_string(),
            "YYYY-MM-DD HH24:MI:SS.FF9 TZHTZM".to_string(),
        ),
        (
            "TIMESTAMP_TZ_OUTPUT_FORMAT".to_string(),
            "YYYY-MM-DD HH24:MI:SS.FF9 TZHTZM".to_string(),
        ),
        ("BINARY_OUTPUT_FORMAT".to_string(), "HEX".to_string()),
        ("USE_CACHED_RESULT".to_string(), "FALSE".to_string()),
    ])
}

/// A conservative Snowflake unquoted-identifier check: a leading letter or
/// underscore, then letters/digits/underscore/`$`, bounded length. Used to gate
/// `--database`/`--schema`/`--role`/`--warehouse` values.
fn is_safe_sql_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    value.len() <= 255 && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
}

fn name(prefix: &str, key: &str) -> String {
    format!("{prefix}_{key}")
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_u32(key: &str) -> Option<u32> {
    env_value(key).and_then(|value| value.parse().ok())
}

fn env_u64(key: &str) -> Option<u64> {
    env_value(key).and_then(|value| value.parse().ok())
}

fn endpoint_url(account: &str) -> String {
    if account.starts_with("https://") {
        account.trim_end_matches('/').to_string()
    } else {
        format!(
            "https://{}.snowflakecomputing.com",
            account
                .trim()
                .trim_end_matches(".snowflakecomputing.com")
                .trim_end_matches('/')
        )
    }
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(0)
}

/// A per-invocation UUID-shaped `requestId`. A fixed id with `retry=true` is the
/// SQL API idempotency contract, so a stable id would return the cached original
/// statement on a re-run; a unique nonce keeps each CLI run independent.
fn unique_request_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    format!(
        "{:08x}-0000-4000-8000-{:012x}",
        (nanos & 0xffff_ffff) as u32,
        (nanos >> 16) & 0xffff_ffff_ffff
    )
}

/// A scripted stand-in for the SQL API at the `execute_request` seam.
///
/// The public outcome functions resolve a `LiveConn` for the installed profile
/// without any env handles, and every statement they submit is answered from
/// the script in order, so the whole live outcome layer (request shaping,
/// session overrides, receipts, audit, store persistence, envelope shape) runs
/// offline. This is **not** transport-level proof: nothing below
/// `execute_request` (http client, driver, auth) runs here; those have their
/// own scripted-transport tests in the sqlapi driver.
#[cfg(test)]
mod test_support {
    use super::*;
    use franken_snowflake_sqlapi::lifecycle::{Progress, StatementMachine};
    use franken_snowflake_sqlapi::status::ResponseClass;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    struct ScriptState {
        responses: VecDeque<Result<CompletedStatement, SnowflakeError>>,
        submitted: Vec<SubmitStatementRequest>,
        row_caps: Vec<Option<usize>>,
    }

    /// Shared handle to the script: the test keeps one to inspect what was
    /// submitted; the resolved `LiveConn` keeps one to answer statements.
    #[derive(Clone)]
    pub(super) struct Script(Rc<RefCell<ScriptState>>);

    impl Script {
        pub(super) fn execute(
            &self,
            request: SubmitStatementRequest,
            row_cap: Option<usize>,
        ) -> Result<(CompletedStatement, DriverStats, String), SnowflakeError> {
            let mut state = self.0.borrow_mut();
            state.submitted.push(request);
            state.row_caps.push(row_cap);
            let ordinal = state.submitted.len();
            match state.responses.pop_front() {
                Some(Ok(done)) => Ok((
                    done,
                    DriverStats {
                        polls: 1,
                        partitions_fetched: 0,
                    },
                    format!("scripted-request-{ordinal}"),
                )),
                Some(Err(error)) => Err(error),
                None => Err(SnowflakeError::new(
                    SnowflakeErrorCode::Internal,
                    "scripted transport has no response left for this statement",
                )),
            }
        }

        pub(super) fn submitted(&self) -> Vec<SubmitStatementRequest> {
            self.0.borrow().submitted.clone()
        }

        pub(super) fn remaining(&self) -> usize {
            self.0.borrow().responses.len()
        }

        /// The fetch row cap each submitted statement was driven with.
        pub(super) fn row_caps(&self) -> Vec<Option<usize>> {
            self.0.borrow().row_caps.clone()
        }
    }

    struct ScriptedProfile {
        profile: String,
        database: Option<String>,
        schema: Option<String>,
        script: Script,
    }

    thread_local! {
        static SCRIPTED: RefCell<Option<ScriptedProfile>> = const { RefCell::new(None) };
    }

    /// Install a scripted profile for this test thread: `LiveConn::resolve`
    /// for `profile` succeeds without env handles and each submitted statement
    /// is answered from `responses` in order.
    pub(super) fn install(
        profile: &str,
        database: Option<&str>,
        schema: Option<&str>,
        responses: Vec<Result<CompletedStatement, SnowflakeError>>,
    ) -> Script {
        let script = Script(Rc::new(RefCell::new(ScriptState {
            responses: responses.into(),
            submitted: Vec::new(),
            row_caps: Vec::new(),
        })));
        SCRIPTED.with(|slot| {
            *slot.borrow_mut() = Some(ScriptedProfile {
                profile: profile.to_owned(),
                database: database.map(str::to_owned),
                schema: schema.map(str::to_owned),
                script: script.clone(),
            });
        });
        script
    }

    pub(super) fn scripted_conn(profile: &str, overrides: &SessionOverrides) -> Option<LiveConn> {
        SCRIPTED.with(|slot| {
            let slot = slot.borrow();
            let scripted = slot.as_ref().filter(|entry| entry.profile == profile)?;
            let account = "xy12345.us-east-1";
            Some(LiveConn {
                profile: profile.to_owned(),
                account: account.to_owned(),
                user: "SVC_TEST".to_owned(),
                warehouse: overrides
                    .warehouse
                    .clone()
                    .unwrap_or_else(|| "WH_TEST".to_owned()),
                database: overrides
                    .database
                    .clone()
                    .or_else(|| scripted.database.clone()),
                schema: overrides.schema.clone().or_else(|| scripted.schema.clone()),
                role: overrides.role.clone(),
                statement_timeout_seconds: overrides
                    .statement_timeout
                    .unwrap_or(DEFAULT_STATEMENT_TIMEOUT_SECONDS),
                endpoint: SnowflakeEndpoint::parse(endpoint_url(account)).ok()?,
                auth_profile: build_auth_profile("FSNOW_SCRIPTED", "pat").ok()?,
                max_polls: 10,
                partition_concurrency: DEFAULT_PARTITION_CONCURRENCY,
                script: Some(scripted.script.clone()),
            })
        })
    }

    /// Build a completed single-partition statement the way the driver would:
    /// a `200` body with typed column metadata, fed through the lifecycle machine.
    pub(super) fn completed(
        handle: &str,
        columns: &[(&str, &str)],
        rows: &[Vec<Option<&str>>],
    ) -> CompletedStatement {
        let row_type: Vec<serde_json::Value> = columns
            .iter()
            .map(|(name, ty)| serde_json::json!({ "name": name, "type": ty, "nullable": true }))
            .collect();
        let body = serde_json::json!({
            "resultSetMetaData": {
                "numRows": rows.len(),
                "format": "jsonv2",
                "rowType": row_type,
                "partitionInfo": [{ "rowCount": rows.len(), "uncompressedSize": 1 }]
            },
            "data": rows,
            "code": "090001",
            "statementHandle": handle,
            "statementStatusUrl": format!("/api/v2/statements/{handle}"),
            "sqlState": "00000",
            "message": "Statement executed successfully.",
            "requestId": "11111111-1111-1111-1111-111111111111",
            "createdOn": 1_700_000_000_000_u64
        });
        let bytes = serde_json::to_vec(&body).expect("fixture body serializes");
        let mut machine = StatementMachine::new(PollPlan::default());
        match machine.on_submit(ResponseClass::Completed, &bytes) {
            Ok(Progress::Complete(done)) => done,
            _ => panic!("scripted fixture did not complete on submit"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_options_reach_the_sql_api_request() {
        let bindings = BTreeMap::from([
            ("1".to_owned(), Binding::new("TEXT", "provider-derived")),
            ("2".to_owned(), Binding::new("FIXED", "42")),
        ]);
        let mut request = SubmitStatementRequest::new("SELECT ? WHERE ? = 42");
        request.parameters = Some(deterministic_session_parameters());

        apply_query_request_options(
            &mut request,
            QueryRequestOptions {
                row_cap: None,
                bindings: Some(bindings.clone()),
                query_tag: Some("hfdt.trace.123".to_owned()),
            },
        );

        assert_eq!(request.bindings, Some(bindings));
        assert_eq!(
            request
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.get("QUERY_TAG"))
                .map(String::as_str),
            Some("hfdt.trace.123")
        );
    }

    #[test]
    fn positional_binding_validation_rejects_gaps_and_unsafe_types() {
        let gap = BTreeMap::from([
            ("1".to_owned(), Binding::new("TEXT", "one")),
            ("3".to_owned(), Binding::new("TEXT", "three")),
        ]);
        assert!(validate_bindings(&gap).is_err());

        let unsafe_type = BTreeMap::from([(
            "1".to_owned(),
            Binding::new("TEXT; DROP TABLE", "must-not-run"),
        )]);
        assert!(validate_bindings(&unsafe_type).is_err());
    }

    #[test]
    fn query_tag_and_binding_env_names_are_bounded() {
        assert!(validate_query_tag("hfdt.trace.123").is_ok());
        assert!(validate_query_tag("hfdt\ntrace").is_err());
        assert!(is_safe_env_name("HFDT_TYPED_BINDINGS_JSON"));
        assert!(!is_safe_env_name("HFDT-TYPED-BINDINGS"));
    }

    #[test]
    fn run_flags_are_validated_not_ignored() {
        assert_eq!(parse_limit(None).ok(), Some(ROW_EMIT_CAP));
        assert_eq!(parse_limit(Some("5")).ok(), Some(5));
        assert!(parse_limit(Some("0")).is_err());
        assert!(parse_limit(Some("abc")).is_err());
        assert!(parse_limit(Some("1000000")).is_err());

        let bad_role = QueryRunOptions {
            role: Some("READ ONLY; DROP".to_owned()),
            ..QueryRunOptions::default()
        };
        assert!(session_overrides(&bad_role, None, None).is_err());
        let bad_timeout = QueryRunOptions {
            statement_timeout: Some("0".to_owned()),
            ..QueryRunOptions::default()
        };
        assert!(session_overrides(&bad_timeout, None, None).is_err());
        let good = QueryRunOptions {
            role: Some("ANALYST".to_owned()),
            warehouse: Some("COMPUTE_WH".to_owned()),
            statement_timeout: Some("30".to_owned()),
            ..QueryRunOptions::default()
        };
        let overrides = session_overrides(&good, Some("DB"), None).expect("valid overrides");
        assert_eq!(overrides.role.as_deref(), Some("ANALYST"));
        assert_eq!(overrides.statement_timeout, Some(30));
        assert_eq!(overrides.database.as_deref(), Some("DB"));
    }

    #[test]
    fn status_labels_cover_every_class() {
        assert_eq!(status_class_label(StatusClass::Completed), "completed");
        assert_eq!(status_class_label(StatusClass::Unexpected), "unexpected");
    }

    // -----------------------------------------------------------------------
    // Scripted live outcome lane: the public outcome functions run end to end
    // against a scripted `execute_request`, with real store side effects.
    // -----------------------------------------------------------------------

    use super::test_support::{completed, install};

    fn envelope(outcome: crate::Outcome) -> serde_json::Value {
        match outcome.body {
            crate::Body::Envelope { envelope, .. } => {
                serde_json::from_str(&crate::render_json(&crate::envelope_json(&envelope)))
                    .expect("envelope renders as JSON")
            }
            crate::Body::Raw { data } => panic!("expected an envelope, got raw output: {data}"),
        }
    }

    fn request_json(request: &SubmitStatementRequest) -> serde_json::Value {
        serde_json::to_value(request).expect("request serializes")
    }

    const EVENT_COLUMNS: &[(&str, &str)] = &[
        ("EVENT_DATE", "DATE"),
        ("ENTITY_ID", "TEXT"),
        ("VALUE", "FIXED"),
    ];

    fn information_schema_script() -> Vec<Result<CompletedStatement, SnowflakeError>> {
        vec![
            Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000cc01",
                &[
                    ("TABLE_CATALOG", "TEXT"),
                    ("TABLE_SCHEMA", "TEXT"),
                    ("TABLE_NAME", "TEXT"),
                    ("TABLE_TYPE", "TEXT"),
                    ("COMMENT", "TEXT"),
                    ("ROW_COUNT", "FIXED"),
                    ("BYTES", "FIXED"),
                ],
                &[vec![
                    Some("ANALYTICS"),
                    Some("PUBLIC"),
                    Some("EVENTS"),
                    Some("BASE TABLE"),
                    None,
                    Some("1200"),
                    Some("65536"),
                ]],
            )),
            Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000cc02",
                &[
                    ("TABLE_CATALOG", "TEXT"),
                    ("TABLE_SCHEMA", "TEXT"),
                    ("TABLE_NAME", "TEXT"),
                    ("COLUMN_NAME", "TEXT"),
                    ("ORDINAL_POSITION", "FIXED"),
                    ("DATA_TYPE", "TEXT"),
                    ("NUMERIC_PRECISION", "FIXED"),
                    ("NUMERIC_SCALE", "FIXED"),
                    ("CHARACTER_MAXIMUM_LENGTH", "FIXED"),
                    ("IS_NULLABLE", "TEXT"),
                    ("COMMENT", "TEXT"),
                ],
                &[
                    vec![
                        Some("ANALYTICS"),
                        Some("PUBLIC"),
                        Some("EVENTS"),
                        Some("EVENT_DATE"),
                        Some("1"),
                        Some("DATE"),
                        None,
                        None,
                        None,
                        Some("NO"),
                        None,
                    ],
                    vec![
                        Some("ANALYTICS"),
                        Some("PUBLIC"),
                        Some("EVENTS"),
                        Some("ENTITY_ID"),
                        Some("2"),
                        Some("TEXT"),
                        None,
                        None,
                        Some("16"),
                        Some("NO"),
                        None,
                    ],
                    vec![
                        Some("ANALYTICS"),
                        Some("PUBLIC"),
                        Some("EVENTS"),
                        Some("VALUE"),
                        Some("3"),
                        Some("NUMBER"),
                        Some("38"),
                        Some("2"),
                        None,
                        Some("YES"),
                        None,
                    ],
                ],
            )),
        ]
    }

    #[test]
    fn unscripted_profiles_still_require_env_handles() {
        // The seam is opt-in per profile: a profile nobody scripted resolves
        // through the real env path and fails typed, never silently succeeds.
        install("demo", None, None, Vec::new());
        let env = envelope(run_query_outcome(
            OutputFormat::Json,
            "req-unscripted".to_owned(),
            "someone_else".to_owned(),
            "select 1",
            &crate::QueryRunOptions::default(),
        ));
        assert_eq!(env["ok"], false, "{env}");
        assert!(
            env["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("missing required env handles"),
            "{env}"
        );
    }

    #[test]
    fn scripted_query_run_shapes_the_request_and_records_a_readable_receipt() {
        let script = install(
            "demo",
            Some("ANALYTICS"),
            Some("PUBLIC"),
            vec![Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000aa01",
                EVENT_COLUMNS,
                &[
                    vec![Some("18262"), Some("ENTITY123"), Some("1.50")],
                    vec![Some("18263"), Some("ENTITY124"), None],
                    vec![Some("18264"), Some("ENTITY125"), Some("2.25")],
                ],
            ))],
        );
        let options = crate::QueryRunOptions {
            limit: Some("2".to_owned()),
            role: Some("ANALYST".to_owned()),
            warehouse: Some("WH_OVERRIDE".to_owned()),
            statement_timeout: Some("120".to_owned()),
            query_tag: Some("fsnow.test.1".to_owned()),
            ..Default::default()
        };
        let env = envelope(run_query_outcome(
            OutputFormat::Json,
            "req-query-1".to_owned(),
            "demo".to_owned(),
            "select event_date, entity_id, value from events",
            &options,
        ));
        assert_eq!(env["ok"], true, "{env}");
        assert_eq!(env["data_source"], "live");
        assert_eq!(env["data"]["row_count"], 3);
        assert_eq!(env["data"]["returned_rows"], 2);
        assert_eq!(env["data"]["rows"].as_array().map(Vec::len), Some(2));
        assert_eq!(env["data"]["truncated"], true);
        assert_eq!(env["budget_consumed"]["polls"], 1);
        let hash = env["receipt_hash"]
            .as_str()
            .expect("receipt hash")
            .to_owned();
        assert_eq!(hash.len(), 64, "{hash}");

        // The one submitted request carries every honored flag.
        let submitted = script.submitted();
        assert_eq!(submitted.len(), 1);
        let request = request_json(&submitted[0]);
        assert_eq!(request["role"], "ANALYST", "{request}");
        assert_eq!(request["warehouse"], "WH_OVERRIDE", "{request}");
        assert_eq!(request["timeout"], 120, "{request}");
        assert_eq!(request["database"], "ANALYTICS", "{request}");
        assert_eq!(
            request["parameters"]["QUERY_TAG"], "fsnow.test.1",
            "{request}"
        );
        assert_eq!(script.remaining(), 0);
        assert_eq!(
            script.row_caps(),
            vec![Some(2)],
            "the emit cap is passed down so unneeded partitions are not fetched"
        );
        assert_eq!(env["data"]["partitions_fetched"], 1, "{env}");

        // The receipt is readable back from the store by its hash.
        let shown = envelope(catalog_surface::receipt_show_outcome(
            OutputFormat::Json,
            "req-receipt-1".to_owned(),
            hash,
        ));
        assert_eq!(shown["ok"], true, "{shown}");
        assert_eq!(shown["data_source"], "cache");
        assert!(
            shown
                .to_string()
                .contains("01b2c3d4-0000-0000-0000-00000000aa01"),
            "{shown}"
        );
    }

    #[test]
    fn scripted_query_failure_is_a_typed_error_envelope_without_a_receipt() {
        install(
            "demo",
            None,
            None,
            vec![Err(SnowflakeError::new(
                SnowflakeErrorCode::StatementFailed,
                "SQL compilation error: Object 'NOPE' does not exist",
            ))],
        );
        let env = envelope(run_query_outcome(
            OutputFormat::Json,
            "req-query-2".to_owned(),
            "demo".to_owned(),
            "select * from nope",
            &crate::QueryRunOptions::default(),
        ));
        assert_eq!(env["ok"], false, "{env}");
        assert!(
            env["error"]["code"]
                .as_str()
                .unwrap_or("")
                .starts_with("FSNOW-"),
            "{env}"
        );
        assert!(
            env["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("compilation error"),
            "{env}"
        );
        assert!(env["receipt_hash"].is_null(), "{env}");
    }

    #[test]
    fn scripted_catalog_scan_persists_a_snapshot_the_offline_surfaces_read_back() {
        let script = install("demo", None, None, information_schema_script());
        let env = envelope(run_catalog_scan_outcome(
            OutputFormat::Json,
            "req-scan-1".to_owned(),
            "demo".to_owned(),
            "ANALYTICS".to_owned(),
            "PUBLIC".to_owned(),
        ));
        assert_eq!(env["ok"], true, "{env}");
        assert_eq!(env["data_source"], "live");
        let datasets = env["data"]["datasets"]
            .as_array()
            .unwrap_or_else(|| panic!("datasets array in {env}"));
        assert_eq!(datasets.len(), 1, "{env}");
        let dataset_id = datasets[0]["dataset_id"]
            .as_str()
            .expect("dataset id")
            .to_owned();
        assert!(
            dataset_id.starts_with("analytics_public_events_b3_"),
            "{dataset_id}"
        );
        assert_eq!(datasets[0]["approx_row_count"], 1200, "{env}");
        assert_eq!(env["receipt_hash"].as_str().map(str::len), Some(64));

        // Discovery statements are bound, never interpolated, carry the
        // session context, and always fetch every partition.
        let submitted = script.submitted();
        assert_eq!(submitted.len(), 2);
        assert_eq!(script.row_caps(), vec![None, None]);
        for request in &submitted {
            let json = request_json(request);
            let statement = json["statement"].as_str().expect("statement");
            assert!(statement.contains("TABLE_CATALOG = ?"), "{statement}");
            assert!(statement.contains("TABLE_SCHEMA = ?"), "{statement}");
            assert!(
                !statement.contains("ANALYTICS"),
                "scope must be bound: {statement}"
            );
            assert_eq!(json["timeout"], 60, "{json}");
            assert_eq!(json["warehouse"], "WH_TEST", "{json}");
            assert_eq!(json["bindings"]["1"]["value"], "ANALYTICS", "{json}");
            assert_eq!(json["bindings"]["2"]["value"], "PUBLIC", "{json}");
        }

        // Offline surfaces read the persisted snapshot back.
        let inspect = envelope(catalog_surface::dataset_inspect_outcome(
            OutputFormat::Json,
            "req-inspect-1".to_owned(),
            dataset_id.clone(),
        ));
        assert_eq!(inspect["ok"], true, "{inspect}");
        assert_eq!(inspect["data_source"], "cache");
        assert!(
            inspect.to_string().contains("ENTITY_ID"),
            "column catalog missing: {inspect}"
        );
        let graph = envelope(run_catalog_graph_outcome(
            OutputFormat::Json,
            "req-graph-1".to_owned(),
            "demo".to_owned(),
            Some("ANALYTICS".to_owned()),
            Some("PUBLIC".to_owned()),
            GraphOutput::Json,
            false,
        ));
        assert_eq!(graph["ok"], true, "{graph}");
        assert_eq!(graph["data_source"], "cache");
        assert!(graph.to_string().contains("EVENTS"), "{graph}");

        // Dataset mode plans against the snapshot and runs through the same seam.
        let run_script = install(
            "demo",
            None,
            None,
            vec![Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000dd01",
                &[("EVENT_DATE", "DATE"), ("VALUE", "FIXED")],
                &[vec![Some("19724"), Some("2.50")]],
            ))],
        );
        let spec = crate::dataset_mode::DatasetQuerySpec {
            dataset_id: dataset_id.clone(),
            profile: Some("demo".to_owned()),
            entity: Some("ENTITY123".to_owned()),
            from: Some("2024-01-01".to_owned()),
            to: Some("2024-12-31".to_owned()),
            select: vec!["EVENT_DATE".to_owned(), "VALUE".to_owned()],
            limit: Some("10".to_owned()),
            ..Default::default()
        };
        let run = envelope(run_dataset_query_outcome(
            OutputFormat::Json,
            "req-dsrun-1".to_owned(),
            spec,
            &crate::QueryRunOptions::default(),
        ));
        assert_eq!(run["ok"], true, "{run}");
        assert_eq!(run["data_source"], "live");
        assert_eq!(run["data"]["row_count"], 1, "{run}");
        let submitted = run_script.submitted();
        assert_eq!(submitted.len(), 1);
        let json = request_json(&submitted[0]);
        let statement = json["statement"].as_str().expect("statement");
        assert!(statement.contains("ENTITY_ID"), "{statement}");
        assert!(
            !statement.contains("ENTITY123"),
            "entity must be bound: {statement}"
        );
        assert!(
            json["bindings"].as_object().is_some_and(|b| b.len() >= 3),
            "{json}"
        );
        assert_eq!(json["database"], "ANALYTICS", "{json}");
        assert_eq!(json["schema"], "PUBLIC", "{json}");

        // `dataset profile --execute` maps the returned stats by column name.
        let profile_script = install(
            "demo",
            None,
            None,
            vec![Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000ee01",
                &[("EVENT_DATE__MIN", "DATE"), ("EVENT_DATE__MAX", "DATE")],
                &[vec![Some("19000"), Some("19724")]],
            ))],
        );
        let profile = envelope(dataset_profile_execute_outcome(
            OutputFormat::Json,
            "req-profile-1".to_owned(),
            dataset_id,
        ));
        assert_eq!(profile["ok"], true, "{profile}");
        assert_eq!(
            profile["data"]["stats"]["EVENT_DATE__MAX"], "19724",
            "{profile}"
        );
        assert_eq!(profile_script.submitted().len(), 1);
    }

    #[test]
    fn scripted_export_run_writes_a_local_csv() {
        install(
            "demo",
            None,
            None,
            vec![Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000ff01",
                &[("ID", "FIXED"), ("NAME", "TEXT")],
                &[vec![Some("1"), Some("alpha")], vec![Some("2"), None]],
            ))],
        );
        let out = std::env::temp_dir().join(format!(
            "fsnow-scripted-export-{}-{}.csv",
            std::process::id(),
            local_store::now_unix_ms()
        ));
        let spec = ExportPlanSpec {
            profile: Some("demo".to_owned()),
            sql: Some("select id, name from events".to_owned()),
            format: Some("csv".to_owned()),
            ..Default::default()
        };
        let env = envelope(export_run_outcome(
            OutputFormat::Json,
            "req-export-1".to_owned(),
            spec,
            Some(out.display().to_string()),
        ));
        assert_eq!(env["ok"], true, "{env}");
        assert_eq!(env["data_source"], "live");
        let written = std::fs::read_to_string(&out).expect("export file written");
        let _ = std::fs::remove_file(&out);
        assert!(written.starts_with("ID,NAME"), "{written}");
        assert!(written.contains("1,alpha"), "{written}");
        assert_eq!(written.lines().count(), 3, "{written}");
        assert_eq!(
            env["receipt_hash"].as_str().map(str::len),
            Some(64),
            "{env}"
        );
    }

    #[test]
    fn scripted_profile_doctor_online_reports_the_probe_result() {
        install(
            "demo",
            None,
            None,
            vec![Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000ab01",
                &[("SNOWFLAKE_VERSION", "TEXT")],
                &[vec![Some("9.12.0")]],
            ))],
        );
        let env = envelope(profile_doctor_online_outcome(
            OutputFormat::Json,
            "req-doctor-1".to_owned(),
            "demo".to_owned(),
        ));
        assert_eq!(env["ok"], true, "{env}");
        assert_eq!(env["data_source"], "live");
        assert!(env.to_string().contains("9.12.0"), "{env}");
        assert_eq!(
            env["receipt_hash"].as_str().map(str::len),
            Some(64),
            "{env}"
        );
    }
}
