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

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::runtime::RuntimeBuilder;
use asupersync::{Cx, Outcome};
use franken_snowflake_auth::{
    AuthLane, AuthMechanism, AuthProfile, CredentialLifetime, KEYPAIR_JWT_TOKEN_TYPE,
    OAUTH_TOKEN_TYPE, OidcTokenSource, PROGRAMMATIC_ACCESS_TOKEN_TYPE, ProcessSecretResolver,
    ReauthDecision, SecretSource, SnowflakeAuth,
};
use franken_snowflake_cache::{
    CatalogSnapshotRecord, ContentAddress as CacheAddress, ExportKind, ExportRecord,
    QueryReceiptRecord, VerifiedPayload,
};
use franken_snowflake_catalog::discovery::{
    CatalogDiscoveryInput, CatalogDiscoveryTables, DiscoveryStatementKind,
    build_information_schema_requests, build_snapshot_from_information_schema, persist_snapshot,
};
use franken_snowflake_catalog::model::{CatalogSnapshot, DataSourceClass, DiscoveryGapKind};
use franken_snowflake_catalog::relations::{
    RelationOptions, RelationOutcome, RelationSource, apply_relation_results,
    plan_relation_discovery,
};
use franken_snowflake_core::cancel::{
    CancelKind, attempts_remote_cancel, cancel_outcome_kind, cancel_policy,
};
use franken_snowflake_core::error::{SnowflakeError, SnowflakeErrorCode};
use franken_snowflake_core::exit::ExitCode as CoreExitCode;
use franken_snowflake_core::guardrails::enforce_require_live;
use franken_snowflake_core::ids::{
    DatabaseName, RoleName, SchemaName, StatementHandle, WarehouseName,
};
use franken_snowflake_core::outcome::{DataSource, OutcomeKind};
use franken_snowflake_core::redact::redact;
use franken_snowflake_core::typed::{ColumnCodec, JsonRepr, TYPED_ROW_ENCODING, WIRE_ROW_ENCODING};
use franken_snowflake_export::{
    CopySource, ExportColumn, ExportReceipt, LocalExportInput, ResultPartition,
    StreamingTextExport, TextFormat,
};
use franken_snowflake_http::{
    AuthorizationDescriptor, CancelHttpRequest, SnowflakeAuthTokenType, SnowflakeEndpoint,
    SnowflakeHttpClient, StatusClass, TlsRootPolicy, TransportConfig, TransportError,
};
use franken_snowflake_sqlapi::driver::{
    AuthProvider, DriverEvent, DriverObserver, DriverStats, RowSink, StatementHooks,
    run_multi_statement_hooked, run_statement_hooked,
};
use franken_snowflake_sqlapi::lifecycle::{
    CompletedStatement, CostQuota, DEFAULT_PARTITION_CONCURRENCY, MAX_PARTITION_CONCURRENCY,
    PollPlan,
};
use franken_snowflake_sqlapi::request::{Binding, SubmitQueryParams, SubmitStatementRequest};
use franken_snowflake_sqlapi::response::ResultSet;

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
/// How long past the statement timeout the client waits before cancelling on
/// its own: a healthy server reports its own timeout first.
const CLIENT_DEADLINE_MARGIN: Duration = Duration::from_secs(5);
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
    /// A fixed SQL API `requestId` (confirmed writes); a fresh one otherwise.
    sql_api_request_id: Option<String>,
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

/// A column's name/type/nullability/precision/scale, projected from the
/// result-set metadata. `type_name` is the bare SQL API type (`"fixed"`); the
/// numeric shape lives in `precision`/`scale`, which typed writers must use.
struct LiveColumn {
    name: String,
    type_name: String,
    nullable: bool,
    precision: Option<u32>,
    scale: Option<u32>,
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
    /// The QUERY_TAG the statement ran with, for the receipt.
    query_tag: Option<String>,
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
            "fsnow.query.run.v2",
            request_id.clone(),
            profile,
            error,
        )
    };
    let mut request_options = match query_request_options(
        options.bindings_env.as_deref(),
        options.bindings_json.as_deref(),
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
        Ok(conn) => conn
            .tagged("query.run", &request_id)
            .with_statement_tag(request_options.query_tag.as_deref())
            .with_progress(options.progress),
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
                profile.clone(),
                "query.run",
                "fsnow.query.run.v2",
                Vec::new(),
                &rows,
                emit_cap,
                RowEncoding::from_raw_cells(options.raw_cells),
                receipt_hash.clone(),
                warnings,
                vec![
                    receipt_show_command(receipt_hash.as_deref()),
                    format!("franken-snowflake query plan --profile {profile} --sql <sql> --json"),
                ],
            )
        }
        Err(error) => with_terminal_receipt(
            fail(&error, profile),
            "query.run",
            &conn,
            &request_id,
            sql,
            &error,
        ),
    }
}

/// `query run --allow-multiple-statements` (reality-check bead L1): run a
/// batch of reads as one multi-statement request (`MULTI_STATEMENT_COUNT` =
/// the batch size) and answer each statement's rows, in order, under
/// `data.statements[]`. The caller already refused bindings, empty
/// statements, and anything but reads.
pub fn run_batch_query_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    sql: &str,
    statements: &[&str],
    options: &QueryRunOptions,
) -> crate::Outcome {
    let fail = |error: &SnowflakeError, profile: String| {
        failure_outcome(
            format,
            "query.run",
            "fsnow.query.run.v2",
            request_id.clone(),
            profile,
            error,
        )
    };
    let mut request_options = match query_request_options(None, None, options.query_tag.as_deref())
    {
        Ok(request_options) => request_options,
        Err(error) => return fail(&error, profile),
    };
    let emit_cap = match parse_limit(options.limit.as_deref()) {
        Ok(cap) => cap,
        Err(error) => return fail(&error, profile),
    };
    // Per statement: do not download partitions the envelope will never show.
    request_options.row_cap = Some(emit_cap);
    let overrides = match session_overrides(options, None, None) {
        Ok(overrides) => overrides,
        Err(error) => return fail(&error, profile),
    };
    let conn = match LiveConn::resolve(&profile, &overrides) {
        Ok(conn) => conn
            .tagged("query.run", &request_id)
            .with_statement_tag(request_options.query_tag.as_deref())
            .with_progress(options.progress),
        Err(error) => return fail(&error, profile),
    };
    match execute_batch(&conn, sql, statements.len(), request_options) {
        Ok((parent, results)) => {
            if let Err(error) = enforce_require_live(options.require_live, DataSource::Live) {
                return fail(&error, profile);
            }
            let per_statement: Vec<serde_json::Value> = results
                .iter()
                .map(|rows| {
                    serde_json::json!({
                        "statement_handle": rows.statement_handle,
                        "row_count": rows.total_rows,
                        "columns": rows
                            .column_pairs()
                            .into_iter()
                            .map(|(name, snowflake_type)| {
                                serde_json::json!({ "name": name, "type": snowflake_type })
                            })
                            .collect::<Vec<_>>(),
                    })
                })
                .collect();
            let (receipt_hash, warnings) = record_receipt(
                "query.run",
                &conn,
                &request_id,
                sql,
                &parent,
                "statement_executed",
                serde_json::json!({ "statements": per_statement }),
            );
            batch_success(
                format,
                request_id,
                profile,
                &parent,
                &results,
                statements,
                emit_cap,
                RowEncoding::from_raw_cells(options.raw_cells),
                receipt_hash.clone(),
                warnings,
                vec![receipt_show_command(receipt_hash.as_deref())],
            )
        }
        Err(error) => with_terminal_receipt(
            fail(&error, profile),
            "query.run",
            &conn,
            &request_id,
            sql,
            &error,
        ),
    }
}

/// Run `sql`, a batch of `count` statements, as one multi-statement request
/// and assemble each statement's rows (reality-check bead L1). Returns the
/// parent (its `total_rows` is the batch's total; its own row is Snowflake's
/// status message) and each statement in order.
fn execute_batch(
    conn: &LiveConn,
    sql: &str,
    count: usize,
    options: QueryRequestOptions,
) -> Result<(LiveRows, Vec<LiveRows>), SnowflakeError> {
    let row_cap = options.row_cap;
    let mut request = build_request(conn, sql, options);
    // The one place the pinned single-statement count is lifted: the guard
    // counted the batch with the shared lexer, and Snowflake refuses the
    // request (422) when its own count differs.
    request
        .parameters
        .get_or_insert_with(BTreeMap::new)
        .insert("MULTI_STATEMENT_COUNT".to_owned(), count.to_string());
    let query_tag = request
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.get("QUERY_TAG"))
        .cloned();
    let sql_api_request_id = unique_request_id();
    LAST_RUN.with(RefCell::take);
    #[cfg(test)]
    if conn.script.is_some() {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::Internal,
            "the scripted test transport does not model multi-statement requests",
        ));
    }
    let params = SubmitQueryParams {
        request_id: Some(sql_api_request_id.clone()),
        retry: true,
        asynchronous: false,
        nullable: None,
    };
    let poll_plan = PollPlan::with_max_polls(conn.max_polls)
        .with_partition_concurrency(conn.partition_concurrency)
        .with_row_cap(row_cap)
        .with_execution_timeout(conn.execution_timeout_for(count))
        .with_cost_quota(conn.cost_quota()?);
    let progress = conn.progress;
    let (outcome, stats, facts) = with_runtime(conn, move |cx, client, auth| {
        Box::pin(async move {
            let mut observer = RunObserver::new(progress);
            let (outcome, stats) = run_multi_statement_hooked(
                cx,
                client,
                auth,
                request,
                params,
                poll_plan,
                Some(&mut observer),
            )
            .await;
            Ok((outcome, stats, observer.facts))
        })
    })?;
    LAST_RUN.with(|slot| *slot.borrow_mut() = facts);
    let result = outcome_into_result(outcome, "the statements", true)?;
    let statements: Vec<LiveRows> = result
        .statements
        .into_iter()
        .map(|done| {
            let mut rows = into_rows(done, DriverStats::default(), sql_api_request_id.clone());
            rows.query_tag.clone_from(&query_tag);
            rows
        })
        .collect();
    let mut parent = into_rows(result.parent, stats, sql_api_request_id);
    parent.query_tag = query_tag;
    parent.total_rows = statements.iter().map(|rows| rows.total_rows).sum();
    Ok((parent, statements))
}

/// A batch's envelope: each statement's columns and rows, projected like a
/// single statement's and capped at `emit_cap` each, under
/// `data.statements[]` in order.
#[allow(clippy::too_many_arguments)]
fn batch_success(
    format: OutputFormat,
    request_id: String,
    profile: String,
    parent: &LiveRows,
    results: &[LiveRows],
    statements: &[&str],
    emit_cap: usize,
    encoding: RowEncoding,
    receipt_hash: Option<String>,
    mut warnings: Vec<Json>,
    safe_next_commands: Vec<String>,
) -> crate::Outcome {
    let mut entries = Vec::with_capacity(results.len());
    for (index, rows) in results.iter().enumerate() {
        let position = index + 1;
        let returned = rows.rows.len().min(emit_cap);
        let truncated = rows.rows.len() > emit_cap;
        let projected = project_rows(rows, returned, encoding);
        warnings.extend(projected.warnings.into_iter().map(|warning| match warning {
            Json::String(text) => json_string(format!("statement {position}: {text}")),
            other => other,
        }));
        if truncated {
            warnings.push(json_string(format!(
                "statement {position}: result truncated to {emit_cap} rows in this envelope; {} total rows were returned (raise --limit up to {MAX_ROW_EMIT_CAP})",
                rows.total_rows
            )));
        }
        let statement = statements.get(index).copied().unwrap_or_default();
        entries.push(json_object(vec![
            ("index", Json::Number(index as i64)),
            (
                "statement_handle",
                json_string(rows.statement_handle.clone()),
            ),
            (
                "sql_preview_redacted",
                json_string(crate::compact_sql(&redact(statement))),
            ),
            ("columns", projected.columns),
            ("rows", projected.rows),
            ("row_count", Json::Number(rows.total_rows)),
            ("returned_rows", Json::Number(returned as i64)),
            ("partition_count", Json::Number(rows.partition_count as i64)),
            (
                "partitions_fetched",
                Json::Number(i64::from(rows.fetched_partitions)),
            ),
            ("truncated", Json::Bool(truncated)),
        ]));
    }
    let data = json_object(vec![
        ("row_encoding", json_string(encoding.token())),
        ("statement_count", Json::Number(results.len() as i64)),
        ("statements", json_array(entries)),
        ("row_emit_cap", Json::Number(emit_cap as i64)),
        (
            "sql_api_request_id",
            json_string(parent.sql_api_request_id.clone()),
        ),
    ]);
    let mut envelope = base_envelope(
        true,
        "success",
        "query.run",
        "fsnow.query.run.v2",
        request_id,
        data,
    );
    stamp_live(&mut envelope, &profile, parent, receipt_hash);
    envelope.safe_next_commands = safe_next_commands;
    envelope.warnings = warnings;
    crate::Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

// ---------------------------------------------------------------------------
// receipt refetch (reality-check bead L5)
// ---------------------------------------------------------------------------

/// How long Snowflake keeps a query's result for `RESULT_SCAN` ("persisted
/// query results" are kept 24 hours; docs.snowflake.com/en/user-guide/querying-persisted-results,
/// consulted 2026-09-24).
const RESULT_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

/// Whether `id` has the shape of a Snowflake query id (a UUID, 8-4-4-4-12 hex).
fn is_query_id(id: &str) -> bool {
    let parts: Vec<&str> = id.split('-').collect();
    parts.len() == 5
        && parts.iter().zip([8, 4, 4, 4, 12]).all(|(part, len)| {
            part.len() == len && part.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

/// The query id a receipt's rows can be re-read with, or the typed reason not.
fn refetch_query_id(record: &QueryReceiptRecord, now_ms: u64) -> Result<String, SnowflakeError> {
    if !record.is_successful_result_scan_candidate() {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::MetadataError,
            format!(
                "receipt `{}` ({}, receipt_state {}) has no completed result to refetch",
                record.receipt_id, record.command_id, record.receipt_state
            ),
        ));
    }
    let query_id = record.snowflake_query_id.clone().unwrap_or_default();
    if !is_query_id(&query_id) {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::MetadataError,
            format!(
                "receipt `{}` records a query id that is not a Snowflake query id; refusing to build RESULT_SCAN",
                record.receipt_id
            ),
        ));
    }
    let age_ms = now_ms.saturating_sub(record.created_at_ms);
    if age_ms > RESULT_RETENTION_MS {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::CacheError,
            format!(
                "receipt `{}` is {} h old; Snowflake keeps a query's result for RESULT_SCAN about 24 h, so it has likely expired; run the statement again",
                record.receipt_id,
                age_ms / 3_600_000
            ),
        ));
    }
    Ok(query_id)
}

/// Re-read a completed statement's rows from Snowflake's result cache with
/// `RESULT_SCAN` on the query id its receipt recorded, without running the
/// statement again. The refetch itself gets a receipt.
pub fn run_receipt_refetch_outcome(
    format: OutputFormat,
    request_id: String,
    receipt_hash: String,
    profile_override: Option<String>,
    limit: Option<&str>,
    raw_cells: bool,
) -> crate::Outcome {
    let fail = |error: &SnowflakeError, profile: String| {
        failure_outcome(
            format,
            "receipt.refetch",
            "fsnow.receipt.refetch.v1",
            request_id.clone(),
            profile,
            error,
        )
    };
    let receipt_id = receipt_hash
        .trim()
        .strip_prefix("blake3:")
        .unwrap_or(receipt_hash.trim())
        .to_ascii_lowercase();
    let fallback_profile = profile_override.clone().unwrap_or_default();
    let store = match local_store::open_store() {
        Ok(store) => store,
        Err(error) => {
            return fail(
                &SnowflakeError::new(SnowflakeErrorCode::CacheError, error.message()),
                fallback_profile,
            );
        }
    };
    let record = match store.cache.query_receipt(&receipt_id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return fail(
                &SnowflakeError::new(
                    SnowflakeErrorCode::MetadataError,
                    format!(
                        "receipt `{receipt_id}` is not in the local store at {}",
                        store.dir.display()
                    ),
                ),
                fallback_profile,
            );
        }
        Err(error) => {
            return fail(
                &SnowflakeError::new(SnowflakeErrorCode::CacheError, error.to_string()),
                fallback_profile,
            );
        }
    };
    let profile = profile_override.unwrap_or_else(|| record.profile_id.clone());
    let query_id = match refetch_query_id(&record, local_store::now_unix_ms()) {
        Ok(query_id) => query_id,
        Err(error) => return fail(&error, profile),
    };
    let emit_cap = match parse_limit(limit) {
        Ok(cap) => cap,
        Err(error) => return fail(&error, profile),
    };
    let conn = match LiveConn::resolve(&profile, &SessionOverrides::default()) {
        Ok(conn) => conn.tagged("receipt.refetch", &request_id),
        Err(error) => return fail(&error, profile),
    };
    // The id was checked to be UUID-shaped above, so it is inlined as a
    // literal: RESULT_SCAN takes a string, and a bind variable in that
    // position is not confirmed for the SQL API.
    let sql = format!("SELECT * FROM TABLE(RESULT_SCAN('{query_id}'))");
    let request_options = QueryRequestOptions {
        row_cap: Some(emit_cap),
        ..QueryRequestOptions::default()
    };
    match execute(&conn, &sql, request_options) {
        Ok(rows) => {
            let (receipt_hash, warnings) = record_receipt(
                "receipt.refetch",
                &conn,
                &request_id,
                &sql,
                &rows,
                "statement_executed",
                serde_json::json!({
                    "source_receipt_id": record.receipt_id,
                    "source_query_id": query_id,
                }),
            );
            rows_success(
                format,
                request_id,
                profile,
                "receipt.refetch",
                "fsnow.receipt.refetch.v1",
                vec![
                    ("source_receipt_id", json_string(record.receipt_id.clone())),
                    ("source_query_id", json_string(query_id)),
                ],
                &rows,
                emit_cap,
                RowEncoding::from_raw_cells(raw_cells),
                receipt_hash.clone(),
                warnings,
                vec![receipt_show_command(receipt_hash.as_deref())],
            )
        }
        Err(error) => with_terminal_receipt(
            fail(&error, profile),
            "receipt.refetch",
            &conn,
            &request_id,
            &sql,
            &error,
        ),
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
        "fsnow.query.run.v2",
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
            "fsnow.query.run.v2",
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
        Ok(conn) => conn
            .tagged("query.run", &request_id)
            .with_statement_tag(Some(&planned.plan.guardrails.query_tag))
            .with_progress(options.progress),
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
        sql_api_request_id: None,
    };
    let rows = match execute(&conn, &planned.plan.sql, request_options) {
        Ok(rows) => {
            if let Err(error) = enforce_require_live(options.require_live, DataSource::Live) {
                return fail(&error);
            }
            rows
        }
        Err(error) => {
            return with_terminal_receipt(
                fail(&error),
                "query.run",
                &conn,
                &request_id,
                &planned.plan.sql,
                &error,
            );
        }
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
        "fsnow.query.run.v2",
        crate::dataset_mode::plan_json(&planned),
        &rows,
        emit_cap,
        RowEncoding::from_raw_cells(options.raw_cells),
        receipt_hash.clone(),
        warnings,
        vec![
            receipt_show_command(receipt_hash.as_deref()),
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
    /// The ladder's proof: only core's write-intent ladder mints one, so no
    /// read path can build an `AuthorizedWrite` (reality-check bead oj0.29).
    pub grant: &'a franken_snowflake_core::write_intent::WriteAuthorization,
    /// The exact mutating statement the ladder authorized.
    pub sql: &'a str,
    /// Stable statement-kind token (e.g. `insert`, `copy_into_table`).
    pub statement_kind: &'a str,
    /// Coarse safety class token (e.g. `dml`, `external_file`).
    pub safety_class: &'a str,
    /// The write-intent ladder receipt / idempotency id (non-secret).
    pub idempotency_request_id: String,
    /// For a confirmed write: the dry run's id, submitted as the SQL API
    /// `requestId` with `retry=true` so a replay cannot write twice.
    pub confirmed_request_id: Option<String>,
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
    if !write.grant.covers(write.sql) {
        return failure_outcome(
            format,
            "query.write",
            "fsnow.query.write.v1",
            request_id,
            profile,
            &SnowflakeError::new(
                SnowflakeErrorCode::MutationRefused,
                "the write authorization does not cover this statement",
            ),
        );
    }
    let overrides = SessionOverrides {
        database: write.database.clone(),
        schema: write.schema.clone(),
        ..SessionOverrides::default()
    };
    let conn = match LiveConn::resolve(&profile, &overrides) {
        Ok(conn) => conn.tagged("query.write", &request_id),
        Err(error) => {
            // An authorized write that never reached Snowflake is still an
            // attempt on the ledger (bead B4: audit every attempt).
            if let Ok(store) = local_store::open_store() {
                let _ = local_store::append_audit(
                    &store,
                    "query.write",
                    &request_id,
                    "write_not_submitted",
                    &serde_json::json!({
                        "profile_id": profile,
                        "statement_kind": write.statement_kind,
                        "idempotency_request_id": write.idempotency_request_id,
                        "error_code": error.stable_code(),
                    }),
                    None,
                );
            }
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
    // Audit every attempt before it leaves the process, so an indeterminate
    // outcome (a killed process, a lost response) still leaves a record.
    if let Ok(store) = local_store::open_store() {
        let _ = local_store::append_audit(
            &store,
            "query.write",
            &request_id,
            "write_submitted",
            &serde_json::json!({
                "profile_id": profile,
                "statement_kind": write.statement_kind,
                "idempotency_request_id": write.idempotency_request_id,
                "sql_api_request_id": write.confirmed_request_id,
                "sql_preview_redacted": crate::compact_sql(&redact(write.sql)),
            }),
            None,
        );
    }
    let options = QueryRequestOptions {
        sql_api_request_id: write.confirmed_request_id.clone(),
        ..QueryRequestOptions::default()
    };
    match execute(&conn, write.sql, options) {
        Ok(rows) => {
            let (receipt_hash, mut warnings) = record_receipt(
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
            // The confirmation is single-use once its write completed.
            if let Some(confirm_id) = &write.confirmed_request_id {
                let consumed = local_store::open_store()
                    .map_err(|error| error.message())
                    .and_then(|store| {
                        local_store::record_confirmation_consumed(
                            &store,
                            &request_id,
                            confirm_id,
                            receipt_hash.as_deref(),
                        )
                        .map_err(|error| error.to_string())
                    });
                if let Err(message) = consumed {
                    warnings.push(json_string(format!(
                        "the confirmation could not be marked used: {message}"
                    )));
                }
            }
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
        Err(error) => with_terminal_receipt(
            failure_outcome(
                format,
                "query.write",
                "fsnow.query.write.v1",
                request_id.clone(),
                profile,
                &error,
            ),
            "query.write",
            &conn,
            &request_id,
            write.sql,
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
    let projected = project_rows(rows, returned, RowEncoding::Typed);
    warnings.extend(projected.warnings);

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
            ("row_encoding", json_string(RowEncoding::Typed.token())),
            ("columns", projected.columns),
            ("rows", projected.rows),
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
    stamp_live(&mut envelope, &profile, rows, receipt_hash.clone());
    envelope.safe_next_commands = vec![
        receipt_show_command(receipt_hash.as_deref()),
        format!("franken-snowflake query run --profile {profile} --sql <select-to-verify> --json"),
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

/// A live discovery scan: the snapshot, its store record, the TABLES/COLUMNS
/// row sets, the relation pass's statement count and polls, and what happened
/// to persistence.
struct ScanResult {
    input: CatalogDiscoveryInput,
    snapshot: CatalogSnapshot,
    record: CatalogSnapshotRecord,
    tables: LiveRows,
    columns: LiveRows,
    relation_statements: usize,
    relation_polls: u32,
    store_dir: Option<String>,
    drift: Option<franken_snowflake_catalog::diff::CatalogDiff>,
    warnings: Vec<Json>,
}

/// Run the catalog crate's bound INFORMATION_SCHEMA discovery statements
/// (TABLES + COLUMNS) live, then its relation pass (keys, view dependencies,
/// stages, file formats, external tables, opt-in tags), build the snapshot,
/// and persist it to the local store. `schema = None` scans every schema in
/// the database. A relation statement Snowflake rejects (privilege, edition,
/// a view it cannot resolve) becomes a gap in the snapshot; any other error
/// ends the scan.
fn scan_catalog(
    conn: &LiveConn,
    profile: &str,
    database: &str,
    schema: Option<&str>,
    trace_id: &str,
    relation_options: RelationOptions,
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
        let (completed, stats, sql_api_request_id) = execute_request(conn, request, None, None)?;
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
    let mut snapshot = build_snapshot_from_information_schema(&input, &discovery_tables);
    let plan = plan_relation_discovery(&input, &snapshot, relation_options);
    let relation_statements = plan.statements.len();
    let mut relation_polls = 0_u32;
    let mut relation_results = Vec::with_capacity(relation_statements);
    for statement in plan.statements {
        let mut request = statement.request.clone();
        apply_session(conn, &mut request);
        let outcome = match execute_request(conn, request, None, None) {
            Ok((completed, stats, _)) => {
                relation_polls = relation_polls.saturating_add(stats.polls);
                RelationOutcome::Completed(completed)
            }
            Err(error) if error.code == SnowflakeErrorCode::StatementFailed => {
                RelationOutcome::Failed(error.message)
            }
            Err(error) => return Err(error),
        };
        relation_results.push((statement, outcome));
    }
    apply_relation_results(&mut snapshot, plan.gaps, relation_results);
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
    let (drift, store_dir) = match local_store::open_store() {
        Ok(store) => {
            let previous_snapshot =
                match store
                    .cache
                    .latest_catalog_snapshot(profile, Some(database), schema)
                {
                    Ok(Some(record)) => {
                        serde_json::from_str::<CatalogSnapshot>(&record.payload.canonical).ok()
                    }
                    _ => None,
                };
            let drift = match previous_snapshot.as_ref() {
                Some(prev) => franken_snowflake_catalog::diff::diff_snapshots(prev, &snapshot),
                None => franken_snowflake_catalog::diff::CatalogDiff::initial_scan(&snapshot),
            };
            let dir = match persist_snapshot(&*store.cache, &input, &snapshot, now_ms) {
                Ok(()) => Some(store.dir.display().to_string()),
                Err(error) => {
                    warnings.push(json_string(format!(
                        "snapshot was not persisted to the local store: {error}"
                    )));
                    None
                }
            };
            (Some(drift), dir)
        }
        Err(error) => {
            warnings.push(json_string(format!(
                "snapshot was not persisted: {}",
                error.message()
            )));
            (None, None)
        }
    };
    Ok(ScanResult {
        input,
        snapshot,
        record,
        tables,
        columns,
        relation_statements,
        relation_polls,
        store_dir,
        drift,
        warnings,
    })
}

/// `catalog scan <profile> --database <db> --schema <schema>`: live discovery
/// through the catalog crate, persisted locally, summarized in the envelope.
/// A relation source Snowflake refused makes the scan `partial_success`
/// (exit 1) with a warning naming the source; the snapshot is still kept.
pub fn run_catalog_scan_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    database: String,
    schema: String,
    require_live: bool,
    relations: RelationOptions,
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
        Ok(conn) => conn.tagged("catalog.scan", &request_id),
        Err(error) => return fail(&error),
    };
    let scan = match scan_catalog(
        &conn,
        &profile,
        &database,
        Some(&schema),
        &request_id,
        relations,
    ) {
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
        &format!(
            "INFORMATION_SCHEMA.TABLES + INFORMATION_SCHEMA.COLUMNS discovery and {} relation statements",
            scan.relation_statements
        ),
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
    let mut relation_failed = false;
    for gap in &scan.snapshot.gaps {
        let what = match gap.kind {
            DiscoveryGapKind::Skipped => continue,
            DiscoveryGapKind::Failed => {
                relation_failed = true;
                "was refused"
            }
            DiscoveryGapKind::Truncated => "was truncated",
            DiscoveryGapKind::Unresolved => "left rows unresolved",
        };
        let documentation = relation_source_documentation(&gap.source);
        warnings.push(json_string(format!(
            "catalog relation source `{}` {what}: {}{}",
            gap.source,
            gap.detail,
            documentation
                .map(|url| format!(" (see {url})"))
                .unwrap_or_default()
        )));
    }

    let mut data = vec![
        ("profile_id", json_string(profile.clone())),
        ("database", json_string(database.clone())),
        ("schema", json_string(schema)),
    ];
    data.extend(catalog_surface::snapshot_summary_json(&scan.snapshot));
    if let Some(drift) = &scan.drift {
        data.push(("drift", Json::from_value(drift)));
        if drift.is_breaking() {
            warnings.push(json_string(format!(
                "Catalog scan detected breaking schema changes: {}",
                drift.summary_text()
            )));
        } else if drift.has_changes() && drift.base_snapshot_id.is_some() {
            warnings.push(json_string(format!(
                "Catalog drift detected: {}",
                drift.summary_text()
            )));
        }
    }
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
        if relation_failed {
            "partial_success"
        } else {
            "success"
        },
        "catalog.scan",
        "fsnow.catalog.scan.v1",
        request_id,
        json_object(data),
    );
    stamp_live(&mut envelope, &profile, &scan.tables, receipt_hash);
    envelope.budget_consumed = budget_consumed(
        scan.tables
            .stats
            .polls
            .saturating_add(scan.columns.stats.polls)
            .saturating_add(scan.relation_polls),
        &scan.tables.stats,
        scan.tables
            .total_rows
            .saturating_add(scan.columns.total_rows),
    );
    envelope.warnings = warnings;
    let example_dataset = scan
        .snapshot
        .datasets
        .first()
        .map(|d| d.id.as_str())
        .unwrap_or("<dataset-id>");
    envelope.safe_next_commands = vec![
        format!("franken-snowflake dataset inspect {example_dataset} --json"),
        format!("franken-snowflake catalog graph {profile} --database {database} --mermaid"),
        format!("franken-snowflake catalog lineage {profile} <DB.SCHEMA.OBJECT> --down --json"),
        format!("franken-snowflake dataset profile {example_dataset} --json"),
    ];
    crate::Outcome {
        status: if relation_failed {
            CoreExitCode::Findings
        } else {
            CoreExitCode::Success
        },
        body: Body::Envelope { envelope, format },
    }
}

/// The documentation URL of a relation source named in a gap.
fn relation_source_documentation(source: &str) -> Option<&'static str> {
    [
        RelationSource::PrimaryKeys,
        RelationSource::TableConstraints,
        RelationSource::ReferentialConstraints,
        RelationSource::Stages,
        RelationSource::FileFormats,
        RelationSource::ExternalTables,
        RelationSource::ObjectReferences,
        RelationSource::TagReferences,
    ]
    .into_iter()
    .find(|candidate| candidate.as_str() == source)
    .map(RelationSource::documentation)
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
        Ok(conn) => conn.tagged("catalog.graph", &request_id),
        Err(error) => return fail(&error),
    };
    let scan = match scan_catalog(
        &conn,
        &profile,
        &database,
        schema.as_deref(),
        &request_id,
        RelationOptions::default(),
    ) {
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
        Ok(conn) => conn.tagged("query.cancel", &request_id),
        Err(error) => return fail(&error),
    };
    let handle = StatementHandle::new(statement_handle.clone());
    let response = match with_runtime(&conn, |cx, client, auth| {
        Box::pin(async move {
            let auth = auth.descriptor()?;
            let outcome = client
                .cancel_statement(
                    cx,
                    CancelHttpRequest {
                        auth,
                        statement_handle: handle,
                        reason_kind: CancelKind::User,
                    },
                )
                .await;
            outcome_into_result(outcome, "the cancel request", false)
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
    envelope.profile_id = Some(profile.clone());
    envelope.statement_handle = Some(statement_handle);
    if !acknowledged {
        envelope.error = Some(error_info(
            SnowflakeErrorCode::UpstreamError,
            format!("cancel endpoint returned {status_label}: {preview}"),
            vec![json_string("live SQL API transport")],
        ));
        envelope.repair_commands = vec![format!(
            "franken-snowflake profile doctor {profile} --online --json"
        )];
    }
    envelope.safe_next_commands = vec![format!(
        "franken-snowflake profile doctor {profile} --online --json"
    )];
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
        Ok(conn) => conn.tagged("dataset.profile", &request_id),
        Err(error) => return fail(&error),
    };
    let rows = match execute(&conn, &plan.sql, QueryRequestOptions::default()) {
        Ok(rows) => rows,
        Err(error) => {
            return with_terminal_receipt(
                fail(&error),
                "dataset.profile",
                &conn,
                &request_id,
                &plan.sql,
                &error,
            );
        }
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
    stamp_live(&mut envelope, &plan.profile, &rows, receipt_hash.clone());
    envelope.warnings = warnings;
    envelope.safe_next_commands = vec![
        format!("franken-snowflake dataset inspect {dataset_id} --json"),
        receipt_show_command(receipt_hash.as_deref()),
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
    sandbox_out: bool,
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
    // Validate the destination before running anything (no warehouse cost for
    // a refused path). Sandbox mode confines it under <data_dir>/exports.
    let sandbox_root = if sandbox_out {
        match local_store::data_dir() {
            Some(dir) => Some(dir.join("exports")),
            None => {
                return fail(&usage(
                    "export run --sandbox-out needs a data directory; set FRANKEN_SNOWFLAKE_DATA_DIR",
                ));
            }
        }
    } else {
        None
    };
    let target =
        match crate::export_path::resolve_out(&out_path, sandbox_root.as_deref(), spec.overwrite) {
            Ok(target) => target,
            Err(message) => return fail(&usage(&format!("export run refused: {message}"))),
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
        Some("parquet") => "parquet",
        Some("frame") => "frame",
        Some(other) => {
            return fail(&usage(&format!(
                "Unknown --format `{other}`; use csv, jsonl, parquet, or frame."
            )));
        }
    };
    if export_format == "frame" && !cfg!(feature = "frankenpandas") {
        return fail(&SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            "format `frame` requires rebuild with --features frankenpandas",
        ));
    }
    let conn = match LiveConn::resolve(&profile, &SessionOverrides::default()) {
        Ok(conn) => conn
            .tagged("export.run", &request_id)
            .with_progress(spec.progress),
        Err(error) => return fail(&error),
    };
    let max_rows = match export_max_rows(spec.max_rows.as_deref(), &profile) {
        Ok(max_rows) => max_rows,
        Err(error) => return fail(&error),
    };
    let created_at_ms = local_store::now_unix_ms();
    let target_label = redact(&out_path).into_owned();
    let text_format = match export_format {
        "csv" => Some(TextFormat::Csv),
        "jsonl" => Some(TextFormat::Jsonl),
        _ => None,
    };
    let (rows, receipt, log_line) = if let Some(text_format) = text_format {
        // CSV/JSONL stream to the file as each fetch window completes
        // (reality-check bead E5): peak memory is one window, not the result.
        let file = match crate::export_path::open_artifact(&target) {
            Ok(file) => file,
            Err(message) => {
                return fail(&SnowflakeError::new(
                    SnowflakeErrorCode::Internal,
                    format!("could not open {target_label}: {message}"),
                ));
            }
        };
        match stream_text_export(
            &conn,
            &sql,
            file,
            text_format,
            max_rows,
            &target_label,
            created_at_ms,
        ) {
            Ok(done) => done,
            Err(error) => {
                return with_terminal_receipt(
                    fail(&error),
                    "export.run",
                    &conn,
                    &request_id,
                    &sql,
                    &error,
                );
            }
        }
    } else {
        // Parquet and frame need the whole result; the row cap stops the fetch
        // just past --max-rows so an oversized result is refused, not buffered.
        let request_options = QueryRequestOptions {
            row_cap: Some(max_rows.saturating_add(1)),
            ..QueryRequestOptions::default()
        };
        let rows = match execute(&conn, &sql, request_options) {
            Ok(rows) => rows,
            Err(error) => {
                return with_terminal_receipt(
                    fail(&error),
                    "export.run",
                    &conn,
                    &request_id,
                    &sql,
                    &error,
                );
            }
        };
        if rows.rows.len() > max_rows {
            return fail(&max_rows_error(max_rows));
        }
        let input = LocalExportInput::new(
            rows.columns
                .iter()
                .map(|column| {
                    ExportColumn::new(column.name.clone(), column.type_name.clone())
                        .nullable(column.nullable)
                        .precision_scale(column.precision, column.scale)
                })
                .collect(),
            vec![ResultPartition::new(0, rows.rows.clone())],
        );
        let parquet_compression = match spec
            .compression
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("snappy") => franken_snowflake_export::ParquetCompression::Snappy,
            Some("gzip") => franken_snowflake_export::ParquetCompression::Gzip,
            Some("none") | Some("uncompressed") => {
                franken_snowflake_export::ParquetCompression::Uncompressed
            }
            Some(other) => {
                return fail(&usage(&format!(
                    "Unknown --compression `{other}`; for parquet use snappy (default), gzip, or none."
                )));
            }
        };
        let parquet_opts = franken_snowflake_export::ParquetWriterOptions {
            compression: parquet_compression,
            ..Default::default()
        };
        let artifact = match export_format {
            "parquet" => franken_snowflake_export::export_parquet(
                &input,
                target_label.clone(),
                created_at_ms,
                Some(parquet_opts),
            ),
            "frame" => {
                #[cfg(feature = "frankenpandas")]
                {
                    let frame_cols: Vec<franken_snowflake_frame::SnowflakeColumn> = rows
                        .columns
                        .iter()
                        .map(|column| {
                            franken_snowflake_frame::SnowflakeColumn::new(
                                column.name.clone(),
                                column.type_name.clone(),
                            )
                            .nullable(column.nullable)
                        })
                        .collect();
                    let frame_partitions = vec![franken_snowflake_frame::ResultPartition::new(
                        0,
                        rows.rows.clone(),
                    )];
                    match franken_snowflake_frame::materialize_partitions(
                        &frame_cols,
                        frame_partitions,
                    ) {
                        Ok(frame) => match serde_json::to_vec_pretty(&frame) {
                            Ok(bytes) => {
                                let content_address =
                                    franken_snowflake_export::ContentAddress::blake3(&bytes);
                                let receipt = franken_snowflake_export::ExportReceipt::new(
                                    franken_snowflake_export::ExportReceiptKind::LocalJsonl,
                                    Some(franken_snowflake_export::ExportFormat::Jsonl),
                                    target_label.clone(),
                                    content_address,
                                    Some(frame.row_count as u64),
                                    None,
                                    None,
                                    created_at_ms,
                                    vec!["format:frame".to_string()],
                                );
                                let log_line = serde_json::to_string(&receipt).unwrap_or_default();
                                Ok(franken_snowflake_export::LocalExportArtifact {
                                    bytes,
                                    receipt,
                                    log_line,
                                })
                            }
                            Err(err) => Err(franken_snowflake_export::ExportError::Json {
                                message: err.to_string(),
                            }),
                        },
                        Err(err) => Err(franken_snowflake_export::ExportError::Json {
                            message: err.to_string(),
                        }),
                    }
                }
                #[cfg(not(feature = "frankenpandas"))]
                {
                    unreachable!("guarded above");
                }
            }
            other => Err(franken_snowflake_export::ExportError::Json {
                message: format!("format `{other}` is written by the streaming path"),
            }),
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
        if let Err(error) = crate::export_path::write_artifact(&target, &artifact.bytes) {
            return fail(&SnowflakeError::new(
                SnowflakeErrorCode::Internal,
                format!("could not write {target_label}: {error}"),
            ));
        }
        (rows, artifact.receipt, artifact.log_line)
    };
    let (receipt_hash, mut warnings) = record_receipt(
        "export.run",
        &conn,
        &request_id,
        &sql,
        &rows,
        "export_written",
        serde_json::json!({
            "format": export_format,
            "export_id": receipt.export_id,
            "content_hash": receipt.content_address.digest_hex,
            "byte_len": receipt.content_address.byte_len,
            "streamed": text_format.is_some(),
        }),
    );
    if let (Some(receipt_id), Ok(store)) = (receipt_hash.as_ref(), local_store::open_store()) {
        let record = ExportRecord {
            export_id: receipt.export_id.clone(),
            receipt_id: receipt_id.clone(),
            export_kind: if export_format == "csv" {
                ExportKind::LocalCsv
            } else if export_format == "parquet" {
                ExportKind::LocalParquet
            } else if export_format == "frame" {
                ExportKind::LocalFrame
            } else {
                ExportKind::LocalJsonl
            },
            target_uri_redacted: target_label.clone(),
            content_address: CacheAddress {
                algorithm: receipt.content_address.algorithm.clone(),
                digest_hex: receipt.content_address.digest_hex.clone(),
                byte_len: receipt.content_address.byte_len,
            },
            row_count: receipt.row_count,
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
                "resolved_path",
                json_string(redact(&target.path.to_string_lossy()).into_owned()),
            ),
            ("overwrote", Json::Bool(target.overwrite)),
            (
                "bytes_written",
                Json::Number(i64::try_from(receipt.content_address.byte_len).unwrap_or(i64::MAX)),
            ),
            ("row_count", Json::Number(rows.total_rows)),
            ("streamed", Json::Bool(text_format.is_some())),
            (
                "max_rows",
                Json::Number(i64::try_from(max_rows).unwrap_or(i64::MAX)),
            ),
            ("export_receipt", Json::from_value(&receipt)),
            (
                "export_log_line",
                json_string(log_line.trim_end().to_string()),
            ),
        ]),
    );
    stamp_live(&mut envelope, &profile, &rows, receipt_hash.clone());
    envelope.warnings = warnings;
    envelope.safe_next_commands = vec![receipt_show_command(receipt_hash.as_deref())];
    crate::Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

/// Default `--max-rows` for `export run` (reality-check bead E5).
const DEFAULT_EXPORT_MAX_ROWS: usize = 1_000_000;

/// `--max-rows`, else `<PREFIX>_EXPORT_MAX_ROWS`, else 1,000,000.
fn export_max_rows(flag: Option<&str>, profile: &str) -> Result<usize, SnowflakeError> {
    let env_name = format!("{}_EXPORT_MAX_ROWS", crate::profile_env_prefix(profile));
    let (raw, source) = match flag {
        Some(value) => (Some(value.to_owned()), "--max-rows".to_owned()),
        None => (env_value(&env_name), env_name),
    };
    let Some(raw) = raw else {
        return Ok(DEFAULT_EXPORT_MAX_ROWS);
    };
    match raw.trim().parse::<usize>() {
        Ok(value) if value > 0 => Ok(value),
        _ => Err(SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            format!("{source} must be a positive row count (got `{raw}`)"),
        )),
    }
}

fn max_rows_error(max_rows: usize) -> SnowflakeError {
    SnowflakeError::new(
        SnowflakeErrorCode::RowCapExceeded,
        format!(
            "the result has more than {max_rows} rows (--max-rows); raise --max-rows, or unload it in Snowflake with `export plan` (COPY INTO a stage)"
        ),
    )
}

/// Writes a streaming CSV/JSONL export as rows arrive; refuses once the
/// export would pass `--max-rows` (the driver then cancels the statement).
struct ExportSink {
    format: TextFormat,
    file: Option<crate::export_path::ArtifactFile>,
    writer: Option<StreamingTextExport<crate::export_path::ArtifactFile>>,
    max_rows: usize,
}

impl RowSink for ExportSink {
    fn accept(
        &mut self,
        result_set: &ResultSet,
        rows: Vec<Vec<Option<String>>>,
    ) -> Result<(), SnowflakeError> {
        let export_error = |error: franken_snowflake_export::ExportError| {
            SnowflakeError::new(
                SnowflakeErrorCode::UsageError,
                format!("local export failed: {error}"),
            )
        };
        if self.writer.is_none() {
            let columns = result_set
                .result_set_meta_data
                .row_type
                .iter()
                .map(|column| {
                    ExportColumn::new(column.name.clone(), column.column_type.clone())
                        .nullable(column.nullable)
                        .precision_scale(
                            column.precision.and_then(|p| u32::try_from(p).ok()),
                            column.scale.and_then(|s| u32::try_from(s).ok()),
                        )
                })
                .collect();
            let Some(file) = self.file.take() else {
                return Err(SnowflakeError::new(
                    SnowflakeErrorCode::Internal,
                    "the export file is already in use",
                ));
            };
            self.writer =
                Some(StreamingTextExport::new(self.format, columns, file).map_err(export_error)?);
        }
        let Some(writer) = self.writer.as_mut() else {
            return Err(SnowflakeError::new(
                SnowflakeErrorCode::Internal,
                "the export writer is missing",
            ));
        };
        let written = usize::try_from(writer.rows_written()).unwrap_or(usize::MAX);
        if written.saturating_add(rows.len()) > self.max_rows {
            return Err(max_rows_error(self.max_rows));
        }
        writer.write_rows(&rows).map_err(export_error)
    }
}

/// [`execute`], handing rows to `sink` as each fetch window completes; the
/// returned rows carry the metadata only. The sink is owned so it can ride
/// into the runtime and come back.
fn execute_streaming<S: RowSink + 'static>(
    conn: &LiveConn,
    sql: &str,
    options: QueryRequestOptions,
    sink: S,
) -> Result<(LiveRows, S), SnowflakeError> {
    let fixed_request_id = options.sql_api_request_id.clone();
    let request = build_request(conn, sql, options);
    let query_tag = request
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.get("QUERY_TAG"))
        .cloned();
    let sql_api_request_id = fixed_request_id.unwrap_or_else(unique_request_id);
    LAST_RUN.with(RefCell::take);
    #[cfg(test)]
    if let Some(script) = &conn.script {
        let mut sink = sink;
        let plan = PollPlan::with_max_polls(conn.max_polls)
            .with_execution_timeout(conn.execution_timeout())
            .with_cost_quota(conn.cost_quota()?);
        let (mut done, stats, id) = script.execute(request, plan, &sql_api_request_id)?;
        let rows = std::mem::take(&mut done.rows);
        sink.accept(&done.result_set, rows)?;
        let mut live = into_rows(done, stats, id);
        live.query_tag = query_tag;
        return Ok((live, sink));
    }
    let params = SubmitQueryParams {
        request_id: Some(sql_api_request_id.clone()),
        retry: true,
        asynchronous: false,
        nullable: None,
    };
    let poll_plan = PollPlan::with_max_polls(conn.max_polls)
        .with_partition_concurrency(conn.partition_concurrency)
        .with_execution_timeout(conn.execution_timeout())
        .with_cost_quota(conn.cost_quota()?);
    let progress = conn.progress;
    let (outcome, stats, sink, facts) = with_runtime(conn, move |cx, client, auth| {
        Box::pin(async move {
            let mut sink = sink;
            let mut observer = RunObserver::new(progress);
            let hooks = StatementHooks {
                sink: Some(&mut sink),
                observer: Some(&mut observer),
            };
            let (outcome, stats) =
                run_statement_hooked(cx, client, auth, request, params, poll_plan, hooks).await;
            Ok((outcome, stats, sink, observer.facts))
        })
    })?;
    LAST_RUN.with(|slot| *slot.borrow_mut() = facts);
    let done = outcome_into_result(outcome, "the statement", true)?;
    let mut live = into_rows(done, stats, sql_api_request_id);
    live.query_tag = query_tag;
    Ok((live, sink))
}

/// Stream a CSV/JSONL export into `file` and commit it; the receipt's content
/// address covers exactly the bytes written.
fn stream_text_export(
    conn: &LiveConn,
    sql: &str,
    file: crate::export_path::ArtifactFile,
    format: TextFormat,
    max_rows: usize,
    target_label: &str,
    created_at_ms: u64,
) -> Result<(LiveRows, ExportReceipt, String), SnowflakeError> {
    let sink = ExportSink {
        format,
        file: Some(file),
        writer: None,
        max_rows,
    };
    let (rows, sink) = execute_streaming(conn, sql, QueryRequestOptions::default(), sink)?;
    let Some(writer) = sink.writer else {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::Internal,
            "the statement completed without result metadata",
        ));
    };
    let (file, receipt, log_line) = writer
        .finish(target_label.to_owned(), created_at_ms)
        .map_err(|error| {
            SnowflakeError::new(
                SnowflakeErrorCode::UsageError,
                format!("local export failed: {error}"),
            )
        })?;
    file.commit().map_err(|message| {
        SnowflakeError::new(
            SnowflakeErrorCode::Internal,
            format!("could not write {target_label}: {message}"),
        )
    })?;
    Ok((rows, receipt, log_line))
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
        Ok(conn) => conn.tagged("profile.doctor", &request_id),
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
            let (receipt_hash, mut warnings) = record_receipt(
                "profile.doctor",
                &conn,
                &request_id,
                PROBE_SQL,
                &rows,
                "profile_probed",
                serde_json::json!({ "snowflake_version": version }),
            );
            let (credential, mut lifetime_warnings) = online_credential_lifetime(&conn);
            warnings.append(&mut lifetime_warnings);
            let prefix = crate::profile_env_prefix(&profile);
            let flag = |key: &str| {
                env_value(&format!("{prefix}_{key}"))
                    .is_some_and(|value| value.eq_ignore_ascii_case("true"))
            };
            let (role_privileges, mut role_warnings, refusal) = role_verdict(
                &role_write_check(&conn),
                !flag("WRITE_ENABLED"),
                flag("READ_ONLY_EXPECTED"),
            );
            if let Some(error) = refusal {
                return failure_outcome(
                    format,
                    "profile.doctor",
                    "fsnow.profile.doctor.v1",
                    request_id,
                    profile,
                    &error,
                );
            }
            warnings.append(&mut role_warnings);
            probe_success(
                format,
                request_id,
                profile,
                version,
                &rows,
                receipt_hash,
                warnings,
                credential,
                role_privileges,
            )
        }
        Err(error) => with_terminal_receipt(
            failure_outcome(
                format,
                "profile.doctor",
                "fsnow.profile.doctor.v1",
                request_id.clone(),
                profile,
                &error,
            ),
            "profile.doctor",
            &conn,
            &request_id,
            PROBE_SQL,
            &error,
        ),
    }
}

/// The credential's remaining lifetime as far as it can be known online
/// (reality-check bead C5): the resolved credential's own lifetime (a JWT
/// OAuth bearer's `exp`, the key-pair validity cap) and, for the PAT lane, the
/// user's tokens from `SHOW USER PROGRAMMATIC ACCESS TOKENS`
/// (docs.snowflake.com/en/sql-reference/sql/show-user-programmatic-access-tokens,
/// consulted 2026-09-24; the secret is never returned, so the one this profile
/// uses cannot be singled out and the soonest active expiry is reported).
fn online_credential_lifetime(conn: &LiveConn) -> (Json, Vec<Json>) {
    let now = now_unix_seconds();
    let mut fields = Vec::new();
    let mut warnings = Vec::new();
    if let Ok(mechanism) =
        conn.auth_profile
            .resolve(&ProcessSecretResolver, &conn.account, &conn.user)
    {
        let (lifetime, mut found) = lifetime_findings(&mechanism.lifetime(), now);
        fields.push(("credential", lifetime));
        warnings.append(&mut found);
    }
    if matches!(conn.auth_profile, AuthProfile::Pat { .. }) {
        match execute(
            conn,
            "SHOW USER PROGRAMMATIC ACCESS TOKENS",
            QueryRequestOptions::default(),
        ) {
            Ok(rows) => {
                let (tokens, mut found) = pat_token_findings(&rows, now);
                fields.push(("programmatic_access_tokens", tokens));
                warnings.append(&mut found);
            }
            Err(error) => fields.push((
                "programmatic_access_tokens",
                json_string(format!(
                    "not listed ({}): the role may not run SHOW USER PROGRAMMATIC ACCESS TOKENS",
                    error.stable_code()
                )),
            )),
        }
    }
    (json_object(fields), warnings)
}

/// How many roles the grant walk visits before it reports `partial`.
const ROLE_WALK_LIMIT: usize = 8;

/// What `SHOW GRANTS TO ROLE` says the profile's role (and the roles granted to
/// it) may do.
#[derive(Debug, Default)]
struct RoleCheck {
    role: Option<String>,
    /// Write-capable grants, e.g. `INSERT on TABLE DB.S.T (via LOADER)`.
    write_grants: Vec<String>,
    roles_checked: Vec<String>,
    /// The walk stopped at [`ROLE_WALK_LIMIT`] with roles left unvisited.
    partial: bool,
    /// Why the check could not run (the role may not see its own grants).
    error: Option<String>,
}

/// Privileges that let a role change data or objects.
fn is_write_capable_privilege(privilege: &str) -> bool {
    let privilege = privilege.trim().to_ascii_uppercase();
    matches!(
        privilege.as_str(),
        "INSERT"
            | "UPDATE"
            | "DELETE"
            | "TRUNCATE"
            | "OWNERSHIP"
            | "ALL"
            | "ALL PRIVILEGES"
            | "EXECUTE TASK"
    ) || privilege.starts_with("CREATE ")
        || privilege.starts_with("APPLY ")
}

/// A role name as a quoted identifier (SHOW takes no bind variables).
fn quoted_identifier(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Walk `SHOW GRANTS TO ROLE` from `CURRENT_ROLE()` through the roles granted
/// to it (reality-check bead oj0.25; the enforceable read-only guard is
/// Snowflake's RBAC, not the client-side SQL classifier). Columns per
/// docs.snowflake.com/en/sql-reference/sql/show-grants (consulted 2026-09-24):
/// privilege, granted_on, name.
fn role_write_check(conn: &LiveConn) -> RoleCheck {
    let mut check = RoleCheck::default();
    let current = match execute(
        conn,
        "SELECT CURRENT_ROLE()",
        QueryRequestOptions::default(),
    ) {
        Ok(rows) => rows
            .rows
            .first()
            .and_then(|row| row.first())
            .cloned()
            .flatten(),
        Err(error) => {
            check.error = Some(format!("CURRENT_ROLE() failed ({})", error.stable_code()));
            return check;
        }
    };
    let Some(current) = current else {
        check.error = Some("the session has no current role".to_owned());
        return check;
    };
    check.role = Some(current.clone());
    let mut pending = vec![current];
    while let Some(role) = pending.pop() {
        if check.roles_checked.contains(&role) {
            continue;
        }
        if check.roles_checked.len() >= ROLE_WALK_LIMIT {
            check.partial = true;
            break;
        }
        let sql = format!("SHOW GRANTS TO ROLE {}", quoted_identifier(&role));
        let rows = match execute(conn, &sql, QueryRequestOptions::default()) {
            Ok(rows) => rows,
            Err(error) => {
                check.error = Some(format!(
                    "SHOW GRANTS TO ROLE {role} failed ({})",
                    error.stable_code()
                ));
                return check;
            }
        };
        let column = |name: &str| {
            rows.columns
                .iter()
                .position(|column| column.name.eq_ignore_ascii_case(name))
        };
        let (Some(privilege_at), Some(granted_on_at), Some(name_at)) =
            (column("privilege"), column("granted_on"), column("name"))
        else {
            check.error = Some("unrecognized SHOW GRANTS columns".to_owned());
            return check;
        };
        let via = if check.roles_checked.is_empty() {
            String::new()
        } else {
            format!(" (via {role})")
        };
        for row in &rows.rows {
            let cell = |at: usize| row.get(at).cloned().flatten().unwrap_or_default();
            let (privilege, granted_on, name) =
                (cell(privilege_at), cell(granted_on_at), cell(name_at));
            if granted_on.eq_ignore_ascii_case("ROLE") && privilege.eq_ignore_ascii_case("USAGE") {
                pending.push(name);
            } else if is_write_capable_privilege(&privilege) {
                check
                    .write_grants
                    .push(format!("{privilege} on {granted_on} {name}{via}"));
            }
        }
        check.roles_checked.push(role);
    }
    check
}

/// The doctor's reading of a [`RoleCheck`]: the `role_privileges` field, the
/// warnings, and a refusal when the profile expects a read-only role
/// (`<PREFIX>_READ_ONLY_EXPECTED=true`) but the role can write or the check
/// could not prove otherwise.
fn role_verdict(
    check: &RoleCheck,
    read_profile: bool,
    read_only_expected: bool,
) -> (Json, Vec<Json>, Option<SnowflakeError>) {
    let write_capable = if check.write_grants.is_empty() {
        if check.error.is_some() || check.partial {
            Json::Null
        } else {
            Json::Bool(false)
        }
    } else {
        Json::Bool(true)
    };
    let data = json_object(vec![
        ("role", option_json(check.role.clone())),
        ("write_capable", write_capable),
        (
            "write_grants",
            json_array(
                check
                    .write_grants
                    .iter()
                    .take(10)
                    .map(|grant| json_string(grant.clone()))
                    .collect(),
            ),
        ),
        (
            "roles_checked",
            json_array(
                check
                    .roles_checked
                    .iter()
                    .map(|role| json_string(role.clone()))
                    .collect(),
            ),
        ),
        ("partial", Json::Bool(check.partial)),
        ("note", option_json(check.error.clone())),
    ]);
    let role = check.role.clone().unwrap_or_else(|| "?".to_owned());
    let mut warnings = Vec::new();
    let mut problem = None;
    if !check.write_grants.is_empty() && (read_profile || read_only_expected) {
        let shown: Vec<&str> = check
            .write_grants
            .iter()
            .take(3)
            .map(String::as_str)
            .collect();
        problem = Some(format!(
            "this read profile's role `{role}` can mutate data ({}{}); give read profiles a read-only role",
            shown.join(", "),
            if check.write_grants.len() > 3 {
                ", ..."
            } else {
                ""
            }
        ));
    } else if read_only_expected && (check.error.is_some() || check.partial) {
        problem = Some(format!(
            "READ_ONLY_EXPECTED is set but the grants of role `{role}` could not be fully checked ({})",
            check
                .error
                .clone()
                .unwrap_or_else(|| format!("more than {ROLE_WALK_LIMIT} roles"))
        ));
    }
    let refusal = match problem {
        Some(message) if read_only_expected => Some(SnowflakeError::new(
            SnowflakeErrorCode::ProfileInvalid,
            message,
        )),
        Some(message) => {
            warnings.push(json_string(message));
            None
        }
        None => None,
    };
    (data, warnings, refusal)
}

/// Remaining lifetime of a resolved credential, with a warning when it is
/// short: OAuth under 10 minutes, a PAT within 2 days, or a key-pair JWT
/// validity above Snowflake's cap.
fn lifetime_findings(lifetime: &CredentialLifetime, now: i64) -> (Json, Vec<Json>) {
    let remaining = lifetime.seconds_until_expiry(now);
    let mut warnings = Vec::new();
    match (lifetime.lane, remaining) {
        (AuthLane::OAuthBearer, Some(seconds)) if seconds <= 600 => {
            warnings.push(json_string(format!(
                "the OAuth access token expires in {} minute(s); this connector cannot refresh it",
                (seconds.max(0) + 59) / 60
            )));
        }
        _ => {
            if let Some(warning) = lifetime.doctor_warning_at(now) {
                warnings.push(json_string(warning.message));
            }
        }
    }
    let data = json_object(vec![
        ("lane", json_string(lifetime.lane.to_string())),
        (
            "expires_in_seconds",
            remaining.map_or(Json::Null, Json::Number),
        ),
    ]);
    (data, warnings)
}

/// Active tokens and the soonest expiry from `SHOW USER PROGRAMMATIC ACCESS
/// TOKENS`; a warning when an active token expires within 7 days. `expires_at`
/// is a jsonv2 timestamp (fractional epoch seconds).
fn pat_token_findings(rows: &LiveRows, now: i64) -> (Json, Vec<Json>) {
    let column = |name: &str| {
        rows.columns
            .iter()
            .position(|column| column.name.eq_ignore_ascii_case(name))
    };
    let (Some(name_at), Some(expires_at), Some(status_at)) =
        (column("name"), column("expires_at"), column("status"))
    else {
        return (
            json_string("unrecognized SHOW USER PROGRAMMATIC ACCESS TOKENS columns"),
            Vec::new(),
        );
    };
    let cell = |row: &Vec<Option<String>>, at: usize| row.get(at).cloned().flatten();
    let mut active: Vec<(String, i64)> = rows
        .rows
        .iter()
        .filter(|row| {
            cell(row, status_at).is_some_and(|status| status.eq_ignore_ascii_case("ACTIVE"))
        })
        .filter_map(|row| {
            let seconds = cell(row, expires_at)?.trim().parse::<f64>().ok()?;
            Some((
                cell(row, name_at).unwrap_or_default(),
                seconds.floor() as i64,
            ))
        })
        .collect();
    active.sort_by_key(|(_, expires)| *expires);
    let mut warnings = Vec::new();
    if let Some((name, expires)) = active.first()
        && expires - now <= 7 * 24 * 60 * 60
    {
        warnings.push(json_string(format!(
            "programmatic access token `{name}` expires in {} day(s); rotate the profile's PAT if it is this one",
            ((expires - now).max(0) + 86_399) / 86_400
        )));
    }
    let data = json_object(vec![
        (
            "active",
            Json::Number(i64::try_from(active.len()).unwrap_or(i64::MAX)),
        ),
        (
            "soonest_expiry_unix_seconds",
            active
                .first()
                .map_or(Json::Null, |(_, expires)| Json::Number(*expires)),
        ),
    ]);
    (data, warnings)
}

#[allow(clippy::too_many_arguments)]
fn probe_success(
    format: OutputFormat,
    request_id: String,
    profile: String,
    version: Option<String>,
    rows: &LiveRows,
    receipt_hash: Option<String>,
    warnings: Vec<Json>,
    credential_lifetime: Json,
    role_privileges: Json,
) -> crate::Outcome {
    let data = json_object(vec![
        ("profile_id", json_string(profile.clone())),
        ("live_probe_requested", Json::Bool(true)),
        ("live_probe_attempted", Json::Bool(true)),
        ("live_probe_ok", Json::Bool(true)),
        // The probe authenticates, so the credential was read (never emitted).
        ("secret_values_read", Json::Bool(true)),
        ("credential_lifetime", credential_lifetime),
        ("role_privileges", role_privileges),
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
        format!(
            "franken-snowflake catalog scan {profile} --database <db> --schema <schema> --json"
        ),
        format!("franken-snowflake query run --profile {profile} --sql <sql> --json"),
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
    /// `<PREFIX>_CA_BUNDLE`: verify the server against this PEM bundle instead
    /// of the OS trust store (a TLS-intercepting proxy's CA).
    tls_roots: TlsRootPolicy,
    auth_profile: AuthProfile,
    max_polls: u32,
    /// Partition fetch window (`<PREFIX>_PARTITION_CONCURRENCY`, default 4).
    partition_concurrency: usize,
    /// `<PREFIX>_QUERY_TAG`: generated per invocation (unset), fixed, or off.
    query_tag_policy: QueryTagPolicy,
    /// The QUERY_TAG every statement of this invocation carries unless the
    /// request sets its own (`--query-tag`, the dataset planner); set by
    /// [`LiveConn::tagged`].
    query_tag: Option<String>,
    /// `--progress`: NDJSON progress events on stderr (reality-check bead E5).
    progress: bool,
    /// `<PREFIX>_MAX_CREDITS`: the advisory credit cap per request, in
    /// millionths of a credit (reality-check bead E3).
    max_microcredits: Option<u64>,
    /// `<PREFIX>_WAREHOUSE_CREDITS_PER_HOUR`: the warehouse's rate when the
    /// profile states it (else `SHOW WAREHOUSES` supplies it), in millionths.
    microcredits_per_hour: Option<u64>,
    /// The resolved credit cap, looked up once per invocation.
    cost_quota: std::cell::OnceCell<Result<Option<CostQuota>, SnowflakeError>>,
    /// Test-only: answers every `execute_request` from a script instead of the
    /// SQL API (see `test_support`). Always `None` in production builds.
    #[cfg(test)]
    script: Option<test_support::Script>,
}

impl LiveConn {
    /// The client-side execution bound: the statement timeout plus a margin
    /// (`0`, Snowflake's "no limit", sets none).
    fn execution_timeout(&self) -> Option<Duration> {
        self.execution_timeout_for(1)
    }

    /// The credit cap for this invocation's requests: `None` unless the profile
    /// sets `MAX_CREDITS`. The warehouse's rate is the profile's
    /// `WAREHOUSE_CREDITS_PER_HOUR` or, once per invocation, `SHOW WAREHOUSES`
    /// (which also says whether the warehouse is suspended, i.e. whether the
    /// run pays the resume minimum). A stated rate assumes a running warehouse.
    fn cost_quota(&self) -> Result<Option<CostQuota>, SnowflakeError> {
        self.cost_quota
            .get_or_init(|| {
                let Some(max_microcredits) = self.max_microcredits else {
                    return Ok(None);
                };
                let (microcredits_per_hour, resumes_warehouse) = match self.microcredits_per_hour {
                    Some(rate) => (rate, false),
                    None => warehouse_rate(self)?,
                };
                Ok(Some(CostQuota {
                    microcredits_per_hour,
                    max_microcredits,
                    resumes_warehouse,
                }))
            })
            .clone()
    }

    /// The bound for a request running `statements` statements one after
    /// another (a multi-statement batch's parent spans all of them): the
    /// statement timeout for each, plus one margin.
    fn execution_timeout_for(&self, statements: usize) -> Option<Duration> {
        (self.statement_timeout_seconds > 0).then(|| {
            let statements = u32::try_from(statements.max(1)).unwrap_or(u32::MAX);
            Duration::from_secs(u64::from(self.statement_timeout_seconds))
                .saturating_mul(statements)
                + CLIENT_DEADLINE_MARGIN
        })
    }

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
        // Refused before any credential is read or any socket opens.
        if crate::classify_auth_lane(&lane) == crate::AuthLaneStatus::Quarantined {
            return Err(SnowflakeError::new(
                SnowflakeErrorCode::ProfileInvalid,
                crate::WORKLOAD_IDENTITY_QUARANTINE,
            ));
        }
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
                format!(
                    "auth lane must be one of pat, oauth_bearer, key_pair_jwt, or workload_identity (got {lane})"
                ),
            ));
        }

        let account = account.unwrap_or_default();
        let endpoint = live_endpoint(&account).map_err(|error| {
            SnowflakeError::new(SnowflakeErrorCode::ProfileInvalid, error.message)
        })?;
        let tls_roots = env_value(&name(&prefix, "CA_BUNDLE"))
            .map_or(TlsRootPolicy::NativeRoots, |path| {
                TlsRootPolicy::ExplicitPemBundle(PathBuf::from(path))
            });
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
            tls_roots,
            auth_profile,
            max_polls: env_u32(&name(&prefix, "MAX_POLLS")).unwrap_or(DEFAULT_MAX_POLLS),
            partition_concurrency: env_u32(&name(&prefix, "PARTITION_CONCURRENCY"))
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(DEFAULT_PARTITION_CONCURRENCY)
                .clamp(1, MAX_PARTITION_CONCURRENCY),
            query_tag_policy: query_tag_policy(env_value(&name(&prefix, "QUERY_TAG")).as_deref())?,
            query_tag: None,
            progress: false,
            max_microcredits: env_microcredits(&name(&prefix, "MAX_CREDITS"))?,
            microcredits_per_hour: env_microcredits(&name(&prefix, "WAREHOUSE_CREDITS_PER_HOUR"))?,
            cost_quota: std::cell::OnceCell::new(),
            #[cfg(test)]
            script: None,
        })
    }

    /// Report progress on stderr as NDJSON (`--progress`).
    fn with_progress(mut self, progress: bool) -> Self {
        self.progress = progress;
        self
    }

    /// Bind the invocation's default QUERY_TAG (reality-check bead L5), so
    /// Snowflake's query history ties each statement back to its envelope:
    /// `fsnow:<command_id>:<request_id>` unless the profile fixes or disables it.
    fn tagged(mut self, command_id: &str, request_id: &str) -> Self {
        self.query_tag = match &self.query_tag_policy {
            QueryTagPolicy::Generated => Some(format!("fsnow:{command_id}:{request_id}")),
            QueryTagPolicy::Fixed(tag) => Some(tag.clone()),
            QueryTagPolicy::Off => None,
        };
        self
    }

    /// An explicit tag (`--query-tag`, the dataset planner's) replaces the
    /// default, so a failure receipt records the tag the statement ran with.
    fn with_statement_tag(mut self, tag: Option<&str>) -> Self {
        if let Some(tag) = tag {
            self.query_tag = Some(tag.to_owned());
        }
        self
    }
}

/// How a profile's statements are tagged (`<PREFIX>_QUERY_TAG`).
#[derive(Clone, Debug, PartialEq, Eq)]
enum QueryTagPolicy {
    /// Unset: `fsnow:<command_id>:<request_id>`.
    Generated,
    /// A fixed tag for every statement.
    Fixed(String),
    /// `off`: no default tag.
    Off,
}

fn query_tag_policy(raw: Option<&str>) -> Result<QueryTagPolicy, SnowflakeError> {
    match raw.map(str::trim) {
        None | Some("") => Ok(QueryTagPolicy::Generated),
        Some(value) if value.eq_ignore_ascii_case("off") => Ok(QueryTagPolicy::Off),
        Some(value) => validate_query_tag(value)
            .map(QueryTagPolicy::Fixed)
            .map_err(|_| {
                SnowflakeError::new(
                    SnowflakeErrorCode::ProfileInvalid,
                    format!(
                        "_QUERY_TAG must be `off` or 1..={MAX_QUERY_TAG_BYTES} bytes without control characters"
                    ),
                )
            }),
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
        let mut config = TransportConfig::new(conn.endpoint.clone());
        config.tls_roots = conn.tls_roots.clone();
        let client = SnowflakeHttpClient::for_runtime(config).map_err(|error| {
            SnowflakeError::new(
                SnowflakeErrorCode::ProfileInvalid,
                format!("the profile's CA bundle was refused: {}", error.message),
            )
        })?;
        let mut mechanism = conn
            .auth_profile
            .resolve(&ProcessSecretResolver, &conn.account, &conn.user)
            .map_err(|error| {
                let code = match error.stable_code() {
                    "FSNOW-2004" => SnowflakeErrorCode::CredentialExpired,
                    _ => SnowflakeErrorCode::CredentialMissing,
                };
                SnowflakeError::new(code, error.to_string())
            })?;
        if let AuthMechanism::WorkloadIdentityFederation(ref mut wif) = mechanism {
            let http_client = asupersync::http::Client::default_for_runtime(&cx);
            wif.token_for_poll_at(
                &cx,
                &http_client,
                &ProcessSecretResolver,
                now_unix_seconds(),
            )
            .await
            .map_err(|error| {
                let code = match error.stable_code() {
                    "FSNOW-2004" => SnowflakeErrorCode::CredentialExpired,
                    _ => SnowflakeErrorCode::CredentialMissing,
                };
                SnowflakeError::new(code, error.to_string())
            })?;
        }
        let mut auth = MechanismAuth { mechanism };
        // Resolve once up front so a missing/invalid credential fails before
        // any request is built, with the same typed error as before.
        auth.descriptor()?;
        let _in_flight = InFlight::enter();
        cancel_on_signal(&cx, body(&cx, &client, &mut auth)).await
    })
}

/// The SQL API endpoint for a profile's account. Production builds accept only
/// a Snowflake host. A `testkit-endpoint` build (never a release) also accepts
/// a loopback `https://127.0.0.1:<port>`, and only when the run opts in with
/// `FRANKEN_SNOWFLAKE_TESTKIT_ENDPOINT=1`, so the socket e2e reaches its mock
/// while every other test keeps the production refusal.
fn live_endpoint(account: &str) -> Result<SnowflakeEndpoint, TransportError> {
    #[cfg(feature = "testkit-endpoint")]
    if SnowflakeEndpoint::parse(endpoint_url(account)).is_err()
        && env_value("FRANKEN_SNOWFLAKE_TESTKIT_ENDPOINT").as_deref() == Some("1")
        && let Ok(loopback) = SnowflakeEndpoint::parse_testkit_loopback(account)
    {
        return Ok(loopback);
    }
    SnowflakeEndpoint::parse(endpoint_url(account))
}

// ---------------------------------------------------------------------------
// Signals (reality-check bead E1)
// ---------------------------------------------------------------------------

/// How often an in-flight statement checks for a pending signal.
const SIGNAL_CHECK_INTERVAL: Duration = Duration::from_millis(100);

/// Process-wide signal state, installed on first use through signal-hook's
/// flag API (Asupersync's dispatcher is not used: it would keep SIGINT/SIGTERM
/// away from the default action for the rest of the process, so a long-lived
/// `mcp serve` could not be stopped with Ctrl-C).
///
/// - No statement in flight (`idle`): SIGINT/SIGTERM keep their default
///   action; the process ends as it always did.
/// - A statement in flight: the first signal only sets its pending flag, which
///   [`cancel_on_signal`] turns into a cancellation of the statement's `Cx`
///   (`User` for SIGINT, `Shutdown` for SIGTERM), so the driver fires the
///   SQL API remote cancel and the envelope says `cancelled`.
/// - A second signal while the first is pending exits at once (130 / 143).
struct SignalFlags {
    idle: Arc<AtomicBool>,
    interrupt: Arc<AtomicBool>,
    terminate: Arc<AtomicBool>,
    /// Statements in flight (`mcp serve --http` can run several at once).
    in_flight: AtomicUsize,
}

static SIGNAL_FLAGS: OnceLock<Option<SignalFlags>> = OnceLock::new();

fn signal_flags() -> Option<&'static SignalFlags> {
    SIGNAL_FLAGS
        .get_or_init(|| {
            use signal_hook::consts::{SIGINT, SIGTERM};
            use signal_hook::flag;
            let flags = SignalFlags {
                idle: Arc::new(AtomicBool::new(true)),
                interrupt: Arc::new(AtomicBool::new(false)),
                terminate: Arc::new(AtomicBool::new(false)),
                in_flight: AtomicUsize::new(0),
            };
            // Registration order matters: signal-hook runs the actions in order.
            for (signal, pending, status) in [
                (SIGINT, &flags.interrupt, 130),
                (SIGTERM, &flags.terminate, 143),
            ] {
                flag::register_conditional_default(signal, Arc::clone(&flags.idle)).ok()?;
                flag::register_conditional_shutdown(signal, status, Arc::clone(pending)).ok()?;
                flag::register(signal, Arc::clone(pending)).ok()?;
            }
            Some(flags)
        })
        .as_ref()
}

/// The exit status of a run that a signal cancelled: 130 after SIGINT, 143
/// after SIGTERM (the shell convention, so a script's `set -e` or loop stops
/// as it would for any interrupted command). `None` when no signal arrived;
/// never installs the handlers itself.
pub(crate) fn signal_exit_status() -> Option<u8> {
    let flags = SIGNAL_FLAGS.get().and_then(Option::as_ref)?;
    signal_status(
        flags.interrupt.load(Ordering::SeqCst),
        flags.terminate.load(Ordering::SeqCst),
    )
}

fn signal_status(interrupt: bool, terminate: bool) -> Option<u8> {
    if interrupt {
        Some(130)
    } else if terminate {
        Some(143)
    } else {
        None
    }
}

/// Marks a statement in flight for the signal handlers; restores the default
/// action when dropped (a panic unwinding through the runtime included).
struct InFlight(&'static SignalFlags);

impl InFlight {
    fn enter() -> Option<Self> {
        let flags = signal_flags()?;
        if flags.in_flight.fetch_add(1, Ordering::SeqCst) == 0 {
            // First statement in flight: forget signals from an idle period.
            flags.interrupt.store(false, Ordering::SeqCst);
            flags.terminate.store(false, Ordering::SeqCst);
        }
        flags.idle.store(false, Ordering::SeqCst);
        Some(Self(flags))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if self.0.in_flight.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.idle.store(true, Ordering::SeqCst);
        }
    }
}

/// Reports whether the MCP request a statement serves was cancelled.
pub(crate) type CancelProbe = Arc<dyn Fn() -> bool + Send + Sync>;

thread_local! {
    /// The cancel probe of the MCP request or TUI query this thread is
    /// serving, if any.
    static EXTERNAL_CANCEL: RefCell<Option<CancelProbe>> = const { RefCell::new(None) };
}

/// Receives every driver event of the statements this thread runs (the TUI's
/// progress pane).
pub(crate) type ProgressSink = Arc<dyn Fn(&DriverEvent) + Send + Sync>;

thread_local! {
    /// The progress sink of the TUI query this thread is running, if any.
    static PROGRESS_SINK: RefCell<Option<ProgressSink>> = const { RefCell::new(None) };
}

/// Run `work` with `sink` receiving this thread's driver events.
#[cfg_attr(not(feature = "tui"), allow(dead_code))]
pub(crate) fn with_progress_sink<T>(sink: ProgressSink, work: impl FnOnce() -> T) -> T {
    struct Reset(Option<ProgressSink>);
    impl Drop for Reset {
        fn drop(&mut self) {
            let previous = self.0.take();
            PROGRESS_SINK.with(|slot| *slot.borrow_mut() = previous);
        }
    }
    let _reset = Reset(PROGRESS_SINK.with(|slot| slot.borrow_mut().replace(sink)));
    work()
}

/// Run `work` with `cancel` as this thread's external cancel probe.
#[cfg_attr(not(any(feature = "mcp", feature = "tui")), allow(dead_code))]
pub(crate) fn with_external_cancel<T>(cancel: CancelProbe, work: impl FnOnce() -> T) -> T {
    struct Reset(Option<CancelProbe>);
    impl Drop for Reset {
        fn drop(&mut self) {
            let previous = self.0.take();
            EXTERNAL_CANCEL.with(|slot| *slot.borrow_mut() = previous);
        }
    }
    let _reset = Reset(EXTERNAL_CANCEL.with(|slot| slot.borrow_mut().replace(cancel)));
    work()
}

/// Drive `work` to completion; a pending SIGINT/SIGTERM, or the external
/// cancel probe of an MCP request, cancels `cx` once.
async fn cancel_on_signal<T>(cx: &Cx, work: impl std::future::Future<Output = T>) -> T {
    static NEVER: AtomicBool = AtomicBool::new(false);
    let external = EXTERNAL_CANCEL.with(|slot| slot.borrow().clone());
    match signal_flags() {
        Some(flags) => {
            cancel_on_flags(cx, work, &flags.interrupt, &flags.terminate, external).await
        }
        None if external.is_some() => cancel_on_flags(cx, work, &NEVER, &NEVER, external).await,
        None => work.await,
    }
}

/// The signal-independent core of [`cancel_on_signal`] (unit-testable).
async fn cancel_on_flags<T>(
    cx: &Cx,
    work: impl std::future::Future<Output = T>,
    interrupt: &AtomicBool,
    terminate: &AtomicBool,
    external: Option<CancelProbe>,
) -> T {
    use std::task::Poll;
    let mut work = std::pin::pin!(work);
    let mut raised = false;
    loop {
        let tick = asupersync::time::sleep(cx.now_for_observability(), SIGNAL_CHECK_INTERVAL);
        let mut tick = std::pin::pin!(tick);
        let finished = std::future::poll_fn(|task| {
            if let Poll::Ready(value) = work.as_mut().poll(task) {
                return Poll::Ready(Some(value));
            }
            if tick.as_mut().poll(task).is_ready() {
                return Poll::Ready(None);
            }
            Poll::Pending
        })
        .await;
        if let Some(value) = finished {
            return value;
        }
        if !raised {
            if interrupt.load(Ordering::SeqCst) {
                cx.cancel_with(CancelKind::User, Some("interrupted (SIGINT)"));
                raised = true;
            } else if terminate.load(Ordering::SeqCst) {
                cx.cancel_with(CancelKind::Shutdown, Some("terminated (SIGTERM)"));
                raised = true;
            } else if external.as_ref().is_some_and(|cancelled| cancelled()) {
                cx.cancel_with(
                    CancelKind::User,
                    Some("the request was cancelled (MCP cancellation or TUI Esc)"),
                );
                raised = true;
            }
        }
    }
}

/// What one statement run learned beyond its outcome: the handle Snowflake
/// issued (none when the statement was never accepted) and the answer to the
/// remote cancel, when one was sent (reality-check bead E1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RunFacts {
    statement_handle: Option<String>,
    remote_cancel: Option<(bool, String)>,
}

thread_local! {
    /// The facts of the last statement run on this thread, for the terminal
    /// receipt of a run that ended without rows.
    static LAST_RUN: RefCell<RunFacts> = RefCell::new(RunFacts::default());
}

/// Watches every live statement: records its [`RunFacts`] and, with
/// `--progress`, prints one JSON object per driver event on stderr (stdout
/// keeps the single envelope), with the milliseconds since the statement
/// started.
struct RunObserver {
    started: Instant,
    progress: bool,
    facts: RunFacts,
    sink: Option<ProgressSink>,
}

impl RunObserver {
    fn new(progress: bool) -> Self {
        Self {
            started: Instant::now(),
            progress,
            facts: RunFacts::default(),
            sink: PROGRESS_SINK.with(|slot| slot.borrow().clone()),
        }
    }
}

impl DriverObserver for RunObserver {
    fn event(&mut self, event: DriverEvent) {
        match &event {
            DriverEvent::Submitted {
                statement_handle: Some(handle),
                ..
            } => self.facts.statement_handle = Some(handle.clone()),
            DriverEvent::RemoteCancel {
                statement_handle,
                acknowledged,
                detail,
            } => {
                self.facts
                    .statement_handle
                    .get_or_insert_with(|| statement_handle.clone());
                self.facts.remote_cancel = Some((*acknowledged, detail.clone()));
            }
            _ => {}
        }
        if let Some(sink) = &self.sink {
            sink(&event);
        }
        if self.progress {
            use std::io::Write as _;
            let elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let line = progress_line(&event, elapsed_ms);
            let _ = writeln!(std::io::stderr().lock(), "{line}");
        }
    }
}

fn progress_line(event: &DriverEvent, elapsed_ms: u64) -> String {
    let value = match event {
        DriverEvent::Submitted {
            statement_handle,
            running,
        } => serde_json::json!({
            "event": "submitted", "statement_handle": statement_handle,
            "running": running, "elapsed_ms": elapsed_ms,
        }),
        DriverEvent::Polled { polls } => {
            serde_json::json!({ "event": "polled", "polls": polls, "elapsed_ms": elapsed_ms })
        }
        DriverEvent::PartitionFetched { index, rows, bytes } => serde_json::json!({
            "event": "partition_fetched", "index": index, "rows": rows,
            "bytes": bytes, "elapsed_ms": elapsed_ms,
        }),
        DriverEvent::Completed { rows, partitions } => serde_json::json!({
            "event": "completed", "rows": rows, "partitions": partitions,
            "elapsed_ms": elapsed_ms,
        }),
        DriverEvent::RemoteCancel {
            statement_handle,
            acknowledged,
            detail,
        } => serde_json::json!({
            "event": "remote_cancel", "statement_handle": statement_handle,
            "acknowledged": acknowledged, "detail": detail, "elapsed_ms": elapsed_ms,
        }),
    };
    value.to_string()
}

/// Submit one prepared request and drive it to completion under the profile's
/// bounds and credit cap. Returns the completed statement, the driver's
/// stats, and the SQL API `requestId`.
fn execute_request(
    conn: &LiveConn,
    request: SubmitStatementRequest,
    row_cap: Option<usize>,
    fixed_request_id: Option<String>,
) -> Result<(CompletedStatement, DriverStats, String), SnowflakeError> {
    let cost_quota = conn.cost_quota()?;
    drive_request(conn, request, row_cap, fixed_request_id, cost_quota)
}

/// [`execute_request`] with an explicit credit cap (the rate lookup's own
/// `SHOW WAREHOUSES` runs without one).
fn drive_request(
    conn: &LiveConn,
    request: SubmitStatementRequest,
    row_cap: Option<usize>,
    fixed_request_id: Option<String>,
    cost_quota: Option<CostQuota>,
) -> Result<(CompletedStatement, DriverStats, String), SnowflakeError> {
    let sql_api_request_id = fixed_request_id.unwrap_or_else(unique_request_id);
    LAST_RUN.with(RefCell::take);
    let poll_plan = PollPlan::with_max_polls(conn.max_polls)
        .with_partition_concurrency(conn.partition_concurrency)
        .with_row_cap(row_cap)
        .with_execution_timeout(conn.execution_timeout())
        .with_cost_quota(cost_quota);
    #[cfg(test)]
    if let Some(script) = &conn.script {
        return script.execute(request, poll_plan, &sql_api_request_id);
    }
    let params = SubmitQueryParams {
        request_id: Some(sql_api_request_id.clone()),
        retry: true,
        asynchronous: false,
        nullable: None,
    };
    let progress = conn.progress;
    let (outcome, stats, facts) = with_runtime(conn, move |cx, client, auth| {
        Box::pin(async move {
            let mut observer = RunObserver::new(progress);
            let hooks = StatementHooks {
                sink: None,
                observer: Some(&mut observer),
            };
            let (outcome, stats) =
                run_statement_hooked(cx, client, auth, request, params, poll_plan, hooks).await;
            Ok((outcome, stats, observer.facts))
        })
    })?;
    LAST_RUN.with(|slot| *slot.borrow_mut() = facts);
    outcome_into_result(outcome, "the statement", true)
        .map(|done| (done, stats, sql_api_request_id))
}

/// Carry the driver's four-valued outcome onto the CLI error channel without
/// flattening it (reality-check bead C6): a cancellation keeps its kind, so
/// the envelope reads `cancelled`/`timeout` and the exit code follows the
/// core cancel policy, and a panic keeps its redacted payload summary.
fn outcome_into_result<T>(
    outcome: Outcome<T, SnowflakeError>,
    what: &str,
    submitted_statement: bool,
) -> Result<T, SnowflakeError> {
    match outcome {
        Outcome::Ok(value) => Ok(value),
        Outcome::Err(error) => Err(error),
        Outcome::Cancelled(reason) => {
            let remote = if !submitted_statement {
                ""
            } else if attempts_remote_cancel(cancel_policy(reason.kind)) {
                "; a best-effort remote cancel was sent for the submitted statement, if any"
            } else {
                "; no remote cancel (the statement drains quietly)"
            };
            Err(SnowflakeError::cancelled(
                reason.kind,
                format!(
                    "{what} was cancelled before completion (cancel kind {:?}){remote}",
                    reason.kind
                ),
            ))
        }
        Outcome::Panicked(payload) => Err(SnowflakeError::new(
            SnowflakeErrorCode::Internal,
            format!("{what} panicked: {}", redact(payload.message())),
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
    let fixed_request_id = options.sql_api_request_id.clone();
    let request = build_request(conn, sql, options);
    let query_tag = request
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.get("QUERY_TAG"))
        .cloned();
    let (done, stats, sql_api_request_id) =
        execute_request(conn, request, row_cap, fixed_request_id)?;
    let mut rows = into_rows(done, stats, sql_api_request_id);
    rows.query_tag = query_tag;
    Ok(rows)
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
    if let Some(tag) = &conn.query_tag {
        parameters.insert("QUERY_TAG".to_owned(), tag.clone());
    }
    if let Some(existing) = request.parameters.take() {
        parameters.extend(existing);
    }
    // Server-side backstop for the client's one-statement guard: with an
    // explicit count of 1, Snowflake rejects a request whose statement count
    // differs instead of running it, whatever the account/user default is (the
    // documented request default is 1, but a MULTI_STATEMENT_COUNT parameter can
    // be set at account level). Inserted last so nothing can override it.
    parameters.insert("MULTI_STATEMENT_COUNT".to_owned(), "1".to_owned());
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
        statement_handle: Some(&rows.statement_handle),
        sql_api_request_id: Some(&rows.sql_api_request_id),
        query_tag: rows.query_tag.as_deref(),
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
        terminal_failure: None,
    };
    match local_store::record_execution(&store, &facts) {
        Ok(hash) => (Some(hash), Vec::new()),
        Err(error) => (
            None,
            vec![json_string(format!("receipt not recorded: {error}"))],
        ),
    }
}

/// A live statement ended without rows (failed, cancelled, or timed out):
/// record a receipt that says how, and point the failure envelope at it, so
/// `receipt show` can explain the attempt later (reality-check bead C6).
fn with_terminal_receipt(
    mut outcome: crate::Outcome,
    command_id: &str,
    conn: &LiveConn,
    trace_id: &str,
    sql: &str,
    error: &SnowflakeError,
) -> crate::Outcome {
    let outcome_kind = match error.cancel_kind.map(cancel_outcome_kind) {
        Some(OutcomeKind::Timeout) => "timeout",
        Some(_) => "cancelled",
        None if error.code == SnowflakeErrorCode::StatementTimeout => "timeout",
        None => "error",
    };
    let cancel_kind = error.cancel_kind.map(|kind| format!("{kind:?}"));
    let message = redact(&error.message);
    let preview = crate::compact_sql(&redact(sql));
    let run = LAST_RUN.with(RefCell::take);
    let facts = ExecutionFacts {
        command_id,
        profile: &conn.profile,
        trace_id,
        sql_preview_redacted: &preview,
        statement_handle: run.statement_handle.as_deref(),
        sql_api_request_id: None,
        query_tag: conn.query_tag.as_deref(),
        row_count: 0,
        partitions: &[],
        columns: &[],
        warehouse: Some(&conn.warehouse),
        database: conn.database.as_deref(),
        schema: conn.schema.as_deref(),
        role: conn.role.as_deref(),
        statement_timeout_seconds: conn.statement_timeout_seconds,
        polls: 0,
        event_kind: "statement_terminal",
        extra: terminal_run_json(&run),
        terminal_failure: Some(local_store::TerminalFailure {
            outcome_kind,
            error_code: error.stable_code(),
            message: &message,
            cancel_kind: cancel_kind.as_deref(),
        }),
    };
    let recorded = local_store::open_store()
        .map_err(|error| error.message())
        .and_then(|store| {
            local_store::record_execution(&store, &facts).map_err(|error| error.to_string())
        });
    if let crate::Body::Envelope { envelope, .. } = &mut outcome.body {
        if run.statement_handle.is_some() {
            envelope.statement_handle.clone_from(&run.statement_handle);
            envelope.query_id.clone_from(&run.statement_handle);
        }
        match recorded {
            Ok(hash) => {
                envelope
                    .safe_next_commands
                    .insert(0, receipt_show_command(Some(&hash)));
                envelope.receipt_hash = Some(hash);
            }
            Err(message) => envelope
                .warnings
                .push(json_string(format!("receipt not recorded: {message}"))),
        }
    }
    outcome
}

/// The terminal receipt's account of the run: whether Snowflake ever accepted
/// the statement (a run cancelled while connecting never was) and, when a
/// remote cancel was sent, whether Snowflake acknowledged it.
fn terminal_run_json(run: &RunFacts) -> serde_json::Value {
    let mut extra = serde_json::json!({
        "accepted_by_snowflake": run.statement_handle.is_some(),
    });
    if let (Some((acknowledged, detail)), Some(body)) = (&run.remote_cancel, extra.as_object_mut())
    {
        body.insert(
            "remote_cancel".to_owned(),
            serde_json::json!({ "acknowledged": acknowledged, "detail": detail }),
        );
    }
    extra
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
    envelope.budget_consumed = budget_consumed(rows.stats.polls, &rows.stats, rows.total_rows);
}

/// `budget_consumed` for a live run: what was measured (polls, execution
/// time, rows) beside the bounds each statement ran under: the poll quota, the
/// client-side execution deadline (absent when none was set) and, with a credit
/// cap, the warehouse rate, the cap and the estimate, in millionths of a credit.
fn budget_consumed(polls: u32, bounds: &DriverStats, rows: i64) -> Json {
    let millis =
        |duration: Duration| Json::Number(i64::try_from(duration.as_millis()).unwrap_or(i64::MAX));
    let micro = |value: u64| Json::Number(i64::try_from(value).unwrap_or(i64::MAX));
    let mut fields = vec![
        ("polls", Json::Number(i64::from(polls))),
        ("poll_quota", Json::Number(i64::from(bounds.poll_quota))),
    ];
    if let Some(timeout) = bounds.execution_timeout {
        fields.push(("execution_timeout_ms", millis(timeout)));
    }
    if let Some(execution) = bounds.execution {
        fields.push(("execution_ms", millis(execution)));
    }
    if let Some(quota) = bounds.cost_quota {
        fields.push(("microcredits_per_hour", micro(quota.microcredits_per_hour)));
        fields.push(("max_microcredits", micro(quota.max_microcredits)));
        fields.push((
            "estimated_microcredits",
            micro(quota.estimate(bounds.execution.unwrap_or_default())),
        ));
    }
    fields.push(("rows", Json::Number(rows)));
    json_object(fields)
}

/// `<PREFIX>_MAX_CREDITS` / `<PREFIX>_WAREHOUSE_CREDITS_PER_HOUR`: a positive
/// decimal number of credits with at most six decimals, in millionths.
fn env_microcredits(key: &str) -> Result<Option<u64>, SnowflakeError> {
    let Some(value) = env_value(key) else {
        return Ok(None);
    };
    parse_microcredits(&value).map(Some).ok_or_else(|| {
        SnowflakeError::new(
            SnowflakeErrorCode::ProfileInvalid,
            format!("{key} must be a positive number of credits with at most six decimals"),
        )
    })
}

/// A positive decimal (`0.05`, `1`, `.25`) in millionths, exactly.
fn parse_microcredits(text: &str) -> Option<u64> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    if (whole.is_empty() && fraction.is_empty())
        || !digits(whole)
        || !digits(fraction)
        || fraction.len() > 6
    {
        return None;
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let fraction: u64 = format!("{fraction:0<6}").parse().ok()?;
    let micro = whole.checked_mul(1_000_000)?.checked_add(fraction)?;
    (micro > 0).then_some(micro)
}

/// Where the rates of warehouses without a published per-size rate live
/// (Gen2 standard and Snowpark-optimized; consulted 2026-09-25).
const CREDIT_TABLE_URL: &str = "https://www.snowflake.com/legal-files/CreditConsumptionTable.pdf";

/// The warehouse's rate (millionths of a credit per hour) and whether it is
/// suspended, from `SHOW WAREHOUSES`. Only Gen1 standard warehouses have a
/// published per-size rate; any other warehouse is refused with the profile
/// variable that states the rate.
fn warehouse_rate(conn: &LiveConn) -> Result<(u64, bool), SnowflakeError> {
    let quoted = conn
        .warehouse
        .strip_prefix('"')
        .and_then(|name| name.strip_suffix('"'));
    let wanted = quoted.map_or_else(|| conn.warehouse.clone(), |name| name.replace("\"\"", "\""));
    let sql = format!("SHOW WAREHOUSES LIKE '{}'", wanted.replace('\'', "''"));
    let request = build_request(conn, &sql, QueryRequestOptions::default());
    let (done, stats, id) = drive_request(conn, request, None, None, None)?;
    let listed = into_rows(done, stats, id);
    let column = |name: &str| {
        listed
            .columns
            .iter()
            .position(|column| column.name.eq_ignore_ascii_case(name))
    };
    let (name_at, state_at, type_at, size_at, generation_at) = (
        column("name"),
        column("state"),
        column("type"),
        column("size"),
        column("generation"),
    );
    let cell = |row: &Vec<Option<String>>, at: Option<usize>| {
        at.and_then(|at| row.get(at)).and_then(|cell| cell.clone())
    };
    let row = listed
        .rows
        .iter()
        .find(|row| {
            cell(row, name_at).is_some_and(|name| {
                if quoted.is_some() {
                    name == wanted
                } else {
                    name.eq_ignore_ascii_case(&wanted)
                }
            })
        })
        .ok_or_else(|| {
            SnowflakeError::new(
                SnowflakeErrorCode::ProfileInvalid,
                format!(
                    "MAX_CREDITS needs the warehouse's credit rate, and SHOW WAREHOUSES does not list {} for this role",
                    conn.warehouse
                ),
            )
        })?;
    warehouse_row_rate(
        cell(row, type_at).as_deref(),
        cell(row, size_at).as_deref(),
        cell(row, generation_at).as_deref(),
        cell(row, state_at).as_deref(),
    )
    .map_err(|what| {
        let prefix = crate::profile_env_prefix(&conn.profile);
        SnowflakeError::new(
            SnowflakeErrorCode::ProfileInvalid,
            format!(
                "the credit rate of {what} is not published in Snowflake's docs; set {} to its credits per hour ({CREDIT_TABLE_URL})",
                name(&prefix, "WAREHOUSE_CREDITS_PER_HOUR")
            ),
        )
    })
}

/// A `SHOW WAREHOUSES` row's rate and whether the warehouse is suspended, or
/// what makes its rate unknown.
fn warehouse_row_rate(
    kind: Option<&str>,
    size: Option<&str>,
    generation: Option<&str>,
    state: Option<&str>,
) -> Result<(u64, bool), String> {
    let kind = kind.unwrap_or("STANDARD");
    if !kind.eq_ignore_ascii_case("STANDARD") {
        return Err(format!("a {kind} warehouse"));
    }
    if let Some(generation) = generation.filter(|generation| generation.trim() != "1") {
        return Err(format!("a generation {generation} standard warehouse"));
    }
    let size = size.unwrap_or("(no size)");
    let rate =
        gen1_microcredits_per_hour(size).ok_or_else(|| format!("a warehouse of size {size}"))?;
    Ok((
        rate,
        state.is_some_and(|state| state.eq_ignore_ascii_case("SUSPENDED")),
    ))
}

/// The Gen1 standard warehouse rate for a `SHOW WAREHOUSES` size, in millionths
/// of a credit per hour
/// (<https://docs.snowflake.com/en/user-guide/warehouses-overview>, consulted
/// 2026-09-25: X-Small 1 credit per hour, doubling per size to 6X-Large 512).
fn gen1_microcredits_per_hour(size: &str) -> Option<u64> {
    let key: String = size
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|character| character.to_ascii_lowercase())
        .collect();
    let credits: u64 = match key.as_str() {
        "xsmall" => 1,
        "small" => 2,
        "medium" => 4,
        "large" => 8,
        "xlarge" => 16,
        "2xlarge" | "x2large" | "xxlarge" => 32,
        "3xlarge" | "x3large" | "xxxlarge" => 64,
        "4xlarge" | "x4large" => 128,
        "5xlarge" | "x5large" => 256,
        "6xlarge" | "x6large" => 512,
        _ => return None,
    };
    Some(credits * 1_000_000)
}

/// The copy-pasteable `receipt show` command for a given receipt hash.
fn receipt_show_command(receipt_hash: Option<&str>) -> String {
    match receipt_hash {
        Some(hash) => format!("franken-snowflake receipt show {hash} --json"),
        None => "franken-snowflake receipt show <receipt-hash> --json".to_string(),
    }
}

/// The secret env-var name a given auth lane requires, or `None` for an
/// unknown/unsupported lane.
fn secret_env_for_lane(prefix: &str, lane: &str) -> Option<String> {
    match lane {
        "pat" | "programmatic_access_token" => Some(name(prefix, "PAT")),
        "oauth" | "oauth_bearer" | "oauth_bearer_token" => Some(name(prefix, "OAUTH_BEARER")),
        "key_pair_jwt" | "jwt" => Some(name(prefix, "PRIVATE_KEY_PEM")),
        "workload_identity" | "workload_identity_federation" | "oidc" => {
            if env_value(&name(prefix, "OIDC_TOKEN_FILE")).is_some() {
                Some(name(prefix, "OIDC_TOKEN_FILE"))
            } else {
                Some(name(prefix, "OIDC_TOKEN"))
            }
        }
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
        "workload_identity" | "workload_identity_federation" | "oidc" => {
            let token_source = if let Some(path) = env_value(&name(prefix, "OIDC_TOKEN_FILE")) {
                OidcTokenSource::file(path)
            } else if env_value(&name(prefix, "OIDC_TOKEN")).is_some() {
                OidcTokenSource::env_var(name(prefix, "OIDC_TOKEN"))
            } else {
                return Err(SnowflakeError::new(
                    SnowflakeErrorCode::CredentialMissing,
                    format!(
                        "either {}_OIDC_TOKEN_FILE or {}_OIDC_TOKEN must be set",
                        prefix, prefix
                    ),
                ));
            };
            let token_url = env_value(&name(prefix, "OIDC_TOKEN_URL"))
                .or_else(|| env_value(&name(prefix, "TOKEN_URL")));
            let scope = env_value(&name(prefix, "OIDC_SCOPE"));
            let client_id = env_value(&name(prefix, "OIDC_CLIENT_ID"));
            let refresh_before_expiry_seconds =
                env_u64(&name(prefix, "OIDC_REFRESH_BEFORE_EXPIRY_SECONDS"));
            Ok(AuthProfile::WorkloadIdentityFederation {
                token_source,
                token_url,
                scope,
                client_id,
                refresh_before_expiry_seconds,
            })
        }
        other => Err(SnowflakeError::new(
            SnowflakeErrorCode::ProfileInvalid,
            format!(
                "auth lane must be one of pat, oauth_bearer, key_pair_jwt, or workload_identity (got {other})"
            ),
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
    bindings_json: Option<&str>,
    query_tag: Option<&str>,
) -> Result<QueryRequestOptions, SnowflakeError> {
    let bindings = if let Some(encoded) = bindings_json {
        Some(parse_bindings_payload(encoded)?)
    } else {
        bindings_env.map(parse_bindings_env).transpose()?
    };
    let query_tag = query_tag.map(validate_query_tag).transpose()?;
    Ok(QueryRequestOptions {
        row_cap: None,
        bindings,
        query_tag,
        sql_api_request_id: None,
    })
}

/// Parse and validate an inline typed-bindings JSON payload (the same shape
/// `--bindings-env` carries) for embedded callers like the TUI executor.
fn parse_bindings_payload(encoded: &str) -> Result<BTreeMap<String, Binding>, SnowflakeError> {
    if encoded.len() > MAX_BINDINGS_JSON_BYTES {
        return Err(SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            format!("bindings payload exceeds {MAX_BINDINGS_JSON_BYTES} bytes"),
        ));
    }
    let bindings = serde_json::from_str::<BTreeMap<String, Binding>>(encoded).map_err(|error| {
        SnowflakeError::new(
            SnowflakeErrorCode::UsageError,
            format!("bindings payload is not a typed positional binding object: {error}"),
        )
    })?;
    validate_bindings(&bindings)?;
    Ok(bindings)
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
            precision: column.precision.and_then(|p| u32::try_from(p).ok()),
            scale: column.scale.and_then(|s| u32::try_from(s).ok()),
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
        query_tag: None,
    }
}

/// How result cells are rendered (reality-check bead C1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowEncoding {
    /// `typed.v1`: one JSON representation per column, chosen from its rowType.
    Typed,
    /// `jsonv2.wire`: the SQL API strings as received (`--raw-cells`).
    Wire,
}

impl RowEncoding {
    fn from_raw_cells(raw_cells: bool) -> Self {
        if raw_cells { Self::Wire } else { Self::Typed }
    }

    fn token(self) -> &'static str {
        match self {
            Self::Typed => TYPED_ROW_ENCODING,
            Self::Wire => WIRE_ROW_ENCODING,
        }
    }
}

/// An envelope's `columns` and `rows`, plus a warning per column that could not
/// be typed.
struct ProjectedRows {
    columns: Json,
    rows: Json,
    warnings: Vec<Json>,
}

/// Render the first `returned` rows. In `typed.v1` every column gets one
/// representation from its rowType (`columns[].json_repr`); a column holding a
/// cell that does not match its wire convention keeps the wire strings for all
/// of its cells (`json_repr: "wire"`) and is named in a warning. Cell values
/// never appear in a warning.
fn project_rows(rows: &LiveRows, returned: usize, encoding: RowEncoding) -> ProjectedRows {
    let shown = rows.rows.get(..returned).unwrap_or(rows.rows.as_slice());
    let mut cells: Vec<Vec<Json>> = shown
        .iter()
        .map(|_| Vec::with_capacity(rows.columns.len()))
        .collect();
    let mut columns = Vec::with_capacity(rows.columns.len());
    let mut warnings = Vec::new();
    for (index, column) in rows.columns.iter().enumerate() {
        let codec = ColumnCodec::new(
            &column.type_name,
            column.precision.map(i64::from),
            column.scale.map(i64::from),
        );
        let wire = |row: &Vec<Option<String>>| row.get(index).cloned().flatten();
        let typed = match encoding {
            RowEncoding::Wire => None,
            RowEncoding::Typed => match shown
                .iter()
                .map(|row| codec.decode(wire(row).as_deref()).map(Json::from_serde))
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(typed) => Some(typed),
                Err(error) => {
                    warnings.push(json_string(format!(
                        "column `{}` ({}): a cell {error}; the column keeps the jsonv2 wire strings",
                        column.name, column.type_name
                    )));
                    None
                }
            },
        };
        let json_repr = if typed.is_some() {
            codec.json_repr()
        } else {
            JsonRepr::Wire
        };
        let values = typed.unwrap_or_else(|| {
            shown
                .iter()
                .map(|row| wire(row).map_or(Json::Null, json_string))
                .collect()
        });
        for (row_cells, value) in cells.iter_mut().zip(values) {
            row_cells.push(value);
        }
        columns.push(json_object(vec![
            ("name", json_string(column.name.clone())),
            ("type", json_string(column.type_name.clone())),
            ("nullable", Json::Bool(column.nullable)),
            (
                "precision",
                column
                    .precision
                    .map_or(Json::Null, |precision| Json::Number(i64::from(precision))),
            ),
            (
                "scale",
                column
                    .scale
                    .map_or(Json::Null, |scale| Json::Number(i64::from(scale))),
            ),
            ("json_repr", json_string(json_repr.as_str())),
        ]));
    }
    ProjectedRows {
        columns: json_array(columns),
        rows: json_array(cells.into_iter().map(json_array).collect()),
        warnings,
    }
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
    encoding: RowEncoding,
    receipt_hash: Option<String>,
    mut warnings: Vec<Json>,
    safe_next_commands: Vec<String>,
) -> crate::Outcome {
    let returned = rows.rows.len().min(emit_cap);
    let truncated = rows.rows.len() > emit_cap;
    let projected = project_rows(rows, returned, encoding);
    warnings.extend(projected.warnings);
    leading.extend(vec![
        ("row_encoding", json_string(encoding.token())),
        ("columns", projected.columns),
        ("rows", projected.rows),
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
    let outcome_kind = match error.cancel_kind.map(cancel_outcome_kind) {
        Some(OutcomeKind::Timeout) => "timeout",
        Some(_) => "cancelled",
        None => outcome_kind_for(error.code),
    };
    let mut evidence = vec![json_string("live SQL API transport")];
    if let Some(kind) = error.cancel_kind {
        evidence.push(json_string(format!("cancel_kind={kind:?}")));
    }
    let mut envelope = base_envelope(
        false,
        outcome_kind,
        command_id,
        output_contract_id,
        request_id,
        json_object(vec![]),
    );
    envelope.profile_id = Some(profile);
    envelope.error = Some(error_info(error.code, error.message.clone(), evidence));
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

/// The SQL API base URL for an account handle (shared with offline
/// `profile validate` through `franken_snowflake_core::endpoint`).
fn endpoint_url(account: &str) -> String {
    franken_snowflake_core::endpoint::endpoint_url(account)
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
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    format!(
        "{:08x}-0000-4000-8000-{:012x}",
        (nanos & 0xffff_ffff) as u32,
        ((nanos >> 16) ^ seq) & 0xffff_ffff_ffff
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
        /// The SQL API `requestId` each statement was submitted with.
        request_ids: Vec<String>,
    }

    /// Shared handle to the script: the test keeps one to inspect what was
    /// submitted; the resolved `LiveConn` keeps one to answer statements.
    #[derive(Clone)]
    pub(super) struct Script(Rc<RefCell<ScriptState>>);

    impl Script {
        /// Stands in for the driver: answers the next scripted response and,
        /// like the driver, reports the plan's bounds in the stats.
        pub(super) fn execute(
            &self,
            request: SubmitStatementRequest,
            poll_plan: PollPlan,
            sql_api_request_id: &str,
        ) -> Result<(CompletedStatement, DriverStats, String), SnowflakeError> {
            let mut state = self.0.borrow_mut();
            state.submitted.push(request);
            state.row_caps.push(poll_plan.row_cap);
            state.request_ids.push(sql_api_request_id.to_owned());
            let ordinal = state.submitted.len();
            match state.responses.pop_front() {
                Some(Ok(done)) => Ok((
                    done,
                    DriverStats {
                        polls: 1,
                        partitions_fetched: 0,
                        poll_quota: poll_plan.max_polls,
                        execution_timeout: poll_plan.execution_timeout,
                        cost_quota: poll_plan.cost_quota,
                        execution: None,
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

        /// The SQL API `requestId` each submitted statement carried.
        pub(super) fn request_ids(&self) -> Vec<String> {
            self.0.borrow().request_ids.clone()
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
            request_ids: Vec::new(),
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
                tls_roots: TlsRootPolicy::NativeRoots,
                auth_profile: build_auth_profile("FSNOW_SCRIPTED", "pat").ok()?,
                max_polls: 10,
                partition_concurrency: DEFAULT_PARTITION_CONCURRENCY,
                query_tag_policy: QueryTagPolicy::Generated,
                query_tag: None,
                progress: false,
                max_microcredits: None,
                microcredits_per_hour: None,
                cost_quota: std::cell::OnceCell::new(),
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
                "numRows": rows.len() as i64,
                "format": "jsonv2",
                "rowType": row_type,
                "partitionInfo": [{ "rowCount": rows.len() as i64, "uncompressedSize": 1 }]
            },
            "data": rows,
            "code": "090001",
            "statementHandle": handle,
            "statementStatusUrl": format!("/api/v2/statements/{handle}"),
            "sqlState": "00000",
            "message": "Statement executed successfully.",
            "requestId": "11111111-1111-1111-1111-111111111111",
            "createdOn": 1_700_000_000_000_i64
        });
        let bytes = serde_json::to_vec(&body).unwrap_or_default();
        let mut machine = StatementMachine::new(PollPlan::default());
        if let Ok(Progress::Complete(done)) = machine.on_submit(ResponseClass::Completed, &bytes) {
            return done;
        }
        let result_set =
            serde_json::from_slice::<franken_snowflake_sqlapi::response::ResultSet>(&bytes)
                .unwrap_or_else(|_| franken_snowflake_sqlapi::response::ResultSet {
                    result_set_meta_data: franken_snowflake_sqlapi::response::ResultSetMetaData {
                        num_rows: rows.len() as i64,
                        format: "jsonv2".to_owned(),
                        row_type: Vec::new(),
                        partition_info: Vec::new(),
                    },
                    data: Vec::new(),
                    code: "090001".to_owned(),
                    statement_handle: StatementHandle::new(handle),
                    statement_status_url: None,
                    statement_handles: None,
                    sql_state: None,
                    message: None,
                    request_id: None,
                    created_on: None,
                    stats: None,
                });
        let string_rows = rows
            .iter()
            .map(|r| r.iter().map(|c| c.map(str::to_owned)).collect())
            .collect();
        CompletedStatement {
            statement_handle: StatementHandle::new(handle),
            result_set,
            rows: string_rows,
            total_partitions: 1,
            fetched_partitions: 1,
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
                query_tag: Some("acme.trace.123".to_owned()),
                sql_api_request_id: None,
            },
        );

        assert_eq!(request.bindings, Some(bindings));
        assert_eq!(
            request
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.get("QUERY_TAG"))
                .map(String::as_str),
            Some("acme.trace.123")
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
        assert!(validate_query_tag("acme.trace.123").is_ok());
        assert!(validate_query_tag("acme\ntrace").is_err());
        assert!(is_safe_env_name("ACME_TYPED_BINDINGS_JSON"));
        assert!(!is_safe_env_name("ACME-TYPED-BINDINGS"));
    }

    #[test]
    fn run_flags_are_validated_not_ignored() -> Result<(), String> {
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
        let overrides = session_overrides(&good, Some("DB"), None).map_err(|e| e.to_string())?;
        assert_eq!(overrides.role.as_deref(), Some("ANALYST"));
        assert_eq!(overrides.statement_timeout, Some(30));
        assert_eq!(overrides.database.as_deref(), Some("DB"));
        Ok(())
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
                    .unwrap_or_default()
            }
            crate::Body::Raw { data } => serde_json::from_str(&data).unwrap_or(serde_json::json!({
                "raw": data,
            })),
        }
    }

    fn request_json(request: &SubmitStatementRequest) -> serde_json::Value {
        serde_json::to_value(request).unwrap_or_default()
    }

    const EVENT_COLUMNS: &[(&str, &str)] = &[
        ("EVENT_DATE", "DATE"),
        ("ENTITY_ID", "TEXT"),
        ("VALUE", "FIXED"),
    ];

    fn information_schema_script() -> Vec<Result<CompletedStatement, SnowflakeError>> {
        information_schema_script_with_scope("ANALYTICS", "PUBLIC")
    }

    fn information_schema_script_with_scope(
        database: &str,
        schema: &str,
    ) -> Vec<Result<CompletedStatement, SnowflakeError>> {
        let mut script = vec![
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
                    Some(database),
                    Some(schema),
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
                        Some(database),
                        Some(schema),
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
                        Some(database),
                        Some(schema),
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
                        Some(database),
                        Some(schema),
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
        ];
        script.extend(relation_script(database, schema));
        script
    }

    /// The relation pass for a schema holding one base table: SHOW PRIMARY
    /// KEYS (EVENTS keyed on ENTITY_ID, EVENT_DATE), then empty constraint,
    /// stage and file-format listings. No view or external table, and tags
    /// are opt-in, so nothing else is submitted.
    fn relation_script(
        database: &str,
        schema: &str,
    ) -> Vec<Result<CompletedStatement, SnowflakeError>> {
        let pk = |column, sequence| {
            vec![
                Some("2026-09-01"),
                Some(database),
                Some(schema),
                Some("EVENTS"),
                Some(column),
                Some(sequence),
                None,
                Some("PK_EVENTS"),
            ]
        };
        let empty = |handle: &str, columns: &[(&str, &str)]| Ok(completed(handle, columns, &[]));
        vec![
            Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000cc03",
                &[
                    ("created_on", "TEXT"),
                    ("database_name", "TEXT"),
                    ("schema_name", "TEXT"),
                    ("table_name", "TEXT"),
                    ("column_name", "TEXT"),
                    ("key_sequence", "FIXED"),
                    ("comment", "TEXT"),
                    ("constraint_name", "TEXT"),
                ],
                &[pk("EVENT_DATE", "2"), pk("ENTITY_ID", "1")],
            )),
            empty(
                "01b2c3d4-0000-0000-0000-00000000cc04",
                &[("CONSTRAINT_NAME", "TEXT"), ("CONSTRAINT_TYPE", "TEXT")],
            ),
            empty(
                "01b2c3d4-0000-0000-0000-00000000cc05",
                &[
                    ("CONSTRAINT_NAME", "TEXT"),
                    ("UNIQUE_CONSTRAINT_NAME", "TEXT"),
                ],
            ),
            empty(
                "01b2c3d4-0000-0000-0000-00000000cc06",
                &[("STAGE_NAME", "TEXT")],
            ),
            empty(
                "01b2c3d4-0000-0000-0000-00000000cc07",
                &[("FILE_FORMAT_NAME", "TEXT")],
            ),
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
        // Beside the measured polls, the bounds the statement ran under: the
        // profile's poll quota and this run's --statement-timeout 120 + 5 s.
        assert_eq!(env["budget_consumed"]["poll_quota"], 10);
        assert_eq!(env["budget_consumed"]["execution_timeout_ms"], 125_000);
        assert!(env["budget_consumed"].get("deadline_ms").is_none(), "{env}");
        let hash = env["receipt_hash"].as_str().unwrap_or("").to_owned();
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
        assert_eq!(
            request["parameters"]["MULTI_STATEMENT_COUNT"], "1",
            "every live submit pins the one-statement backstop: {request}"
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
    fn scripted_query_failure_is_a_typed_error_envelope_with_a_failed_receipt() {
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
        // The attempt still leaves a receipt that says it failed (reality-check
        // bead C6); before, a failed statement left no trace in the store.
        let hash = env["receipt_hash"].as_str().unwrap_or_default().to_owned();
        assert_eq!(hash.len(), 64, "{env}");
        let shown = envelope(crate::execute(
            ["receipt", "show", hash.as_str(), "--json"]
                .map(str::to_owned)
                .to_vec(),
        ));
        assert_eq!(shown["data"]["receipt_state"], "failed", "{shown}");
        assert_eq!(
            shown["data"]["receipt"]["error"]["code"], "FSNOW-4002",
            "{shown}"
        );
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
            false,
            RelationOptions::default(),
        ));
        assert_eq!(env["ok"], true, "{env}");
        assert_eq!(env["outcome_kind"], "success", "{env}");
        assert_eq!(env["data_source"], "live");
        let datasets = env["data"]["datasets"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(datasets.len(), 1, "{env}");
        let dataset_id = datasets
            .first()
            .and_then(|d| d["dataset_id"].as_str())
            .unwrap_or("")
            .to_owned();
        assert!(
            dataset_id.starts_with("analytics_public_events_b3_"),
            "{dataset_id}"
        );
        assert_eq!(datasets[0]["approx_row_count"], 1200, "{env}");
        assert_eq!(env["receipt_hash"].as_str().map(str::len), Some(64));
        assert_eq!(env["data"]["drift"]["summary"]["datasets_added"], 1);
        assert_eq!(
            env["data"]["drift"]["summary"]["has_breaking_changes"],
            false
        );
        let safe_cmds = env["safe_next_commands"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            safe_cmds
                .iter()
                .any(|c| c.as_str().unwrap_or("").contains(&dataset_id)),
            "safe_next_commands should name the dataset: {safe_cmds:?}"
        );

        // The relation pass: the primary key in key order, and the opt-in
        // tag source reported as skipped rather than silently empty.
        assert_eq!(
            datasets[0]["primary_key"],
            serde_json::json!(["ENTITY_ID", "EVENT_DATE"]),
            "{env}"
        );
        let relations = &env["data"]["relations"];
        assert_eq!(relations["discovered"], true, "{env}");
        assert_eq!(relations["primary_key_count"], 1, "{env}");
        assert!(
            relations["gaps"].to_string().contains("tag_references"),
            "{env}"
        );

        // Discovery statements are bound, never interpolated, carry the
        // session context, and always fetch every partition; SHOW takes no
        // binds, so its scope is quoted.
        let submitted = script.submitted();
        assert_eq!(submitted.len(), 7);
        assert_eq!(script.row_caps(), vec![None; 7]);
        let show = request_json(&submitted[2]);
        assert_eq!(
            show["statement"], r#"SHOW PRIMARY KEYS IN SCHEMA "ANALYTICS"."PUBLIC""#,
            "{show}"
        );
        for request in &submitted[..2] {
            let json = request_json(request);
            let statement = json["statement"].as_str().unwrap_or("");
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
        assert_eq!(
            inspect["data"]["relations"]["primary_key"],
            serde_json::json!(["ENTITY_ID", "EVENT_DATE"]),
            "{inspect}"
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
        let statement = json["statement"].as_str().unwrap_or("");
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
    fn scripted_catalog_scan_detects_drift_across_successive_scans() {
        // First scan: initial scan for this profile, 1 dataset added
        let _s1 = install(
            "drift_profile",
            None,
            None,
            information_schema_script_with_scope("DRIFT_DB", "DRIFT_SCHEMA"),
        );
        let env1 = envelope(run_catalog_scan_outcome(
            OutputFormat::Json,
            "req-scan-drift-1".to_owned(),
            "drift_profile".to_owned(),
            "DRIFT_DB".to_owned(),
            "DRIFT_SCHEMA".to_owned(),
            false,
            RelationOptions::default(),
        ));
        assert_eq!(env1["ok"], true);
        assert_eq!(env1["data"]["drift"]["summary"]["datasets_added"], 1);
        assert_eq!(
            env1["data"]["drift"]["base_snapshot_id"],
            serde_json::Value::Null
        );

        // Second scan: identical catalog
        let _s2 = install(
            "drift_profile",
            None,
            None,
            information_schema_script_with_scope("DRIFT_DB", "DRIFT_SCHEMA"),
        );
        let env2 = envelope(run_catalog_scan_outcome(
            OutputFormat::Json,
            "req-scan-drift-2".to_owned(),
            "drift_profile".to_owned(),
            "DRIFT_DB".to_owned(),
            "DRIFT_SCHEMA".to_owned(),
            false,
            RelationOptions::default(),
        ));
        assert_eq!(env2["ok"], true);
        assert_eq!(env2["data"]["drift"]["summary"]["is_identical"], true);
        assert_eq!(
            env2["data"]["drift"]["base_snapshot_id"],
            env1["data"]["store"]["snapshot_id"]
        );
    }

    #[test]
    fn a_refused_relation_source_is_partial_success_and_the_snapshot_is_kept() {
        let mut script = information_schema_script_with_scope("GAP_DB", "GAP_SCHEMA");
        // TABLES, COLUMNS, SHOW PRIMARY KEYS, then TABLE_CONSTRAINTS refused.
        script[3] = Err(SnowflakeError::new(
            SnowflakeErrorCode::StatementFailed,
            "SQL access control error: Insufficient privileges to operate on schema 'GAP_SCHEMA'",
        ));
        install("gap_profile", None, None, script);
        let outcome = run_catalog_scan_outcome(
            OutputFormat::Json,
            "req-scan-gap".to_owned(),
            "gap_profile".to_owned(),
            "GAP_DB".to_owned(),
            "GAP_SCHEMA".to_owned(),
            false,
            RelationOptions::default(),
        );
        assert_eq!(outcome.status, CoreExitCode::Findings);
        let env = envelope(outcome);
        assert_eq!(env["ok"], true, "{env}");
        assert_eq!(env["outcome_kind"], "partial_success", "{env}");
        assert_eq!(env["data"]["store"]["persisted"], true, "{env}");
        assert_eq!(env["data"]["datasets"][0]["column_count"], 3, "{env}");
        let warnings = env["warnings"].to_string();
        assert!(
            warnings.contains("`table_constraints` was refused")
                && warnings.contains("Insufficient privileges")
                && warnings.contains("info-schema/table_constraints"),
            "{env}"
        );
        assert!(
            env["data"]["relations"]["gaps"]
                .to_string()
                .contains(r#""kind":"failed""#),
            "{env}"
        );
    }

    /// Reality-check bead oj0.35: a manifest overlay reassigns roles and limits
    /// at read time (inspect and dataset planning), and a field naming a
    /// column the dataset lacks is refused with suggestions, never ignored.
    #[test]
    fn a_manifest_overlay_reassigns_roles_at_read_time() {
        let column = |name, ordinal, kind| {
            vec![
                Some("OVL_DB"),
                Some("PUBLIC"),
                Some("EVENTS"),
                Some(name),
                Some(ordinal),
                Some(kind),
                None,
                None,
                None,
                Some("YES"),
                None,
            ]
        };
        let mut script = vec![
            Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000cd01",
                &[
                    ("TABLE_CATALOG", "TEXT"),
                    ("TABLE_SCHEMA", "TEXT"),
                    ("TABLE_NAME", "TEXT"),
                    ("TABLE_TYPE", "TEXT"),
                    ("COMMENT", "TEXT"),
                ],
                &[vec![
                    Some("OVL_DB"),
                    Some("PUBLIC"),
                    Some("EVENTS"),
                    Some("BASE TABLE"),
                    None,
                ]],
            )),
            Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000cd02",
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
                    column("EVENT_DATE", "1", "DATE"),
                    column("LOADED_AT", "2", "TIMESTAMP_NTZ"),
                    column("ACCOUNT_REF", "3", "TEXT"),
                    column("VALUE", "4", "NUMBER"),
                ],
            )),
        ];
        script.extend(relation_script("OVL_DB", "PUBLIC"));
        install("overlay_profile", None, None, script);
        let scan = envelope(run_catalog_scan_outcome(
            OutputFormat::Json,
            "req-scan-overlay".to_owned(),
            "overlay_profile".to_owned(),
            "OVL_DB".to_owned(),
            "PUBLIC".to_owned(),
            false,
            RelationOptions::default(),
        ));
        let dataset_id = scan["data"]["datasets"][0]["dataset_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(!dataset_id.is_empty(), "{scan}");
        let plan = || {
            envelope(crate::dataset_mode::dataset_plan_outcome(
                OutputFormat::Json,
                "req-plan-overlay".to_owned(),
                crate::dataset_mode::DatasetQuerySpec {
                    dataset_id: dataset_id.clone(),
                    from: Some("2024-01-01".to_owned()),
                    to: Some("2024-02-01".to_owned()),
                    ..Default::default()
                },
            ))
        };
        let before = plan();
        let sql = before["data"]["sql"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(
            sql.contains(r#""EVENT_DATE" >= ?"#),
            "discovery's time index: {before}"
        );

        let overlay_path = local_store::data_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("overlay-{:?}.toml", std::thread::current().id()));
        let use_overlay = |text: &str| {
            std::fs::create_dir_all(overlay_path.parent().unwrap_or(&overlay_path)).ok();
            std::fs::write(&overlay_path, text).expect("write overlay");
            catalog_surface::TEST_MANIFEST_OVERLAY
                .with(|slot| *slot.borrow_mut() = Some(overlay_path.clone()));
        };
        use_overlay(
            "[[datasets]]\ndatabase = \"ovl_db\"\nschema = \"public\"\nobject = \"events\"\ndefault_limit = 7\n\n[[datasets.fields]]\ncolumn = \"loaded_at\"\nrole = \"time_index\"\n\n[[datasets.fields]]\ncolumn = \"ACCOUNT_REF\"\nrole = \"entity_key\"\n",
        );
        let after = plan();
        let sql = after["data"]["sql"].as_str().unwrap_or_default().to_owned();
        assert!(
            sql.contains(r#""LOADED_AT" >= ?"#) && !sql.contains(r#""EVENT_DATE" >= ?"#),
            "the overlay's time index wins: {after}"
        );
        assert!(
            after["data"]["bindings"]
                .to_string()
                .contains(r#""value":"7""#),
            "the overlay's default limit binds the LIMIT: {after}"
        );
        let inspect = envelope(catalog_surface::dataset_inspect_outcome(
            OutputFormat::Json,
            "req-inspect-overlay".to_owned(),
            dataset_id.clone(),
        ));
        assert_eq!(inspect["ok"], true, "{inspect}");
        assert!(inspect["data"]["overlay"].as_str().is_some(), "{inspect}");
        let fields = inspect["data"]["manifest"]["fields"].to_string();
        assert!(
            fields.contains(r#""column":"ACCOUNT_REF","role":"entity_key""#)
                && fields.contains(r#""role_confidence":"overlay""#),
            "{fields}"
        );

        // A column the dataset does not have: refused, with a suggestion.
        use_overlay(
            "[[datasets]]\nid = \"DATASET\"\n\n[[datasets.fields]]\ncolumn = \"LOADED\"\nrole = \"time_index\"\n"
                .replace("DATASET", &dataset_id)
                .as_str(),
        );
        let refused = envelope(catalog_surface::dataset_inspect_outcome(
            OutputFormat::Json,
            "req-inspect-overlay-bad".to_owned(),
            dataset_id.clone(),
        ));
        assert_eq!(refused["ok"], false, "{refused}");
        assert_eq!(refused["error"]["code"], "FSNOW-1002", "{refused}");
        assert!(
            refused["did_you_mean"].to_string().contains("LOADED_AT"),
            "{refused}"
        );
        let validated = envelope(catalog_surface::validate_manifest_outcome(
            OutputFormat::Json,
            "req-validate-overlay".to_owned(),
        ));
        assert_eq!(validated["ok"], false, "{validated}");
        catalog_surface::TEST_MANIFEST_OVERLAY.with(|slot| *slot.borrow_mut() = None);
        let _ = std::fs::remove_file(&overlay_path);
    }

    /// Reality-check bead oj0.39: the local-store adapter passes the same
    /// conformance suite as the fixture adapter over artifacts a scripted scan,
    /// query and export persisted; unknown ids are typed errors.
    #[test]
    fn the_local_store_adapter_passes_the_conformance_suite() {
        use franken_snowflake_core::adapter::SnowflakeDataLakeAdapter;
        use franken_snowflake_core::adapter::conformance::{
            ConformanceProbe, check_adapter_conformance,
        };
        use franken_snowflake_core::ids::{DatasetId, ProfileName, ReceiptHash};
        use franken_snowflake_core::outcome::DataSource;

        install(
            "adapter_profile",
            None,
            None,
            information_schema_script_with_scope("ADP_DB", "PUBLIC"),
        );
        let scan = envelope(run_catalog_scan_outcome(
            OutputFormat::Json,
            "req-adapter-scan".to_owned(),
            "adapter_profile".to_owned(),
            "ADP_DB".to_owned(),
            "PUBLIC".to_owned(),
            false,
            RelationOptions::default(),
        ));
        let dataset = scan["data"]["datasets"][0]["dataset_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        install(
            "adapter_profile",
            None,
            None,
            vec![Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000ad01",
                &[("ID", "FIXED"), ("NAME", "TEXT")],
                &[vec![Some("1"), Some("alpha")]],
            ))],
        );
        let query = envelope(run_query_outcome(
            OutputFormat::Json,
            "req-adapter-query".to_owned(),
            "adapter_profile".to_owned(),
            "select id, name from events",
            &crate::QueryRunOptions::default(),
        ));
        let receipt = query["receipt_hash"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        install(
            "adapter_profile",
            None,
            None,
            vec![Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000ad02",
                &[("ID", "FIXED"), ("NAME", "TEXT")],
                &[vec![Some("1"), Some("alpha")]],
            ))],
        );
        let out = std::env::temp_dir().join(format!(
            "fsnow-adapter-export-{}-{}.csv",
            std::process::id(),
            local_store::now_unix_ms()
        ));
        let export = envelope(export_run_outcome(
            OutputFormat::Json,
            "req-adapter-export".to_owned(),
            ExportPlanSpec {
                profile: Some("adapter_profile".to_owned()),
                sql: Some("select id, name from events".to_owned()),
                format: Some("csv".to_owned()),
                ..Default::default()
            },
            Some(out.display().to_string()),
            false,
        ));
        let _ = std::fs::remove_file(&out);
        let export_id = export["data"]["export_receipt"]["export_id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(
            !dataset.is_empty() && !receipt.is_empty() && !export_id.is_empty(),
            "{scan}\n{query}\n{export}"
        );

        let adapter = crate::adapter::LocalStoreAdapter::open_with_env(Box::new(|name| {
            let value = match name.strip_prefix("FRANKEN_SNOWFLAKE_ADAPTER_PROFILE_")? {
                "ACCOUNT" => "xy12345.us-east-1",
                "USER" => "SVC_ADAPTER",
                "AUTH" => "pat",
                "WAREHOUSE" => "WH_ADAPTER",
                "PAT" => "set-but-never-read-by-diagnostics",
                _ => return None,
            };
            Some(value.to_owned())
        }))
        .expect("open the local store");
        let probe = ConformanceProbe {
            profile: ProfileName::new("adapter_profile"),
            dataset: DatasetId::new(dataset.clone()),
            receipt: ReceiptHash::new(receipt),
            export_id: Some(export_id),
            frame_id: None,
            expected_data_source: DataSource::Live,
        };
        assert_eq!(
            check_adapter_conformance(&adapter, &probe),
            Vec::<String>::new()
        );
        // The dataset contract carries the discovered fields and the
        // snapshot's live provenance.
        let manifest = adapter
            .dataset_manifest(&DatasetId::new(dataset))
            .expect("the scanned dataset");
        assert_eq!(manifest.data.fields.len(), 3);
        assert_eq!(manifest.data.provenance.data_source, DataSource::Live);
        // A profile without handles is not found; one without a lane is invalid.
        let missing = crate::adapter::LocalStoreAdapter::open_with_env(Box::new(|_| None))
            .expect("open the local store");
        assert_eq!(
            missing
                .profile_diagnostics(&ProfileName::new("adapter_profile"))
                .map(|_| ())
                .map_err(|error| error.code),
            Err(SnowflakeErrorCode::ProfileNotFound)
        );
    }

    #[test]
    fn a_transport_error_in_the_relation_pass_fails_the_scan() {
        let mut script = information_schema_script_with_scope("NET_DB", "NET_SCHEMA");
        script[2] = Err(SnowflakeError::new(
            SnowflakeErrorCode::NetworkError,
            "connection reset",
        ));
        install("net_profile", None, None, script);
        let outcome = run_catalog_scan_outcome(
            OutputFormat::Json,
            "req-scan-net".to_owned(),
            "net_profile".to_owned(),
            "NET_DB".to_owned(),
            "NET_SCHEMA".to_owned(),
            false,
            RelationOptions::default(),
        );
        assert_ne!(outcome.status, CoreExitCode::Success);
        assert_ne!(outcome.status, CoreExitCode::Findings);
        let env = envelope(outcome);
        assert_eq!(env["ok"], false, "{env}");
    }

    #[test]
    fn scripted_export_run_writes_a_local_csv() -> Result<(), String> {
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
        let spec = || ExportPlanSpec {
            profile: Some("demo".to_owned()),
            sql: Some("select id, name from events".to_owned()),
            format: Some("csv".to_owned()),
            ..Default::default()
        };
        let env = envelope(export_run_outcome(
            OutputFormat::Json,
            "req-export-1".to_owned(),
            spec(),
            Some(out.display().to_string()),
            false,
        ));
        assert_eq!(env["ok"], true, "{env}");
        assert_eq!(env["data"]["overwrote"], false, "{env}");
        // A second run to the same path is refused before any statement runs
        // (reality-check bead B2): no silent overwrite.
        let again = envelope(export_run_outcome(
            OutputFormat::Json,
            "req-export-2".to_owned(),
            spec(),
            Some(out.display().to_string()),
            false,
        ));
        assert_eq!(again["ok"], false, "{again}");
        assert!(again.to_string().contains("--overwrite"), "{again}");
        assert_eq!(env["data_source"], "live");
        let written = std::fs::read_to_string(&out).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(&out);
        assert!(written.starts_with("ID,NAME"), "{written}");
        assert!(written.contains("1,alpha"), "{written}");
        assert_eq!(written.lines().count(), 3, "{written}");
        assert_eq!(
            env["receipt_hash"].as_str().map(str::len),
            Some(64),
            "{env}"
        );
        Ok(())
    }

    /// Reality-check bead E5: --max-rows refuses an oversized streaming export
    /// with FSNOW-3004 and leaves no file behind.
    #[test]
    fn scripted_export_run_refuses_past_max_rows_and_leaves_no_file() -> Result<(), String> {
        install(
            "demo",
            None,
            None,
            vec![Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000ff02",
                &[("ID", "FIXED"), ("NAME", "TEXT")],
                &[vec![Some("1"), Some("alpha")], vec![Some("2"), None]],
            ))],
        );
        let out = std::env::temp_dir().join(format!(
            "fsnow-scripted-export-cap-{}-{}.csv",
            std::process::id(),
            local_store::now_unix_ms()
        ));
        let spec = ExportPlanSpec {
            profile: Some("demo".to_owned()),
            sql: Some("select id, name from events".to_owned()),
            format: Some("csv".to_owned()),
            max_rows: Some("1".to_owned()),
            ..Default::default()
        };
        let env = envelope(export_run_outcome(
            OutputFormat::Json,
            "req-export-cap".to_owned(),
            spec,
            Some(out.display().to_string()),
            false,
        ));
        assert_eq!(env["ok"], false, "{env}");
        assert_eq!(env["error"]["code"], "FSNOW-3004", "{env}");
        assert!(!out.exists(), "a refused export leaves no file");
        assert_eq!(
            export_max_rows(Some("0"), "demo").map_err(|e| e.code).err(),
            Some(SnowflakeErrorCode::UsageError)
        );
        assert_eq!(
            export_max_rows(None, "demo").ok(),
            Some(DEFAULT_EXPORT_MAX_ROWS)
        );
        Ok(())
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

    /// Reality-check bead C6: all four driver outcomes survive to the edge.
    #[test]
    fn outcome_into_result_keeps_cancel_kind_and_panic_summary() {
        use asupersync::{CancelReason, PanicPayload};
        let ok: Outcome<u8, SnowflakeError> = Outcome::ok(7);
        assert_eq!(outcome_into_result(ok, "the statement", true).ok(), Some(7));
        let err: Outcome<u8, SnowflakeError> = Outcome::err(SnowflakeError::new(
            SnowflakeErrorCode::StatementFailed,
            "bad sql",
        ));
        assert_eq!(
            outcome_into_result(err, "the statement", true).map_err(|e| e.code),
            Err(SnowflakeErrorCode::StatementFailed)
        );
        let cancelled: Outcome<u8, SnowflakeError> = Outcome::cancelled(CancelReason::deadline());
        let error = outcome_into_result(cancelled, "the statement", true).err();
        assert_eq!(
            error.as_ref().map(|e| e.code),
            Some(SnowflakeErrorCode::Cancelled)
        );
        assert_eq!(
            error.as_ref().and_then(|e| e.cancel_kind),
            Some(CancelKind::Deadline)
        );
        assert!(
            error
                .as_ref()
                .is_some_and(|e| e.message.contains("remote cancel was sent")),
            "{error:?}"
        );
        let panicked: Outcome<u8, SnowflakeError> =
            Outcome::panicked(PanicPayload::new("index out of bounds"));
        let error = outcome_into_result(panicked, "the statement", true).err();
        assert_eq!(
            error.as_ref().map(|e| e.code),
            Some(SnowflakeErrorCode::Internal)
        );
        assert!(
            error
                .as_ref()
                .is_some_and(|e| e.message.contains("panicked: index out of bounds")),
            "{error:?}"
        );
    }

    #[test]
    fn credit_settings_parse_as_exact_millionths() {
        assert_eq!(parse_microcredits("0.05"), Some(50_000));
        assert_eq!(parse_microcredits("1"), Some(1_000_000));
        assert_eq!(parse_microcredits(".000001"), Some(1));
        assert_eq!(parse_microcredits("2.5"), Some(2_500_000));
        for bad in [
            "0",
            "0.0",
            "-1",
            "1e3",
            "abc",
            "0.0000001",
            "",
            ".",
            "1.2.3",
        ] {
            assert_eq!(parse_microcredits(bad), None, "{bad}");
        }
    }

    #[test]
    fn warehouse_rates_come_from_the_published_gen1_table_only() {
        assert_eq!(
            warehouse_row_rate(
                Some("STANDARD"),
                Some("X-Small"),
                Some("1"),
                Some("STARTED")
            ),
            Ok((1_000_000, false))
        );
        assert_eq!(
            warehouse_row_rate(Some("STANDARD"), Some("6X-Large"), None, Some("SUSPENDED")),
            Ok((512_000_000, true))
        );
        assert_eq!(
            warehouse_row_rate(
                Some("STANDARD"),
                Some("Medium"),
                Some("1"),
                Some("RESIZING")
            ),
            Ok((4_000_000, false))
        );
        assert_eq!(gen1_microcredits_per_hour("X5LARGE"), Some(256_000_000));
        // Negatives: no published rate is refused, never guessed.
        assert!(warehouse_row_rate(Some("STANDARD"), Some("X-Small"), Some("2"), None).is_err());
        assert!(
            warehouse_row_rate(Some("SNOWPARK-OPTIMIZED"), Some("Medium"), None, None).is_err()
        );
        assert!(warehouse_row_rate(Some("STANDARD"), Some("Enormous"), Some("1"), None).is_err());
    }

    /// Reality-check bead C6: a cancelled statement is not an internal error at
    /// the edge. Deadline reads `timeout` (exit 5), cost budget `cancelled`
    /// (exit 2), both FSNOW-5004 with the kind in the evidence.
    #[test]
    fn scripted_cancellations_reach_the_envelope_by_kind() {
        for (kind, outcome_kind, exit) in [
            (CancelKind::Deadline, "timeout", 5),
            (CancelKind::PollQuota, "cancelled", 5),
            (CancelKind::CostBudget, "cancelled", 2),
        ] {
            install(
                "demo",
                None,
                None,
                vec![Err(SnowflakeError::cancelled(kind, "scripted cancel"))],
            );
            let outcome = run_query_outcome(
                OutputFormat::Json,
                "req-cancel".to_owned(),
                "demo".to_owned(),
                "select 1",
                &crate::QueryRunOptions::default(),
            );
            assert_eq!(outcome.status.code(), exit, "{kind:?}");
            let env = envelope(outcome);
            assert_eq!(env["ok"], false, "{env}");
            assert_eq!(env["outcome_kind"], outcome_kind, "{kind:?}: {env}");
            assert_eq!(env["error"]["code"], "FSNOW-5004", "{env}");
            assert!(
                env.to_string().contains(&format!("cancel_kind={kind:?}")),
                "{env}"
            );
            // The attempt still leaves a receipt that says how it ended.
            let hash = env["receipt_hash"].as_str().unwrap_or_default().to_owned();
            assert_eq!(hash.len(), 64, "{env}");
            let shown = envelope(crate::execute(
                ["receipt", "show", hash.as_str(), "--json"]
                    .map(str::to_owned)
                    .to_vec(),
            ))
            .to_string();
            let state = if outcome_kind == "timeout" {
                "timed_out"
            } else {
                "cancelled"
            };
            assert!(
                shown.contains(&format!("\"receipt_state\":\"{state}\"")),
                "{shown}"
            );
        }
    }

    /// Reality-check bead L5: every live statement carries a QUERY_TAG that
    /// ties it back to the envelope, unless the request brings its own or the
    /// profile turns the default off.
    #[test]
    fn statements_carry_the_invocation_query_tag() {
        assert_eq!(query_tag_policy(None).ok(), Some(QueryTagPolicy::Generated));
        assert_eq!(
            query_tag_policy(Some(" OFF ")).ok(),
            Some(QueryTagPolicy::Off)
        );
        assert_eq!(
            query_tag_policy(Some("team.etl")).ok(),
            Some(QueryTagPolicy::Fixed("team.etl".to_owned()))
        );
        assert!(query_tag_policy(Some("bad\ntag")).is_err());

        let script = install(
            "demo",
            None,
            None,
            vec![Ok(completed(
                "01b2-tag",
                &[("N", "FIXED")],
                &[vec![Some("1")]],
            ))],
        );
        let env = envelope(run_query_outcome(
            OutputFormat::Json,
            "req-tag-1".to_owned(),
            "demo".to_owned(),
            "select 1",
            &crate::QueryRunOptions::default(),
        ));
        assert_eq!(env["ok"], true, "{env}");
        let submitted = request_json(&script.submitted()[0]);
        assert_eq!(
            submitted["parameters"]["QUERY_TAG"], "fsnow:query.run:req-tag-1",
            "{submitted}"
        );
        let hash = env["receipt_hash"].as_str().unwrap_or_default().to_owned();
        let shown = envelope(crate::execute(
            ["receipt", "show", hash.as_str(), "--json"]
                .map(str::to_owned)
                .to_vec(),
        ))
        .to_string();
        assert!(shown.contains("fsnow:query.run:req-tag-1"), "{shown}");
    }

    /// Reality-check bead B4: a confirmed write submits its dry run's id as the
    /// SQL API requestId (with retry=true a replay returns the first result
    /// instead of writing twice) and marks the confirmation used once it
    /// completes; a bare write gets a fresh id and consumes nothing.
    #[test]
    fn confirmed_write_submits_its_dry_run_id_and_consumes_it() {
        let rows_inserted = || {
            Ok(completed(
                "01b2c3d4-0000-0000-0000-00000000aa71",
                &[("number of rows inserted", "FIXED")],
                &[vec![Some("1")]],
            ))
        };
        let script = install("demo", None, None, vec![rows_inserted(), rows_inserted()]);
        let confirm_id = local_store::random_id().unwrap();
        let grant = crate::tests::authorized_insert().unwrap();
        let write = |confirmed: Option<String>| AuthorizedWrite {
            grant: &grant,
            sql: "insert into t values (1)",
            statement_kind: "insert",
            safety_class: "dml",
            idempotency_request_id: confirm_id.clone(),
            confirmed_request_id: confirmed,
            database: None,
            schema: None,
        };
        let confirmed = envelope(run_write_outcome(
            OutputFormat::Json,
            "req-write-1".to_owned(),
            "demo".to_owned(),
            &write(Some(confirm_id.clone())),
        ));
        assert_eq!(confirmed["ok"], true, "{confirmed}");
        let bare = envelope(run_write_outcome(
            OutputFormat::Json,
            "req-write-2".to_owned(),
            "demo".to_owned(),
            &write(None),
        ));
        assert_eq!(bare["ok"], true, "{bare}");
        let ids = script.request_ids();
        assert_eq!(ids.len(), 2);
        assert_eq!(
            ids[0], confirm_id,
            "the confirmed write reuses its dry run's id"
        );
        assert_ne!(ids[1], confirm_id, "a bare write gets a fresh id");
        let store = local_store::open_store().unwrap();
        assert_eq!(
            local_store::confirmation_consumed_by(&store, &confirm_id).as_deref(),
            confirmed["receipt_hash"].as_str(),
            "the completed confirmed write is recorded against its receipt"
        );
    }

    /// Reality-check bead E1: a pending interrupt cancels the statement's
    /// context with `User` (terminate: `Shutdown`), which is what makes the
    /// driver fire the remote cancel; with nothing pending the work finishes
    /// untouched.
    #[test]
    fn a_pending_signal_cancels_the_statement_context() {
        let run = |interrupt: bool, terminate: bool, external: bool| {
            let runtime = RuntimeBuilder::current_thread().build().unwrap();
            let interrupt = AtomicBool::new(interrupt);
            let terminate = AtomicBool::new(terminate);
            // An MCP request's cancel probe (reality-check bead E2).
            let external = external.then(|| Arc::new(|| true) as CancelProbe);
            runtime.block_on(async move {
                let cx = Cx::current().unwrap();
                // Stands in for the driver's poll wait: runs until its context
                // is cancelled, or finishes on its own after ~0.5 s.
                let work = async {
                    for _ in 0..50 {
                        if cx.checkpoint().is_err() {
                            return cx.cancel_reason().map(|reason| reason.kind);
                        }
                        asupersync::time::sleep(
                            cx.now_for_observability(),
                            Duration::from_millis(10),
                        )
                        .await;
                    }
                    None
                };
                cancel_on_flags(&cx, work, &interrupt, &terminate, external).await
            })
        };
        assert_eq!(run(true, false, false), Some(CancelKind::User));
        assert_eq!(run(false, true, false), Some(CancelKind::Shutdown));
        assert_eq!(run(false, false, true), Some(CancelKind::User));
        assert_eq!(
            run(false, false, false),
            None,
            "nothing pending: the work is not cancelled"
        );
    }

    /// Reality-check bead C5: `profile doctor --online` on the PAT lane lists
    /// the user's tokens and warns about the soonest active expiry.
    #[test]
    fn scripted_doctor_online_reports_pat_expiry() {
        let now = now_unix_seconds();
        let soon = format!("{}.000000000", now + 2 * 86_400);
        let later = format!("{}.000000000", now + 90 * 86_400);
        let expired = format!("{}.000000000", now - 86_400);
        install(
            "demo",
            None,
            None,
            vec![
                Ok(completed(
                    "01b2c3d4-0000-0000-0000-00000000ab21",
                    &[("SNOWFLAKE_VERSION", "TEXT")],
                    &[vec![Some("9.30.0")]],
                )),
                Ok(completed(
                    "01b2c3d4-0000-0000-0000-00000000ab22",
                    &[
                        ("name", "TEXT"),
                        ("expires_at", "TIMESTAMP_LTZ"),
                        ("status", "TEXT"),
                    ],
                    &[
                        vec![Some("ci_token"), Some(later.as_str()), Some("ACTIVE")],
                        vec![Some("laptop_token"), Some(soon.as_str()), Some("ACTIVE")],
                        vec![Some("old_token"), Some(expired.as_str()), Some("EXPIRED")],
                    ],
                )),
            ],
        );
        let env = envelope(profile_doctor_online_outcome(
            OutputFormat::Json,
            "req-doctor-pat".to_owned(),
            "demo".to_owned(),
        ));
        assert_eq!(env["ok"], true, "{env}");
        let tokens = &env["data"]["credential_lifetime"]["programmatic_access_tokens"];
        assert_eq!(tokens["active"], 2, "{env}");
        assert_eq!(
            tokens["soonest_expiry_unix_seconds"],
            now + 2 * 86_400,
            "{env}"
        );
        assert!(
            env["warnings"]
                .to_string()
                .contains("`laptop_token` expires in 2 day(s)"),
            "{env}"
        );
    }

    #[test]
    fn lifetime_findings_warn_by_lane() {
        let lifetime = |lane, expires_at| CredentialLifetime {
            lane,
            issued_at_unix_seconds: None,
            expires_at_unix_seconds: expires_at,
            expected_validity_seconds: None,
            max_validity_seconds: None,
            refresh_before_expiry_seconds: None,
        };
        let (data, warnings) =
            lifetime_findings(&lifetime(AuthLane::OAuthBearer, Some(1_300)), 1_000);
        assert!(crate::render_json(&data).contains(r#""expires_in_seconds":300"#));
        assert_eq!(warnings.len(), 1);
        assert!(crate::render_json(&warnings[0]).contains("expires in 5 minute(s)"));
        let (_, none) = lifetime_findings(&lifetime(AuthLane::OAuthBearer, Some(10_000)), 1_000);
        assert!(none.is_empty(), "an hour left is not a warning: {none:?}");
        let (data, none) = lifetime_findings(&lifetime(AuthLane::OAuthBearer, None), 1_000);
        assert!(none.is_empty());
        assert!(
            crate::render_json(&data).contains(r#""expires_in_seconds":null"#),
            "opaque token: lifetime unknown"
        );
    }

    /// Reality-check bead C1: the documented jsonv2 conventions become typed
    /// cells with one representation per column; `--raw-cells` keeps the wire
    /// strings; a column holding a cell that breaks its convention keeps the
    /// wire strings for every cell, with a warning that never echoes the value.
    #[test]
    fn rows_are_typed_per_column_or_kept_on_the_wire() {
        use franken_snowflake_sqlapi::lifecycle::{Progress, StatementMachine};
        use franken_snowflake_sqlapi::status::ResponseClass;
        let fixture = include_bytes!(
            "../../franken-snowflake-testkit/fixtures/sqlapi/jsonv2_codec_cells.json"
        );
        let mut machine = StatementMachine::new(PollPlan::default());
        let Ok(Progress::Complete(done)) = machine.on_submit(ResponseClass::Completed, fixture)
        else {
            panic!("the codec fixture is a completed statement");
        };
        let mut rows = into_rows(done, DriverStats::default(), "req".to_owned());
        let parse = |json: &Json| -> serde_json::Value {
            serde_json::from_str(&crate::render_json(json)).unwrap_or_default()
        };

        let typed = project_rows(&rows, 1, RowEncoding::Typed);
        assert!(typed.warnings.is_empty(), "{:?}", typed.warnings);
        assert_eq!(
            parse(&typed.rows),
            serde_json::json!([[
                "12345678901234567.89",
                "99999999999999999999",
                1.25,
                "1.2345678901234567890123456789012345678E+39",
                true,
                "2020-01-01",
                "23:01:59.000000000",
                "2021-01-28T22:09:37.123456789",
                "2021-01-28T22:09:37.123456789Z",
                "2021-03-19T18:06:59.000000000+01:00",
                "DEADBEEF",
                {"k": [1, 2]},
                {"nested": {"ok": true}},
                [1, "two", null],
                null
            ]])
        );
        let reprs = |columns: &Json| -> Vec<String> {
            parse(columns)
                .as_array()
                .map(|columns| {
                    columns
                        .iter()
                        .map(|column| column["json_repr"].as_str().unwrap_or("").to_owned())
                        .collect()
                })
                .unwrap_or_default()
        };
        assert_eq!(
            reprs(&typed.columns),
            [
                "decimal_string",
                "decimal_string",
                "float",
                "decimal_string",
                "bool",
                "date",
                "time",
                "timestamp_ntz",
                "timestamp_utc",
                "timestamp_offset",
                "hex",
                "json",
                "json",
                "json",
                "string"
            ]
        );
        assert_eq!(parse(&typed.columns)[0]["scale"], 2);

        let wire = project_rows(&rows, 1, RowEncoding::Wire);
        assert_eq!(parse(&wire.rows)[0][5], "18262");
        assert_eq!(parse(&wire.rows)[0][11], r#"{"k":[1,2]}"#);
        assert!(reprs(&wire.columns).iter().all(|repr| repr == "wire"));

        // One malformed DATE cell: that column falls back, the others stay typed.
        if let Some(cell) = rows.rows.get_mut(0).and_then(|row| row.get_mut(5)) {
            *cell = Some("not-a-day-count".to_owned());
        }
        let degraded = project_rows(&rows, 1, RowEncoding::Typed);
        assert_eq!(reprs(&degraded.columns)[5], "wire");
        assert_eq!(parse(&degraded.rows)[0][5], "not-a-day-count");
        assert_eq!(parse(&degraded.rows)[0][4], true);
        assert_eq!(degraded.warnings.len(), 1);
        let warning = crate::render_json(&degraded.warnings[0]);
        assert!(warning.contains("EVENT_DATE"), "{warning}");
        assert!(!warning.contains("not-a-day-count"), "{warning}");
    }

    /// Reality-check bead C1: typed rows match the published JSON Schema
    /// (docs/protocol/typed_rows.v1.schema.json) cell by cell, every
    /// representation is exercised, the published example is exactly what the
    /// codec fixture projects to, and the shapes a naive decoder produces fail.
    #[test]
    fn typed_rows_match_the_published_schema_and_example() {
        use franken_snowflake_sqlapi::lifecycle::{Progress, StatementMachine};
        use franken_snowflake_sqlapi::status::ResponseClass;
        use std::collections::BTreeSet;
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/protocol/typed_rows.v1.schema.json"
        ))
        .expect("the schema is JSON");
        let example: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/protocol/typed_rows.v1.example.json"
        ))
        .expect("the example is JSON");
        let project = |body: &[u8]| -> serde_json::Value {
            let mut machine = StatementMachine::new(PollPlan::default());
            let Ok(Progress::Complete(done)) = machine.on_submit(ResponseClass::Completed, body)
            else {
                panic!("a completed statement");
            };
            let rows = into_rows(done, DriverStats::default(), "req".to_owned());
            let projected = project_rows(&rows, rows.rows.len(), RowEncoding::Typed);
            let parse = |json: &Json| -> serde_json::Value {
                serde_json::from_str(&crate::render_json(json)).unwrap_or_default()
            };
            serde_json::json!({
                "row_encoding": RowEncoding::Typed.token(),
                "columns": parse(&projected.columns),
                "rows": parse(&projected.rows),
            })
        };
        let fixture = project(include_bytes!(
            "../../franken-snowflake-testkit/fixtures/sqlapi/jsonv2_codec_cells.json"
        ));
        assert_eq!(fixture, example, "docs/protocol/typed_rows.v1.example.json");
        // The two representations the fixture lacks: a small exact integer
        // and a type without a typed form.
        let extra = project(
            br#"{"code":"090001","statementHandle":"01b2c3d4-0000-0000-0000-00000000c1c1","resultSetMetaData":{"numRows":2,"format":"jsonv2","rowType":[{"name":"ID","type":"FIXED","precision":9,"scale":0,"nullable":false},{"name":"PLACE","type":"GEOGRAPHY","nullable":true}],"partitionInfo":[{"rowCount":2,"uncompressedSize":64}]},"data":[["-42","POINT(1 2)"],["7",null]]}"#,
        );
        let compile = |schema: &serde_json::Value| {
            jsonschema::validator_for(schema).expect("the schema compiles")
        };
        let whole = compile(&schema);
        let violations = |data: &serde_json::Value| -> Vec<String> {
            let mut found: Vec<String> = whole
                .iter_errors(data)
                .map(|error| error.to_string())
                .collect();
            let columns = data["columns"].as_array().cloned().unwrap_or_default();
            for (index, column) in columns.iter().enumerate() {
                let repr = column["json_repr"].as_str().unwrap_or_default();
                let cell = compile(&serde_json::json!({
                    "$schema": schema["$schema"],
                    "$defs": schema["$defs"],
                    "$ref": format!("#/$defs/cell_{repr}"),
                }));
                for row in data["rows"].as_array().into_iter().flatten() {
                    if !cell.is_valid(&row[index]) {
                        found.push(format!("{}: {} is not {repr}", column["name"], row[index]));
                    }
                }
            }
            found
        };
        assert_eq!(violations(&fixture), Vec::<String>::new());
        assert_eq!(violations(&extra), Vec::<String>::new());
        let exercised: BTreeSet<String> = [&fixture, &extra]
            .iter()
            .flat_map(|data| data["columns"].as_array().cloned().unwrap_or_default())
            .filter_map(|column| column["json_repr"].as_str().map(str::to_owned))
            .collect();
        let published: BTreeSet<String> =
            schema["$defs"]["column"]["properties"]["json_repr"]["enum"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|repr| repr.as_str().map(str::to_owned))
                .collect();
        assert_eq!(exercised, published, "every representation is exercised");
        // Shapes a naive decoder produces fail.
        for (column, naive) in [
            // FIXED(38,2) through a float.
            (0, serde_json::json!(12_345_678_901_234_567.89)),
            // BOOLEAN left as text.
            (4, serde_json::json!("true")),
            // DATE as the wire day count.
            (5, serde_json::json!(18_262)),
            // TIME without its nine fractional digits.
            (6, serde_json::json!("23:01:59")),
            // TIMESTAMP_TZ without its offset.
            (9, serde_json::json!("2021-03-19T18:06:59.000000000")),
            // Odd-length hex.
            (10, serde_json::json!("DEADBEE")),
        ] {
            let mut broken = fixture.clone();
            broken["rows"][0][column] = naive.clone();
            assert!(
                !violations(&broken).is_empty(),
                "{naive} passed as column {column}"
            );
        }
    }

    /// Reality-check bead L5: only a completed receipt with a UUID-shaped
    /// query id inside the ~24 h result retention can be refetched.
    #[test]
    fn refetch_needs_a_fresh_completed_receipt_with_a_query_id() {
        let record =
            |outcome: &str, query_id: Option<&str>, created_at_ms: u64| QueryReceiptRecord {
                receipt_id: "r1".to_owned(),
                plan_id: "p".to_owned(),
                profile_id: "demo".to_owned(),
                command_id: "query.run".to_owned(),
                trace_id: "t".to_owned(),
                outcome_kind: outcome.to_owned(),
                receipt_state: "completed".to_owned(),
                statement_handle: query_id.map(str::to_owned),
                snowflake_query_id: query_id.map(str::to_owned),
                request_id: None,
                row_count: Some(1),
                receipt: VerifiedPayload {
                    canonical: "{}".to_owned(),
                    address: CacheAddress::blake3(b"{}"),
                },
                created_at_ms,
            };
        let id = "01b2c3d4-0000-0000-0000-00000000ab21";
        let now = 10 * RESULT_RETENTION_MS;
        assert_eq!(
            refetch_query_id(&record("ok", Some(id), now - 1_000), now).ok(),
            Some(id.to_owned())
        );
        let failed = refetch_query_id(&record("error", Some(id), now), now)
            .err()
            .map(|e| e.code);
        assert_eq!(failed, Some(SnowflakeErrorCode::MetadataError));
        let missing = refetch_query_id(&record("ok", None, now), now)
            .err()
            .map(|e| e.code);
        assert_eq!(missing, Some(SnowflakeErrorCode::MetadataError));
        // Never interpolate anything but a UUID-shaped id into RESULT_SCAN.
        for bad in [
            "x'); drop table t; --",
            "01b2c3d4-0000-0000-0000",
            "01b2c3d4-0000-0000-0000-00000000ab2g",
        ] {
            let refused = refetch_query_id(&record("ok", Some(bad), now), now)
                .err()
                .map(|e| e.code);
            assert_eq!(refused, Some(SnowflakeErrorCode::MetadataError), "{bad}");
        }
        let expired = refetch_query_id(&record("ok", Some(id), now - RESULT_RETENTION_MS - 1), now)
            .err()
            .map(|e| e.code);
        assert_eq!(expired, Some(SnowflakeErrorCode::CacheError));
    }

    /// Reality-check bead oj0.25: the grant walk follows granted roles and
    /// flags write-capable privileges with the role they come from.
    #[test]
    fn role_write_check_walks_granted_roles() {
        let grants = |handle: &str, rows: &[[&str; 3]]| {
            completed(
                handle,
                &[
                    ("privilege", "TEXT"),
                    ("granted_on", "TEXT"),
                    ("name", "TEXT"),
                ],
                &rows
                    .iter()
                    .map(|row| row.iter().map(|cell| Some(*cell)).collect())
                    .collect::<Vec<_>>(),
            )
        };
        let script = install(
            "demo",
            None,
            None,
            vec![
                Ok(completed(
                    "01b2c3d4-0000-0000-0000-00000000ab31",
                    &[("CURRENT_ROLE()", "TEXT")],
                    &[vec![Some("ANALYST")]],
                )),
                Ok(grants(
                    "01b2c3d4-0000-0000-0000-00000000ab32",
                    &[
                        ["USAGE", "WAREHOUSE", "WH"],
                        ["SELECT", "TABLE", "DB.S.T"],
                        ["USAGE", "ROLE", "LOADER"],
                    ],
                )),
                Ok(grants(
                    "01b2c3d4-0000-0000-0000-00000000ab33",
                    &[
                        ["INSERT", "TABLE", "DB.S.T"],
                        ["CREATE TABLE", "SCHEMA", "DB.S"],
                    ],
                )),
            ],
        );
        let conn = LiveConn::resolve("demo", &SessionOverrides::default()).unwrap();
        let check = role_write_check(&conn);
        assert_eq!(check.role.as_deref(), Some("ANALYST"));
        assert_eq!(check.roles_checked, ["ANALYST", "LOADER"]);
        assert_eq!(
            check.write_grants,
            [
                "INSERT on TABLE DB.S.T (via LOADER)",
                "CREATE TABLE on SCHEMA DB.S (via LOADER)"
            ]
        );
        let statements: Vec<String> = script
            .submitted()
            .into_iter()
            .map(|request| request.statement)
            .collect();
        assert_eq!(statements[1], r#"SHOW GRANTS TO ROLE "ANALYST""#);
        assert_eq!(statements[2], r#"SHOW GRANTS TO ROLE "LOADER""#);
    }

    #[test]
    fn role_verdict_warns_refuses_and_passes() {
        let check = |write_grants: &[&str], error: Option<&str>| RoleCheck {
            role: Some("R".to_owned()),
            write_grants: write_grants
                .iter()
                .map(|grant| (*grant).to_owned())
                .collect(),
            roles_checked: vec!["R".to_owned()],
            partial: false,
            error: error.map(str::to_owned),
        };
        // Read-only grants: no warning, no refusal, write_capable false.
        let (data, warnings, refusal) = role_verdict(&check(&[], None), true, true);
        assert!(warnings.is_empty() && refusal.is_none());
        assert!(crate::render_json(&data).contains(r#""write_capable":false"#));
        // A write grant on a read profile warns.
        let (_, warnings, refusal) =
            role_verdict(&check(&["INSERT on TABLE T"], None), true, false);
        assert_eq!(warnings.len(), 1);
        assert!(refusal.is_none());
        assert!(crate::render_json(&warnings[0]).contains("can mutate data (INSERT on TABLE T)"));
        // READ_ONLY_EXPECTED turns it into a profile error (exit 3).
        let (_, _, refusal) = role_verdict(&check(&["INSERT on TABLE T"], None), true, true);
        assert_eq!(
            refusal.map(|error| error.code),
            Some(SnowflakeErrorCode::ProfileInvalid)
        );
        // A write profile is expected to write: no warning.
        let (_, warnings, refusal) =
            role_verdict(&check(&["INSERT on TABLE T"], None), false, false);
        assert!(warnings.is_empty() && refusal.is_none());
        // An unverifiable check fails closed only when read-only is expected.
        let (data, warnings, refusal) =
            role_verdict(&check(&[], Some("SHOW GRANTS failed")), true, false);
        assert!(warnings.is_empty() && refusal.is_none());
        assert!(crate::render_json(&data).contains(r#""write_capable":null"#));
        let (_, _, refusal) = role_verdict(&check(&[], Some("SHOW GRANTS failed")), true, true);
        assert!(refusal.is_some());
        assert!(is_write_capable_privilege("apply masking policy"));
        assert!(!is_write_capable_privilege("SELECT"));
        assert!(!is_write_capable_privilege("USAGE"));
        assert_eq!(quoted_identifier(r#"we"ird"#), r#""we""ird""#);
    }

    #[test]
    fn progress_lines_are_one_json_object_per_event() {
        let line = progress_line(
            &DriverEvent::PartitionFetched {
                index: 2,
                rows: 10,
                bytes: 512,
            },
            7,
        );
        let value: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
        assert_eq!(value["event"], "partition_fetched");
        assert_eq!(value["index"], 2);
        assert_eq!(value["rows"], 10);
        assert_eq!(value["bytes"], 512);
        assert_eq!(value["elapsed_ms"], 7);
        assert!(!line.contains('\n'));
    }

    #[test]
    fn the_run_observer_keeps_the_handle_and_the_cancel_answer() {
        let mut observer = RunObserver::new(false);
        observer.event(DriverEvent::Submitted {
            statement_handle: Some("01b2-handle".to_owned()),
            running: true,
        });
        observer.event(DriverEvent::Polled { polls: 1 });
        observer.event(DriverEvent::RemoteCancel {
            statement_handle: "01b2-handle".to_owned(),
            acknowledged: true,
            detail: "completed".to_owned(),
        });
        assert_eq!(
            observer.facts,
            RunFacts {
                statement_handle: Some("01b2-handle".to_owned()),
                remote_cancel: Some((true, "completed".to_owned())),
            }
        );
        let extra = terminal_run_json(&observer.facts);
        assert_eq!(extra["accepted_by_snowflake"], true);
        assert_eq!(extra["remote_cancel"]["acknowledged"], true);
        // Never accepted (cancelled while connecting): no handle, no cancel.
        let never = terminal_run_json(&RunFacts::default());
        assert_eq!(never["accepted_by_snowflake"], false);
        assert!(never.get("remote_cancel").is_none());
        let line = progress_line(
            &DriverEvent::RemoteCancel {
                statement_handle: "h".to_owned(),
                acknowledged: false,
                detail: "unexpected".to_owned(),
            },
            3,
        );
        assert!(line.contains(r#""event":"remote_cancel""#), "{line}");
    }

    /// Bead w0i.11: a run on a thread with a progress sink hands every driver
    /// event to it; the sink is gone once the scope ends.
    #[test]
    fn the_run_observer_feeds_the_threads_progress_sink() {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        with_progress_sink(
            Arc::new(move |event: &DriverEvent| {
                if let Ok(mut events) = recorded.lock() {
                    events.push(progress_line(event, 0));
                }
            }),
            || {
                let mut observer = RunObserver::new(false);
                observer.event(DriverEvent::Submitted {
                    statement_handle: Some("01b2-handle".to_owned()),
                    running: false,
                });
                observer.event(DriverEvent::Completed {
                    rows: 3,
                    partitions: 1,
                });
            },
        );
        let lines = seen.lock().map(|events| events.clone()).unwrap_or_default();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("01b2-handle"), "{lines:?}");
        let mut after = RunObserver::new(false);
        after.event(DriverEvent::Polled { polls: 1 });
        assert_eq!(seen.lock().map(|events| events.len()).unwrap_or(0), 2);
    }

    #[test]
    fn signal_cancelled_runs_exit_130_or_143() {
        assert_eq!(signal_status(true, false), Some(130));
        assert_eq!(signal_status(false, true), Some(143));
        assert_eq!(
            signal_status(true, true),
            Some(130),
            "SIGINT was the cancel"
        );
        assert_eq!(signal_status(false, false), None);
    }

    #[test]
    fn unique_request_id_produces_distinct_values() {
        let id1 = unique_request_id();
        let id2 = unique_request_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 36);
        assert_eq!(id2.len(), 36);
    }
}
