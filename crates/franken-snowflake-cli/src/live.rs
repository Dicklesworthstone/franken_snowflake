//! Live SQL API transport wiring for the CLI (`feature = "live"`).
//!
//! Only compiled with `--features live`. It reuses the crate-root envelope
//! machinery (`crate::base_envelope`, `crate::Json`, `crate::Outcome`, ...) and
//! the published transport stack (`franken-snowflake-{auth,http,sqlapi}` +
//! Asupersync), driving the exact submit -> poll -> partition -> assemble flow the
//! opt-in `live_proof` integration test already proves end-to-end.
//!
//! Provenance and safety contract:
//! - On success the envelope carries `data_source = "live"` and the real
//!   statement handle; it never substitutes fixture or empty data.
//! - When a profile's credential env handles are absent the command returns a
//!   typed credential error (exit code 3), not a silent empty result.
//! - Result rows are capped into the envelope at [`ROW_EMIT_CAP`] with an explicit
//!   `truncated` flag and a warning, so an agent never has an unbounded payload
//!   silently appear (full extraction is a Snowflake-side `LIMIT`/`COPY INTO`).
//! - Secrets are never read into any message here; auth/transport errors arrive
//!   already redacted, and the crate-root `sanitize_envelope` pass runs the
//!   secret-leak redactor over the whole envelope (including row data) before
//!   output.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use asupersync::runtime::RuntimeBuilder;
use asupersync::{Cx, Outcome};
use franken_snowflake_auth::{
    AuthProfile, KEYPAIR_JWT_TOKEN_TYPE, OAUTH_TOKEN_TYPE, PROGRAMMATIC_ACCESS_TOKEN_TYPE,
    ProcessSecretResolver, SecretSource, SnowflakeAuth,
};
use franken_snowflake_core::error::{SnowflakeError, SnowflakeErrorCode};
use franken_snowflake_core::exit::ExitCode as CoreExitCode;
use franken_snowflake_core::ids::{DatabaseName, RoleName, SchemaName, WarehouseName};
use franken_snowflake_http::{
    AuthorizationDescriptor, SnowflakeAuthTokenType, SnowflakeEndpoint, SnowflakeHttpClient,
    TransportConfig,
};
use franken_snowflake_sqlapi::driver::run_statement;
use franken_snowflake_sqlapi::lifecycle::{CompletedStatement, PollPlan};
use franken_snowflake_sqlapi::request::{SubmitQueryParams, SubmitStatementRequest};

use crate::{Body, Json, OutputFormat, base_envelope, error_info, json_array, json_object, json_string};

/// SQL API statement timeout (seconds) requested per submit.
const REQUEST_TIMEOUT_SECONDS: u32 = 60;
/// Poll budget if a profile does not override `<PREFIX>_MAX_POLLS`.
const DEFAULT_MAX_POLLS: u32 = 120;
/// Maximum rows materialized into a single response envelope. The driver still
/// assembles the full result; this only bounds the JSON payload an agent sees.
const ROW_EMIT_CAP: usize = 1000;
/// Upper bound on tables listed by one `catalog scan` (pushed down as a SQL
/// `LIMIT`, so an unbounded schema never floods the result).
const CATALOG_SCAN_LIMIT: usize = 10_000;

/// A column's name/type/nullability, projected from the result-set metadata.
struct LiveColumn {
    name: String,
    type_name: String,
    nullable: bool,
}

/// The assembled rows plus the metadata an agent needs to interpret them.
struct LiveRows {
    statement_handle: String,
    columns: Vec<LiveColumn>,
    rows: Vec<Vec<Option<String>>>,
    total_rows: i64,
    partition_count: usize,
}

/// Run one read-only statement live and return a `query run` envelope. Caller
/// guarantees `profile` is present and `sql` already passed the local read-only
/// safety check; credential and transport failures collapse to typed errors.
pub fn run_query_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    sql: &str,
) -> crate::Outcome {
    match execute(&profile, sql, None, None) {
        Ok(rows) => query_success(format, request_id, profile, &rows),
        Err(error) => {
            failure_outcome(format, "query.run", "fsnow.query.run.v1", request_id, profile, &error)
        }
    }
}

/// Run a live `INFORMATION_SCHEMA.TABLES` scan for the given database/schema and
/// return a `catalog scan` envelope. The caller (`parse_catalog`) guarantees both
/// `database` and `schema` are present. Both are validated as plain SQL
/// identifiers before interpolation so the discovery SQL cannot be injected.
pub fn run_catalog_scan_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    database: String,
    schema: String,
) -> crate::Outcome {
    if !is_safe_sql_identifier(&database) {
        return failure_outcome(
            format,
            "catalog.scan",
            "fsnow.catalog.scan.v1",
            request_id,
            profile,
            &SnowflakeError::new(
                SnowflakeErrorCode::UsageError,
                "--database must be a plain SQL identifier (letters, digits, _ or $)",
            ),
        );
    }
    if !is_safe_sql_identifier(&schema) {
        return failure_outcome(
            format,
            "catalog.scan",
            "fsnow.catalog.scan.v1",
            request_id,
            profile,
            &SnowflakeError::new(
                SnowflakeErrorCode::UsageError,
                "--schema must be a plain SQL identifier (letters, digits, _ or $)",
            ),
        );
    }

    let sql = format!(
        "SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, ROW_COUNT, BYTES \
         FROM {database}.INFORMATION_SCHEMA.TABLES \
         WHERE TABLE_SCHEMA = '{schema}' \
         ORDER BY TABLE_SCHEMA, TABLE_NAME \
         LIMIT {CATALOG_SCAN_LIMIT}"
    );
    match execute(&profile, &sql, Some(&database), Some(&schema)) {
        Ok(rows) => rows_success(
            format,
            request_id,
            profile,
            "catalog.scan",
            "fsnow.catalog.scan.v1",
            vec![
                ("database", json_string(database)),
                ("schema", json_string(schema)),
            ],
            &rows,
            vec![
                "franken-snowflake catalog graph <profile> --database <db> --mermaid".to_string(),
                "franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string(),
            ],
        ),
        Err(error) => failure_outcome(
            format,
            "catalog.scan",
            "fsnow.catalog.scan.v1",
            request_id,
            profile,
            &error,
        ),
    }
}

/// Live build: render the catalog lineage graph (profile -> database -> schema ->
/// object) from a real `INFORMATION_SCHEMA.TABLES` scan. Mirrors `catalog scan`'s
/// scoping and safety: requires `--database`, validates identifiers, never
/// substitutes fixture data. Mermaid/SVG return raw text; JSON/TOON carry
/// nodes + edges + the Mermaid rendering in a `data_source: live` envelope.
pub fn run_catalog_graph_outcome(
    format: OutputFormat,
    request_id: String,
    profile: String,
    database: Option<String>,
    schema: Option<String>,
    graph_output: crate::GraphOutput,
) -> crate::Outcome {
    let Some(database) = database else {
        return failure_outcome(
            format,
            "catalog.graph",
            "fsnow.catalog.graph.v1",
            request_id,
            profile,
            &SnowflakeError::new(
                SnowflakeErrorCode::UsageError,
                "catalog graph requires --database (and optionally --schema) to scope the live scan",
            ),
        );
    };
    if !is_safe_sql_identifier(&database) {
        return failure_outcome(
            format,
            "catalog.graph",
            "fsnow.catalog.graph.v1",
            request_id,
            profile,
            &SnowflakeError::new(
                SnowflakeErrorCode::UsageError,
                "--database must be a plain SQL identifier (letters, digits, _ or $)",
            ),
        );
    }
    if let Some(schema_name) = &schema {
        if !is_safe_sql_identifier(schema_name) {
            return failure_outcome(
                format,
                "catalog.graph",
                "fsnow.catalog.graph.v1",
                request_id,
                profile,
                &SnowflakeError::new(
                    SnowflakeErrorCode::UsageError,
                    "--schema must be a plain SQL identifier (letters, digits, _ or $)",
                ),
            );
        }
    }

    let where_clause = match &schema {
        Some(schema_name) => format!("WHERE TABLE_SCHEMA = '{schema_name}' "),
        None => String::new(),
    };
    let sql = format!(
        "SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE \
         FROM {database}.INFORMATION_SCHEMA.TABLES \
         {where_clause}\
         ORDER BY TABLE_SCHEMA, TABLE_NAME \
         LIMIT {CATALOG_SCAN_LIMIT}"
    );
    let rows = match execute(&profile, &sql, Some(&database), schema.as_deref()) {
        Ok(rows) => rows,
        Err(error) => {
            return failure_outcome(
                format,
                "catalog.graph",
                "fsnow.catalog.graph.v1",
                request_id,
                profile,
                &error,
            );
        }
    };

    let graph = CatalogHierarchy::from_rows(&profile, &rows);

    match graph_output {
        crate::GraphOutput::Mermaid => crate::Outcome {
            status: CoreExitCode::Success,
            body: Body::Raw {
                data: graph.to_mermaid(),
            },
        },
        crate::GraphOutput::Svg => crate::Outcome {
            status: CoreExitCode::Success,
            body: Body::Raw {
                data: graph.to_svg(),
            },
        },
        crate::GraphOutput::Json | crate::GraphOutput::Toon => {
            let out_format = if matches!(graph_output, crate::GraphOutput::Toon) {
                OutputFormat::Toon
            } else {
                format
            };
            let mut envelope = base_envelope(
                true,
                "success",
                "catalog.graph",
                "fsnow.catalog.graph.v1",
                request_id,
                json_object(vec![
                    ("profile_id", json_string(profile.clone())),
                    ("database", json_string(database)),
                    (
                        "schema",
                        schema.map_or(Json::Null, json_string),
                    ),
                    ("nodes", graph.nodes_json()),
                    ("edges", graph.edges_json()),
                    ("node_count", Json::Number(graph.nodes.len() as i64)),
                    ("edge_count", Json::Number(graph.edges.len() as i64)),
                    ("mermaid", json_string(graph.to_mermaid())),
                ]),
            );
            envelope.data_source = "live";
            envelope.profile_id = Some(profile);
            envelope.safe_next_commands = vec![
                "franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json"
                    .to_string(),
            ];
            crate::Outcome {
                status: CoreExitCode::Success,
                body: Body::Envelope {
                    envelope,
                    format: out_format,
                },
            }
        }
    }
}

/// A deterministic profile -> database -> schema -> object containment graph built
/// directly from `INFORMATION_SCHEMA.TABLES` rows. Index-based node ids keep the
/// Mermaid/SVG output collision-free and safe regardless of object names.
#[derive(Default)]
struct CatalogHierarchy {
    ids: BTreeMap<String, usize>,
    /// `(kind, label)` indexed by node id.
    nodes: Vec<(&'static str, String)>,
    edge_set: std::collections::BTreeSet<(usize, usize)>,
    edges: Vec<(usize, usize)>,
}

impl CatalogHierarchy {
    fn from_rows(profile: &str, rows: &LiveRows) -> Self {
        let mut h = Self::default();
        let profile_node = h.ensure(format!("P|{profile}"), "profile", format!("profile: {profile}"));
        for row in &rows.rows {
            let cell = |i: usize| row.get(i).and_then(Clone::clone).unwrap_or_default();
            let database = cell(0);
            let schema = cell(1);
            let table = cell(2);
            if database.is_empty() || schema.is_empty() || table.is_empty() {
                continue;
            }
            let db = h.ensure(format!("D|{database}"), "database", database.clone());
            let sc = h.ensure(format!("S|{database}.{schema}"), "schema", schema.clone());
            let ob = h.ensure(
                format!("O|{database}.{schema}.{table}"),
                "object",
                table.clone(),
            );
            h.edge(profile_node, db);
            h.edge(db, sc);
            h.edge(sc, ob);
        }
        h
    }

    fn ensure(&mut self, key: String, kind: &'static str, label: String) -> usize {
        if let Some(&idx) = self.ids.get(&key) {
            return idx;
        }
        let idx = self.nodes.len();
        self.ids.insert(key, idx);
        self.nodes.push((kind, label));
        idx
    }

    fn edge(&mut self, source: usize, target: usize) {
        if self.edge_set.insert((source, target)) {
            self.edges.push((source, target));
        }
    }

    fn to_mermaid(&self) -> String {
        let mut out = String::from("graph TD\n");
        if self.nodes.is_empty() {
            out.push_str("  EMPTY[\"no objects found for this scope\"]\n");
            return out;
        }
        for (idx, (_kind, label)) in self.nodes.iter().enumerate() {
            out.push_str(&format!("  n{idx}[\"{}\"]\n", escape_mermaid_label(label)));
        }
        for (source, target) in &self.edges {
            out.push_str(&format!("  n{source} --> n{target}\n"));
        }
        out
    }

    fn to_svg(&self) -> String {
        let line_height = 18;
        let height = (self.nodes.len().max(1) * line_height) + 20;
        let mut out = format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" role=\"img\" aria-label=\"catalog graph\" \
             width=\"480\" height=\"{height}\">\n"
        );
        for (idx, (kind, label)) in self.nodes.iter().enumerate() {
            let y = 20 + idx * line_height;
            out.push_str(&format!(
                "  <text x=\"10\" y=\"{y}\">{}: {}</text>\n",
                escape_xml(kind),
                escape_xml(label)
            ));
        }
        out.push_str("</svg>\n");
        out
    }

    fn nodes_json(&self) -> Json {
        json_array(
            self.nodes
                .iter()
                .enumerate()
                .map(|(idx, (kind, label))| {
                    json_object(vec![
                        ("id", json_string(format!("n{idx}"))),
                        ("kind", json_string(*kind)),
                        ("label", json_string(label.clone())),
                    ])
                })
                .collect(),
        )
    }

    fn edges_json(&self) -> Json {
        json_array(
            self.edges
                .iter()
                .map(|(source, target)| {
                    json_object(vec![
                        ("source", json_string(format!("n{source}"))),
                        ("target", json_string(format!("n{target}"))),
                        ("kind", json_string("contains")),
                    ])
                })
                .collect(),
        )
    }
}

/// HTML-entity-encode a Mermaid node label so an object name can never inject
/// graph structure. The label sits inside `id["..."]`; encoding `"`/`<`/`>`/`&`
/// and flattening newlines makes structural breakout impossible (`]` and `\` are
/// literal inside the quoted span, so they need no escaping).
fn escape_mermaid_label(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for ch in label.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\n' | '\r' => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

fn escape_xml(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

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
    match execute(&profile, PROBE_SQL, None, None) {
        Ok(rows) => {
            let version = rows
                .rows
                .first()
                .and_then(|row| row.first())
                .and_then(Clone::clone);
            probe_success(format, request_id, profile, version)
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
    envelope.data_source = "live";
    envelope.profile_id = Some(profile);
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

/// Resolve credentials, drive the statement to completion, and assemble rows.
fn execute(
    profile: &str,
    sql: &str,
    database: Option<&str>,
    schema: Option<&str>,
) -> Result<LiveRows, SnowflakeError> {
    let conn = LiveConn::resolve(profile, database, schema)?;
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
        let client =
            SnowflakeHttpClient::default_for_runtime(TransportConfig::new(conn.endpoint.clone()), &cx);
        let mut mechanism = conn
            .auth_profile
            .resolve(&ProcessSecretResolver, &conn.account, &conn.user)
            .map_err(|error| {
                SnowflakeError::new(SnowflakeErrorCode::CredentialMissing, error.to_string())
            })?;
        let auth = authorization_descriptor(&mut mechanism)?;
        let request = build_request(&conn, sql);
        let params = SubmitQueryParams {
            request_id: Some(unique_request_id()),
            retry: true,
            asynchronous: false,
            nullable: None,
        };
        match run_statement(
            &cx,
            &client,
            auth,
            request,
            params,
            PollPlan::with_max_polls(conn.max_polls),
        )
        .await
        {
            Outcome::Ok(done) => Ok(into_rows(done)),
            Outcome::Err(error) => Err(error),
            Outcome::Cancelled(reason) => Err(SnowflakeError::new(
                SnowflakeErrorCode::Internal,
                format!("statement was cancelled before completion: {:?}", reason.kind),
            )),
            Outcome::Panicked(_) => Err(SnowflakeError::new(
                SnowflakeErrorCode::Internal,
                "statement task panicked before completion",
            )),
        }
    })
}

/// A profile's resolved live connection inputs (no secret values — the PAT/key is
/// referenced only through a `SecretSource` resolved at request time).
struct LiveConn {
    account: String,
    user: String,
    warehouse: String,
    database: Option<String>,
    schema: Option<String>,
    role: Option<String>,
    endpoint: SnowflakeEndpoint,
    auth_profile: AuthProfile,
    max_polls: u32,
}

impl LiveConn {
    fn resolve(
        profile: &str,
        database: Option<&str>,
        schema: Option<&str>,
    ) -> Result<Self, SnowflakeError> {
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
        let warehouse = env_value(&name(&prefix, "WAREHOUSE"));

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
        if let Some(secret_env) = &secret_env {
            if env_value(secret_env).is_none() {
                missing.push(secret_env.clone());
            }
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

        Ok(Self {
            account,
            user: user.unwrap_or_default(),
            warehouse: warehouse.unwrap_or_default(),
            database: database.map(str::to_string).or_else(|| env_value(&name(&prefix, "DATABASE"))),
            schema: schema.map(str::to_string).or_else(|| env_value(&name(&prefix, "SCHEMA"))),
            role: env_value(&name(&prefix, "ROLE")),
            endpoint,
            auth_profile,
            max_polls: env_u32(&name(&prefix, "MAX_POLLS")).unwrap_or(DEFAULT_MAX_POLLS),
        })
    }
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
    let credential = |detail: String| SnowflakeError::new(SnowflakeErrorCode::CredentialMissing, detail);
    match lane {
        "pat" | "programmatic_access_token" => Ok(AuthProfile::pat(
            SecretSource::env_var(name(prefix, "PAT")).map_err(|error| credential(error.to_string()))?,
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

fn build_request(conn: &LiveConn, sql: &str) -> SubmitStatementRequest {
    let mut request = SubmitStatementRequest::new(sql);
    request.timeout = Some(REQUEST_TIMEOUT_SECONDS);
    request.warehouse = Some(WarehouseName::new(conn.warehouse.clone()));
    request.database = conn.database.clone().map(DatabaseName::new);
    request.schema = conn.schema.clone().map(SchemaName::new);
    request.role = conn.role.clone().map(RoleName::new);
    request.parameters = Some(deterministic_session_parameters());
    request
}

fn authorization_descriptor(
    mechanism: &mut impl SnowflakeAuth,
) -> Result<AuthorizationDescriptor, SnowflakeError> {
    let headers = mechanism.headers_at(now_unix_seconds()).map_err(|error| {
        SnowflakeError::new(SnowflakeErrorCode::CredentialMissing, error.to_string())
    })?;
    let bearer = headers.authorization_value().strip_prefix("Bearer ").ok_or_else(|| {
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
        mechanism.credential_handle().unwrap_or("cred_resolved_without_handle"),
    ))
}

fn into_rows(done: CompletedStatement) -> LiveRows {
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
    let statement_handle = done.statement_handle.as_str().to_string();
    LiveRows {
        statement_handle,
        columns,
        total_rows,
        partition_count,
        rows: done.rows,
    }
}

fn query_success(
    format: OutputFormat,
    request_id: String,
    profile: String,
    rows: &LiveRows,
) -> crate::Outcome {
    rows_success(
        format,
        request_id,
        profile,
        "query.run",
        "fsnow.query.run.v1",
        Vec::new(),
        rows,
        vec!["franken-snowflake query plan --profile <profile> --sql <sql> --json".to_string()],
    )
}

/// Build a `data_source = "live"` success envelope carrying assembled rows. The
/// rows are projected positionally (matching the `columns` order, the jsonv2
/// shape) and capped at [`ROW_EMIT_CAP`] with an explicit `truncated` flag.
/// `leading` fields (e.g. catalog `database`/`schema`) are placed before the row
/// payload in `data`.
#[allow(clippy::too_many_arguments)]
fn rows_success(
    format: OutputFormat,
    request_id: String,
    profile: String,
    command_id: &'static str,
    output_contract_id: &'static str,
    mut leading: Vec<(&'static str, Json)>,
    rows: &LiveRows,
    safe_next_commands: Vec<String>,
) -> crate::Outcome {
    let returned = rows.rows.len().min(ROW_EMIT_CAP);
    let truncated = rows.rows.len() > ROW_EMIT_CAP;

    let columns_json = json_array(
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
    );
    let rows_json = json_array(
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
    );
    leading.extend(vec![
        ("columns", columns_json),
        ("rows", rows_json),
        ("row_count", Json::Number(rows.total_rows)),
        ("returned_rows", Json::Number(returned as i64)),
        ("partition_count", Json::Number(rows.partition_count as i64)),
        ("row_emit_cap", Json::Number(ROW_EMIT_CAP as i64)),
        ("truncated", Json::Bool(truncated)),
    ]);

    let mut envelope = base_envelope(
        true,
        "success",
        command_id,
        output_contract_id,
        request_id,
        json_object(leading),
    );
    envelope.data_source = "live";
    envelope.profile_id = Some(profile);
    envelope.statement_handle = Some(rows.statement_handle.clone());
    envelope.query_id = Some(rows.statement_handle.clone());
    envelope.budget_consumed = json_object(vec![
        ("deadline_ms", Json::Number(0)),
        ("polls", Json::Number(0)),
        ("rows", Json::Number(rows.total_rows)),
    ]);
    envelope.safe_next_commands = safe_next_commands;
    if truncated {
        envelope.warnings = vec![json_string(format!(
            "result truncated to {ROW_EMIT_CAP} rows in this envelope; {} total rows were \
             returned (use a Snowflake-side LIMIT or COPY INTO for full extraction)",
            rows.total_rows
        ))];
    }

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
        | SnowflakeErrorCode::WarehouseRefused => "refusal",
        _ => "error",
    }
}

/// Deterministic session output formats so live results are stable across runs
/// (UTC, fixed date/time/timestamp/binary formats, result cache disabled).
fn deterministic_session_parameters() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("TIMEZONE".to_string(), "UTC".to_string()),
        ("DATE_OUTPUT_FORMAT".to_string(), "YYYY-MM-DD".to_string()),
        ("TIME_OUTPUT_FORMAT".to_string(), "HH24:MI:SS.FF9".to_string()),
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
/// `database`/`schema` before they are interpolated into the discovery SQL, so a
/// crafted value cannot inject (it is rejected, never escaped-and-trusted).
fn is_safe_sql_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    value.len() <= 255
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
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
