//! Opt-in live proof lanes for the real Snowflake SQL API path.
//!
//! This test is safe in no-account CI: without `FRANKEN_SNOWFLAKE_LIVE=1` and a
//! named profile's env handles, it records a typed skip artifact and does not
//! resolve credentials or perform network IO. With explicit opt-in, it uses the
//! real auth model, Asupersync HTTP transport, and SQL API statement driver.

use std::collections::BTreeMap;
use std::env;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use asupersync::runtime::RuntimeBuilder;
use asupersync::{CancelKind, Cx, Outcome};
use franken_snowflake_auth::{
    AuthProfile, KEYPAIR_JWT_TOKEN_TYPE, OAUTH_TOKEN_TYPE, PROGRAMMATIC_ACCESS_TOKEN_TYPE,
    ProcessSecretResolver, SecretSource, SnowflakeAuth,
};
use franken_snowflake_core::ids::{
    DatabaseName, RoleName, SchemaName, StatementHandle, WarehouseName,
};
use franken_snowflake_http::{
    AuthorizationDescriptor, CancelHttpRequest, SnowflakeAuthTokenType, SnowflakeEndpoint,
    SnowflakeHttpClient, StatusClass, SubmitHttpRequest, TransportConfig, TransportRoute,
};
use franken_snowflake_sqlapi::driver::run_statement;
use franken_snowflake_sqlapi::lifecycle::{CompletedStatement, PollPlan};
use franken_snowflake_sqlapi::request::{SubmitQueryParams, SubmitStatementRequest};
use franken_snowflake_sqlapi::response::{QueryStatus, StatementCancelResponse};
use franken_snowflake_testkit::harness::logger::RunLogger;
use serde::Serialize;

const COMMAND_ID: &str = "live-proof";
const DOC_CONSULTED: &str = "2026-06-25";
const SQL_API_INDEX_DOC: &str = "https://docs.snowflake.com/en/developer-guide/sql-api/index";
const SQL_API_REFERENCE_DOC: &str =
    "https://docs.snowflake.com/en/developer-guide/sql-api/reference";
const SQL_API_RESPONSE_DOC: &str =
    "https://docs.snowflake.com/en/developer-guide/sql-api/handling-responses";
const SYSTEM_WAIT_DOC: &str = "https://docs.snowflake.com/en/sql-reference/functions/system_wait";
const GENERATOR_DOC: &str = "https://docs.snowflake.com/en/sql-reference/functions/generator";
const LIVE_OPT_IN_ENV: &str = "FRANKEN_SNOWFLAKE_LIVE";
const LIVE_PROFILE_ENV: &str = "FRANKEN_SNOWFLAKE_LIVE_PROFILE";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LiveGateCode {
    NotOptedIn,
    ProfileMissing,
    ProfileInvalid,
    RequiredEnvMissing,
    AuthLaneInvalid,
    EndpointInvalid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct LiveGate {
    schema: &'static str,
    code: LiveGateCode,
    outcome: &'static str,
    profile: Option<String>,
    missing_env: Vec<String>,
    detail: String,
    docs_consulted: DocsConsulted,
}

impl LiveGate {
    const SCHEMA: &'static str = "franken_snowflake.live_gate.v1";

    fn new(
        code: LiveGateCode,
        profile: Option<String>,
        missing_env: Vec<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            schema: Self::SCHEMA,
            code,
            outcome: "skip",
            profile,
            missing_env,
            detail: detail.into(),
            docs_consulted: DocsConsulted::current(),
        }
    }

    fn to_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|error| error.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct DocsConsulted {
    date: &'static str,
    urls: [&'static str; 5],
}

impl DocsConsulted {
    const fn current() -> Self {
        Self {
            date: DOC_CONSULTED,
            urls: [
                SQL_API_INDEX_DOC,
                SQL_API_REFERENCE_DOC,
                SQL_API_RESPONSE_DOC,
                SYSTEM_WAIT_DOC,
                GENERATOR_DOC,
            ],
        }
    }
}

#[derive(Clone, Debug)]
struct LiveProfile {
    profile: String,
    env_prefix: String,
    account: String,
    user: String,
    database: String,
    schema: String,
    warehouse: String,
    role: Option<String>,
    endpoint: SnowflakeEndpoint,
    auth_profile: AuthProfile,
    max_polls: u32,
    profile_sql: String,
    catalog_sql: String,
    small_sql: String,
    cancel_sql: String,
    partition_sql: String,
}

impl LiveProfile {
    #[allow(clippy::result_large_err)]
    fn load() -> Result<Self, LiveGate> {
        if env::var(LIVE_OPT_IN_ENV).as_deref() != Ok("1") {
            return Err(LiveGate::new(
                LiveGateCode::NotOptedIn,
                None,
                vec![LIVE_OPT_IN_ENV.to_string()],
                "set FRANKEN_SNOWFLAKE_LIVE=1 to enable live Snowflake SQL API proof lanes",
            ));
        }

        let profile = required_env(LIVE_PROFILE_ENV).map_err(|missing| {
            LiveGate::new(
                LiveGateCode::ProfileMissing,
                None,
                missing,
                "live proof requires an explicit profile handle",
            )
        })?;
        if !is_valid_profile_id(&profile) {
            return Err(LiveGate::new(
                LiveGateCode::ProfileInvalid,
                Some(profile),
                Vec::new(),
                "profile id must be 1-128 ASCII letters, digits, dot, dash, or underscore",
            ));
        }

        let env_prefix = profile_env_prefix(&profile);
        let required = [
            env_name(&env_prefix, "ACCOUNT"),
            env_name(&env_prefix, "USER"),
            env_name(&env_prefix, "AUTH"),
            env_name(&env_prefix, "DATABASE"),
            env_name(&env_prefix, "SCHEMA"),
            env_name(&env_prefix, "WAREHOUSE"),
        ];
        let mut missing = missing_env(required.iter().map(String::as_str));
        let auth_lane = env_value(&env_name(&env_prefix, "AUTH")).unwrap_or_default();
        match auth_lane.as_str() {
            "pat" | "programmatic_access_token" => {
                push_missing(&mut missing, &env_name(&env_prefix, "PAT"));
            }
            "oauth" | "oauth_bearer" | "oauth_bearer_token" => {
                push_missing(&mut missing, &env_name(&env_prefix, "OAUTH_BEARER"));
            }
            "key_pair_jwt" | "jwt" => {
                push_missing(&mut missing, &env_name(&env_prefix, "PRIVATE_KEY_PEM"));
            }
            _ if !auth_lane.is_empty() => {
                return Err(LiveGate::new(
                    LiveGateCode::AuthLaneInvalid,
                    Some(profile),
                    Vec::new(),
                    "auth lane must be one of pat, oauth_bearer, or key_pair_jwt",
                ));
            }
            _ => {}
        }
        if !missing.is_empty() {
            return Err(LiveGate::new(
                LiveGateCode::RequiredEnvMissing,
                Some(profile),
                missing,
                "one or more required non-secret env handles are absent",
            ));
        }

        let account = required_env(&env_name(&env_prefix, "ACCOUNT")).map_err(|missing| {
            LiveGate::new(
                LiveGateCode::RequiredEnvMissing,
                Some(profile.clone()),
                missing,
                "account identifier is required",
            )
        })?;
        let endpoint = SnowflakeEndpoint::parse(endpoint_url(&account)).map_err(|error| {
            LiveGate::new(
                LiveGateCode::EndpointInvalid,
                Some(profile.clone()),
                Vec::new(),
                error.message,
            )
        })?;
        let user = required_env(&env_name(&env_prefix, "USER")).map_err(|missing| {
            LiveGate::new(
                LiveGateCode::RequiredEnvMissing,
                Some(profile.clone()),
                missing,
                "user identifier is required",
            )
        })?;
        let database = required_env(&env_name(&env_prefix, "DATABASE")).map_err(|missing| {
            LiveGate::new(
                LiveGateCode::RequiredEnvMissing,
                Some(profile.clone()),
                missing,
                "database is required for catalog and query proof lanes",
            )
        })?;
        let schema = required_env(&env_name(&env_prefix, "SCHEMA")).map_err(|missing| {
            LiveGate::new(
                LiveGateCode::RequiredEnvMissing,
                Some(profile.clone()),
                missing,
                "schema is required for catalog and query proof lanes",
            )
        })?;
        let warehouse = required_env(&env_name(&env_prefix, "WAREHOUSE")).map_err(|missing| {
            LiveGate::new(
                LiveGateCode::RequiredEnvMissing,
                Some(profile.clone()),
                missing,
                "warehouse is required so live proof never relies on account defaults",
            )
        })?;
        let role = env_value(&env_name(&env_prefix, "ROLE"));
        let auth_profile = auth_profile(&env_prefix, auth_lane.as_str()).map_err(|detail| {
            LiveGate::new(
                LiveGateCode::AuthLaneInvalid,
                Some(profile.clone()),
                Vec::new(),
                detail,
            )
        })?;

        Ok(Self {
            profile,
            env_prefix: env_prefix.clone(),
            account,
            user,
            database,
            schema,
            warehouse,
            role,
            endpoint,
            auth_profile,
            max_polls: env_u32(&env_name(&env_prefix, "MAX_POLLS")).unwrap_or(120),
            profile_sql: env_value(&env_name(&env_prefix, "PROFILE_SQL"))
                .unwrap_or_else(|| "SELECT CURRENT_VERSION() AS SNOWFLAKE_VERSION".to_string()),
            catalog_sql: env_value(&env_name(&env_prefix, "CATALOG_SQL")).unwrap_or_else(|| {
                "SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME \
                 FROM INFORMATION_SCHEMA.TABLES \
                 ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME LIMIT 1"
                    .to_string()
            }),
            small_sql: env_value(&env_name(&env_prefix, "SMALL_SQL"))
                .unwrap_or_else(|| "SELECT 1 AS FSNOW_LIVE_PROOF".to_string()),
            cancel_sql: env_value(&env_name(&env_prefix, "CANCEL_SQL"))
                .unwrap_or_else(|| "CALL SYSTEM$WAIT(30, 'SECONDS')".to_string()),
            partition_sql: env_value(&env_name(&env_prefix, "PARTITION_SQL")).unwrap_or_else(
                || "SELECT SEQ4() AS N FROM TABLE(GENERATOR(ROWCOUNT => 50000))".to_string(),
            ),
        })
    }

    fn request(&self, sql: &str, timeout_seconds: u32) -> SubmitStatementRequest {
        let mut request = SubmitStatementRequest::new(sql);
        request.timeout = Some(timeout_seconds);
        request.database = Some(DatabaseName::new(self.database.clone()));
        request.schema = Some(SchemaName::new(self.schema.clone()));
        request.warehouse = Some(WarehouseName::new(self.warehouse.clone()));
        request.role = self.role.clone().map(RoleName::new);
        request.parameters = Some(deterministic_session_parameters());
        request
    }

    fn redact_detail(&self, detail: impl AsRef<str>) -> String {
        detail
            .as_ref()
            .replace(&self.account, "[REDACTED_ACCOUNT]")
            .replace(self.endpoint.host(), "[REDACTED_ACCOUNT_HOST]")
    }
}

#[test]
fn opt_in_live_sql_api_proof_lanes() -> Result<(), String> {
    let artifacts_root = artifacts_root();
    let trace_id = env::var("FRANKEN_SNOWFLAKE_LIVE_TRACE_ID")
        .unwrap_or_else(|_| "fsnow-live-proof".to_string());
    let mut logger = RunLogger::new(artifacts_root, trace_id).map_err(|error| error.to_string())?;
    logger
        .info(
            COMMAND_ID,
            "docs_consulted",
            serde_json::to_string(&DocsConsulted::current()).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;

    let profile = match LiveProfile::load() {
        Ok(profile) => profile,
        Err(gate) => {
            logger
                .skip(COMMAND_ID, "credential_gate", gate.to_json()?)
                .map_err(|error| error.to_string())?;
            let summary = logger.finish().map_err(|error| error.to_string())?;
            if summary.skipped == 0 || summary.failed != 0 {
                return Err("missing live credentials must produce a typed skip".to_string());
            }
            return Ok(());
        }
    };

    match run_live_lanes(&profile, &mut logger) {
        Ok(()) => {
            let summary = logger.finish().map_err(|error| error.to_string())?;
            if summary.ok() {
                Ok(())
            } else {
                Err(format!(
                    "live proof failed; artifacts are in {}",
                    summary.artifacts_dir
                ))
            }
        }
        Err(error) => {
            let redacted = profile.redact_detail(error);
            logger
                .fail(
                    COMMAND_ID,
                    "live_sql_api_path",
                    "all live lanes pass",
                    redacted,
                )
                .map_err(|log_error| log_error.to_string())?;
            let summary = logger.finish().map_err(|log_error| log_error.to_string())?;
            Err(format!(
                "live proof failed; artifacts are in {}",
                summary.artifacts_dir
            ))
        }
    }
}

#[test]
fn spawned_cli_helper_strips_secret_env_and_disables_live_transport() {
    let sanitized = sanitized_spawned_cli_env([
        ("PATH", "/usr/bin"),
        (LIVE_OPT_IN_ENV, "1"),
        (LIVE_PROFILE_ENV, "trial"),
        ("FRANKEN_SNOWFLAKE_TRIAL_ACCOUNT", "acme-test"),
        ("FRANKEN_SNOWFLAKE_TRIAL_AUTH", "pat"),
        ("FRANKEN_SNOWFLAKE_TRIAL_PAT", "secret-pat"),
        ("FRANKEN_SNOWFLAKE_TRIAL_OAUTH_BEARER", "secret-oauth"),
        ("FRANKEN_SNOWFLAKE_TRIAL_PRIVATE_KEY_PEM", "secret-key"),
        (
            "FRANKEN_SNOWFLAKE_TRIAL_PRIVATE_KEY_PASSPHRASE",
            "secret-passphrase",
        ),
        ("FRANKEN_SNOWFLAKE_TRIAL_PASSWORD", "secret-password"),
    ]);

    assert_eq!(
        sanitized.get(LIVE_OPT_IN_ENV).map(String::as_str),
        Some("0")
    );
    assert!(!sanitized.contains_key(LIVE_PROFILE_ENV));
    assert_eq!(
        sanitized
            .get("FRANKEN_SNOWFLAKE_TRIAL_ACCOUNT")
            .map(String::as_str),
        Some("acme-test")
    );
    assert_eq!(
        sanitized
            .get("FRANKEN_SNOWFLAKE_TRIAL_AUTH")
            .map(String::as_str),
        Some("pat")
    );
    for key in sanitized.keys() {
        assert!(
            !is_secret_snowflake_env(key),
            "secret-shaped env var leaked into spawned CLI env: {key}"
        );
    }
}

fn run_live_lanes(profile: &LiveProfile, logger: &mut RunLogger) -> Result<(), String> {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or_else(|| "Asupersync runtime did not install Cx".to_string())?;
        let client =
            SnowflakeHttpClient::default_for_runtime(TransportConfig::new(profile.endpoint.clone()), &cx);
        let mut auth = profile
            .auth_profile
            .resolve(&ProcessSecretResolver, &profile.account, &profile.user)
            .map_err(|error| profile.redact_detail(error.to_string()))?;
        let auth = authorization_descriptor(&mut auth).map_err(|error| profile.redact_detail(error))?;

        logger
            .pass(COMMAND_ID, "credential_gate")
            .map_err(|error| error.to_string())?;
        logger
            .info(
                COMMAND_ID,
                "profile_env_contract",
                format!(
                    "profile={}, prefix={}, auth_fingerprint={}",
                    profile.profile,
                    profile.env_prefix,
                    auth.redacted_fingerprint()
                ),
            )
            .map_err(|error| error.to_string())?;

        let profile_probe = run_query_lane(
            &cx,
            &client,
            auth.clone(),
            profile,
            "profile_doctor_online",
            &profile.profile_sql,
            "00000000-0000-4000-8000-000000000101",
        )
        .await?;
        require_rows(profile, "profile_doctor_online", &profile_probe, 1)?;
        logger
            .pass(COMMAND_ID, "profile_doctor_online")
            .map_err(|error| error.to_string())?;

        let catalog = run_query_lane(
            &cx,
            &client,
            auth.clone(),
            profile,
            "catalog_scan",
            &profile.catalog_sql,
            "00000000-0000-4000-8000-000000000102",
        )
        .await?;
        logger
            .info(
                COMMAND_ID,
                "catalog_scan_rows",
                format!("rows={}", catalog.rows.len()),
            )
            .map_err(|error| error.to_string())?;
        logger
            .pass(COMMAND_ID, "catalog_scan")
            .map_err(|error| error.to_string())?;

        let small = run_query_lane(
            &cx,
            &client,
            auth.clone(),
            profile,
            "small_select",
            &profile.small_sql,
            "00000000-0000-4000-8000-000000000103",
        )
        .await?;
        require_rows(profile, "small_select", &small, 1)?;
        logger
            .pass(COMMAND_ID, "small_select")
            .map_err(|error| error.to_string())?;

        let cancelled = cancel_lane(&cx, &client, auth.clone(), profile).await?;
        logger
            .info(
                COMMAND_ID,
                "async_cancel_handle",
                format!("statement_handle={}", cancelled.as_str()),
            )
            .map_err(|error| error.to_string())?;
        logger
            .pass(COMMAND_ID, "async_cancel")
            .map_err(|error| error.to_string())?;

        let partitioned = run_query_lane(
            &cx,
            &client,
            auth,
            profile,
            "partitioned_result",
            &profile.partition_sql,
            "00000000-0000-4000-8000-000000000105",
        )
        .await?;
        if partitioned.result_set.partition_count() < 2 {
            return Err(format!(
                "partitioned_result did not produce multiple partitions; set {}_PARTITION_SQL to a larger read-only query",
                profile.env_prefix
            ));
        }
        logger
            .info(
                COMMAND_ID,
                "partitioned_result_partitions",
                format!(
                    "partitions={}, rows={}",
                    partitioned.result_set.partition_count(),
                    partitioned.rows.len()
                ),
            )
            .map_err(|error| error.to_string())?;
        logger
            .pass(COMMAND_ID, "partitioned_result")
            .map_err(|error| error.to_string())?;

        Ok(())
    })
}

async fn run_query_lane(
    cx: &Cx,
    client: &SnowflakeHttpClient,
    auth: AuthorizationDescriptor,
    profile: &LiveProfile,
    lane: &str,
    sql: &str,
    request_id: &str,
) -> Result<CompletedStatement, String> {
    let request = profile.request(sql, 60);
    let params = SubmitQueryParams {
        request_id: Some(request_id.to_string()),
        retry: true,
        asynchronous: false,
        nullable: None,
    };
    match run_statement(
        cx,
        client,
        auth,
        request,
        params,
        PollPlan::with_max_polls(profile.max_polls),
    )
    .await
    {
        Outcome::Ok(done) => Ok(done),
        Outcome::Err(error) => Err(profile.redact_detail(format!("{lane}: {error}"))),
        Outcome::Cancelled(reason) => Err(format!("{lane}: cancelled: {:?}", reason.kind)),
        Outcome::Panicked(payload) => Err(format!("{lane}: panicked: {payload:?}")),
    }
}

async fn cancel_lane(
    cx: &Cx,
    client: &SnowflakeHttpClient,
    auth: AuthorizationDescriptor,
    profile: &LiveProfile,
) -> Result<StatementHandle, String> {
    let params = SubmitQueryParams {
        request_id: Some("00000000-0000-4000-8000-000000000104".to_string()),
        retry: true,
        asynchronous: true,
        nullable: None,
    };
    let body = serde_json::to_vec(&profile.request(&profile.cancel_sql, 120))
        .map_err(|error| format!("async_cancel: failed to serialize submit request: {error}"))?;
    let submit = SubmitHttpRequest {
        route: TransportRoute::SubmitWithQuery {
            query: params.to_query_pairs(),
        },
        auth: auth.clone(),
        body,
        retry_resubmit: false,
    };
    let response = match client.submit_statement(cx, submit).await {
        Outcome::Ok(response) => response,
        Outcome::Err(error) => return Err(profile.redact_detail(format!("async_cancel: {error}"))),
        Outcome::Cancelled(reason) => {
            return Err(format!(
                "async_cancel: cancelled before handle: {:?}",
                reason.kind
            ));
        }
        Outcome::Panicked(payload) => return Err(format!("async_cancel: panicked: {payload:?}")),
    };
    if response.status != StatusClass::Running {
        return Err(format!(
            "async_cancel expected a 202/running handle, got {:?}",
            response.status
        ));
    }
    let status: QueryStatus = serde_json::from_slice(&response.body)
        .map_err(|error| format!("async_cancel: failed to decode QueryStatus: {error}"))?;
    let handle = status.statement_handle;
    let cancel = CancelHttpRequest {
        auth,
        statement_handle: handle.clone(),
        reason_kind: CancelKind::User,
    };
    let response = match client.cancel_statement(cx, cancel).await {
        Outcome::Ok(response) => response,
        Outcome::Err(error) => return Err(profile.redact_detail(format!("async_cancel: {error}"))),
        Outcome::Cancelled(reason) => {
            return Err(format!(
                "async_cancel: cancel request cancelled: {:?}",
                reason.kind
            ));
        }
        Outcome::Panicked(payload) => return Err(format!("async_cancel: panicked: {payload:?}")),
    };
    if response.status != StatusClass::Completed {
        return Err(format!(
            "async_cancel expected cancel endpoint completion, got {:?}",
            response.status
        ));
    }
    let _ack: StatementCancelResponse = serde_json::from_slice(&response.body)
        .map_err(|error| format!("async_cancel: failed to decode cancel response: {error}"))?;
    Ok(handle)
}

fn authorization_descriptor(
    mechanism: &mut impl SnowflakeAuth,
) -> Result<AuthorizationDescriptor, String> {
    let headers = mechanism
        .headers_at(now_unix_seconds())
        .map_err(|error| error.to_string())?;
    let bearer = headers
        .authorization_value()
        .strip_prefix("Bearer ")
        .ok_or_else(|| "authorization header did not contain a bearer token".to_string())?;
    let token_type = match headers.token_type_value() {
        PROGRAMMATIC_ACCESS_TOKEN_TYPE => SnowflakeAuthTokenType::ProgrammaticAccessToken,
        KEYPAIR_JWT_TOKEN_TYPE => SnowflakeAuthTokenType::KeypairJwt,
        OAUTH_TOKEN_TYPE => SnowflakeAuthTokenType::OAuth,
        other => return Err(format!("unsupported auth token type: {other}")),
    };
    Ok(AuthorizationDescriptor::bearer(
        token_type,
        bearer,
        mechanism
            .credential_handle()
            .unwrap_or("cred_resolved_without_handle"),
    ))
}

fn require_rows(
    profile: &LiveProfile,
    lane: &str,
    completed: &CompletedStatement,
    minimum: usize,
) -> Result<(), String> {
    if completed.rows.len() >= minimum {
        Ok(())
    } else {
        Err(profile.redact_detail(format!(
            "{lane}: expected at least {minimum} row(s), got {}",
            completed.rows.len()
        )))
    }
}

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

fn auth_profile(env_prefix: &str, lane: &str) -> Result<AuthProfile, String> {
    match lane {
        "pat" | "programmatic_access_token" => Ok(AuthProfile::pat(
            SecretSource::env_var(env_name(env_prefix, "PAT"))
                .map_err(|error| error.to_string())?,
        )),
        "oauth" | "oauth_bearer" | "oauth_bearer_token" => Ok(AuthProfile::oauth_bearer(
            SecretSource::env_var(env_name(env_prefix, "OAUTH_BEARER"))
                .map_err(|error| error.to_string())?,
        )),
        "key_pair_jwt" | "jwt" => Ok(AuthProfile::key_pair_jwt(
            SecretSource::env_var(env_name(env_prefix, "PRIVATE_KEY_PEM"))
                .map_err(|error| error.to_string())?,
            env_value(&env_name(env_prefix, "PRIVATE_KEY_PASSPHRASE"))
                .map(|_| SecretSource::env_var(env_name(env_prefix, "PRIVATE_KEY_PASSPHRASE")))
                .transpose()
                .map_err(|error| error.to_string())?,
            env_u64(&env_name(env_prefix, "JWT_VALIDITY_SECONDS")).unwrap_or(3600),
        )),
        _ => Err("auth lane must be one of pat, oauth_bearer, or key_pair_jwt".to_string()),
    }
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

fn artifacts_root() -> PathBuf {
    env::var_os("FRANKEN_SNOWFLAKE_LIVE_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .map(|path| path.join("fsnow-live-proof"))
        })
        .unwrap_or_else(|| PathBuf::from("target").join("fsnow-live-proof"))
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(0)
}

fn env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn required_env(name: &str) -> Result<String, Vec<String>> {
    env_value(name).ok_or_else(|| vec![name.to_string()])
}

fn missing_env<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    names
        .filter(|name| env_value(name).is_none())
        .map(str::to_string)
        .collect()
}

fn push_missing(missing: &mut Vec<String>, name: &str) {
    if env_value(name).is_none() {
        missing.push(name.to_string());
    }
}

fn env_u32(name: &str) -> Option<u32> {
    env_value(name).and_then(|value| value.parse::<u32>().ok())
}

fn env_u64(name: &str) -> Option<u64> {
    env_value(name).and_then(|value| value.parse::<u64>().ok())
}

fn env_name(prefix: &str, key: &str) -> String {
    format!("{prefix}_{key}")
}

fn is_valid_profile_id(profile: &str) -> bool {
    !profile.is_empty()
        && profile.len() <= 128
        && profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn profile_env_prefix(profile: &str) -> String {
    let mut suffix = String::new();
    for byte in profile.bytes() {
        if byte.is_ascii_alphanumeric() {
            suffix.push(byte.to_ascii_uppercase() as char);
        } else if matches!(byte, b'.' | b'-' | b'_') {
            suffix.push('_');
        }
    }
    if suffix.is_empty() {
        "FRANKEN_SNOWFLAKE_PROFILE".to_string()
    } else {
        format!("FRANKEN_SNOWFLAKE_{suffix}")
    }
}

fn sanitized_spawned_cli_env<I, K, V>(source: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    let mut sanitized = BTreeMap::new();
    for (key, value) in source {
        let key = key.into();
        if key == LIVE_PROFILE_ENV || key == LIVE_OPT_IN_ENV || is_secret_snowflake_env(&key) {
            continue;
        }
        sanitized.insert(key, value.into());
    }
    sanitized.insert(LIVE_OPT_IN_ENV.to_string(), "0".to_string());
    sanitized
}

fn is_secret_snowflake_env(key: &str) -> bool {
    key.starts_with("FRANKEN_SNOWFLAKE_")
        && (key.ends_with("_PAT")
            || key.ends_with("_OAUTH_BEARER")
            || key.ends_with("_PRIVATE_KEY_PEM")
            || key.ends_with("_PRIVATE_KEY_PASSPHRASE")
            || key.ends_with("_PASSWORD")
            || key.ends_with("_TOKEN")
            || key.ends_with("_SECRET"))
}
