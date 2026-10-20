//! `doctor` and `selftest`: real, executed checks over the linked code and the
//! local environment. Every check here can fail; none is a literal.
//!
//! `doctor` answers "is this machine/binary ready?" (data dir, local store,
//! default profile handles, compiled features). `selftest` answers "does the
//! linked contract code still behave?" (envelope round trip, redaction canaries,
//! read-only guard, write ladder, operator schemas, store round trip, export
//! plan hardening). Both run offline and never read a secret value.

use std::fs;
use std::path::Path;

use franken_snowflake_cache::{AuditEventRecord, CacheBackend, DATA_DIR_ENV, FileCache};
use franken_snowflake_catalog::operator::{
    built_in_operator_catalog, describe_operator_json_schema,
};
use franken_snowflake_core::redact::{REDACTION_PLACEHOLDER, redact};
use franken_snowflake_core::write_intent::{
    WriteIntentDecision, WriteIntentMode, WriteIntentPolicy, WriteIntentRefusalCode,
    WriteIntentRequest, WriteStatementKind, evaluate_write_intent,
};
use franken_snowflake_export::{CopyIntoOptions, CopyIntoPlan, CopySource, ExportFormat};

use crate::local_store;
use crate::{
    Json, check_json, check_json_owned, has_multiple_statements, is_select_like, json_object,
    json_string, readiness_status, string_array,
};

/// `doctor --json` payload: environment and binary readiness.
pub fn doctor_data() -> Json {
    let mut checks = vec![
        check_json_owned(
            "binary",
            "pass",
            format!(
                "franken-snowflake {} on {}/{}; features: live={} mcp={} toon={} tui={} frankenpandas={} frankensearch={}",
                env!("CARGO_PKG_VERSION"),
                std::env::consts::OS,
                std::env::consts::ARCH,
                crate::live_transport_available(),
                crate::mcp_surface_available(),
                crate::toon_output_available(),
                cfg!(feature = "tui"),
                cfg!(feature = "frankenpandas"),
                cfg!(feature = "frankensearch"),
            ),
        ),
        contract_check(),
        data_dir_check(),
        local_store_check(),
        default_profile_check(),
        check_json_owned(
            "operator_catalog",
            "pass",
            format!(
                "{} predicate operators loaded from the catalog crate",
                built_in_operator_catalog().len()
            ),
        ),
        if crate::live_transport_available() {
            check_json(
                "live_transport",
                "pass",
                "SQL API transport compiled in (--features live); credentials are checked per profile at run time",
            )
        } else {
            check_json(
                "live_transport",
                "not_checked",
                "not compiled into this binary; rebuild with --features live for query run / catalog scan / query write",
            )
        },
        if crate::mcp_surface_available() {
            check_json(
                "mcp_surface",
                "pass",
                "mcp serve compiled in (--features mcp)",
            )
        } else {
            check_json(
                "mcp_surface",
                "not_checked",
                "not compiled into this binary; rebuild with --features mcp for mcp serve",
            )
        },
        if cfg!(feature = "frankenpandas") {
            check_json(
                "frame_materialization",
                "pass",
                "FrankenPandas columnar frame materialization compiled in (--features frankenpandas)",
            )
        } else {
            check_json(
                "frame_materialization",
                "not_checked",
                "not compiled into this binary; rebuild with --features frankenpandas for columnar frame materialization",
            )
        },
        if cfg!(feature = "frankensearch") {
            check_json(
                "text_indexing",
                "pass",
                "Frankensearch hash+lexical text indexing compiled in (--features frankensearch)",
            )
        } else {
            check_json(
                "text_indexing",
                "not_checked",
                "not compiled into this binary; rebuild with --features frankensearch for text indexing",
            )
        },
        live_proof_check(),
    ];
    let status = readiness_status(&checks);
    checks.shrink_to_fit();
    json_object(vec![
        ("status", json_string(status)),
        ("checks", Json::Array(checks)),
    ])
}

fn contract_check() -> Json {
    let rendered = crate::execute_cli_contract(vec!["capabilities".to_string()]).stdout;
    match serde_json::from_str::<serde_json::Value>(&rendered) {
        Ok(value) if value.get("command_id").and_then(|v| v.as_str()) == Some("capabilities") => {
            check_json_owned(
                "cli_contract",
                "pass",
                format!(
                    "{} commands registered; envelope renders and parses as JSON",
                    crate::COMMAND_SPECS.len()
                ),
            )
        }
        Ok(_) => check_json("cli_contract", "fail", "capabilities envelope is malformed"),
        Err(error) => check_json_owned(
            "cli_contract",
            "fail",
            format!("capabilities envelope is not valid JSON: {error}"),
        ),
    }
}

fn data_dir_check() -> Json {
    let Some(dir) = local_store::data_dir() else {
        return check_json_owned(
            "data_dir",
            "warn",
            format!("no data directory could be resolved; set {DATA_DIR_ENV}=<writable-dir>"),
        );
    };
    match probe_writable(&dir) {
        Ok(()) => check_json_owned("data_dir", "pass", format!("{} is writable", dir.display())),
        Err(error) => check_json_owned(
            "data_dir",
            "fail",
            format!("{} is not writable: {error}", dir.display()),
        ),
    }
}

fn probe_writable(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    // Unique per call: two concurrent doctor invocations in one process (the
    // MCP server, or tests) must not race on the same probe file.
    static PROBE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let probe = dir.join(format!(
        ".fsnow-doctor-probe-{}-{}-{}",
        std::process::id(),
        local_store::now_unix_ms(),
        PROBE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    fs::write(&probe, b"probe").map_err(|error| error.to_string())?;
    fs::remove_file(&probe).map_err(|error| error.to_string())
}

fn local_store_check() -> Json {
    match local_store::open_store() {
        Ok(store) => {
            let manifests = store.cache.dataset_ids().map(|ids| ids.len()).unwrap_or(0);
            let audit = store
                .cache
                .audit_events()
                .map(|events| events.len())
                .unwrap_or(0);
            let skipped = store.skipped_lines();
            check_json_owned(
                "local_store",
                if skipped == 0 { "pass" } else { "warn" },
                format!(
                    "opened {} ({} store, schema v{}); {manifests} dataset manifests, {audit} audit events, {skipped} unreadable log lines",
                    store.dir.display(),
                    store.backend.as_str(),
                    store.cache.schema_version().0
                ),
            )
        }
        Err(error) => check_json_owned("local_store", "fail", error.message()),
    }
}

fn default_profile_check() -> Json {
    let Some(profile) = crate::default_profile_env() else {
        return check_json(
            "default_profile",
            "not_checked",
            "FRANKEN_SNOWFLAKE_DEFAULT_PROFILE is unset (optional; pass --profile explicitly)",
        );
    };
    if !crate::is_valid_profile_id(&profile) {
        return check_json_owned(
            "default_profile",
            "fail",
            format!("FRANKEN_SNOWFLAKE_DEFAULT_PROFILE=`{profile}` is not a valid profile id"),
        );
    }
    let presence = profile_handle_presence(&profile);
    let missing: Vec<String> = presence
        .required_missing
        .iter()
        .map(ToString::to_string)
        .collect();
    if missing.is_empty() {
        check_json_owned(
            "default_profile",
            "pass",
            format!(
                "profile `{profile}` has every required handle set (auth lane: {})",
                presence.auth_lane.as_deref().unwrap_or("unknown")
            ),
        )
    } else {
        check_json_owned(
            "default_profile",
            "warn",
            format!(
                "profile `{profile}` is missing env handles (names only): {}",
                missing.join(", ")
            ),
        )
    }
}

/// Environment variable pointing to a `live_proof_state.json` file to enforce
/// the 14-day freshness and binary `git_sha` gate in `doctor --json`.
pub const LIVE_PROOF_STATE_ENV: &str = "FRANKEN_SNOWFLAKE_LIVE_PROOF_STATE";

/// Maximum age in days for a credentialed live proof before `doctor --json`
/// warns when the live proof state gate is active.
pub const LIVE_PROOF_MAX_AGE_DAYS: i64 = 14;

const COMPILED_LIVE_PROOF_STATE: &str = include_str!("../../../docs/live_proof_state.json");

fn live_proof_check() -> Json {
    let today_days = local_store::now_unix_seconds().div_euclid(86_400);
    if let Some(explicit_path) = std::env::var(LIVE_PROOF_STATE_ENV)
        .ok()
        .map(|val| val.trim().to_owned())
        .filter(|val| !val.is_empty())
    {
        return match fs::read_to_string(&explicit_path) {
            Ok(raw) => evaluate_live_proof_state(&raw, today_days, crate::BUILD_GIT_SHA, true),
            Err(error) => check_json_owned(
                "live_proof",
                "fail",
                format!("{LIVE_PROOF_STATE_ENV}=`{explicit_path}` could not be read: {error}"),
            ),
        };
    }
    if let Some(dir) = local_store::data_dir() {
        let local_state = dir.join("live_proof_state.json");
        if local_state.exists() {
            return match fs::read_to_string(&local_state) {
                Ok(raw) => evaluate_live_proof_state(&raw, today_days, crate::BUILD_GIT_SHA, true),
                Err(error) => check_json_owned(
                    "live_proof",
                    "fail",
                    format!("{} could not be read: {error}", local_state.display()),
                ),
            };
        }
    }
    evaluate_live_proof_state(
        COMPILED_LIVE_PROOF_STATE,
        today_days,
        crate::BUILD_GIT_SHA,
        false,
    )
}

/// Evaluate a `franken_snowflake.live_proof_state.v1` JSON payload against
/// `today_epoch_days` and `binary_git_sha`. When `enforce_gate` is true,
/// staleness (`> 14` days) or a binary `git_sha` mismatch yields `"warn"`;
/// when false (default offline environment without an explicit state override),
/// an unverified/older baseline reports `"not_checked"` with the committed run
/// metadata so offline `doctor --json` remains a clean local health gate.
pub fn evaluate_live_proof_state(
    raw_json: &str,
    today_epoch_days: i64,
    binary_git_sha: &str,
    enforce_gate: bool,
) -> Json {
    let parsed: serde_json::Value = match serde_json::from_str(raw_json) {
        Ok(val) => val,
        Err(error) => {
            return check_json_owned(
                "live_proof",
                "fail",
                format!("live_proof_state JSON is malformed: {error}"),
            );
        }
    };
    let last_pass_date = parsed
        .get("last_pass_date")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim();
    let last_pass_sha = parsed
        .get("last_pass_sha")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .trim();
    let max_age_days = parsed
        .get("max_age_days")
        .and_then(serde_json::Value::as_i64)
        .filter(|&days| days > 0)
        .unwrap_or(LIVE_PROOF_MAX_AGE_DAYS);
    let step_count = parsed
        .get("steps")
        .and_then(serde_json::Value::as_object)
        .map_or(0, serde_json::Map::len);
    let Some(pass_days) = parse_ymd_epoch_days(last_pass_date) else {
        return check_json_owned(
            "live_proof",
            "fail",
            format!("live_proof_state has invalid or missing last_pass_date `{last_pass_date}`"),
        );
    };
    let age_days = today_epoch_days.saturating_sub(pass_days);
    let stale_age = age_days > max_age_days || age_days < 0;
    let sha_mismatch = !binary_git_sha.is_empty()
        && binary_git_sha != "unknown"
        && !last_pass_sha.is_empty()
        && last_pass_sha != "unknown"
        && !binary_git_sha.starts_with(last_pass_sha)
        && !last_pass_sha.starts_with(binary_git_sha);

    if !stale_age && !sha_mismatch {
        return check_json_owned(
            "live_proof",
            "pass",
            format!(
                "live proof passed on {last_pass_date} ({age_days}d ago <= {max_age_days}d window; sha={last_pass_sha}; {step_count} steps recorded)"
            ),
        );
    }

    let mut reasons = Vec::new();
    if stale_age {
        reasons.push(format!(
            "age {age_days}d exceeds {max_age_days}d freshness window (last_pass_date={last_pass_date})"
        ));
    }
    if sha_mismatch {
        reasons.push(format!(
            "recorded sha `{last_pass_sha}` differs from running binary sha `{binary_git_sha}`"
        ));
    }
    let reason_str = reasons.join("; ");
    if enforce_gate {
        check_json_owned(
            "live_proof",
            "warn",
            format!(
                "live proof state requires refresh ({reason_str}; {step_count} steps recorded)"
            ),
        )
    } else {
        check_json_owned(
            "live_proof",
            "not_checked",
            format!(
                "committed live proof baseline from {last_pass_date} (sha={last_pass_sha}, {step_count} steps; {reason_str}); set {LIVE_PROOF_STATE_ENV}=docs/live_proof_state.json to enforce the freshness gate"
            ),
        )
    }
}

fn parse_ymd_epoch_days(ymd: &str) -> Option<i64> {
    let mut parts = ymd.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let day: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `selftest --json` payload: executed contract fixtures.
pub fn selftest_data() -> Json {
    let fixtures = vec![
        envelope_round_trip_fixture(),
        redaction_fixture(),
        read_only_guard_fixture(),
        write_ladder_fixture(),
        operator_schema_fixture(),
        local_store_fixture(),
        export_plan_fixture(),
        frame_codec_mapping_fixture(),
        text_indexing_provenance_fixture(),
    ];
    json_object(vec![
        ("status", json_string(readiness_status(&fixtures))),
        ("offline", Json::Bool(true)),
        ("fixtures", Json::Array(fixtures)),
    ])
}

fn envelope_round_trip_fixture() -> Json {
    let rendered = crate::execute_cli_contract(vec!["capabilities".to_string()]).stdout;
    let parsed = match serde_json::from_str::<serde_json::Value>(&rendered) {
        Ok(value) => value,
        Err(error) => {
            return check_json_owned(
                "json_envelope_round_trip",
                "fail",
                format!("envelope is not valid JSON: {error}"),
            );
        }
    };
    let required = [
        "ok",
        "outcome_kind",
        "command_id",
        "output_contract_id",
        "schema_version",
        "data_source",
        "profile_id",
        "request_id",
        "query_id",
        "statement_handle",
        "receipt_hash",
        "started_at",
        "finished_at",
        "duration_ms",
        "warnings",
        "safe_next_commands",
        "repair_commands",
        "did_you_mean",
        "budget_consumed",
        "redactions_applied",
        "data",
        "error",
    ];
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|key| parsed.get(key).is_none())
        .collect();
    if missing.is_empty() {
        check_json_owned(
            "json_envelope_round_trip",
            "pass",
            format!(
                "all {} envelope keys present after render+parse",
                required.len()
            ),
        )
    } else {
        check_json_owned(
            "json_envelope_round_trip",
            "fail",
            format!("missing envelope keys: {}", missing.join(", ")),
        )
    }
}

fn redaction_fixture() -> Json {
    let canaries = [
        "sfpat_selftestCanary0123456789",
        "eyJhbGciOiJSUzI1NiJ9.selftest.canary",
        "AKIASELFTESTCANARY01",
        "ghp_selftestCanaryToken0123456789",
        "-----BEGIN PRIVATE KEY-----\nselftest\n-----END PRIVATE KEY-----",
    ];
    let mut leaked = Vec::new();
    for canary in canaries {
        let text = format!("token={canary} trailing");
        let redacted = redact(&text);
        if redacted.contains(canary) || !redacted.contains(REDACTION_PLACEHOLDER) {
            leaked.push(
                canary
                    .split(['\n', '.'])
                    .next()
                    .unwrap_or(canary)
                    .to_string(),
            );
        }
    }
    if leaked.is_empty() {
        check_json_owned(
            "secret_redaction",
            "pass",
            format!("{} planted secret shapes redacted", canaries.len()),
        )
    } else {
        check_json_owned(
            "secret_redaction",
            "fail",
            format!("redactor leaked canary shapes: {}", leaked.join(", ")),
        )
    }
}

fn read_only_guard_fixture() -> Json {
    let cases: [(&str, bool); 11] = [
        ("select 1", true),
        ("WITH x AS (SELECT 1) SELECT * FROM x", true),
        ("SELECT /* delete from t */ 1", true),
        ("-- delete from t\nselect 1", true),
        ("select $$ a;b $$, a$b, $1 from @s", true),
        ("delete from t", false),
        ("with x as (select 1) delete from t", false),
        // If Snowflake nests block comments, the outer comment swallows the
        // inner one and what remains is the mutation; nesting is undocumented,
        // so any nested comment is refused.
        ("/* /* nested */ select 1 */ delete from t", false),
        ("select 1; select 2", false),
        // An apostrophe inside a `$$` string must not hide the separator.
        ("select $$ it's $$; delete from t", false),
        ("select system$cancel_all_queries(1)", false),
    ];
    let mut wrong = Vec::new();
    for (sql, expected_read) in cases {
        let is_read = is_select_like(sql) && !has_multiple_statements(sql);
        if is_read != expected_read {
            wrong.push(sql.to_string());
        }
    }
    if wrong.is_empty() {
        check_json_owned(
            "read_only_guard",
            "pass",
            format!("{} SQL safety cases classified as expected", cases.len()),
        )
    } else {
        check_json_owned(
            "read_only_guard",
            "fail",
            format!("misclassified: {}", wrong.join(" | ")),
        )
    }
}

fn write_ladder_fixture() -> Json {
    let disabled = WriteIntentPolicy::default();
    let mut request = WriteIntentRequest::new(
        WriteIntentMode::PrepareExecution,
        "insert into t values (1)",
    );
    request.dry_run = true;
    let refused = matches!(
        evaluate_write_intent(&request, &disabled),
        WriteIntentDecision::Refused { refusal } if refusal.code == WriteIntentRefusalCode::MutationsDisabled
    );
    let enabled = crate::write_policy_from_flags(true, false, true, WriteStatementKind::Insert);
    let mut dry = WriteIntentRequest::new(WriteIntentMode::PlanDryRun, "insert into t values (1)");
    dry.dry_run = true;
    dry.allowlist_id = Some(crate::cli_allowlist_id(WriteStatementKind::Insert));
    dry.request_id = Some(franken_snowflake_core::ids::RequestId::new("selftest-req"));
    let planned = matches!(
        evaluate_write_intent(&dry, &enabled),
        WriteIntentDecision::DryRunPlanned { plan } if !plan.required_confirmation_token.as_str().is_empty()
    );
    if refused && planned {
        check_json(
            "write_intent_ladder",
            "pass",
            "disabled policy refuses; enabled dry-run plans a confirmation token",
        )
    } else {
        check_json_owned(
            "write_intent_ladder",
            "fail",
            format!("refused_when_disabled={refused} dry_run_planned={planned}"),
        )
    }
}

fn operator_schema_fixture() -> Json {
    let catalog = built_in_operator_catalog();
    let bad: Vec<String> = catalog
        .iter()
        .filter(|entry| {
            let schema = describe_operator_json_schema(entry);
            schema.get("$schema").is_none() || schema.get("properties").is_none()
        })
        .map(|entry| entry.id.clone())
        .collect();
    if bad.is_empty() {
        check_json_owned(
            "operator_json_schemas",
            "pass",
            format!("{} operators project to JSON Schema 2020-12", catalog.len()),
        )
    } else {
        check_json_owned(
            "operator_json_schemas",
            "fail",
            format!("operators without a valid schema: {}", bad.join(", ")),
        )
    }
}

fn local_store_fixture() -> Json {
    let dir = std::env::temp_dir().join(format!(
        "fsnow-selftest-{}-{}",
        std::process::id(),
        local_store::now_unix_ms()
    ));
    let result = (|| -> Result<(), String> {
        let cache = FileCache::open(&dir).map_err(|error| error.to_string())?;
        cache
            .append_audit_event(AuditEventRecord {
                event_id: "selftest-event".to_owned(),
                receipt_id: None,
                command_id: "selftest".to_owned(),
                trace_id: "selftest".to_owned(),
                event_kind: "selftest".to_owned(),
                event_json: "{}".to_owned(),
                created_at_ms: 1,
            })
            .map_err(|error| error.to_string())?;
        drop(cache);
        let reopened = FileCache::open(&dir).map_err(|error| error.to_string())?;
        let events = reopened.audit_events().map_err(|error| error.to_string())?;
        if events.len() == 1 && events[0].event_id == "selftest-event" {
            Ok(())
        } else {
            Err(format!("expected 1 replayed event, found {}", events.len()))
        }
    })();
    let _ = fs::remove_dir_all(&dir);
    match result {
        Ok(()) => check_json(
            "local_store_round_trip",
            "pass",
            "append-only file store persists and replays an audit event across reopen",
        ),
        Err(error) => check_json_owned("local_store_round_trip", "fail", error),
    }
}

fn export_plan_fixture() -> Json {
    let good = CopyIntoPlan::new(
        "@selftest_stage/run",
        CopySource::Query {
            sql: "select 1".to_owned(),
        },
    )
    .to_sql()
    .is_ok();
    let parquet = CopyIntoPlan::new(
        "@selftest_stage/run",
        CopySource::Query {
            sql: "select 1".to_owned(),
        },
    )
    .with_options(CopyIntoOptions {
        format: ExportFormat::Parquet,
        ..Default::default()
    })
    .to_sql()
    .is_ok();
    let injected = CopyIntoPlan::new(
        "@selftest_stage/run; drop table t --",
        CopySource::Query {
            sql: "select 1".to_owned(),
        },
    )
    .to_sql()
    .is_err();
    let multi = CopyIntoPlan::new(
        "@selftest_stage/run",
        CopySource::Query {
            sql: "select 1; drop table t".to_owned(),
        },
    )
    .to_sql()
    .is_err();
    if good && parquet && injected && multi {
        check_json(
            "export_plan_hardening",
            "pass",
            "COPY INTO plan renders (CSV & Parquet); injected location and multi-statement source are refused",
        )
    } else {
        check_json_owned(
            "export_plan_hardening",
            "fail",
            format!(
                "renders_csv={good} renders_parquet={parquet} location_injection_refused={injected} multi_statement_refused={multi}"
            ),
        )
    }
}

fn frame_codec_mapping_fixture() -> Json {
    #[cfg(feature = "frankenpandas")]
    {
        use franken_snowflake_frame::FrameStorageKind;
        frame_codec_check(&[
            ("ID", FrameStorageKind::Int64),
            ("AMOUNT", FrameStorageKind::DecimalString),
            ("FLAG", FrameStorageKind::Bool),
            ("VAL", FrameStorageKind::Float64),
            ("NOTE", FrameStorageKind::Utf8),
        ])
    }
    #[cfg(not(feature = "frankenpandas"))]
    {
        // Nothing to execute: the frame codec is not linked into this binary.
        // Reporting `pass` here (as before 2026-09-24) certified code that
        // was never run.
        check_json(
            "frame_codec_mapping",
            "skipped",
            "frame codec not compiled into this binary (build with --features frankenpandas to run this check)",
        )
    }
}

/// Decode a fixed five-column row through the frame codec and compare each
/// column's storage kind with `expected` (a test feeds a wrong expectation to
/// prove the check can fail).
#[cfg(feature = "frankenpandas")]
fn frame_codec_check(expected: &[(&str, franken_snowflake_frame::FrameStorageKind)]) -> Json {
    use franken_snowflake_frame::{ResultPartition, SnowflakeColumn, materialize_partitions};
    {
        let columns = vec![
            SnowflakeColumn::new("ID", "FIXED")
                .with_scale(0)
                .with_precision(18),
            SnowflakeColumn::new("AMOUNT", "FIXED")
                .with_scale(2)
                .with_precision(10),
            SnowflakeColumn::new("FLAG", "BOOLEAN"),
            SnowflakeColumn::new("VAL", "REAL"),
            SnowflakeColumn::new("NOTE", "TEXT"),
        ];
        let partitions = vec![ResultPartition::new(
            0,
            vec![vec![
                Some("42".to_string()),
                Some("12.34".to_string()),
                Some("true".to_string()),
                Some("3.14".to_string()),
                Some("test".to_string()),
            ]],
        )];
        match materialize_partitions(&columns, partitions) {
            Ok(frame) => {
                let kind = |name: &str| frame.column(name).map(|c| c.metadata.storage_kind);
                let wrong: Vec<String> = expected
                    .iter()
                    .filter(|(name, want)| kind(name) != Some(*want))
                    .map(|(name, want)| format!("{name}: expected {want:?}, got {:?}", kind(name)))
                    .collect();
                if wrong.is_empty() && frame.row_count == 1 {
                    check_json_owned(
                        "frame_codec_mapping",
                        "pass",
                        format!(
                            "decoded {} typed columns (FIXED/FIXED(10,2)/BOOLEAN/REAL/TEXT) through the frame codec with the expected storage kinds",
                            frame.columns.len()
                        ),
                    )
                } else {
                    check_json_owned(
                        "frame_codec_mapping",
                        "fail",
                        format!("rows={} mismatches: {}", frame.row_count, wrong.join("; ")),
                    )
                }
            }
            Err(e) => check_json_owned(
                "frame_codec_mapping",
                "fail",
                format!("frame materialization error: {e}"),
            ),
        }
    }
}

fn text_indexing_provenance_fixture() -> Json {
    #[cfg(feature = "frankensearch")]
    {
        text_provenance_check("receipt-123")
    }
    #[cfg(not(feature = "frankensearch"))]
    {
        // Nothing to execute: text indexing is not linked into this binary.
        // (Before 2026-09-24 this branch formatted a string and then "verified"
        // its own prefix, reporting `pass`.)
        check_json(
            "text_indexing_provenance",
            "skipped",
            "text indexing not compiled into this binary (build with --features frankensearch to run this check)",
        )
    }
}

/// Derive a document handle and chunk for a query-result source with this
/// receipt hash and verify provenance (a test feeds an empty hash to prove the
/// check can fail).
#[cfg(feature = "frankensearch")]
fn text_provenance_check(receipt_hash: &str) -> Json {
    {
        use franken_snowflake_core::guardrails::RightsClass;
        use franken_snowflake_core::ids::ReceiptHash;
        use franken_snowflake_text_indexing::{
            TEXT_INDEX_SCHEMA_VERSION, TextChunk, TextDocumentHandle, TextSourceRef,
        };
        let source = TextSourceRef::QueryResult {
            receipt_hash: ReceiptHash::new(receipt_hash),
            statement_handle: None,
            query_id: None,
            dataset_id: None,
            object_ref_redacted: Some("TABLE_A".to_string()),
        };
        let valid = source.validate().is_ok();
        let handle = TextDocumentHandle::from_source(&source, "body", 0);
        let chunk = TextChunk::new(
            source,
            "body",
            0,
            "sample extracted text",
            RightsClass::Internal,
        );
        let handle_str = handle.as_str();
        let expected_prefix = format!("fsnow-text:v{TEXT_INDEX_SCHEMA_VERSION}:query:");
        if valid
            && handle_str.starts_with(&expected_prefix)
            && chunk.text == "sample extracted text"
        {
            check_json_owned(
                "text_indexing_provenance",
                "pass",
                format!("derived stable handle `{handle_str}` and verified provenance validation"),
            )
        } else {
            check_json(
                "text_indexing_provenance",
                "fail",
                "text indexing provenance verification failed",
            )
        }
    }
}

/// Env-handle presence (names only, never values) for a profile.
pub struct HandlePresence {
    pub auth_lane: Option<String>,
    pub required_missing: Vec<String>,
    pub handles: Vec<Json>,
    /// Why `<PREFIX>_ACCOUNT` does not form a usable SQL API endpoint, if set
    /// and unusable (the live path would refuse it with FSNOW-2002).
    pub account_error: Option<&'static str>,
}

/// Inspect which env handles a profile has set. Reads only the `_AUTH` lane
/// value (a lane name, not a secret); every other handle is reported by name
/// and presence.
pub fn profile_handle_presence(profile: &str) -> HandlePresence {
    let prefix = crate::profile_env_prefix(profile);
    let present = |key: &str| {
        std::env::var(format!("{prefix}_{key}"))
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
    };
    let auth_lane = std::env::var(format!("{prefix}_AUTH"))
        .ok()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty());
    let secret_key = match auth_lane.as_deref() {
        Some("pat" | "programmatic_access_token") => Some("PAT"),
        Some("oauth" | "oauth_bearer" | "oauth_bearer_token") => Some("OAUTH_BEARER"),
        Some("key_pair_jwt" | "jwt") => Some("PRIVATE_KEY_PEM"),
        Some("workload_identity" | "workload_identity_federation" | "oidc") => {
            if present("OIDC_TOKEN_FILE") {
                Some("OIDC_TOKEN_FILE")
            } else {
                Some("OIDC_TOKEN")
            }
        }
        _ => None,
    };
    let mut handles = Vec::new();
    let mut required_missing = Vec::new();
    let mut push = |key: &str, required: bool, secret: bool| {
        let is_present = present(key);
        if required && !is_present {
            required_missing.push(format!("{prefix}_{key}"));
        }
        handles.push(json_object(vec![
            ("name", json_string(format!("{prefix}_{key}"))),
            ("required", Json::Bool(required)),
            ("secret", Json::Bool(secret)),
            ("present", Json::Bool(is_present)),
        ]));
    };
    for key in ["ACCOUNT", "USER", "AUTH", "WAREHOUSE"] {
        push(key, true, false);
    }
    for key in [
        "DATABASE",
        "SCHEMA",
        "ROLE",
        "MAX_POLLS",
        "STATEMENT_TIMEOUT_SECONDS",
        "PARTITION_CONCURRENCY",
        "QUERY_TAG",
        "CA_BUNDLE",
    ] {
        push(key, false, false);
    }
    for key in [
        "WRITE_ENABLED",
        "WRITE_ALLOW_DDL",
        "WRITE_REQUIRE_CONFIRM",
        "READ_ONLY_EXPECTED",
    ] {
        push(key, false, false);
    }
    match secret_key {
        Some(key) => {
            push(key, true, true);
            if key == "PRIVATE_KEY_PEM" {
                push("PRIVATE_KEY_PASSPHRASE", false, true);
                push("JWT_VALIDITY_SECONDS", false, false);
            } else if key == "OIDC_TOKEN" || key == "OIDC_TOKEN_FILE" {
                if key == "OIDC_TOKEN" {
                    push("OIDC_TOKEN_FILE", false, true);
                } else {
                    push("OIDC_TOKEN", false, true);
                }
                push("OIDC_TOKEN_URL", false, false);
                push("OIDC_SCOPE", false, false);
                push("OIDC_CLIENT_ID", false, false);
                push("OIDC_REFRESH_BEFORE_EXPIRY_SECONDS", false, false);
            }
        }
        None => {
            for key in [
                "PAT",
                "OAUTH_BEARER",
                "PRIVATE_KEY_PEM",
                "OIDC_TOKEN",
                "OIDC_TOKEN_FILE",
            ] {
                push(key, false, true);
            }
        }
    }
    // The account identifier is not a secret; validate the endpoint it forms
    // with the same rule the live transport applies (no socket).
    let account_error = std::env::var(format!("{prefix}_ACCOUNT"))
        .ok()
        .filter(|value| !value.trim().is_empty())
        .and_then(|account| franken_snowflake_core::endpoint::validate_account(&account).err());
    HandlePresence {
        auth_lane,
        required_missing,
        handles,
        account_error,
    }
}

/// Lane names the `_AUTH` handle accepts, for diagnostics.
pub fn supported_auth_lanes() -> Json {
    // workload_identity is implemented but quarantined (not Snowflake's
    // documented SQL API protocol); it is refused on the live path.
    string_array(vec![
        "pat".to_string(),
        "key_pair_jwt".to_string(),
        "oauth_bearer".to_string(),
    ])
}

#[cfg(test)]
mod tests {
    /// Reality-check bead C4: the frame fixture can fail. A wrong expected
    /// storage kind (scaled NUMBER as a float) must report `fail`.
    #[cfg(feature = "frankenpandas")]
    #[test]
    fn frame_codec_check_fails_on_a_wrong_expectation() {
        use franken_snowflake_frame::FrameStorageKind;
        let wrong = crate::render_json(&super::frame_codec_check(&[(
            "AMOUNT",
            FrameStorageKind::Float64,
        )]));
        assert!(wrong.contains("\"status\":\"fail\""), "{wrong}");
        assert!(wrong.contains("AMOUNT"), "{wrong}");
        let right = crate::render_json(&super::frame_codec_check(&[(
            "AMOUNT",
            FrameStorageKind::DecimalString,
        )]));
        assert!(right.contains("\"status\":\"pass\""), "{right}");
    }

    /// Reality-check bead C4: the text-indexing fixture can fail. A source
    /// without a receipt hash has no provenance and must report `fail`.
    #[cfg(feature = "frankensearch")]
    #[test]
    fn text_provenance_check_fails_without_a_receipt_hash() {
        let missing = crate::render_json(&super::text_provenance_check(""));
        assert!(missing.contains("\"status\":\"fail\""), "{missing}");
        let present = crate::render_json(&super::text_provenance_check("receipt-123"));
        assert!(present.contains("\"status\":\"pass\""), "{present}");
    }

    /// Bead oj0.24: `evaluate_live_proof_state` passes on a fresh state with
    /// matching sha, warns when older than 14 days (negative case) or when the
    /// sha differs from the running binary, and fails on malformed JSON.
    #[test]
    fn live_proof_state_check_warns_on_stale_date_or_sha_mismatch() {
        let Some(today) = super::parse_ymd_epoch_days("2026-10-14") else {
            return;
        };
        let fresh_state = r#"{"schema":"franken_snowflake.live_proof_state.v1","last_pass_date":"2026-10-10","last_pass_sha":"bcc10fe","max_age_days":14,"steps":{"query_run_small":{"date":"2026-10-10","sha":"bcc10fe","status":"pass"}}}"#;
        let pass = crate::render_json(&super::evaluate_live_proof_state(
            fresh_state,
            today,
            "bcc10fe",
            true,
        ));
        assert!(pass.contains("\"status\":\"pass\""), "{pass}");
        assert!(pass.contains("4d ago"), "{pass}");

        let stale_state = r#"{"schema":"franken_snowflake.live_proof_state.v1","last_pass_date":"2026-09-28","last_pass_sha":"bcc10fe","max_age_days":14,"steps":{"query_run_small":{"date":"2026-09-28","sha":"bcc10fe","status":"pass"}}}"#;
        let warn_stale = crate::render_json(&super::evaluate_live_proof_state(
            stale_state,
            today,
            "bcc10fe",
            true,
        ));
        assert!(warn_stale.contains("\"status\":\"warn\""), "{warn_stale}");
        assert!(warn_stale.contains("exceeds 14d"), "{warn_stale}");

        let warn_sha = crate::render_json(&super::evaluate_live_proof_state(
            fresh_state,
            today,
            "deadbeef",
            true,
        ));
        assert!(warn_sha.contains("\"status\":\"warn\""), "{warn_sha}");
        assert!(
            warn_sha.contains("differs from running binary sha"),
            "{warn_sha}"
        );

        let bad_json = crate::render_json(&super::evaluate_live_proof_state(
            "{not json",
            today,
            "bcc10fe",
            true,
        ));
        assert!(bad_json.contains("\"status\":\"fail\""), "{bad_json}");
    }
}
