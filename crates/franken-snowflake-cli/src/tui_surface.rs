//! `fsnow tui --profile <profile>`: the interactive catalog browser and query
//! planner (FrankenTUI) over the local store's latest catalog snapshot for the
//! profile. Compiled only with the `tui` feature; the default build answers a
//! typed refusal from `tui_dispatch`.
//!
//! What runs here is offline by default: browsing the persisted snapshot and
//! planning raw SQL through the shared planner. With the `live` feature the
//! launch injects an executor, so Enter on a planned query runs it through
//! the same live path as `query run` (blocking v1: the result lines land in
//! the log pane when the statement returns). Without `live`, submit logs a
//! typed pointer to `fsnow query run`.

use std::io::IsTerminal;

use franken_snowflake_cache::CacheBackend;
use franken_snowflake_catalog::model::CatalogSnapshot;
use franken_snowflake_core::error::SnowflakeErrorCode;
use franken_snowflake_core::exit::ExitCode as CoreExitCode;
#[cfg(feature = "live")]
use franken_snowflake_tui::ExecutorLine;
#[cfg(not(feature = "live"))]
use franken_snowflake_tui::run_terminal;
use franken_snowflake_tui::{SnowflakeTuiApp, run_terminal_with_executor};

use crate::catalog_surface::{DATA_SOURCE_CACHE, store_error, typed_error};
use crate::local_store;
use crate::{Body, Json, Outcome, OutputFormat, base_envelope, json_object, json_string};

const COMMAND_ID: &str = "tui";
const CONTRACT_ID: &str = "fsnow.tui.launch.v1";

/// Launch the interactive session and, once it ends, report what was browsed.
pub fn launch_outcome(
    format: OutputFormat,
    request_id: String,
    profile: Option<String>,
) -> Outcome {
    let profile = profile.filter(|profile| !profile.is_empty()).or_else(|| {
        std::env::var("FRANKEN_SNOWFLAKE_DEFAULT_PROFILE")
            .ok()
            .filter(|profile| !profile.is_empty())
    });
    let Some(profile) = profile else {
        return typed_error(
            format,
            COMMAND_ID,
            CONTRACT_ID,
            request_id,
            None,
            SnowflakeErrorCode::UsageError,
            "Missing --profile for `tui`. Pass --profile <profile> or set FRANKEN_SNOWFLAKE_DEFAULT_PROFILE."
                .to_owned(),
            Vec::new(),
            vec!["franken-snowflake tui --profile <profile>".to_owned()],
            Vec::new(),
            Vec::new(),
        );
    };
    let store = match local_store::open_store() {
        Ok(store) => store,
        Err(error) => {
            return store_error(
                format,
                COMMAND_ID,
                CONTRACT_ID,
                request_id,
                Some(profile),
                &error,
            );
        }
    };
    let scan_command = format!(
        "franken-snowflake catalog scan {profile} --database <db> --schema <schema> --json"
    );
    let record = match store.cache.latest_catalog_snapshot(&profile, None, None) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return typed_error(
                format,
                COMMAND_ID,
                CONTRACT_ID,
                request_id,
                Some(profile.clone()),
                SnowflakeErrorCode::MetadataError,
                format!(
                    "no catalog snapshot for profile `{profile}` in the local store; run a catalog scan first (needs the live feature and credentials)"
                ),
                vec![json_string("local store")],
                vec![scan_command],
                Vec::new(),
                Vec::new(),
            );
        }
        Err(error) => {
            return typed_error(
                format,
                COMMAND_ID,
                CONTRACT_ID,
                request_id,
                Some(profile),
                SnowflakeErrorCode::MetadataError,
                format!("local store read failed: {error}"),
                vec![json_string("local store")],
                vec!["franken-snowflake doctor --json".to_owned()],
                Vec::new(),
                Vec::new(),
            );
        }
    };
    let snapshot: CatalogSnapshot = match serde_json::from_str(&record.payload.canonical) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return typed_error(
                format,
                COMMAND_ID,
                CONTRACT_ID,
                request_id,
                Some(profile),
                SnowflakeErrorCode::MetadataError,
                format!(
                    "stored snapshot {} is not readable: {error}",
                    record.snapshot_id
                ),
                vec![json_string("local store")],
                vec![scan_command],
                Vec::new(),
                Vec::new(),
            );
        }
    };
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        return typed_error(
            format,
            COMMAND_ID,
            CONTRACT_ID,
            request_id,
            Some(profile.clone()),
            SnowflakeErrorCode::UsageError,
            "`tui` needs an interactive terminal on stdin and stdout; agents and pipelines should use the JSON surfaces instead (catalog graph, dataset inspect, query plan)."
                .to_owned(),
            Vec::new(),
            vec![
                format!("franken-snowflake catalog graph {profile} --database <db> --json"),
                "franken-snowflake dataset inspect <dataset-id> --json".to_owned(),
                "franken-snowflake query plan --profile <profile> --sql <sql> --json".to_owned(),
            ],
            Vec::new(),
            Vec::new(),
        );
    }
    let dataset_count = snapshot.datasets.len();
    let column_count = snapshot.columns.len();
    let app = SnowflakeTuiApp::from_catalog_snapshot(&snapshot);
    let run_result = {
        #[cfg(feature = "live")]
        {
            let executor = build_query_executor(profile.clone());
            run_terminal_with_executor(app, Some(executor))
        }
        #[cfg(not(feature = "live"))]
        {
            run_terminal(app)
        }
    };
    if let Err(error) = run_result {
        return typed_error(
            format,
            COMMAND_ID,
            CONTRACT_ID,
            request_id,
            Some(profile),
            SnowflakeErrorCode::Internal,
            format!("the terminal session failed: {error}"),
            Vec::new(),
            vec!["franken-snowflake doctor --json".to_owned()],
            Vec::new(),
            Vec::new(),
        );
    }
    let mut envelope = base_envelope(
        true,
        "success",
        COMMAND_ID,
        CONTRACT_ID,
        request_id,
        json_object(vec![
            ("profile_id", json_string(profile.clone())),
            ("snapshot_id", json_string(record.snapshot_id.clone())),
            (
                "datasets",
                Json::Number(i64::try_from(dataset_count).unwrap_or(i64::MAX)),
            ),
            (
                "columns",
                Json::Number(i64::try_from(column_count).unwrap_or(i64::MAX)),
            ),
            ("session", json_string("ended")),
        ]),
    );
    envelope.data_source = DATA_SOURCE_CACHE;
    envelope.profile_id = Some(profile);
    envelope.safe_next_commands = vec![
        "franken-snowflake query plan --profile <profile> --sql <sql> --json".to_owned(),
        "franken-snowflake dataset inspect <dataset-id> --json".to_owned(),
    ];
    Outcome {
        status: CoreExitCode::Success,
        body: Body::Envelope { envelope, format },
    }
}

/// Build the host-side executor the TUI calls when the operator submits a
/// planned query: it drives the exact same live outcome path as `query run`
/// and renders compact result lines for the log pane.
#[cfg(feature = "live")]
fn build_query_executor(profile: String) -> franken_snowflake_tui::QueryExecutor {
    Box::new(move |sql: &str| {
        let options = crate::QueryRunOptions::default();
        let outcome = crate::live::run_query_outcome(
            OutputFormat::Json,
            local_store::invocation_id("tui-query-run"),
            profile.clone(),
            sql,
            &options,
        );
        render_outcome_lines(outcome)
    })
}

/// Render a `query run` outcome into TUI log lines: a summary line, the typed
/// error (if any), the statement handle and receipt hash, the row counts, and
/// up to ten result rows.
#[cfg(feature = "live")]
fn render_outcome_lines(outcome: Outcome) -> Vec<ExecutorLine> {
    let status = outcome.status.code();
    let rendered = match &outcome.body {
        Body::Envelope { envelope, .. } => crate::render_json(&crate::envelope_json(envelope)),
        Body::Raw { data } => data.clone(),
    };
    let value: serde_json::Value =
        serde_json::from_str(&rendered).unwrap_or(serde_json::Value::Null);
    let ok = value
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let get_str = |key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let get_u64 = |key: &str| value.get(key).and_then(serde_json::Value::as_u64);

    let mut lines = vec![ExecutorLine {
        outcome: if ok { "ok" } else { "error" }.to_owned(),
        message: format!(
            "query run exit={} data_source={}",
            status,
            get_str("data_source").unwrap_or_else(|| "unspecified".to_owned())
        ),
    }];
    if !ok {
        lines.push(ExecutorLine {
            outcome: "error".to_owned(),
            message: format!(
                "{}: {}",
                get_str("code").unwrap_or_else(|| "unknown".to_owned()),
                get_str("message").unwrap_or_else(|| "no detail".to_owned())
            ),
        });
        return lines;
    }
    if let Some(handle) = get_str("statement_handle") {
        lines.push(ExecutorLine {
            outcome: "ok".to_owned(),
            message: format!("statement handle {handle}"),
        });
    }
    if let Some(receipt) = get_str("receipt_hash") {
        lines.push(ExecutorLine {
            outcome: "ok".to_owned(),
            message: format!("receipt {receipt} (fsnow receipt show {receipt})"),
        });
    }
    lines.push(ExecutorLine {
        outcome: "ok".to_owned(),
        message: format!(
            "rows returned={} of {} total{} partitions={}",
            get_u64("returned_rows").map_or("?".to_owned(), |n| n.to_string()),
            get_u64("result_row_count").map_or("?".to_owned(), |n| n.to_string()),
            if value
                .get("truncated")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                " (truncated)"
            } else {
                ""
            },
            get_u64("partition_count").map_or("?".to_owned(), |n| n.to_string()),
        ),
    });
    if let Some(rows) = value.get("rows").and_then(serde_json::Value::as_array) {
        for (index, row) in rows.iter().take(10).enumerate() {
            let cells = row
                .as_array()
                .map(|cells| {
                    cells
                        .iter()
                        .map(serde_json::Value::to_string)
                        .collect::<Vec<_>>()
                        .join(" | ")
                })
                .unwrap_or_default();
            lines.push(ExecutorLine {
                outcome: "ok".to_owned(),
                message: format!("row {:>3} | {cells}", index.saturating_add(1)),
            });
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use franken_snowflake_cache::{CatalogSnapshotRecord, ContentAddress, VerifiedPayload};
    use franken_snowflake_catalog::model::{DataSourceClass, Provenance, ProvenanceSource};

    fn envelope(outcome: Outcome) -> serde_json::Value {
        match outcome.body {
            Body::Envelope { envelope, .. } => {
                serde_json::from_str(&crate::render_json(&crate::envelope_json(&envelope)))
                    .expect("envelope renders as JSON")
            }
            Body::Raw { data } => panic!("expected an envelope, got raw output: {data}"),
        }
    }

    fn seed_empty_snapshot(profile: &str) {
        let provenance = Provenance {
            source: ProvenanceSource::Fixture,
            data_source: DataSourceClass::Fixture,
            snapshot_id: format!("snap-{profile}"),
            discovered_at: "2026-01-01T00:00:00Z".to_owned(),
            profile_fingerprint: format!("profile:{profile}"),
            object_fingerprint: "snowflake-object:DB.PUBLIC".to_owned(),
            command_id: "test".to_owned(),
            trace_id: "test".to_owned(),
            redactions_applied: Vec::new(),
        };
        let snapshot = CatalogSnapshot::empty(provenance);
        let canonical = serde_json::to_string(&snapshot).expect("snapshot serializes");
        let store = local_store::open_store().expect("test store");
        store
            .cache
            .insert_catalog_snapshot(CatalogSnapshotRecord {
                snapshot_id: format!("snap-{profile}"),
                profile_id: profile.to_owned(),
                source_kind: "fixture".to_owned(),
                database_name: Some("DB".to_owned()),
                schema_name: Some("PUBLIC".to_owned()),
                captured_at_ms: 1_700_000_000_000,
                payload: VerifiedPayload {
                    address: ContentAddress::blake3(canonical.as_bytes()),
                    canonical,
                },
            })
            .expect("snapshot stored");
    }

    #[test]
    fn missing_profile_is_a_usage_error() {
        let env = envelope(launch_outcome(
            OutputFormat::Json,
            "req-tui-0".to_owned(),
            None,
        ));
        assert_eq!(env["ok"], false, "{env}");
        assert!(
            env["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("Missing --profile"),
            "{env}"
        );
    }

    #[test]
    fn no_snapshot_is_a_typed_metadata_error_naming_the_scan() {
        let env = envelope(launch_outcome(
            OutputFormat::Json,
            "req-tui-1".to_owned(),
            Some("never-scanned".to_owned()),
        ));
        assert_eq!(env["ok"], false, "{env}");
        assert!(
            env["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("no catalog snapshot"),
            "{env}"
        );
        assert!(
            env.to_string().contains("catalog scan never-scanned"),
            "{env}"
        );
    }

    #[test]
    fn without_a_terminal_the_launch_refuses_before_touching_the_screen() {
        // Under `cargo test` stdin/stdout are pipes, so a seeded snapshot gets
        // as far as the terminal check and no further: no alternate screen,
        // no raw mode, and the process does not hang waiting for keys.
        seed_empty_snapshot("tui-demo");
        let env = envelope(launch_outcome(
            OutputFormat::Json,
            "req-tui-2".to_owned(),
            Some("tui-demo".to_owned()),
        ));
        assert_eq!(env["ok"], false, "{env}");
        assert_eq!(env["profile_id"], "tui-demo", "{env}");
        assert!(
            env["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("interactive terminal"),
            "{env}"
        );
        assert!(env.to_string().contains("catalog graph tui-demo"), "{env}");
    }
}
