//! End-to-end proof that drives the REAL `franken-snowflake` binary through the
//! README command set with a clean environment, a temporary local store, and
//! planted canary secrets. This is the lane that catches envelope drift, exit
//! code drift, silently-dropped flags, and secret leaks that in-process unit
//! tests cannot see.
//!
//! Every assertion is against observable process behavior: exit code, stdout
//! JSON, stderr text, and files in the temp data directory. No live account is
//! contacted: the planted profile points at a loopback URL that the transport
//! refuses as a non-canonical Snowflake host before any socket is opened.

// Integration-test crate: panicking on an unexpected process result IS the
// failure mechanism, so the production panic/expect bans do not apply here.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const BIN: &str = env!("CARGO_BIN_EXE_franken-snowflake");

/// Planted secret values. Every one must be absent from all output.
const CANARY_PAT: &str = "sfpat_e2eCanaryPatValue0123456789";
const CANARY_OAUTH: &str = "eyJhbGciOiJSUzI1NiJ9.e2eCanaryOauth.sig";
const CANARY_PEM: &str = "-----BEGIN PRIVATE KEY-----\ne2eCanaryKeyBody\n-----END PRIVATE KEY-----";

const ENVELOPE_KEYS: [&str; 22] = [
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

struct Run {
    exit: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|error| panic!("stdout is not JSON ({error}): {}", self.stdout))
    }

    fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}

struct Harness {
    data_dir: PathBuf,
}

impl Harness {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        let data_dir =
            std::env::temp_dir().join(format!("fsnow-e2e-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&data_dir).expect("temp data dir");
        Self { data_dir }
    }

    /// Run the binary with a scrubbed environment: only the store override, a
    /// HOME under the temp dir, and the planted profile handles.
    fn run(&self, args: &[&str]) -> Run {
        let output = Command::new(BIN)
            .args(args)
            .env_clear()
            .env("HOME", &self.data_dir)
            .env("FRANKEN_SNOWFLAKE_DATA_DIR", &self.data_dir)
            // Planted profile `e2e`: complete handle set, loopback account so
            // the live build refuses before any network I/O (FSNOW-2002).
            .env("FRANKEN_SNOWFLAKE_E2E_ACCOUNT", "https://127.0.0.1:9")
            .env("FRANKEN_SNOWFLAKE_E2E_USER", "E2E_USER")
            .env("FRANKEN_SNOWFLAKE_E2E_AUTH", "pat")
            .env("FRANKEN_SNOWFLAKE_E2E_WAREHOUSE", "E2E_WH")
            .env("FRANKEN_SNOWFLAKE_E2E_PAT", CANARY_PAT)
            .env("FRANKEN_SNOWFLAKE_E2E_OAUTH_BEARER", CANARY_OAUTH)
            .env("FRANKEN_SNOWFLAKE_E2E_PRIVATE_KEY_PEM", CANARY_PEM)
            .env("FRANKEN_SNOWFLAKE_E2E_WRITE_ENABLED", "true")
            .output()
            .expect("spawn franken-snowflake");
        let run = Run {
            exit: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        };
        for canary in [CANARY_PAT, CANARY_OAUTH, "e2eCanaryKeyBody"] {
            assert!(
                !run.stdout.contains(canary) && !run.stderr.contains(canary),
                "canary secret leaked by {args:?}: stdout={} stderr={}",
                run.stdout,
                run.stderr
            );
        }
        run
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.data_dir);
    }
}

fn assert_envelope(run: &Run, command_id: &str) -> serde_json::Value {
    let value = run.json();
    let object = value.as_object().expect("envelope object");
    let missing: Vec<&str> = ENVELOPE_KEYS
        .iter()
        .copied()
        .filter(|key| !object.contains_key(*key))
        .collect();
    assert!(missing.is_empty(), "missing envelope keys {missing:?}");
    assert_eq!(value["schema_version"], "fsnow.envelope.v1");
    assert_eq!(value["command_id"], command_id, "{}", run.stdout);
    let request_id = value["request_id"].as_str().expect("request_id string");
    assert_eq!(request_id.len(), 36, "request_id must be UUID-shaped");
    let started = value["started_at"].as_str().expect("started_at");
    assert!(
        started.len() == 20 && started.ends_with('Z') && started.starts_with("20"),
        "started_at must be RFC 3339 UTC, got {started}"
    );
    assert!(value["duration_ms"].as_i64().unwrap_or(-1) >= 0);
    if value["ok"] == false {
        assert!(
            value["error"]["code"]
                .as_str()
                .is_some_and(|c| c.starts_with("FSNOW-")),
            "error envelopes carry a stable FSNOW code: {}",
            run.stdout
        );
        assert!(
            run.stderr.contains("FSNOW-"),
            "stderr carries the diagnostic line: {}",
            run.stderr
        );
    } else {
        assert!(
            run.stderr.is_empty(),
            "stdout is data, stderr is diagnostics: {}",
            run.stderr
        );
    }
    value
}

#[test]
fn discovery_commands_run_offline_with_exit_zero() {
    let h = Harness::new("discovery");
    for (args, command_id) in [
        (vec!["onboard", "--json"], "onboard"),
        (vec!["capabilities", "--json"], "capabilities"),
        (vec!["agent-handbook", "--json"], "agent-handbook"),
        (vec!["robot-docs", "guide"], "robot-docs.guide"),
        (vec!["help"], "help"),
        (vec!["doctor", "--json"], "doctor"),
        (vec!["selftest", "--json"], "selftest"),
    ] {
        let run = h.run(&args);
        assert_eq!(run.exit, 0, "{args:?}: {} {}", run.stdout, run.stderr);
        let value = assert_envelope(&run, command_id);
        assert_eq!(value["ok"], true);
    }
    // doctor and selftest execute real checks: nothing may be a literal "not_checked"
    // in selftest, and doctor must report the temp data dir it probed.
    let doctor = h.run(&["doctor", "--json"]).json();
    let checks = doctor["data"]["checks"].as_array().unwrap();
    let data_dir_check = checks
        .iter()
        .find(|c| c["name"] == "data_dir")
        .expect("data_dir check");
    assert_eq!(data_dir_check["status"], "pass");
    assert!(
        data_dir_check["detail"]
            .as_str()
            .unwrap()
            .contains(h.data_dir.to_str().unwrap()),
        "doctor probes the overridden data dir"
    );
    let selftest = h.run(&["selftest", "--json"]).json();
    let fixtures = selftest["data"]["fixtures"].as_array().unwrap();
    assert!(fixtures.len() >= 7);
    assert!(fixtures.iter().all(|f| f["status"] == "pass"), "{selftest}");
}

#[test]
fn capabilities_registry_documents_every_command_with_input_schemas() {
    let h = Harness::new("capabilities");
    let value = h.run(&["capabilities", "--json"]).json();
    let commands = value["data"]["commands"].as_array().unwrap();
    let ids: BTreeSet<&str> = commands
        .iter()
        .map(|c| c["command_id"].as_str().unwrap())
        .collect();
    for expected in [
        "onboard",
        "capabilities",
        "doctor",
        "selftest",
        "profile.validate",
        "profile.doctor",
        "catalog.scan",
        "catalog.graph",
        "dataset.inspect",
        "dataset.profile",
        "dataset.describe_operator",
        "query.plan",
        "query.run",
        "query.write",
        "query.cancel",
        "receipt.show",
        "export.plan",
        "export.run",
        "mcp.serve",
        "tui",
    ] {
        assert!(ids.contains(expected), "missing {expected}");
    }
    for command in commands {
        let schema = &command["input_schema"];
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert!(!schema["properties"].as_object().unwrap().is_empty());
    }
    let flags = &value["data"]["feature_flags"];
    assert_eq!(flags["live"], cfg!(feature = "live"));
    assert_eq!(flags["mcp"], cfg!(feature = "mcp"));
    assert_eq!(flags["tui"], cfg!(feature = "tui"));

    // TOON is an alternate encoding of the same envelope.
    let toon = h.run(&["capabilities", "--toon"]);
    assert_eq!(toon.exit, 0);
    assert!(toon.stdout.starts_with("ok: true"));
}

#[test]
fn profile_validate_reports_handle_presence_by_name_only() {
    let h = Harness::new("profile");
    let complete = h.run(&["profile", "validate", "e2e", "--json"]);
    assert_eq!(complete.exit, 0, "{}", complete.stdout);
    let value = assert_envelope(&complete, "profile.validate");
    assert_eq!(value["data"]["status"], "validated");
    assert_eq!(value["data"]["auth_lane"], "pat");
    let handles = value["data"]["env_handles"].as_array().unwrap();
    let pat = handles
        .iter()
        .find(|h| h["name"] == "FRANKEN_SNOWFLAKE_E2E_PAT")
        .expect("PAT handle listed");
    assert_eq!(pat["present"], true);
    assert_eq!(pat["secret"], true);

    let missing = h.run(&["profile", "validate", "unset-profile", "--json"]);
    assert_eq!(missing.exit, 1);
    let value = assert_envelope(&missing, "profile.validate");
    assert_eq!(value["outcome_kind"], "partial_success");
    let repairs = value["repair_commands"].as_array().unwrap();
    assert!(
        repairs.iter().any(
            |r| r.as_str().unwrap() == "export FRANKEN_SNOWFLAKE_UNSET_PROFILE_ACCOUNT=<value>"
        )
    );

    let doctor = h.run(&["profile", "doctor", "e2e", "--json"]);
    assert_eq!(doctor.exit, 1, "offline doctor is a partial result");
    assert_envelope(&doctor, "profile.doctor");
}

#[test]
fn every_operator_has_a_schema_and_typos_get_suggestions() {
    let h = Harness::new("operators");
    for op in [
        "eq",
        "neq",
        "lt",
        "lte",
        "gt",
        "gte",
        "between",
        "in",
        "is_null",
        "is_not_null",
        "contains",
    ] {
        let run = h.run(&["dataset", "describe-operator", op, "--jsonschema"]);
        assert_eq!(run.exit, 0, "{op}: {}", run.stderr);
        let value = assert_envelope(&run, "dataset.describe_operator");
        assert_eq!(value["data"]["operator"], op);
        assert_eq!(
            value["data"]["json_schema"]["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
    }
    let typo = h.run(&["dataset", "describe-operator", "betwen"]);
    assert_eq!(typo.exit, 64);
    let value = assert_envelope(&typo, "dataset.describe_operator");
    assert_eq!(value["did_you_mean"][0], "between");
}

#[test]
fn query_plan_and_write_ladder_behave_offline() {
    let h = Harness::new("query");
    let plan = h.run(&[
        "query",
        "plan",
        "--profile",
        "e2e",
        "--sql",
        "select 1",
        "--json",
    ]);
    assert_eq!(plan.exit, 0);
    let value = assert_envelope(&plan, "query.plan");
    assert_eq!(value["data"]["statement_kind"], "read");

    let mutation = h.run(&[
        "query",
        "plan",
        "--profile",
        "e2e",
        "--sql",
        "delete from t",
        "--json",
    ]);
    assert_eq!(mutation.exit, 2);
    assert_eq!(mutation.code(), "FSNOW-3001");

    let hidden = h.run(&[
        "query",
        "plan",
        "--profile",
        "e2e",
        "--sql",
        "/* /* nested */ select 1 */ delete from t",
        "--json",
    ]);
    assert_eq!(
        hidden.exit, 2,
        "mutation behind a nested comment must be refused"
    );

    // Dataset-mode flags are refused loudly, never silently dropped.
    let dataset_flag = h.run(&[
        "query",
        "run",
        "--profile",
        "e2e",
        "--sql",
        "select 1",
        "--from",
        "2024-01-01",
        "--json",
    ]);
    assert_eq!(dataset_flag.exit, 64);
    assert!(dataset_flag.stdout.contains("--from"));

    // Write ladder: dry run plans a token bound to (profile, SQL).
    let dry = h.run(&[
        "query",
        "write",
        "--profile",
        "e2e",
        "--sql",
        "insert into t values (1)",
        "--dry-run",
        "--json",
    ]);
    assert_eq!(dry.exit, 0, "{}", dry.stdout);
    let value = assert_envelope(&dry, "query.write");
    let token = value["data"]["required_confirmation_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(token.starts_with("confirm:insert:"));
    assert_eq!(value["data"]["will_submit"], false);

    // Writes are disabled for a profile without WRITE_ENABLED and the refusal
    // lands on the append-only audit ledger in the temp store.
    let refused = h.run(&[
        "query",
        "write",
        "--profile",
        "unset-profile",
        "--sql",
        "insert into t values (1)",
        "--json",
    ]);
    assert_eq!(refused.exit, 2);
    assert_eq!(refused.code(), "FSNOW-3007");
    let ledger =
        fs::read_to_string(h.data_dir.join("query_audit_log.jsonl")).expect("audit ledger");
    assert!(ledger.contains("write_refused"), "{ledger}");
    assert!(!ledger.contains(CANARY_PAT));
}

#[test]
fn live_surfaces_refuse_cleanly_without_transport_or_before_any_socket() {
    let h = Harness::new("live");
    let live = cfg!(feature = "live");
    // (args, command_id, expected exit without live, expected exit with live)
    let cases: Vec<(Vec<&str>, &str, i32, i32)> = vec![
        (
            vec![
                "query",
                "run",
                "--profile",
                "e2e",
                "--sql",
                "select 1",
                "--json",
            ],
            "query.run",
            2,
            3,
        ),
        (
            vec![
                "catalog",
                "scan",
                "e2e",
                "--database",
                "DB",
                "--schema",
                "PUBLIC",
                "--json",
            ],
            "catalog.scan",
            2,
            3,
        ),
        (
            vec!["query", "cancel", "01aa-0000", "--profile", "e2e", "--json"],
            "query.cancel",
            2,
            3,
        ),
        (
            vec![
                "query",
                "write",
                "--profile",
                "e2e",
                "--sql",
                "insert into t values (1)",
                "--json",
            ],
            "query.write",
            2,
            3,
        ),
        (
            vec![
                "export",
                "run",
                "--profile",
                "e2e",
                "--sql",
                "select 1",
                "--out",
                "x.csv",
                "--json",
            ],
            "export.run",
            2,
            3,
        ),
        (
            vec!["profile", "doctor", "e2e", "--online", "--json"],
            "profile.doctor",
            1,
            3,
        ),
    ];
    for (args, command_id, without, with) in cases {
        let run = h.run(&args);
        let expected = if live { with } else { without };
        assert_eq!(
            run.exit, expected,
            "{args:?}: {} {}",
            run.stdout, run.stderr
        );
        let value = assert_envelope(&run, command_id);
        if live && expected == 3 {
            // The loopback account is rejected as a non-canonical Snowflake host
            // before any network I/O; nothing was submitted.
            assert_eq!(value["error"]["code"], "FSNOW-2002", "{}", run.stdout);
        }
        assert_ne!(
            value["data_source"], "live",
            "no live provenance without a live result"
        );
    }
}

#[test]
fn store_backed_lookups_are_typed_misses_on_a_fresh_store() {
    let h = Harness::new("store");
    for (args, command_id) in [
        (
            vec!["dataset", "inspect", "nope_b3_ffff", "--json"],
            "dataset.inspect",
        ),
        (
            vec!["dataset", "profile", "nope_b3_ffff", "--json"],
            "dataset.profile",
        ),
        (vec!["receipt", "show", "0000", "--json"], "receipt.show"),
    ] {
        let run = h.run(&args);
        assert_eq!(run.exit, 7, "{args:?}: {}", run.stdout);
        let value = assert_envelope(&run, command_id);
        assert_eq!(value["error"]["code"], "FSNOW-7002");
    }
    let graph = h.run(&["catalog", "graph", "e2e", "--database", "DB", "--json"]);
    if cfg!(feature = "live") {
        assert_eq!(
            graph.exit, 3,
            "live build falls through to a scan: {}",
            graph.stdout
        );
    } else {
        assert_eq!(graph.exit, 7, "{}", graph.stdout);
        assert!(graph.stdout.contains("catalog scan e2e --database DB"));
    }
}

#[test]
fn export_plan_renders_copy_into_and_hands_off_to_query_write() {
    let h = Harness::new("export");
    let run = h.run(&[
        "export",
        "plan",
        "--profile",
        "e2e",
        "--sql",
        "select * from events",
        "--location",
        "@my_stage/exports/run_001",
        "--format",
        "jsonl",
        "--compression",
        "gzip",
        "--json",
    ]);
    assert_eq!(run.exit, 0, "{}", run.stderr);
    let value = assert_envelope(&run, "export.plan");
    let sql = value["data"]["plan_sql"].as_str().unwrap();
    assert!(sql.starts_with("COPY INTO @my_stage/exports/run_001 FROM (select * from events)"));
    assert!(sql.contains("TYPE = JSON COMPRESSION = GZIP"));
    assert_eq!(value["data"]["plan_hash"].as_str().unwrap().len(), 64);
    assert!(
        value["data"]["execute_with"]["command"]
            .as_str()
            .unwrap()
            .starts_with("franken-snowflake query write --profile e2e --sql")
    );

    let injected = h.run(&[
        "export",
        "plan",
        "--sql",
        "select 1",
        "--location",
        "@stg/x; drop",
        "--json",
    ]);
    assert_eq!(injected.exit, 64);
    assert!(injected.stdout.contains("export plan refused"));

    let missing = h.run(&["export", "plan", "--json"]);
    assert_eq!(missing.exit, 64);
}

#[test]
fn unknown_commands_and_flags_are_usage_errors_with_suggestions() {
    let h = Harness::new("usage");
    let typo = h.run(&["querry", "--sql", "select 1"]);
    assert_eq!(typo.exit, 64);
    let value = assert_envelope(&typo, "help");
    assert_eq!(value["error"]["code"], "FSNOW-1001");
    assert_eq!(value["did_you_mean"][0], "query");

    let flag = h.run(&["capabilities", "--jsno"]);
    assert_eq!(flag.exit, 64);
    assert_eq!(flag.json()["error"]["code"], "FSNOW-1002");

    // Without the feature `tui` is a typed feature refusal; with it, a profile
    // that was never scanned is a typed metadata error that names the scan.
    // Either way the child exits instead of waiting for keys.
    let tui = h.run(&["tui", "--profile", "e2e"]);
    if cfg!(feature = "tui") {
        assert_ne!(tui.exit, 0);
        let value = tui.json();
        assert_eq!(value["ok"], false);
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("no catalog snapshot"),
            "{value}"
        );
        assert!(value.to_string().contains("catalog scan e2e"), "{value}");
    } else {
        assert_eq!(tui.exit, 64);
        assert_eq!(tui.json()["error"]["code"], "FSNOW-1002");
    }

    if !cfg!(feature = "mcp") {
        let mcp = h.run(&["mcp", "serve", "--stdio"]);
        assert_eq!(mcp.exit, 64);
    }
}
