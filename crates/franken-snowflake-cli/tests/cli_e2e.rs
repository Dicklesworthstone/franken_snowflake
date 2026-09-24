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
const FSNOW_BIN: &str = env!("CARGO_BIN_EXE_fsnow");

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
        self.run_with(args, &[])
    }

    /// Like [`Harness::run`], with extra env vars applied last (they override
    /// the planted defaults). Only for offline commands: overriding the account
    /// with a canonical Snowflake host must never reach a live command.
    fn run_with(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Run {
        let mut command = Command::new(BIN);
        command
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
            .env("FRANKEN_SNOWFLAKE_E2E_WRITE_ENABLED", "true");
        for (key, value) in extra_env {
            command.env(key, value);
        }
        let output = command.output().expect("spawn franken-snowflake");
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
    assert!(fixtures.len() >= 9);
    // A fixture whose subject is not compiled in says `skipped` (reality-check
    // bead C4); every other fixture really passes.
    let expected = |name: &str| {
        let uncompiled = (name == "frame_codec_mapping" && !cfg!(feature = "frankenpandas"))
            || (name == "text_indexing_provenance" && !cfg!(feature = "frankensearch"));
        if uncompiled { "skipped" } else { "pass" }
    };
    for fixture in fixtures {
        let name = fixture["name"].as_str().unwrap_or_default();
        assert_eq!(fixture["status"], expected(name), "{name}: {selftest}");
    }
    assert!(fixtures.iter().any(|f| f["name"] == "frame_codec_mapping"));
    assert!(
        fixtures
            .iter()
            .any(|f| f["name"] == "text_indexing_provenance")
    );
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
        "catalog.diff",
        "dataset.inspect",
        "dataset.profile",
        "dataset.describe_operator",
        "dataset.validate_manifest",
        "catalog.search",
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
    assert_eq!(flags["frankenpandas"], cfg!(feature = "frankenpandas"));
    assert_eq!(flags["frankensearch"], cfg!(feature = "frankensearch"));

    // TOON is an alternate encoding of the same envelope.
    let toon = h.run(&["capabilities", "--toon"]);
    assert_eq!(toon.exit, 0);
    assert!(toon.stdout.starts_with("ok: true"));
}

#[test]
fn profile_validate_reports_handle_presence_by_name_only() {
    let h = Harness::new("profile");
    // Offline validation only: a canonical account overrides the planted
    // loopback one for this single command.
    let canonical = [("FRANKEN_SNOWFLAKE_E2E_ACCOUNT", "xy12345.us-east-1")];
    let complete = h.run_with(&["profile", "validate", "e2e", "--json"], &canonical);
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

/// Reality-check bead C5: `profile validate` must not bless a profile that
/// every live command refuses. The planted loopback account (the live path
/// refuses it with FSNOW-2002 before any socket) and an unknown or quarantined
/// auth lane are errors, exit 3, with a repair command.
#[test]
fn profile_validate_refuses_unusable_profiles() {
    let h = Harness::new("profile-unusable");
    let loopback = h.run(&["profile", "validate", "e2e", "--json"]);
    assert_eq!(loopback.exit, 3, "{}", loopback.stdout);
    let value = assert_envelope(&loopback, "profile.validate");
    assert_eq!(value["outcome_kind"], "error");
    assert_eq!(loopback.code(), "FSNOW-2002");
    assert_eq!(value["data"]["status"], "invalid");
    assert!(
        value["data"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "account_endpoint" && c["status"] == "fail"),
        "{}",
        loopback.stdout
    );
    for (account, lane) in [
        ("https://x.snowflakecomputing.com.evil.com", "pat"),
        ("xy12345.us-east-1", "bogus_lane"),
        ("xy12345.us-east-1", "workload_identity"),
    ] {
        let run = h.run_with(
            &["profile", "validate", "e2e", "--json"],
            &[
                ("FRANKEN_SNOWFLAKE_E2E_ACCOUNT", account),
                ("FRANKEN_SNOWFLAKE_E2E_AUTH", lane),
                ("FRANKEN_SNOWFLAKE_E2E_OIDC_TOKEN", "x"),
            ],
        );
        assert_eq!(run.exit, 3, "{account}/{lane}: {}", run.stdout);
        assert_eq!(run.code(), "FSNOW-2002", "{account}/{lane}");
    }
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

/// Reality-check bead oj0.36: `catalog search` with no snapshot is a typed
/// FSNOW-7002 naming the scan to run; a query with no words is a usage error.
#[test]
fn catalog_search_needs_a_snapshot_and_words() {
    let h = Harness::new("search");
    let missing = h.run(&["catalog", "search", "e2e", "revenue", "--json"]);
    assert_eq!(missing.exit, 7, "{}", missing.stdout);
    assert_eq!(missing.code(), "FSNOW-7002");
    assert!(
        missing.stdout.contains("catalog scan e2e"),
        "{}",
        missing.stdout
    );
    let wordless = h.run(&["catalog", "search", "e2e", "::", "--json"]);
    assert_eq!(wordless.exit, 64, "{}", wordless.stdout);
    let no_query = h.run(&["catalog", "search", "e2e", "--json"]);
    assert_eq!(no_query.exit, 64, "{}", no_query.stdout);
}

/// Reality-check bead oj0.35: `dataset validate-manifest` reads the overlay
/// named by FRANKEN_SNOWFLAKE_MANIFEST offline. No file is an empty success; a
/// valid file lists its entries (unscanned ones as warnings); a
/// credential-like key is refused without echoing its value; a missing
/// explicit file is an error, never a silent default.
#[test]
fn validate_manifest_reads_the_overlay_offline() {
    let h = Harness::new("overlay");
    let none = h.run(&["dataset", "validate-manifest", "--json"]);
    assert_eq!(none.exit, 0, "{}", none.stderr);
    let value = assert_envelope(&none, "dataset.validate_manifest");
    assert_eq!(value["data"]["present"], false);

    let path = h.data_dir.join("overlay.toml");
    let path_text = path.to_string_lossy().into_owned();
    fs::write(
        &path,
        "[[datasets]]\ndatabase = \"ANALYTICS\"\nschema = \"PUBLIC\"\nobject = \"EVENTS\"\ndefault_limit = 10\n\n[[datasets.fields]]\ncolumn = \"ACCOUNT_REF\"\nrole = \"entity_key\"\n",
    )
    .expect("write overlay");
    let env = [("FRANKEN_SNOWFLAKE_MANIFEST", path_text.as_str())];
    let valid = h.run_with(&["dataset", "validate-manifest", "--json"], &env);
    assert_eq!(valid.exit, 0, "{}", valid.stdout);
    let value = assert_envelope(&valid, "dataset.validate_manifest");
    assert_eq!(value["data"]["present"], true);
    assert_eq!(value["data"]["entry_count"], 1);
    assert_eq!(
        value["data"]["entries"][0]["target"],
        "ANALYTICS.PUBLIC.EVENTS"
    );
    assert!(
        value["warnings"].to_string().contains("matches no dataset"),
        "{}",
        valid.stdout
    );

    fs::write(
        &path,
        "[[datasets]]\nid = \"x\"\nsnowflake_password = \"hunter2-canary\"\n",
    )
    .expect("write overlay");
    let secret = h.run_with(&["dataset", "validate-manifest", "--json"], &env);
    assert_eq!(secret.exit, 64, "{}", secret.stdout);
    assert_eq!(secret.code(), "FSNOW-1002");
    assert!(secret.stdout.contains("snowflake_password"));
    assert!(
        !secret.stdout.contains("hunter2-canary"),
        "{}",
        secret.stdout
    );
    assert!(
        !secret.stderr.contains("hunter2-canary"),
        "{}",
        secret.stderr
    );

    let missing = h.run_with(
        &["dataset", "validate-manifest", "--json"],
        &[(
            "FRANKEN_SNOWFLAKE_MANIFEST",
            "/nonexistent/fsnow-overlay.toml",
        )],
    );
    assert_eq!(missing.exit, 64, "{}", missing.stdout);
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
            vec![
                "export",
                "run",
                "--profile",
                "e2e",
                "--sql",
                "select 1",
                "--format",
                "frame",
                "--out",
                "x.ipc",
                "--json",
            ],
            "export.run",
            2,
            if cfg!(feature = "frankenpandas") {
                3
            } else {
                64
            },
        ),
        (
            vec![
                "export",
                "run",
                "--profile",
                "e2e",
                "--sql",
                "select 1",
                "--format",
                "jsonl",
                "--out",
                "x.jsonl",
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
        if live && expected == 64 {
            assert_eq!(value["error"]["code"], "FSNOW-1002", "{}", run.stdout);
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
        (
            vec!["catalog", "diff", "e2e", "--database", "DB", "--json"],
            "catalog.diff",
        ),
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
    let graph_mermaid = h.run(&["catalog", "graph", "e2e", "--database", "DB", "--mermaid"]);
    if cfg!(feature = "live") {
        assert_eq!(
            graph_mermaid.exit, 3,
            "live build falls through to a scan: {}",
            graph_mermaid.stdout
        );
    } else {
        assert_eq!(graph_mermaid.exit, 7, "{}", graph_mermaid.stdout);
        assert!(
            graph_mermaid
                .stdout
                .contains("catalog scan e2e --database DB")
        );
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

    let run_csv = h.run(&[
        "export",
        "plan",
        "--profile",
        "e2e",
        "--sql",
        "select * from events",
        "--location",
        "@my_stage/exports/run_002",
        "--format",
        "csv",
        "--json",
    ]);
    assert_eq!(run_csv.exit, 0, "{}", run_csv.stderr);
    let value_csv = assert_envelope(&run_csv, "export.plan");
    let sql_csv = value_csv["data"]["plan_sql"].as_str().unwrap();
    assert!(sql_csv.starts_with("COPY INTO @my_stage/exports/run_002 FROM (select * from events)"));
    assert!(sql_csv.contains("TYPE = CSV"));

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

    let graph_conflict = h.run(&[
        "catalog",
        "graph",
        "e2e",
        "--database",
        "DB",
        "--json",
        "--mermaid",
    ]);
    assert_eq!(graph_conflict.exit, 64);
    assert_eq!(graph_conflict.json()["error"]["code"], "FSNOW-1002");
    assert!(
        graph_conflict.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Conflicting catalog graph output formats")
    );

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

    let mcp_no_sub = h.run(&["mcp"]);
    assert_eq!(mcp_no_sub.exit, 64);
    assert_eq!(mcp_no_sub.json()["command_id"], "mcp.serve");
    assert!(
        mcp_no_sub.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Expected `franken-snowflake mcp serve")
    );

    let mcp_typo = h.run(&["mcp", "servve"]);
    assert_eq!(mcp_typo.exit, 64);
    assert_eq!(mcp_typo.json()["did_you_mean"][0], "serve");

    let mcp_conflict = h.run(&["mcp", "serve", "--stdio", "--http", "127.0.0.1:3000"]);
    assert_eq!(mcp_conflict.exit, 64);
    assert!(
        mcp_conflict.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Conflicting MCP serve modes")
    );

    let mcp_missing_addr = h.run(&["mcp", "serve", "--http"]);
    assert_eq!(mcp_missing_addr.exit, 64);
    assert!(
        mcp_missing_addr.json()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Missing address for `mcp serve --http`")
    );

    if !cfg!(feature = "mcp") {
        let mcp = h.run(&["mcp", "serve", "--stdio"]);
        assert_eq!(mcp.exit, 64);
    }
}

#[test]
fn fsnow_alias_binary_runs_and_shares_contract() {
    let output = Command::new(FSNOW_BIN)
        .args(["capabilities", "--json"])
        .output()
        .expect("run fsnow");
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("parse json");
    assert_eq!(value["command_id"], "capabilities");
    assert_eq!(value["ok"], true);
}

/// Reality-check bead H1: the binary names the commit it was built from, and
/// `--with-exe-hash` self-reports the SHA-256 of the file actually executing,
/// so a proof harness can check it ran the build it meant to.
#[test]
fn capabilities_reports_build_identity_and_self_hash() {
    use sha2::{Digest, Sha256};
    let h = Harness::new("build-identity");
    let run = h.run(&["capabilities", "--with-exe-hash", "--json"]);
    assert_eq!(run.exit, 0, "{}", run.stdout);
    let value = assert_envelope(&run, "capabilities");
    let build = &value["data"]["build"];
    assert_eq!(build["version"], env!("CARGO_PKG_VERSION"));
    for key in ["git_sha", "target", "profile", "rustc"] {
        assert!(
            build[key].as_str().is_some_and(|text| !text.is_empty()),
            "build.{key} missing: {build}"
        );
    }
    assert!(build["features"].is_array(), "{build}");
    let expected: String = Sha256::digest(fs::read(BIN).expect("read the test binary"))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(build["exe_sha256"], expected.as_str(), "{build}");
    // The source digest uses the exact recipe the live-proof scripts
    // recompute from the working tree, so a stale .git on a build worker
    // cannot make a binary look like a build of these sources.
    let digest = build["source_digest"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert_eq!(digest.len(), 64, "{build}");
    if cfg!(unix) && Command::new("sha256sum").arg("--version").output().is_ok() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        let recipe = "{ find crates -type f \\( -name '*.rs' -o -name Cargo.toml \\) -not -path '*/target/*'; echo Cargo.toml; echo Cargo.lock; } | LC_ALL=C sort | xargs sha256sum | sha256sum | cut -d' ' -f1";
        let out = Command::new("sh")
            .args(["-c", recipe])
            .current_dir(root)
            .output()
            .expect("run the digest recipe");
        let tree = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        assert_eq!(
            digest, tree,
            "build.rs and the scripts must agree on the recipe"
        );
    }
    // Hashing reads the whole binary, so it is opt-in.
    let plain = h.run(&["capabilities", "--json"]);
    let plain = assert_envelope(&plain, "capabilities");
    assert!(plain["data"]["build"].get("exe_sha256").is_none());
    assert_eq!(plain["data"]["build"]["git_sha"], build["git_sha"]);
}

/// Every file under `dir`, recursively (the harness's private data dir).
fn files_under(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files
}

/// Reality-check bead B5: the string value of a secret-bearing SQL parameter
/// never reaches stdout, stderr, or the append-only local store, on the
/// refusal path, the dry-run path, and the confirm path; and a suggested
/// command never embeds a redacted copy that would run with `[REDACTED]`.
#[test]
fn secret_sql_literals_never_leave_the_process() {
    let h = Harness::new("sql-secrets");
    let corpus = [
        (
            "alter user u1 set password = 'cnry_pw_7f3a'",
            "cnry_pw_7f3a",
        ),
        (
            "create stage s1 url = 's3://b/p' credentials = (aws_key_id = 'cnry_akid_51e2' aws_secret_key = 'cnry_sk_9c0d')",
            "cnry_sk_9c0d",
        ),
        (
            "copy into @s1/x from t1 credentials = (azure_sas_token = 'cnry_sas_8b1f')",
            "cnry_sas_8b1f",
        ),
        (
            "create secret s2 type = generic_string secret_string = 'cnry_ss_e19b'",
            "cnry_ss_e19b",
        ),
        (
            "create api integration a2 api_provider = aws_api_gateway api_key = 'cnry_ak_2b9c'",
            "cnry_ak_2b9c",
        ),
    ];
    let ddl = [("FRANKEN_SNOWFLAKE_E2E_WRITE_ALLOW_DDL", "true")];
    let mut runs = Vec::new();
    for (sql, _) in corpus {
        // Default profile: DDL is refused (COPY INTO proceeds to the live
        // path, which refuses the loopback account before any socket).
        runs.push(h.run(&["query", "write", "--profile", "e2e", "--sql", sql, "--json"]));
        // DDL allowed: the dry-run plan, then the confirm path with its token.
        let plan = h.run_with(
            &[
                "query",
                "write",
                "--profile",
                "e2e",
                "--sql",
                sql,
                "--dry-run",
                "--json",
            ],
            &ddl,
        );
        let value = plan.json();
        assert_eq!(plan.exit, 0, "{}", plan.stdout);
        let preview = value["data"]["redacted_sql_preview"]
            .as_str()
            .unwrap_or_default();
        assert!(preview.contains("'[REDACTED]'"), "{preview}");
        let confirm = value["data"]["confirm_command"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(
            !confirm.contains("[REDACTED]"),
            "runnable with a redacted value: {confirm}"
        );
        let token = value["data"]["required_confirmation_token"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        runs.push(plan);
        runs.push(h.run_with(
            &[
                "query",
                "write",
                "--profile",
                "e2e",
                "--sql",
                sql,
                "--confirm",
                &token,
                "--json",
            ],
            &ddl,
        ));
    }
    let stored: Vec<(PathBuf, String)> = files_under(&h.data_dir)
        .into_iter()
        .map(|path| {
            let text = String::from_utf8_lossy(&fs::read(&path).unwrap_or_default()).into_owned();
            (path, text)
        })
        .collect();
    assert!(
        !stored.is_empty(),
        "the refusals were expected to reach the audit log"
    );
    for (_, canary) in corpus {
        for run in &runs {
            assert!(
                !run.stdout.contains(canary) && !run.stderr.contains(canary),
                "{canary} leaked: {} {}",
                run.stdout,
                run.stderr
            );
        }
        for (path, text) in &stored {
            assert!(
                !text.contains(canary),
                "{canary} persisted in {}",
                path.display()
            );
        }
    }
}

/// Reality-check bead B4 (first rung): a supplied `--confirm` is checked even
/// in the frictionless default; a token for other SQL is refused, not ignored.
#[test]
fn a_mismatched_confirm_token_is_refused_in_the_default_mode() {
    let h = Harness::new("confirm-mismatch");
    let plan = h.run(&[
        "query",
        "write",
        "--profile",
        "e2e",
        "--sql",
        "insert into t values (1)",
        "--dry-run",
        "--json",
    ]);
    let token = plan.json()["data"]["required_confirmation_token"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let other = h.run(&[
        "query",
        "write",
        "--profile",
        "e2e",
        "--sql",
        "insert into t values (2)",
        "--confirm",
        &token,
        "--json",
    ]);
    assert_eq!(other.exit, 2, "{}", other.stdout);
    assert_eq!(other.code(), "FSNOW-3008", "{}", other.stdout);
    // The matching token passes the ladder (the live path then refuses the
    // loopback account, FSNOW-2002, before any socket).
    let same = h.run(&[
        "query",
        "write",
        "--profile",
        "e2e",
        "--sql",
        "insert into t values (1)",
        "--confirm",
        &token,
        "--json",
    ]);
    assert_ne!(same.code(), "FSNOW-3008", "{}", same.stdout);
}

/// Reality-check bead C7a: the workload-identity lane is refused before any
/// credential is read or any request is built. The quarantine check runs ahead
/// of the endpoint check, so the refusal names the quarantine, not the planted
/// loopback account.
#[test]
fn workload_identity_lane_is_refused_before_any_request() {
    let h = Harness::new("wif");
    let run = h.run_with(
        &[
            "query",
            "run",
            "--profile",
            "e2e",
            "--sql",
            "select 1",
            "--json",
        ],
        &[
            ("FRANKEN_SNOWFLAKE_E2E_AUTH", "workload_identity"),
            ("FRANKEN_SNOWFLAKE_E2E_OIDC_TOKEN", "e2e.oidc.assertion"),
        ],
    );
    assert_ne!(run.exit, 0, "{}", run.stdout);
    if cfg!(feature = "live") {
        assert_eq!(run.exit, 3, "{}", run.stdout);
        assert_eq!(run.code(), "FSNOW-2002", "{}", run.stdout);
        assert!(run.stdout.contains("quarantined"), "{}", run.stdout);
        assert!(!run.stdout.contains("not canonical"), "{}", run.stdout);
    }
}

/// Reality-check bead B4: confirmation tokens are random per dry run (never
/// derived from the SQL), bound in the store to one statement and profile,
/// and expire; a forged or foreign token is refused.
#[test]
fn confirmation_tokens_are_random_bound_and_expiring() {
    let h = Harness::new("confirm-bound");
    let sql = "insert into t values (1)";
    let token = |run: &Run| {
        run.json()["data"]["required_confirmation_token"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    };
    let dry = || {
        h.run(&[
            "query",
            "write",
            "--profile",
            "e2e",
            "--sql",
            sql,
            "--dry-run",
            "--json",
        ])
    };
    let (first, second) = (dry(), dry());
    let (t1, t2) = (token(&first), token(&second));
    assert!(t1.starts_with("confirm:insert:"), "{}", first.stdout);
    assert_ne!(t1, t2, "tokens are random, not a hash of the statement");
    let confirm = |token: &str, profile: &str, env: &[(&str, &str)]| {
        h.run_with(
            &[
                "query",
                "write",
                "--profile",
                profile,
                "--sql",
                sql,
                "--confirm",
                token,
                "--json",
            ],
            env,
        )
    };
    // The matching token passes the ladder (the transport then refuses the
    // loopback account, or the build has no live transport).
    let ok = confirm(&t1, "e2e", &[]);
    assert_ne!(ok.code(), "FSNOW-3008", "{}", ok.stdout);
    if cfg!(feature = "live") {
        // Authorized but never submitted (the loopback account is refused
        // before any socket): still an attempt on the ledger.
        let ledger: String = files_under(&h.data_dir)
            .iter()
            .map(|path| String::from_utf8_lossy(&fs::read(path).unwrap_or_default()).into_owned())
            .collect();
        assert!(ledger.contains("write_not_submitted"), "{}", ok.stdout);
        assert!(ledger.contains("write_dry_run"), "{}", ok.stdout);
    }
    let forged = confirm(
        "confirm:insert:00000000-0000-4000-8000-000000000000",
        "e2e",
        &[],
    );
    assert_eq!(forged.code(), "FSNOW-3008", "{}", forged.stdout);
    assert!(
        forged.stdout.contains("names no dry run"),
        "{}",
        forged.stdout
    );
    let other = confirm(
        &t1,
        "other",
        &[("FRANKEN_SNOWFLAKE_OTHER_WRITE_ENABLED", "true")],
    );
    assert_eq!(other.code(), "FSNOW-3008", "{}", other.stdout);
    assert!(
        other.stdout.contains("different statement or profile"),
        "{}",
        other.stdout
    );
    let expired = confirm(
        &t2,
        "e2e",
        &[("FRANKEN_SNOWFLAKE_E2E_WRITE_TOKEN_TTL_SECONDS", "0")],
    );
    assert_eq!(expired.code(), "FSNOW-3008", "{}", expired.stdout);
    assert!(expired.stdout.contains("expired"), "{}", expired.stdout);
}

/// Reality-check bead B4: statements the SQL API cannot run alone are refused
/// typed (FSNOW-3010); procedures and external unloads need their own opt-in
/// (FSNOW-3011); a profile kind allowlist is enforced and parsed strictly.
#[test]
fn write_ladder_gates_unsupported_procedure_and_external_statements() {
    let h = Harness::new("write-gates");
    let write = |sql: &str, env: &[(&str, &str)]| {
        h.run_with(
            &["query", "write", "--profile", "e2e", "--sql", sql, "--json"],
            env,
        )
    };
    for sql in [
        "put file:///etc/hosts @s",
        "get @s file:///tmp/",
        "use role accountadmin",
        "alter session set query_tag = 'x'",
        "begin",
        "set v = 1",
    ] {
        let run = write(sql, &[]);
        assert_eq!(run.exit, 2, "{sql}: {}", run.stdout);
        assert_eq!(run.code(), "FSNOW-3010", "{sql}: {}", run.stdout);
    }
    let call = write("call my_proc()", &[]);
    assert_eq!(call.code(), "FSNOW-3011", "{}", call.stdout);
    assert!(
        call.stdout.contains("WRITE_ALLOW_PROCEDURES"),
        "{}",
        call.stdout
    );
    let allowed = write(
        "call my_proc()",
        &[("FRANKEN_SNOWFLAKE_E2E_WRITE_ALLOW_PROCEDURES", "true")],
    );
    assert_ne!(allowed.code(), "FSNOW-3011", "{}", allowed.stdout);
    let unload = write(
        "copy into 's3://bucket/x' from t credentials = (aws_key_id = 'e2e_key_id')",
        &[],
    );
    assert_eq!(unload.code(), "FSNOW-3011", "{}", unload.stdout);
    assert!(
        unload.stdout.contains("WRITE_ALLOW_EXTERNAL"),
        "{}",
        unload.stdout
    );
    // Inline cloud keys are flagged, and never echoed.
    assert!(
        unload.stdout.contains("STORAGE INTEGRATION"),
        "{}",
        unload.stdout
    );
    assert!(!unload.stdout.contains("e2e_key_id"), "{}", unload.stdout);
    let not_listed = write(
        "delete from t",
        &[("FRANKEN_SNOWFLAKE_E2E_WRITE_ALLOWED_KINDS", "insert")],
    );
    assert_eq!(not_listed.code(), "FSNOW-3001", "{}", not_listed.stdout);
    let bad_list = write(
        "insert into t values (1)",
        &[("FRANKEN_SNOWFLAKE_E2E_WRITE_ALLOWED_KINDS", "insert,upsert")],
    );
    assert_eq!(bad_list.code(), "FSNOW-2002", "{}", bad_list.stdout);
    assert!(bad_list.stdout.contains("upsert"), "{}", bad_list.stdout);
}
