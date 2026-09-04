//! Opt-in CLI live-proof lane: drives the real `franken-snowflake` binary end to
//! end against a live Snowflake account (the missing evidence for bead
//! `fsnow-agent-ergonomic-cli-cli-live-e2e-and-receipts-bvf`).
//!
//! This test is safe in no-account CI: without `FRANKEN_SNOWFLAKE_LIVE=1` and a
//! named profile's env handles, it records a typed skip artifact and never
//! resolves credentials or performs network IO. With explicit opt-in it spawns
//! the compiled binary (same feature set as the test invocation) and asserts
//! the live envelope contract: `data_source:live`, a real statement handle, a
//! 64-hex content-addressed `receipt_hash` that `receipt show` reads back, and
//! no secret material in any captured output.
//!
//! Mirrors `franken-snowflake-sqlapi/tests/live_proof.rs` (driver-level lane)
//! and `scripts/live-proof-cli.sh` (full battery); this file pins the core
//! proof inside the crate's own test suite. Docs: `docs/live_proof.md`.
//!
//! Integration-test crate: panicking on an unexpected process result IS the
//! failure mechanism, so the production panic/expect bans do not apply here.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const LIVE_OPT_IN_ENV: &str = "FRANKEN_SNOWFLAKE_LIVE";
const LIVE_PROFILE_ENV: &str = "FRANKEN_SNOWFLAKE_LIVE_PROFILE";
const GATE_SCHEMA: &str = "franken_snowflake.cli_live_gate.v1";

/// A gate decision: either run the proof or record a typed skip. Skips are
/// findings-preserving (they name the missing handles), never silent passes.
struct Gate {
    code: &'static str,
    detail: String,
    missing_env: Vec<String>,
}

fn gate() -> Result<String, Gate> {
    if env_value(LIVE_OPT_IN_ENV).as_deref() != Some("1") {
        return Err(Gate {
            code: "NotOptedIn",
            detail: "set FRANKEN_SNOWFLAKE_LIVE=1 to run the CLI live proof".to_string(),
            missing_env: vec![LIVE_OPT_IN_ENV.to_string()],
        });
    }
    let profile = match env_value(LIVE_PROFILE_ENV) {
        Some(profile) => profile,
        None => {
            return Err(Gate {
                code: "ProfileMissing",
                detail: format!("set {LIVE_PROFILE_ENV}=<profile> to name the live profile"),
                missing_env: vec![LIVE_PROFILE_ENV.to_string()],
            });
        }
    };
    let prefix = env_prefix(&profile);
    let mut missing = missing_env(
        [
            env_name(&prefix, "ACCOUNT").as_str(),
            env_name(&prefix, "USER").as_str(),
            env_name(&prefix, "AUTH").as_str(),
        ]
        .into_iter(),
    );
    let lane = env_value(env_name(&prefix, "AUTH").as_str()).unwrap_or_default();
    let secret_handle = match lane.as_str() {
        "pat" => env_name(&prefix, "PAT"),
        "oauth_bearer" => env_name(&prefix, "OAUTH_BEARER"),
        "key_pair_jwt" => env_name(&prefix, "PRIVATE_KEY_PEM"),
        "" => {
            return Err(Gate {
                code: "AuthLaneInvalid",
                detail: format!("{} must name an auth lane", env_name(&prefix, "AUTH")),
                missing_env: Vec::new(),
            });
        }
        other => {
            return Err(Gate {
                code: "AuthLaneInvalid",
                detail: format!(
                    "{} names unknown lane {other:?} (pat, oauth_bearer, key_pair_jwt)",
                    env_name(&prefix, "AUTH")
                ),
                missing_env: Vec::new(),
            });
        }
    };
    if env_value(secret_handle.as_str()).is_none() {
        missing.push(secret_handle);
    }
    if !missing.is_empty() {
        return Err(Gate {
            code: "RequiredEnvMissing",
            detail: format!("profile {profile:?} is missing credential env handles"),
            missing_env: missing,
        });
    }
    Ok(profile)
}

fn env_prefix(profile: &str) -> String {
    let mut prefix = String::from("FRANKEN_SNOWFLAKE_");
    for ch in profile.chars() {
        if ch.is_ascii_alphanumeric() {
            prefix.push(ch.to_ascii_uppercase());
        } else {
            prefix.push('_');
        }
    }
    prefix
}

fn env_name(prefix: &str, suffix: &str) -> String {
    format!("{prefix}_{suffix}")
}

fn env_value(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn missing_env<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    names
        .filter(|name| env_value(name).is_none())
        .map(str::to_string)
        .collect()
}

fn artifacts_root() -> PathBuf {
    env::var_os("FRANKEN_SNOWFLAKE_LIVE_ARTIFACTS_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .map(|path| path.join("fsnow-cli-live-proof"))
        })
        .unwrap_or_else(|| PathBuf::from("target").join("fsnow-cli-live-proof"))
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(0)
}

/// Append one gate/step event; failures to persist never fail the proof.
fn append_event(line: &str) {
    let root = artifacts_root();
    let _ = fs::create_dir_all(&root);
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("events.jsonl"))
    {
        let _ = writeln!(file, "{line}");
    }
}

fn record_skip(gate: &Gate) {
    let missing = gate
        .missing_env
        .iter()
        .map(|name| format!("\"{name}\""))
        .collect::<Vec<_>>()
        .join(",");
    let detail = gate.detail.replace('\\', " ").replace('"', "'");
    append_event(&format!(
        "{{\"schema\":\"{GATE_SCHEMA}\",\"code\":\"{}\",\"outcome\":\"skip\",\"ts\":{},\"missing_env\":[{missing}],\"detail\":\"{detail}\"}}",
        gate.code,
        now_unix_seconds()
    ));
    println!(
        "skip: {} ({}) ({})",
        gate.code,
        gate.missing_env.join(","),
        gate.detail
    );
}

/// Run the compiled CLI with the test process's environment (which the gate
/// already proved carries the profile handles) plus a per-run data dir, and
/// return (exit_code, stdout). Every stdout is captured for the secret scan;
/// envelopes are redaction-gated at compile time, so echoing them into
/// assertion failures is safe.
fn run_cli(
    bin: &str,
    data_dir: &PathBuf,
    args: &[&str],
    captured: &mut Vec<String>,
) -> (i32, String) {
    let output = Command::new(bin)
        .args(args)
        .env("FRANKEN_SNOWFLAKE_DATA_DIR", data_dir)
        .output()
        .unwrap_or_else(|error| panic!("spawn {bin}: {error}"));
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    captured.push(stdout.clone());
    (output.status.code().unwrap_or(-1), stdout)
}

fn assert_envelope(step: &str, exit_code: i32, stdout: &str, expected_exit: i32) {
    assert_eq!(
        exit_code, expected_exit,
        "{step}: exit {exit_code}, expected {expected_exit}; stdout: {stdout}"
    );
    assert!(
        stdout.contains("\"command_id\""),
        "{step}: not an envelope: {stdout}"
    );
}

fn is_64_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[test]
fn cli_live_proof_end_to_end() {
    let profile = match gate() {
        Ok(profile) => profile,
        Err(gate) => {
            record_skip(&gate);
            return;
        }
    };
    let prefix = env_prefix(&profile);
    let bin = env!("CARGO_BIN_EXE_franken-snowflake");
    let mut captured: Vec<String> = Vec::new();

    // Fresh per-run local store so receipts land somewhere inspectable.
    let run_dir = artifacts_root().join(format!("run-{}", now_unix_seconds()));
    fs::create_dir_all(&run_dir).expect("create run dir");
    let data_dir = run_dir.join("data");

    // Step 1: offline validation of the profile handles (never reads secrets).
    let (code, out) = run_cli(
        bin,
        &data_dir,
        &["profile", "validate", profile.as_str(), "--json"],
        &mut captured,
    );
    assert_envelope("profile_validate", code, &out, 0);
    append_event(&format!(
        "{{\"schema\":\"{GATE_SCHEMA}\",\"code\":\"profile_validate\",\"outcome\":\"pass\",\"ts\":{}}}",
        now_unix_seconds()
    ));

    // Step 2: the online probe runs the real auth + transport stack.
    let (code, out) = run_cli(
        bin,
        &data_dir,
        &["profile", "doctor", profile.as_str(), "--online", "--json"],
        &mut captured,
    );
    assert_envelope("profile_doctor_online", code, &out, 0);
    assert!(
        out.contains("\"data_source\":\"live\""),
        "profile_doctor_online: expected data_source=live: {out}"
    );

    // Step 3: a real read, with --require-live forcing the live contract.
    let small_sql = env_value(env_name(&prefix, "SMALL_SQL").as_str())
        .unwrap_or_else(|| "SELECT 1 AS FSNOW_CLI_LIVE_PROOF".to_string());
    let (code, out) = run_cli(
        bin,
        &data_dir,
        &[
            "query",
            "run",
            "--profile",
            profile.as_str(),
            "--sql",
            small_sql.as_str(),
            "--require-live",
            "--json",
        ],
        &mut captured,
    );
    assert_envelope("query_run", code, &out, 0);
    assert!(
        out.contains("\"data_source\":\"live\""),
        "query_run: expected data_source=live: {out}"
    );

    // Step 4: the receipt hash is 64-hex and reads back from the local store.
    let receipt_hash = out
        .split("\"receipt_hash\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| panic!("query_run: no receipt_hash in envelope: {out}"))
        .to_string();
    assert!(
        is_64_hex(&receipt_hash),
        "query_run: receipt_hash not 64-hex: {receipt_hash}"
    );
    let (code, out) = run_cli(
        bin,
        &data_dir,
        &["receipt", "show", receipt_hash.as_str(), "--json"],
        &mut captured,
    );
    assert_envelope("receipt_show", code, &out, 0);
    assert!(
        out.contains(&receipt_hash),
        "receipt_show: hash not echoed: {out}"
    );

    // Step 5: secret scan over everything captured. Only ever compares against
    // handle values; the values themselves are never printed.
    let secret_sources = [
        env_name(&prefix, "PAT"),
        env_name(&prefix, "OAUTH_BEARER"),
        env_name(&prefix, "PRIVATE_KEY_PEM"),
        env_name(&prefix, "PRIVATE_KEY_PASSPHRASE"),
    ];
    let secret_values: Vec<String> = secret_sources
        .iter()
        .filter_map(|name| env_value(name))
        .filter(|value| value.len() >= 8)
        .collect();
    let everything: String = captured.join("\n");
    for value in secret_values {
        assert!(
            !everything.contains(&value),
            "secret scan: a credential handle value leaked into captured output"
        );
    }
    assert!(
        !everything.contains("BEGIN PRIVATE KEY") && !everything.contains("BEGIN RSA PRIVATE KEY"),
        "secret scan: private-key marker leaked into captured output"
    );

    append_event(&format!(
        "{{\"schema\":\"{GATE_SCHEMA}\",\"code\":\"cli_live_proof_end_to_end\",\"outcome\":\"pass\",\"ts\":{}}}",
        now_unix_seconds()
    ));
    println!("cli live proof passed; run dir: {}", run_dir.display());
}
