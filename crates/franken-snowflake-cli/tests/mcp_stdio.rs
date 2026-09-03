//! Spawns the real binary as an MCP stdio server, performs the JSON-RPC
//! handshake, lists the tools, calls two of them, and proves CLI/MCP parity:
//! the tool result is byte-for-byte the CLI envelope for the same verb
//! (modulo the per-invocation request id and timing).
#![cfg(feature = "mcp")]
// Integration-test crate: panicking on an unexpected process result IS the
// failure mechanism, so the production panic/expect bans do not apply here.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_franken-snowflake");

fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("fsnow-mcp-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Strip the fields that legitimately differ between two invocations.
fn stable(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(object) = value.as_object_mut() {
        for key in ["request_id", "started_at", "finished_at", "duration_ms"] {
            object.remove(key);
        }
    }
    value
}

#[test]
fn mcp_stdio_handshake_lists_tools_and_returns_cli_envelopes() {
    let data_dir = temp_dir("stdio");
    let mut child = Command::new(BIN)
        .args(["mcp", "serve", "--stdio"])
        .env_clear()
        .env("HOME", &data_dir)
        .env("FRANKEN_SNOWFLAKE_DATA_DIR", &data_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp serve --stdio");

    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let requests = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"fsnow-e2e","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"capabilities","arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"dataset_describe_operator","arguments":{"operator":"between"}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"export_plan","arguments":{"profile":"demo","sql":"select * from events","location":"@my_stage/exports/run_001","format":"jsonl"}}}"#,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"query_plan","arguments":{"dataset_id":"never_scanned_b3_0000","entity":"E1"}}}"#,
    ];
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for request in requests {
            stdin.write_all(request.as_bytes()).expect("write request");
            stdin.write_all(b"\n").expect("newline");
        }
        stdin.flush().expect("flush");
    }

    let mut responses = std::collections::BTreeMap::<u64, serde_json::Value>::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while responses.len() < 6 && std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(line) => {
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line)
                    && let Some(id) = value.get("id").and_then(serde_json::Value::as_u64)
                {
                    responses.insert(id, value);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&data_dir);

    assert_eq!(
        responses.len(),
        6,
        "expected 6 responses, got {responses:?}"
    );

    let init = &responses[&1]["result"];
    assert_eq!(init["serverInfo"]["name"], "franken-snowflake");
    assert_eq!(init["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));

    let tools = responses[&2]["result"]["tools"]
        .as_array()
        .expect("tools array");
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(tools.len(), 19, "{names:?}");
    for expected in [
        "capabilities",
        "onboard",
        "doctor",
        "selftest",
        "profile_validate",
        "catalog_scan",
        "catalog_graph",
        "dataset_inspect",
        "dataset_describe_operator",
        "query_plan",
        "query_run",
        "query_cancel",
        "receipt_show",
        "export_plan",
        "export_run",
        "dataset_profile",
        "profile_doctor",
    ] {
        assert!(names.contains(&expected), "missing tool {expected}");
    }

    // Parity: the tool result IS the CLI envelope for the same verb.
    let text = responses[&3]["result"]["content"][0]["text"]
        .as_str()
        .expect("tool result text");
    let via_mcp: serde_json::Value = serde_json::from_str(text).expect("envelope JSON");
    assert_eq!(via_mcp["command_id"], "capabilities");
    let cli = Command::new(BIN)
        .args(["capabilities", "--json"])
        .env_clear()
        .env("FRANKEN_SNOWFLAKE_DATA_DIR", &data_dir)
        .output()
        .expect("cli capabilities");
    let via_cli: serde_json::Value =
        serde_json::from_slice(&cli.stdout).expect("cli envelope JSON");
    assert_eq!(
        stable(via_mcp),
        stable(via_cli),
        "MCP and CLI envelopes must not drift"
    );

    let describe = responses[&4]["result"]["content"][0]["text"]
        .as_str()
        .expect("describe-operator text");
    let describe: serde_json::Value = serde_json::from_str(describe).expect("envelope JSON");
    assert_eq!(describe["command_id"], "dataset.describe_operator");
    assert_eq!(describe["data"]["operator"], "between");

    // export_plan carries every flag through to the CLI: a real COPY INTO plan
    // comes back as the CLI envelope (the old zero-parameter tool could only
    // produce a usage error).
    let export = responses[&5]["result"]["content"][0]["text"]
        .as_str()
        .expect("export_plan text");
    let export: serde_json::Value = serde_json::from_str(export).expect("envelope JSON");
    assert_eq!(export["ok"], true, "{export}");
    assert_eq!(export["command_id"], "export.plan");
    assert!(
        export.to_string().contains("COPY INTO"),
        "plan should carry the COPY INTO statement: {export}"
    );

    // Dataset mode reaches the CLI planner: an unknown dataset is the CLI's
    // typed FSNOW-7002 error, returned verbatim as the tool's envelope text
    // (only exit-2 refusals become JSON-RPC tool errors).
    let dataset = responses[&6]["result"]["content"][0]["text"]
        .as_str()
        .expect("dataset-mode tool result carries the CLI envelope");
    let envelope: serde_json::Value = serde_json::from_str(dataset).expect("envelope JSON");
    assert_eq!(envelope["ok"], false, "{envelope}");
    assert_eq!(envelope["command_id"], "query.plan", "{envelope}");
    assert_eq!(envelope["error"]["code"], "FSNOW-7002", "{envelope}");
    assert!(
        envelope.to_string().contains("catalog scan"),
        "the repair command names the scan: {envelope}"
    );
}
