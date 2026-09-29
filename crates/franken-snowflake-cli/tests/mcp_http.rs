//! Spawns the real binary as `mcp serve --http 127.0.0.1:0` and replays the
//! 2026-09-23 cross-origin exploit over real loopback sockets. The shipped
//! v0.0.4 binary answered a foreign Origin's preflight with
//! `access-control-allow-origin: <that origin>` and ran `tools/call` for it with
//! no credentials; the secured transport must refuse all of that, require the
//! bearer token, refuse foreign Host headers, and hide side-effecting tools.
#![cfg(feature = "mcp")]
// Integration-test crate: panicking on an unexpected process result IS the
// failure mechanism, so the production panic/expect bans do not apply here.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

const BIN: &str = env!("CARGO_BIN_EXE_franken-snowflake");
const TOKEN: &str = "fsnow-e2e-token-0123456789abcdef0123456789";

fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("fsnow-mcp-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

struct Server {
    child: Child,
    port: u16,
    /// The server's stderr, line by line (the reader keeps draining it).
    stderr: mpsc::Receiver<String>,
}

impl Server {
    /// Every stderr line the server has written so far.
    fn stderr_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        while let Ok(line) = self.stderr.recv_timeout(Duration::from_millis(300)) {
            lines.push(line);
        }
        lines
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start `mcp serve --http 127.0.0.1:0` and read the bound port from stderr.
fn start(label: &str, extra_args: &[&str]) -> Server {
    let data_dir = temp_dir(label);
    let mut args = vec!["mcp", "serve", "--http", "127.0.0.1:0"];
    args.extend_from_slice(extra_args);
    let mut child = Command::new(BIN)
        .args(&args)
        .env_clear()
        .env("HOME", &data_dir)
        .env("FRANKEN_SNOWFLAKE_DATA_DIR", &data_dir)
        .env("FRANKEN_SNOWFLAKE_MCP_TOKEN", TOKEN)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp serve --http");
    let stderr = child.stderr.take().expect("stderr");
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    // Owned by the guard from here on, so every path (a panic included) kills
    // and reaps the child.
    let mut server = Server {
        child,
        port: 0,
        stderr: rx,
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let line = server
            .stderr
            .recv_timeout(remaining)
            .expect("server announced its listening address");
        if let Some(rest) = line.split("http://127.0.0.1:").nth(1) {
            server.port = rest
                .split('/')
                .next()
                .and_then(|p| p.parse().ok())
                .expect("port in listening line");
            assert!(
                !line.contains(TOKEN),
                "the listening line must not print the token: {line}"
            );
            return server;
        }
    }
}

/// Send one raw HTTP request; return (status, lowercase headers, body).
fn http(
    port: u16,
    method: &str,
    headers: &[(&str, String)],
    body: &str,
) -> (u16, Vec<(String, String)>, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("timeout");
    let mut request = format!("{method} /mcp HTTP/1.1\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!(
        "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    stream.write_all(request.as_bytes()).expect("write");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    (status, headers, body.to_owned())
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fsnow-e2e","version":"0"}}}"#;

fn host(port: u16) -> (&'static str, String) {
    ("Host", format!("127.0.0.1:{port}"))
}

fn bearer() -> (&'static str, String) {
    ("Authorization", format!("Bearer {TOKEN}"))
}

#[test]
fn http_transport_refuses_the_cross_origin_exploit_and_requires_the_token() {
    let server = start("http", &[]);
    let port = server.port;
    let evil = ("Origin", "https://evil.example".to_owned());

    // 1. The exploit's preflight: refused, and the foreign origin is not echoed.
    let (status, headers, _) = http(
        port,
        "OPTIONS",
        &[
            host(port),
            evil.clone(),
            ("Access-Control-Request-Method", "POST".to_owned()),
        ],
        "",
    );
    assert_eq!(status, 403, "foreign-origin preflight must be refused");
    assert_eq!(header(&headers, "access-control-allow-origin"), None);

    // 2. The exploit's POST (even with a valid token): refused, not echoed.
    let (status, headers, _) = http(port, "POST", &[host(port), evil, bearer()], INITIALIZE);
    assert_eq!(status, 403);
    assert_eq!(header(&headers, "access-control-allow-origin"), None);

    // 3. No token / wrong token: 401.
    let (status, headers, _) = http(port, "POST", &[host(port)], INITIALIZE);
    assert_eq!(status, 401);
    assert_eq!(header(&headers, "www-authenticate"), Some("Bearer"));
    let (status, _, _) = http(
        port,
        "POST",
        &[host(port), ("Authorization", "Bearer wrong".to_owned())],
        INITIALIZE,
    );
    assert_eq!(status, 401);

    // 4. DNS rebinding: a foreign Host header is refused.
    let (status, _, _) = http(
        port,
        "POST",
        &[("Host", format!("attacker.example:{port}")), bearer()],
        INITIALIZE,
    );
    assert_eq!(status, 403);

    // 5. The legitimate client: initialize, list, call.
    let (status, _, body) = http(port, "POST", &[host(port), bearer()], INITIALIZE);
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"serverInfo\""), "{body}");
    let (status, _, body) = http(
        port,
        "POST",
        &[host(port), bearer()],
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    );
    assert_eq!(status, 200, "{body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("json");
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert!(names.contains(&"query_plan"), "{names:?}");
    assert!(
        !names.contains(&"export_run") && !names.contains(&"query_cancel"),
        "side-effecting tools are hidden over HTTP by default: {names:?}"
    );
    let (status, _, body) = http(
        port,
        "POST",
        &[host(port), bearer()],
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"export_run","arguments":{"profile":"demo","sql":"select 1","format":"csv","out":"/tmp/x.csv"}}}"#,
    );
    assert_eq!(status, 200);
    assert!(body.contains("--allow-tool export_run"), "{body}");
    let (status, _, body) = http(
        port,
        "POST",
        &[host(port), bearer()],
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"query_plan","arguments":{"profile":"demo","sql":"select 1"}}}"#,
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("fsnow.query.plan.v1"), "{body}");

    // 6. Every request left one JSON decision line on stderr; the refused
    //    cross-origin attempt is on record, and the token never is.
    let lines = server.stderr_lines();
    let events: Vec<serde_json::Value> = lines
        .iter()
        .filter_map(|line| serde_json::from_str(line).ok())
        .filter(|event: &serde_json::Value| event["event"] == "mcp_http_request")
        .collect();
    assert!(
        events.iter().any(|e| e["decision"] == "refused"
            && e["status"] == 403
            && e["origin"] == "https://evil.example"),
        "{lines:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["decision"] == "refused" && e["status"] == 401),
        "{lines:?}"
    );
    assert!(
        events.iter().any(|e| e["decision"] == "dispatched"
            && e["rpc_method"] == "tools/call"
            && e["tool"] == "query_plan"),
        "{lines:?}"
    );
    assert!(
        lines.iter().all(|line| !line.contains(TOKEN)),
        "the token must never be logged: {lines:?}"
    );
}

#[test]
fn allowed_origin_and_tool_are_honored() {
    let server = start(
        "http-allow",
        &[
            "--allow-origin",
            "https://trusted.example",
            "--allow-tool",
            "export_run",
        ],
    );
    let port = server.port;
    let trusted = ("Origin", "https://trusted.example".to_owned());
    let (status, headers, _) = http(port, "OPTIONS", &[host(port), trusted.clone()], "");
    assert_eq!(status, 204);
    assert_eq!(
        header(&headers, "access-control-allow-origin"),
        Some("https://trusted.example")
    );
    let (status, headers, body) = http(
        port,
        "POST",
        &[host(port), trusted.clone(), bearer()],
        INITIALIZE,
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        header(&headers, "access-control-allow-origin"),
        Some("https://trusted.example")
    );
    let (status, _, body) = http(
        port,
        "POST",
        &[host(port), trusted, bearer()],
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"export_run\""), "{body}");
    // Reality-check bead B2: even when allowed, the MCP export tool is
    // confined to the export directory; `..` is refused before any statement.
    let (status, _, body) = http(
        port,
        "POST",
        &[host(port), bearer()],
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"export_run","arguments":{"profile":"demo","sql":"select 1","format":"csv","out":"../../escape.csv"}}}"#,
    );
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("may not contain"), "{body}");
    assert!(!body.contains("\"ok\":true"), "{body}");
}

#[test]
fn http_without_a_token_refuses_to_start() {
    let data_dir = temp_dir("http-notoken");
    let output = Command::new(BIN)
        .args(["mcp", "serve", "--http", "127.0.0.1:0"])
        .env_clear()
        .env("HOME", &data_dir)
        .env("FRANKEN_SNOWFLAKE_DATA_DIR", &data_dir)
        .stdin(Stdio::null())
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("FRANKEN_SNOWFLAKE_MCP_TOKEN"), "{stderr}");
}
