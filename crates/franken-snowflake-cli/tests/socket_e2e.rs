//! Hermetic socket-level end-to-end proof (reality-check bead F1): the REAL
//! `franken-snowflake` binary, through the REAL Asupersync HTTP/1.1 + TLS
//! client, against a loopback mock SQL API served over a real TLS listener.
//!
//! Nothing below `main` is replaced. The only test seam is the `testkit-endpoint`
//! cargo feature plus the `FRANKEN_SNOWFLAKE_TESTKIT_ENDPOINT=1` opt-in, which
//! together admit a `https://127.0.0.1:<port>` account endpoint; certificate
//! verification runs through the production `<PREFIX>_CA_BUNDLE` path against a
//! CA minted per run. Response bodies come from the testkit's kx6 SQL API
//! fixtures. Every run plants a canary PAT and scans stdout, stderr and every
//! file the binary wrote for it.
//!
//! No-claim: this proves the connector's own wire behavior against a faithful
//! mock; it is not evidence that Snowflake answers the same way (that is the
//! credentialed live-proof lane).

#![cfg(feature = "testkit-endpoint")]
// Integration-test crate: panicking on an unexpected process result IS the
// failure mechanism, so the production panic/expect bans do not apply here.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asupersync::http::h1::server::{HostPolicy, Http1Config, Http1Server};
use asupersync::http::{Request, Response};
use asupersync::net::TcpListener;
use asupersync::runtime::RuntimeBuilder;
use asupersync::tls::{CertificateChain, PrivateKey, TlsAcceptorBuilder};
use franken_snowflake_testkit::mock::http::{MockHttpResponse, reason_phrase};
use franken_snowflake_testkit::mock::scenarios;

const BIN: &str = env!("CARGO_BIN_EXE_franken-snowflake");
const CANARY_PAT: &str = "sfpat_socketCanaryPatValue0123456789";
const SUBMIT_PATH: &str = "/api/v2/statements";

// ---------------------------------------------------------------------------
// TLS material and the mock server
// ---------------------------------------------------------------------------

/// A throwaway self-signed certificate for 127.0.0.1/localhost.
struct TestCert {
    cert_pem: String,
    key_pem: String,
}

impl TestCert {
    fn mint() -> Self {
        let certified = rcgen::generate_simple_self_signed(vec![
            "127.0.0.1".to_owned(),
            "localhost".to_owned(),
        ])
        .expect("mint a test certificate");
        Self {
            cert_pem: certified.cert.pem(),
            key_pem: certified.signing_key.serialize_pem(),
        }
    }
}

/// One request as the mock saw it on the wire.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn from_request(request: Request) -> Self {
        Self {
            method: request.method.as_str().to_owned(),
            target: request.uri,
            headers: request.headers,
            body: request.body,
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }

    fn query(&self, key: &str) -> Option<&str> {
        let query = self.target.split_once('?')?.1;
        query.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            (name == key).then_some(value)
        })
    }

    fn is_submit(&self) -> bool {
        self.method == "POST" && self.path() == SUBMIT_PATH
    }

    fn is_poll_of(&self, handle: &str) -> bool {
        self.method == "GET"
            && self.path() == format!("{SUBMIT_PATH}/{handle}")
            && self.query("partition").is_none()
    }

    fn body_json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).expect("request body is JSON")
    }
}

type Script = dyn Fn(&Seen, &[Seen]) -> MockHttpResponse + Send + Sync;

/// A mock SQL API on `127.0.0.1:<ephemeral>` behind TLS. `script` answers each
/// request given everything seen before it; the log is shared with the test.
struct MockServer {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl MockServer {
    fn start(
        cert: &TestCert,
        script: impl Fn(&Seen, &[Seen]) -> MockHttpResponse + Send + Sync + 'static,
    ) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let script: Arc<Script> = Arc::new(script);
        let chain = CertificateChain::from_pem(cert.cert_pem.as_bytes()).expect("cert chain");
        let key = PrivateKey::from_pem(cert.key_pem.as_bytes()).expect("private key");
        let acceptor = TlsAcceptorBuilder::new(chain, key)
            .alpn_protocols(vec![b"http/1.1".to_vec()])
            .build()
            .expect("TLS acceptor");
        let (port_tx, port_rx) = std::sync::mpsc::channel();
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("server runtime");
            runtime.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                let port = listener.local_addr().expect("local addr").port();
                port_tx.send(port).expect("report port");
                // The Host header the client must send (the server refuses any
                // other, so this also checks the client's Host header).
                let hosts = vec![format!("127.0.0.1:{port}"), "127.0.0.1".to_owned()];
                loop {
                    // A listener error ends the server; the test then times out
                    // loudly instead of spinning.
                    let Ok((tcp, _)) = listener.accept().await else {
                        break;
                    };
                    // A client that rejects our certificate fails here, before
                    // any request is read.
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        continue;
                    };
                    let script = Arc::clone(&script);
                    let log = Arc::clone(&log);
                    let handler = move |request: Request| {
                        let seen = Seen::from_request(request);
                        let mut log = log.lock().expect("request log");
                        let reply = script(&seen, &log);
                        log.push(seen);
                        std::future::ready(to_response(reply))
                    };
                    let config = Http1Config::default()
                        .keep_alive(false)
                        .host_policy(HostPolicy::allow_list(hosts.clone()));
                    let _ = Http1Server::with_config(handler, config).serve(tls).await;
                }
            });
        });
        let port = port_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("mock server bound");
        Self { port, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("request log").clone()
    }

    // Only the (Unix) signal scenario waits on the server mid-run.
    #[cfg_attr(not(unix), allow(dead_code))]
    fn wait_for(&self, what: &str, done: impl Fn(&[Seen]) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            if done(&self.seen()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("timed out waiting for {what}; saw {:?}", self.seen());
    }
}

fn to_response(reply: MockHttpResponse) -> Response {
    let mut response = Response::new(reply.status, reason_phrase(reply.status), reply.body);
    response.headers = reply.headers;
    response
}

fn json(status: u16, value: &serde_json::Value) -> MockHttpResponse {
    MockHttpResponse::json(status, value.to_string().into_bytes())
}

fn not_found() -> MockHttpResponse {
    json(
        404,
        &serde_json::json!({"code": "390404", "message": "not found"}),
    )
}

/// The kx6 `202` golden, re-pointed at `handle`.
fn running(handle: &str) -> MockHttpResponse {
    let mut body: serde_json::Value =
        serde_json::from_slice(scenarios::RESP_202_RUNNING).expect("202 golden");
    body["statementHandle"] = handle.into();
    body["statementStatusUrl"] = format!("{SUBMIT_PATH}/{handle}").into();
    json(202, &body)
}

/// The kx6 multi-partition `200` golden, re-pointed at `handle`: two inline
/// rows plus partitions 1 (gzip, two rows) and 2 (identity, one row).
fn completed_multi(handle: &str) -> MockHttpResponse {
    let mut body: serde_json::Value =
        serde_json::from_slice(scenarios::RESP_200_MULTI).expect("200 golden");
    body["statementHandle"] = handle.into();
    body["statementStatusUrl"] = format!("{SUBMIT_PATH}/{handle}").into();
    json(200, &body)
}

/// The kx6 single-partition `200` golden, re-pointed at `handle`.
fn completed_single(handle: &str) -> MockHttpResponse {
    let mut body: serde_json::Value =
        serde_json::from_slice(scenarios::RESP_200_SINGLE).expect("200 golden");
    body["statementHandle"] = handle.into();
    body["statementStatusUrl"] = format!("{SUBMIT_PATH}/{handle}").into();
    json(200, &body)
}

/// A completed single-partition result with the given rowType
/// (`(name, type, precision, scale)`) and rows.
fn result_set(
    handle: &str,
    columns: &[(&str, &str, Option<i64>, Option<i64>)],
    rows: &[Vec<Option<&str>>],
) -> MockHttpResponse {
    let row_type: Vec<serde_json::Value> = columns
        .iter()
        .map(|(name, kind, precision, scale)| {
            serde_json::json!({
                "name": name, "type": kind, "nullable": true,
                "precision": precision, "scale": scale
            })
        })
        .collect();
    json(
        200,
        &serde_json::json!({
            "resultSetMetaData": {
                "numRows": rows.len(),
                "format": "jsonv2",
                "rowType": row_type,
                "partitionInfo": [{"rowCount": rows.len(), "uncompressedSize": 256}]
            },
            "data": rows,
            "code": "090001",
            "sqlState": "00000",
            "statementHandle": handle,
            "statementStatusUrl": format!("{SUBMIT_PATH}/{handle}"),
            "message": "Statement executed successfully."
        }),
    )
}

// ---------------------------------------------------------------------------
// The binary under test
// ---------------------------------------------------------------------------

/// A scratch store + CA bundle for one test, removed on drop.
struct Harness {
    dir: PathBuf,
    ca_bundle: PathBuf,
}

impl Harness {
    fn new(label: &str, trusted: &TestCert) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "fsnow-socket-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(dir.join("store")).expect("temp dir");
        let ca_bundle = dir.join("ca.pem");
        fs::write(&ca_bundle, &trusted.cert_pem).expect("write CA bundle");
        Self { dir, ca_bundle }
    }

    /// The binary with a scrubbed environment and the planted `sock` profile
    /// pointing at `port`.
    fn command(&self, port: u16, args: &[&str]) -> Command {
        let store = self.dir.join("store");
        let mut command = Command::new(BIN);
        command
            .args(args)
            .env_clear()
            .env("HOME", &store)
            .env("FRANKEN_SNOWFLAKE_DATA_DIR", &store)
            .env("FRANKEN_SNOWFLAKE_TESTKIT_ENDPOINT", "1")
            .env(
                "FRANKEN_SNOWFLAKE_SOCK_ACCOUNT",
                format!("https://127.0.0.1:{port}"),
            )
            .env("FRANKEN_SNOWFLAKE_SOCK_USER", "SOCK_USER")
            .env("FRANKEN_SNOWFLAKE_SOCK_AUTH", "pat")
            .env("FRANKEN_SNOWFLAKE_SOCK_WAREHOUSE", "SOCK_WH")
            .env("FRANKEN_SNOWFLAKE_SOCK_PAT", CANARY_PAT)
            .env("FRANKEN_SNOWFLAKE_SOCK_CA_BUNDLE", &self.ca_bundle);
        // Windows sockets need SYSTEMROOT to initialize.
        if let Some(root) = std::env::var_os("SYSTEMROOT") {
            command.env("SYSTEMROOT", root);
        }
        command
    }

    fn run(&self, port: u16, args: &[&str]) -> Run {
        self.finish(args, self.command(port, args).output().expect("spawn"))
    }

    /// Exit code, parsed envelope, and the canary scan over stdout, stderr and
    /// every file the binary left in the store.
    fn finish(&self, args: &[&str], output: Output) -> Run {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            !stdout.contains(CANARY_PAT) && !stderr.contains(CANARY_PAT),
            "canary PAT leaked by {args:?}: stdout={stdout} stderr={stderr}"
        );
        for file in files_under(&self.dir.join("store")) {
            let bytes = fs::read(&file).unwrap_or_default();
            assert!(
                !String::from_utf8_lossy(&bytes).contains(CANARY_PAT),
                "canary PAT leaked into {}",
                file.display()
            );
        }
        let envelope = serde_json::from_str(&stdout)
            .unwrap_or_else(|error| panic!("stdout is not JSON ({error}): {stdout}\n{stderr}"));
        Run {
            exit: output.status.code().unwrap_or(-1),
            envelope,
            stderr,
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A spawned `mcp serve` killed and reaped however its test ends: a failing
/// assertion otherwise orphaned `mcp serve --http` (on Windows the orphan held
/// the test's pipes open and locked the binary against the next link).
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl std::ops::Deref for KillOnDrop {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for KillOnDrop {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        let Ok(entries) = fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
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

struct Run {
    exit: i32,
    envelope: serde_json::Value,
    stderr: String,
}

impl Run {
    fn context(&self) -> String {
        format!(
            "exit={} envelope={} stderr={}",
            self.exit, self.envelope, self.stderr
        )
    }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// 202 -> poll -> 200 with two extra partitions (one gzip), all over TLS:
/// the request contract on the wire, the assembled rows, the receipt.
#[test]
fn query_run_polls_and_streams_gzip_partitions_over_tls() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f101";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, before| {
        if request.is_submit() {
            return running(HANDLE);
        }
        if request.is_poll_of(HANDLE) {
            let polls = before.iter().filter(|seen| seen.is_poll_of(HANDLE)).count();
            return if polls == 0 {
                running(HANDLE)
            } else {
                completed_multi(HANDLE)
            };
        }
        match (
            request.path() == format!("{SUBMIT_PATH}/{HANDLE}"),
            request.query("partition"),
        ) {
            (true, Some("1")) => scenarios::gzip_partition(),
            (true, Some("2")) => {
                MockHttpResponse::json(200, br#"{"data":[["5","epsilon"]]}"#.to_vec())
            }
            _ => not_found(),
        }
    });
    let h = Harness::new("partitions", &cert);
    let sql = "select event_date, entity_id from events";
    let run = h.run(
        server.port,
        &["query", "run", "--profile", "sock", "--sql", sql, "--json"],
    );
    assert_eq!(run.exit, 0, "{}", run.context());
    let env = &run.envelope;
    assert_eq!(env["ok"], true, "{}", run.context());
    assert_eq!(env["data_source"], "live", "{}", run.context());
    assert_eq!(env["statement_handle"], HANDLE, "{}", run.context());
    assert!(env["receipt_hash"].is_string(), "{}", run.context());
    assert_eq!(env["data"]["row_count"], 5, "{}", run.context());
    // Inline partition 0 counts as fetched.
    assert_eq!(env["data"]["partition_count"], 3, "{}", run.context());
    assert_eq!(env["data"]["partitions_fetched"], 3, "{}", run.context());
    assert_eq!(
        env["data"]["rows"],
        serde_json::json!([
            ["2020-01-01", "ENTITY123"],
            ["2020-01-02", "ENTITY124"],
            ["1970-01-04", "gamma"],
            ["1970-01-05", "delta"],
            ["1970-01-06", "epsilon"]
        ]),
        "typed rows (DATE as ISO dates), in partition order: {}",
        run.context()
    );
    assert_eq!(env["data"]["row_encoding"], "typed.v1", "{}", run.context());
    assert_eq!(
        env["data"]["columns"][0]["json_repr"],
        "date",
        "{}",
        run.context()
    );

    let seen = server.seen();
    let submits: Vec<&Seen> = seen.iter().filter(|seen| seen.is_submit()).collect();
    assert_eq!(submits.len(), 1, "{seen:?}");
    let submit = submits[0];
    // The credential reaches the server, typed, and only in the header.
    assert_eq!(
        submit.header("Authorization"),
        Some(format!("Bearer {CANARY_PAT}").as_str())
    );
    assert_eq!(
        submit.header("X-Snowflake-Authorization-Token-Type"),
        Some("PROGRAMMATIC_ACCESS_TOKEN")
    );
    assert!(submit.query("requestId").is_some(), "{}", submit.target);
    let body = submit.body_json();
    assert_eq!(body["statement"], sql);
    assert_eq!(body["warehouse"], "SOCK_WH");
    assert_eq!(body["parameters"]["MULTI_STATEMENT_COUNT"], "1");
    assert!(
        body["parameters"]["QUERY_TAG"]
            .as_str()
            .is_some_and(|tag| tag.starts_with("fsnow:query.run:")),
        "{body}"
    );
    assert!(body["timeout"].as_u64().is_some_and(|t| t > 0), "{body}");
    assert_eq!(
        seen.iter().filter(|s| s.is_poll_of(HANDLE)).count(),
        2,
        "one 202 poll, then the 200: {seen:?}"
    );
    for partition in ["1", "2"] {
        let fetch = seen
            .iter()
            .find(|s| s.query("partition") == Some(partition))
            .unwrap_or_else(|| panic!("partition {partition} fetched: {seen:?}"));
        assert_eq!(fetch.method, "GET");
        assert!(
            fetch
                .header("Accept-Encoding")
                .is_some_and(|value| value.contains("gzip")),
            "{fetch:?}"
        );
        assert!(fetch.header("Authorization").is_some());
    }
    assert!(
        !seen.iter().any(|s| s.path().ends_with("/cancel")),
        "a completed statement is never cancelled: {seen:?}"
    );
}

/// A 429 without Retry-After is resubmitted with the SAME requestId and
/// `retry=true`, so Snowflake can deduplicate it.
#[test]
fn rate_limited_submit_is_resubmitted_with_the_same_request_id() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f102";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, before| {
        if request.is_submit() {
            return if before.iter().any(Seen::is_submit) {
                completed_single(HANDLE)
            } else {
                scenarios::rate_limited()
            };
        }
        not_found()
    });
    let h = Harness::new("ratelimit", &cert);
    let run = h.run(
        server.port,
        &[
            "query",
            "run",
            "--profile",
            "sock",
            "--sql",
            "select 1",
            "--json",
        ],
    );
    assert_eq!(run.exit, 0, "{}", run.context());
    assert_eq!(run.envelope["data"]["row_count"], 2, "{}", run.context());
    let seen = server.seen();
    let submits: Vec<&Seen> = seen.iter().filter(|s| s.is_submit()).collect();
    assert_eq!(submits.len(), 2, "{seen:?}");
    let first = submits[0].query("requestId").expect("requestId on submit");
    assert_eq!(submits[1].query("requestId"), Some(first), "{seen:?}");
    // Every submit carries the idempotent-resubmit contract, so the automatic
    // retry is allowed at all (a plain submit is never retried).
    assert_eq!(submits[1].query("retry"), Some("true"), "{seen:?}");
    assert_eq!(
        submits[0].body, submits[1].body,
        "a resubmit carries the identical statement"
    );
}

/// A 422 is a typed statement failure with the SQL error, not a transport
/// error, and nothing is cancelled.
#[test]
fn failed_statement_is_typed() {
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if request.is_submit() {
            return scenarios::statement_failed();
        }
        not_found()
    });
    let h = Harness::new("failed", &cert);
    let run = h.run(
        server.port,
        &[
            "query",
            "run",
            "--profile",
            "sock",
            "--sql",
            "select * from missing_table",
            "--json",
        ],
    );
    assert_eq!(run.exit, 4, "{}", run.context());
    assert_eq!(run.envelope["ok"], false);
    assert_eq!(
        run.envelope["error"]["code"],
        "FSNOW-4002",
        "{}",
        run.context()
    );
    assert!(
        run.envelope["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("syntax error")),
        "{}",
        run.context()
    );
    assert_eq!(server.seen().len(), 1, "{:?}", server.seen());
}

/// `query cancel <handle>` posts to the SQL API cancel endpoint.
#[test]
fn query_cancel_posts_to_the_cancel_endpoint() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f104";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if request.method == "POST" && request.path() == format!("{SUBMIT_PATH}/{HANDLE}/cancel") {
            return scenarios::cancel();
        }
        not_found()
    });
    let h = Harness::new("cancel", &cert);
    let run = h.run(
        server.port,
        &["query", "cancel", HANDLE, "--profile", "sock", "--json"],
    );
    assert_eq!(run.exit, 0, "{}", run.context());
    assert_eq!(run.envelope["ok"], true, "{}", run.context());
    let seen = server.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].path(), format!("{SUBMIT_PATH}/{HANDLE}/cancel"));
    assert_eq!(
        seen[0].header("Authorization"),
        Some(format!("Bearer {CANARY_PAT}").as_str())
    );
}

/// Ctrl-C while a statement runs (reality-check bead E1): the binary fires the
/// SQL API cancel for the in-flight handle and reports `cancelled`.
#[cfg(unix)]
#[test]
fn sigint_cancels_the_statement_in_flight() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f105";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if request.is_submit() || request.is_poll_of(HANDLE) {
            return running(HANDLE);
        }
        if request.method == "POST" && request.path() == format!("{SUBMIT_PATH}/{HANDLE}/cancel") {
            return scenarios::cancel();
        }
        not_found()
    });
    let h = Harness::new("sigint", &cert);
    let args = [
        "query",
        "run",
        "--profile",
        "sock",
        "--sql",
        "select system$wait(600)",
        "--json",
    ];
    let child = h
        .command(server.port, &args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    server.wait_for("the first poll", |seen| {
        seen.iter().any(|s| s.is_poll_of(HANDLE))
    });
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("send SIGINT");
    assert!(status.success());
    let output = child.wait_with_output().expect("binary exits after SIGINT");
    let run = h.finish(&args, output);
    let seen = server.seen();
    assert!(
        seen.iter()
            .any(|s| s.method == "POST" && s.path() == format!("{SUBMIT_PATH}/{HANDLE}/cancel")),
        "the in-flight statement was cancelled server-side: {seen:?}"
    );
    assert_eq!(run.envelope["ok"], false, "{}", run.context());
    assert_eq!(
        run.envelope["outcome_kind"],
        "cancelled",
        "{}",
        run.context()
    );
    // An interrupted command exits 130, as the shell expects.
    assert_eq!(run.exit, 130, "{}", run.context());
    assert_eq!(
        run.envelope["statement_handle"],
        HANDLE,
        "{}",
        run.context()
    );
    // The receipt says the statement was accepted and the cancel acknowledged.
    let receipt = run.envelope["receipt_hash"]
        .as_str()
        .expect("a cancelled run records a receipt")
        .to_owned();
    let show = h.run(server.port, &["receipt", "show", &receipt, "--json"]);
    let shown = show.envelope["data"].to_string();
    assert!(
        shown.contains(r#""accepted_by_snowflake":true"#)
            && shown.contains(r#""remote_cancel":{"acknowledged":true"#)
            && shown.contains(HANDLE),
        "{}",
        show.context()
    );
}

/// Reality-check bead E2: over `mcp serve --stdio`, a `notifications/cancelled`
/// for a running `query_run` cancels the statement server-side while the call
/// is still running, and the call answers `cancelled`.
#[cfg(feature = "mcp")]
#[test]
fn an_mcp_cancel_notification_cancels_the_running_statement() {
    use std::io::{BufRead as _, Write as _};
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f160";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if request.is_submit() || request.is_poll_of(HANDLE) {
            return running(HANDLE);
        }
        if request.method == "POST" && request.path() == format!("{SUBMIT_PATH}/{HANDLE}/cancel") {
            return scenarios::cancel();
        }
        not_found()
    });
    let h = Harness::new("mcpcancel", &cert);
    let mut child = KillOnDrop(
        h.command(server.port, &["mcp", "serve", "--stdio"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn mcp serve --stdio"),
    );
    let stdout = child.stdout.take().expect("stdout");
    let (lines, received) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
        {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let mut stdin = child.stdin.take().expect("stdin");
    let mut send = |line: &str| {
        stdin.write_all(line.as_bytes()).expect("write");
        stdin.write_all(b"\n").expect("newline");
        stdin.flush().expect("flush");
    };
    send(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"fsnow-e2e","version":"0"}}}"#,
    );
    send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
    send(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_run","arguments":{"profile":"sock","sql":"select system$wait(600)"}}}"#,
    );
    server.wait_for("the first poll", |seen| {
        seen.iter().any(|s| s.is_poll_of(HANDLE))
    });
    send(
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2,"reason":"user pressed stop"}}"#,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut answer = None;
    while answer.is_none() && std::time::Instant::now() < deadline {
        if let Ok(line) = received.recv_timeout(std::time::Duration::from_secs(1))
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&line)
            && value["id"] == 2
        {
            answer = Some(value);
        }
    }
    let is_cancel =
        |s: &Seen| s.method == "POST" && s.path() == format!("{SUBMIT_PATH}/{HANDLE}/cancel");
    assert_eq!(
        server.seen().iter().filter(|s| is_cancel(s)).count(),
        1,
        "the notification cancelled its statement: {:?}",
        server.seen()
    );
    // A client that closes its input mid-call cancels the call too.
    send(
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query_run","arguments":{"profile":"sock","sql":"select system$wait(600)"}}}"#,
    );
    server.wait_for("the second call's first poll", |seen| {
        seen.iter().filter(|s| s.is_submit()).count() == 2
            && seen
                .iter()
                .rev()
                .take_while(|s| !s.is_submit())
                .any(|s| s.is_poll_of(HANDLE))
    });
    assert_eq!(
        server.seen().iter().filter(|s| is_cancel(s)).count(),
        1,
        "nothing cancels the second call before stdin closes"
    );
    drop(send);
    drop(stdin);
    server.wait_for("the cancel after stdin closed", |seen| {
        seen.iter().filter(|s| is_cancel(s)).count() == 2
    });
    let _ = child.kill();
    let _ = child.wait();
    let answer = answer.expect("the cancelled call answers");
    let text = answer.to_string();
    assert!(text.contains("cancelled"), "{text}");
    assert!(!text.contains(CANARY_PAT), "{text}");
}

/// Send one HTTP/1.1 request to `mcp serve --http` and return (status, body).
#[cfg(feature = "mcp")]
fn mcp_http_post(port: u16, token: &str, body: &str) -> (u16, String) {
    use std::io::{Read as _, Write as _};
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(90)))
        .expect("read timeout");
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).expect("write");
    let mut raw = Vec::new();
    let _ = stream.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, payload) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    (status, payload.to_owned())
}

/// The CLI envelope inside an MCP `tools/call` answer, without the fields
/// that differ per invocation.
#[cfg(feature = "mcp")]
fn tool_envelope(answer: &str) -> serde_json::Value {
    let answer: serde_json::Value = serde_json::from_str(answer).expect("JSON-RPC answer");
    let text = answer["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("tool text in {answer}"));
    stable_envelope(serde_json::from_str(text).expect("envelope JSON"))
}

/// Drop what legitimately differs between two runs of the same statement.
#[cfg(feature = "mcp")]
fn stable_envelope(mut envelope: serde_json::Value) -> serde_json::Value {
    if let Some(object) = envelope.as_object_mut() {
        for key in [
            "request_id",
            "receipt_hash",
            "safe_next_commands",
            "started_at",
            "finished_at",
            "duration_ms",
        ] {
            object.remove(key);
        }
    }
    if let Some(data) = envelope["data"].as_object_mut() {
        data.remove("sql_api_request_id");
    }
    envelope
}

/// A receipt with what differs between two runs of one statement removed:
/// ids of the invocation and the SQL API request, timestamps, the content
/// address (it hashes those), the generated query tag (it names the
/// invocation), and the audit trail (its own ids and times).
#[cfg(feature = "mcp")]
fn without_invocation_identity(mut value: serde_json::Value) -> serde_json::Value {
    const VOLATILE: &[&str] = &[
        "receipt_id",
        "trace_id",
        "sql_api_request_id",
        "request_id",
        "created_at_ms",
        "created_at",
        "content_address",
        "query_tag",
        "audit_events",
    ];
    match &mut value {
        serde_json::Value::Object(map) => {
            for key in VOLATILE {
                map.remove(*key);
            }
            for child in map.values_mut() {
                *child = without_invocation_identity(child.take());
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                *item = without_invocation_identity(item.take());
            }
        }
        _ => {}
    }
    value
}

/// Reality-check beads oj0.32 and E2 over `mcp serve --http` with the real
/// TLS transport: an authorized `query_run` answers the same envelope as the
/// CLI for the same statement (volatile fields aside), and a
/// `notifications/cancelled` sent on another connection while a call runs
/// cancels its statement server-side.
#[cfg(feature = "mcp")]
#[test]
fn mcp_over_http_matches_the_cli_and_a_cancel_notification_cancels_the_call() {
    use std::io::BufRead as _;
    const DONE: &str = "01b2c3d4-0000-0000-0000-00000000f170";
    const HELD: &str = "01b2c3d4-0000-0000-0000-00000000f171";
    const HUNG_UP: &str = "01b2c3d4-0000-0000-0000-00000000f172";
    const TOKEN: &str = "fsnow-socket-token-0123456789abcdef0123456789";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if request.is_submit() {
            let statement = request.body_json()["statement"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            return if statement.contains("system$wait(601)") {
                running(HUNG_UP)
            } else if statement.contains("system$wait") {
                running(HELD)
            } else {
                completed_single(DONE)
            };
        }
        for handle in [HELD, HUNG_UP] {
            if request.is_poll_of(handle) {
                return running(handle);
            }
            if request.method == "POST"
                && request.path() == format!("{SUBMIT_PATH}/{handle}/cancel")
            {
                return scenarios::cancel();
            }
        }
        not_found()
    });
    let h = Harness::new("mcphttp", &cert);
    let cli = h.run(
        server.port,
        &[
            "query",
            "run",
            "--profile",
            "sock",
            "--sql",
            "select 1",
            "--json",
        ],
    );
    assert_eq!(cli.exit, 0, "{}", cli.context());

    let mut child = KillOnDrop(
        h.command(server.port, &["mcp", "serve", "--http", "127.0.0.1:0"])
            .env("FRANKEN_SNOWFLAKE_MCP_TOKEN", TOKEN)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn mcp serve --http"),
    );
    let stderr = child.stderr.take().expect("stderr");
    let (lines, received) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let port: u16 = loop {
        let line = received
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("the server announces its address");
        if let Some(rest) = line.split("http://127.0.0.1:").nth(1)
            && let Some(port) = rest.split('/').next().and_then(|p| p.parse().ok())
        {
            break port;
        }
    };

    // The server refuses tools/call until the client has initialized.
    let (status, answer) = mcp_http_post(
        port,
        TOKEN,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fsnow-e2e","version":"0"}}}"#,
    );
    assert_eq!(status, 200, "{answer}");

    // Parity: the same statement through MCP answers the CLI's envelope.
    let (status, answer) = mcp_http_post(
        port,
        TOKEN,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"query_run","arguments":{"profile":"sock","sql":"select 1"}}}"#,
    );
    assert_eq!(status, 200, "{answer}");
    assert_eq!(
        tool_envelope(&answer),
        stable_envelope(cli.envelope.clone()),
        "MCP and CLI envelopes differ"
    );
    // Receipts too (bead oj0.32): the MCP call recorded the same receipt as
    // the CLI run, invocation identity and timing aside.
    let answered: serde_json::Value = serde_json::from_str(&answer).expect("JSON-RPC answer");
    let mcp_envelope: serde_json::Value = serde_json::from_str(
        answered["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default(),
    )
    .expect("envelope JSON");
    let receipt_of = |envelope: &serde_json::Value| {
        envelope["receipt_hash"]
            .as_str()
            .expect("a receipt hash")
            .to_owned()
    };
    let (cli_receipt, mcp_receipt) = (receipt_of(&cli.envelope), receipt_of(&mcp_envelope));
    assert_ne!(cli_receipt, mcp_receipt, "two runs, two receipts");
    let shown = |hash: &str| {
        let run = h.run(server.port, &["receipt", "show", hash, "--json"]);
        assert_eq!(run.exit, 0, "{}", run.context());
        without_invocation_identity(run.envelope["data"].clone())
    };
    assert_eq!(
        shown(&cli_receipt),
        shown(&mcp_receipt),
        "the MCP call's receipt differs from the CLI's"
    );

    // Cancellation: call on one connection, cancel on another.
    let call = std::thread::spawn(move || {
        mcp_http_post(
            port,
            TOKEN,
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"query_run","arguments":{"profile":"sock","sql":"select system$wait(600)"}}}"#,
        )
    });
    server.wait_for("the held statement's first poll", |seen| {
        seen.iter().any(|s| s.is_poll_of(HELD))
    });
    let (status, _) = mcp_http_post(
        port,
        TOKEN,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"user pressed stop"}}"#,
    );
    assert!(status == 200 || status == 202 || status == 204, "{status}");
    let (status, answer) = call.join().expect("the cancelled call returns");

    // Hang-up: a client that closes its connection mid-call, sending nothing
    // else, cancels its statement too.
    let is_hang_up_cancel =
        |s: &Seen| s.method == "POST" && s.path() == format!("{SUBMIT_PATH}/{HUNG_UP}/cancel");
    {
        use std::io::Write as _;
        let body = r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"query_run","arguments":{"profile":"sock","sql":"select system$wait(601)"}}}"#;
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        write!(
            stream,
            "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("write");
        server.wait_for("the hung-up call's first poll", |seen| {
            seen.iter().any(|s| s.is_poll_of(HUNG_UP))
        });
        assert!(
            !server.seen().iter().any(is_hang_up_cancel),
            "nothing cancels the call while its client is connected"
        );
    }
    server.wait_for("the cancel after the hang-up", |seen| {
        seen.iter().any(is_hang_up_cancel)
    });
    let seen = server.seen();
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        seen.iter()
            .any(|s| s.method == "POST" && s.path() == format!("{SUBMIT_PATH}/{HELD}/cancel")),
        "the running statement was cancelled server-side: {seen:?}"
    );
    assert!(!answer.contains(CANARY_PAT), "{answer}");
    assert!(
        status != 200 || answer.contains("cancel"),
        "the call answers as cancelled: {status} {answer}"
    );
}

/// Negative: a server whose certificate does not chain to the profile's CA
/// bundle gets no request at all; verification is real, not skipped.
#[test]
fn a_certificate_outside_the_ca_bundle_is_refused_before_any_request() {
    let served = TestCert::mint();
    let trusted = TestCert::mint();
    let server = MockServer::start(&served, |_, _| completed_single("never"));
    let h = Harness::new("foreign-ca", &trusted);
    let run = h.run(
        server.port,
        &[
            "query",
            "run",
            "--profile",
            "sock",
            "--sql",
            "select 1",
            "--json",
        ],
    );
    assert_eq!(run.envelope["ok"], false, "{}", run.context());
    assert_eq!(
        run.envelope["error"]["code"],
        "FSNOW-5001",
        "{}",
        run.context()
    );
    assert!(server.seen().is_empty(), "{:?}", server.seen());
}

/// Negative: without the runtime opt-in, the SAME binary refuses the loopback
/// endpoint as a profile error before any socket (the production host rule).
#[test]
fn loopback_endpoint_needs_the_testkit_opt_in() {
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |_, _| completed_single("never"));
    let h = Harness::new("no-opt-in", &cert);
    let args = [
        "query",
        "run",
        "--profile",
        "sock",
        "--sql",
        "select 1",
        "--json",
    ];
    let mut command = h.command(server.port, &args);
    command.env_remove("FRANKEN_SNOWFLAKE_TESTKIT_ENDPOINT");
    let run = h.finish(&args, command.output().expect("spawn"));
    assert_eq!(run.exit, 3, "{}", run.context());
    assert_eq!(
        run.envelope["error"]["code"],
        "FSNOW-2002",
        "{}",
        run.context()
    );
    assert!(server.seen().is_empty(), "{:?}", server.seen());
}

/// Negative: an unreadable CA bundle is a typed profile error, never a silent
/// fallback to the OS trust store.
#[test]
fn an_unreadable_ca_bundle_is_a_profile_error() {
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |_, _| completed_single("never"));
    let h = Harness::new("bad-bundle", &cert);
    let args = [
        "query",
        "run",
        "--profile",
        "sock",
        "--sql",
        "select 1",
        "--json",
    ];
    let mut command = h.command(server.port, &args);
    command.env("FRANKEN_SNOWFLAKE_SOCK_CA_BUNDLE", h.dir.join("absent.pem"));
    let run = h.finish(&args, command.output().expect("spawn"));
    assert_eq!(run.exit, 3, "{}", run.context());
    assert_eq!(
        run.envelope["error"]["code"],
        "FSNOW-2002",
        "{}",
        run.context()
    );
    assert!(server.seen().is_empty(), "{:?}", server.seen());
}

/// A 408 from a poll is the typed statement timeout (the server already
/// cancelled the statement), never a transport error.
#[test]
fn statement_timeout_on_poll_is_typed() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f108";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if request.is_submit() {
            return running(HANDLE);
        }
        if request.is_poll_of(HANDLE) {
            return scenarios::statement_timeout();
        }
        if request.path().ends_with("/cancel") {
            return scenarios::cancel();
        }
        not_found()
    });
    let h = Harness::new("timeout", &cert);
    let run = h.run(
        server.port,
        &[
            "query",
            "run",
            "--profile",
            "sock",
            "--sql",
            "select 1",
            "--json",
        ],
    );
    assert_eq!(run.exit, 4, "{}", run.context());
    assert_eq!(
        run.envelope["error"]["code"],
        "FSNOW-4003",
        "{}",
        run.context()
    );
}

/// A partition that cannot be fetched fails the run AND cancels the
/// statement server-side (no orphan keeps the warehouse busy).
#[test]
fn a_failed_partition_fetch_cancels_the_statement() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f109";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if request.is_submit() {
            return completed_multi(HANDLE);
        }
        if request.method == "POST" && request.path() == format!("{SUBMIT_PATH}/{HANDLE}/cancel") {
            return scenarios::cancel();
        }
        match request.query("partition") {
            Some("1") => scenarios::gzip_partition(),
            _ => not_found(),
        }
    });
    let h = Harness::new("partition-error", &cert);
    let run = h.run(
        server.port,
        &[
            "query",
            "run",
            "--profile",
            "sock",
            "--sql",
            "select 1",
            "--json",
        ],
    );
    assert_eq!(run.envelope["ok"], false, "{}", run.context());
    assert!(
        run.envelope["error"]["code"]
            .as_str()
            .is_some_and(|code| code.starts_with("FSNOW-")),
        "{}",
        run.context()
    );
    let seen = server.seen();
    assert!(
        seen.iter()
            .any(|s| s.method == "POST" && s.path() == format!("{SUBMIT_PATH}/{HANDLE}/cancel")),
        "the failed run cancelled its statement: {seen:?}"
    );
}

/// `--limit` stops early: the inline rows satisfy the cap, so no partition
/// is downloaded at all.
#[test]
fn a_row_cap_satisfied_inline_fetches_no_partition() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f110";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if request.is_submit() {
            return completed_multi(HANDLE);
        }
        match request.query("partition") {
            Some("1") => scenarios::gzip_partition(),
            Some("2") => MockHttpResponse::json(200, br#"{"data":[["5","epsilon"]]}"#.to_vec()),
            _ => not_found(),
        }
    });
    let h = Harness::new("row-cap", &cert);
    let run = h.run(
        server.port,
        &[
            "query",
            "run",
            "--profile",
            "sock",
            "--sql",
            "select 1",
            "--limit",
            "2",
            "--json",
        ],
    );
    assert_eq!(run.exit, 0, "{}", run.context());
    assert_eq!(
        run.envelope["data"]["returned_rows"],
        2,
        "{}",
        run.context()
    );
    // Only the inline partition 0.
    assert_eq!(
        run.envelope["data"]["partitions_fetched"],
        1,
        "{}",
        run.context()
    );
    let seen = server.seen();
    assert!(
        !seen.iter().any(|s| s.query("partition").is_some()),
        "no partition download past the cap: {seen:?}"
    );
}

/// The DML result Snowflake returns for a one-row INSERT.
fn inserted_one(handle: &str) -> MockHttpResponse {
    json(
        200,
        &serde_json::json!({
            "resultSetMetaData": {
                "numRows": 1,
                "format": "jsonv2",
                "partitionInfo": [{"rowCount": 1, "uncompressedSize": 16}],
                "rowType": [{"name": "number of rows inserted", "type": "fixed",
                             "scale": 0, "precision": 19, "nullable": false}]
            },
            "data": [["1"]],
            "code": "090001",
            "sqlState": "00000",
            "statementHandle": handle,
            "statementStatusUrl": format!("{SUBMIT_PATH}/{handle}"),
            "message": "Statement executed successfully.",
            "stats": {"numRowsInserted": 1}
        }),
    )
}

/// The write ladder over the wire: a dry run issues a token, the confirmed
/// write submits the dry run's id as the SQL API requestId (so a replay is
/// deduplicated server-side), the audit ledger records the submission, and a
/// second use of the spent token never reaches the server.
#[test]
fn a_confirmed_write_submits_its_dry_run_id_and_is_single_use() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f111";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if request.is_submit() {
            return inserted_one(HANDLE);
        }
        not_found()
    });
    let h = Harness::new("write", &cert);
    let sql = "insert into t values (1)";
    let write = |extra: &[&str]| {
        let mut args = vec!["query", "write", "--profile", "sock", "--sql", sql];
        args.extend_from_slice(extra);
        args.push("--json");
        let mut command = h.command(server.port, &args);
        command
            .env("FRANKEN_SNOWFLAKE_SOCK_WRITE_ENABLED", "true")
            .env("FRANKEN_SNOWFLAKE_SOCK_WRITE_REQUIRE_CONFIRM", "true");
        h.finish(&args, command.output().expect("spawn"))
    };
    let dry = write(&["--dry-run"]);
    assert_eq!(dry.exit, 0, "{}", dry.context());
    assert!(server.seen().is_empty(), "a dry run never submits");
    let token = dry.envelope["data"]["required_confirmation_token"]
        .as_str()
        .expect("token")
        .to_owned();
    let id = token
        .strip_prefix("confirm:insert:")
        .expect("token shape")
        .to_owned();

    let confirmed = write(&["--confirm", token.as_str()]);
    assert_eq!(confirmed.exit, 0, "{}", confirmed.context());
    assert_eq!(confirmed.envelope["ok"], true, "{}", confirmed.context());
    let seen = server.seen();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].query("requestId"), Some(id.as_str()), "{seen:?}");
    assert_eq!(seen[0].query("retry"), Some("true"), "{seen:?}");
    assert_eq!(seen[0].body_json()["statement"], sql);
    let ledger = fs::read_to_string(h.dir.join("store").join("query_audit_log.jsonl"))
        .expect("audit ledger");
    assert!(ledger.contains("write_submitted"), "{ledger}");

    let replay = write(&["--confirm", token.as_str()]);
    assert_ne!(
        replay.exit,
        0,
        "a spent token is refused: {}",
        replay.context()
    );
    assert_eq!(
        server.seen().len(),
        1,
        "the replay never reached the server"
    );
}

/// Key-pair JWT: a 401 on submit re-signs once and resubmits with the same
/// requestId; the token type header says KEYPAIR_JWT.
#[test]
fn a_401_on_submit_re_signs_the_jwt_once() {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f112";
    let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2_048).expect("RSA key");
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("PKCS#8 PEM")
        .to_string();
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, before| {
        if request.is_submit() {
            return if before.iter().any(Seen::is_submit) {
                completed_single(HANDLE)
            } else {
                json(
                    401,
                    &serde_json::json!({"code": "390144", "message": "JWT token is invalid."}),
                )
            };
        }
        not_found()
    });
    let h = Harness::new("jwt", &cert);
    let args = [
        "query",
        "run",
        "--profile",
        "sock",
        "--sql",
        "select 1",
        "--json",
    ];
    let mut command = h.command(server.port, &args);
    command
        .env("FRANKEN_SNOWFLAKE_SOCK_AUTH", "key_pair_jwt")
        .env_remove("FRANKEN_SNOWFLAKE_SOCK_PAT")
        .env("FRANKEN_SNOWFLAKE_SOCK_PRIVATE_KEY_PEM", &pem);
    let run = h.finish(&args, command.output().expect("spawn"));
    assert_eq!(run.exit, 0, "{}", run.context());
    let seen = server.seen();
    let submits: Vec<&Seen> = seen.iter().filter(|s| s.is_submit()).collect();
    assert_eq!(submits.len(), 2, "{seen:?}");
    for submit in &submits {
        assert_eq!(
            submit.header("X-Snowflake-Authorization-Token-Type"),
            Some("KEYPAIR_JWT")
        );
        assert!(
            submit
                .header("Authorization")
                .is_some_and(|value| value.starts_with("Bearer ey")),
            "{submit:?}"
        );
    }
    assert_eq!(submits[0].query("requestId"), submits[1].query("requestId"));
    assert!(
        !run.stderr.contains("PRIVATE KEY") && !run.envelope.to_string().contains("PRIVATE KEY")
    );
}

/// A partition larger than Asupersync's 16 MiB default body cap is read in
/// full: the transport reads up to the configured 64 MiB partition limit.
#[test]
fn a_partition_larger_than_16_mib_is_read() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f113";
    const ROWS: usize = 17_500;
    let cell = "x".repeat(1_000);
    let mut big = String::from(r#"{"data":["#);
    for index in 0..ROWS {
        if index > 0 {
            big.push(',');
        }
        big.push_str(&format!(r#"["{index}","{cell}"]"#));
    }
    big.push_str("]}");
    assert!(big.len() > 16 * 1024 * 1024, "{} bytes", big.len());
    let big = big.into_bytes();
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, move |request, _| {
        if request.is_submit() {
            let mut body: serde_json::Value =
                serde_json::from_slice(scenarios::RESP_200_MULTI).expect("200 golden");
            body["statementHandle"] = HANDLE.into();
            body["resultSetMetaData"]["numRows"] = (2 + ROWS).into();
            body["resultSetMetaData"]["partitionInfo"] = serde_json::json!([
                {"rowCount": 2, "uncompressedSize": 64},
                {"rowCount": ROWS, "uncompressedSize": big.len()}
            ]);
            return json(200, &body);
        }
        match request.query("partition") {
            Some("1") => MockHttpResponse::json(200, big.clone()),
            _ => not_found(),
        }
    });
    let h = Harness::new("big-partition", &cert);
    let run = h.run(
        server.port,
        &[
            "query",
            "run",
            "--profile",
            "sock",
            "--sql",
            "select 1",
            "--limit",
            "3",
            "--json",
        ],
    );
    assert_eq!(run.exit, 0, "{}", run.context());
    assert_eq!(
        run.envelope["data"]["partitions_fetched"],
        2,
        "{}",
        run.context()
    );
    assert_eq!(
        run.envelope["data"]["returned_rows"],
        3,
        "{}",
        run.context()
    );
    // The first partition-1 row: day 0 of the DATE column.
    assert_eq!(
        run.envelope["data"]["rows"][2][0],
        "1970-01-01",
        "{}",
        run.context()
    );
}

/// `--raw-cells` returns the SQL API wire strings (reality-check bead C1).
#[test]
fn raw_cells_returns_the_wire_strings() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f114";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if request.is_submit() {
            return completed_single(HANDLE);
        }
        not_found()
    });
    let h = Harness::new("raw-cells", &cert);
    let args = [
        "query",
        "run",
        "--profile",
        "sock",
        "--sql",
        "select 1",
        "--raw-cells",
        "--json",
    ];
    let run = h.run(server.port, &args);
    assert_eq!(run.exit, 0, "{}", run.context());
    let data = &run.envelope["data"];
    assert_eq!(data["row_encoding"], "jsonv2.wire", "{}", run.context());
    assert_eq!(data["rows"][0][0], "18262", "{}", run.context());
    assert_eq!(data["rows"][0][2], "1.50", "{}", run.context());
    assert_eq!(data["columns"][0]["json_repr"], "wire", "{}", run.context());
}

/// The discovery-to-query path over the wire: `catalog scan` runs its
/// INFORMATION_SCHEMA statements (filters bound as parameters, never
/// interpolated) and its relation pass (keys, the view's dependencies,
/// stages, file formats), and persists a snapshot; `dataset inspect` reads it
/// offline; the graph verbs walk it; `query run --dataset` compiles and
/// submits the pushed-down SQL and returns typed rows. A second scan asking
/// for tags the role cannot read is `partial_success`, never a silent empty.
#[test]
fn catalog_scan_then_dataset_inspect_then_dataset_query() {
    const TABLES: &str = "01b2c3d4-0000-0000-0000-00000000f120";
    const COLUMNS: &str = "01b2c3d4-0000-0000-0000-00000000f121";
    const QUERY: &str = "01b2c3d4-0000-0000-0000-00000000f122";
    const RELATION: &str = "01b2c3d4-0000-0000-0000-00000000f123";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if !request.is_submit() {
            return not_found();
        }
        let statement = request.body_json()["statement"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let text = |name| (name, "TEXT", None, None);
        if statement.contains("INFORMATION_SCHEMA.TABLES") {
            return result_set(
                TABLES,
                &[
                    ("TABLE_CATALOG", "TEXT", None, None),
                    ("TABLE_SCHEMA", "TEXT", None, None),
                    ("TABLE_NAME", "TEXT", None, None),
                    ("TABLE_TYPE", "TEXT", None, None),
                    ("COMMENT", "TEXT", None, None),
                    ("ROW_COUNT", "FIXED", Some(38), Some(0)),
                    ("BYTES", "FIXED", Some(38), Some(0)),
                ],
                &[
                    vec![
                        Some("DB"),
                        Some("PUBLIC"),
                        Some("EVENTS"),
                        Some("BASE TABLE"),
                        Some("daily events"),
                        Some("3"),
                        Some("4096"),
                    ],
                    vec![
                        Some("DB"),
                        Some("PUBLIC"),
                        Some("EVENTS_DAILY"),
                        Some("VIEW"),
                        None,
                        None,
                        None,
                    ],
                ],
            );
        }
        if statement.starts_with("SHOW PRIMARY KEYS") {
            return result_set(
                RELATION,
                &[
                    text("created_on"),
                    text("database_name"),
                    text("schema_name"),
                    text("table_name"),
                    text("column_name"),
                    ("key_sequence", "FIXED", Some(38), Some(0)),
                    text("comment"),
                    text("constraint_name"),
                ],
                &[vec![
                    Some("2026-09-01"),
                    Some("DB"),
                    Some("PUBLIC"),
                    Some("EVENTS"),
                    Some("ENTITY_ID"),
                    Some("1"),
                    None,
                    Some("PK_EVENTS"),
                ]],
            );
        }
        if statement.contains("GET_OBJECT_REFERENCES") {
            return result_set(
                RELATION,
                &[
                    text("DATABASE_NAME"),
                    text("SCHEMA_NAME"),
                    text("VIEW_NAME"),
                    text("REFERENCED_DATABASE_NAME"),
                    text("REFERENCED_SCHEMA_NAME"),
                    text("REFERENCED_OBJECT_NAME"),
                    text("REFERENCED_OBJECT_TYPE"),
                ],
                &[vec![
                    Some("DB"),
                    Some("PUBLIC"),
                    Some("EVENTS_DAILY"),
                    Some("DB"),
                    Some("PUBLIC"),
                    Some("EVENTS"),
                    Some("TABLE"),
                ]],
            );
        }
        if statement.contains("INFORMATION_SCHEMA.STAGES") {
            return result_set(
                RELATION,
                &[
                    text("STAGE_CATALOG"),
                    text("STAGE_SCHEMA"),
                    text("STAGE_NAME"),
                    text("STAGE_URL"),
                    text("STAGE_REGION"),
                    text("STAGE_TYPE"),
                    text("COMMENT"),
                ],
                &[vec![
                    Some("DB"),
                    Some("PUBLIC"),
                    Some("LANDING"),
                    None,
                    None,
                    Some("Internal Named"),
                    None,
                ]],
            );
        }
        if statement.contains("TAG_REFERENCES") {
            return scenarios::statement_failed();
        }
        if statement.contains("INFORMATION_SCHEMA.TABLE_CONSTRAINTS")
            || statement.contains("INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS")
            || statement.contains("INFORMATION_SCHEMA.FILE_FORMATS")
        {
            return result_set(RELATION, &[text("CONSTRAINT_NAME")], &[]);
        }
        if statement.contains("INFORMATION_SCHEMA.COLUMNS") {
            let column = |name, ordinal, kind, precision, scale| {
                vec![
                    Some("DB"),
                    Some("PUBLIC"),
                    Some("EVENTS"),
                    Some(name),
                    Some(ordinal),
                    Some(kind),
                    precision,
                    scale,
                    None,
                    Some("YES"),
                    None,
                ]
            };
            return result_set(
                COLUMNS,
                &[
                    ("TABLE_CATALOG", "TEXT", None, None),
                    ("TABLE_SCHEMA", "TEXT", None, None),
                    ("TABLE_NAME", "TEXT", None, None),
                    ("COLUMN_NAME", "TEXT", None, None),
                    ("ORDINAL_POSITION", "FIXED", Some(9), Some(0)),
                    ("DATA_TYPE", "TEXT", None, None),
                    ("NUMERIC_PRECISION", "FIXED", Some(9), Some(0)),
                    ("NUMERIC_SCALE", "FIXED", Some(9), Some(0)),
                    ("CHARACTER_MAXIMUM_LENGTH", "FIXED", Some(9), Some(0)),
                    ("IS_NULLABLE", "TEXT", None, None),
                    ("COMMENT", "TEXT", None, None),
                ],
                &[
                    column("EVENT_DATE", "1", "DATE", None, None),
                    column("ENTITY_ID", "2", "TEXT", None, None),
                    column("AMOUNT", "3", "NUMBER", Some("38"), Some("2")),
                ],
            );
        }
        result_set(
            QUERY,
            &[
                ("EVENT_DATE", "DATE", None, None),
                ("ENTITY_ID", "TEXT", None, None),
                ("AMOUNT", "FIXED", Some(38), Some(2)),
            ],
            &[vec![Some("18262"), Some("ENTITY123"), Some("12.50")]],
        )
    });
    let h = Harness::new("catalog", &cert);

    let scan = h.run(
        server.port,
        &[
            "catalog",
            "scan",
            "sock",
            "--database",
            "DB",
            "--schema",
            "PUBLIC",
            "--json",
        ],
    );
    assert_eq!(scan.exit, 0, "{}", scan.context());
    assert_eq!(
        scan.envelope["outcome_kind"],
        "success",
        "{}",
        scan.context()
    );
    let data = &scan.envelope["data"];
    assert_eq!(data["store"]["persisted"], true, "{}", scan.context());
    let dataset = &data["datasets"][0];
    assert_eq!(dataset["object"], "EVENTS", "{}", scan.context());
    assert_eq!(dataset["column_count"], 3, "{}", scan.context());
    assert_eq!(
        dataset["primary_key"],
        serde_json::json!(["ENTITY_ID"]),
        "{}",
        scan.context()
    );
    assert_eq!(
        data["relations"]["view_depends_on"],
        1,
        "{}",
        scan.context()
    );
    assert_eq!(data["relations"]["stage_count"], 1, "{}", scan.context());
    // Field roles inferred from the discovered column types.
    assert_eq!(dataset["roles"]["time_index"][0], "EVENT_DATE");
    assert_eq!(dataset["roles"]["entity_key"][0], "ENTITY_ID");
    let dataset_id = dataset["dataset_id"]
        .as_str()
        .expect("dataset id")
        .to_owned();
    // TABLES, COLUMNS, then the relation pass: SHOW PRIMARY KEYS, the two
    // constraint views, STAGES, FILE_FORMATS, and one GET_OBJECT_REFERENCES
    // for the view (no external table, tags not requested).
    let discovery: Vec<Seen> = server.seen();
    assert_eq!(discovery.len(), 8, "{discovery:?}");
    for statement in &discovery {
        let body = statement.body_json();
        let sql = body["statement"].as_str().unwrap_or_default();
        assert!(
            !sql.contains("'DB'") && !sql.contains("'PUBLIC'"),
            "filters are bound, never interpolated: {sql}"
        );
        if sql.starts_with("SHOW") {
            assert_eq!(sql, r#"SHOW PRIMARY KEYS IN SCHEMA "DB"."PUBLIC""#);
        } else if sql.contains("GET_OBJECT_REFERENCES") {
            assert_eq!(body["bindings"]["3"]["value"], "\"EVENTS_DAILY\"", "{body}");
        } else {
            assert_eq!(body["bindings"]["1"]["value"], "DB", "{body}");
        }
    }

    let inspect = h.run(server.port, &["dataset", "inspect", &dataset_id, "--json"]);
    assert_eq!(inspect.exit, 0, "{}", inspect.context());
    assert_eq!(server.seen().len(), 8, "inspect is offline");

    let query = h.run(
        server.port,
        &[
            "query",
            "run",
            "--dataset",
            &dataset_id,
            "--limit",
            "5",
            "--json",
        ],
    );
    assert_eq!(query.exit, 0, "{}", query.context());
    let seen = server.seen();
    assert_eq!(seen.len(), 9, "{seen:?}");
    let submitted = seen[8].body_json();
    let sql = submitted["statement"].as_str().unwrap_or_default();
    assert!(sql.contains("EVENTS"), "{sql}");
    assert_eq!(
        query.envelope["data"]["rows"],
        serde_json::json!([["2020-01-01", "ENTITY123", "12.50"]]),
        "{}",
        query.context()
    );

    // Graph verbs over the persisted snapshot (reality-check bead oj0.34),
    // all offline: the mock sees no further request.
    let relates = h.run(
        server.port,
        &["catalog", "relates", "sock", "db.public.events", "--json"],
    );
    assert_eq!(relates.exit, 0, "{}", relates.context());
    let related: Vec<String> = relates.envelope["data"]["related"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry["node"]["qualified_name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    for expected in ["DB.PUBLIC", "DB.PUBLIC.EVENTS.AMOUNT", "DB"] {
        assert!(
            related.iter().any(|name| name == expected),
            "{expected}: {related:?}"
        );
    }
    // Lineage follows dependencies, not containment: the view reads the
    // table, and the table is read by the view and by its dataset.
    let up = h.run(
        server.port,
        &[
            "catalog",
            "lineage",
            "sock",
            "DB.PUBLIC.EVENTS_DAILY",
            "--up",
            "--json",
        ],
    );
    assert_eq!(up.exit, 0, "{}", up.context());
    assert_eq!(up.envelope["data"]["count"], 1, "{}", up.context());
    let source = &up.envelope["data"]["nodes"][0];
    assert_eq!(
        source["node"]["qualified_name"],
        "DB.PUBLIC.EVENTS",
        "{}",
        up.context()
    );
    assert_eq!(source["via"], "view_depends_on", "{}", up.context());
    let down = h.run(
        server.port,
        &[
            "catalog",
            "lineage",
            "sock",
            "DB.PUBLIC.EVENTS",
            "--down",
            "--json",
        ],
    );
    let dependents: Vec<String> = down.envelope["data"]["nodes"]
        .as_array()
        .map(|nodes| {
            nodes
                .iter()
                .map(|step| format!("{}:{}", step["via"], step["node"]["kind"]))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        dependents.contains(&r#""view_depends_on":"object""#.to_owned())
            && dependents.contains(&r#""dataset_object":"dataset""#.to_owned()),
        "{dependents:?} {}",
        down.context()
    );
    assert!(
        !down.envelope["data"]["nodes"]
            .to_string()
            .contains("DB.PUBLIC.EVENTS.AMOUNT"),
        "columns are containment, not lineage: {}",
        down.context()
    );
    let cycles = h.run(server.port, &["catalog", "cycles", "sock", "--json"]);
    assert_eq!(cycles.exit, 0, "{}", cycles.context());
    assert_eq!(cycles.envelope["data"]["count"], 0, "{}", cycles.context());
    let unknown = h.run(
        server.port,
        &["catalog", "relates", "sock", "DB.PUBLIC.EVENTZ", "--json"],
    );
    assert_eq!(
        unknown.envelope["error"]["code"],
        "FSNOW-7002",
        "{}",
        unknown.context()
    );
    assert!(
        unknown.envelope["did_you_mean"]
            .to_string()
            .contains("DB.PUBLIC.EVENTS"),
        "{}",
        unknown.context()
    );
    // Search ranks by the query's words, offline; nothing matching is an
    // empty success, not an error (reality-check bead oj0.36).
    let search = h.run(
        server.port,
        &["catalog", "search", "sock", "daily events", "--json"],
    );
    assert_eq!(search.exit, 0, "{}", search.context());
    assert_eq!(
        search.envelope["data"]["hits"][0]["qualified_name"],
        "DB.PUBLIC.EVENTS_DAILY",
        "both words beat one: {}",
        search.context()
    );
    assert_eq!(search.envelope["data"]["count"], 2, "{}", search.context());
    let amount = h.run(
        server.port,
        &["catalog", "search", "sock", "amount", "--json"],
    );
    assert_eq!(
        amount.envelope["data"]["hits"][0]["matches"][0]["text"],
        "AMOUNT",
        "{}",
        amount.context()
    );
    let nothing = h.run(
        server.port,
        &["catalog", "search", "sock", "zebra", "--json"],
    );
    assert_eq!(nothing.exit, 0, "{}", nothing.context());
    assert_eq!(
        nothing.envelope["data"]["count"],
        0,
        "{}",
        nothing.context()
    );
    assert_eq!(server.seen().len(), 9, "graph verbs and search are offline");

    // Tags the role cannot read: the scan still lands, as partial_success
    // (exit 1) with a warning naming the source.
    let tagged = h.run(
        server.port,
        &[
            "catalog",
            "scan",
            "sock",
            "--database",
            "DB",
            "--schema",
            "PUBLIC",
            "--tags",
            "--json",
        ],
    );
    assert_eq!(tagged.exit, 1, "{}", tagged.context());
    assert_eq!(
        tagged.envelope["outcome_kind"],
        "partial_success",
        "{}",
        tagged.context()
    );
    assert_eq!(tagged.envelope["ok"], true, "{}", tagged.context());
    assert!(
        tagged.envelope["warnings"]
            .to_string()
            .contains("`tag_references` was refused"),
        "{}",
        tagged.context()
    );
    assert_eq!(
        tagged.envelope["data"]["relations"]["view_depends_on"],
        1,
        "{}",
        tagged.context()
    );
}

/// Reality-check bead oj0.42: text Snowflake controls (a table name, a comment,
/// a cell) carrying terminal escapes never reaches stdout or stderr raw, in any
/// output mode, with `NO_COLOR` and `CI` set and stdout piped; JSON keeps the
/// bytes as `\u001b` escapes, and `--toon` falls back to JSON for them.
#[test]
fn planted_terminal_escapes_never_reach_the_terminal() {
    const TABLES: &str = "01b2c3d4-0000-0000-0000-00000000f190";
    const COLUMNS: &str = "01b2c3d4-0000-0000-0000-00000000f191";
    const RELATION: &str = "01b2c3d4-0000-0000-0000-00000000f192";
    const QUERY: &str = "01b2c3d4-0000-0000-0000-00000000f193";
    // An OSC 52 clipboard write, a bell, a screen clear, and a C1 CSI.
    const HOSTILE: &str = "\u{1b}]52;c;cHduZWQ=\u{7}\u{1b}[2J\u{9b}";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if !request.is_submit() {
            return not_found();
        }
        let statement = request.body_json()["statement"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let table = format!("EV{HOSTILE}IL");
        let comment = format!("note {HOSTILE}");
        if statement.contains("INFORMATION_SCHEMA.TABLES") {
            return result_set(
                TABLES,
                &[
                    ("TABLE_CATALOG", "TEXT", None, None),
                    ("TABLE_SCHEMA", "TEXT", None, None),
                    ("TABLE_NAME", "TEXT", None, None),
                    ("TABLE_TYPE", "TEXT", None, None),
                    ("COMMENT", "TEXT", None, None),
                    ("ROW_COUNT", "FIXED", Some(38), Some(0)),
                    ("BYTES", "FIXED", Some(38), Some(0)),
                ],
                &[vec![
                    Some("DB"),
                    Some("PUBLIC"),
                    Some(table.as_str()),
                    Some("BASE TABLE"),
                    Some(comment.as_str()),
                    Some("1"),
                    Some("64"),
                ]],
            );
        }
        if statement.contains("INFORMATION_SCHEMA.COLUMNS") {
            return result_set(
                COLUMNS,
                &[
                    ("TABLE_CATALOG", "TEXT", None, None),
                    ("TABLE_SCHEMA", "TEXT", None, None),
                    ("TABLE_NAME", "TEXT", None, None),
                    ("COLUMN_NAME", "TEXT", None, None),
                    ("ORDINAL_POSITION", "FIXED", Some(9), Some(0)),
                    ("DATA_TYPE", "TEXT", None, None),
                    ("NUMERIC_PRECISION", "FIXED", Some(9), Some(0)),
                    ("NUMERIC_SCALE", "FIXED", Some(9), Some(0)),
                    ("CHARACTER_MAXIMUM_LENGTH", "FIXED", Some(9), Some(0)),
                    ("IS_NULLABLE", "TEXT", None, None),
                    ("COMMENT", "TEXT", None, None),
                ],
                &[vec![
                    Some("DB"),
                    Some("PUBLIC"),
                    Some(table.as_str()),
                    Some("NOTE"),
                    Some("1"),
                    Some("TEXT"),
                    None,
                    None,
                    None,
                    Some("YES"),
                    Some(comment.as_str()),
                ]],
            );
        }
        if statement.starts_with("SHOW") || statement.contains("INFORMATION_SCHEMA.") {
            return result_set(RELATION, &[("NAME", "TEXT", None, None)], &[]);
        }
        result_set(
            QUERY,
            &[("NOTE", "TEXT", None, None)],
            &[vec![Some(comment.as_str())]],
        )
    });
    let h = Harness::new("ansi", &cert);
    let run = |args: &[&str]| {
        let output = h
            .command(server.port, args)
            .env("NO_COLOR", "1")
            .env("CI", "1")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("spawn");
        for (stream, bytes) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
            assert!(
                !bytes.iter().any(|byte| *byte == 0x1b || *byte == 0x07),
                "{args:?} wrote a raw escape to {stream}: {}",
                String::from_utf8_lossy(bytes)
            );
            let text = String::from_utf8_lossy(bytes);
            assert!(
                !text.contains('\u{9b}'),
                "{args:?} wrote a raw C1 control to {stream}: {text}"
            );
        }
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    };

    let scan = [
        "catalog",
        "scan",
        "sock",
        "--database",
        "DB",
        "--schema",
        "PUBLIC",
    ];
    let (exit, json) = run(&[&scan[..], &["--json"][..]].concat());
    assert_eq!(exit, 0, "{json}");
    assert!(
        json.contains("\\u001b"),
        "JSON keeps the byte as an escape: {json}"
    );
    let envelope: serde_json::Value = serde_json::from_str(&json).expect("scan JSON");
    let dataset_id = envelope["data"]["datasets"][0]["dataset_id"]
        .as_str()
        .expect("dataset id")
        .to_owned();
    let (exit, toon) = run(&[&scan[..], &["--toon"][..]].concat());
    assert_eq!(exit, 0, "{toon}");
    for format in ["--mermaid", "--svg", "--toon"] {
        let (exit, out) = run(&[
            "catalog",
            "graph",
            "sock",
            "--database",
            "DB",
            "--schema",
            "PUBLIC",
            format,
        ]);
        assert_eq!(exit, 0, "{format}: {out}");
        assert!(out.contains("EV"), "{format}: {out}");
    }
    let (exit, out) = run(&["dataset", "inspect", &dataset_id, "--toon"]);
    assert_eq!(exit, 0, "{out}");
    let (exit, out) = run(&[
        "query",
        "run",
        "--profile",
        "sock",
        "--sql",
        "select note from notes",
        "--toon",
    ]);
    assert_eq!(exit, 0, "{out}");
    let (exit, out) = run(&[
        "query",
        "run",
        "--profile",
        "sock",
        "--sql",
        "select note from notes",
        "--json",
    ]);
    assert_eq!(exit, 0, "{out}");
    assert!(out.contains("\\u001b]52"), "{out}");
}

/// Reality-check bead L1: `--allow-multiple-statements` sends ONE request with
/// `MULTI_STATEMENT_COUNT` = the batch size, then fetches each statement by the
/// handle the parent lists, in order; a count Snowflake disputes is a typed
/// failure; a batch holding a mutation, or bindings, never reaches the server.
#[test]
fn a_batch_of_reads_runs_as_one_multi_statement_request() {
    const PARENT: &str = "01b2c3d4-0000-0000-0000-00000000f180";
    const FIRST: &str = "01b2c3d4-0000-0000-0000-00000000f181";
    const SECOND: &str = "01b2c3d4-0000-0000-0000-00000000f182";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if request.is_submit() {
            let statement = request.body_json()["statement"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            if statement.contains("disputed") {
                // The documented message; the docs give no error code, so the
                // code here is a placeholder.
                return json(
                    422,
                    &serde_json::json!({
                        "code": "000000",
                        "sqlState": "0A000",
                        "message": "Actual statement count 3 did not match the desired statement count 2.",
                        "statementHandle": PARENT,
                    }),
                );
            }
            return json(
                200,
                &serde_json::json!({
                    "resultSetMetaData": {
                        "numRows": 1,
                        "format": "jsonv2",
                        "rowType": [{ "name": "multiple statement execution", "type": "text", "nullable": false }]
                    },
                    "data": [["Multiple statements executed successfully."]],
                    "code": "090001",
                    "sqlState": "00000",
                    "message": "Statement executed successfully.",
                    "statementHandle": PARENT,
                    "statementStatusUrl": format!("{SUBMIT_PATH}/{PARENT}"),
                    "statementHandles": [FIRST, SECOND],
                }),
            );
        }
        if request.is_poll_of(FIRST) {
            return result_set(
                FIRST,
                &[("N", "FIXED", Some(9), Some(0))],
                &[vec![Some("1")]],
            );
        }
        if request.is_poll_of(SECOND) {
            return result_set(
                SECOND,
                &[("WORD", "TEXT", None, None)],
                &[vec![Some("two")], vec![Some("deux")]],
            );
        }
        not_found()
    });
    let h = Harness::new("batch", &cert);
    let batch = |sql: &str, extra: &[&str]| {
        let mut args = vec![
            "query",
            "run",
            "--profile",
            "sock",
            "--sql",
            sql,
            "--allow-multiple-statements",
            "--json",
        ];
        args.extend_from_slice(extra);
        h.run(server.port, &args)
    };

    let run = batch("select 1 as n; select word from words;", &[]);
    assert_eq!(run.exit, 0, "{}", run.context());
    let data = &run.envelope["data"];
    assert_eq!(data["statement_count"], 2, "{}", run.context());
    assert_eq!(data["statements"][0]["rows"], serde_json::json!([[1]]));
    assert_eq!(
        data["statements"][1]["rows"],
        serde_json::json!([["two"], ["deux"]])
    );
    assert_eq!(data["statements"][1]["statement_handle"], SECOND);
    assert_eq!(
        data["statements"][1]["sql_preview_redacted"],
        "select word from words"
    );
    assert_eq!(
        run.envelope["statement_handle"],
        PARENT,
        "{}",
        run.context()
    );
    let seen = server.seen();
    assert_eq!(
        seen.len(),
        3,
        "one submit, then one GET per statement: {seen:?}"
    );
    let submitted = seen[0].body_json();
    assert_eq!(
        submitted["parameters"]["MULTI_STATEMENT_COUNT"], "2",
        "{submitted}"
    );
    assert!(
        seen[1].is_poll_of(FIRST) && seen[2].is_poll_of(SECOND),
        "{seen:?}"
    );

    // Snowflake counts differently: a typed failure naming the counts.
    let disputed = batch("select 'disputed'; select 2", &[]);
    assert_ne!(disputed.exit, 0, "{}", disputed.context());
    assert!(
        disputed.envelope["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("did not match the desired statement count"),
        "{}",
        disputed.context()
    );
    let before = server.seen().len();

    // Refused before any request: a mutation anywhere in the batch, bindings.
    let mutation = batch("select 1; delete from events", &[]);
    assert_eq!(
        mutation.envelope["error"]["code"],
        "FSNOW-3001",
        "{}",
        mutation.context()
    );
    let bound = batch(
        "select ?; select 2",
        &["--bindings-env", "FSNOW_SOCKET_BINDINGS"],
    );
    assert_eq!(
        bound.envelope["error"]["code"],
        "FSNOW-1002",
        "{}",
        bound.context()
    );
    assert_eq!(
        server.seen().len(),
        before,
        "refused batches never reach the server"
    );
}

/// Reality-check bead oj0.39: the local-store adapter conforms over the store
/// the real binary filled through TLS (a catalog scan, a dataset query, a CSV
/// export and, with `frankenpandas`, a frame), answering every operation
/// offline and naming the PAT only by its env handle.
#[test]
fn the_local_store_adapter_conforms_over_what_the_binary_persisted() {
    use franken_snowflake_cli::adapter::LocalStoreAdapter;
    use franken_snowflake_core::adapter::SnowflakeDataLakeAdapter;
    use franken_snowflake_core::adapter::conformance::{
        ConformanceProbe, check_adapter_conformance,
    };
    use franken_snowflake_core::ids::{DatasetId, ProfileName, ReceiptHash};
    use franken_snowflake_core::outcome::DataSource;

    const TABLES: &str = "01b2c3d4-0000-0000-0000-00000000f150";
    const COLUMNS: &str = "01b2c3d4-0000-0000-0000-00000000f151";
    const RELATION: &str = "01b2c3d4-0000-0000-0000-00000000f152";
    const QUERY: &str = "01b2c3d4-0000-0000-0000-00000000f153";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if !request.is_submit() {
            return not_found();
        }
        let statement = request.body_json()["statement"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if statement.contains("INFORMATION_SCHEMA.TABLES") {
            return result_set(
                TABLES,
                &[
                    ("TABLE_CATALOG", "TEXT", None, None),
                    ("TABLE_SCHEMA", "TEXT", None, None),
                    ("TABLE_NAME", "TEXT", None, None),
                    ("TABLE_TYPE", "TEXT", None, None),
                    ("COMMENT", "TEXT", None, None),
                    ("ROW_COUNT", "FIXED", Some(38), Some(0)),
                    ("BYTES", "FIXED", Some(38), Some(0)),
                ],
                &[vec![
                    Some("DB"),
                    Some("PUBLIC"),
                    Some("EVENTS"),
                    Some("BASE TABLE"),
                    None,
                    Some("1"),
                    Some("64"),
                ]],
            );
        }
        if statement.contains("INFORMATION_SCHEMA.COLUMNS") {
            let column = |name, ordinal, kind| {
                vec![
                    Some("DB"),
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
            return result_set(
                COLUMNS,
                &[
                    ("TABLE_CATALOG", "TEXT", None, None),
                    ("TABLE_SCHEMA", "TEXT", None, None),
                    ("TABLE_NAME", "TEXT", None, None),
                    ("COLUMN_NAME", "TEXT", None, None),
                    ("ORDINAL_POSITION", "FIXED", Some(9), Some(0)),
                    ("DATA_TYPE", "TEXT", None, None),
                    ("NUMERIC_PRECISION", "FIXED", Some(9), Some(0)),
                    ("NUMERIC_SCALE", "FIXED", Some(9), Some(0)),
                    ("CHARACTER_MAXIMUM_LENGTH", "FIXED", Some(9), Some(0)),
                    ("IS_NULLABLE", "TEXT", None, None),
                    ("COMMENT", "TEXT", None, None),
                ],
                &[
                    column("EVENT_DATE", "1", "DATE"),
                    column("ENTITY_ID", "2", "TEXT"),
                ],
            );
        }
        if statement.starts_with("SHOW") || statement.contains("INFORMATION_SCHEMA.") {
            // The relation pass: no keys, constraints, stages or formats.
            return result_set(RELATION, &[("NAME", "TEXT", None, None)], &[]);
        }
        result_set(
            QUERY,
            &[
                ("EVENT_DATE", "DATE", None, None),
                ("ENTITY_ID", "TEXT", None, None),
            ],
            &[vec![Some("18262"), Some("ENTITY123")]],
        )
    });
    let h = Harness::new("adapter", &cert);
    let scan = h.run(
        server.port,
        &[
            "catalog",
            "scan",
            "sock",
            "--database",
            "DB",
            "--schema",
            "PUBLIC",
            "--json",
        ],
    );
    assert_eq!(scan.exit, 0, "{}", scan.context());
    let dataset_id = scan.envelope["data"]["datasets"][0]["dataset_id"]
        .as_str()
        .expect("dataset id")
        .to_owned();
    let query = h.run(
        server.port,
        &["query", "run", "--dataset", &dataset_id, "--json"],
    );
    assert_eq!(query.exit, 0, "{}", query.context());
    let receipt = query.envelope["receipt_hash"]
        .as_str()
        .expect("receipt hash")
        .to_owned();
    let export = |format: &str, file: &str| {
        let out = h.dir.join(file).to_string_lossy().into_owned();
        let run = h.run(
            server.port,
            &[
                "export",
                "run",
                "--profile",
                "sock",
                "--sql",
                "select event_date, entity_id from events",
                "--format",
                format,
                "--out",
                &out,
                "--json",
            ],
        );
        assert_eq!(run.exit, 0, "{}", run.context());
        run.envelope["data"]["export_receipt"]["export_id"]
            .as_str()
            .expect("export id")
            .to_owned()
    };
    let export_id = export("csv", "adapter.csv");
    let frame_id = cfg!(feature = "frankenpandas").then(|| export("frame", "adapter.frame.json"));
    let requests = server.seen().len();

    let adapter = LocalStoreAdapter::open_at(
        &h.dir.join("store"),
        Box::new(|name| {
            let value = match name.strip_prefix("FRANKEN_SNOWFLAKE_SOCK_")? {
                "ACCOUNT" => "https://127.0.0.1:1",
                "USER" => "SOCK_USER",
                "AUTH" => "pat",
                "WAREHOUSE" => "SOCK_WH",
                "PAT" => CANARY_PAT,
                _ => return None,
            };
            Some(value.to_owned())
        }),
    )
    .expect("open the store the binary wrote");
    let probe = ConformanceProbe {
        profile: ProfileName::new("sock"),
        dataset: DatasetId::new(dataset_id.clone()),
        receipt: ReceiptHash::new(receipt.clone()),
        export_id: Some(export_id),
        frame_id: frame_id.clone(),
        expected_data_source: DataSource::Live,
    };
    assert_eq!(
        check_adapter_conformance(&adapter, &probe),
        Vec::<String>::new()
    );
    let manifest = adapter
        .dataset_manifest(&DatasetId::new(dataset_id))
        .expect("the scanned dataset");
    assert_eq!(manifest.data.fields.len(), 2);
    assert_eq!(
        adapter
            .query_receipt(&ReceiptHash::new(receipt))
            .expect("the query receipt")
            .data
            .row_count,
        Some(1)
    );
    if let Some(frame_id) = frame_id {
        let frame = adapter.frame_ingest(&frame_id).expect("the frame");
        let names: Vec<&str> = frame
            .data
            .columns
            .iter()
            .map(|column| column.name.as_str())
            .collect();
        assert_eq!(names, ["EVENT_DATE", "ENTITY_ID"]);
    }
    let diagnostics = serde_json::to_string(
        &adapter
            .profile_diagnostics(&ProfileName::new("sock"))
            .expect("diagnostics"),
    )
    .expect("serialize");
    assert!(!diagnostics.contains(CANARY_PAT), "{diagnostics}");
    assert!(
        diagnostics.contains("FRANKEN_SNOWFLAKE_SOCK_PAT"),
        "{diagnostics}"
    );
    assert_eq!(server.seen().len(), requests, "the adapter is offline");
}

/// `receipt refetch` re-reads a completed statement's rows with RESULT_SCAN on
/// the query id its receipt recorded (reality-check bead L5); an unknown
/// receipt never reaches the server.
#[test]
fn receipt_refetch_reads_the_result_cache_by_query_id() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f130";
    const REFETCH: &str = "01b2c3d4-0000-0000-0000-00000000f131";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if !request.is_submit() {
            return not_found();
        }
        let statement = request.body_json()["statement"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if statement.contains("RESULT_SCAN") {
            completed_single(REFETCH)
        } else {
            completed_single(HANDLE)
        }
    });
    let h = Harness::new("refetch", &cert);
    let first = h.run(
        server.port,
        &[
            "query",
            "run",
            "--profile",
            "sock",
            "--sql",
            "select 1",
            "--json",
        ],
    );
    assert_eq!(first.exit, 0, "{}", first.context());
    let receipt = first.envelope["receipt_hash"]
        .as_str()
        .expect("receipt hash")
        .to_owned();

    let refetch = h.run(server.port, &["receipt", "refetch", &receipt, "--json"]);
    assert_eq!(refetch.exit, 0, "{}", refetch.context());
    let data = &refetch.envelope["data"];
    assert_eq!(data["source_query_id"], HANDLE, "{}", refetch.context());
    assert_eq!(
        data["rows"],
        serde_json::json!([
            ["2020-01-01", "ENTITY123", "1.50"],
            ["2020-01-02", "ENTITY124", null]
        ]),
        "{}",
        refetch.context()
    );
    let seen = server.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert_eq!(
        seen[1].body_json()["statement"],
        format!("SELECT * FROM TABLE(RESULT_SCAN('{HANDLE}'))")
    );

    let unknown = h.run(server.port, &["receipt", "refetch", "00", "--json"]);
    assert_ne!(unknown.exit, 0, "{}", unknown.context());
    assert_eq!(
        unknown.envelope["error"]["code"],
        "FSNOW-7002",
        "{}",
        unknown.context()
    );
    assert_eq!(
        server.seen().len(),
        2,
        "an unknown receipt reaches no server"
    );
}

/// `export run` streams CSV to the file over TLS (reality-check bead E5):
/// every partition's rows in order, temporal cells as typed text; `--max-rows`
/// refuses a larger result, cancels the statement and leaves no file.
#[test]
fn export_run_streams_csv_and_max_rows_refuses_without_a_file() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f140";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, _| {
        if request.is_submit() {
            return completed_multi(HANDLE);
        }
        if request.method == "POST" && request.path().ends_with("/cancel") {
            return scenarios::cancel();
        }
        match request.query("partition") {
            Some("1") => scenarios::gzip_partition(),
            Some("2") => MockHttpResponse::json(200, br#"{"data":[["5","epsilon"]]}"#.to_vec()),
            _ => not_found(),
        }
    });
    let h = Harness::new("export", &cert);
    let out = h.dir.join("events.csv");
    let out_arg = out.to_string_lossy().into_owned();
    let sql = "select event_date, entity_id from events";
    let run = h.run(
        server.port,
        &[
            "export",
            "run",
            "--profile",
            "sock",
            "--sql",
            sql,
            "--format",
            "csv",
            "--out",
            &out_arg,
            "--json",
        ],
    );
    assert_eq!(run.exit, 0, "{}", run.context());
    assert_eq!(run.envelope["data"]["streamed"], true, "{}", run.context());
    let written = fs::read_to_string(&out).expect("export file");
    assert_eq!(
        written,
        "EVENT_DATE,ENTITY_ID\n2020-01-01,ENTITY123\n2020-01-02,ENTITY124\n\
         1970-01-04,gamma\n1970-01-05,delta\n1970-01-06,epsilon\n"
    );
    assert_eq!(
        run.envelope["data"]["bytes_written"],
        written.len(),
        "{}",
        run.context()
    );

    let capped = h.dir.join("capped.csv");
    let capped_arg = capped.to_string_lossy().into_owned();
    let args = [
        "export",
        "run",
        "--profile",
        "sock",
        "--sql",
        sql,
        "--format",
        "csv",
        "--out",
        &capped_arg,
        "--max-rows",
        "3",
        "--json",
    ];
    let mut command = h.command(server.port, &args);
    // One partition per window, so the limit trips while the statement still
    // has partitions to fetch.
    command.env("FRANKEN_SNOWFLAKE_SOCK_PARTITION_CONCURRENCY", "1");
    let refused = h.finish(&args, command.output().expect("spawn"));
    assert_eq!(
        refused.envelope["error"]["code"],
        "FSNOW-3004",
        "{}",
        refused.context()
    );
    assert!(!capped.exists(), "a refused export leaves no file");
    let leftovers = fs::read_dir(&h.dir)
        .expect("harness dir")
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().contains("fsnow-tmp"))
        .count();
    assert_eq!(leftovers, 0, "no temporary file is left behind");
    assert!(
        server
            .seen()
            .iter()
            .any(|s| s.method == "POST" && s.path() == format!("{SUBMIT_PATH}/{HANDLE}/cancel")),
        "the oversized statement was cancelled: {:?}",
        server.seen()
    );
}

/// `--progress` (reality-check bead E5): one JSON object per statement event
/// on stderr, while stdout stays the single envelope and the export is the
/// same bytes as without it.
#[test]
fn progress_events_go_to_stderr_and_change_nothing_else() {
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000f150";
    let cert = TestCert::mint();
    let server = MockServer::start(&cert, |request, before| {
        if request.is_submit() {
            return running(HANDLE);
        }
        if request.is_poll_of(HANDLE) {
            // Polls of this run only: the second export resubmits the handle.
            let polls = before
                .iter()
                .rev()
                .take_while(|seen| !seen.is_submit())
                .filter(|seen| seen.is_poll_of(HANDLE))
                .count();
            return if polls == 0 {
                running(HANDLE)
            } else {
                completed_multi(HANDLE)
            };
        }
        match request.query("partition") {
            Some("1") => scenarios::gzip_partition(),
            Some("2") => MockHttpResponse::json(200, br#"{"data":[["5","epsilon"]]}"#.to_vec()),
            _ => not_found(),
        }
    });
    let h = Harness::new("progress", &cert);
    let export = |name: &str, progress: bool| {
        let out = h.dir.join(name).to_string_lossy().into_owned();
        let mut args = vec![
            "export",
            "run",
            "--profile",
            "sock",
            "--sql",
            "select 1",
            "--format",
            "jsonl",
        ];
        if progress {
            args.push("--progress");
        }
        args.extend(["--out", out.as_str(), "--json"]);
        let run = h.run(server.port, &args);
        (run, fs::read(&out).unwrap_or_default())
    };
    let (quiet, quiet_bytes) = export("quiet.jsonl", false);
    let (loud, loud_bytes) = export("loud.jsonl", true);
    assert_eq!(quiet.exit, 0, "{}", quiet.context());
    assert_eq!(loud.exit, 0, "{}", loud.context());
    assert!(!quiet_bytes.is_empty());
    assert_eq!(
        quiet_bytes, loud_bytes,
        "--progress changes no output bytes"
    );
    assert!(
        quiet.stderr.trim().is_empty(),
        "no events unasked: {}",
        quiet.stderr
    );
    let events: Vec<serde_json::Value> = loud
        .stderr
        .lines()
        .map(|line| serde_json::from_str(line).expect("each stderr line is one JSON object"))
        .collect();
    let kinds: Vec<&str> = events
        .iter()
        .map(|event| event["event"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        kinds,
        [
            "submitted",
            "polled",
            "polled",
            "partition_fetched",
            "partition_fetched",
            "completed"
        ],
        "{}",
        loud.stderr
    );
    assert_eq!(events[0]["running"], true);
    assert_eq!(events[0]["statement_handle"], HANDLE);
    assert_eq!(events[3]["index"], 1);
    assert_eq!(events[3]["rows"], 2);
    assert_eq!(events[5]["rows"], 5);
    assert_eq!(events[5]["partitions"], 3);
    assert!(events.iter().all(|event| event["elapsed_ms"].is_u64()));
}
