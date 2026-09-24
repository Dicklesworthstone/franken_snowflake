//! Secured HTTP front end for `franken-snowflake mcp serve --http <addr>`.
//!
//! fastmcp 0.3.2's built-in HTTP loop answers every request with a permissive
//! CORS policy (`Access-Control-Allow-Origin` echoes any origin), does not look
//! at the HTTP `Authorization` header, and does not check `Host`. Verified on
//! the shipped v0.0.4 binary (2026-09-23): a web page could preflight, then
//! `initialize` and `tools/call` the server cross-origin and read the result —
//! with whatever live Snowflake credentials the serving shell had exported.
//!
//! This module owns the socket instead and only then dispatches into the same
//! fastmcp `Server` through its public `dispatch_request_concurrent`, so the
//! tools, handlers and envelopes are unchanged. Policy, decided per request:
//!
//! - `Authorization: Bearer <token>` is required (constant-time compare); the
//!   token comes from `FRANKEN_SNOWFLAKE_MCP_TOKEN` (≥ 32 chars) and the server
//!   refuses to start without one. The token is never logged.
//! - A request carrying an `Origin` header is refused unless the origin was
//!   explicitly allowed (`--allow-origin`); arbitrary origins are never echoed.
//! - `Host` must name the bound address or a loopback alias (DNS-rebinding
//!   defense).
//! - Binding a non-loopback address requires `--allow-remote`.
//! - Only read-only tools are exposed by default; side-effecting tools
//!   (`export_run` writes a local file, `query_cancel` cancels a remote
//!   statement) need `--allow-tool <name>`. Hidden tools are removed from
//!   `tools/list` and refused on `tools/call`.

use std::collections::BTreeSet;
use std::io::{BufReader, BufWriter, Write as _};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use fastmcp_rust::bidirectional::TransportSendFn;
use fastmcp_rust::http::{HttpMethod, HttpRequest, HttpResponse, HttpStatus, HttpTransport};
use fastmcp_rust::{
    Cx, JsonRpcRequest, NotificationSender, PendingRequests, RequestSender, Server, Session,
};
use franken_snowflake_core::error::SnowflakeErrorCode;
use serde_json::{Value, json};

/// Env handle holding the bearer token for `mcp serve --http`.
pub const MCP_TOKEN_ENV: &str = "FRANKEN_SNOWFLAKE_MCP_TOKEN";
/// Minimum accepted token length.
pub const MIN_TOKEN_LEN: usize = 32;
/// The MCP JSON-RPC endpoint path.
pub const MCP_PATH: &str = "/mcp";
/// Unauthenticated liveness path (returns no data).
pub const HEALTH_PATH: &str = "/health";

/// Operator choices for the HTTP transport.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HttpServeOptions {
    /// Address to bind (`127.0.0.1:3000`).
    pub addr: String,
    /// Browser origins allowed to call the server (exact match).
    pub allowed_origins: Vec<String>,
    /// Side-effecting tools to expose in addition to the read-only set.
    pub extra_tools: Vec<String>,
    /// Permit a non-loopback bind address.
    pub allow_remote: bool,
}

/// The per-request policy. `Debug` is hand-written so the token never prints.
pub struct HttpPolicy {
    token: String,
    allowed_hosts: BTreeSet<String>,
    allowed_origins: BTreeSet<String>,
    allowed_tools: BTreeSet<String>,
}

impl std::fmt::Debug for HttpPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpPolicy")
            .field("token", &"[REDACTED]")
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_origins", &self.allowed_origins)
            .field("allowed_tools", &self.allowed_tools)
            .finish()
    }
}

/// What to do with one HTTP request.
#[derive(Debug)]
pub enum Decision {
    /// Answer immediately (refusals, health, allowed preflight).
    Respond(HttpResponse),
    /// Dispatch the JSON-RPC body; attach CORS for this allowed origin, if any.
    Dispatch { cors_origin: Option<String> },
}

impl HttpPolicy {
    /// Build the policy for a bound port.
    #[must_use]
    pub fn new(
        token: String,
        bound_host: &str,
        port: u16,
        allowed_origins: &[String],
        allowed_tools: BTreeSet<String>,
    ) -> Self {
        let mut allowed_hosts: BTreeSet<String> = ["127.0.0.1", "localhost", "[::1]"]
            .iter()
            .map(|host| format!("{host}:{port}"))
            .collect();
        allowed_hosts.insert(format!("{}:{port}", bound_host.to_ascii_lowercase()));
        Self {
            token,
            allowed_hosts,
            allowed_origins: allowed_origins.iter().cloned().collect(),
            allowed_tools,
        }
    }

    /// Tools this server exposes over HTTP.
    #[must_use]
    pub fn allowed_tools(&self) -> &BTreeSet<String> {
        &self.allowed_tools
    }

    /// Decide what to do with `request` (pure: no I/O).
    #[must_use]
    pub fn decide(&self, request: &HttpRequest) -> Decision {
        if request.path == HEALTH_PATH && request.method == HttpMethod::Get {
            return Decision::Respond(HttpResponse::ok().with_json(&json!({"status": "ok"})));
        }
        if request.path != MCP_PATH {
            return refuse(HttpStatus::NOT_FOUND, "not found");
        }
        let host_ok = request.header("host").is_some_and(|host| {
            self.allowed_hosts
                .contains(&host.trim().to_ascii_lowercase())
        });
        if !host_ok {
            return refuse(
                HttpStatus::FORBIDDEN,
                "Host header does not name this server (DNS-rebinding defense)",
            );
        }
        let origin = request.header("origin").map(str::trim);
        let cors_origin = match origin {
            None => None,
            Some(origin) if self.allowed_origins.contains(origin) => Some(origin.to_owned()),
            Some(_) => {
                return refuse(
                    HttpStatus::FORBIDDEN,
                    "cross-origin requests are refused unless the origin was allowed with --allow-origin",
                );
            }
        };
        if request.method == HttpMethod::Options {
            // Preflight for an explicitly allowed origin only.
            return Decision::Respond(match cors_origin {
                Some(origin) => with_cors(HttpResponse::new(HttpStatus(204)), &origin),
                None => HttpResponse::new(HttpStatus::FORBIDDEN),
            });
        }
        if request.method != HttpMethod::Post {
            return refuse(HttpStatus::METHOD_NOT_ALLOWED, "use POST");
        }
        if !self.bearer_matches(request.authorization()) {
            return Decision::Respond(
                HttpResponse::new(HttpStatus::UNAUTHORIZED)
                    .with_header("www-authenticate", "Bearer")
                    .with_json(&json!({
                        "error": format!(
                            "missing or wrong bearer token; send `Authorization: Bearer <token>` with the value of {MCP_TOKEN_ENV}"
                        )
                    })),
            );
        }
        Decision::Dispatch { cors_origin }
    }

    fn bearer_matches(&self, header: Option<&str>) -> bool {
        let Some(presented) = header.and_then(|value| {
            let (scheme, token) = value.trim().split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
        }) else {
            return false;
        };
        constant_time_eq(presented.as_bytes(), self.token.as_bytes())
    }
}

fn refuse(status: HttpStatus, message: &str) -> Decision {
    Decision::Respond(HttpResponse::new(status).with_json(&json!({ "error": message })))
}

fn with_cors(response: HttpResponse, origin: &str) -> HttpResponse {
    response
        .with_header("access-control-allow-origin", origin)
        .with_header("vary", "Origin")
        .with_header("access-control-allow-methods", "POST, OPTIONS")
        .with_header(
            "access-control-allow-headers",
            "Content-Type, Authorization",
        )
}

/// Compare without an early exit on the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Validate the token handle: present and long enough.
///
/// # Errors
/// A human-readable refusal naming the env handle and how to set it.
pub fn token_from_env() -> Result<String, String> {
    let token = std::env::var(MCP_TOKEN_ENV).unwrap_or_default();
    let token = token.trim().to_owned();
    if token.len() < MIN_TOKEN_LEN {
        return Err(format!(
            "`mcp serve --http` requires a bearer token of at least {MIN_TOKEN_LEN} characters in {MCP_TOKEN_ENV} \
             (for example: export {MCP_TOKEN_ENV}=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n')); \
             clients send it as `Authorization: Bearer <token>`. Use `mcp serve --stdio` for local agents."
        ));
    }
    Ok(token)
}

/// Remove hidden tools from a `tools/list` result and refuse hidden tools on
/// `tools/call`. Returns `Err(error)` with a JSON-RPC error body to send instead
/// of dispatching.
fn gate_tool_call(request: &JsonRpcRequest, policy: &HttpPolicy) -> Result<(), Value> {
    if request.method != "tools/call" {
        return Ok(());
    }
    let name = request
        .params
        .as_ref()
        .and_then(|params| params.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if policy.allowed_tools.contains(name) {
        Ok(())
    } else {
        Err(json!({
            "code": -32602,
            "message": format!(
                "tool `{name}` is not exposed over HTTP; restart with `--allow-tool {name}` to expose it"
            ),
        }))
    }
}

fn filter_tools_list(response: &mut Value, policy: &HttpPolicy) {
    if let Some(tools) = response
        .get_mut("result")
        .and_then(|result| result.get_mut("tools"))
        .and_then(Value::as_array_mut)
    {
        tools.retain(|tool| {
            tool.get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| policy.allowed_tools.contains(name))
        });
    }
}

/// Handle one authorized JSON-RPC body.
fn dispatch_body(
    server: &Server,
    cx: &Cx,
    session: &Arc<Mutex<Session>>,
    policy: &HttpPolicy,
    body: &[u8],
) -> HttpResponse {
    let request: JsonRpcRequest = match serde_json::from_slice(body) {
        Ok(request) => request,
        Err(error) => {
            return HttpResponse::bad_request()
                .with_json(&json!({"error": format!("invalid JSON-RPC body: {error}")}));
        }
    };
    let id = request.id.clone();
    let is_tools_list = request.method == "tools/list";
    if let Err(error) = gate_tool_call(&request, policy) {
        return HttpResponse::ok().with_json(&json!({"jsonrpc": "2.0", "id": id, "error": error}));
    }
    // Client notifications need no dispatch or reply; a cancellation is
    // recorded for the running call it names (reality-check bead E2).
    if request.method.starts_with("notifications/") {
        if request.method == "notifications/cancelled" {
            crate::fastmcp_surface::note_http_cancellation(request.params.as_ref());
        }
        return HttpResponse::new(HttpStatus::ACCEPTED);
    }
    let notify: NotificationSender = Arc::new(|_| {});
    let send_fn: TransportSendFn =
        Arc::new(|_| Err("the HTTP transport does not carry server-to-client requests".into()));
    let request_sender = RequestSender::new(Arc::new(PendingRequests::new()), send_fn);
    let Some(response) =
        server.dispatch_request_concurrent(cx, session, request, &notify, &request_sender)
    else {
        return HttpResponse::new(HttpStatus::ACCEPTED);
    };
    let mut value = serde_json::to_value(&response).unwrap_or(Value::Null);
    if is_tools_list {
        filter_tools_list(&mut value, policy);
    }
    HttpResponse::ok().with_json(&value)
}

fn serve_connection(
    stream: TcpStream,
    server: &Server,
    session: &Arc<Mutex<Session>>,
    policy: &HttpPolicy,
) {
    let Ok(reader_stream) = stream.try_clone() else {
        return;
    };
    let mut transport = HttpTransport::new(BufReader::new(reader_stream), BufWriter::new(stream));
    let Ok(request) = transport.read_request() else {
        return;
    };
    let (response, dispatched) = match policy.decide(&request) {
        Decision::Respond(response) => (response, false),
        Decision::Dispatch { cors_origin } => {
            let cx = Cx::for_request();
            let response = dispatch_body(server, &cx, session, policy, &request.body);
            let response = match cors_origin {
                Some(origin) => with_cors(response, &origin),
                None => response,
            };
            (response, true)
        }
    };
    log_request(&request, &response, dispatched);
    let _ = transport.write_response(&response);
}

/// One JSON line per request on stderr: method, path, host, origin, JSON-RPC
/// method and tool, and the decision, so refused cross-origin or
/// unauthenticated attempts leave a trail. The authorization header and the
/// request arguments are never logged; a closed stderr is ignored, never a
/// panic.
fn log_request(request: &HttpRequest, response: &HttpResponse, dispatched: bool) {
    let status = response.status.0;
    let decision = if dispatched {
        "dispatched"
    } else if status >= 400 {
        "refused"
    } else {
        "answered"
    };
    let rpc: Value = if dispatched {
        serde_json::from_slice(&request.body).unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    let redact = |value: Option<&str>| {
        value.map(|text| franken_snowflake_core::redact::redact(text).into_owned())
    };
    let line = json!({
        "event": "mcp_http_request",
        "method": format!("{:?}", request.method).to_ascii_uppercase(),
        "path": redact(Some(&request.path)),
        "host": redact(request.header("host")),
        "origin": redact(request.header("origin")),
        "rpc_method": rpc.get("method").and_then(Value::as_str),
        "tool": rpc.pointer("/params/name").and_then(Value::as_str),
        "decision": decision,
        "status": status,
    });
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

fn usage_exit(message: &str) -> ! {
    eprintln!(
        "{}: {message}",
        SnowflakeErrorCode::UsageError.stable_code()
    );
    std::process::exit(64)
}

/// Run the secured HTTP transport until the process is killed.
pub fn run_secure_http(server: Server, options: &HttpServeOptions, read_only_tools: &[&str]) -> ! {
    let token = token_from_env().unwrap_or_else(|message| usage_exit(&message));
    let listener = TcpListener::bind(&options.addr).unwrap_or_else(|error| {
        usage_exit(&format!(
            "cannot bind `mcp serve --http {}`: {error}",
            franken_snowflake_core::redact::redact(&options.addr)
        ))
    });
    let local = listener
        .local_addr()
        .unwrap_or_else(|error| usage_exit(&format!("cannot read the bound address: {error}")));
    if !local.ip().is_loopback() && !options.allow_remote {
        usage_exit(&format!(
            "`mcp serve --http {}` binds a non-loopback address; pass --allow-remote to accept that (the token is then the only guard), or bind 127.0.0.1",
            local
        ));
    }
    let known: BTreeSet<String> = server.tools().into_iter().map(|tool| tool.name).collect();
    for extra in &options.extra_tools {
        if !known.contains(extra) {
            usage_exit(&format!(
                "--allow-tool `{extra}` names no tool; known tools: {}",
                known.iter().cloned().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    let mut allowed_tools: BTreeSet<String> = read_only_tools
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    allowed_tools.extend(options.extra_tools.iter().cloned());
    let bound_host = match local.ip() {
        IpAddr::V6(ip) => format!("[{ip}]"),
        IpAddr::V4(ip) => ip.to_string(),
    };
    let policy = Arc::new(HttpPolicy::new(
        token,
        &bound_host,
        local.port(),
        &options.allowed_origins,
        allowed_tools,
    ));
    let session = Arc::new(Mutex::new(Session::new(
        server.info().clone(),
        server.capabilities().clone(),
    )));
    let server = Arc::new(server);
    eprintln!(
        "franken-snowflake MCP HTTP server listening on http://{local}{MCP_PATH} (bearer token from {MCP_TOKEN_ENV}; tools: {})",
        policy
            .allowed_tools()
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    );
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let server = Arc::clone(&server);
        let session = Arc::clone(&session);
        let policy = Arc::clone(&policy);
        std::thread::spawn(move || serve_connection(stream, &server, &session, &policy));
    }
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn policy() -> HttpPolicy {
        HttpPolicy::new(
            TOKEN.to_owned(),
            "127.0.0.1",
            3000,
            &["https://trusted.example".to_owned()],
            ["query_plan".to_owned(), "capabilities".to_owned()]
                .into_iter()
                .collect(),
        )
    }

    fn post(headers: &[(&str, &str)]) -> HttpRequest {
        headers.iter().fold(
            HttpRequest::new(HttpMethod::Post, MCP_PATH),
            |req, (k, v)| req.with_header(*k, *v),
        )
    }

    fn status(decision: &Decision) -> Option<u16> {
        match decision {
            Decision::Respond(response) => Some(response.status.0),
            Decision::Dispatch { .. } => None,
        }
    }

    fn cors_header(decision: &Decision) -> Option<String> {
        match decision {
            Decision::Respond(response) => {
                response.headers.get("access-control-allow-origin").cloned()
            }
            Decision::Dispatch { cors_origin } => cors_origin.clone(),
        }
    }

    const AUTH: (&str, &str) = ("authorization", "Bearer 0123456789abcdef0123456789abcdef");

    #[test]
    fn authorized_same_host_request_dispatches() {
        let decision = policy().decide(&post(&[("host", "127.0.0.1:3000"), AUTH]));
        assert!(matches!(decision, Decision::Dispatch { cors_origin: None }));
        let decision = policy().decide(&post(&[("host", "localhost:3000"), AUTH]));
        assert!(matches!(decision, Decision::Dispatch { .. }));
    }

    #[test]
    fn missing_or_wrong_token_is_401() {
        assert_eq!(
            status(&policy().decide(&post(&[("host", "127.0.0.1:3000")]))),
            Some(401)
        );
        let wrong = ("authorization", "Bearer 0123456789abcdef0123456789abcdeX");
        assert_eq!(
            status(&policy().decide(&post(&[("host", "127.0.0.1:3000"), wrong]))),
            Some(401)
        );
        let basic = ("authorization", "Basic 0123456789abcdef0123456789abcdef");
        assert_eq!(
            status(&policy().decide(&post(&[("host", "127.0.0.1:3000"), basic]))),
            Some(401)
        );
    }

    /// The 2026-09-23 exploit: a foreign page's preflight and POST.
    #[test]
    fn foreign_origin_is_refused_even_with_a_valid_token() {
        let evil = ("origin", "https://evil.example");
        let preflight = HttpRequest::new(HttpMethod::Options, MCP_PATH)
            .with_header("host", "127.0.0.1:3000")
            .with_header("origin", "https://evil.example");
        let decision = policy().decide(&preflight);
        assert_eq!(status(&decision), Some(403));
        assert_eq!(
            cors_header(&decision),
            None,
            "an arbitrary origin is never echoed"
        );
        let decision = policy().decide(&post(&[("host", "127.0.0.1:3000"), evil, AUTH]));
        assert_eq!(status(&decision), Some(403));
        assert_eq!(cors_header(&decision), None);
    }

    #[test]
    fn allowed_origin_gets_cors_for_itself_only() {
        let origin = ("origin", "https://trusted.example");
        let preflight = HttpRequest::new(HttpMethod::Options, MCP_PATH)
            .with_header("host", "127.0.0.1:3000")
            .with_header("origin", "https://trusted.example");
        let decision = policy().decide(&preflight);
        assert_eq!(status(&decision), Some(204));
        assert_eq!(
            cors_header(&decision).as_deref(),
            Some("https://trusted.example")
        );
        let decision = policy().decide(&post(&[("host", "127.0.0.1:3000"), origin, AUTH]));
        assert_eq!(
            cors_header(&decision).as_deref(),
            Some("https://trusted.example")
        );
    }

    /// DNS rebinding: the attacker's hostname resolves to 127.0.0.1, so the
    /// browser sends `Host: attacker.example:3000`.
    #[test]
    fn foreign_host_is_refused() {
        let decision = policy().decide(&post(&[("host", "attacker.example:3000"), AUTH]));
        assert_eq!(status(&decision), Some(403));
        let decision = policy().decide(&post(&[AUTH]));
        assert_eq!(
            status(&decision),
            Some(403),
            "a missing Host is refused too"
        );
    }

    #[test]
    fn health_is_open_and_other_paths_are_404() {
        let health = HttpRequest::new(HttpMethod::Get, HEALTH_PATH);
        assert_eq!(status(&policy().decide(&health)), Some(200));
        let other = HttpRequest::new(HttpMethod::Post, "/other")
            .with_header("host", "127.0.0.1:3000")
            .with_header("authorization", AUTH.1);
        assert_eq!(status(&policy().decide(&other)), Some(404));
    }

    #[test]
    fn hidden_tools_are_refused_and_filtered() {
        let policy = policy();
        let call = |name: &str| {
            JsonRpcRequest::new(
                "tools/call",
                Some(json!({"name": name, "arguments": {}})),
                7_i64,
            )
        };
        assert!(gate_tool_call(&call("query_plan"), &policy).is_ok());
        let refused = gate_tool_call(&call("export_run"), &policy);
        assert!(refused.is_err_and(|error| {
            error["message"]
                .as_str()
                .is_some_and(|m| m.contains("--allow-tool export_run"))
        }));
        let mut listed = json!({"result": {"tools": [
            {"name": "query_plan"}, {"name": "export_run"}, {"name": "capabilities"}
        ]}});
        filter_tools_list(&mut listed, &policy);
        assert_eq!(
            listed["result"]["tools"],
            json!([{"name": "query_plan"}, {"name": "capabilities"}])
        );
    }

    #[test]
    fn debug_never_prints_the_token() {
        let rendered = format!("{:?}", policy());
        assert!(!rendered.contains(TOKEN));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn constant_time_eq_matches_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }
}
