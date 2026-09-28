//! Redacted wire transcripts of live exchanges, and their replay
//! (reality-check bead oj0.21).
//!
//! The June 2026 live run found two decode bugs that every document-derived
//! fixture had hidden (`compressedSize` absent on inline partition 0; partition
//! bodies are `{"data": [...]}`, not a bare array). A credentialed run should
//! leave no-account regression fixtures behind, so with
//! `FRANKEN_SNOWFLAKE_CAPTURE_DIR` set the CLI wraps its production transport
//! ([`crate::SnowflakeHttpClient::capturing`]) and a [`TranscriptRecorder`]
//! writes one JSON file per HTTP exchange, `<seq>-<route>.json`. Before a byte
//! reaches disk the exchange is normalized and checked:
//!
//! - only the path and query are kept (never the host), and the account host
//!   and name are replaced wherever else they appear;
//! - `Authorization`, cookie and token-named header values become `[REDACTED]`;
//! - statement handles and request ids become stable placeholders
//!   (`00000000-0000-4000-8000-00000000000N`, in order of first appearance), so
//!   a replay drives the driver down the same paths;
//! - a gzip body is decoded and marked, so partitions are readable;
//! - a transcript that still contains a registered secret value or a bearer
//!   token shape is not written: `refused-<seq>.txt` names the reason (never
//!   the value).
//!
//! [`ReplayHttp`] serves a directory of transcripts back as a [`RawHttp`], so
//! the production driver can be run against what Snowflake actually sent.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use asupersync::Cx;
use asupersync::http::compress::{
    Compressor, DecompressionLimit, Decompressor, GzipCompressor, GzipDecompressor,
};
use asupersync::http::{ClientError as AsupersyncClientError, Method, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::RawHttp;

/// Transcript schema.
pub const TRANSCRIPT_SCHEMA: &str = "fsnow.wire_transcript.v1";
/// The env var that turns capture on in the CLI (a directory).
pub const CAPTURE_DIR_ENV: &str = "FRANKEN_SNOWFLAKE_CAPTURE_DIR";
const REDACTED: &str = "[REDACTED]";
/// Largest decoded body a transcript keeps (a bigger one is cut and marked).
const MAX_TRANSCRIPT_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Shortest value treated as an id or a secret (shorter strings would match
/// ordinary text).
const MIN_TOKEN_LEN: usize = 8;

/// One recorded exchange.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Transcript {
    pub schema: String,
    pub seq: u32,
    /// `submit`, `poll`, `partition`, `cancel`, or `other`.
    pub route: String,
    pub request: TranscriptRequest,
    pub response: TranscriptResponse,
}

/// The request half: method, path, query, redacted headers, body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TranscriptRequest {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: TranscriptBody,
}

/// The response half; `content_encoding` records a gzip body (decoded here).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TranscriptResponse {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub content_encoding: Option<String>,
    pub body: TranscriptBody,
}

/// A body as JSON when it parses, else text.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TranscriptBody {
    Empty,
    Json(Value),
    Text(String),
}

impl TranscriptBody {
    fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::Empty;
        }
        let cut = &bytes[..bytes.len().min(MAX_TRANSCRIPT_BODY_BYTES)];
        serde_json::from_slice(cut)
            .map(Self::Json)
            .unwrap_or_else(|_| Self::Text(String::from_utf8_lossy(cut).into_owned()))
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Empty => Vec::new(),
            Self::Json(value) => serde_json::to_vec(value).unwrap_or_default(),
            Self::Text(text) => text.clone().into_bytes(),
        }
    }
}

/// Writes redacted transcripts into one directory.
pub struct TranscriptRecorder {
    dir: PathBuf,
    /// Account host and account name, replaced wherever they appear.
    account_strings: Vec<(String, &'static str)>,
    secrets: Vec<String>,
    state: Mutex<RecorderState>,
}

#[derive(Default)]
struct RecorderState {
    next_seq: u32,
    ids: BTreeMap<String, String>,
}

impl std::fmt::Debug for TranscriptRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranscriptRecorder")
            .field("dir", &self.dir)
            .field("secrets", &self.secrets.len())
            .finish_non_exhaustive()
    }
}

impl TranscriptRecorder {
    /// A recorder writing into `dir` (created) for the endpoint `host`
    /// (`<account>.snowflakecomputing.com`).
    ///
    /// # Errors
    /// The directory cannot be created.
    pub fn new(dir: impl Into<PathBuf>, host: &str) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        let mut account_strings = vec![(host.to_owned(), "<account-host>")];
        if let Some(account) = host.split('.').next().filter(|a| a.len() >= 3) {
            account_strings.push((account.to_owned(), "<account>"));
        }
        Ok(Self {
            dir,
            account_strings,
            secrets: Vec::new(),
            state: Mutex::new(RecorderState {
                next_seq: 1,
                ids: BTreeMap::new(),
            }),
        })
    }

    /// Values that must never be written (credential env values, key lines).
    #[must_use]
    pub fn with_secrets(mut self, secrets: impl IntoIterator<Item = String>) -> Self {
        self.secrets = secrets
            .into_iter()
            .map(|secret| secret.trim().to_owned())
            .filter(|secret| secret.len() >= MIN_TOKEN_LEN)
            .collect();
        self
    }

    /// The capture directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Record one exchange. Never fails the request: a transcript that cannot
    /// be written or is refused leaves only a `refused-<seq>.txt` reason.
    pub fn record(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        response: &Response,
    ) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let (path, query) = split_url(url);
        let route = route_of(method, &path, &query);
        let (content_encoding, response_body) = decode_body(response);
        let mut transcript = Transcript {
            schema: TRANSCRIPT_SCHEMA.to_owned(),
            seq: 0,
            route: route.to_owned(),
            request: TranscriptRequest {
                method: method.to_owned(),
                path: path.clone(),
                query: query.clone(),
                headers: redact_headers(headers),
                body: TranscriptBody::from_bytes(body),
            },
            response: TranscriptResponse {
                status: response.status,
                reason: response.reason.clone(),
                headers: redact_headers(&response.headers),
                content_encoding,
                body: TranscriptBody::from_bytes(&response_body),
            },
        };
        // Ids in order of first appearance: the request's, then the response's.
        let mut found = Vec::new();
        collect_path_ids(&path, &mut found);
        for (key, value) in &query {
            if key == "requestId" {
                found.push(value.clone());
            }
        }
        if let TranscriptBody::Json(value) = &transcript.response.body {
            collect_body_ids(value, &mut found);
        }
        for id in found {
            if id.len() >= MIN_TOKEN_LEN && !state.ids.contains_key(&id) {
                let placeholder = format!("00000000-0000-4000-8000-{:012x}", state.ids.len() + 1);
                state.ids.insert(id, placeholder);
            }
        }
        let mut seq = state.next_seq;
        loop {
            transcript.seq = seq;
            let file = self.dir.join(format!("{seq:03}-{route}.json"));
            let text = match serde_json::to_string_pretty(&transcript) {
                Ok(text) => self.normalize(&text, &state.ids),
                Err(error) => {
                    self.refuse(seq, &format!("could not encode the transcript: {error}"));
                    break;
                }
            };
            if let Some(reason) = self.leak(&text) {
                self.refuse(seq, reason);
                break;
            }
            match OpenOptions::new().write(true).create_new(true).open(&file) {
                Ok(mut handle) => {
                    let _ = handle.write_all(text.as_bytes());
                    break;
                }
                // Another process writes into the same directory: next number.
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => seq += 1,
                Err(_) => break,
            }
        }
        state.next_seq = seq + 1;
    }

    fn normalize(&self, text: &str, ids: &BTreeMap<String, String>) -> String {
        let mut out = text.to_owned();
        for (id, placeholder) in ids {
            out = out.replace(id.as_str(), placeholder);
        }
        for (value, placeholder) in &self.account_strings {
            out = replace_ignore_ascii_case(&out, value, placeholder);
        }
        out
    }

    /// Why `text` must not be written, if it must not.
    fn leak(&self, text: &str) -> Option<&'static str> {
        if self
            .secrets
            .iter()
            .any(|secret| text.contains(secret.as_str()))
        {
            return Some("a registered secret value appears in the transcript");
        }
        if has_bearer_shape(text) {
            return Some("a bearer-token shape appears in the transcript");
        }
        None
    }

    fn refuse(&self, seq: u32, reason: &str) {
        let _ = std::fs::write(
            self.dir.join(format!("refused-{seq:03}.txt")),
            format!("transcript {seq} was not written: {reason}\n"),
        );
    }
}

fn split_url(url: &str) -> (String, Vec<(String, String)>) {
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path_and_query = without_scheme
        .find('/')
        .map_or("/", |at| &without_scheme[at..]);
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query, ""));
    let query = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key.to_owned(), value.to_owned())
        })
        .collect();
    (path.to_owned(), query)
}

fn route_of(method: &str, path: &str, query: &[(String, String)]) -> &'static str {
    let statements = "/api/v2/statements";
    if !path.starts_with(statements) {
        return "other";
    }
    let rest = path[statements.len()..].trim_start_matches('/');
    match (method, rest.is_empty(), rest.ends_with("/cancel")) {
        ("POST", true, _) => "submit",
        ("POST", false, true) => "cancel",
        ("GET", false, false) if query.iter().any(|(key, _)| key == "partition") => "partition",
        ("GET", false, false) => "poll",
        _ => "other",
    }
}

fn redact_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let lower = name.to_ascii_lowercase();
            let secret = lower == "authorization"
                || lower.contains("cookie")
                || (lower.contains("token") && lower != "x-snowflake-authorization-token-type");
            (
                name.clone(),
                if secret {
                    REDACTED.to_owned()
                } else {
                    value.clone()
                },
            )
        })
        .collect()
}

fn decode_body(response: &Response) -> (Option<String>, Vec<u8>) {
    let gzip = response.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-encoding") && value.trim().eq_ignore_ascii_case("gzip")
    });
    if !gzip {
        return (None, response.body.clone());
    }
    let mut decoded = Vec::new();
    let mut decompressor =
        GzipDecompressor::new(DecompressionLimit::new(MAX_TRANSCRIPT_BODY_BYTES));
    match decompressor
        .decompress(response.body.as_slice(), &mut decoded)
        .and_then(|()| decompressor.finish(&mut decoded))
    {
        Ok(()) => (Some("gzip".to_owned()), decoded),
        // Keep the undecodable bytes as text evidence, marked.
        Err(_) => (Some("gzip-undecodable".to_owned()), response.body.clone()),
    }
}

fn collect_path_ids(path: &str, found: &mut Vec<String>) {
    let segments: Vec<&str> = path.split('/').collect();
    for (index, segment) in segments.iter().enumerate() {
        if *segment == "statements"
            && let Some(handle) = segments.get(index + 1).filter(|next| !next.is_empty())
        {
            found.push((*handle).to_owned());
        }
    }
}

fn collect_body_ids(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                match (key.as_str(), child) {
                    ("statementHandle" | "requestId" | "queryId", Value::String(id)) => {
                        found.push(id.clone());
                    }
                    ("statementHandles", Value::Array(items)) => {
                        found.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
                    }
                    ("statementStatusUrl", Value::String(url)) => {
                        collect_path_ids(split_url(url).0.as_str(), found);
                    }
                    _ => collect_body_ids(child, found),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_body_ids(item, found);
            }
        }
        _ => {}
    }
}

fn replace_ignore_ascii_case(text: &str, needle: &str, replacement: &str) -> String {
    if needle.is_empty() {
        return text.to_owned();
    }
    let lower_text = text.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    while let Some(at) = lower_text[from..].find(&lower_needle) {
        let start = from + at;
        out.push_str(&text[from..start]);
        out.push_str(replacement);
        from = start + needle.len();
    }
    out.push_str(&text[from..]);
    out
}

/// `Bearer ` followed by 16 or more token characters.
fn has_bearer_shape(text: &str) -> bool {
    text.match_indices("Bearer ").any(|(at, prefix)| {
        text[at + prefix.len()..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .count()
            >= 16
    })
}

/// Serves a directory of transcripts back, in order: each request takes the
/// first unused transcript with the same method, path, and `partition`
/// parameter. A gzip body is re-encoded, so the driver's decode path runs.
#[derive(Debug)]
pub struct ReplayHttp {
    transcripts: Vec<Transcript>,
    used: Mutex<Vec<bool>>,
}

impl ReplayHttp {
    /// Load every `NNN-<route>.json` in `dir`, in sequence order.
    ///
    /// # Errors
    /// A file that is unreadable or not a transcript.
    pub fn from_dir(dir: &Path) -> Result<Self, String> {
        let mut transcripts = Vec::new();
        let entries =
            std::fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            let is_transcript = path.extension().is_some_and(|ext| ext == "json")
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.as_bytes().first().is_some_and(u8::is_ascii_digit));
            if !is_transcript {
                continue;
            }
            let raw =
                std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            let transcript: Transcript = serde_json::from_slice(&raw)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            transcripts.push(transcript);
        }
        transcripts.sort_by_key(|transcript| transcript.seq);
        let used = Mutex::new(vec![false; transcripts.len()]);
        Ok(Self { transcripts, used })
    }

    /// The loaded transcripts, in order.
    #[must_use]
    pub fn transcripts(&self) -> &[Transcript] {
        &self.transcripts
    }

    /// How many transcripts no request has taken yet.
    #[must_use]
    pub fn unused(&self) -> usize {
        match self.used.lock() {
            Ok(used) => used.iter().filter(|taken| !**taken).count(),
            Err(poisoned) => poisoned
                .into_inner()
                .iter()
                .filter(|taken| !**taken)
                .count(),
        }
    }

    fn take(&self, method: &str, url: &str) -> Option<Transcript> {
        let (path, query) = split_url(url);
        let partition = |query: &[(String, String)]| {
            query
                .iter()
                .find(|(key, _)| key == "partition")
                .map(|(_, value)| value.clone())
        };
        let wanted = partition(&query);
        let mut used = match self.used.lock() {
            Ok(used) => used,
            Err(poisoned) => poisoned.into_inner(),
        };
        let index = self
            .transcripts
            .iter()
            .enumerate()
            .position(|(index, transcript)| {
                !used[index]
                    && transcript.request.method == method
                    && transcript.request.path == path
                    && partition(&transcript.request.query) == wanted
            })?;
        used[index] = true;
        Some(self.transcripts[index].clone())
    }
}

impl RawHttp for ReplayHttp {
    async fn send(
        &self,
        _cx: &Cx,
        method: Method,
        url: String,
        _headers: Vec<(String, String)>,
        _body: Vec<u8>,
        _timeout: Option<Duration>,
    ) -> Result<Response, AsupersyncClientError> {
        let Some(transcript) = self.take(method.as_str(), &url) else {
            return Err(AsupersyncClientError::InvalidUrl(format!(
                "no unused transcript for {} {}",
                method.as_str(),
                split_url(&url).0
            )));
        };
        let recorded = &transcript.response;
        let mut body = recorded.body.to_bytes();
        let gzip = recorded.content_encoding.as_deref() == Some("gzip");
        if gzip {
            let mut compressed = Vec::new();
            let mut compressor = GzipCompressor::new();
            if compressor
                .compress(&body, &mut compressed)
                .and_then(|()| compressor.finish(&mut compressed))
                .is_ok()
            {
                body = compressed;
            }
        }
        let mut response = Response::new(recorded.status, recorded.reason.clone(), body);
        for (name, value) in &recorded.headers {
            // The recorded headers describe the decoded body; length and
            // encoding are the ones this response actually has.
            if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("content-encoding")
            {
                continue;
            }
            response = response.with_header(name.clone(), value.clone());
        }
        if gzip {
            response = response.with_header("Content-Encoding", "gzip");
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "acme-prod.snowflakecomputing.com";
    const HANDLE: &str = "01b2c3d4-0000-0000-0000-00000000abcd";
    const REQUEST: &str = "5d0f1b2a-1111-4222-8333-444455556666";
    const TOKEN: &str = "pat-secret-value-0123456789abcdef";

    fn dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fsnow-capture-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut compressor = GzipCompressor::new();
        compressor.compress(bytes, &mut out).expect("compress");
        compressor.finish(&mut out).expect("finish");
        out
    }

    fn read(dir: &Path, name: &str) -> String {
        std::fs::read_to_string(dir.join(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
    }

    /// A submit, a poll and a gzip partition are written without the host, the
    /// account, the token or the real ids, and replay serves them back: the
    /// same statuses and decoded bodies, with the handle the driver will follow.
    #[test]
    fn exchanges_are_redacted_normalized_and_replayable() {
        let out = dir("roundtrip");
        let recorder = TranscriptRecorder::new(&out, HOST)
            .expect("recorder")
            .with_secrets([TOKEN.to_owned()]);
        let auth = vec![
            ("Authorization".to_owned(), format!("Bearer {TOKEN}")),
            ("User-Agent".to_owned(), "franken-snowflake/0".to_owned()),
        ];
        let submit_body = format!(
            r#"{{"statementHandle":"{HANDLE}","statementStatusUrl":"/api/v2/statements/{HANDLE}","code":"333334","message":"running on acme-prod"}}"#
        );
        recorder.record(
            "POST",
            &format!("https://{HOST}/api/v2/statements?requestId={REQUEST}&retry=true"),
            &auth,
            br#"{"statement":"select 1"}"#,
            &Response::new(202, "Accepted", submit_body.into_bytes()),
        );
        recorder.record(
            "GET",
            &format!("https://{HOST}/api/v2/statements/{HANDLE}?partition=1"),
            &auth,
            b"",
            &Response::new(200, "OK", gzip(br#"{"data":[["x"]]}"#))
                .with_header("Content-Encoding", "gzip"),
        );

        let submit = read(&out, "001-submit.json");
        let partition = read(&out, "002-partition.json");
        for text in [&submit, &partition] {
            assert!(
                !text.contains(HOST) && !text.contains("acme-prod"),
                "{text}"
            );
            assert!(!text.contains(TOKEN) && !text.contains(HANDLE), "{text}");
            assert!(text.contains(REDACTED), "{text}");
        }
        assert!(
            submit.contains("00000000-0000-4000-8000-000000000002"),
            "{submit}"
        );
        assert!(!submit.contains(REQUEST), "{submit}");
        assert!(
            partition.contains(r#""content_encoding": "gzip""#),
            "{partition}"
        );
        let recorded: Transcript = serde_json::from_str(&partition).expect("transcript");
        assert_eq!(
            recorded.response.body,
            TranscriptBody::Json(serde_json::json!({"data": [["x"]]})),
            "the gzip body is decoded"
        );

        let replay = ReplayHttp::from_dir(&out).expect("load");
        assert_eq!(replay.transcripts().len(), 2);
        asupersync::test_utils::run_test_with_cx(|cx| async move {
            let handle = "00000000-0000-4000-8000-000000000002";
            let submitted = replay
                .send(
                    &cx,
                    Method::Post,
                    "https://example.test/api/v2/statements?requestId=fresh".to_owned(),
                    vec![],
                    vec![],
                    None,
                )
                .await
                .expect("submit replayed");
            assert_eq!(submitted.status, 202);
            let body: Value = serde_json::from_slice(&submitted.body).expect("json");
            assert_eq!(body["statementHandle"], handle);
            let fetched = replay
                .send(
                    &cx,
                    Method::Get,
                    format!("https://example.test/api/v2/statements/{handle}?partition=1"),
                    vec![],
                    vec![],
                    None,
                )
                .await
                .expect("partition replayed");
            assert!(
                fetched
                    .headers
                    .iter()
                    .any(|(name, value)| name == "Content-Encoding" && value == "gzip")
            );
            let (_, decoded) = decode_body(&fetched);
            assert_eq!(decoded, br#"{"data":[["x"]]}"#);
            // Negative: nothing is left for a second partition-1 fetch.
            assert!(
                replay
                    .send(
                        &cx,
                        Method::Get,
                        format!("https://example.test/api/v2/statements/{handle}?partition=1"),
                        vec![],
                        vec![],
                        None,
                    )
                    .await
                    .is_err()
            );
        });
    }

    /// A secret the redaction does not cover (here, echoed in a response
    /// message) stops the transcript: only a reason is written.
    #[test]
    fn a_transcript_holding_a_secret_is_refused() {
        let out = dir("refused");
        let recorder = TranscriptRecorder::new(&out, HOST)
            .expect("recorder")
            .with_secrets([TOKEN.to_owned()]);
        let echoed = format!(r#"{{"code":"390303","message":"token {TOKEN} expired"}}"#);
        recorder.record(
            "POST",
            &format!("https://{HOST}/api/v2/statements"),
            &[],
            b"{}",
            &Response::new(401, "Unauthorized", echoed.into_bytes()),
        );
        let names: Vec<String> = std::fs::read_dir(&out)
            .expect("dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, vec!["refused-001.txt".to_owned()]);
        let reason = read(&out, "refused-001.txt");
        assert!(
            reason.contains("secret") && !reason.contains(TOKEN),
            "{reason}"
        );

        // A bearer shape with no registered secret is refused too.
        let bare = TranscriptRecorder::new(&out, HOST).expect("recorder");
        bare.record(
            "GET",
            &format!("https://{HOST}/api/v2/statements/{HANDLE}"),
            &[],
            b"",
            &Response::new(
                200,
                "OK",
                b"{\"echo\":\"Bearer abcdefghijklmnopqrstuvwxyz\"}".to_vec(),
            ),
        );
        assert!(!out.join("002-poll.json").exists() && !out.join("001-poll.json").exists());
    }

    #[test]
    fn routes_are_named_from_method_and_path() {
        let route = |method: &str, url: &str| {
            let (path, query) = split_url(url);
            route_of(method, &path, &query)
        };
        assert_eq!(
            route("POST", "https://h/api/v2/statements?requestId=a"),
            "submit"
        );
        assert_eq!(route("GET", "https://h/api/v2/statements/abc"), "poll");
        assert_eq!(
            route("GET", "https://h/api/v2/statements/abc?partition=2"),
            "partition"
        );
        assert_eq!(
            route("POST", "https://h/api/v2/statements/abc/cancel"),
            "cancel"
        );
        assert_eq!(route("GET", "https://h/oauth/token"), "other");
    }
}
