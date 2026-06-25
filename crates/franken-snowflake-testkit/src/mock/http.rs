//! Transport-neutral HTTP request/response types and HTTP/1.1 wire framing.
//!
//! These carry only what the mock SQL API cares about — method, path, headers,
//! and a byte body — so they work equally for the integration lane (a
//! `fastapi_rust` handler) and the codec lane ([`MockHttpResponse::to_wire`]
//! over a `VirtualTcpStream`). No `asupersync`, no sockets.

use std::fmt;

use franken_snowflake_core::redact::redact;

/// The HTTP method, as the mock distinguishes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Method {
    /// `GET` — poll a statement handle or fetch a partition.
    Get,
    /// `POST` — submit a statement or cancel a handle.
    Post,
    /// Any other method, carried verbatim (upper-cased by convention).
    Other(String),
}

impl Method {
    /// The wire token for this method.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Other(token) => token,
        }
    }
}

/// The SQL API response-status classification mirrored by the mock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseClass {
    /// `200`: completed result or cancel acknowledgement.
    Completed,
    /// `202`: statement accepted and still running.
    Running,
    /// `408`: statement timeout.
    StatementTimeout,
    /// `422`: SQL compilation/execution failure.
    StatementFailed,
    /// `429`: server rate limit / overload.
    RateLimited,
    /// Any other status code.
    Other(u16),
}

impl ResponseClass {
    /// Classify a raw status code.
    #[must_use]
    pub const fn from_status(status: u16) -> Self {
        match status {
            200 => Self::Completed,
            202 => Self::Running,
            408 => Self::StatementTimeout,
            422 => Self::StatementFailed,
            429 => Self::RateLimited,
            other => Self::Other(other),
        }
    }
}

/// A request the mock receives.
#[derive(Clone, PartialEq, Eq)]
pub struct MockHttpRequest {
    /// HTTP method.
    pub method: Method,
    /// Request target, including any query string (e.g. `/api/v2/statements?async=true`).
    pub path: String,
    /// Header name/value pairs, in send order.
    pub headers: Vec<(String, String)>,
    /// Request body bytes (empty for a `GET`).
    pub body: Vec<u8>,
}

impl fmt::Debug for MockHttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockHttpRequest")
            .field("method", &self.method)
            .field("path", &redact(&self.path))
            .field("headers", &redacted_headers(&self.headers))
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl MockHttpRequest {
    /// A `GET` for `path` with no headers or body.
    #[must_use]
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            method: Method::Get,
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A `POST` to `path` carrying `body`.
    #[must_use]
    pub fn post(path: impl Into<String>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            method: Method::Post,
            path: path.into(),
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// Add a header (builder style).
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the bearer `Authorization` header (builder style).
    #[must_use]
    pub fn with_bearer(self, token: impl Into<String>) -> Self {
        self.with_header("Authorization", format!("Bearer {}", token.into()))
    }

    /// Look up a header value case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The `Authorization` header, if present.
    #[must_use]
    pub fn authorization(&self) -> Option<&str> {
        self.header("Authorization")
    }
}

/// A response the mock returns.
#[derive(Clone, PartialEq, Eq)]
pub struct MockHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Header name/value pairs, in emit order. `Content-Length` is appended by
    /// [`MockHttpResponse::to_wire`] when absent.
    pub headers: Vec<(String, String)>,
    /// Response body bytes (already gzip-compressed when `Content-Encoding: gzip`).
    pub body: Vec<u8>,
}

impl fmt::Debug for MockHttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockHttpResponse")
            .field("status", &self.status)
            .field("headers", &redacted_headers(&self.headers))
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl MockHttpResponse {
    /// A JSON response: `Content-Type: application/json` over `body`.
    #[must_use]
    pub fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: body.into(),
        }
    }

    /// A gzip-compressed JSON response: `Content-Type: application/json` plus
    /// `Content-Encoding: gzip`. `gz_body` must already be gzip bytes.
    #[must_use]
    pub fn gzip_json(status: u16, gz_body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("Content-Encoding".to_owned(), "gzip".to_owned()),
            ],
            body: gz_body.into(),
        }
    }

    /// Add a header (builder style).
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// The SQL API classification of this response's status code.
    #[must_use]
    pub fn class(&self) -> ResponseClass {
        ResponseClass::from_status(self.status)
    }

    /// Whether a header is present (case-insensitive).
    #[must_use]
    pub fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case(name))
    }

    /// Render this response as raw HTTP/1.1 bytes: status line, headers (with an
    /// auto `Content-Length` when absent), the CRLF separator, then the body.
    /// This is the golden protocol packet a codec test replays over a stream.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.body.len());
        extend(&mut out, "HTTP/1.1 ");
        extend(&mut out, &self.status.to_string());
        out.push(b' ');
        extend(&mut out, reason_phrase(self.status));
        extend(&mut out, "\r\n");
        for (name, value) in &self.headers {
            extend(&mut out, name);
            extend(&mut out, ": ");
            extend(&mut out, value);
            extend(&mut out, "\r\n");
        }
        if !self.has_header("Content-Length") {
            extend(&mut out, "Content-Length: ");
            extend(&mut out, &self.body.len().to_string());
            extend(&mut out, "\r\n");
        }
        extend(&mut out, "\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

fn redacted_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| (name.clone(), redact(value).into_owned()))
        .collect()
}

fn extend(buffer: &mut Vec<u8>, text: &str) {
    buffer.extend_from_slice(text.as_bytes());
}

/// The reason phrase for the SQL API status codes (and a few transport codes).
#[must_use]
pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        408 => "Request Timeout",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_wire_frames_status_headers_and_auto_content_length() -> Result<(), String> {
        let response = MockHttpResponse::json(202, b"{\"code\":\"333334\"}".to_vec());
        let wire = response.to_wire();
        let text = std::str::from_utf8(&wire).map_err(|_| "wire is not UTF-8".to_owned())?;
        assert!(text.starts_with("HTTP/1.1 202 Accepted\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        // Content-Length is computed from the body and the head ends in a blank line.
        assert!(text.contains("Content-Length: 17\r\n"));
        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or("missing header terminator")?;
        assert!(!head.contains("\r\n\r\n"));
        assert_eq!(body, "{\"code\":\"333334\"}");
        Ok(())
    }

    #[test]
    fn class_routes_status_codes() {
        assert_eq!(
            MockHttpResponse::json(200, vec![]).class(),
            ResponseClass::Completed
        );
        assert_eq!(
            MockHttpResponse::json(202, vec![]).class(),
            ResponseClass::Running
        );
        assert_eq!(
            MockHttpResponse::json(429, vec![]).class(),
            ResponseClass::RateLimited
        );
    }

    #[test]
    fn request_headers_are_case_insensitive() {
        let request = MockHttpRequest::get("/api/v2/statements/x").with_bearer("tok");
        assert_eq!(request.header("authorization"), Some("Bearer tok"));
        assert_eq!(request.authorization(), Some("Bearer tok"));
        assert_eq!(request.header("missing"), None);
    }

    #[test]
    fn mock_http_debug_redacts_paths_headers_and_body_bytes() {
        let request = MockHttpRequest::post(
            "/api/v2/statements?requestId=sfpat_mock_path_secret_123",
            b"sfpat_mock_body_secret_123".to_vec(),
        )
        .with_bearer("ghp_mock_header_secret_123");
        let response = MockHttpResponse::json(200, b"sfpat_mock_response_secret_123".to_vec())
            .with_header("X-Token", "ghp_mock_response_header_secret_123");
        let decimal_secret_prefix = "115, 102, 112, 97, 116";

        for rendered in [format!("{request:?}"), format!("{response:?}")] {
            assert!(!rendered.contains("sfpat_mock_path_secret_123"));
            assert!(!rendered.contains("ghp_mock_header_secret_123"));
            assert!(!rendered.contains("sfpat_mock_body_secret_123"));
            assert!(!rendered.contains("sfpat_mock_response_secret_123"));
            assert!(!rendered.contains("ghp_mock_response_header_secret_123"));
            assert!(!rendered.contains(decimal_secret_prefix));
            assert!(rendered.contains("[REDACTED]"));
            assert!(rendered.contains("body_len"));
        }
    }

    #[test]
    fn gzip_response_advertises_content_encoding() {
        let response = MockHttpResponse::gzip_json(200, vec![0x1f, 0x8b]);
        assert!(response.has_header("Content-Encoding"));
        let text = String::from_utf8_lossy(&response.to_wire()).into_owned();
        assert!(text.contains("Content-Encoding: gzip\r\n"));
    }
}
