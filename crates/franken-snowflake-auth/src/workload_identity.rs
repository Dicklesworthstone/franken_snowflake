//! RFC 7523 Native OIDC Workload Identity Federation for keyless cloud agents.
//!
//! Enables agents running in Kubernetes (IRSA, projected service account tokens),
//! AWS, GCP, Azure, or GitHub Actions to authenticate to Snowflake by exchanging
//! a short-lived OIDC JWT assertion for a Snowflake OAuth session token without
//! storing any static private keys or PATs.
//!
//! Conforms strictly to:
//! - RFC 7523: JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication
//!   and Authorization Grants (`urn:ietf:params:oauth:grant-type:jwt-bearer`).
//! - RFC 7519: JSON Web Token (JWT) format and standard claims (`exp`, `iat`, `iss`, `sub`).
//! - Snowflake OAuth 2.0 Workload Identity token-exchange endpoint.

use std::fmt;
use std::future::Future;
use std::path::Path;

use asupersync::Cx;
use asupersync::http::{Client as AsupersyncHttpClient, Method};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};

use crate::redaction_policy::REDACTED;
use crate::{
    AuthError, AuthHeaders, AuthLane, CredentialLifetime, OAUTH_TOKEN_TYPE, SecretPresence,
    SecretResolver, SecretSourceKind, SecretValue, SnowflakeAuth, opaque_credential_handle,
};

/// RFC 7523 OAuth 2.0 grant type URI for JWT Bearer Token Exchange.
pub const RFC7523_JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Default OAuth scope requested for Snowflake SQL API sessions.
pub const DEFAULT_OIDC_SCOPE: &str = "session:role-any";

/// Default window before expiration (in seconds) to trigger token renewal.
pub const DEFAULT_PRE_EXPIRY_REFRESH_SECONDS: u64 = 60;

/// Default Snowflake OAuth token-request path.
pub const SNOWFLAKE_OAUTH_TOKEN_REQUEST_PATH: &str = "/oauth/token-request";

/// Trait defining the asynchronous HTTP exchange required for OIDC token grants.
pub trait OidcHttpExchange: Send + Sync {
    fn post_form(
        &self,
        cx: &Cx,
        url: &str,
        form_body: &str,
    ) -> impl Future<Output = Result<(u16, Vec<u8>), AuthError>> + Send;
}

impl OidcHttpExchange for AsupersyncHttpClient {
    async fn post_form(
        &self,
        cx: &Cx,
        url: &str,
        form_body: &str,
    ) -> Result<(u16, Vec<u8>), AuthError> {
        let headers = [
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "application/json"),
        ];
        let resp = self
            .request_builder(Method::Post, url)
            .headers(headers)
            .body(form_body.as_bytes().to_vec())
            .send(cx)
            .await
            .map_err(|err| AuthError::OidcTokenExchangeFailed {
                status_code: 0,
                reason: format!("network transport error contacting token endpoint `{url}`: {err}"),
            })?;
        Ok((resp.status, resp.body))
    }
}

/// A non-secret pointer to an OIDC token assertion.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OidcTokenSource {
    EnvVar {
        #[serde(skip_serializing)]
        name: String,
    },
    File {
        path: String,
    },
    SecretProvider {
        handle: String,
    },
}

impl OidcTokenSource {
    #[must_use]
    pub fn env_var(name: impl Into<String>) -> Self {
        Self::EnvVar { name: name.into() }
    }

    #[must_use]
    pub fn file(path: impl Into<String>) -> Self {
        Self::File { path: path.into() }
    }

    #[must_use]
    pub fn secret_provider(handle: impl Into<String>) -> Self {
        Self::SecretProvider {
            handle: handle.into(),
        }
    }

    #[must_use]
    pub fn credential_handle(&self) -> String {
        match self {
            Self::EnvVar { name } => opaque_credential_handle("env", name),
            Self::File { path } => format!("file:{path}"),
            Self::SecretProvider { handle } => opaque_credential_handle("provider", handle),
        }
    }

    pub fn probe_offline<R: SecretResolver>(
        &self,
        resolver: &R,
    ) -> (SecretSourceKind, SecretPresence) {
        match self {
            Self::EnvVar { name } => {
                let presence = if resolver.env_var_present(name) {
                    SecretPresence::Present
                } else {
                    SecretPresence::Missing
                };
                (SecretSourceKind::EnvVar, presence)
            }
            Self::File { path } => {
                let presence = if Path::new(path).is_file() {
                    SecretPresence::Present
                } else {
                    SecretPresence::Missing
                };
                (SecretSourceKind::EnvVar, presence)
            }
            Self::SecretProvider { .. } => (
                SecretSourceKind::SecretProvider,
                SecretPresence::UnknownExternal,
            ),
        }
    }

    pub fn resolve<R: SecretResolver>(&self, resolver: &R) -> Result<SecretValue, AuthError> {
        match self {
            Self::EnvVar { name } => resolver.read_env_secret(name),
            Self::File { path } => {
                let content =
                    std::fs::read_to_string(path).map_err(|err| AuthError::OidcAssertionIo {
                        path: path.clone(),
                        reason: err.to_string(),
                    })?;
                let trimmed = content.trim();
                if trimmed.is_empty() {
                    return Err(AuthError::OidcAssertionMalformed {
                        reason: format!("token file `{path}` is empty"),
                        remediation: "ensure projected service account token or file contains a non-empty OIDC JWT".to_string(),
                    });
                }
                SecretValue::new(trimmed)
            }
            Self::SecretProvider { handle } => resolver.read_provider_secret(handle),
        }
    }
}

impl fmt::Debug for OidcTokenSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EnvVar { name } => f
                .debug_struct("OidcTokenSource::EnvVar")
                .field("credential_handle", &opaque_credential_handle("env", name))
                .finish(),
            Self::File { path } => f
                .debug_struct("OidcTokenSource::File")
                .field("path", path)
                .finish(),
            Self::SecretProvider { handle } => f
                .debug_struct("OidcTokenSource::SecretProvider")
                .field("handle", handle)
                .finish(),
        }
    }
}

impl fmt::Display for OidcTokenSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.credential_handle())
    }
}

/// Standard claims extracted from an OIDC assertion JWT.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcAssertionClaims {
    pub exp: i64,
    pub iat: Option<i64>,
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
}

/// Decodes and validates an OIDC JWT assertion client-side prior to network exchange.
///
/// Fail-closed checks:
/// 1. Verifies non-empty string.
/// 2. Verifies RFC 7519 structure (exactly 3 dot-separated segments).
/// 3. Decodes Base64URL payload and parses JSON claims.
/// 4. Validates required `exp` claim.
/// 5. Validates `exp > now_unix_seconds`. Expired assertions are rejected immediately
///    with `FSNOW-2004` (`AuthError::OidcAssertionExpired`) without issuing an HTTP request.
pub fn parse_and_validate_oidc_assertion(
    raw_jwt: &str,
    now_unix_seconds: i64,
) -> Result<OidcAssertionClaims, AuthError> {
    let trimmed = raw_jwt.trim();
    if trimmed.is_empty() {
        return Err(AuthError::EmptySecretValue);
    }
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::OidcAssertionMalformed {
            reason: format!("expected 3 dot-separated JWT segments, got {}", parts.len()),
            remediation: "ensure the credential source yields a standard RFC 7519 JWT assertion"
                .to_string(),
        });
    }

    let payload_bytes =
        decode_jwt_segment(parts[1]).map_err(|err| AuthError::OidcAssertionMalformed {
            reason: format!("failed to decode JWT payload base64url: {err}"),
            remediation: "ensure OIDC token payload is standard base64url encoded".to_string(),
        })?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).map_err(|err| {
        AuthError::OidcAssertionMalformed {
            reason: format!("failed to parse JWT payload JSON: {err}"),
            remediation: "ensure OIDC token payload is valid JSON".to_string(),
        }
    })?;

    let exp = payload.get("exp").and_then(|v| v.as_i64()).ok_or_else(|| {
        AuthError::OidcAssertionMalformed {
            reason: "missing required `exp` (expiration) timestamp claim in OIDC assertion"
                .to_string(),
            remediation: "ensure cloud STS / IdP issues a JWT with standard `exp` in Unix seconds"
                .to_string(),
        }
    })?;

    let iat = payload.get("iat").and_then(|v| v.as_i64());
    let iss = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let sub = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let aud = payload.get("aud").and_then(|v| {
        if let Some(s) = v.as_str() {
            Some(s.to_string())
        } else if let Some(arr) = v.as_array() {
            arr.first()
                .and_then(|first| first.as_str())
                .map(str::to_string)
        } else {
            None
        }
    });

    if exp <= now_unix_seconds {
        return Err(AuthError::OidcAssertionExpired {
            expires_at_unix_seconds: exp,
            now_unix_seconds,
            remediation: "refresh the cloud STS or projected service account token assertion"
                .to_string(),
        });
    }

    Ok(OidcAssertionClaims {
        exp,
        iat,
        iss,
        sub,
        aud,
    })
}

fn decode_jwt_segment(segment: &str) -> Result<Vec<u8>, String> {
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(segment) {
        return Ok(bytes);
    }
    if let Ok(bytes) = URL_SAFE.decode(segment) {
        return Ok(bytes);
    }
    let padded = match segment.len() % 4 {
        2 => format!("{segment}=="),
        3 => format!("{segment}="),
        _ => segment.to_string(),
    };
    URL_SAFE
        .decode(&padded)
        .or_else(|_| STANDARD.decode(&padded))
        .map_err(|e| e.to_string())
}

/// Format the RFC 7523 application/x-www-form-urlencoded POST body.
#[must_use]
pub fn format_rfc7523_form_body(
    assertion: &str,
    scope: Option<&str>,
    client_id: Option<&str>,
) -> String {
    let mut parts = Vec::with_capacity(4);
    parts.push(format!(
        "grant_type={}",
        url_encode(RFC7523_JWT_BEARER_GRANT_TYPE)
    ));
    parts.push(format!("assertion={}", url_encode(assertion)));
    let scope_val = scope.unwrap_or(DEFAULT_OIDC_SCOPE);
    parts.push(format!("scope={}", url_encode(scope_val)));
    if let Some(cid) = client_id.filter(|cid| !cid.trim().is_empty()) {
        parts.push(format!("client_id={}", url_encode(cid)));
    }
    parts.join("&")
}

fn url_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

/// An exchanged, short-lived Snowflake session token and lifetime metadata.
#[derive(Clone)]
pub struct SnowflakeSessionToken {
    session_token: SecretValue,
    token_type: String,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    scope: Option<String>,
}

impl SnowflakeSessionToken {
    pub fn new(
        token: impl Into<String>,
        token_type: impl Into<String>,
        issued_at_unix_seconds: i64,
        expires_at_unix_seconds: i64,
        scope: Option<String>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            session_token: SecretValue::new(token)?,
            token_type: token_type.into(),
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            scope,
        })
    }

    #[must_use]
    pub fn session_token_secret(&self) -> &SecretValue {
        &self.session_token
    }

    #[must_use]
    pub fn expose_token(&self) -> &str {
        self.session_token.expose_secret()
    }

    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    #[must_use]
    pub fn issued_at_unix_seconds(&self) -> i64 {
        self.issued_at_unix_seconds
    }

    #[must_use]
    pub fn expires_at_unix_seconds(&self) -> i64 {
        self.expires_at_unix_seconds
    }

    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    #[must_use]
    pub fn is_expired(&self, now_unix_seconds: i64) -> bool {
        self.expires_at_unix_seconds <= now_unix_seconds
    }

    #[must_use]
    pub fn needs_refresh(&self, now_unix_seconds: i64, refresh_window_seconds: u64) -> bool {
        let remaining = self
            .expires_at_unix_seconds
            .saturating_sub(now_unix_seconds);
        remaining <= refresh_window_seconds as i64
    }
}

impl fmt::Debug for SnowflakeSessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowflakeSessionToken")
            .field("session_token", &REDACTED)
            .field("token_type", &self.token_type)
            .field("issued_at_unix_seconds", &self.issued_at_unix_seconds)
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .field("scope", &self.scope)
            .finish()
    }
}

impl fmt::Display for SnowflakeSessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SnowflakeSessionToken([REDACTED])")
    }
}

/// Parses the JSON response received from the Snowflake OAuth token-request endpoint.
pub fn parse_rfc7523_token_response(
    status_code: u16,
    body: &[u8],
    now_unix_seconds: i64,
) -> Result<SnowflakeSessionToken, AuthError> {
    if status_code != 200 {
        let err_msg = if let Ok(val) = serde_json::from_slice::<serde_json::Value>(body) {
            val.get("error_description")
                .or_else(|| val.get("error"))
                .or_else(|| val.get("message"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error")
                .to_string()
        } else {
            String::from_utf8_lossy(body).to_string()
        };
        return Err(AuthError::OidcTokenExchangeFailed {
            status_code,
            reason: format!("Snowflake token endpoint answered status {status_code}: {err_msg}"),
        });
    }

    let parsed: serde_json::Value =
        serde_json::from_slice(body).map_err(|err| AuthError::OidcTokenExchangeFailed {
            status_code,
            reason: format!("failed to parse token endpoint JSON response: {err}"),
        })?;

    let access_token_str = parsed
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::OidcTokenExchangeFailed {
            status_code,
            reason: "missing `access_token` in response body".to_string(),
        })?;

    let token_type = parsed
        .get("token_type")
        .and_then(|v| v.as_str())
        .unwrap_or("Bearer")
        .to_string();

    let expires_in = parsed
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);

    let scope = parsed
        .get("scope")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let expires_at_unix_seconds = now_unix_seconds.saturating_add(expires_in as i64);

    SnowflakeSessionToken::new(
        access_token_str,
        token_type,
        now_unix_seconds,
        expires_at_unix_seconds,
        scope,
    )
}

/// Workload Identity Federation Authenticator.
///
/// Holds configuration, token source pointers, and a cached Snowflake session token.
#[derive(Clone)]
pub struct WorkloadIdentityAuth {
    account: String,
    user: String,
    assertion_source: OidcTokenSource,
    endpoint_url: String,
    scope: String,
    client_id: Option<String>,
    refresh_before_expiry_seconds: u64,
    credential_handle: Option<String>,
    cached_session: Option<SnowflakeSessionToken>,
}

impl WorkloadIdentityAuth {
    pub fn new(
        account: impl Into<String>,
        user: impl Into<String>,
        token_source: OidcTokenSource,
        token_url: Option<String>,
        scope: Option<String>,
        client_id: Option<String>,
        refresh_before_expiry_seconds: Option<u64>,
    ) -> Result<Self, AuthError> {
        let account = account.into();
        let user = user.into();
        if account.trim().is_empty() {
            return Err(AuthError::EmptyAccount);
        }
        if user.trim().is_empty() {
            return Err(AuthError::EmptyUser);
        }
        let endpoint_url = token_url.unwrap_or_else(|| {
            let acct = account.trim();
            if acct.starts_with("http://") || acct.starts_with("https://") {
                format!("{acct}{SNOWFLAKE_OAUTH_TOKEN_REQUEST_PATH}")
            } else {
                format!("https://{acct}.snowflakecomputing.com{SNOWFLAKE_OAUTH_TOKEN_REQUEST_PATH}")
            }
        });
        let credential_handle = Some(token_source.credential_handle());
        Ok(Self {
            account,
            user,
            assertion_source: token_source,
            endpoint_url,
            scope: scope.unwrap_or_else(|| DEFAULT_OIDC_SCOPE.to_string()),
            client_id,
            refresh_before_expiry_seconds: refresh_before_expiry_seconds
                .unwrap_or(DEFAULT_PRE_EXPIRY_REFRESH_SECONDS),
            credential_handle,
            cached_session: None,
        })
    }

    #[must_use]
    pub fn with_cached_session_token(mut self, session_token: SnowflakeSessionToken) -> Self {
        self.cached_session = Some(session_token);
        self
    }

    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    #[must_use]
    pub fn token_source(&self) -> &OidcTokenSource {
        &self.assertion_source
    }

    #[must_use]
    pub fn token_url(&self) -> &str {
        &self.endpoint_url
    }

    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    #[must_use]
    pub fn refresh_before_expiry_seconds(&self) -> u64 {
        self.refresh_before_expiry_seconds
    }

    #[must_use]
    pub fn cached_session_token(&self) -> Option<&SnowflakeSessionToken> {
        self.cached_session.as_ref()
    }

    /// Perform token exchange using the given HTTP transport and resolver.
    pub async fn exchange_token_at<T: OidcHttpExchange, R: SecretResolver>(
        &mut self,
        cx: &Cx,
        transport: &T,
        resolver: &R,
        now_unix_seconds: i64,
    ) -> Result<&SnowflakeSessionToken, AuthError> {
        let raw_assertion = self.assertion_source.resolve(resolver)?;
        // Fail-closed pre-flight validation
        let _claims =
            parse_and_validate_oidc_assertion(raw_assertion.expose_secret(), now_unix_seconds)?;

        let form_body = format_rfc7523_form_body(
            raw_assertion.expose_secret(),
            Some(&self.scope),
            self.client_id.as_deref(),
        );

        let (status, body) = transport
            .post_form(cx, &self.endpoint_url, &form_body)
            .await?;
        let session_token = parse_rfc7523_token_response(status, &body, now_unix_seconds)?;
        self.cached_session = Some(session_token);
        Ok(self
            .cached_session
            .as_ref()
            .unwrap_or_else(|| unreachable!("cached_session was just set")))
    }

    /// Retrieve a valid session token, refreshing it automatically if expired or
    /// within the pre-expiry window.
    pub async fn token_for_poll_at<T: OidcHttpExchange, R: SecretResolver>(
        &mut self,
        cx: &Cx,
        transport: &T,
        resolver: &R,
        now_unix_seconds: i64,
    ) -> Result<&SnowflakeSessionToken, AuthError> {
        let needs_refresh = match &self.cached_session {
            None => true,
            Some(token) => {
                token.needs_refresh(now_unix_seconds, self.refresh_before_expiry_seconds)
            }
        };

        if needs_refresh {
            self.exchange_token_at(cx, transport, resolver, now_unix_seconds)
                .await
        } else {
            Ok(self
                .cached_session
                .as_ref()
                .unwrap_or_else(|| unreachable!("cached_session verified present")))
        }
    }
}

impl SnowflakeAuth for WorkloadIdentityAuth {
    fn lane(&self) -> AuthLane {
        AuthLane::WorkloadIdentityFederation
    }

    fn credential_handle(&self) -> Option<&str> {
        self.credential_handle.as_deref()
    }

    fn headers_at(&mut self, now_unix_seconds: i64) -> Result<AuthHeaders, AuthError> {
        let token =
            self.cached_session
                .as_ref()
                .ok_or_else(|| AuthError::OidcAssertionMalformed {
                    reason: "no active Snowflake session token; exchange required".to_string(),
                    remediation: "invoke token exchange before attempting SQL API queries"
                        .to_string(),
                })?;

        if token.is_expired(now_unix_seconds) {
            return Err(AuthError::OidcAssertionExpired {
                expires_at_unix_seconds: token.expires_at_unix_seconds,
                now_unix_seconds,
                remediation: "Snowflake session token has expired; token refresh required"
                    .to_string(),
            });
        }

        Ok(AuthHeaders::bearer(token.expose_token(), OAUTH_TOKEN_TYPE))
    }

    fn lifetime(&self) -> CredentialLifetime {
        match &self.cached_session {
            Some(token) => CredentialLifetime {
                lane: AuthLane::WorkloadIdentityFederation,
                issued_at_unix_seconds: Some(token.issued_at_unix_seconds),
                expires_at_unix_seconds: Some(token.expires_at_unix_seconds),
                expected_validity_seconds: Some(
                    token
                        .expires_at_unix_seconds
                        .saturating_sub(token.issued_at_unix_seconds)
                        .max(0) as u64,
                ),
                max_validity_seconds: Some(3600),
                refresh_before_expiry_seconds: Some(self.refresh_before_expiry_seconds),
            },
            None => CredentialLifetime {
                lane: AuthLane::WorkloadIdentityFederation,
                issued_at_unix_seconds: None,
                expires_at_unix_seconds: None,
                expected_validity_seconds: None,
                max_validity_seconds: Some(3600),
                refresh_before_expiry_seconds: Some(self.refresh_before_expiry_seconds),
            },
        }
    }

    fn on_unauthorized_mid_poll(&mut self, _now_unix_seconds: i64) -> crate::ReauthDecision {
        self.cached_session = None;
        crate::ReauthDecision::ReauthRequired {
            lane: AuthLane::WorkloadIdentityFederation,
            credential_handle: self.credential_handle.clone(),
            reason: "Snowflake returned 401 mid-poll; OIDC token re-exchange required".to_string(),
        }
    }
}

impl fmt::Debug for WorkloadIdentityAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkloadIdentityAuth")
            .field("account", &self.account)
            .field("user", &self.user)
            .field("assertion_source", &self.assertion_source)
            .field("endpoint_url", &self.endpoint_url)
            .field("scope", &self.scope)
            .field("client_id", &self.client_id)
            .field(
                "refresh_before_expiry_seconds",
                &self.refresh_before_expiry_seconds,
            )
            .field("credential_handle", &self.credential_handle)
            .field(
                "cached_session",
                &self.cached_session.as_ref().map(|_| REDACTED),
            )
            .finish()
    }
}

impl fmt::Display for WorkloadIdentityAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WorkloadIdentityAuth(account={}, user={}, handle={})",
            self.account,
            self.user,
            self.credential_handle.as_deref().unwrap_or(REDACTED)
        )
    }
}
