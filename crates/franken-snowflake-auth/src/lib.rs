//! `franken-snowflake-auth` — secret-safe Snowflake auth construction.
//!
//! Owns header construction for the supported auth lanes, in implementation
//! order: programmatic access token (PAT) bearer headers, key-pair RS256 JWT
//! signing and rotation metadata, OAuth bearer pass-through, and workload
//! identity federation placeholder types. Secret source descriptors reference
//! environment variable names or external secret handles — **never** raw secret
//! values.
//!
//! Auth constructors return redacted `Debug` output by default; the env var name
//! is `#[serde(skip_serializing)]`; and the compile-time credential `Debug`-leak
//! gate (`docs/security_model.md`, bead
//! `fsnow-native-snowflake-connector-w0i.5`) fails the build if any
//! credential-shaped field carries a derived `Debug`.
//!
//! The key-pair JWT path is pinned to `jsonwebtoken` with
//! `default-features = false, features = ["rust_crypto", "use_pem"]` (pure-Rust
//! RSA/SHA-2 RS256 — no OpenSSL, no ring signing, no Tokio). See the "Auth Crypto
//! Path" section of the plan.
//!
//! Status: Phase 0 skeleton. Implemented across
//! `fsnow-native-snowflake-connector-w0i.2` (JWT signer) and
//! `fsnow-auth-foundations-kdw` (PAT/OAuth + signer integration).

use std::env;
use std::error::Error;
use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

mod redaction_policy;
pub use redaction_policy::{
    CREDENTIAL_FIELD_MARKERS, NON_SECRET_CREDENTIAL_FIELD_MARKERS, REDACTED,
    SECRET_VALUE_NEEDLE_PREFIXES,
};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Snowflake's SQL API auth token-type header.
pub const SNOWFLAKE_AUTHORIZATION_TOKEN_TYPE_HEADER: &str = "X-Snowflake-Authorization-Token-Type";

/// Token-type value Snowflake expects for key-pair JWT auth.
pub const KEYPAIR_JWT_TOKEN_TYPE: &str = "KEYPAIR_JWT";

/// Token-type value Snowflake expects for programmatic access tokens.
pub const PROGRAMMATIC_ACCESS_TOKEN_TYPE: &str = "PROGRAMMATIC_ACCESS_TOKEN";

/// Token-type value Snowflake expects for OAuth bearer tokens.
pub const OAUTH_TOKEN_TYPE: &str = "OAUTH";

/// Standard bearer authorization header.
pub const AUTHORIZATION_HEADER: &str = "Authorization";

/// Snowflake ignores JWT validity beyond one hour.
pub const MAX_JWT_VALIDITY_SECONDS: u64 = 3_600;

/// Refresh a cached JWT this many seconds before expiry by default.
pub const DEFAULT_REFRESH_BEFORE_EXPIRY_SECONDS: u64 = 60;

/// Snowflake PATs default to 15-day expiry unless policy says otherwise.
pub const PAT_DEFAULT_VALIDITY_SECONDS: u64 = 15 * 24 * 60 * 60;

/// Snowflake caps PAT expiry policy at 365 days.
pub const PAT_MAX_VALIDITY_SECONDS: u64 = 365 * 24 * 60 * 60;

/// Snowflake OAuth access tokens are typically short lived.
pub const OAUTH_EXPECTED_VALIDITY_SECONDS: u64 = 10 * 60;

/// Structured auth log schema version.
pub const AUTH_LOG_SCHEMA_VERSION: u16 = 1;

/// Errors emitted by secret-safe auth construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    EmptyAccount,
    EmptyUser,
    EmptySecretSource { source_kind: &'static str },
    EmptySecretValue,
    MissingEnvVar { name: String, next_command: String },
    UnsupportedSecretProvider { handle: String },
    UnsupportedAuthLane { lane: AuthLane },
    InvalidPrivateKey { reason: String },
    InvalidPublicKey { reason: String },
    RsaKeyTooSmall { bits: usize },
    JwtSigning { reason: String },
    InvalidValiditySeconds,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAccount => f.write_str("Snowflake account identifier is empty"),
            Self::EmptyUser => f.write_str("Snowflake user is empty"),
            Self::EmptySecretSource { source_kind } => {
                write!(f, "{source_kind} secret source is empty")
            }
            Self::EmptySecretValue => f.write_str("resolved credential value is empty"),
            Self::MissingEnvVar { name, next_command } => {
                write!(
                    f,
                    "required credential environment variable {name} is not set; next command: {next_command}"
                )
            }
            Self::UnsupportedSecretProvider { handle } => {
                write!(
                    f,
                    "secret provider handle {handle} is not supported by this resolver"
                )
            }
            Self::UnsupportedAuthLane { lane } => {
                write!(f, "auth lane {lane} is not implemented yet")
            }
            Self::InvalidPrivateKey { reason } => {
                write!(f, "invalid RSA private key material: {reason}")
            }
            Self::InvalidPublicKey { reason } => {
                write!(f, "invalid RSA public key material: {reason}")
            }
            Self::RsaKeyTooSmall { bits } => {
                write!(
                    f,
                    "RSA key is {bits} bits; Snowflake key-pair auth requires at least 2048 bits"
                )
            }
            Self::JwtSigning { reason } => write!(f, "RS256 JWT signing failed: {reason}"),
            Self::InvalidValiditySeconds => {
                f.write_str("JWT validity must be greater than zero seconds")
            }
        }
    }
}

impl Error for AuthError {}

/// Supported Snowflake auth lanes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthLane {
    ProgrammaticAccessToken,
    KeyPairJwt,
    OAuthBearer,
    WorkloadIdentityFederation,
}

impl fmt::Display for AuthLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProgrammaticAccessToken => f.write_str("programmatic_access_token"),
            Self::KeyPairJwt => f.write_str("key_pair_jwt"),
            Self::OAuthBearer => f.write_str("oauth_bearer"),
            Self::WorkloadIdentityFederation => f.write_str("workload_identity_federation"),
        }
    }
}

/// Kind of non-secret pointer used to retrieve credential material.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretSourceKind {
    EnvVar,
    SecretProvider,
}

/// Profile-safe pointer to credential material.
///
/// This never stores the secret value. Environment variable names are accepted
/// while deserializing profiles, but skipped in serialized diagnostics so JSON
/// output only carries opaque credential handles.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecretSource {
    EnvVar {
        #[serde(skip_serializing)]
        name: String,
    },
    SecretProvider {
        handle: String,
    },
}

impl SecretSource {
    pub fn env_var(name: impl Into<String>) -> Result<Self, AuthError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(AuthError::EmptySecretSource {
                source_kind: "environment variable",
            });
        }
        Ok(Self::EnvVar { name })
    }

    pub fn secret_provider(handle: impl Into<String>) -> Result<Self, AuthError> {
        let handle = handle.into();
        if handle.trim().is_empty() {
            return Err(AuthError::EmptySecretSource {
                source_kind: "secret provider",
            });
        }
        Ok(Self::SecretProvider { handle })
    }

    #[must_use]
    pub fn kind(&self) -> SecretSourceKind {
        match self {
            Self::EnvVar { .. } => SecretSourceKind::EnvVar,
            Self::SecretProvider { .. } => SecretSourceKind::SecretProvider,
        }
    }

    #[must_use]
    pub fn credential_handle(&self) -> String {
        match self {
            Self::EnvVar { name } => opaque_credential_handle("env", name),
            Self::SecretProvider { handle } => opaque_credential_handle("provider", handle),
        }
    }

    pub fn probe_offline<R: SecretResolver>(&self, resolver: &R) -> SecretSourceStatus {
        match self {
            Self::EnvVar { name } => {
                let presence = if resolver.env_var_present(name) {
                    SecretPresence::Present
                } else {
                    SecretPresence::Missing
                };
                SecretSourceStatus {
                    source_kind: SecretSourceKind::EnvVar,
                    credential_handle: self.credential_handle(),
                    presence,
                }
            }
            Self::SecretProvider { .. } => SecretSourceStatus {
                source_kind: SecretSourceKind::SecretProvider,
                credential_handle: self.credential_handle(),
                presence: SecretPresence::UnknownExternal,
            },
        }
    }

    pub fn resolve<R: SecretResolver>(&self, resolver: &R) -> Result<SecretValue, AuthError> {
        match self {
            Self::EnvVar { name } => resolver.read_env_secret(name),
            Self::SecretProvider { handle } => resolver.read_provider_secret(handle),
        }
    }
}

impl fmt::Debug for SecretSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretSource")
            .field("kind", &self.kind())
            .field("credential_handle", &self.credential_handle())
            .finish()
    }
}

impl fmt::Display for SecretSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.credential_handle())
    }
}

/// Presence-only secret source status for offline profile validation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretPresence {
    Present,
    Missing,
    UnknownExternal,
}

/// Redacted, serializable source status for profile validation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecretSourceStatus {
    pub source_kind: SecretSourceKind,
    pub credential_handle: String,
    pub presence: SecretPresence,
}

/// Runtime secret value. Formatting and JSON serialization always redact.
#[derive(Clone, Eq, PartialEq)]
pub struct SecretValue {
    value: String,
}

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Result<Self, AuthError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(AuthError::EmptySecretValue);
        }
        Ok(Self { value })
    }

    fn expose_secret(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Serialize for SecretValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(REDACTED)
    }
}

/// Secret lookup abstraction used by profile validation and live resolution.
pub trait SecretResolver {
    fn env_var_present(&self, name: &str) -> bool;
    fn read_env_secret(&self, name: &str) -> Result<SecretValue, AuthError>;
    fn read_provider_secret(&self, handle: &str) -> Result<SecretValue, AuthError>;
}

/// Process environment resolver for live auth material resolution.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessSecretResolver;

impl SecretResolver for ProcessSecretResolver {
    fn env_var_present(&self, name: &str) -> bool {
        env::var_os(name).is_some()
    }

    fn read_env_secret(&self, name: &str) -> Result<SecretValue, AuthError> {
        let value = env::var(name).map_err(|_| AuthError::MissingEnvVar {
            name: name.to_string(),
            next_command: export_env_next_command(name),
        })?;
        SecretValue::new(value)
    }

    fn read_provider_secret(&self, handle: &str) -> Result<SecretValue, AuthError> {
        Err(AuthError::UnsupportedSecretProvider {
            handle: handle.to_string(),
        })
    }
}

/// Credential lifetime metadata surfaced to doctor-style diagnostics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialLifetime {
    pub lane: AuthLane,
    pub issued_at_unix_seconds: Option<i64>,
    pub expires_at_unix_seconds: Option<i64>,
    pub expected_validity_seconds: Option<u64>,
    pub max_validity_seconds: Option<u64>,
    pub refresh_before_expiry_seconds: Option<u64>,
}

impl CredentialLifetime {
    #[must_use]
    pub fn seconds_until_expiry(&self, now_unix_seconds: i64) -> Option<i64> {
        self.expires_at_unix_seconds
            .map(|expires_at| expires_at.saturating_sub(now_unix_seconds))
    }

    #[must_use]
    pub fn doctor_warning_at(&self, now_unix_seconds: i64) -> Option<CredentialLifetimeWarning> {
        if self.lane == AuthLane::KeyPairJwt {
            let requested = self.expected_validity_seconds?;
            let max = self.max_validity_seconds?;
            return (requested > max).then(|| CredentialLifetimeWarning {
                lane: self.lane,
                message: format!("key-pair JWT requested validity exceeds Snowflake's {max}s cap"),
            });
        }

        let remaining = self.seconds_until_expiry(now_unix_seconds)?;
        match self.lane {
            AuthLane::ProgrammaticAccessToken if remaining <= 2 * 24 * 60 * 60 => {
                Some(CredentialLifetimeWarning {
                    lane: self.lane,
                    message: format!(
                        "programmatic access token expires in {} day(s)",
                        ceil_div_i64(remaining.max(0), 24 * 60 * 60)
                    ),
                })
            }
            AuthLane::OAuthBearer if remaining <= 2 * 60 => Some(CredentialLifetimeWarning {
                lane: self.lane,
                message: format!(
                    "OAuth access token expires in {} minute(s); refresh before long polling",
                    ceil_div_i64(remaining.max(0), 60)
                ),
            }),
            _ => None,
        }
    }
}

/// Non-secret doctor warning derived from lifetime metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialLifetimeWarning {
    pub lane: AuthLane,
    pub message: String,
}

/// Structured auth event suitable for JSON-line logs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthLogLine {
    pub schema_version: u16,
    pub event: String,
    pub lane: AuthLane,
    pub credential_handle: Option<String>,
    pub message: String,
    pub lifetime: Option<CredentialLifetime>,
}

impl AuthLogLine {
    #[must_use]
    pub fn new(
        event: impl Into<String>,
        lane: AuthLane,
        credential_handle: Option<String>,
        message: impl Into<String>,
        lifetime: Option<CredentialLifetime>,
    ) -> Self {
        Self {
            schema_version: AUTH_LOG_SCHEMA_VERSION,
            event: event.into(),
            lane,
            credential_handle,
            message: message.into(),
            lifetime,
        }
    }
}

/// Common auth headers for all bearer lanes.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthHeaders {
    authorization: String,
    token_type: &'static str,
}

impl AuthHeaders {
    #[must_use]
    pub fn bearer(token: &str, token_type: &'static str) -> Self {
        Self {
            authorization: format!("Bearer {token}"),
            token_type,
        }
    }

    #[must_use]
    pub fn authorization_header_name(&self) -> &'static str {
        AUTHORIZATION_HEADER
    }

    #[must_use]
    pub fn authorization_value(&self) -> &str {
        &self.authorization
    }

    #[must_use]
    pub fn token_type_header_name(&self) -> &'static str {
        SNOWFLAKE_AUTHORIZATION_TOKEN_TYPE_HEADER
    }

    #[must_use]
    pub fn token_type_value(&self) -> &'static str {
        self.token_type
    }
}

impl fmt::Debug for AuthHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthHeaders")
            .field("authorization", &REDACTED)
            .field("token_type", &self.token_type)
            .finish()
    }
}

impl Serialize for AuthHeaders {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AuthHeaders", 2)?;
        state.serialize_field(AUTHORIZATION_HEADER, REDACTED)?;
        state.serialize_field(SNOWFLAKE_AUTHORIZATION_TOKEN_TYPE_HEADER, self.token_type)?;
        state.end()
    }
}

/// Backwards-compatible name from the JWT signer bead.
pub type KeyPairJwtHeaders = AuthHeaders;

/// Snowflake JWT claim set for key-pair auth.
///
/// `iss` intentionally includes the public-key fingerprint while `sub` does
/// not. Snowflake requires both ACCOUNT and USER to be uppercase, and accounts
/// containing dots are normalized with dots replaced by dashes.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnowflakeJwtClaims {
    pub iss: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
}

impl fmt::Debug for SnowflakeJwtClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowflakeJwtClaims")
            .field("iss", &REDACTED)
            .field("sub", &REDACTED)
            .field("iat", &self.iat)
            .field("exp", &self.exp)
            .finish()
    }
}

/// Signed Snowflake key-pair JWT plus non-secret metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedKeyPairJwt {
    token: String,
    pub claims: SnowflakeJwtClaims,
    pub public_key_fingerprint: String,
    pub issued_at_unix_seconds: i64,
    pub expires_at_unix_seconds: i64,
}

impl SignedKeyPairJwt {
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    #[must_use]
    pub fn bearer_authorization_value(&self) -> String {
        format!("Bearer {}", self.token)
    }

    #[must_use]
    pub fn headers(&self) -> KeyPairJwtHeaders {
        AuthHeaders::bearer(self.token(), KEYPAIR_JWT_TOKEN_TYPE)
    }
}

impl fmt::Debug for SignedKeyPairJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedKeyPairJwt")
            .field("token", &REDACTED)
            .field("claims", &self.claims)
            .field("public_key_fingerprint", &self.public_key_fingerprint)
            .field("issued_at_unix_seconds", &self.issued_at_unix_seconds)
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish()
    }
}

impl Serialize for SignedKeyPairJwt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SignedKeyPairJwt", 5)?;
        state.serialize_field("token", REDACTED)?;
        state.serialize_field("claims", &self.claims)?;
        state.serialize_field("public_key_fingerprint", &self.public_key_fingerprint)?;
        state.serialize_field("issued_at_unix_seconds", &self.issued_at_unix_seconds)?;
        state.serialize_field("expires_at_unix_seconds", &self.expires_at_unix_seconds)?;
        state.end()
    }
}

/// Pure-Rust RS256 signer for Snowflake key-pair JWT authentication.
#[derive(Clone)]
pub struct KeyPairJwtSigner {
    account: String,
    user: String,
    subject: String,
    issuer_prefix: String,
    public_key_fingerprint: String,
    public_key_der: Vec<u8>,
    encoding_key: EncodingKey,
}

impl KeyPairJwtSigner {
    /// Load a PKCS#8 PEM RSA private key and prepare a Snowflake JWT signer.
    ///
    /// `private_key_passphrase`, when present, is used to decrypt an encrypted
    /// PKCS#8 PEM. Both encrypted and unencrypted paths are parsed with the
    /// pure-Rust `rsa`/`pkcs8` stack; signing uses `jsonwebtoken` RS256 with its
    /// `rust_crypto` + `use_pem` path.
    pub fn from_pkcs8_pem(
        account: impl AsRef<str>,
        user: impl AsRef<str>,
        private_key_pem: impl AsRef<str>,
        private_key_passphrase: Option<&str>,
    ) -> Result<Self, AuthError> {
        let private_key = match private_key_passphrase {
            Some(passphrase) => RsaPrivateKey::from_pkcs8_encrypted_pem(
                private_key_pem.as_ref(),
                passphrase.as_bytes(),
            )
            .map_err(|source| AuthError::InvalidPrivateKey {
                reason: source.to_string(),
            })?,
            None => RsaPrivateKey::from_pkcs8_pem(private_key_pem.as_ref()).map_err(|source| {
                AuthError::InvalidPrivateKey {
                    reason: source.to_string(),
                }
            })?,
        };

        Self::from_private_key(account, user, private_key)
    }

    /// Load unencrypted PKCS#8 DER RSA private key bytes.
    pub fn from_pkcs8_der(
        account: impl AsRef<str>,
        user: impl AsRef<str>,
        private_key_der: &[u8],
    ) -> Result<Self, AuthError> {
        let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der).map_err(|source| {
            AuthError::InvalidPrivateKey {
                reason: source.to_string(),
            }
        })?;
        Self::from_private_key(account, user, private_key)
    }

    fn from_private_key(
        account: impl AsRef<str>,
        user: impl AsRef<str>,
        private_key: RsaPrivateKey,
    ) -> Result<Self, AuthError> {
        let account = normalize_account_for_jwt(account.as_ref())?;
        let user = normalize_user_for_jwt(user.as_ref())?;
        let public_key = RsaPublicKey::from(&private_key);
        let bits = public_key.n().bits();
        if bits < 2_048 {
            return Err(AuthError::RsaKeyTooSmall { bits });
        }

        let public_key_der = public_key
            .to_public_key_der()
            .map_err(|source| AuthError::InvalidPublicKey {
                reason: source.to_string(),
            })?
            .as_ref()
            .to_vec();
        let public_key_fingerprint = public_key_fingerprint_from_der(&public_key_der);

        // jsonwebtoken's rust_crypto RSA signer expects PKCS#1 DER internally.
        let private_key_pkcs1_der =
            private_key
                .to_pkcs1_der()
                .map_err(|source| AuthError::InvalidPrivateKey {
                    reason: source.to_string(),
                })?;
        let encoding_key = EncodingKey::from_rsa_der(private_key_pkcs1_der.as_bytes());
        let subject = format!("{account}.{user}");
        let issuer_prefix = format!("{subject}.{public_key_fingerprint}");

        Ok(Self {
            account,
            user,
            subject,
            issuer_prefix,
            public_key_fingerprint,
            public_key_der,
            encoding_key,
        })
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
    pub fn subject(&self) -> &str {
        &self.subject
    }

    #[must_use]
    pub fn public_key_fingerprint(&self) -> &str {
        &self.public_key_fingerprint
    }

    #[must_use]
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }

    /// Build a Snowflake claim set at a deterministic timestamp.
    pub fn claims_at(
        &self,
        issued_at_unix_seconds: i64,
        requested_validity_seconds: u64,
    ) -> Result<SnowflakeJwtClaims, AuthError> {
        if requested_validity_seconds == 0 {
            return Err(AuthError::InvalidValiditySeconds);
        }
        let validity_seconds = requested_validity_seconds.min(MAX_JWT_VALIDITY_SECONDS);
        let exp = issued_at_unix_seconds.saturating_add(validity_seconds as i64);
        Ok(SnowflakeJwtClaims {
            iss: self.issuer_prefix.clone(),
            sub: self.subject.clone(),
            iat: issued_at_unix_seconds,
            exp,
        })
    }

    /// Sign a fresh RS256 Snowflake key-pair JWT.
    pub fn sign_at(
        &self,
        issued_at_unix_seconds: i64,
        requested_validity_seconds: u64,
    ) -> Result<SignedKeyPairJwt, AuthError> {
        let claims = self.claims_at(issued_at_unix_seconds, requested_validity_seconds)?;
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("JWT".to_string());
        let token = encode(&header, &claims, &self.encoding_key).map_err(|source| {
            AuthError::JwtSigning {
                reason: source.to_string(),
            }
        })?;

        Ok(SignedKeyPairJwt {
            token,
            public_key_fingerprint: self.public_key_fingerprint.clone(),
            issued_at_unix_seconds,
            expires_at_unix_seconds: claims.exp,
            claims,
        })
    }

    #[must_use]
    pub fn refresh_session(&self, requested_validity_seconds: u64) -> KeyPairJwtRefreshSession {
        KeyPairJwtRefreshSession {
            signer: self.clone(),
            requested_validity_seconds,
            refresh_before_expiry_seconds: DEFAULT_REFRESH_BEFORE_EXPIRY_SECONDS,
            current: None,
        }
    }
}

impl fmt::Debug for KeyPairJwtSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPairJwtSigner")
            .field("account", &self.account)
            .field("user", &self.user)
            .field("public_key_fingerprint", &self.public_key_fingerprint)
            .field("private_key", &REDACTED)
            .finish()
    }
}

impl Serialize for KeyPairJwtSigner {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("KeyPairJwtSigner", 4)?;
        state.serialize_field("account", &self.account)?;
        state.serialize_field("user", &self.user)?;
        state.serialize_field("public_key_fingerprint", &self.public_key_fingerprint)?;
        state.serialize_field("private_key", REDACTED)?;
        state.end()
    }
}

/// Stateful helper used by long polling code to re-sign before JWT expiry.
#[derive(Clone)]
pub struct KeyPairJwtRefreshSession {
    signer: KeyPairJwtSigner,
    requested_validity_seconds: u64,
    refresh_before_expiry_seconds: u64,
    current: Option<SignedKeyPairJwt>,
}

impl KeyPairJwtRefreshSession {
    #[must_use]
    pub fn with_refresh_before_expiry_seconds(mut self, seconds: u64) -> Self {
        self.refresh_before_expiry_seconds = seconds;
        self
    }

    pub fn token_for_poll_at(
        &mut self,
        now_unix_seconds: i64,
    ) -> Result<&SignedKeyPairJwt, AuthError> {
        let should_refresh = self.current.as_ref().map_or(true, |signed| {
            let seconds_until_expiry = signed
                .expires_at_unix_seconds
                .saturating_sub(now_unix_seconds);
            seconds_until_expiry <= self.refresh_before_expiry_seconds as i64
        });

        if should_refresh {
            self.current = Some(
                self.signer
                    .sign_at(now_unix_seconds, self.requested_validity_seconds)?,
            );
        }

        self.current.as_ref().ok_or(AuthError::JwtSigning {
            reason: "refresh session did not retain a signed token".to_string(),
        })
    }
}

impl fmt::Debug for KeyPairJwtRefreshSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPairJwtRefreshSession")
            .field("signer", &self.signer)
            .field(
                "requested_validity_seconds",
                &self.requested_validity_seconds,
            )
            .field(
                "refresh_before_expiry_seconds",
                &self.refresh_before_expiry_seconds,
            )
            .field("current", &self.current.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// Profile auth descriptor. This is safe to deserialize from configuration.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthProfile {
    Pat {
        source: SecretSource,
        issued_at_unix_seconds: Option<i64>,
        expires_at_unix_seconds: Option<i64>,
    },
    KeyPairJwt {
        private_key_source: SecretSource,
        private_key_passphrase_source: Option<SecretSource>,
        requested_validity_seconds: u64,
    },
    OAuthBearer {
        source: SecretSource,
        issued_at_unix_seconds: Option<i64>,
        expires_at_unix_seconds: Option<i64>,
    },
    WorkloadIdentityFederation {
        provider: String,
    },
}

impl AuthProfile {
    #[must_use]
    pub fn pat(source: SecretSource) -> Self {
        Self::Pat {
            source,
            issued_at_unix_seconds: None,
            expires_at_unix_seconds: None,
        }
    }

    #[must_use]
    pub fn key_pair_jwt(
        private_key_source: SecretSource,
        private_key_passphrase_source: Option<SecretSource>,
        requested_validity_seconds: u64,
    ) -> Self {
        Self::KeyPairJwt {
            private_key_source,
            private_key_passphrase_source,
            requested_validity_seconds,
        }
    }

    #[must_use]
    pub fn oauth_bearer(source: SecretSource) -> Self {
        Self::OAuthBearer {
            source,
            issued_at_unix_seconds: None,
            expires_at_unix_seconds: None,
        }
    }

    #[must_use]
    pub fn lane(&self) -> AuthLane {
        match self {
            Self::Pat { .. } => AuthLane::ProgrammaticAccessToken,
            Self::KeyPairJwt { .. } => AuthLane::KeyPairJwt,
            Self::OAuthBearer { .. } => AuthLane::OAuthBearer,
            Self::WorkloadIdentityFederation { .. } => AuthLane::WorkloadIdentityFederation,
        }
    }

    #[must_use]
    pub fn validate_offline<R: SecretResolver>(&self, resolver: &R) -> Vec<SecretSourceStatus> {
        match self {
            Self::Pat { source, .. } | Self::OAuthBearer { source, .. } => {
                vec![source.probe_offline(resolver)]
            }
            Self::KeyPairJwt {
                private_key_source,
                private_key_passphrase_source,
                ..
            } => {
                let mut statuses = vec![private_key_source.probe_offline(resolver)];
                if let Some(source) = private_key_passphrase_source {
                    statuses.push(source.probe_offline(resolver));
                }
                statuses
            }
            Self::WorkloadIdentityFederation { .. } => Vec::new(),
        }
    }

    pub fn resolve<R: SecretResolver>(
        &self,
        resolver: &R,
        account: &str,
        user: &str,
    ) -> Result<AuthMechanism, AuthError> {
        match self {
            Self::Pat {
                source,
                issued_at_unix_seconds,
                expires_at_unix_seconds,
            } => ProgrammaticAccessTokenAuth::from_source(
                source,
                resolver,
                *issued_at_unix_seconds,
                *expires_at_unix_seconds,
            )
            .map(AuthMechanism::ProgrammaticAccessToken),
            Self::KeyPairJwt {
                private_key_source,
                private_key_passphrase_source,
                requested_validity_seconds,
            } => KeyPairJwtAuth::from_sources(
                account,
                user,
                private_key_source,
                private_key_passphrase_source.as_ref(),
                *requested_validity_seconds,
                resolver,
            )
            .map(AuthMechanism::KeyPairJwt),
            Self::OAuthBearer {
                source,
                issued_at_unix_seconds,
                expires_at_unix_seconds,
            } => OAuthBearerAuth::from_source(
                source,
                resolver,
                *issued_at_unix_seconds,
                *expires_at_unix_seconds,
            )
            .map(AuthMechanism::OAuthBearer),
            Self::WorkloadIdentityFederation { .. } => Err(AuthError::UnsupportedAuthLane {
                lane: AuthLane::WorkloadIdentityFederation,
            }),
        }
    }
}

impl fmt::Debug for AuthProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pat {
                source,
                issued_at_unix_seconds,
                expires_at_unix_seconds,
            } => f
                .debug_struct("AuthProfile::Pat")
                .field("source", source)
                .field("issued_at_unix_seconds", issued_at_unix_seconds)
                .field("expires_at_unix_seconds", expires_at_unix_seconds)
                .finish(),
            Self::KeyPairJwt {
                private_key_source,
                private_key_passphrase_source,
                requested_validity_seconds,
            } => f
                .debug_struct("AuthProfile::KeyPairJwt")
                .field("private_key_source", private_key_source)
                .field(
                    "private_key_passphrase_source",
                    private_key_passphrase_source,
                )
                .field("requested_validity_seconds", requested_validity_seconds)
                .finish(),
            Self::OAuthBearer {
                source,
                issued_at_unix_seconds,
                expires_at_unix_seconds,
            } => f
                .debug_struct("AuthProfile::OAuthBearer")
                .field("source", source)
                .field("issued_at_unix_seconds", issued_at_unix_seconds)
                .field("expires_at_unix_seconds", expires_at_unix_seconds)
                .finish(),
            Self::WorkloadIdentityFederation { provider } => f
                .debug_struct("AuthProfile::WorkloadIdentityFederation")
                .field("provider", provider)
                .finish(),
        }
    }
}

/// Re-auth policy decision after a mid-poll 401.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ReauthDecision {
    NotRequired,
    ReauthRequired {
        lane: AuthLane,
        credential_handle: Option<String>,
        reason: String,
    },
    ResignJwt {
        reason: String,
    },
}

/// Common interface consumed by SQL API transport and statement polling code.
pub trait SnowflakeAuth {
    fn lane(&self) -> AuthLane;
    fn credential_handle(&self) -> Option<&str>;
    fn headers_at(&mut self, now_unix_seconds: i64) -> Result<AuthHeaders, AuthError>;
    fn lifetime(&self) -> CredentialLifetime;

    fn on_unauthorized_mid_poll(&mut self, _now_unix_seconds: i64) -> ReauthDecision {
        ReauthDecision::NotRequired
    }

    fn log_line(&self, event: &str, message: &str) -> AuthLogLine {
        AuthLogLine::new(
            event,
            self.lane(),
            self.credential_handle().map(str::to_string),
            message,
            Some(self.lifetime()),
        )
    }
}

/// Resolved auth mechanism. Runtime credentials are redacted in all formatting.
pub enum AuthMechanism {
    ProgrammaticAccessToken(ProgrammaticAccessTokenAuth),
    KeyPairJwt(KeyPairJwtAuth),
    OAuthBearer(OAuthBearerAuth),
}

impl SnowflakeAuth for AuthMechanism {
    fn lane(&self) -> AuthLane {
        match self {
            Self::ProgrammaticAccessToken(auth) => auth.lane(),
            Self::KeyPairJwt(auth) => auth.lane(),
            Self::OAuthBearer(auth) => auth.lane(),
        }
    }

    fn credential_handle(&self) -> Option<&str> {
        match self {
            Self::ProgrammaticAccessToken(auth) => auth.credential_handle(),
            Self::KeyPairJwt(auth) => auth.credential_handle(),
            Self::OAuthBearer(auth) => auth.credential_handle(),
        }
    }

    fn headers_at(&mut self, now_unix_seconds: i64) -> Result<AuthHeaders, AuthError> {
        match self {
            Self::ProgrammaticAccessToken(auth) => auth.headers_at(now_unix_seconds),
            Self::KeyPairJwt(auth) => auth.headers_at(now_unix_seconds),
            Self::OAuthBearer(auth) => auth.headers_at(now_unix_seconds),
        }
    }

    fn lifetime(&self) -> CredentialLifetime {
        match self {
            Self::ProgrammaticAccessToken(auth) => auth.lifetime(),
            Self::KeyPairJwt(auth) => auth.lifetime(),
            Self::OAuthBearer(auth) => auth.lifetime(),
        }
    }

    fn on_unauthorized_mid_poll(&mut self, now_unix_seconds: i64) -> ReauthDecision {
        match self {
            Self::ProgrammaticAccessToken(auth) => auth.on_unauthorized_mid_poll(now_unix_seconds),
            Self::KeyPairJwt(auth) => auth.on_unauthorized_mid_poll(now_unix_seconds),
            Self::OAuthBearer(auth) => auth.on_unauthorized_mid_poll(now_unix_seconds),
        }
    }
}

impl fmt::Debug for AuthMechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProgrammaticAccessToken(auth) => f
                .debug_tuple("AuthMechanism::ProgrammaticAccessToken")
                .field(auth)
                .finish(),
            Self::KeyPairJwt(auth) => f
                .debug_tuple("AuthMechanism::KeyPairJwt")
                .field(auth)
                .finish(),
            Self::OAuthBearer(auth) => f
                .debug_tuple("AuthMechanism::OAuthBearer")
                .field(auth)
                .finish(),
        }
    }
}

/// Runtime PAT authenticator.
#[derive(Clone)]
pub struct ProgrammaticAccessTokenAuth {
    credential: SecretValue,
    credential_handle: Option<String>,
    lifetime: CredentialLifetime,
}

impl ProgrammaticAccessTokenAuth {
    pub fn from_bearer_token(
        token: impl Into<String>,
        issued_at_unix_seconds: Option<i64>,
        expires_at_unix_seconds: Option<i64>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            credential: SecretValue::new(token)?,
            credential_handle: None,
            lifetime: pat_lifetime(issued_at_unix_seconds, expires_at_unix_seconds),
        })
    }

    pub fn from_source<R: SecretResolver>(
        source: &SecretSource,
        resolver: &R,
        issued_at_unix_seconds: Option<i64>,
        expires_at_unix_seconds: Option<i64>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            credential: source.resolve(resolver)?,
            credential_handle: Some(source.credential_handle()),
            lifetime: pat_lifetime(issued_at_unix_seconds, expires_at_unix_seconds),
        })
    }
}

impl SnowflakeAuth for ProgrammaticAccessTokenAuth {
    fn lane(&self) -> AuthLane {
        AuthLane::ProgrammaticAccessToken
    }

    fn credential_handle(&self) -> Option<&str> {
        self.credential_handle.as_deref()
    }

    fn headers_at(&mut self, _now_unix_seconds: i64) -> Result<AuthHeaders, AuthError> {
        Ok(AuthHeaders::bearer(
            self.credential.expose_secret(),
            PROGRAMMATIC_ACCESS_TOKEN_TYPE,
        ))
    }

    fn lifetime(&self) -> CredentialLifetime {
        self.lifetime.clone()
    }
}

impl fmt::Debug for ProgrammaticAccessTokenAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProgrammaticAccessTokenAuth")
            .field("credential", &REDACTED)
            .field("credential_handle", &self.credential_handle)
            .field("lifetime", &self.lifetime)
            .finish()
    }
}

impl fmt::Display for ProgrammaticAccessTokenAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProgrammaticAccessTokenAuth([REDACTED])")
    }
}

/// Runtime OAuth bearer authenticator.
#[derive(Clone)]
pub struct OAuthBearerAuth {
    credential: SecretValue,
    credential_handle: Option<String>,
    lifetime: CredentialLifetime,
}

impl OAuthBearerAuth {
    pub fn from_bearer_token(
        token: impl Into<String>,
        issued_at_unix_seconds: Option<i64>,
        expires_at_unix_seconds: Option<i64>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            credential: SecretValue::new(token)?,
            credential_handle: None,
            lifetime: oauth_lifetime(issued_at_unix_seconds, expires_at_unix_seconds),
        })
    }

    pub fn from_source<R: SecretResolver>(
        source: &SecretSource,
        resolver: &R,
        issued_at_unix_seconds: Option<i64>,
        expires_at_unix_seconds: Option<i64>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            credential: source.resolve(resolver)?,
            credential_handle: Some(source.credential_handle()),
            lifetime: oauth_lifetime(issued_at_unix_seconds, expires_at_unix_seconds),
        })
    }
}

impl SnowflakeAuth for OAuthBearerAuth {
    fn lane(&self) -> AuthLane {
        AuthLane::OAuthBearer
    }

    fn credential_handle(&self) -> Option<&str> {
        self.credential_handle.as_deref()
    }

    fn headers_at(&mut self, _now_unix_seconds: i64) -> Result<AuthHeaders, AuthError> {
        Ok(AuthHeaders::bearer(
            self.credential.expose_secret(),
            OAUTH_TOKEN_TYPE,
        ))
    }

    fn lifetime(&self) -> CredentialLifetime {
        self.lifetime.clone()
    }

    fn on_unauthorized_mid_poll(&mut self, _now_unix_seconds: i64) -> ReauthDecision {
        ReauthDecision::ReauthRequired {
            lane: AuthLane::OAuthBearer,
            credential_handle: self.credential_handle.clone(),
            reason: "OAuth bearer returned 401 while polling; refresh the access token and retry the poll".to_string(),
        }
    }
}

impl fmt::Debug for OAuthBearerAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthBearerAuth")
            .field("credential", &REDACTED)
            .field("credential_handle", &self.credential_handle)
            .field("lifetime", &self.lifetime)
            .finish()
    }
}

impl fmt::Display for OAuthBearerAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OAuthBearerAuth([REDACTED])")
    }
}

/// Runtime key-pair JWT authenticator backed by the RS256 signer.
#[derive(Clone)]
pub struct KeyPairJwtAuth {
    session: KeyPairJwtRefreshSession,
    requested_validity_seconds: u64,
    credential_handle: Option<String>,
}

impl KeyPairJwtAuth {
    #[must_use]
    pub fn from_signer(signer: KeyPairJwtSigner, requested_validity_seconds: u64) -> Self {
        Self {
            session: signer.refresh_session(requested_validity_seconds),
            requested_validity_seconds,
            credential_handle: None,
        }
    }

    pub fn from_sources<R: SecretResolver>(
        account: &str,
        user: &str,
        private_key_source: &SecretSource,
        private_key_passphrase_source: Option<&SecretSource>,
        requested_validity_seconds: u64,
        resolver: &R,
    ) -> Result<Self, AuthError> {
        let private_key = private_key_source.resolve(resolver)?;
        let passphrase = private_key_passphrase_source
            .map(|source| source.resolve(resolver))
            .transpose()?;
        let signer = KeyPairJwtSigner::from_pkcs8_pem(
            account,
            user,
            private_key.expose_secret(),
            passphrase.as_ref().map(SecretValue::expose_secret),
        )?;
        Ok(Self {
            session: signer.refresh_session(requested_validity_seconds),
            requested_validity_seconds,
            credential_handle: Some(private_key_source.credential_handle()),
        })
    }
}

impl SnowflakeAuth for KeyPairJwtAuth {
    fn lane(&self) -> AuthLane {
        AuthLane::KeyPairJwt
    }

    fn credential_handle(&self) -> Option<&str> {
        self.credential_handle.as_deref()
    }

    fn headers_at(&mut self, now_unix_seconds: i64) -> Result<AuthHeaders, AuthError> {
        Ok(self.session.token_for_poll_at(now_unix_seconds)?.headers())
    }

    fn lifetime(&self) -> CredentialLifetime {
        CredentialLifetime {
            lane: AuthLane::KeyPairJwt,
            issued_at_unix_seconds: None,
            expires_at_unix_seconds: None,
            expected_validity_seconds: Some(self.requested_validity_seconds),
            max_validity_seconds: Some(MAX_JWT_VALIDITY_SECONDS),
            refresh_before_expiry_seconds: Some(DEFAULT_REFRESH_BEFORE_EXPIRY_SECONDS),
        }
    }

    fn on_unauthorized_mid_poll(&mut self, _now_unix_seconds: i64) -> ReauthDecision {
        ReauthDecision::ResignJwt {
            reason: "key-pair JWT returned 401 while polling; re-sign before retrying the poll"
                .to_string(),
        }
    }
}

impl fmt::Debug for KeyPairJwtAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPairJwtAuth")
            .field("session", &self.session)
            .field(
                "requested_validity_seconds",
                &self.requested_validity_seconds,
            )
            .field("credential_handle", &self.credential_handle)
            .finish()
    }
}

/// Normalize a Snowflake account identifier for JWT `iss` / `sub` values.
pub fn normalize_account_for_jwt(account: &str) -> Result<String, AuthError> {
    let normalized = account.trim().to_ascii_uppercase().replace('.', "-");
    if normalized.is_empty() {
        return Err(AuthError::EmptyAccount);
    }
    Ok(normalized)
}

/// Normalize a Snowflake user identifier for JWT `iss` / `sub` values.
pub fn normalize_user_for_jwt(user: &str) -> Result<String, AuthError> {
    let normalized = user.trim().to_ascii_uppercase();
    if normalized.is_empty() {
        return Err(AuthError::EmptyUser);
    }
    Ok(normalized)
}

/// Snowflake public-key fingerprint:
/// `SHA256:<base64(SHA-256 of SubjectPublicKeyInfo DER)>`.
#[must_use]
pub fn public_key_fingerprint_from_der(public_key_der: &[u8]) -> String {
    let digest = Sha256::digest(public_key_der);
    format!("SHA256:{}", BASE64_STANDARD.encode(digest))
}

/// Redact explicit secret values plus token-like values matching the shared
/// secret prefix policy.
#[must_use]
pub fn redact_with_policy(input: &str, explicit_secret_needles: &[&str]) -> String {
    let mut redacted = input.to_string();
    let mut explicit = explicit_secret_needles
        .iter()
        .copied()
        .filter(|needle| !needle.is_empty())
        .collect::<Vec<_>>();
    explicit.sort_by_key(|needle| std::cmp::Reverse(needle.len()));
    for needle in explicit {
        redacted = redacted.replace(needle, REDACTED);
    }

    let mut prefixes = SECRET_VALUE_NEEDLE_PREFIXES.to_vec();
    prefixes.sort_by_key(|needle| std::cmp::Reverse(needle.len()));
    for prefix in prefixes {
        redacted = redact_prefixed_tokens(&redacted, prefix);
    }
    redacted
}

/// Return the longest known secret prefix that starts `candidate`.
#[must_use]
pub fn longest_secret_prefix(candidate: &str) -> Option<&'static str> {
    SECRET_VALUE_NEEDLE_PREFIXES
        .iter()
        .copied()
        .filter(|prefix| candidate.starts_with(prefix))
        .max_by_key(|prefix| prefix.len())
}

/// Detect whether text contains any known secret-looking prefix.
#[must_use]
pub fn contains_secret_needle(input: &str) -> bool {
    SECRET_VALUE_NEEDLE_PREFIXES
        .iter()
        .any(|prefix| input.contains(prefix))
}

fn pat_lifetime(
    issued_at_unix_seconds: Option<i64>,
    expires_at_unix_seconds: Option<i64>,
) -> CredentialLifetime {
    CredentialLifetime {
        lane: AuthLane::ProgrammaticAccessToken,
        issued_at_unix_seconds,
        expires_at_unix_seconds,
        expected_validity_seconds: Some(PAT_DEFAULT_VALIDITY_SECONDS),
        max_validity_seconds: Some(PAT_MAX_VALIDITY_SECONDS),
        refresh_before_expiry_seconds: None,
    }
}

fn oauth_lifetime(
    issued_at_unix_seconds: Option<i64>,
    expires_at_unix_seconds: Option<i64>,
) -> CredentialLifetime {
    CredentialLifetime {
        lane: AuthLane::OAuthBearer,
        issued_at_unix_seconds,
        expires_at_unix_seconds,
        expected_validity_seconds: Some(OAUTH_EXPECTED_VALIDITY_SECONDS),
        max_validity_seconds: None,
        refresh_before_expiry_seconds: Some(60),
    }
}

fn opaque_credential_handle(prefix: &str, value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let suffix: String = BASE64_STANDARD
        .encode(digest)
        .chars()
        .filter(|candidate| candidate.is_ascii_alphanumeric())
        .take(12)
        .collect();
    format!("cred_{prefix}_{suffix}")
}

fn export_env_next_command(name: &str) -> String {
    format!("export {name}=<redacted>")
}

fn ceil_div_i64(value: i64, divisor: i64) -> i64 {
    if value <= 0 {
        0
    } else {
        (value + divisor - 1) / divisor
    }
}

fn redact_prefixed_tokens(input: &str, prefix: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;
    while let Some(start) = remaining.find(prefix) {
        output.push_str(&remaining[..start]);
        let secret_tail = &remaining[start..];
        if prefix.chars().any(char::is_whitespace) {
            output.push_str(REDACTED);
            remaining = &secret_tail[prefix.len()..];
            continue;
        }
        let end = secret_tail
            .char_indices()
            .find_map(|(idx, ch)| is_secret_delimiter(ch).then_some(idx))
            .unwrap_or(secret_tail.len());
        output.push_str(REDACTED);
        remaining = &secret_tail[end..];
    }
    output.push_str(remaining);
    output
}

fn is_secret_delimiter(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ';' | ')' | ']' | '}')
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};

    use super::*;

    const TEST_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJETqse41HRBsc
7cfcq3ak4oZWFCoZlcic525A3FfO4qW9BMtRO/iXiyCCHn8JhiL9y8j5JdVP2Q9Z
IpfElcFd3/guS9w+5RqQGgCR+H56IVUyHZWtTJbKPcwWXQdNUX0rBFcsBzCRESJL
eelOEdHIjG7LRkx5l/FUvlqsyHDVJEQsHwegZ8b8C0fz0EgT2MMEdn10t6Ur1rXz
jMB/wvCg8vG8lvciXmedyo9xJ8oMOh0wUEgxziVDMMovmC+aJctcHUAYubwoGN8T
yzcvnGqL7JSh36Pwy28iPzXZ2RLhAyJFU39vLaHdljwthUaupldlNyCfa6Ofy4qN
ctlUPlN1AgMBAAECggEAdESTQjQ70O8QIp1ZSkCYXeZjuhj081CK7jhhp/4ChK7J
GlFQZMwiBze7d6K84TwAtfQGZhQ7km25E1kOm+3hIDCoKdVSKch/oL54f/BK6sKl
qlIzQEAenho4DuKCm3I4yAw9gEc0DV70DuMTR0LEpYyXcNJY3KNBOTjN5EYQAR9s
2MeurpgK2MdJlIuZaIbzSGd+diiz2E6vkmcufJLtmYUT/k/ddWvEtz+1DnO6bRHh
xuuDMeJA/lGB/EYloSLtdyCF6sII6C6slJJtgfb0bPy7l8VtL5iDyz46IKyzdyzW
tKAn394dm7MYR1RlUBEfqFUyNK7C+pVMVoTwCC2V4QKBgQD64syfiQ2oeUlLYDm4
CcKSP3RnES02bcTyEDFSuGyyS1jldI4A8GXHJ/lG5EYgiYa1RUivge4lJrlNfjyf
dV230xgKms7+JiXqag1FI+3mqjAgg4mYiNjaao8N8O3/PD59wMPeWYImsWXNyeHS
55rUKiHERtCcvdzKl4u35ZtTqQKBgQDNKnX2bVqOJ4WSqCgHRhOm386ugPHfy+8j
m6cicmUR46ND6ggBB03bCnEG9OtGisxTo/TuYVRu3WP4KjoJs2LD5fwdwJqpgtHl
yVsk45Y1Hfo+7M6lAuR8rzCi6kHHNb0HyBmZjysHWZsn79ZM+sQnLpgaYgQGRbKV
DZWlbw7g7QKBgQCl1u+98UGXAP1jFutwbPsx40IVszP4y5ypCe0gqgon3UiY/G+1
zTLp79GGe/SjI2VpQ7AlW7TI2A0bXXvDSDi3/5Dfya9ULnFXv9yfvH1QwWToySpW
Kvd1gYSoiX84/WCtjZOr0e0HmLIb0vw0hqZA4szJSqoxQgvF22EfIWaIaQKBgQCf
34+OmMYw8fEvSCPxDxVvOwW2i7pvV14hFEDYIeZKW2W1HWBhVMzBfFB5SE8yaCQy
pRfOzj9aKOCm2FjjiErVNpkQoi6jGtLvScnhZAt/lr2TXTrl8OwVkPrIaN0bG/AS
aUYxmBPCpXu3UjhfQiWqFq/mFyzlqlgvuCc9g95HPQKBgAscKP8mLxdKwOgX8yFW
GcZ0izY/30012ajdHY+/QK5lsMoxTnn0skdS+spLxaS5ZEO4qvPVb8RAoCkWMMal
2pOhmquJQVDPDLuZHdrIiKiDM20dy9sMfHygWcZjQ4WSxf/J7T9canLZIXFhHAZT
3wc9h4G8BBCtWN2TN/LsGZdB
-----END PRIVATE KEY-----"#;

    const TEST_PUBLIC_KEY_PEM: &[u8] = br#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyRE6rHuNR0QbHO3H3Kt2
pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXB
Xd/4LkvcPuUakBoAkfh+eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHR
yIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG/AtH89BIE9jDBHZ9dLelK9a184zAf8Lw
oPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xq
i+yUod+j8MtvIj812dkS4QMiRVN/by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5T
dQIDAQAB
-----END PUBLIC KEY-----"#;

    fn signer() -> Result<KeyPairJwtSigner, Box<dyn std::error::Error>> {
        Ok(KeyPairJwtSigner::from_pkcs8_pem(
            "org.account",
            "svc_user",
            TEST_PRIVATE_KEY_PEM,
            None,
        )?)
    }

    struct FakeResolver {
        env_name: String,
        env_value: Option<String>,
        presence_checks: Cell<usize>,
        read_checks: Cell<usize>,
    }

    impl FakeResolver {
        fn with_env(name: &str, value: &str) -> Self {
            Self {
                env_name: name.to_string(),
                env_value: Some(value.to_string()),
                presence_checks: Cell::new(0),
                read_checks: Cell::new(0),
            }
        }

        fn missing(name: &str) -> Self {
            Self {
                env_name: name.to_string(),
                env_value: None,
                presence_checks: Cell::new(0),
                read_checks: Cell::new(0),
            }
        }
    }

    impl SecretResolver for FakeResolver {
        fn env_var_present(&self, name: &str) -> bool {
            self.presence_checks
                .set(self.presence_checks.get().saturating_add(1));
            name == self.env_name && self.env_value.is_some()
        }

        fn read_env_secret(&self, name: &str) -> Result<SecretValue, AuthError> {
            self.read_checks
                .set(self.read_checks.get().saturating_add(1));
            if name == self.env_name {
                if let Some(value) = &self.env_value {
                    return SecretValue::new(value.clone());
                }
            }
            Err(AuthError::MissingEnvVar {
                name: name.to_string(),
                next_command: export_env_next_command(name),
            })
        }

        fn read_provider_secret(&self, handle: &str) -> Result<SecretValue, AuthError> {
            Err(AuthError::UnsupportedSecretProvider {
                handle: handle.to_string(),
            })
        }
    }

    #[test]
    fn normalizes_account_and_user_for_snowflake_claims() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(
            normalize_account_for_jwt("xy12345.us-east-1")?,
            "XY12345-US-EAST-1"
        );
        assert_eq!(normalize_user_for_jwt("svc_user")?, "SVC_USER");
        Ok(())
    }

    #[test]
    fn pat_auth_constructs_bearer_headers_with_pat_token_type()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut auth = ProgrammaticAccessTokenAuth::from_bearer_token(
            "pat-secret-value",
            Some(1_800_000_000),
            Some(1_800_000_000 + PAT_DEFAULT_VALIDITY_SECONDS as i64),
        )?;
        let headers = auth.headers_at(1_800_000_000)?;

        assert_eq!(headers.authorization_header_name(), AUTHORIZATION_HEADER);
        assert_eq!(headers.authorization_value(), "Bearer pat-secret-value");
        assert_eq!(
            headers.token_type_header_name(),
            SNOWFLAKE_AUTHORIZATION_TOKEN_TYPE_HEADER
        );
        assert_eq!(headers.token_type_value(), PROGRAMMATIC_ACCESS_TOKEN_TYPE);
        assert!(!format!("{headers:?}").contains("pat-secret-value"));
        assert!(!serde_json::to_string(&headers)?.contains("pat-secret-value"));
        Ok(())
    }

    #[test]
    fn oauth_auth_constructs_bearer_headers_with_oauth_token_type()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut auth = OAuthBearerAuth::from_bearer_token(
            "oauth-secret-value",
            Some(1_800_000_000),
            Some(1_800_000_000 + OAUTH_EXPECTED_VALIDITY_SECONDS as i64),
        )?;
        let headers = auth.headers_at(1_800_000_000)?;

        assert_eq!(headers.authorization_value(), "Bearer oauth-secret-value");
        assert_eq!(headers.token_type_value(), OAUTH_TOKEN_TYPE);
        assert!(!format!("{headers:?}").contains("oauth-secret-value"));
        assert!(!serde_json::to_string(&headers)?.contains("oauth-secret-value"));
        Ok(())
    }

    #[test]
    fn profile_env_source_probes_presence_without_reading_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        let resolver = FakeResolver::with_env("SNOWFLAKE_PAT", "pat-secret-value");
        let source = SecretSource::env_var("SNOWFLAKE_PAT")?;
        let profile = AuthProfile::pat(source);
        let statuses = profile.validate_offline(&resolver);
        let json = serde_json::to_string(&profile)?;

        assert_eq!(resolver.presence_checks.get(), 1);
        assert_eq!(resolver.read_checks.get(), 0);
        assert_eq!(statuses[0].presence, SecretPresence::Present);
        assert!(!json.contains("SNOWFLAKE_PAT"));
        assert!(!json.contains("pat-secret-value"));
        Ok(())
    }

    #[test]
    fn missing_env_var_teaches_exact_next_command_without_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        let resolver = FakeResolver::missing("SNOWFLAKE_PAT");
        let source = SecretSource::env_var("SNOWFLAKE_PAT")?;
        let error = match source.resolve(&resolver) {
            Ok(_) => return Err("missing env var unexpectedly resolved".into()),
            Err(error) => error,
        };
        let message = error.to_string();

        assert!(message.contains("export SNOWFLAKE_PAT=<redacted>"));
        assert!(!message.contains("pat-secret-value"));
        Ok(())
    }

    #[test]
    fn auth_profile_resolves_pat_from_source() -> Result<(), Box<dyn std::error::Error>> {
        let resolver = FakeResolver::with_env("SNOWFLAKE_PAT", "pat-secret-value");
        let profile = AuthProfile::Pat {
            source: SecretSource::env_var("SNOWFLAKE_PAT")?,
            issued_at_unix_seconds: Some(1_800_000_000),
            expires_at_unix_seconds: Some(1_800_000_000 + PAT_DEFAULT_VALIDITY_SECONDS as i64),
        };
        let mut auth = profile.resolve(&resolver, "org.account", "svc_user")?;
        let headers = auth.headers_at(1_800_000_000)?;

        assert_eq!(auth.lane(), AuthLane::ProgrammaticAccessToken);
        assert_eq!(headers.authorization_value(), "Bearer pat-secret-value");
        assert_eq!(headers.token_type_value(), PROGRAMMATIC_ACCESS_TOKEN_TYPE);
        assert_eq!(resolver.read_checks.get(), 1);
        Ok(())
    }

    #[test]
    fn shared_redactor_uses_secret_needle_prefixes() {
        let input = "Authorization: Bearer sk-live-secret and ghp_exampletoken";
        let redacted = redact_with_policy(input, &["live-secret"]);

        assert!(contains_secret_needle(input));
        assert_eq!(longest_secret_prefix("ghp_exampletoken"), Some("ghp_"));
        assert!(!redacted.contains("sk-live-secret"));
        assert!(!redacted.contains("ghp_exampletoken"));
        assert!(redacted.contains(REDACTED));
    }

    #[test]
    fn signs_rs256_claims_with_snowflake_issuer_and_subject()
    -> Result<(), Box<dyn std::error::Error>> {
        let signer = signer()?;
        let signed = signer.sign_at(1_800_000_000, 900)?;
        assert_eq!(
            signed.claims.iss,
            format!("ORG-ACCOUNT.SVC_USER.{}", signer.public_key_fingerprint())
        );
        assert_eq!(signed.claims.sub, "ORG-ACCOUNT.SVC_USER");
        assert_eq!(signed.claims.exp - signed.claims.iat, 900);
        assert!(signed.claims.iss.contains(".SHA256:"));
        assert!(!signed.claims.sub.contains("SHA256:"));

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        let decoded = decode::<SnowflakeJwtClaims>(
            signed.token(),
            &DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM)?,
            &validation,
        )?;
        assert_eq!(decoded.claims, signed.claims);
        Ok(())
    }

    #[test]
    fn computes_snowflake_public_key_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
        let signer = signer()?;
        let fingerprint = public_key_fingerprint_from_der(signer.public_key_der());
        assert_eq!(fingerprint, signer.public_key_fingerprint());
        assert_eq!(
            fingerprint,
            "SHA256:Foko4xUtBlPwCwPWms3QTmlxlZ4/mnroZslhbUJTinM="
        );
        Ok(())
    }

    #[test]
    fn caps_jwt_expiration_to_one_hour() -> Result<(), Box<dyn std::error::Error>> {
        let signer = signer()?;
        let claims = signer.claims_at(1_800_000_000, 7_200)?;
        assert_eq!(claims.exp - claims.iat, MAX_JWT_VALIDITY_SECONDS as i64);
        Ok(())
    }

    #[test]
    fn emits_keypair_jwt_headers() -> Result<(), Box<dyn std::error::Error>> {
        let signed = signer()?.sign_at(1_800_000_000, MAX_JWT_VALIDITY_SECONDS)?;
        let headers = signed.headers();
        assert_eq!(headers.authorization_header_name(), AUTHORIZATION_HEADER);
        assert!(headers.authorization_value().starts_with("Bearer "));
        assert_eq!(
            headers.token_type_header_name(),
            SNOWFLAKE_AUTHORIZATION_TOKEN_TYPE_HEADER
        );
        assert_eq!(headers.token_type_value(), KEYPAIR_JWT_TOKEN_TYPE);
        Ok(())
    }

    #[test]
    fn jwt_signer_is_available_behind_auth_trait() -> Result<(), Box<dyn std::error::Error>> {
        let mut auth = AuthMechanism::KeyPairJwt(KeyPairJwtAuth::from_signer(
            signer()?,
            MAX_JWT_VALIDITY_SECONDS,
        ));
        let headers = auth.headers_at(1_800_000_000)?;

        assert_eq!(auth.lane(), AuthLane::KeyPairJwt);
        assert!(headers.authorization_value().starts_with("Bearer "));
        assert_eq!(headers.token_type_value(), KEYPAIR_JWT_TOKEN_TYPE);
        Ok(())
    }

    #[test]
    fn lifetime_metadata_surfaces_doctor_warnings() -> Result<(), Box<dyn std::error::Error>> {
        let pat = ProgrammaticAccessTokenAuth::from_bearer_token(
            "pat-secret-value",
            Some(1_800_000_000),
            Some(1_800_000_000 + 60 * 60),
        )?;
        let oauth = OAuthBearerAuth::from_bearer_token(
            "oauth-secret-value",
            Some(1_800_000_000),
            Some(1_800_000_000 + 90),
        )?;
        let jwt = KeyPairJwtAuth::from_signer(signer()?, MAX_JWT_VALIDITY_SECONDS + 1);

        assert!(
            pat.lifetime()
                .doctor_warning_at(1_800_000_000)
                .map(|warning| warning.message.contains("expires in"))
                .unwrap_or(false)
        );
        assert!(
            oauth
                .lifetime()
                .doctor_warning_at(1_800_000_000)
                .map(|warning| warning.message.contains("refresh"))
                .unwrap_or(false)
        );
        assert!(
            jwt.lifetime()
                .doctor_warning_at(1_800_000_000)
                .map(|warning| warning.message.contains("3600s cap"))
                .unwrap_or(false)
        );
        Ok(())
    }

    #[test]
    fn oauth_unauthorized_mid_poll_triggers_reauth() -> Result<(), Box<dyn std::error::Error>> {
        let mut auth = OAuthBearerAuth::from_bearer_token(
            "oauth-secret-value",
            Some(1_800_000_000),
            Some(1_800_000_600),
        )?;
        let decision = auth.on_unauthorized_mid_poll(1_800_000_100);

        assert!(matches!(
            decision,
            ReauthDecision::ReauthRequired {
                lane: AuthLane::OAuthBearer,
                ..
            }
        ));
        assert!(!format!("{decision:?}").contains("oauth-secret-value"));
        Ok(())
    }

    #[test]
    fn supports_encrypted_pkcs8_pem_loading() -> Result<(), Box<dyn std::error::Error>> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(TEST_PRIVATE_KEY_PEM)?;
        let encrypted = private_key.to_pkcs8_encrypted_pem(
            &mut OsRng,
            "correct horse battery staple",
            LineEnding::LF,
        )?;
        let signer = KeyPairJwtSigner::from_pkcs8_pem(
            "org.account",
            "svc_user",
            encrypted.as_str(),
            Some("correct horse battery staple"),
        )?;
        let signed = signer.sign_at(1_800_000_000, 300)?;
        assert_eq!(signed.claims.sub, "ORG-ACCOUNT.SVC_USER");
        Ok(())
    }

    #[test]
    fn refresh_session_resigns_before_expiration() -> Result<(), Box<dyn std::error::Error>> {
        let signer = signer()?;
        let mut session = signer
            .refresh_session(7_200)
            .with_refresh_before_expiry_seconds(60);
        let first = session.token_for_poll_at(1_000)?.token().to_string();
        let reused = session.token_for_poll_at(4_500)?.token().to_string();
        let refreshed = session.token_for_poll_at(4_541)?.token().to_string();

        assert_eq!(first, reused);
        assert_ne!(first, refreshed);
        Ok(())
    }

    #[test]
    fn debug_and_json_are_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let signer = signer()?;
        let signed = signer.sign_at(1_800_000_000, 300)?;
        let mut pat = ProgrammaticAccessTokenAuth::from_bearer_token(
            "pat-secret-value",
            Some(1_800_000_000),
            Some(1_800_000_000 + PAT_DEFAULT_VALIDITY_SECONDS as i64),
        )?;
        let oauth = OAuthBearerAuth::from_bearer_token(
            "oauth-secret-value",
            Some(1_800_000_000),
            Some(1_800_000_600),
        )?;
        let source = SecretSource::env_var("SNOWFLAKE_PAT")?;
        let profile = AuthProfile::pat(source);
        let headers = pat.headers_at(1_800_000_000)?;
        let log = pat.log_line("auth.headers", "constructed auth headers");
        let signer_debug = format!("{signer:?}");
        let signed_debug = format!("{signed:?}");
        let pat_debug = format!("{pat:?}");
        let oauth_display = format!("{oauth}");
        let signed_json = serde_json::to_string(&signed)?;
        let signer_json = serde_json::to_string(&signer)?;
        let profile_json = serde_json::to_string(&profile)?;
        let headers_json = serde_json::to_string(&headers)?;
        let log_json = serde_json::to_string(&log)?;

        assert!(!signer_debug.contains("MIIEvg"));
        assert!(!signed_debug.contains(signed.token()));
        assert!(!signed_json.contains(signed.token()));
        assert!(!signer_json.contains("MIIEvg"));
        assert!(!pat_debug.contains("pat-secret-value"));
        assert!(!oauth_display.contains("oauth-secret-value"));
        assert!(!profile_json.contains("SNOWFLAKE_PAT"));
        assert!(!headers_json.contains("pat-secret-value"));
        assert!(!log_json.contains("pat-secret-value"));
        assert!(signed_json.contains(REDACTED));
        assert!(signer_json.contains(REDACTED));
        assert!(headers_json.contains(REDACTED));
        Ok(())
    }
}
