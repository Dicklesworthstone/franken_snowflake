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

use std::error::Error;
use std::fmt;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Snowflake's SQL API auth token-type header.
pub const SNOWFLAKE_AUTHORIZATION_TOKEN_TYPE_HEADER: &str = "X-Snowflake-Authorization-Token-Type";

/// Token-type value Snowflake expects for key-pair JWT auth.
pub const KEYPAIR_JWT_TOKEN_TYPE: &str = "KEYPAIR_JWT";

/// Standard bearer authorization header.
pub const AUTHORIZATION_HEADER: &str = "Authorization";

/// Snowflake ignores JWT validity beyond one hour.
pub const MAX_JWT_VALIDITY_SECONDS: u64 = 3_600;

/// Refresh a cached JWT this many seconds before expiry by default.
pub const DEFAULT_REFRESH_BEFORE_EXPIRY_SECONDS: u64 = 60;

const REDACTED: &str = "[REDACTED]";

/// Errors emitted by secret-safe auth construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    EmptyAccount,
    EmptyUser,
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

/// Snowflake JWT claim set for key-pair auth.
///
/// `iss` intentionally includes the public-key fingerprint while `sub` does
/// not. Snowflake requires both ACCOUNT and USER to be uppercase, and accounts
/// containing dots are normalized with dots replaced by dashes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnowflakeJwtClaims {
    pub iss: String,
    pub sub: String,
    pub iat: i64,
    pub exp: i64,
}

/// Redacted auth headers for a signed key-pair JWT.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyPairJwtHeaders {
    authorization: String,
    token_type: &'static str,
}

impl KeyPairJwtHeaders {
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

impl fmt::Debug for KeyPairJwtHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPairJwtHeaders")
            .field("authorization", &REDACTED)
            .field("token_type", &self.token_type)
            .finish()
    }
}

impl Serialize for KeyPairJwtHeaders {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("KeyPairJwtHeaders", 2)?;
        state.serialize_field(AUTHORIZATION_HEADER, REDACTED)?;
        state.serialize_field(SNOWFLAKE_AUTHORIZATION_TOKEN_TYPE_HEADER, self.token_type)?;
        state.end()
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
        KeyPairJwtHeaders {
            authorization: self.bearer_authorization_value(),
            token_type: KEYPAIR_JWT_TOKEN_TYPE,
        }
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

#[cfg(test)]
mod tests {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use rand::rngs::OsRng;
    use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
    use rsa::RsaPrivateKey;

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
    fn signs_rs256_claims_with_snowflake_issuer_and_subject(
    ) -> Result<(), Box<dyn std::error::Error>> {
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
            "SHA256:O/h7FuxJXP1yEmxgqCqVW0PkmE8Yl2xIuJtYfHdWjDs="
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
        let signer_debug = format!("{signer:?}");
        let signed_debug = format!("{signed:?}");
        let signed_json = serde_json::to_string(&signed)?;
        let signer_json = serde_json::to_string(&signer)?;

        assert!(!signer_debug.contains("MIIEvg"));
        assert!(!signed_debug.contains(signed.token()));
        assert!(!signed_json.contains(signed.token()));
        assert!(!signer_json.contains("MIIEvg"));
        assert!(signed_json.contains(REDACTED));
        assert!(signer_json.contains(REDACTED));
        Ok(())
    }
}
