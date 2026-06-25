/// Replacement used anywhere credential material would otherwise be displayed.
pub const REDACTED: &str = "[REDACTED]";

/// Secret-looking prefixes used by the redactor and output scanners.
pub const SECRET_VALUE_NEEDLE_PREFIXES: &[&str] = &[
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "AKIA",
    "AIza",
    "eyJ",
    "ghp_",
    "glpat-",
    "pat_",
    "sfpat_",
    "sk-",
    "xoxb-",
];

/// Field-name markers that require hand-written redacting `Debug`.
pub const CREDENTIAL_FIELD_MARKERS: &[&str] = &[
    "_api_key",
    "_password",
    "_passphrase",
    "_pat",
    "_private_key",
    "_secret",
    "_token",
    "api_key",
    "authorization",
    "credential",
    "password",
    "passphrase",
    "pat",
    "private_key",
    "secret",
    "token",
];

/// Field names that may contain credential-shaped words but are non-secret
/// descriptors or metadata.
pub const NON_SECRET_CREDENTIAL_FIELD_MARKERS: &[&str] = &[
    "credential_handle",
    "expires_at_unix_seconds",
    "expected_validity_seconds",
    "issued_at_unix_seconds",
    "max_validity_seconds",
    "private_key_fingerprint",
    "private_key_passphrase_source",
    "private_key_source",
    "refresh_before_expiry_seconds",
    "requested_validity_seconds",
    "token_type",
];
