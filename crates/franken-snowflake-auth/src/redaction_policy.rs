/// Replacement used anywhere credential material would otherwise be displayed.
pub const REDACTED: &str = "[REDACTED]";

/// Secret-looking prefixes used by the redactor and output scanners.
///
/// MUST stay in sync with `franken_snowflake_core::redact::SECRET_PREFIXES`. The
/// list is duplicated (not imported) only because `build.rs` `include!`s this file
/// for the credential-`Debug`-leak gate, and a build script cannot depend on the
/// `core` crate. A cross-crate drift guard that fails CI if the two diverge lives
/// in the CLI tests (`secret_needle_lists_do_not_drift`).
pub const SECRET_VALUE_NEEDLE_PREFIXES: &[&str] = &[
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "AKIA",
    "ASIA",
    "AIza",
    "eyJ",
    "ghp_",
    "gho_",
    "github_pat_",
    "glpat-",
    "pat_",
    "sfpat_",
    "sk-",
    "xoxb-",
    "xoxp-",
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
