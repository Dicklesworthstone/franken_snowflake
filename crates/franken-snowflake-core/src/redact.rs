//! The single shared secret-needle list and the composable redactor.
//!
//! Per `docs/security_model.md`, the redactor and the last-mile output scanner
//! must source their needle list from **one** constant so they cannot drift.
//! [`SECRET_PREFIXES`] is that constant; [`redact`] and [`contains_secret`] share
//! one span-finder so a string is redacted exactly where it is detected.
//!
//! [`CREDENTIAL_FIELD_SUFFIXES`] is consumed by the compile-time credential
//! `Debug`-leak gate (bead `fsnow-native-snowflake-connector-w0i.5`).

use std::borrow::Cow;

/// Known secret-shape prefixes (longest-prefix detection). Extend here only.
pub const SECRET_PREFIXES: &[&str] = &[
    "eyJ",    // JWT / base64url JSON header
    "AKIA",   // AWS access key id
    "ASIA",   // AWS temporary access key id
    "ghp_",   // GitHub personal access token
    "gho_",   // GitHub OAuth token
    "github_pat_",
    "sk-",    // OpenAI-style secret key
    "xoxb-",  // Slack bot token
    "xoxp-",  // Slack user token
    "glpat-", // GitLab personal access token
    "AIza",   // Google API key
];

/// Field-name suffixes that mark a struct field as credential-shaped. The
/// `Debug`-leak gate fails the build if a `#[derive(Debug)]` struct has such a
/// field without a hand-rolled redacting `Debug`.
pub const CREDENTIAL_FIELD_SUFFIXES: &[&str] = &[
    "_api_key",
    "_apikey",
    "_password",
    "_passphrase",
    "_private_key",
    "_secret",
    "_token",
];

/// The text substituted for a detected secret.
pub const REDACTION_PLACEHOLDER: &str = "[REDACTED]";

/// Characters that continue a secret token once a prefix has matched.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '+' | '=' | ':')
}

/// Byte spans `[start, end)` of secret-shaped tokens, in order.
fn secret_spans(input: &str) -> Vec<(usize, usize)> {
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut spans = Vec::new();
    let mut idx = 0;
    while idx < chars.len() {
        let (byte_start, _) = chars[idx];
        let at_boundary = idx == 0 || !is_token_char(chars[idx - 1].1);
        if at_boundary {
            let rest = &input[byte_start..];
            if SECRET_PREFIXES.iter().any(|p| rest.starts_with(*p)) {
                let mut end = idx;
                while end < chars.len() && is_token_char(chars[end].1) {
                    end += 1;
                }
                let byte_end = if end < chars.len() {
                    chars[end].0
                } else {
                    input.len()
                };
                spans.push((byte_start, byte_end));
                idx = end;
                continue;
            }
        }
        idx += 1;
    }
    spans
}

/// Whether `input` contains a secret-shaped token.
#[must_use]
pub fn contains_secret(input: &str) -> bool {
    !secret_spans(input).is_empty()
}

/// Replace every secret-shaped token in `input` with [`REDACTION_PLACEHOLDER`].
///
/// Returns the input borrowed unchanged when nothing matched, so the common
/// no-secret path allocates nothing.
#[must_use]
pub fn redact(input: &str) -> Cow<'_, str> {
    let spans = secret_spans(input);
    if spans.is_empty() {
        return Cow::Borrowed(input);
    }
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0;
    for (start, end) in spans {
        out.push_str(&input[cursor..start]);
        out.push_str(REDACTION_PLACEHOLDER);
        cursor = end;
    }
    out.push_str(&input[cursor..]);
    Cow::Owned(out)
}

/// Whether `field_name` is credential-shaped per [`CREDENTIAL_FIELD_SUFFIXES`].
#[must_use]
pub fn is_credential_field(field_name: &str) -> bool {
    let lowered = field_name.to_ascii_lowercase();
    CREDENTIAL_FIELD_SUFFIXES
        .iter()
        .any(|suffix| lowered.ends_with(suffix))
}
