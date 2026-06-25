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

/// Characters that continue a secret token to the right once a prefix has
/// matched (includes base64 `+`/`/`/`=` padding and url-safe `-`/`_`).
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '+' | '=')
}

/// Whether `c`, immediately preceding a candidate prefix, keeps a token going
/// leftward (so the candidate is *not* at a token boundary). Separators that
/// commonly precede secrets — `=`, `:`, whitespace, quotes — are excluded here,
/// so `key=eyJ...` and `Authorization: eyJ...` are still detected.
fn continues_token_left(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '+')
}

/// Byte spans `[start, end)` of secret-shaped tokens, in order.
fn secret_spans(input: &str) -> Vec<(usize, usize)> {
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut spans = Vec::new();
    let mut idx = 0;
    while idx < chars.len() {
        let (byte_start, _) = chars[idx];
        let at_boundary = idx == 0 || !continues_token_left(chars[idx - 1].1);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needle_list_has_expected_prefixes() {
        for needle in ["eyJ", "AKIA", "ghp_", "sk-", "xoxb-", "glpat-", "AIza"] {
            assert!(SECRET_PREFIXES.contains(&needle), "missing needle {needle}");
        }
        assert!(!SECRET_PREFIXES.is_empty());
    }

    #[test]
    fn redacts_jwt_shaped_token() {
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig done";
        let out = redact(input);
        assert!(out.contains(REDACTION_PLACEHOLDER));
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(out.contains("done"));
    }

    #[test]
    fn plain_text_is_borrowed_unchanged() {
        let input = "this is a basket of plain words";
        let out = redact(input);
        assert!(matches!(out, std::borrow::Cow::Borrowed(_)));
        assert_eq!(out.as_ref(), input);
        assert!(!contains_secret(input));
    }

    #[test]
    fn prefix_only_matches_at_token_boundary() {
        // "sk-" mid-token in "ask-me" is not a secret boundary.
        assert!(!contains_secret("please ask-me later"));
        // At a boundary it is detected.
        assert!(contains_secret("key=sk-ABCDEF0123456789"));
    }

    #[test]
    fn redacts_multiple_secrets() {
        let input = "a=AKIAEXAMPLE0001 b=ghp_abcdEFGH0001";
        let out = redact(input);
        assert!(!out.contains("AKIAEXAMPLE0001"));
        assert!(!out.contains("ghp_abcdEFGH0001"));
        assert_eq!(out.matches(REDACTION_PLACEHOLDER).count(), 2);
    }

    #[test]
    fn credential_field_detection() {
        assert!(is_credential_field("snowflake_private_key"));
        assert!(is_credential_field("SNOWFLAKE_PAT_TOKEN"));
        assert!(is_credential_field("db_password"));
        assert!(!is_credential_field("username"));
        assert!(!is_credential_field("account"));
    }
}
