//! The single shared secret-needle list and the composable redactor.
//!
//! Per `docs/security_model.md`, the redactor and the last-mile output scanner
//! must source their needle list from **one** constant so they cannot drift.
//! [`SECRET_PREFIXES`] is that constant; [`redact`] and [`contains_secret`] share
//! one span-finder so a string is redacted exactly where it is detected.
//!
//! [`CREDENTIAL_FIELD_EXACT`] / [`CREDENTIAL_FIELD_SUFFIXES`] are consumed by the
//! compile-time credential `Debug`-leak gate (bead
//! `fsnow-native-snowflake-connector-w0i.5`).

use std::borrow::Cow;

/// Known secret-shape prefixes (longest-prefix detection). Extend here only.
pub const SECRET_PREFIXES: &[&str] = &[
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "eyJ",  // JWT / base64url JSON header
    "AKIA", // AWS access key id
    "ASIA", // AWS temporary access key id
    "ghp_", // GitHub personal access token
    "gho_", // GitHub OAuth token
    "github_pat_",
    "pat_",
    "sfpat_",
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

/// Exact field names that are credential-shaped even without a separator.
pub const CREDENTIAL_FIELD_EXACT: &[&str] = &[
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "password",
    "passphrase",
    "pat",
    "private_key",
    "secret",
    "token",
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
///
/// Exposed so the last-mile canary guard can reuse the exact span-finder the
/// redactor uses — including multi-line PEM private-key blocks — rather than
/// re-tokenizing on whitespace, which would silently miss the whitespace-bearing
/// PEM header needles. Sharing this one finder keeps detection and redaction from
/// drifting.
#[must_use]
pub fn secret_spans(input: &str) -> Vec<(usize, usize)> {
    let chars: Vec<(usize, char)> = input.char_indices().collect();
    let mut spans = Vec::new();
    let mut idx = 0;
    while idx < chars.len() {
        let (byte_start, _) = chars[idx];
        let at_boundary = idx == 0 || !continues_token_left(chars[idx - 1].1);
        if at_boundary {
            let rest = &input[byte_start..];
            if let Some(prefix) = longest_secret_prefix(rest) {
                if is_pem_private_key_prefix(prefix) {
                    let byte_end = pem_private_key_end(input, byte_start);
                    spans.push((byte_start, byte_end));
                    idx = chars
                        .iter()
                        .position(|(byte_index, _)| *byte_index >= byte_end)
                        .unwrap_or(chars.len());
                    continue;
                }
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

/// The longest known secret prefix at the start of `input`.
#[must_use]
pub fn longest_secret_prefix(input: &str) -> Option<&'static str> {
    SECRET_PREFIXES
        .iter()
        .copied()
        .filter(|prefix| input.starts_with(prefix))
        .max_by_key(|prefix| prefix.len())
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

/// Redact exact account identifiers when a caller requested account redaction.
///
/// Secrets are still handled by [`redact`]; this helper is intentionally exact
/// match for account identifiers supplied by the caller, because account strings
/// are not always sensitive and should only be removed on request.
#[must_use]
pub fn redact_with_account(input: &str, account_identifiers: &[&str]) -> String {
    let mut output = input.to_owned();
    let mut accounts = account_identifiers
        .iter()
        .copied()
        .filter(|account| !account.trim().is_empty())
        .collect::<Vec<_>>();
    accounts.sort_by_key(|account| std::cmp::Reverse(account.len()));
    for account in accounts {
        output = output.replace(account, REDACTION_PLACEHOLDER);
    }
    output
}

fn is_pem_private_key_prefix(prefix: &str) -> bool {
    prefix.starts_with("-----BEGIN ") && prefix.contains("PRIVATE KEY")
}

fn pem_private_key_end(input: &str, byte_start: usize) -> usize {
    let rest = &input[byte_start..];
    if let Some(end_marker) = rest.find("-----END ") {
        let after_end = &rest[end_marker..];
        if let Some(line_end) = after_end.find('\n') {
            return byte_start + end_marker + line_end;
        }
        return input.len();
    }
    // No closing `-----END ...-----` marker: the block is malformed or
    // truncated, so redact through the end of the input. Stopping at the first
    // newline (the end of the `-----BEGIN ...-----` line) would leave the
    // base64 key body in cleartext — a fail-open leak.
    input.len()
}

/// Whether `field_name` is credential-shaped per [`CREDENTIAL_FIELD_EXACT`] /
/// [`CREDENTIAL_FIELD_SUFFIXES`].
#[must_use]
pub fn is_credential_field(field_name: &str) -> bool {
    let lowered = field_name.to_ascii_lowercase();
    CREDENTIAL_FIELD_EXACT.contains(&lowered.as_str())
        || CREDENTIAL_FIELD_SUFFIXES
        .iter()
        .any(|suffix| lowered.ends_with(suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needle_list_has_expected_prefixes() {
        for needle in [
            "-----BEGIN PRIVATE KEY-----",
            "eyJ",
            "AKIA",
            "ghp_",
            "sk-",
            "xoxb-",
            "glpat-",
            "AIza",
        ] {
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
    fn every_secret_prefix_redacts_in_header_and_query_param_forms() {
        for prefix in SECRET_PREFIXES {
            let suffix = if prefix.chars().any(char::is_whitespace) {
                "\nabc123\n-----END PRIVATE KEY-----"
            } else {
                "ABCdef0123"
            };
            let header = format!("Authorization: Bearer {prefix}{suffix}");
            let query = format!("?token={prefix}{suffix}");
            for sample in [header, query] {
                let out = redact(&sample);
                assert!(
                    out.contains(REDACTION_PLACEHOLDER),
                    "prefix {prefix} not redacted in {sample:?}"
                );
                assert!(
                    !contains_secret(out.as_ref()),
                    "redacted output still contains secret prefix {prefix}: {out}"
                );
            }
        }
    }

    #[test]
    fn truncated_pem_private_key_without_end_marker_is_fully_redacted() {
        // A PEM block missing its `-----END ...-----` line must still have the
        // base64 key body redacted, not just the `-----BEGIN ...-----` line.
        // Stopping at the first newline left the key material in cleartext.
        let input = "loaded -----BEGIN PRIVATE KEY-----\nMIIBODYsecretMaterial0123456789";
        let out = redact(input);
        assert!(out.contains(REDACTION_PLACEHOLDER));
        assert!(!out.contains("MIIBODYsecretMaterial0123456789"));
        assert!(!contains_secret(out.as_ref()));
        // The shared span-finder is reused by the canary guard, so it must agree.
        assert_eq!(secret_spans(input).len(), 1);
    }

    #[test]
    fn account_redaction_is_opt_in_and_exact() {
        let input = "xy12345.us-east-1 and xy12345";
        assert_eq!(
            redact_with_account(input, &["xy12345.us-east-1"]),
            "[REDACTED] and xy12345"
        );
    }

    #[test]
    fn credential_field_detection() {
        assert!(is_credential_field("snowflake_private_key"));
        assert!(is_credential_field("SNOWFLAKE_PAT_TOKEN"));
        assert!(is_credential_field("db_password"));
        assert!(is_credential_field("token"));
        assert!(is_credential_field("password"));
        assert!(is_credential_field("secret"));
        assert!(is_credential_field("api_key"));
        assert!(is_credential_field("authorization"));
        assert!(!is_credential_field("username"));
        assert!(!is_credential_field("account"));
        assert!(!is_credential_field("token_type"));
    }
}
