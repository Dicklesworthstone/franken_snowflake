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
    concat!("-----BEGIN ", "PRIVATE KEY-----"),
    concat!("-----BEGIN RSA ", "PRIVATE KEY-----"),
    concat!("-----BEGIN ENCRYPTED ", "PRIVATE KEY-----"),
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

/// Parameter-name fragments whose string value is a secret in Snowflake SQL
/// (upper-cased match). The families, with the reference pages consulted
/// 2026-09-24 (see `docs/security_model.md`):
/// `PASSWORD` (CREATE/ALTER USER, CREATE SECRET), `CREDENTIALS = (AWS_KEY_ID,
/// AWS_SECRET_KEY, AWS_TOKEN | AZURE_SAS_TOKEN)` and `ENCRYPTION = (MASTER_KEY,
/// KMS_KEY_ID)` (CREATE STAGE, COPY INTO), `OAUTH_CLIENT_SECRET`,
/// `OAUTH_REFRESH_TOKEN` and `SECRET_STRING` (CREATE SECRET, security
/// integrations), `API_KEY` (CREATE API INTEGRATION). Matching by fragment
/// covers new members of the same families; over-redacting a public value such
/// as `RSA_PUBLIC_KEY` is the safe direction.
pub const SECRET_SQL_PARAMETER_FRAGMENTS: &[&str] = &[
    "PASSWORD",
    "PASSPHRASE",
    "SECRET",
    "TOKEN",
    "CREDENTIAL",
    "_KEY",
];

fn is_secret_sql_parameter(word: &str) -> bool {
    let upper = word.to_ascii_uppercase();
    SECRET_SQL_PARAMETER_FRAGMENTS
        .iter()
        .any(|fragment| upper.contains(fragment))
}

/// Byte spans of string values assigned to secret-bearing SQL parameters:
/// the content of `'...'` or `$$...$$` after `<param>`, `<param> =`, or
/// `<param> =>`. Context-free on purpose, so it also finds the literal when
/// the SQL is embedded in a shell command, a message, or a comment. An
/// unterminated value runs to the end of the input (fail closed). A value that
/// is already exactly [`REDACTION_PLACEHOLDER`] is not a span, so redacted
/// output does not read as a leak.
#[must_use]
pub fn secret_sql_literal_spans(input: &str) -> Vec<(usize, usize)> {
    let bytes = input.as_bytes();
    let is_word_start = |b: u8| b.is_ascii_alphabetic() || b == b'_';
    let is_word_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';
    let skip_space = |mut i: usize| {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        i
    };
    let mut spans = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let starts_word = is_word_start(bytes[i]) && (i == 0 || !is_word_byte(bytes[i - 1]));
        if !starts_word {
            i += 1;
            continue;
        }
        let word_start = i;
        while i < bytes.len() && is_word_byte(bytes[i]) {
            i += 1;
        }
        if !is_secret_sql_parameter(&input[word_start..i]) {
            continue;
        }
        let mut j = skip_space(i);
        if bytes.get(j) == Some(&b'=') {
            j += 1;
            if bytes.get(j) == Some(&b'>') {
                j += 1;
            }
            j = skip_space(j);
        }
        let span = if bytes.get(j) == Some(&b'\'') {
            let start = j + 1;
            let mut k = start;
            let mut end = bytes.len();
            while k < bytes.len() {
                match bytes[k] {
                    b'\\' => k += 2,
                    b'\'' if bytes.get(k + 1) == Some(&b'\'') => k += 2,
                    b'\'' => {
                        end = k;
                        break;
                    }
                    _ => k += 1,
                }
            }
            Some((start, end.min(bytes.len())))
        } else if input[j..].starts_with("$$") {
            let start = j + 2;
            let end = input[start..]
                .find("$$")
                .map_or(input.len(), |off| start + off);
            Some((start, end))
        } else {
            None
        };
        if let Some((start, end)) = span {
            if start < end && input.get(start..end) != Some(REDACTION_PLACEHOLDER) {
                spans.push((start, end));
            }
            i = end;
        }
    }
    spans
}

/// Shape spans ([`secret_spans`]) and secret SQL literal spans
/// ([`secret_sql_literal_spans`]), sorted and merged.
fn all_secret_spans(input: &str) -> Vec<(usize, usize)> {
    let mut spans = secret_spans(input);
    spans.extend(secret_sql_literal_spans(input));
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

/// Whether `input` contains a secret-shaped token or a secret-bearing SQL
/// literal.
#[must_use]
pub fn contains_secret(input: &str) -> bool {
    !all_secret_spans(input).is_empty()
}

/// Replace every secret-shaped token and every secret-bearing SQL literal value
/// (`PASSWORD = '...'`, `AWS_SECRET_KEY = '...'`, ...) in `input` with
/// [`REDACTION_PLACEHOLDER`]; SQL literals keep their quotes.
///
/// Returns the input borrowed unchanged when nothing matched, so the common
/// no-secret path allocates nothing.
#[must_use]
pub fn redact(input: &str) -> Cow<'_, str> {
    let spans = all_secret_spans(input);
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

    /// Reality-check bead B5: one statement per secret-bearing parameter family.
    #[test]
    fn secret_sql_literal_values_are_redacted_in_every_family() {
        for (sql, canary) in [
            (
                "alter user u1 set password = 'cnry_pw_7f3a'",
                "cnry_pw_7f3a",
            ),
            (
                "CREATE USER u2 PASSWORD='cnry_pw_b2' LOGIN_NAME='u2'",
                "cnry_pw_b2",
            ),
            (
                "create stage s url='s3://b/p' credentials=(aws_key_id='cnry_akid' aws_secret_key='cnry_sk' aws_token='cnry_tok')",
                "cnry_sk",
            ),
            (
                "copy into @s from t credentials = (azure_sas_token = 'cnry_sas')",
                "cnry_sas",
            ),
            (
                "create stage s2 encryption = (type = 'AWS_CSE' master_key = 'cnry_mk')",
                "cnry_mk",
            ),
            (
                "create secret s3 type = generic_string secret_string = 'cnry_ss'",
                "cnry_ss",
            ),
            (
                "create secret s4 type = oauth2 oauth_refresh_token = $$cnry_rt$$",
                "cnry_rt",
            ),
            (
                "create security integration i type = api_authentication oauth_client_secret = 'cnry_cs'",
                "cnry_cs",
            ),
            ("create api integration a api_key = 'cnry_ak'", "cnry_ak"),
            ("call p(password => 'cnry_named')", "cnry_named"),
        ] {
            let out = redact(sql);
            assert!(!out.contains(canary), "{sql} -> {out}");
            assert!(out.contains("[REDACTED]"), "{sql} -> {out}");
            assert!(contains_secret(sql), "{sql}");
        }
        // Every value in a multi-value clause, not only the first.
        let out =
            redact("credentials=(aws_key_id='cnry_a' aws_secret_key='cnry_b' aws_token='cnry_c')");
        for canary in ["cnry_a", "cnry_b", "cnry_c"] {
            assert!(!out.contains(canary), "{out}");
        }
    }

    #[test]
    fn secret_sql_literal_edge_cases() {
        // Quotes are kept; non-secret values are untouched.
        assert_eq!(
            redact("create stage s url = 's3://b/p' password = 'x'"),
            "create stage s url = 's3://b/p' password = '[REDACTED]'"
        );
        // A doubled or backslash-escaped quote does not end the value early.
        let out = redact("alter user u set password = 'ab''cd\\'ef'");
        assert!(!out.contains("cd") && !out.contains("ef"), "{out}");
        // Unterminated: redact through the end (fail closed).
        assert_eq!(redact("password = 'never closed"), "password = '[REDACTED]");
        // Already-redacted output is not a secret, so a last-mile scan of
        // redacted text stays clean.
        assert!(!contains_secret("alter user u set password = '[REDACTED]'"));
        // Word boundaries: `url` / `comment` values are not secrets.
        assert_eq!(
            redact("comment = 'token rotation'"),
            "comment = 'token rotation'"
        );
    }

    /// The negative case a lexer-based redactor fails: SQL embedded in a shell
    /// command, where `--profile` would lex as a comment hiding the literal.
    #[test]
    fn secret_sql_literal_inside_a_shell_command_is_redacted() {
        let command = "franken-snowflake query write --profile p --sql \"alter user u set password = 'cnry_shell'\" --json";
        let out = redact(command);
        assert!(!out.contains("cnry_shell"), "{out}");
        assert!(out.contains("--profile p"), "{out}");
    }

    #[test]
    fn needle_list_has_expected_prefixes() {
        for needle in [
            concat!("-----BEGIN ", "PRIVATE KEY-----"),
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
        let input = format!(
            "loaded {}{}\nMIIBODYsecretMaterial0123456789",
            "-----BEGIN ", "PRIVATE KEY-----"
        );
        let out = redact(&input);
        assert!(out.contains(REDACTION_PLACEHOLDER));
        assert!(!out.contains("MIIBODYsecretMaterial0123456789"));
        assert!(!contains_secret(out.as_ref()));
        // The shared span-finder is reused by the canary guard, so it must agree.
        assert_eq!(secret_spans(&input).len(), 1);
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
