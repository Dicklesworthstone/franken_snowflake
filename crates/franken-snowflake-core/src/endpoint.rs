//! Snowflake SQL API endpoint construction and validation, shared by the live
//! transport (`franken-snowflake-http`), the CLI live path, and offline
//! `profile validate` so all three agree on which accounts are usable.
//!
//! The rule is fail-closed: the only acceptable endpoint is
//! `https://<account>.snowflakecomputing.com` with a canonical host. IP
//! literals, `localhost`, ports, paths, credentials, fragments, query strings
//! and look-alike suffixes (`x.snowflakecomputing.com.evil.com`) are refused
//! before any socket opens, so a crafted `<PREFIX>_ACCOUNT` cannot point the
//! bearer token at another host. (A test that set the account to `127.0.0.1`
//! once reached Snowflake's wildcard DNS as `127.0.0.1.snowflakecomputing.com`;
//! commit 9297728 introduced the rule, this module makes it shared.)

/// The required host suffix.
pub const SNOWFLAKE_HOST_SUFFIX: &str = ".snowflakecomputing.com";

fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    (s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then(|| &s[prefix.len()..])
}

/// Build the SQL API base URL for an account handle. Locators and org-account
/// names become `https://<account>.snowflakecomputing.com`; an explicit
/// `https://...snowflakecomputing.com` URL is normalized. Anything else (IP
/// literals, `localhost`, host:port, a foreign URL, an explicit `http://`) is
/// passed through unchanged so that [`validate_endpoint`] refuses it explicitly
/// rather than it being silently rewritten.
#[must_use]
pub fn endpoint_url(account: &str) -> String {
    let trimmed = account.trim().trim_end_matches('/');
    if strip_prefix_ignore_ascii_case(trimmed, "http://").is_some() {
        return trimmed.to_owned();
    }
    let (had_scheme, rest) = match strip_prefix_ignore_ascii_case(trimmed, "https://") {
        Some(rest) => (true, rest.trim_end_matches('/')),
        None => (false, trimmed),
    };
    // Only a bare host is normalized. A port, path, query, fragment, or
    // credentials is kept, so validation refuses it instead of it being
    // silently dropped.
    let bare = !rest.is_empty()
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if !bare {
        return format!("https://{rest}");
    }
    let lower = rest.to_ascii_lowercase();
    let is_ip_or_loopback = lower.parse::<std::net::IpAddr>().is_ok() || lower == "localhost";
    if lower.ends_with(SNOWFLAKE_HOST_SUFFIX) || had_scheme || is_ip_or_loopback {
        format!("https://{lower}")
    } else {
        format!("https://{lower}{SNOWFLAKE_HOST_SUFFIX}")
    }
}

/// Validate a SQL API base URL and return its canonical `(base_url, host)`.
///
/// # Errors
/// A human-readable reason the endpoint is refused.
pub fn validate_endpoint(raw: &str) -> Result<(String, String), &'static str> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("Snowflake endpoint is empty");
    }
    let Some(rest) = strip_prefix_ignore_ascii_case(raw, "https://") else {
        return Err("Snowflake endpoint must use https://");
    };
    if rest.contains('@') || raw.contains('#') || raw.contains('?') {
        return Err("Snowflake endpoint must not contain credentials, fragments, or query strings");
    }
    let trimmed = rest.trim_end_matches('/');
    if trimmed.contains('/') {
        return Err("Snowflake endpoint must not contain path segments");
    }
    if trimmed.is_empty() {
        return Err("Snowflake endpoint host is missing");
    }
    let host = trimmed.to_ascii_lowercase();
    if !is_canonical_host(&host) {
        return Err("Snowflake endpoint host is not canonical");
    }
    Ok((format!("https://{host}"), host))
}

fn is_canonical_host(host: &str) -> bool {
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        && host.contains('.')
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..")
        && host.ends_with(SNOWFLAKE_HOST_SUFFIX)
        && host.len() > SNOWFLAKE_HOST_SUFFIX.len()
}

/// Validate an account handle end to end (build the URL, then validate it).
///
/// # Errors
/// The refusal reason, identical to what the live transport reports.
pub fn validate_account(account: &str) -> Result<String, &'static str> {
    validate_endpoint(&endpoint_url(account)).map(|(base, _)| base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locator_and_org_forms_are_accepted() {
        for (account, expected) in [
            (
                "xy12345.us-east-1",
                "https://xy12345.us-east-1.snowflakecomputing.com",
            ),
            ("myorg-prod2", "https://myorg-prod2.snowflakecomputing.com"),
            (
                "https://XY12345.snowflakecomputing.com/",
                "https://xy12345.snowflakecomputing.com",
            ),
        ] {
            assert_eq!(
                validate_account(account),
                Ok(expected.to_owned()),
                "{account}"
            );
        }
    }

    /// A naive `contains(".snowflakecomputing.com")` check passes several of
    /// these; every one must be refused.
    #[test]
    fn hostile_or_non_canonical_accounts_are_refused() {
        for account in [
            "127.0.0.1",
            "localhost",
            "10.0.0.5:443",
            "https://evil.example",
            "http://xy12345.snowflakecomputing.com",
            "https://x.snowflakecomputing.com.evil.com",
            "https://snowflakecomputing.com@evil.com",
            "https://x.snowflakecomputing.com/path",
            "https://x.snowflakecomputing.com?q=1",
            "https://x.snowflakecomputing.com:8443",
            "https://.snowflakecomputing.com",
            "https://a..b.snowflakecomputing.com",
            "xy12345.us-east-1/path",
            "xy12345.us-east-1:443",
            "x.snowflakecomputing.com?role=accountadmin",
            "",
        ] {
            assert!(
                validate_account(account).is_err(),
                "{account:?} must be refused"
            );
        }
    }
}
