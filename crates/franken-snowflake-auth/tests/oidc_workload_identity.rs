#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use franken_snowflake_auth::{
    AuthError, AuthLane, AuthProfile, OidcHttpExchange, OidcTokenSource, ProcessSecretResolver,
    SecretPresence, SecretResolver, SecretValue, SnowflakeAuth, WorkloadIdentityAuth,
    format_rfc7523_form_body, parse_and_validate_oidc_assertion, parse_rfc7523_token_response,
};

/// Mock HTTP exchanger for deterministic token exchange testing.
#[derive(Clone, Default)]
struct MockOidcHttpExchanger {
    pub call_count: Arc<AtomicUsize>,
    pub last_url: Arc<Mutex<Option<String>>>,
    pub last_form_body: Arc<Mutex<Option<String>>>,
    pub scripted_status: u16,
    pub scripted_body: String,
}

impl MockOidcHttpExchanger {
    fn new_success(access_token: &str, expires_in: u64) -> Self {
        let body = serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": "session:role-any"
        })
        .to_string();
        Self {
            call_count: Arc::new(AtomicUsize::new(0)),
            last_url: Arc::new(Mutex::new(None)),
            last_form_body: Arc::new(Mutex::new(None)),
            scripted_status: 200,
            scripted_body: body,
        }
    }

    fn new_error(status: u16, error_code: &str, description: &str) -> Self {
        let body = serde_json::json!({
            "error": error_code,
            "error_description": description
        })
        .to_string();
        Self {
            call_count: Arc::new(AtomicUsize::new(0)),
            last_url: Arc::new(Mutex::new(None)),
            last_form_body: Arc::new(Mutex::new(None)),
            scripted_status: status,
            scripted_body: body,
        }
    }
}

impl OidcHttpExchange for MockOidcHttpExchanger {
    async fn post_form(
        &self,
        _cx: &Cx,
        url: &str,
        form_body: &str,
    ) -> Result<(u16, Vec<u8>), AuthError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut lock) = self.last_url.lock() {
            *lock = Some(url.to_string());
        }
        if let Ok(mut lock) = self.last_form_body.lock() {
            *lock = Some(form_body.to_string());
        }
        Ok((self.scripted_status, self.scripted_body.as_bytes().to_vec()))
    }
}

/// Helper to create a conforming unencrypted JWT assertion for testing.
fn create_test_jwt(exp: i64, iat: i64, iss: &str, sub: &str) -> String {
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT"
    });
    let payload = serde_json::json!({
        "iss": iss,
        "sub": sub,
        "exp": exp,
        "iat": iat,
        "aud": "https://snowflake.example.com"
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
    let sig_b64 = "fake_signature_bytes_for_testing";

    format!("{header_b64}.{payload_b64}.{sig_b64}")
}

#[derive(Default)]
struct StaticSecretResolver {
    pub secret: Option<String>,
}

impl SecretResolver for StaticSecretResolver {
    fn env_var_present(&self, _name: &str) -> bool {
        self.secret.is_some()
    }

    fn read_env_secret(&self, name: &str) -> Result<SecretValue, AuthError> {
        match &self.secret {
            Some(v) => SecretValue::new(v.clone()),
            None => Err(AuthError::MissingEnvVar {
                name: name.to_string(),
                next_command: format!("export {name}=<value>"),
            }),
        }
    }

    fn read_provider_secret(&self, handle: &str) -> Result<SecretValue, AuthError> {
        Err(AuthError::UnsupportedSecretProvider {
            handle: handle.to_string(),
        })
    }
}

#[test]
fn test_token_exchange_request_formation() {
    let raw_jwt = create_test_jwt(
        1800000000,
        1700000000,
        "https://token.actions.githubusercontent.com",
        "repo:org/project:ref:refs/heads/main",
    );

    let form_body = format_rfc7523_form_body(
        &raw_jwt,
        Some("session:role-any"),
        Some("MY_INTEGRATION_CLIENT_ID"),
    );

    assert!(form_body.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"));
    assert!(form_body.contains(&format!("assertion={}", raw_jwt)));
    assert!(form_body.contains("scope=session%3Arole-any"));
    assert!(form_body.contains("client_id=MY_INTEGRATION_CLIENT_ID"));

    // Default scope when None
    let default_form = format_rfc7523_form_body(&raw_jwt, None, None);
    assert!(default_form.contains("scope=session%3Arole-any"));
    assert!(!default_form.contains("client_id"));
}

#[test]
fn test_expired_oidc_token_refusal() {
    let now = 1700000000;
    let expired_at = now - 120; // 2 minutes ago
    let expired_jwt = create_test_jwt(
        expired_at,
        now - 3600,
        "https://kubernetes.default.svc",
        "system:serviceaccount:analytics:snowflake-agent",
    );

    let result = parse_and_validate_oidc_assertion(&expired_jwt, now);
    match result {
        Err(AuthError::OidcAssertionExpired {
            expires_at_unix_seconds,
            now_unix_seconds,
            ..
        }) => {
            assert_eq!(expires_at_unix_seconds, expired_at);
            assert_eq!(now_unix_seconds, now);
        }
        other => panic!("expected OidcAssertionExpired, got {other:?}"),
    }

    // Verify stable error code
    let err = result.unwrap_err();
    assert_eq!(err.stable_code(), "FSNOW-2004");
    assert!(err.to_string().contains("FSNOW-2004"));
}

#[test]
fn test_malformed_oidc_assertion_refusal() {
    let now = 1700000000;

    // Not enough segments
    let two_parts = "header.payload";
    let res1 = parse_and_validate_oidc_assertion(two_parts, now);
    assert_eq!(res1.unwrap_err().stable_code(), "FSNOW-2003");

    // Invalid base64
    let bad_b64 = "header.not-valid-base-64-!@#$.sig";
    let res2 = parse_and_validate_oidc_assertion(bad_b64, now);
    assert_eq!(res2.unwrap_err().stable_code(), "FSNOW-2003");

    // Missing `exp` claim
    let header_b64 = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
    let payload_b64 = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"no_exp\"}");
    let no_exp = format!("{header_b64}.{payload_b64}.sig");
    let res3 = parse_and_validate_oidc_assertion(&no_exp, now);
    assert_eq!(res3.unwrap_err().stable_code(), "FSNOW-2003");

    // Empty string
    let empty_res = parse_and_validate_oidc_assertion("  ", now);
    assert_eq!(empty_res.unwrap_err().stable_code(), "FSNOW-2003");
}

#[test]
fn test_valid_oidc_assertion_claims_parsed() {
    let now = 1700000000;
    let exp = now + 3600;
    let iat = now;
    let iss = "https://accounts.google.com";
    let sub = "service-account-12345";
    let jwt = create_test_jwt(exp, iat, iss, sub);

    let claims = parse_and_validate_oidc_assertion(&jwt, now).expect("validation failed");
    assert_eq!(claims.exp, exp);
    assert_eq!(claims.iat, Some(iat));
    assert_eq!(claims.iss.as_deref(), Some(iss));
    assert_eq!(claims.sub.as_deref(), Some(sub));
}

#[test]
fn test_mock_token_exchange_and_caching() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("runtime build failed");

    runtime.block_on(async {
        let cx = asupersync::Cx::current().expect("ambient cx required");
        let now = 1700000000;
        let test_jwt = create_test_jwt(now + 3600, now, "https://issuer.example.com", "sub1");
        let resolver = StaticSecretResolver {
            secret: Some(test_jwt),
        };

        let mock_transport = MockOidcHttpExchanger::new_success("test_sf_session_token_xyz", 3600);

        let mut auth = WorkloadIdentityAuth::new(
            "myaccount",
            "myuser",
            OidcTokenSource::env_var("MY_OIDC_TOKEN"),
            Some("https://mock.snowflakecomputing.com/oauth/token-request".to_string()),
            Some("session:role-any".to_string()),
            Some("CLIENT_123".to_string()),
            Some(60),
        )
        .expect("auth init failed");

        assert_eq!(auth.lane(), AuthLane::WorkloadIdentityFederation);
        assert_eq!(auth.account(), "myaccount");
        assert_eq!(auth.user(), "myuser");
        assert!(auth.cached_session_token().is_none());

        // First exchange: triggers network call
        let token = auth
            .token_for_poll_at(&cx, &mock_transport, &resolver, now)
            .await
            .expect("token exchange failed");

        assert_eq!(mock_transport.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(token.expose_token(), "test_sf_session_token_xyz");
        assert_eq!(token.expires_at_unix_seconds(), now + 3600);

        // Verify headers
        let headers = auth.headers_at(now).expect("headers failed");
        assert_eq!(headers.token_type_value(), "OAUTH");
        assert_eq!(
            headers.authorization_value(),
            "Bearer test_sf_session_token_xyz"
        );

        // Second exchange at now + 1000: token has 2600s remaining > 60s window.
        // MUST hit cache and NOT invoke HTTP exchange.
        let cached = auth
            .token_for_poll_at(&cx, &mock_transport, &resolver, now + 1000)
            .await
            .expect("cached token fetch failed");

        assert_eq!(mock_transport.call_count.load(Ordering::SeqCst), 1); // STILL 1
        assert_eq!(cached.expose_token(), "test_sf_session_token_xyz");
    });
}

#[test]
fn test_mid_flight_token_refresh() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("runtime build failed");

    runtime.block_on(async {
        let cx = asupersync::Cx::current().expect("ambient cx required");
        let now = 1700000000;
        let test_jwt = create_test_jwt(now + 7200, now, "https://issuer.example.com", "sub1");
        let resolver = StaticSecretResolver {
            secret: Some(test_jwt),
        };

        let mut mock_transport = MockOidcHttpExchanger::new_success("initial_session_token", 3600);

        let mut auth = WorkloadIdentityAuth::new(
            "myaccount",
            "myuser",
            OidcTokenSource::env_var("MY_OIDC_TOKEN"),
            Some("https://mock.snowflakecomputing.com/oauth/token-request".to_string()),
            None,
            None,
            Some(60), // 60s pre-expiry window
        )
        .expect("auth init failed");

        // Initial exchange at now
        let token = auth
            .token_for_poll_at(&cx, &mock_transport, &resolver, now)
            .await
            .expect("token exchange failed");
        assert_eq!(token.expose_token(), "initial_session_token");
        assert_eq!(mock_transport.call_count.load(Ordering::SeqCst), 1);

        // At now + 3530s (70s before expiry of 3600s token): still outside 60s window
        let token2 = auth
            .token_for_poll_at(&cx, &mock_transport, &resolver, now + 3530)
            .await
            .expect("token fetch failed");
        assert_eq!(token2.expose_token(), "initial_session_token");
        assert_eq!(mock_transport.call_count.load(Ordering::SeqCst), 1);

        // At now + 3550s (50s before expiry): inside 60s window! Triggers refresh!
        mock_transport.scripted_body = serde_json::json!({
            "access_token": "refreshed_session_token",
            "token_type": "Bearer",
            "expires_in": 3600
        })
        .to_string();

        let token3 = auth
            .token_for_poll_at(&cx, &mock_transport, &resolver, now + 3550)
            .await
            .expect("token refresh failed");
        assert_eq!(token3.expose_token(), "refreshed_session_token");
        assert_eq!(mock_transport.call_count.load(Ordering::SeqCst), 2); // Incremented!

        // Headers now emit refreshed token
        let headers = auth.headers_at(now + 3550).expect("headers failed");
        assert_eq!(
            headers.authorization_value(),
            "Bearer refreshed_session_token"
        );
    });
}

#[test]
fn test_zero_secret_leaks_in_debug_and_logs() {
    let now = 1700000000;
    let canary_oidc = create_test_jwt(now + 3600, now, "https://sts.canary.example", "canary_user");
    let canary_session = "CANARY_SNOWFLAKE_SECRET_SESSION_TOKEN_123456789";

    let mut auth = WorkloadIdentityAuth::new(
        "canary_account",
        "canary_user",
        OidcTokenSource::env_var("CANARY_OIDC_ENV"),
        Some("https://canary_account.snowflakecomputing.com/oauth/token-request".to_string()),
        Some("session:role-any".to_string()),
        None,
        Some(60),
    )
    .expect("auth init failed");

    let session_token = franken_snowflake_auth::SnowflakeSessionToken::new(
        canary_session,
        "Bearer",
        now,
        now + 3600,
        Some("session:role-any".to_string()),
    )
    .expect("session token init failed");

    auth = auth.with_cached_session_token(session_token);

    // 1. Debug impl must never leak raw session token or OIDC assertion
    let debug_repr = format!("{auth:?}");
    assert!(
        !debug_repr.contains(canary_session),
        "Debug leaked session token!"
    );
    assert!(
        !debug_repr.contains(&canary_oidc),
        "Debug leaked OIDC assertion!"
    );
    assert!(debug_repr.contains("[REDACTED]"));

    // 2. Display impl must never leak
    let display_repr = format!("{auth}");
    assert!(
        !display_repr.contains(canary_session),
        "Display leaked session token!"
    );
    assert!(
        !display_repr.contains(&canary_oidc),
        "Display leaked OIDC assertion!"
    );

    // 3. Structured AuthLogLine must never leak
    let log_line = auth.log_line("token_exchanged", "successfully exchanged OIDC assertion");
    let json_log = serde_json::to_string(&log_line).expect("serialization failed");
    assert!(
        !json_log.contains(canary_session),
        "Log line leaked session token!"
    );
    assert!(
        !json_log.contains(&canary_oidc),
        "Log line leaked OIDC assertion!"
    );
    assert!(json_log.contains("\"lane\":\"workload_identity_federation\""));
}

#[test]
fn test_oidc_token_file_source() {
    let temp_dir = tempfile::tempdir().expect("tempdir failed");
    let token_file = temp_dir.path().join("sa_token.jwt");

    let now = 1700000000;
    let jwt_content = create_test_jwt(now + 3600, now, "https://k8s.local", "k8s_sa");
    std::fs::write(&token_file, &jwt_content).expect("write file failed");

    let source = OidcTokenSource::file(token_file.to_str().unwrap());
    assert_eq!(
        source.credential_handle(),
        format!("file:{}", token_file.display())
    );

    let resolver = ProcessSecretResolver;
    let secret = source.resolve(&resolver).expect("file resolution failed");
    assert_eq!(secret, SecretValue::new(jwt_content).unwrap());

    // Non-existent file
    let missing_source = OidcTokenSource::file("/nonexistent/path/to/token.jwt");
    let err = missing_source.resolve(&resolver).unwrap_err();
    assert_eq!(err.stable_code(), "FSNOW-2003");
}

#[test]
fn test_profile_validation_offline() {
    let profile =
        AuthProfile::workload_identity_federation(OidcTokenSource::env_var("TEST_WIF_TOKEN"));
    assert_eq!(profile.lane(), AuthLane::WorkloadIdentityFederation);

    let mut resolver = StaticSecretResolver::default();
    let statuses = profile.validate_offline(&resolver);
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].presence, SecretPresence::Missing);

    resolver.secret = Some("present".to_string());
    let statuses2 = profile.validate_offline(&resolver);
    assert_eq!(statuses2.len(), 1);
    assert_eq!(statuses2[0].presence, SecretPresence::Present);
}

#[test]
fn test_token_response_parsing_error() {
    let now = 1700000000;
    let error_body = serde_json::json!({
        "error": "invalid_grant",
        "error_description": "The provided assertion has an invalid audience."
    })
    .to_string();

    let result = parse_rfc7523_token_response(400, error_body.as_bytes(), now);
    match result {
        Err(AuthError::OidcTokenExchangeFailed {
            status_code,
            reason,
        }) => {
            assert_eq!(status_code, 400);
            assert!(reason.contains("The provided assertion has an invalid audience"));
        }
        other => panic!("expected OidcTokenExchangeFailed, got {other:?}"),
    }
}

#[test]
fn test_token_exchange_http_error_handling() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("runtime build failed");

    runtime.block_on(async {
        let cx = asupersync::Cx::current().expect("ambient cx required");
        let now = 1700000000;
        let test_jwt = create_test_jwt(now + 3600, now, "https://issuer.example.com", "sub1");
        let resolver = StaticSecretResolver {
            secret: Some(test_jwt),
        };

        let mock_transport = MockOidcHttpExchanger::new_error(
            401,
            "unauthorized_client",
            "Client not authorized for federated exchange",
        );

        let mut auth = WorkloadIdentityAuth::new(
            "test_account",
            "test_user",
            OidcTokenSource::env_var("TEST_OIDC"),
            Some("https://test_account.snowflakecomputing.com/oauth/token-request".to_string()),
            None,
            None,
            Some(60),
        )
        .expect("auth init failed");

        let err = auth
            .token_for_poll_at(&cx, &mock_transport, &resolver, now)
            .await
            .unwrap_err();

        match err {
            AuthError::OidcTokenExchangeFailed {
                status_code,
                reason,
            } => {
                assert_eq!(status_code, 401);
                assert!(reason.contains("Client not authorized"));
            }
            other => panic!("expected OidcTokenExchangeFailed, got {other:?}"),
        }
    });
}
