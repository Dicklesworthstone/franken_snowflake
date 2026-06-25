//! `franken-snowflake-http` -- Asupersync-native HTTPS transport API draft.
//!
//! This crate owns the transport boundary for Snowflake SQL API calls:
//! endpoint validation, TLS/root policy configuration, redacted header
//! construction, request/response body limits, deterministic retry planning,
//! attempt-log vocabulary, partition streaming plans, and the live Asupersync
//! HTTP client seam. It deliberately does not own SQL API schemas, credential
//! lookup/signing, receipts, CLI envelopes, or local cache state.
//!
//! The live transport path is shaped around Asupersync's explicit `&Cx` API and
//! high-level pooled HTTP/1.1 client. The no-account code in this first slice is
//! intentionally useful without live Snowflake credentials.

use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use asupersync::http::Response;
use asupersync::http::compress::{Decompressor, GzipDecompressor, IdentityDecompressor};
use asupersync::http::{
    Client as AsupersyncHttpClient, ClientError as AsupersyncClientError, Method, StatusCode,
};
use asupersync::{CancelKind, Cx, Time};
use franken_snowflake_core::budget::Budget;
use franken_snowflake_core::cancel::{CancelPolicy, CancelReason, cancel_policy};
use franken_snowflake_core::ids::{RequestId, StatementHandle};
use franken_snowflake_core::redact::{REDACTION_PLACEHOLDER, redact};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

const SQL_API_STATEMENTS_PATH: &str = "/api/v2/statements";
const HEADER_AUTHORIZATION: &str = "Authorization";
const HEADER_TOKEN_TYPE: &str = "X-Snowflake-Authorization-Token-Type";
const HEADER_CONTENT_TYPE: &str = "Content-Type";
const HEADER_ACCEPT: &str = "Accept";
const HEADER_ACCEPT_ENCODING: &str = "Accept-Encoding";
const HEADER_CONTENT_ENCODING: &str = "Content-Encoding";
const JSON_MEDIA_TYPE: &str = "application/json";
const PARTITION_ACCEPT_ENCODING: &str = "gzip, identity";
/// Official Snowflake SQL API resubmit contract consulted 2026-06-25.
pub const SNOWFLAKE_SQL_API_RESUBMIT_DOC_URL: &str = "https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests#resubmitting-a-request-to-execute-sql-statements";
/// Date the Snowflake SQL API resubmit contract above was consulted.
pub const SNOWFLAKE_SQL_API_RESUBMIT_DOC_CONSULTED: &str = "2026-06-25";

/// Transport APIs preserve the connector's in-process outcome carrier.
pub type TransportOutcome<T> = franken_snowflake_core::outcome::SnowflakeOutcome<T>;

/// Asupersync capability marker for this crate's effectful transport boundary.
///
/// Public APIs accept `&Cx` directly for now because the upstream capability
/// aliases are still settling, but this marker documents the intended authority:
/// IO + TIME + SPAWN, never REMOTE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransportCaps;

/// Asupersync-native Snowflake SQL API HTTP client facade.
#[derive(Clone)]
pub struct SnowflakeHttpClient {
    config: TransportConfig,
    client: AsupersyncHttpClient,
}

impl fmt::Debug for SnowflakeHttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnowflakeHttpClient")
            .field("config", &self.config)
            .field("client", &"<asupersync-http-client>")
            .finish()
    }
}

impl SnowflakeHttpClient {
    /// Create a client with an explicit Asupersync HTTP client handle.
    #[must_use]
    pub fn new(config: TransportConfig, client: AsupersyncHttpClient) -> Self {
        Self { config, client }
    }

    /// Create a client from the runtime-owned pooled Asupersync HTTP client.
    #[must_use]
    pub fn default_for_runtime(config: TransportConfig, cx: &Cx) -> Self {
        Self {
            config,
            client: AsupersyncHttpClient::default_for_runtime(cx),
        }
    }

    /// Access the immutable transport configuration.
    #[must_use]
    pub const fn config(&self) -> &TransportConfig {
        &self.config
    }

    /// Build a submit request plan without performing network I/O.
    #[must_use]
    pub fn submit_plan(&self, request: &SubmitHttpRequest) -> Result<WireRequest, TransportError> {
        self.wire_request(
            Method::Post,
            request.route.clone(),
            request.body.clone(),
            &request.auth,
            request.retry_resubmit,
        )
    }

    /// Build a poll request plan without performing network I/O.
    #[must_use]
    pub fn poll_plan(&self, request: &PollHttpRequest) -> Result<WireRequest, TransportError> {
        let route = TransportRoute::Poll {
            handle: request.statement_handle.clone(),
        };
        self.wire_request(Method::Get, route, Vec::new(), &request.auth, false)
    }

    /// Build a partition request plan without performing network I/O.
    #[must_use]
    pub fn partition_plan(
        &self,
        request: &PartitionHttpRequest,
    ) -> Result<WireRequest, TransportError> {
        let route = TransportRoute::Partition {
            handle: request.statement_handle.clone(),
            partition: request.partition,
        };
        self.wire_request(Method::Get, route, Vec::new(), &request.auth, false)
    }

    /// Build a cancel request plan without performing network I/O.
    #[must_use]
    pub fn cancel_plan(&self, request: &CancelHttpRequest) -> Result<WireRequest, TransportError> {
        let route = TransportRoute::Cancel {
            handle: request.statement_handle.clone(),
        };
        self.wire_request(Method::Post, route, Vec::new(), &request.auth, false)
    }

    /// Submit a SQL API statement over the live Asupersync HTTPS transport.
    pub async fn submit_statement(
        &self,
        cx: &Cx,
        request: SubmitHttpRequest,
    ) -> TransportOutcome<SubmitHttpResponse> {
        self.execute(cx, request, TransportRouteKind::Submit).await
    }

    /// Poll a submitted statement handle.
    pub async fn poll_statement(
        &self,
        cx: &Cx,
        request: PollHttpRequest,
    ) -> TransportOutcome<PollHttpResponse> {
        self.execute(cx, request, TransportRouteKind::Poll).await
    }

    /// Fetch and decode a result partition.
    pub async fn fetch_partition(
        &self,
        cx: &Cx,
        request: PartitionHttpRequest,
    ) -> TransportOutcome<PartitionBody> {
        self.execute(cx, request, TransportRouteKind::Partition)
            .await
    }

    /// Cancel a statement handle.
    pub async fn cancel_statement(
        &self,
        cx: &Cx,
        request: CancelHttpRequest,
    ) -> TransportOutcome<CancelHttpResponse> {
        self.execute(cx, request, TransportRouteKind::Cancel).await
    }

    /// Send a remote cancel during a bounded cleanup phase after local
    /// cancellation. The caller owns the cleanup `Cx`; this function deliberately
    /// does not manufacture a detached context inside the transport layer.
    pub async fn cancel_after_local_cancel(
        &self,
        cleanup_cx: &Cx,
        auth: AuthorizationDescriptor,
        statement_handle: StatementHandle,
        reason: CancelReason,
    ) -> TransportOutcome<CancelHttpResponse> {
        match cancel_policy(reason.kind) {
            CancelPolicy::RemoteCancelAndReceipt | CancelPolicy::BoundedDrain => {
                run_with_cancellation_mask(
                    cleanup_cx,
                    self.cancel_statement(
                        cleanup_cx,
                        CancelHttpRequest {
                            auth,
                            statement_handle,
                            reason_kind: reason.kind,
                        },
                    ),
                )
                .await
            }
            CancelPolicy::RetryOrDegrade | CancelPolicy::QuietDrain => {
                TransportOutcome::cancelled(reason)
            }
        }
    }

    /// Fetch partitions in order and stream them into the caller's sink.
    pub async fn stream_partitions<S>(
        &self,
        cx: &Cx,
        request: PartitionStreamRequest,
        sink: &mut S,
    ) -> TransportOutcome<PartitionStreamSummary>
    where
        S: PartitionSink,
    {
        if cx.checkpoint().is_err() {
            return TransportOutcome::cancelled(cancel_reason_or(
                cx,
                CancelReason::parent_cancelled,
            ));
        }
        let summary = match request.plan() {
            Ok(summary) => summary,
            Err(error) => return TransportOutcome::err(error.into_snowflake_error()),
        };
        for partition in request.seed_partitions.iter().cloned() {
            if cx.checkpoint().is_err() {
                let reason = cancel_reason_or(cx, CancelReason::parent_cancelled);
                return self
                    .cancel_stream_after_local_cancel(cx, &request, &summary, reason)
                    .await;
            }
            if let Err(error) = sink.accept(cx, partition).await {
                return TransportOutcome::err(error.into_snowflake_error());
            }
            if cx.checkpoint().is_err() {
                let reason = cancel_reason_or(cx, CancelReason::parent_cancelled);
                return self
                    .cancel_stream_after_local_cancel(cx, &request, &summary, reason)
                    .await;
            }
        }

        for partition in request.first_partition..request.end_partition_exclusive {
            if cx.checkpoint().is_err() {
                let reason = cancel_reason_or(cx, CancelReason::parent_cancelled);
                return self
                    .cancel_stream_after_local_cancel(cx, &request, &summary, reason)
                    .await;
            }
            let body: PartitionBody = match self
                .execute(
                    cx,
                    PlannedTransportRequest::partition(
                        request.auth.clone(),
                        request.statement_handle.clone(),
                        partition,
                        request.child_budget,
                    ),
                    TransportRouteKind::Partition,
                )
                .await
            {
                TransportOutcome::Ok(body) => body,
                TransportOutcome::Err(error) => return TransportOutcome::err(error),
                TransportOutcome::Cancelled(reason) => return TransportOutcome::cancelled(reason),
                TransportOutcome::Panicked(payload) => return TransportOutcome::panicked(payload),
            };
            let decoded = DecodedPartition {
                partition,
                body: body.body,
                compression: body.compression,
            };
            if let Err(error) = sink.accept(cx, decoded).await {
                return TransportOutcome::err(error.into_snowflake_error());
            }
            if cx.checkpoint().is_err() {
                let reason = cancel_reason_or(cx, CancelReason::parent_cancelled);
                return self
                    .cancel_stream_after_local_cancel(cx, &request, &summary, reason)
                    .await;
            }
        }

        TransportOutcome::ok(summary)
    }

    async fn cancel_stream_after_local_cancel(
        &self,
        cx: &Cx,
        request: &PartitionStreamRequest,
        summary: &PartitionStreamSummary,
        reason: CancelReason,
    ) -> TransportOutcome<PartitionStreamSummary> {
        if request.remote_cancel_on_local_cancel {
            self.cancel_after_local_cancel(
                cx,
                request.auth.clone(),
                request.statement_handle.clone(),
                reason,
            )
            .await
            .map(|_| summary.clone())
        } else {
            TransportOutcome::cancelled(reason)
        }
    }

    async fn execute<R, T>(
        &self,
        cx: &Cx,
        request: R,
        route_kind: TransportRouteKind,
    ) -> TransportOutcome<T>
    where
        R: Into<PlannedTransportRequest>,
        T: FromResponseBody,
    {
        let mut retry_spent_ms = 0_u64;
        let planned = request.into();
        let wire = match self.wire_request(
            route_kind.method(),
            planned.route.clone(),
            planned.body.clone(),
            &planned.auth,
            planned.retry_resubmit,
        ) {
            Ok(wire) => wire,
            Err(error) => return TransportOutcome::err(error.into_snowflake_error()),
        };

        let mut attempt = 1_u32;
        loop {
            if cx.checkpoint().is_err() {
                return TransportOutcome::cancelled(cancel_reason_or(
                    cx,
                    CancelReason::parent_cancelled,
                ));
            }

            let attempt_budget =
                self.config
                    .retry
                    .attempt_budget(cx.budget(), planned.budget, attempt);
            let budget_now = asupersync::time::wall_now();
            if let Some(reason) = budget_exhaustion_reason_at(attempt_budget, budget_now) {
                return TransportOutcome::cancelled(reason);
            }
            let mut request_builder = self
                .client
                .request_builder(route_kind.method(), wire.url.clone())
                .headers(
                    wire.headers
                        .iter()
                        .map(|h| (h.name.as_str(), h.value.as_str())),
                )
                .body(wire.body.clone());
            if let Some(timeout) = budget_timeout_at(attempt_budget, budget_now) {
                request_builder = request_builder.timeout(timeout);
            }
            let result = request_builder.send(cx).await;

            match result {
                Ok(response) => {
                    let retry_after_ms =
                        retry_after_ms(response.headers.as_slice(), asupersync::time::wall_now());
                    let retryable = is_retryable_status(response.status);
                    if retryable {
                        if !route_allows_automatic_retry(&wire.route) {
                            return TransportOutcome::err(
                                TransportError::new(
                                    TransportErrorCode::NonIdempotentSubmitRetryRefused,
                                    format!(
                                        "{} returned retryable HTTP status {}, but automatic retry requires requestId plus retry=true",
                                        route_kind.as_str(),
                                        response.status
                                    ),
                                )
                                .into_snowflake_error(),
                            );
                        }
                        if let Some(retry) = self.config.retry.next_retry(
                            planned.request_id.as_ref(),
                            route_kind,
                            attempt,
                            retry_after_ms,
                            retry_spent_ms,
                        ) {
                            if let Err(reason) = wait_retry_delay(cx, retry.delay).await {
                                return TransportOutcome::cancelled(reason);
                            }
                            attempt = attempt.saturating_add(1);
                            retry_spent_ms = retry.spent_after_ms;
                            continue;
                        }
                        return TransportOutcome::err(
                            TransportError::new(
                                TransportErrorCode::RetryBudgetExhausted,
                                format!(
                                    "{} exhausted retry budget after {attempt} attempts",
                                    route_kind.as_str()
                                ),
                            )
                            .into_snowflake_error(),
                        );
                    }
                    return match T::from_response(response, self.config.limits, planned.partition) {
                        Ok(value) => TransportOutcome::ok(value),
                        Err(error) => TransportOutcome::err(error.into_snowflake_error()),
                    };
                }
                Err(error) if error.is_cancelled() => {
                    return TransportOutcome::cancelled(cancel_reason_or(
                        cx,
                        CancelReason::parent_cancelled,
                    ));
                }
                Err(AsupersyncClientError::DeadlineExceeded) => {
                    return TransportOutcome::cancelled(cancel_reason_or(
                        cx,
                        CancelReason::deadline,
                    ));
                }
                Err(error) => {
                    if route_allows_automatic_retry(&wire.route) {
                        if let Some(retry) = self.config.retry.next_retry(
                            planned.request_id.as_ref(),
                            route_kind,
                            attempt,
                            None,
                            retry_spent_ms,
                        ) {
                            if let Err(reason) = wait_retry_delay(cx, retry.delay).await {
                                return TransportOutcome::cancelled(reason);
                            }
                            attempt = attempt.saturating_add(1);
                            retry_spent_ms = retry.spent_after_ms;
                            continue;
                        }
                    }
                    return TransportOutcome::err(
                        TransportError::new(
                            TransportErrorCode::NetworkError,
                            format!("Asupersync HTTP client error: {error}"),
                        )
                        .into_snowflake_error(),
                    );
                }
            }
        }
    }

    fn wire_request(
        &self,
        method: Method,
        route: TransportRoute,
        body: Vec<u8>,
        auth: &AuthorizationDescriptor,
        retry_resubmit: bool,
    ) -> Result<WireRequest, TransportError> {
        let route_kind = route.kind();
        self.config.limits.enforce(route_kind, body.len())?;
        if matches!(route_kind, TransportRouteKind::Submit)
            && retry_resubmit
            && !route.has_retry_contract()
        {
            return Err(TransportError::new(
                TransportErrorCode::NonIdempotentSubmitRetryRefused,
                "submit retry requires requestId plus retry=true",
            ));
        }

        let mut headers = auth.wire_headers()?;
        headers.push(Header::new(HEADER_ACCEPT, JSON_MEDIA_TYPE)?);
        if matches!(route_kind, TransportRouteKind::Partition) {
            headers.push(Header::new(
                HEADER_ACCEPT_ENCODING,
                PARTITION_ACCEPT_ENCODING,
            )?);
        }
        if matches!(method, Method::Post) {
            headers.push(Header::new(HEADER_CONTENT_TYPE, JSON_MEDIA_TYPE)?);
        }
        Ok(WireRequest {
            method,
            url: self.config.endpoint.route_url(&route),
            route,
            headers,
            body,
        })
    }
}

/// Immutable transport configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportConfig {
    /// Canonical Snowflake SQL API endpoint.
    pub endpoint: SnowflakeEndpoint,
    /// TLS root policy.
    pub tls_roots: TlsRootPolicy,
    /// Connection-pool constraints.
    pub pool: PoolConfig,
    /// Body-size limits.
    pub limits: BodyLimits,
    /// Retry/backoff behavior.
    pub retry: RetryPolicy,
    /// Attempt-log behavior.
    pub log: AttemptLogPolicy,
}

impl TransportConfig {
    /// Create a config with conservative defaults.
    #[must_use]
    pub fn new(endpoint: SnowflakeEndpoint) -> Self {
        Self {
            endpoint,
            tls_roots: TlsRootPolicy::NativeRoots,
            pool: PoolConfig::default(),
            limits: BodyLimits::default(),
            retry: RetryPolicy::default(),
            log: AttemptLogPolicy::default(),
        }
    }
}

/// Validated HTTPS endpoint for a Snowflake account host.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SnowflakeEndpoint {
    base_url: String,
    host: String,
}

impl SnowflakeEndpoint {
    /// Validate and canonicalize a Snowflake SQL API base endpoint.
    pub fn parse(raw: impl AsRef<str>) -> Result<Self, TransportError> {
        let raw = raw.as_ref().trim();
        if raw.is_empty() {
            return Err(TransportError::new(
                TransportErrorCode::InvalidSnowflakeHost,
                "Snowflake endpoint is empty",
            ));
        }
        let Some(rest) = raw.strip_prefix("https://") else {
            return Err(TransportError::new(
                TransportErrorCode::InvalidSnowflakeHost,
                "Snowflake endpoint must use https://",
            ));
        };
        if rest.contains('@') || raw.contains('#') || raw.contains('?') {
            return Err(TransportError::new(
                TransportErrorCode::InvalidSnowflakeHost,
                "Snowflake endpoint must not contain credentials, fragments, or query strings",
            ));
        }
        let trimmed = rest.trim_end_matches('/');
        let host = trimmed
            .split('/')
            .next()
            .filter(|candidate| !candidate.is_empty())
            .ok_or_else(|| {
                TransportError::new(
                    TransportErrorCode::InvalidSnowflakeHost,
                    "Snowflake endpoint host is missing",
                )
            })?;
        validate_host(host)?;
        let base_url = format!("https://{trimmed}");
        Ok(Self {
            base_url,
            host: host.to_owned(),
        })
    }

    /// Canonical base URL without a trailing slash.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Canonical host portion.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Build an absolute URL for a SQL API route.
    #[must_use]
    pub fn route_url(&self, route: &TransportRoute) -> String {
        format!("{}{}", self.base_url, route.path_and_query())
    }
}

fn validate_host(host: &str) -> Result<(), TransportError> {
    let valid = host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        && host.contains('.')
        && !host.starts_with('.')
        && !host.ends_with('.')
        && !host.contains("..");
    if valid {
        Ok(())
    } else {
        Err(TransportError::new(
            TransportErrorCode::InvalidSnowflakeHost,
            "Snowflake endpoint host is not canonical",
        ))
    }
}

/// TLS root source for live HTTPS.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TlsRootPolicy {
    /// Use the OS trust store through Asupersync/rustls native roots.
    NativeRoots,
    /// Use a caller-provided PEM bundle.
    ExplicitPemBundle(PathBuf),
    /// Test-only marker. Refused unless a testkit path explicitly consumes it.
    TestOnlyInsecureDisabledByDefault,
}

/// Connection-pool policy. This mirrors the plan-level contract without exposing
/// unstable internals from Asupersync's pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PoolConfig {
    /// Maximum idle connections retained per endpoint.
    pub max_idle_per_endpoint: usize,
    /// Maximum in-flight requests per endpoint.
    pub max_in_flight_per_endpoint: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_endpoint: 8,
            max_in_flight_per_endpoint: 16,
        }
    }
}

/// Response/request body limits enforced before decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BodyLimits {
    /// Maximum submit response bytes.
    pub max_submit_response_bytes: u64,
    /// Maximum poll response bytes.
    pub max_poll_response_bytes: u64,
    /// Maximum compressed partition bytes.
    pub max_partition_compressed_bytes: u64,
    /// Maximum uncompressed partition bytes.
    pub max_partition_uncompressed_bytes: u64,
    /// Maximum submit request body bytes.
    pub max_submit_request_bytes: u64,
}

impl BodyLimits {
    /// Enforce request body limits for a route.
    pub fn enforce(self, route: TransportRouteKind, body_len: usize) -> Result<(), TransportError> {
        let max = match route {
            TransportRouteKind::Submit => self.max_submit_request_bytes,
            TransportRouteKind::Poll
            | TransportRouteKind::Partition
            | TransportRouteKind::Cancel => u64::MAX,
        };
        if body_len as u64 > max {
            Err(TransportError::new(
                TransportErrorCode::BodyLimitExceeded,
                format!("request body has {body_len} bytes, limit is {max}"),
            ))
        } else {
            Ok(())
        }
    }

    /// Enforce partition compressed/uncompressed limits.
    pub fn enforce_partition_sizes(
        self,
        compressed: u64,
        uncompressed: u64,
    ) -> Result<(), TransportError> {
        if compressed > self.max_partition_compressed_bytes {
            return Err(TransportError::new(
                TransportErrorCode::BodyLimitExceeded,
                format!(
                    "compressed partition has {compressed} bytes, limit is {}",
                    self.max_partition_compressed_bytes
                ),
            ));
        }
        if uncompressed > self.max_partition_uncompressed_bytes {
            return Err(TransportError::new(
                TransportErrorCode::BodyLimitExceeded,
                format!(
                    "uncompressed partition has {uncompressed} bytes, limit is {}",
                    self.max_partition_uncompressed_bytes
                ),
            ));
        }
        Ok(())
    }

    /// Enforce non-partition response body limits.
    pub fn enforce_response_size(
        self,
        route: TransportRouteKind,
        body_len: usize,
    ) -> Result<(), TransportError> {
        let max = match route {
            TransportRouteKind::Submit => self.max_submit_response_bytes,
            TransportRouteKind::Poll => self.max_poll_response_bytes,
            TransportRouteKind::Cancel => self.max_poll_response_bytes,
            TransportRouteKind::Partition => self.max_partition_compressed_bytes,
        };
        if body_len as u64 > max {
            Err(TransportError::new(
                TransportErrorCode::BodyLimitExceeded,
                format!("response body has {body_len} bytes, limit is {max}"),
            ))
        } else {
            Ok(())
        }
    }
}

impl Default for BodyLimits {
    fn default() -> Self {
        Self {
            max_submit_response_bytes: 8 * 1024 * 1024,
            max_poll_response_bytes: 8 * 1024 * 1024,
            max_partition_compressed_bytes: 64 * 1024 * 1024,
            max_partition_uncompressed_bytes: 512 * 1024 * 1024,
            max_submit_request_bytes: 2 * 1024 * 1024,
        }
    }
}

/// Retry/backoff policy for transport calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RetryPolicy {
    /// Maximum number of attempts including the first try.
    pub max_attempts: u32,
    /// Base exponential delay.
    pub base_delay_ms: u64,
    /// Maximum delay after exponentiation.
    pub max_delay_ms: u64,
    /// Total retry sleep budget.
    pub total_budget_ms: u64,
    /// Whether to honor `Retry-After` when present.
    pub respect_retry_after: bool,
    /// Whether deterministic jitter is applied.
    pub deterministic_jitter: bool,
}

impl RetryPolicy {
    /// Compute the next retry delay.
    #[must_use]
    pub fn delay_for(
        self,
        request_id: Option<&RequestId>,
        route: TransportRouteKind,
        attempt: u32,
        retry_after_ms: Option<u64>,
        spent_ms: u64,
    ) -> Option<Duration> {
        if attempt == 0 || attempt >= self.max_attempts || spent_ms >= self.total_budget_ms {
            return None;
        }
        let from_header = retry_after_ms.filter(|_| self.respect_retry_after);
        let exponential = self
            .base_delay_ms
            .saturating_mul(2_u64.saturating_pow(attempt.saturating_sub(1)))
            .min(self.max_delay_ms);
        let mut delay = from_header.unwrap_or(exponential);
        if from_header.is_none() && self.deterministic_jitter {
            delay = delay.saturating_add(deterministic_jitter_ms(request_id, route, attempt));
        }
        let remaining = self.total_budget_ms.saturating_sub(spent_ms);
        if delay > remaining {
            None
        } else {
            Some(Duration::from_millis(delay))
        }
    }

    fn next_retry(
        self,
        request_id: Option<&RequestId>,
        route: TransportRouteKind,
        attempt: u32,
        retry_after_ms: Option<u64>,
        spent_ms: u64,
    ) -> Option<RetryDecision> {
        let delay = self.delay_for(request_id, route, attempt, retry_after_ms, spent_ms)?;
        Some(RetryDecision {
            delay,
            spent_after_ms: spent_ms.saturating_add(duration_millis_saturating(delay)),
        })
    }

    /// Budget slice for one transport attempt, meet-composed with the caller's
    /// ambient budget and any route-specific child budget.
    #[must_use]
    pub fn attempt_budget(self, ambient: Budget, route_budget: Budget, attempt: u32) -> Budget {
        let remaining_attempts = self
            .max_attempts
            .saturating_sub(attempt.saturating_sub(1))
            .max(1);
        ambient
            .meet(route_budget)
            .meet(Budget::new().with_poll_quota(remaining_attempts))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RetryDecision {
    delay: Duration,
    spent_after_ms: u64,
}

fn duration_millis_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn budget_timeout_at(budget: Budget, now: Time) -> Option<Duration> {
    budget
        .deadline
        .map(|deadline| Duration::from_nanos(deadline.duration_since(now)))
}

fn budget_exhaustion_reason_at(budget: Budget, now: Time) -> Option<CancelReason> {
    if budget_timeout_at(budget, now).is_some_and(|timeout| timeout.is_zero()) {
        return Some(CancelReason::deadline());
    }
    if budget.poll_quota == 0 {
        return Some(CancelReason::poll_quota());
    }
    if matches!(budget.cost_quota, Some(0)) {
        return Some(CancelReason::cost_budget());
    }
    None
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 4,
            base_delay_ms: 100,
            max_delay_ms: 2_000,
            total_budget_ms: 10_000,
            respect_retry_after: true,
            deterministic_jitter: true,
        }
    }
}

fn deterministic_jitter_ms(
    request_id: Option<&RequestId>,
    route: TransportRouteKind,
    attempt: u32,
) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in request_id
        .map_or("no-request-id", RequestId::as_str)
        .bytes()
        .chain(route.as_str().bytes())
        .chain(attempt.to_le_bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash % 31
}

/// Attempt-log controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttemptLogPolicy {
    /// Emit per-attempt events.
    pub enabled: bool,
    /// Hash statement handles in logs.
    pub hash_statement_handles: bool,
    /// Redact account/host identifiers.
    pub redact_account_identifiers: bool,
}

impl Default for AttemptLogPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            hash_statement_handles: true,
            redact_account_identifiers: true,
        }
    }
}

/// Snowflake auth token class for the SQL API token-type header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnowflakeAuthTokenType {
    /// Programmatic access token.
    ProgrammaticAccessToken,
    /// Key-pair JWT.
    KeypairJwt,
    /// OAuth bearer token.
    OAuth,
}

impl SnowflakeAuthTokenType {
    /// Wire value for `X-Snowflake-Authorization-Token-Type`.
    #[must_use]
    pub const fn as_header_value(self) -> &'static str {
        match self {
            Self::ProgrammaticAccessToken => "PROGRAMMATIC_ACCESS_TOKEN",
            Self::KeypairJwt => "KEYPAIR_JWT",
            Self::OAuth => "OAUTH",
        }
    }
}

/// Redacted authorization descriptor supplied by the auth crate.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationDescriptor {
    token_type: SnowflakeAuthTokenType,
    bearer_token: String,
    redacted_fingerprint: String,
}

impl AuthorizationDescriptor {
    /// Create a descriptor from an already-resolved bearer token.
    ///
    /// The token is intentionally not exposed through `Debug`, `Display`, or
    /// serde. The auth crate owns secret-source resolution.
    #[must_use]
    pub fn bearer(
        token_type: SnowflakeAuthTokenType,
        bearer_token: impl Into<String>,
        redacted_fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            token_type,
            bearer_token: bearer_token.into(),
            redacted_fingerprint: redacted_fingerprint.into(),
        }
    }

    /// Redacted fingerprint for logs.
    #[must_use]
    pub fn redacted_fingerprint(&self) -> &str {
        &self.redacted_fingerprint
    }

    fn wire_headers(&self) -> Result<Vec<Header>, TransportError> {
        Ok(vec![
            Header::new(
                HEADER_AUTHORIZATION,
                format!("Bearer {}", self.bearer_token),
            )?,
            Header::new(HEADER_TOKEN_TYPE, self.token_type.as_header_value())?,
        ])
    }
}

impl fmt::Debug for AuthorizationDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizationDescriptor")
            .field("token_type", &self.token_type)
            .field("redacted_fingerprint", &self.redacted_fingerprint)
            .finish_non_exhaustive()
    }
}

/// HTTP header pair.
#[derive(Clone, PartialEq, Eq, Hash, Deserialize)]
pub struct Header {
    /// Header name.
    pub name: String,
    /// Header value.
    pub value: String,
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("name", &self.name)
            .field("value", &redacted_header_value(&self.name, &self.value))
            .finish()
    }
}

impl Serialize for Header {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Header", 2)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("value", &redacted_header_value(&self.name, &self.value))?;
        state.end()
    }
}

impl Header {
    /// Validate and construct a header.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Result<Self, TransportError> {
        let name = name.into();
        let value = value.into();
        if !is_header_name(&name) || !is_header_value(&value) {
            return Err(TransportError::new(
                TransportErrorCode::HeaderRejected,
                "header contains invalid characters",
            ));
        }
        Ok(Self { name, value })
    }
}

fn redacted_header_value(name: &str, value: &str) -> String {
    let value = redact(value).into_owned();
    if !name.eq_ignore_ascii_case(HEADER_AUTHORIZATION) {
        return value;
    }
    if value.contains(REDACTION_PLACEHOLDER) {
        return value;
    }
    let mut words = value.split_whitespace();
    match (words.next(), words.next()) {
        (Some(scheme), Some(_)) => format!("{scheme} {REDACTION_PLACEHOLDER}"),
        _ => REDACTION_PLACEHOLDER.to_owned(),
    }
}

fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-'))
}

fn is_header_value(value: &str) -> bool {
    value.bytes().all(|b| matches!(b, b'\t' | b' '..=b'~'))
}

/// SQL API transport route.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TransportRoute {
    /// `POST /api/v2/statements`.
    Submit,
    /// `POST /api/v2/statements?<query pairs>`.
    SubmitWithQuery {
        /// Stable, caller-rendered submit query parameters in wire order.
        query: Vec<(&'static str, String)>,
    },
    /// `POST /api/v2/statements?requestId=...&retry=true`.
    SubmitRetry {
        /// Stable idempotency request id.
        request_id: RequestId,
    },
    /// `GET /api/v2/statements/{statementHandle}`.
    Poll {
        /// Statement handle.
        handle: StatementHandle,
    },
    /// `GET /api/v2/statements/{statementHandle}?partition=<n>`.
    Partition {
        /// Statement handle.
        handle: StatementHandle,
        /// Partition number.
        partition: u32,
    },
    /// `POST /api/v2/statements/{statementHandle}/cancel`.
    Cancel {
        /// Statement handle.
        handle: StatementHandle,
    },
}

impl TransportRoute {
    /// Coarse route kind.
    #[must_use]
    pub const fn kind(&self) -> TransportRouteKind {
        match self {
            Self::Submit | Self::SubmitWithQuery { .. } | Self::SubmitRetry { .. } => {
                TransportRouteKind::Submit
            }
            Self::Poll { .. } => TransportRouteKind::Poll,
            Self::Partition { .. } => TransportRouteKind::Partition,
            Self::Cancel { .. } => TransportRouteKind::Cancel,
        }
    }

    /// Whether this submit has the Snowflake idempotent resubmit contract.
    #[must_use]
    pub fn has_retry_contract(&self) -> bool {
        match self {
            Self::SubmitRetry { .. } => true,
            Self::SubmitWithQuery { query } => submit_query_has_retry_contract(query),
            Self::Submit | Self::Poll { .. } | Self::Partition { .. } | Self::Cancel { .. } => {
                false
            }
        }
    }

    /// Path and query for the SQL API route.
    #[must_use]
    pub fn path_and_query(&self) -> String {
        match self {
            Self::Submit => SQL_API_STATEMENTS_PATH.to_owned(),
            Self::SubmitWithQuery { query } => render_submit_query(query),
            Self::SubmitRetry { request_id } => {
                format!(
                    "{SQL_API_STATEMENTS_PATH}?requestId={}&retry=true",
                    request_id.as_str()
                )
            }
            Self::Poll { handle } => {
                format!("{SQL_API_STATEMENTS_PATH}/{}", handle.as_str())
            }
            Self::Partition { handle, partition } => {
                format!(
                    "{SQL_API_STATEMENTS_PATH}/{}?partition={partition}",
                    handle.as_str()
                )
            }
            Self::Cancel { handle } => {
                format!("{SQL_API_STATEMENTS_PATH}/{}/cancel", handle.as_str())
            }
        }
    }
}

fn render_submit_query(query: &[(&'static str, String)]) -> String {
    if query.is_empty() {
        return SQL_API_STATEMENTS_PATH.to_owned();
    }

    let mut rendered = String::from(SQL_API_STATEMENTS_PATH);
    for (index, (key, value)) in query.iter().enumerate() {
        rendered.push(if index == 0 { '?' } else { '&' });
        rendered.push_str(&percent_encode_query_component(key));
        rendered.push('=');
        rendered.push_str(&percent_encode_query_component(value));
    }
    rendered
}

fn percent_encode_query_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if is_query_unreserved(byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(hex_digit(byte >> 4));
            encoded.push(hex_digit(byte & 0x0f));
        }
    }
    encoded
}

const fn is_query_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

fn submit_query_has_retry_contract(query: &[(&'static str, String)]) -> bool {
    query
        .iter()
        .any(|(key, value)| *key == "requestId" && !value.is_empty())
        && query
            .iter()
            .any(|(key, value)| *key == "retry" && value == "true")
}

/// Coarse transport route kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportRouteKind {
    /// Submit statement.
    Submit,
    /// Poll statement handle.
    Poll,
    /// Fetch result partition.
    Partition,
    /// Cancel statement handle.
    Cancel,
}

impl TransportRouteKind {
    /// Stable string for logs and jitter seeds.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Submit => "submit",
            Self::Poll => "poll",
            Self::Partition => "partition",
            Self::Cancel => "cancel",
        }
    }

    /// HTTP method for this route kind.
    #[must_use]
    pub const fn method(self) -> Method {
        match self {
            Self::Submit | Self::Cancel => Method::Post,
            Self::Poll | Self::Partition => Method::Get,
        }
    }
}

/// Fully planned wire request.
#[derive(Clone, PartialEq, Eq)]
pub struct WireRequest {
    /// HTTP method.
    pub method: Method,
    /// Absolute URL.
    pub url: String,
    /// SQL API route.
    pub route: TransportRoute,
    /// Wire headers.
    pub headers: Vec<Header>,
    /// Request body bytes.
    pub body: Vec<u8>,
}

impl fmt::Debug for WireRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("route", &self.route)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Status classification for Snowflake SQL API responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusClass {
    /// 200 completed.
    Completed,
    /// 202 accepted/still running.
    Running,
    /// 408 server statement timeout.
    StatementTimeout,
    /// 422 SQL/query failure.
    QueryFailure,
    /// 429 rate limited.
    RateLimited,
    /// Retryable 5xx.
    ServerErrorRetryable,
    /// Any other unexpected status.
    Unexpected,
}

/// Classify Snowflake SQL API status codes without conflating 202 and 429.
#[must_use]
pub fn classify_status(status: StatusCode) -> StatusClass {
    match status.as_u16() {
        200 => StatusClass::Completed,
        202 => StatusClass::Running,
        408 => StatusClass::StatementTimeout,
        422 => StatusClass::QueryFailure,
        429 => StatusClass::RateLimited,
        500..=599 => StatusClass::ServerErrorRetryable,
        _ => StatusClass::Unexpected,
    }
}

/// Attempt-log event target schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptLogEvent {
    /// Schema id.
    pub schema: &'static str,
    /// Redacted or generated trace id.
    pub trace_id: String,
    /// Route kind.
    pub route: TransportRouteKind,
    /// HTTP method.
    pub method: String,
    /// 1-based attempt number.
    pub attempt: u32,
    /// Redacted request fingerprint.
    pub request_fingerprint: String,
    /// Optional hashed statement handle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_handle_hash: Option<String>,
    /// Optional partition index.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition: Option<u32>,
    /// HTTP status if a response was received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Whether the outcome is retryable.
    pub retryable: bool,
    /// Retry-After value in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    /// Elapsed milliseconds.
    pub elapsed_ms: u64,
    /// Compressed bytes observed.
    pub compressed_bytes: u64,
    /// Uncompressed bytes observed.
    pub uncompressed_bytes: u64,
    /// `ok`, `error`, or `cancelled`.
    pub outcome: AttemptOutcome,
    /// Stable transport error code if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<TransportErrorCode>,
}

impl AttemptLogEvent {
    /// Schema identifier.
    pub const SCHEMA: &'static str = "franken_snowflake.transport_attempt.v1";
}

/// Attempt outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcome {
    /// Request completed successfully.
    Ok,
    /// Request failed with a typed error.
    Error,
    /// Request was cancelled.
    Cancelled,
}

/// Compression metadata and decoded body.
#[derive(Clone, PartialEq, Eq)]
pub struct DecodedPartition {
    /// Partition index.
    pub partition: u32,
    /// Raw decoded bytes.
    pub body: Vec<u8>,
    /// Compression metadata.
    pub compression: CompressionEvidence,
}

impl fmt::Debug for DecodedPartition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodedPartition")
            .field("partition", &self.partition)
            .field("body_len", &self.body.len())
            .field("compression", &self.compression)
            .finish()
    }
}

/// Compression metadata captured for evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CompressionEvidence {
    /// Original content encoding.
    pub content_encoding: ContentEncoding,
    /// Compressed bytes observed.
    pub compressed_bytes: u64,
    /// Uncompressed bytes observed.
    pub uncompressed_bytes: u64,
}

/// Supported content encodings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentEncoding {
    /// No content encoding header.
    Identity,
    /// Gzip-compressed response.
    Gzip,
}

impl ContentEncoding {
    /// Parse a content-encoding header.
    pub fn parse(raw: Option<&str>) -> Result<Self, TransportError> {
        match raw.map(str::trim).filter(|value| !value.is_empty()) {
            None => Ok(Self::Identity),
            Some(value) if value.eq_ignore_ascii_case("identity") => Ok(Self::Identity),
            Some(value) if value.eq_ignore_ascii_case("gzip") => Ok(Self::Gzip),
            Some(_) => Err(TransportError::new(
                TransportErrorCode::UnsupportedContentEncoding,
                "unsupported partition content-encoding",
            )),
        }
    }
}

struct DecodedPartitionResponse {
    status: StatusClass,
    body: Vec<u8>,
    compression: CompressionEvidence,
}

fn decode_partition_response(
    response: Response,
    limits: BodyLimits,
    partition: u32,
) -> Result<DecodedPartitionResponse, TransportError> {
    let encoding = ContentEncoding::parse(response_header(
        response.headers.as_slice(),
        HEADER_CONTENT_ENCODING,
    ))?;
    let compressed_bytes = response.body.len() as u64;
    let max_uncompressed =
        usize::try_from(limits.max_partition_uncompressed_bytes).map_err(|_| {
            TransportError::new(
                TransportErrorCode::BodyLimitExceeded,
                "partition uncompressed limit exceeds local addressable memory",
            )
        })?;
    let mut decoded = Vec::new();
    let decode_result = match encoding {
        ContentEncoding::Identity => {
            let mut decompressor = IdentityDecompressor::new(Some(max_uncompressed));
            decompressor
                .decompress(response.body.as_slice(), &mut decoded)
                .and_then(|()| decompressor.finish(&mut decoded))
        }
        ContentEncoding::Gzip => {
            let mut decompressor = GzipDecompressor::new(Some(max_uncompressed));
            decompressor
                .decompress(response.body.as_slice(), &mut decoded)
                .and_then(|()| decompressor.finish(&mut decoded))
        }
    };
    if let Err(error) = decode_result {
        let code = match encoding {
            ContentEncoding::Identity => TransportErrorCode::BodyLimitExceeded,
            ContentEncoding::Gzip => TransportErrorCode::GzipDecodeFailed,
        };
        return Err(TransportError::new(
            code,
            format!("partition {partition} decode failed: {error}"),
        ));
    }
    let uncompressed_bytes = decoded.len() as u64;
    limits.enforce_partition_sizes(compressed_bytes, uncompressed_bytes)?;
    Ok(DecodedPartitionResponse {
        status: classify_status(StatusCode(response.status)),
        body: decoded,
        compression: CompressionEvidence {
            content_encoding: encoding,
            compressed_bytes,
            uncompressed_bytes,
        },
    })
}

fn response_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn retry_after_ms(headers: &[(String, String)], now: Time) -> Option<u64> {
    let raw = response_header(headers, "Retry-After")?.trim();
    raw.parse::<u64>()
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .or_else(|| retry_after_http_date_ms(raw, now))
}

fn retry_after_http_date_ms(raw: &str, now: Time) -> Option<u64> {
    let target_seconds = parse_http_date_unix_seconds(raw)?;
    if target_seconds <= 0 {
        return Some(0);
    }
    let target = Time::from_secs(u64::try_from(target_seconds).ok()?);
    Some(duration_millis_saturating(Duration::from_nanos(
        target.duration_since(now),
    )))
}

fn parse_http_date_unix_seconds(raw: &str) -> Option<i64> {
    parse_imf_fixdate(raw)
        .or_else(|| parse_rfc850_date(raw))
        .or_else(|| parse_asctime_date(raw))
}

fn parse_imf_fixdate(raw: &str) -> Option<i64> {
    let (_, rest) = raw.split_once(", ")?;
    let mut parts = rest.split_ascii_whitespace();
    let day = parts.next()?.parse::<u32>().ok()?;
    let month = parse_http_month(parts.next()?)?;
    let year = parts.next()?.parse::<i32>().ok()?;
    let (hour, minute, second) = parse_http_time(parts.next()?)?;
    if parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    unix_seconds_utc(year, month, day, hour, minute, second)
}

fn parse_rfc850_date(raw: &str) -> Option<i64> {
    let (_, rest) = raw.split_once(", ")?;
    let mut parts = rest.split_ascii_whitespace();
    let date = parts.next()?;
    let mut date_parts = date.split('-');
    let day = date_parts.next()?.parse::<u32>().ok()?;
    let month = parse_http_month(date_parts.next()?)?;
    let year_two_digits = date_parts.next()?.parse::<u32>().ok()?;
    if date_parts.next().is_some() {
        return None;
    }
    let year = if year_two_digits >= 70 {
        1900 + i32::try_from(year_two_digits).ok()?
    } else {
        2000 + i32::try_from(year_two_digits).ok()?
    };
    let (hour, minute, second) = parse_http_time(parts.next()?)?;
    if parts.next()? != "GMT" || parts.next().is_some() {
        return None;
    }
    unix_seconds_utc(year, month, day, hour, minute, second)
}

fn parse_asctime_date(raw: &str) -> Option<i64> {
    let mut parts = raw.split_ascii_whitespace();
    let _weekday = parts.next()?;
    let month = parse_http_month(parts.next()?)?;
    let day = parts.next()?.parse::<u32>().ok()?;
    let (hour, minute, second) = parse_http_time(parts.next()?)?;
    let year = parts.next()?.parse::<i32>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    unix_seconds_utc(year, month, day, hour, minute, second)
}

fn parse_http_month(month: &str) -> Option<u32> {
    match month {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

fn parse_http_time(time: &str) -> Option<(u32, u32, u32)> {
    let mut parts = time.split(':');
    let hour = parts.next()?.parse::<u32>().ok()?;
    let minute = parts.next()?.parse::<u32>().ok()?;
    let second = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second))
}

fn unix_seconds_utc(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<i64> {
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let second = second.min(59);
    Some(
        days_from_civil(year, month, day)
            .checked_mul(86_400)?
            .checked_add(i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))?,
    )
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut year = i64::from(year);
    let month = i64::from(month);
    let day = i64::from(day);
    year -= i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn is_retryable_status(status: u16) -> bool {
    // A 408 StatementTimeout is terminal: the statement already exceeded its
    // server-side STATEMENT_TIMEOUT_IN_SECONDS, so retrying re-runs a query that
    // will time out again and burns the retry budget for nothing. Only transient
    // conditions (429 overload, 5xx) are retried. This matches the authoritative
    // `ResponseClass::is_retryable` in franken-snowflake-sqlapi.
    matches!(
        classify_status(StatusCode(status)),
        StatusClass::RateLimited | StatusClass::ServerErrorRetryable
    )
}

fn route_allows_automatic_retry(route: &TransportRoute) -> bool {
    // Snowflake warns that ambiguous resubmission of a statement can execute
    // the SQL twice. Plain submit retry is allowed only when the URL carries
    // the documented requestId + retry=true contract recorded above. Poll,
    // partition, and cancel are idempotent transport follow-ups.
    route.has_retry_contract()
        || matches!(
            route,
            TransportRoute::Poll { .. }
                | TransportRoute::Partition { .. }
                | TransportRoute::Cancel { .. }
        )
}

fn cancel_reason_or(cx: &Cx, fallback: fn() -> CancelReason) -> CancelReason {
    cx.cancel_reason().unwrap_or_else(fallback)
}

async fn wait_retry_delay(cx: &Cx, delay: Duration) -> Result<(), CancelReason> {
    if cx.checkpoint().is_err() {
        return Err(cancel_reason_or(cx, CancelReason::parent_cancelled));
    }
    if asupersync::time::budget_sleep(cx, delay, cx.now_for_observability())
        .await
        .is_err()
    {
        return Err(cancel_reason_or(cx, CancelReason::deadline));
    }
    if cx.checkpoint().is_err() {
        return Err(cancel_reason_or(cx, CancelReason::parent_cancelled));
    }
    Ok(())
}

async fn run_with_cancellation_mask<T>(cx: &Cx, future: impl Future<Output = T>) -> T {
    let mut future = Box::pin(future);
    std::future::poll_fn(|task| cx.masked(|| future.as_mut().poll(task))).await
}

/// Async partition sink.
pub trait PartitionSink {
    /// Accept a decoded partition in order.
    fn accept(
        &mut self,
        cx: &Cx,
        partition: DecodedPartition,
    ) -> impl std::future::Future<Output = Result<(), TransportError>>;
}

/// Partition stream request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionStreamRequest {
    /// Authorization for partition GETs and optional cleanup cancellation.
    pub auth: AuthorizationDescriptor,
    /// Statement handle.
    pub statement_handle: StatementHandle,
    /// First partition index to fetch.
    pub first_partition: u32,
    /// Exclusive end partition index.
    pub end_partition_exclusive: u32,
    /// Maximum concurrent fetches.
    pub max_concurrent_fetches: usize,
    /// Child budget meet-composed with the ambient query budget for each fetch.
    pub child_budget: Budget,
    /// Whether a local cancellation should attempt a remote statement cancel.
    pub remote_cancel_on_local_cancel: bool,
    /// Seed partitions already decoded, normally inline partition zero.
    pub seed_partitions: Vec<DecodedPartition>,
}

impl PartitionStreamRequest {
    /// Validate and summarize the streaming plan.
    pub fn plan(&self) -> Result<PartitionStreamSummary, TransportError> {
        if self.end_partition_exclusive < self.first_partition {
            return Err(TransportError::new(
                TransportErrorCode::InvalidPartitionPlan,
                "partition end must be greater than or equal to start",
            ));
        }
        if self.max_concurrent_fetches == 0 {
            return Err(TransportError::new(
                TransportErrorCode::InvalidPartitionPlan,
                "partition fetch concurrency must be at least one",
            ));
        }
        Ok(PartitionStreamSummary {
            statement_handle: self.statement_handle.clone(),
            planned_partitions: self.end_partition_exclusive - self.first_partition,
            accepted_seed_partitions: self.seed_partitions.len() as u32,
            max_concurrent_fetches: self.max_concurrent_fetches,
        })
    }
}

/// Partition streaming summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionStreamSummary {
    /// Statement handle.
    pub statement_handle: StatementHandle,
    /// Number of non-seed partitions planned.
    pub planned_partitions: u32,
    /// Number of seed partitions pushed to the sink.
    pub accepted_seed_partitions: u32,
    /// Concurrency bound.
    pub max_concurrent_fetches: usize,
}

/// Request body wrapper for submit.
#[derive(Clone, PartialEq, Eq)]
pub struct SubmitHttpRequest {
    /// Submit route.
    pub route: TransportRoute,
    /// Authorization.
    pub auth: AuthorizationDescriptor,
    /// JSON body bytes owned by the SQL API crate.
    pub body: Vec<u8>,
    /// Whether this call is a retry/resubmit attempt.
    pub retry_resubmit: bool,
}

impl fmt::Debug for SubmitHttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubmitHttpRequest")
            .field("route", &self.route)
            .field("auth", &self.auth)
            .field("body_len", &self.body.len())
            .field("retry_resubmit", &self.retry_resubmit)
            .finish()
    }
}

/// Submit response body.
#[derive(Clone, PartialEq, Eq)]
pub struct SubmitHttpResponse {
    /// HTTP status class.
    pub status: StatusClass,
    /// Raw response body.
    pub body: Vec<u8>,
}

impl fmt::Debug for SubmitHttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubmitHttpResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Poll request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollHttpRequest {
    /// Authorization.
    pub auth: AuthorizationDescriptor,
    /// Statement handle.
    pub statement_handle: StatementHandle,
}

/// Poll response body.
#[derive(Clone, PartialEq, Eq)]
pub struct PollHttpResponse {
    /// HTTP status class.
    pub status: StatusClass,
    /// Raw response body.
    pub body: Vec<u8>,
}

impl fmt::Debug for PollHttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PollHttpResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Partition fetch request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionHttpRequest {
    /// Authorization.
    pub auth: AuthorizationDescriptor,
    /// Statement handle.
    pub statement_handle: StatementHandle,
    /// Partition index.
    pub partition: u32,
}

/// Partition response body.
#[derive(Clone, PartialEq, Eq)]
pub struct PartitionBody {
    /// HTTP status class.
    pub status: StatusClass,
    /// Raw response body.
    pub body: Vec<u8>,
    /// Compression evidence from the wire response.
    pub compression: CompressionEvidence,
}

impl fmt::Debug for PartitionBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartitionBody")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .field("compression", &self.compression)
            .finish()
    }
}

/// Cancel request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CancelHttpRequest {
    /// Authorization.
    pub auth: AuthorizationDescriptor,
    /// Statement handle.
    pub statement_handle: StatementHandle,
    /// Cancellation reason kind.
    pub reason_kind: CancelKind,
}

/// Cancel response body.
#[derive(Clone, PartialEq, Eq)]
pub struct CancelHttpResponse {
    /// HTTP status class.
    pub status: StatusClass,
    /// Raw response body.
    pub body: Vec<u8>,
}

impl fmt::Debug for CancelHttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancelHttpResponse")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish()
    }
}

struct PlannedTransportRequest {
    route: TransportRoute,
    auth: AuthorizationDescriptor,
    body: Vec<u8>,
    retry_resubmit: bool,
    request_id: Option<RequestId>,
    partition: Option<u32>,
    budget: Budget,
}

impl PlannedTransportRequest {
    fn partition(
        auth: AuthorizationDescriptor,
        statement_handle: StatementHandle,
        partition: u32,
        budget: Budget,
    ) -> Self {
        Self {
            route: TransportRoute::Partition {
                handle: statement_handle,
                partition,
            },
            auth,
            body: Vec::new(),
            retry_resubmit: false,
            request_id: None,
            partition: Some(partition),
            budget,
        }
    }
}

impl From<SubmitHttpRequest> for PlannedTransportRequest {
    fn from(value: SubmitHttpRequest) -> Self {
        let request_id = match &value.route {
            TransportRoute::SubmitRetry { request_id } => Some(request_id.clone()),
            TransportRoute::SubmitWithQuery { query } => query
                .iter()
                .find_map(|(key, value)| (*key == "requestId").then(|| RequestId::new(value))),
            TransportRoute::Submit
            | TransportRoute::Poll { .. }
            | TransportRoute::Partition { .. }
            | TransportRoute::Cancel { .. } => None,
        };
        Self {
            route: value.route,
            auth: value.auth,
            body: value.body,
            retry_resubmit: value.retry_resubmit,
            request_id,
            partition: None,
            budget: Budget::unlimited(),
        }
    }
}

impl From<PollHttpRequest> for PlannedTransportRequest {
    fn from(value: PollHttpRequest) -> Self {
        Self {
            route: TransportRoute::Poll {
                handle: value.statement_handle,
            },
            auth: value.auth,
            body: Vec::new(),
            retry_resubmit: false,
            request_id: None,
            partition: None,
            budget: Budget::unlimited(),
        }
    }
}

impl From<PartitionHttpRequest> for PlannedTransportRequest {
    fn from(value: PartitionHttpRequest) -> Self {
        Self {
            route: TransportRoute::Partition {
                handle: value.statement_handle,
                partition: value.partition,
            },
            auth: value.auth,
            body: Vec::new(),
            retry_resubmit: false,
            request_id: None,
            partition: Some(value.partition),
            budget: Budget::unlimited(),
        }
    }
}

impl From<CancelHttpRequest> for PlannedTransportRequest {
    fn from(value: CancelHttpRequest) -> Self {
        Self {
            route: TransportRoute::Cancel {
                handle: value.statement_handle,
            },
            auth: value.auth,
            body: Vec::new(),
            retry_resubmit: false,
            request_id: None,
            partition: None,
            budget: Budget::unlimited(),
        }
    }
}

trait FromResponseBody: Sized {
    fn from_response(
        response: Response,
        limits: BodyLimits,
        partition: Option<u32>,
    ) -> Result<Self, TransportError>;
}

impl FromResponseBody for SubmitHttpResponse {
    fn from_response(
        response: Response,
        limits: BodyLimits,
        _partition: Option<u32>,
    ) -> Result<Self, TransportError> {
        limits.enforce_response_size(TransportRouteKind::Submit, response.body.len())?;
        Ok(Self {
            status: classify_status(StatusCode(response.status)),
            body: response.body,
        })
    }
}

impl FromResponseBody for PollHttpResponse {
    fn from_response(
        response: Response,
        limits: BodyLimits,
        _partition: Option<u32>,
    ) -> Result<Self, TransportError> {
        limits.enforce_response_size(TransportRouteKind::Poll, response.body.len())?;
        Ok(Self {
            status: classify_status(StatusCode(response.status)),
            body: response.body,
        })
    }
}

impl FromResponseBody for PartitionBody {
    fn from_response(
        response: Response,
        limits: BodyLimits,
        partition: Option<u32>,
    ) -> Result<Self, TransportError> {
        let decoded = decode_partition_response(response, limits, partition.unwrap_or_default())?;
        Ok(Self {
            status: decoded.status,
            body: decoded.body,
            compression: decoded.compression,
        })
    }
}

impl FromResponseBody for CancelHttpResponse {
    fn from_response(
        response: Response,
        limits: BodyLimits,
        _partition: Option<u32>,
    ) -> Result<Self, TransportError> {
        limits.enforce_response_size(TransportRouteKind::Cancel, response.body.len())?;
        Ok(Self {
            status: classify_status(StatusCode(response.status)),
            body: response.body,
        })
    }
}

/// Stable transport error codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportErrorCode {
    /// TLS root policy refused.
    TlsRootPolicyRefused,
    /// Invalid Snowflake host or endpoint.
    InvalidSnowflakeHost,
    /// Body size limit exceeded.
    BodyLimitExceeded,
    /// Header failed validation.
    HeaderRejected,
    /// Retry budget exhausted.
    RetryBudgetExhausted,
    /// Cancelled during TCP connect or TLS handshake.
    CancelledDuringConnect,
    /// Remote cancel after submit failed.
    CancelAfterSubmitFailed,
    /// Unexpected HTTP status.
    HttpStatusUnexpected,
    /// Response decode failed.
    ResponseDecodeFailed,
    /// Gzip decode failed.
    GzipDecodeFailed,
    /// Unsupported content encoding.
    UnsupportedContentEncoding,
    /// Submit retry lacks the requestId + retry=true contract.
    NonIdempotentSubmitRetryRefused,
    /// Invalid partition streaming plan.
    InvalidPartitionPlan,
    /// Asupersync HTTP/network error.
    NetworkError,
}

/// Transport error with a stable code and redacted message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportError {
    /// Stable transport error code.
    pub code: TransportErrorCode,
    /// Redacted message.
    pub message: String,
}

impl TransportError {
    /// Create a transport error.
    #[must_use]
    pub fn new(code: TransportErrorCode, message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            code,
            message: redact(&message).into_owned(),
        }
    }

    /// Map to the shared connector error registry.
    #[must_use]
    pub fn into_snowflake_error(self) -> franken_snowflake_core::error::SnowflakeError {
        use franken_snowflake_core::error::{SnowflakeError, SnowflakeErrorCode};
        let code = match self.code {
            TransportErrorCode::RetryBudgetExhausted => SnowflakeErrorCode::RetryBudgetExhausted,
            TransportErrorCode::HttpStatusUnexpected | TransportErrorCode::ResponseDecodeFailed => {
                SnowflakeErrorCode::UpstreamError
            }
            TransportErrorCode::NetworkError
            | TransportErrorCode::TlsRootPolicyRefused
            | TransportErrorCode::InvalidSnowflakeHost
            | TransportErrorCode::CancelledDuringConnect
            | TransportErrorCode::CancelAfterSubmitFailed => SnowflakeErrorCode::NetworkError,
            TransportErrorCode::BodyLimitExceeded
            | TransportErrorCode::HeaderRejected
            | TransportErrorCode::GzipDecodeFailed
            | TransportErrorCode::UnsupportedContentEncoding
            | TransportErrorCode::NonIdempotentSubmitRetryRefused
            | TransportErrorCode::InvalidPartitionPlan => SnowflakeErrorCode::UsageError,
        };
        SnowflakeError::new(code, self.message)
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for TransportError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> SnowflakeEndpoint {
        SnowflakeEndpoint::parse("https://xy12345.us-east-1.snowflakecomputing.com")
            .expect("valid endpoint")
    }

    fn auth() -> AuthorizationDescriptor {
        auth_with_token("secret-token")
    }

    fn auth_with_token(token: &str) -> AuthorizationDescriptor {
        AuthorizationDescriptor::bearer(
            SnowflakeAuthTokenType::ProgrammaticAccessToken,
            token,
            "sha256:abc123",
        )
    }

    fn header(name: &str, value: &str) -> Vec<(String, String)> {
        vec![(name.to_string(), value.to_string())]
    }

    #[test]
    fn endpoint_requires_https_and_rejects_credentials() {
        assert!(SnowflakeEndpoint::parse("http://xy123.snowflakecomputing.com").is_err());
        assert!(SnowflakeEndpoint::parse("https://user@xy123.snowflakecomputing.com").is_err());
        assert!(SnowflakeEndpoint::parse("https://xy123.snowflakecomputing.com?role=x").is_err());
        let parsed = SnowflakeEndpoint::parse("https://xy123.snowflakecomputing.com/")
            .expect("valid endpoint");
        assert_eq!(parsed.base_url(), "https://xy123.snowflakecomputing.com");
    }

    #[test]
    fn route_urls_are_canonical() {
        let request_id = RequestId::new("req-123");
        let handle = StatementHandle::new("stmt-456");
        assert_eq!(
            endpoint().route_url(&TransportRoute::SubmitRetry { request_id }),
            "https://xy12345.us-east-1.snowflakecomputing.com/api/v2/statements?requestId=req-123&retry=true"
        );
        assert_eq!(
            endpoint().route_url(&TransportRoute::Partition {
                handle,
                partition: 7,
            }),
            "https://xy12345.us-east-1.snowflakecomputing.com/api/v2/statements/stmt-456?partition=7"
        );
    }

    #[test]
    fn submit_query_values_are_percent_encoded() {
        let route = TransportRoute::SubmitWithQuery {
            query: vec![
                ("requestId", "req-123&retry=false".to_owned()),
                ("retry", "true".to_owned()),
                ("nullable", "false".to_owned()),
            ],
        };

        assert_eq!(
            endpoint().route_url(&route),
            "https://xy12345.us-east-1.snowflakecomputing.com/api/v2/statements?requestId=req-123%26retry%3Dfalse&retry=true&nullable=false"
        );
        assert!(route.has_retry_contract());
    }

    #[test]
    fn auth_debug_redacts_secret_bearer() {
        let rendered = format!("{:?}", auth());
        assert!(rendered.contains("sha256:abc123"));
        assert!(!rendered.contains("secret-token"));
    }

    #[test]
    fn auth_headers_wire_token_type_without_logging_secret() {
        let headers = auth().wire_headers().expect("headers");
        assert!(
            headers
                .iter()
                .any(|h| { h.name == HEADER_AUTHORIZATION && h.value == "Bearer secret-token" })
        );
        assert!(
            headers
                .iter()
                .any(|h| { h.name == HEADER_TOKEN_TYPE && h.value == "PROGRAMMATIC_ACCESS_TOKEN" })
        );
    }

    #[test]
    fn wire_request_and_header_debug_redact_authorization_bearer() {
        let token = "sfpat_http_debug_secret_123";
        let client = SnowflakeHttpClient::new(
            TransportConfig::new(endpoint()),
            AsupersyncHttpClient::new(),
        );
        let request = SubmitHttpRequest {
            route: TransportRoute::Submit,
            auth: auth_with_token(token),
            body: b"{}".to_vec(),
            retry_resubmit: false,
        };
        let plan = client.submit_plan(&request).expect("submit plan");
        let authorization = plan
            .headers
            .iter()
            .find(|header| header.name == HEADER_AUTHORIZATION)
            .expect("authorization header");

        assert_eq!(authorization.value, format!("Bearer {token}"));

        for rendered in [
            format!("{authorization:?}"),
            format!("{:?}", plan.headers),
            format!("{plan:?}"),
            serde_json::to_string(authorization).expect("header json"),
        ] {
            assert!(
                !rendered.contains(token),
                "diagnostic surface leaked bearer token: {rendered}"
            );
            assert!(rendered.contains(REDACTION_PLACEHOLDER));
        }
    }

    #[test]
    fn body_bearing_debug_surfaces_only_report_lengths() {
        let secret_body = b"sfpat_http_body_secret_123".to_vec();
        let decimal_secret_prefix = "115, 102, 112, 97, 116";
        let compression = CompressionEvidence {
            content_encoding: ContentEncoding::Identity,
            compressed_bytes: secret_body.len() as u64,
            uncompressed_bytes: secret_body.len() as u64,
        };
        let decoded = DecodedPartition {
            partition: 0,
            body: secret_body.clone(),
            compression,
        };
        let stream = PartitionStreamRequest {
            auth: auth(),
            statement_handle: StatementHandle::new("stmt-1"),
            first_partition: 1,
            end_partition_exclusive: 1,
            max_concurrent_fetches: 1,
            child_budget: Budget::unlimited(),
            remote_cancel_on_local_cancel: false,
            seed_partitions: vec![decoded.clone()],
        };

        for rendered in [
            format!(
                "{:?}",
                SubmitHttpRequest {
                    route: TransportRoute::Submit,
                    auth: auth(),
                    body: secret_body.clone(),
                    retry_resubmit: false,
                }
            ),
            format!(
                "{:?}",
                SubmitHttpResponse {
                    status: StatusClass::Completed,
                    body: secret_body.clone(),
                }
            ),
            format!(
                "{:?}",
                PollHttpResponse {
                    status: StatusClass::Running,
                    body: secret_body.clone(),
                }
            ),
            format!(
                "{:?}",
                PartitionBody {
                    status: StatusClass::Completed,
                    body: secret_body.clone(),
                    compression,
                }
            ),
            format!(
                "{:?}",
                CancelHttpResponse {
                    status: StatusClass::Completed,
                    body: secret_body.clone(),
                }
            ),
            format!("{decoded:?}"),
            format!("{stream:?}"),
        ] {
            assert!(
                !rendered.contains("sfpat_http_body_secret_123"),
                "debug surface leaked body as text: {rendered}"
            );
            assert!(
                !rendered.contains(decimal_secret_prefix),
                "debug surface leaked body as reconstructable bytes: {rendered}"
            );
            assert!(rendered.contains("body_len"));
        }
    }

    #[test]
    fn transport_error_constructor_redacts_secret_shaped_messages() {
        let token = "ghp_httpTransportSecret0123";
        let error = TransportError::new(
            TransportErrorCode::NetworkError,
            format!("connect failed with token={token}"),
        );

        for rendered in [
            error.message.clone(),
            error.to_string(),
            serde_json::to_string(&error).expect("error json"),
            format!("{error:?}"),
        ] {
            assert!(
                !rendered.contains(token),
                "transport error leaked secret-shaped token: {rendered}"
            );
            assert!(rendered.contains(REDACTION_PLACEHOLDER));
        }
    }

    #[test]
    fn body_limits_refuse_oversize_submit_request() {
        let limits = BodyLimits {
            max_submit_request_bytes: 3,
            ..BodyLimits::default()
        };
        assert!(limits.enforce(TransportRouteKind::Submit, 4).is_err());
        assert!(limits.enforce(TransportRouteKind::Poll, 4).is_ok());
    }

    #[test]
    fn partition_limits_count_both_compressed_and_uncompressed() {
        let limits = BodyLimits {
            max_partition_compressed_bytes: 10,
            max_partition_uncompressed_bytes: 20,
            ..BodyLimits::default()
        };
        assert!(limits.enforce_partition_sizes(10, 20).is_ok());
        assert!(limits.enforce_partition_sizes(11, 20).is_err());
        assert!(limits.enforce_partition_sizes(10, 21).is_err());
    }

    #[test]
    fn retry_after_wins_before_exponential_jitter() {
        let policy = RetryPolicy::default();
        let request_id = RequestId::new("req-123");
        assert_eq!(
            policy.delay_for(Some(&request_id), TransportRouteKind::Poll, 1, Some(500), 0),
            Some(Duration::from_millis(500))
        );
        let exponential = policy
            .delay_for(Some(&request_id), TransportRouteKind::Poll, 2, None, 0)
            .expect("delay");
        assert!(exponential >= Duration::from_millis(200));
        assert!(exponential <= Duration::from_millis(230));
    }

    #[test]
    fn retry_after_parses_delta_seconds_and_http_dates() {
        let now = Time::from_secs(1_445_412_475);
        assert_eq!(
            retry_after_ms(&header("Retry-After", "5"), now),
            Some(5_000)
        );
        assert_eq!(
            retry_after_ms(&header("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT"), now),
            Some(5_000)
        );
        assert_eq!(
            retry_after_ms(
                &header("Retry-After", "Wednesday, 21-Oct-15 07:28:00 GMT"),
                now
            ),
            Some(5_000)
        );
        assert_eq!(
            retry_after_ms(&header("Retry-After", "Wed Oct 21 07:28:00 2015"), now),
            Some(5_000)
        );
        assert_eq!(
            retry_after_ms(
                &header("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT"),
                Time::from_secs(1_445_412_480)
            ),
            Some(0)
        );
    }

    #[test]
    fn retry_budget_stops_before_sleeping_past_total_budget() {
        let policy = RetryPolicy {
            total_budget_ms: 50,
            ..RetryPolicy::default()
        };
        assert_eq!(
            policy.delay_for(None, TransportRouteKind::Poll, 1, Some(100), 0),
            None
        );
    }

    #[test]
    fn retry_decision_charges_each_delay_once() {
        let policy = RetryPolicy {
            max_attempts: 4,
            base_delay_ms: 25,
            max_delay_ms: 100,
            total_budget_ms: 75,
            respect_retry_after: false,
            deterministic_jitter: false,
        };
        let first = policy
            .next_retry(None, TransportRouteKind::Poll, 1, None, 0)
            .expect("first retry");
        assert_eq!(first.delay, Duration::from_millis(25));
        assert_eq!(first.spent_after_ms, 25);

        let second = policy
            .next_retry(
                None,
                TransportRouteKind::Poll,
                2,
                None,
                first.spent_after_ms,
            )
            .expect("second retry");
        assert_eq!(second.delay, Duration::from_millis(50));
        assert_eq!(second.spent_after_ms, 75);

        assert_eq!(
            policy.next_retry(
                None,
                TransportRouteKind::Poll,
                3,
                None,
                second.spent_after_ms
            ),
            None
        );
    }

    #[test]
    fn attempt_budget_meets_parent_child_and_attempt_quota_once() {
        let parent = Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(10)
            .with_cost_quota(100)
            .with_priority(1);
        let child = Budget::new()
            .with_deadline(Time::from_secs(20))
            .with_poll_quota(8)
            .with_cost_quota(50)
            .with_priority(9);
        let policy = RetryPolicy {
            max_attempts: 4,
            ..RetryPolicy::default()
        };

        let effective = policy.attempt_budget(parent, child, 2);
        let expected = parent.meet(child).meet(Budget::new().with_poll_quota(3));

        assert_eq!(effective, expected);
        assert_eq!(effective.deadline, Some(Time::from_secs(20)));
        assert_eq!(effective.poll_quota, 3);
        assert_eq!(effective.cost_quota, Some(50));
        assert_eq!(effective.priority, 9);
    }

    #[test]
    fn partition_stream_child_budget_flows_to_internal_partition_plan() {
        let parent = Budget::new().with_poll_quota(10).with_cost_quota(100);
        let child = Budget::new().with_poll_quota(2).with_cost_quota(40);
        let planned =
            PlannedTransportRequest::partition(auth(), StatementHandle::new("stmt-1"), 7, child);

        assert_eq!(planned.partition, Some(7));
        assert_eq!(planned.budget, child);
        assert_eq!(
            RetryPolicy::default().attempt_budget(parent, planned.budget, 1),
            parent
                .meet(child)
                .meet(Budget::new().with_poll_quota(RetryPolicy::default().max_attempts))
        );
    }

    #[test]
    fn effective_budget_drives_timeout_and_exhaustion_reason() {
        let now = Time::from_secs(10);
        let bounded = Budget::new().with_deadline(Time::from_secs(12));
        assert_eq!(
            budget_timeout_at(bounded, now),
            Some(Duration::from_secs(2))
        );
        assert!(
            budget_exhaustion_reason_at(Budget::new().with_deadline(Time::from_secs(10)), now)
                .expect("deadline exhausted")
                .is_kind(CancelKind::Deadline)
        );
        assert!(
            budget_exhaustion_reason_at(Budget::new().with_poll_quota(0), now)
                .expect("poll quota exhausted")
                .is_kind(CancelKind::PollQuota)
        );
        assert!(
            budget_exhaustion_reason_at(Budget::new().with_cost_quota(0), now)
                .expect("cost budget exhausted")
                .is_kind(CancelKind::CostBudget)
        );
    }

    #[test]
    fn status_classification_keeps_202_and_429_distinct() {
        assert_eq!(classify_status(StatusCode(200)), StatusClass::Completed);
        assert_eq!(classify_status(StatusCode(202)), StatusClass::Running);
        assert_eq!(
            classify_status(StatusCode(408)),
            StatusClass::StatementTimeout
        );
        assert_eq!(classify_status(StatusCode(422)), StatusClass::QueryFailure);
        assert_eq!(classify_status(StatusCode(429)), StatusClass::RateLimited);
        assert_eq!(
            classify_status(StatusCode(503)),
            StatusClass::ServerErrorRetryable
        );
    }

    #[test]
    fn statement_timeout_408_is_not_retried() {
        // Regression: a 408 statement timeout is terminal, never retried — it
        // would just time out again. Only transient overload/5xx retry. Matches
        // the authoritative sqlapi ResponseClass::is_retryable.
        assert!(!is_retryable_status(408));
        assert!(is_retryable_status(429));
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(503));
        // Terminal/success statuses are never retried.
        assert!(!is_retryable_status(200));
        assert!(!is_retryable_status(422));
        assert!(!is_retryable_status(404));
    }

    #[test]
    fn content_encoding_fails_closed() {
        assert_eq!(
            ContentEncoding::parse(None).expect("identity"),
            ContentEncoding::Identity
        );
        assert_eq!(
            ContentEncoding::parse(Some("gzip")).expect("gzip"),
            ContentEncoding::Gzip
        );
        assert!(ContentEncoding::parse(Some("br")).is_err());
    }

    #[test]
    fn submit_retry_requires_idempotency_contract() {
        let client = SnowflakeHttpClient::new(
            TransportConfig::new(endpoint()),
            AsupersyncHttpClient::new(),
        );
        let request = SubmitHttpRequest {
            route: TransportRoute::Submit,
            auth: auth(),
            body: b"{}".to_vec(),
            retry_resubmit: true,
        };
        assert!(client.submit_plan(&request).is_err());
        let request = SubmitHttpRequest {
            route: TransportRoute::SubmitRetry {
                request_id: RequestId::new("req-123"),
            },
            auth: auth(),
            body: b"{}".to_vec(),
            retry_resubmit: true,
        };
        assert!(client.submit_plan(&request).is_ok());
    }

    #[test]
    fn plain_submit_post_is_not_blindly_retried_but_cancel_is_retry_safe() {
        assert_eq!(SNOWFLAKE_SQL_API_RESUBMIT_DOC_CONSULTED, "2026-06-25");
        assert!(
            SNOWFLAKE_SQL_API_RESUBMIT_DOC_URL
                .contains("/developer-guide/sql-api/submitting-requests")
        );
        assert!(is_retryable_status(503));
        assert!(is_retryable_status(429));

        assert!(!route_allows_automatic_retry(&TransportRoute::Submit));
        assert!(route_allows_automatic_retry(&TransportRoute::SubmitRetry {
            request_id: RequestId::new("req-123")
        }));
        assert!(route_allows_automatic_retry(&TransportRoute::Poll {
            handle: StatementHandle::new("stmt-1")
        }));
        assert!(route_allows_automatic_retry(&TransportRoute::Partition {
            handle: StatementHandle::new("stmt-1"),
            partition: 1,
        }));
        assert!(route_allows_automatic_retry(&TransportRoute::Cancel {
            handle: StatementHandle::new("stmt-1")
        }));
    }

    #[test]
    fn wire_plan_adds_json_headers() {
        let client = SnowflakeHttpClient::new(
            TransportConfig::new(endpoint()),
            AsupersyncHttpClient::new(),
        );
        let request = SubmitHttpRequest {
            route: TransportRoute::Submit,
            auth: auth(),
            body: b"{}".to_vec(),
            retry_resubmit: false,
        };
        let plan = client.submit_plan(&request).expect("submit plan");
        assert_eq!(plan.method, Method::Post);
        assert!(plan.headers.iter().any(|h| h.name == HEADER_ACCEPT));
        assert!(plan.headers.iter().any(|h| h.name == HEADER_CONTENT_TYPE));
    }

    #[test]
    fn partition_wire_plan_advertises_gzip() {
        let client = SnowflakeHttpClient::new(
            TransportConfig::new(endpoint()),
            AsupersyncHttpClient::new(),
        );
        let request = PartitionHttpRequest {
            auth: auth(),
            statement_handle: StatementHandle::new("stmt-1"),
            partition: 2,
        };
        let plan = client.partition_plan(&request).expect("partition plan");
        assert!(
            plan.headers
                .iter()
                .any(|h| h.name == HEADER_ACCEPT_ENCODING && h.value == PARTITION_ACCEPT_ENCODING)
        );
    }

    #[test]
    fn gzip_partition_response_is_decoded_with_evidence() {
        use asupersync::http::compress::{Compressor, GzipCompressor};

        let mut compressed = Vec::new();
        let mut compressor = GzipCompressor::new();
        compressor
            .compress(br#"{"data":[["one"]]}"#, &mut compressed)
            .expect("compress");
        compressor.finish(&mut compressed).expect("finish");

        let response =
            Response::new(200, "OK", compressed.clone()).with_header("content-encoding", "gzip");
        let body =
            PartitionBody::from_response(response, BodyLimits::default(), Some(1)).expect("decode");
        assert_eq!(body.body, br#"{"data":[["one"]]}"#);
        assert_eq!(body.compression.content_encoding, ContentEncoding::Gzip);
        assert_eq!(body.compression.compressed_bytes, compressed.len() as u64);
        assert_eq!(
            body.compression.uncompressed_bytes,
            br#"{"data":[["one"]]}"#.len() as u64
        );
    }

    fn poll_ready<F: Future>(future: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut task = std::task::Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut task) {
            std::task::Poll::Ready(output) => output,
            std::task::Poll::Pending => unreachable!("test future unexpectedly pending"),
        }
    }

    #[test]
    fn cancellation_mask_defers_cleanup_checkpoint() {
        let cx = Cx::for_testing();
        cx.cancel_with(CancelKind::User, Some("cleanup"));

        let checkpoint_ok = poll_ready(run_with_cancellation_mask(&cx, async {
            cx.checkpoint().is_ok()
        }));

        assert!(checkpoint_ok);
        assert!(cx.checkpoint().is_err());
    }

    struct CancellingSink {
        cx: Cx,
        accepted: u32,
    }

    impl PartitionSink for CancellingSink {
        fn accept(
            &mut self,
            _cx: &Cx,
            _partition: DecodedPartition,
        ) -> impl Future<Output = Result<(), TransportError>> {
            self.accepted = self.accepted.saturating_add(1);
            self.cx
                .cancel_with(CancelKind::User, Some("partition sink cancelled"));
            std::future::ready(Ok(()))
        }
    }

    #[test]
    fn partition_stream_observes_cancel_after_seed_accept() {
        let cx = Cx::for_testing();
        let client = SnowflakeHttpClient::new(
            TransportConfig::new(endpoint()),
            AsupersyncHttpClient::new(),
        );
        let request = PartitionStreamRequest {
            auth: auth(),
            statement_handle: StatementHandle::new("stmt-1"),
            first_partition: 1,
            end_partition_exclusive: 1,
            max_concurrent_fetches: 1,
            child_budget: Budget::unlimited(),
            remote_cancel_on_local_cancel: false,
            seed_partitions: vec![DecodedPartition {
                partition: 0,
                body: b"[]".to_vec(),
                compression: CompressionEvidence {
                    content_encoding: ContentEncoding::Identity,
                    compressed_bytes: 2,
                    uncompressed_bytes: 2,
                },
            }],
        };
        let mut sink = CancellingSink {
            cx: cx.clone(),
            accepted: 0,
        };

        let outcome = poll_ready(client.stream_partitions(&cx, request, &mut sink));
        let cancel_kind = match outcome {
            TransportOutcome::Cancelled(reason) => Some(reason.kind),
            TransportOutcome::Ok(_) | TransportOutcome::Err(_) | TransportOutcome::Panicked(_) => {
                None
            }
        };

        assert_eq!(sink.accepted, 1);
        assert_eq!(cancel_kind, Some(CancelKind::User));
    }

    #[test]
    fn partition_stream_plan_validates_concurrency() {
        let request = PartitionStreamRequest {
            auth: auth(),
            statement_handle: StatementHandle::new("stmt-1"),
            first_partition: 1,
            end_partition_exclusive: 3,
            max_concurrent_fetches: 2,
            child_budget: Budget::unlimited(),
            remote_cancel_on_local_cancel: true,
            seed_partitions: Vec::new(),
        };
        assert_eq!(request.plan().expect("plan").planned_partitions, 2);

        let invalid = PartitionStreamRequest {
            max_concurrent_fetches: 0,
            ..request
        };
        assert!(invalid.plan().is_err());
    }
}
