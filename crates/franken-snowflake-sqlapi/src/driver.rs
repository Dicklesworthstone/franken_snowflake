//! The async statement driver: pump the pure [`StatementMachine`] against the
//! live `franken-snowflake-http` transport, cancel-correctly.
//!
//! This is the thin async glue over the pure lifecycle logic. All decisions
//! (status routing, the poll loop, partition assembly) live in
//! [`crate::lifecycle`]; this module only performs the network steps the machine
//! asks for and, crucially, **fires the SQL API cancel endpoint when the
//! ambient `Cx` is cancelled after a statement handle exists** — so no Snowflake
//! statement is orphaned (the obligation/`bracket` contract from
//! `docs/asupersync_leverage.md`).
//!
//! The cancel path delegates to the transport's own
//! `cancel_after_local_cancel`, which masks local cancellation for the bounded
//! cleanup request and single-sources the cancel-policy table. Either way the
//! local outcome is `Cancelled`.

use std::future::Future;
use std::time::Duration;

use asupersync::Cx;
use franken_snowflake_core::cancel::CancelReason;
use franken_snowflake_core::error::{SnowflakeError, SnowflakeErrorCode};
use franken_snowflake_core::ids::StatementHandle;
use franken_snowflake_core::outcome::SnowflakeOutcome;
use franken_snowflake_core::redact::redact;
use franken_snowflake_http::{
    AuthorizationDescriptor, CancelHttpResponse, PartitionBody, PartitionHttpRequest,
    PollHttpRequest, PollHttpResponse, SnowflakeHttpClient, StatusClass, SubmitHttpRequest,
    SubmitHttpResponse, TransportOutcome, TransportRoute,
};

use crate::lifecycle::{
    CompletedStatement, MIN_POLL_INTERVAL, PollPlan, Progress, StatementMachine,
};
use crate::request::{SubmitQueryParams, SubmitStatementRequest};
use crate::status::ResponseClass;

/// The driver outcome: a fully-assembled [`CompletedStatement`] or one of the
/// four `SnowflakeOutcome` terminal states.
pub type StatementOutcome = SnowflakeOutcome<CompletedStatement>;

/// The transport operations the driver needs. `SnowflakeHttpClient` is the
/// production implementation; tests inject a scripted fake so the driver's
/// error and cancellation paths are provable without a socket or an account.
pub trait StatementTransport {
    /// `POST /api/v2/statements`.
    fn submit_statement(
        &self,
        cx: &Cx,
        request: SubmitHttpRequest,
    ) -> impl Future<Output = TransportOutcome<SubmitHttpResponse>>;
    /// `GET /api/v2/statements/{handle}`.
    fn poll_statement(
        &self,
        cx: &Cx,
        request: PollHttpRequest,
    ) -> impl Future<Output = TransportOutcome<PollHttpResponse>>;
    /// `GET /api/v2/statements/{handle}?partition=N` (gzip already decoded).
    fn fetch_partition(
        &self,
        cx: &Cx,
        request: PartitionHttpRequest,
    ) -> impl Future<Output = TransportOutcome<PartitionBody>>;
    /// Policy-routed remote cancel after a local cancellation.
    fn cancel_after_local_cancel(
        &self,
        cx: &Cx,
        auth: AuthorizationDescriptor,
        statement_handle: StatementHandle,
        reason: CancelReason,
    ) -> impl Future<Output = TransportOutcome<CancelHttpResponse>>;
    /// Best-effort remote cancel when the driver abandons a handle after an error.
    fn cancel_orphaned_statement(
        &self,
        cx: &Cx,
        auth: AuthorizationDescriptor,
        statement_handle: StatementHandle,
    ) -> impl Future<Output = TransportOutcome<CancelHttpResponse>>;
}

impl StatementTransport for SnowflakeHttpClient {
    async fn submit_statement(
        &self,
        cx: &Cx,
        request: SubmitHttpRequest,
    ) -> TransportOutcome<SubmitHttpResponse> {
        Self::submit_statement(self, cx, request).await
    }

    async fn poll_statement(
        &self,
        cx: &Cx,
        request: PollHttpRequest,
    ) -> TransportOutcome<PollHttpResponse> {
        Self::poll_statement(self, cx, request).await
    }

    async fn fetch_partition(
        &self,
        cx: &Cx,
        request: PartitionHttpRequest,
    ) -> TransportOutcome<PartitionBody> {
        Self::fetch_partition(self, cx, request).await
    }

    async fn cancel_after_local_cancel(
        &self,
        cx: &Cx,
        auth: AuthorizationDescriptor,
        statement_handle: StatementHandle,
        reason: CancelReason,
    ) -> TransportOutcome<CancelHttpResponse> {
        Self::cancel_after_local_cancel(self, cx, auth, statement_handle, reason).await
    }

    async fn cancel_orphaned_statement(
        &self,
        cx: &Cx,
        auth: AuthorizationDescriptor,
        statement_handle: StatementHandle,
    ) -> TransportOutcome<CancelHttpResponse> {
        Self::cancel_orphaned_statement(self, cx, auth, statement_handle).await
    }
}

/// Supplies the bearer for each SQL API request and decides what to do when the
/// API answers `401`.
///
/// The driver asks for a fresh [`AuthorizationDescriptor`] before every submit,
/// poll, and partition fetch, so a lane that re-signs near expiry (key-pair
/// JWT) keeps a long-polling statement authenticated past the token lifetime
/// without any special casing. On a `401` the driver calls
/// [`AuthProvider::on_unauthorized`]; `Ok(true)` means the credential was
/// refreshed and the same step is retried exactly once, `Ok(false)` means the
/// lane cannot recover (PAT/OAuth) and the statement fails with a typed
/// `CredentialExpired` error (and an orphan cancel if a handle exists).
pub trait AuthProvider {
    /// The descriptor to attach to the next request.
    fn descriptor(&mut self) -> Result<AuthorizationDescriptor, SnowflakeError>;
    /// The API rejected the last descriptor with `401`. Return `Ok(true)` after
    /// refreshing the credential so the step is retried once.
    fn on_unauthorized(&mut self) -> Result<bool, SnowflakeError>;
}

/// A frozen bearer: never refreshes, so a `401` is terminal.
impl AuthProvider for AuthorizationDescriptor {
    fn descriptor(&mut self) -> Result<AuthorizationDescriptor, SnowflakeError> {
        Ok(self.clone())
    }

    fn on_unauthorized(&mut self) -> Result<bool, SnowflakeError> {
        Ok(false)
    }
}

/// Observed effort for one driven statement, for `budget_consumed` reporting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DriverStats {
    /// Number of `GET /statements/{handle}` polls issued after the submit.
    pub polls: u32,
    /// Number of non-inline partitions fetched.
    pub partitions_fetched: u32,
}

/// Submit a statement and drive it to completion: submit -> poll/await ->
/// partition fetch -> assemble, firing the remote cancel endpoint if the ambient
/// `Cx` is cancelled mid-flight.
///
/// `request` is the SQL API submit body; `params` carries the idempotency
/// `requestId`/`retry` query contract that makes a resubmit safe.
pub async fn run_statement<T: StatementTransport>(
    cx: &Cx,
    client: &T,
    auth: AuthorizationDescriptor,
    request: SubmitStatementRequest,
    params: SubmitQueryParams,
    poll_plan: PollPlan,
) -> StatementOutcome {
    run_statement_with_stats(cx, client, auth, request, params, poll_plan)
        .await
        .0
}

/// [`run_statement`] plus the poll/partition counts it consumed.
pub async fn run_statement_with_stats<T: StatementTransport>(
    cx: &Cx,
    client: &T,
    auth: AuthorizationDescriptor,
    request: SubmitStatementRequest,
    params: SubmitQueryParams,
    poll_plan: PollPlan,
) -> (StatementOutcome, DriverStats) {
    let mut frozen = auth;
    run_statement_with_auth(cx, client, &mut frozen, request, params, poll_plan).await
}

/// [`run_statement_with_stats`] with a refreshing [`AuthProvider`]: the bearer
/// is re-derived before every request and a `401` triggers one re-sign + retry
/// of the same step when the provider can refresh.
pub async fn run_statement_with_auth<T: StatementTransport, A: AuthProvider>(
    cx: &Cx,
    client: &T,
    auth: &mut A,
    request: SubmitStatementRequest,
    params: SubmitQueryParams,
    poll_plan: PollPlan,
) -> (StatementOutcome, DriverStats) {
    let mut stats = DriverStats::default();
    let outcome = drive(cx, client, auth, request, params, poll_plan, &mut stats).await;
    (outcome, stats)
}

/// Build the typed error for a `401` the driver could not recover from.
fn unauthorized_error(step: &str, detail: &str) -> SnowflakeError {
    SnowflakeError::new(
        SnowflakeErrorCode::CredentialExpired,
        format!("SQL API returned 401 Unauthorized on {step}: {detail}"),
    )
}

/// After a `401`: spend the one retry allowed for this step by asking the
/// provider to refresh. Returns the new descriptor to retry with, or the typed
/// error to surface.
fn refresh_after_unauthorized<A: AuthProvider>(
    provider: &mut A,
    reauth_left: &mut u8,
    step: &str,
) -> Result<AuthorizationDescriptor, SnowflakeError> {
    if *reauth_left == 0 {
        return Err(unauthorized_error(
            step,
            "the re-signed credential was rejected again; not retrying further",
        ));
    }
    *reauth_left = reauth_left.saturating_sub(1);
    match provider.on_unauthorized()? {
        true => provider.descriptor(),
        false => Err(unauthorized_error(
            step,
            "this credential lane cannot re-sign mid-flight; issue a fresh token and retry",
        )),
    }
}

async fn drive<T: StatementTransport, A: AuthProvider>(
    cx: &Cx,
    client: &T,
    provider: &mut A,
    request: SubmitStatementRequest,
    params: SubmitQueryParams,
    poll_plan: PollPlan,
    stats: &mut DriverStats,
) -> StatementOutcome {
    let body = match serde_json::to_vec(&request) {
        Ok(body) => body,
        Err(error) => {
            return SnowflakeOutcome::err(SnowflakeError::new(
                SnowflakeErrorCode::UsageError,
                format!("failed to serialize submit body: {error}"),
            ));
        }
    };

    let mut auth = match provider.descriptor() {
        Ok(auth) => auth,
        Err(error) => return SnowflakeOutcome::err(error),
    };
    // One 401 retry per step; reset after any accepted response.
    let mut reauth_left: u8 = 1;

    let submit_response = loop {
        let submit = SubmitHttpRequest {
            route: submit_route(&params),
            auth: auth.clone(),
            body: body.clone(),
            retry_resubmit: params.retry,
        };
        match client.submit_statement(cx, submit).await {
            SnowflakeOutcome::Ok(response) if response.status == StatusClass::Unauthorized => {
                // No handle was issued, so a resubmit with the same requestId
                // is safe; nothing to cancel server-side.
                match refresh_after_unauthorized(provider, &mut reauth_left, "submit") {
                    Ok(fresh) => auth = fresh,
                    Err(error) => return SnowflakeOutcome::err(error),
                }
            }
            SnowflakeOutcome::Ok(response) => break response,
            SnowflakeOutcome::Err(error) => return SnowflakeOutcome::err(error),
            SnowflakeOutcome::Cancelled(reason) => return SnowflakeOutcome::cancelled(reason),
            SnowflakeOutcome::Panicked(payload) => return SnowflakeOutcome::panicked(payload),
        }
    };
    reauth_left = 1;

    // Captured before the machine takes ownership; `PollPlan` is `Copy`. The 202
    // poll loop waits this long between GETs (see `wait_poll_interval`).
    let poll_interval = poll_plan.effective_poll_interval();
    let mut machine = StatementMachine::new(poll_plan);
    let mut progress = match machine.on_submit(
        response_class(submit_response.status),
        &submit_response.body,
    ) {
        Ok(progress) => progress,
        Err(error) => return SnowflakeOutcome::err(error.into_snowflake_error()),
    };

    loop {
        match progress {
            Progress::Complete(completed) => return SnowflakeOutcome::ok(completed),
            Progress::TimedOut(failure) => {
                return SnowflakeOutcome::err(terminal_failure_error(
                    SnowflakeErrorCode::StatementTimeout,
                    failure,
                ));
            }
            Progress::Failed(failure) => {
                return SnowflakeOutcome::err(terminal_failure_error(
                    SnowflakeErrorCode::StatementFailed,
                    failure,
                ));
            }
            Progress::PollAgain(handle) => {
                if cx.checkpoint().is_err() {
                    return cancel_locally(cx, client, &auth, &handle, local_cancel_reason(cx))
                        .await;
                }
                // Pace the 202 poll loop: a still-running statement returns 202
                // immediately (the transport only backs off on retryable 429/5xx),
                // so without this cancel-aware wait the loop would hammer the SQL
                // API and burn the poll quota in milliseconds. A cancellation
                // during the wait still fires the remote cancel for the live handle.
                if let Err(reason) = wait_poll_interval(cx, poll_interval).await {
                    return cancel_locally(cx, client, &auth, &handle, reason).await;
                }
                stats.polls = stats.polls.saturating_add(1);
                // Re-derive the bearer so a near-expiry JWT is re-signed before
                // the GET instead of after a 401.
                auth = match provider.descriptor() {
                    Ok(fresh) => fresh,
                    Err(error) => {
                        return abandon_with_error(cx, client, &auth, &handle, error).await;
                    }
                };
                let poll = client
                    .poll_statement(
                        cx,
                        PollHttpRequest {
                            auth: auth.clone(),
                            statement_handle: handle.clone(),
                        },
                    )
                    .await;
                let response = match poll {
                    SnowflakeOutcome::Ok(response) => response,
                    SnowflakeOutcome::Err(error) => {
                        return abandon_with_error(cx, client, &auth, &handle, error).await;
                    }
                    SnowflakeOutcome::Cancelled(reason) => {
                        return cancel_locally(cx, client, &auth, &handle, reason).await;
                    }
                    SnowflakeOutcome::Panicked(payload) => {
                        return SnowflakeOutcome::panicked(payload);
                    }
                };
                if response.status == StatusClass::Unauthorized {
                    match refresh_after_unauthorized(provider, &mut reauth_left, "poll") {
                        Ok(fresh) => {
                            auth = fresh;
                            progress = Progress::PollAgain(handle);
                            continue;
                        }
                        Err(error) => {
                            return abandon_with_error(cx, client, &auth, &handle, error).await;
                        }
                    }
                }
                reauth_left = 1;
                progress = match machine.on_poll(response_class(response.status), &response.body) {
                    Ok(progress) => progress,
                    Err(error) => {
                        return abandon_with_error(
                            cx,
                            client,
                            &auth,
                            &handle,
                            error.into_snowflake_error(),
                        )
                        .await;
                    }
                };
            }
            Progress::FetchPartition { handle, partition } => {
                if cx.checkpoint().is_err() {
                    return cancel_locally(cx, client, &auth, &handle, local_cancel_reason(cx))
                        .await;
                }
                stats.partitions_fetched = stats.partitions_fetched.saturating_add(1);
                auth = match provider.descriptor() {
                    Ok(fresh) => fresh,
                    Err(error) => {
                        return abandon_with_error(cx, client, &auth, &handle, error).await;
                    }
                };
                let fetch = client
                    .fetch_partition(
                        cx,
                        PartitionHttpRequest {
                            auth: auth.clone(),
                            statement_handle: handle.clone(),
                            partition,
                        },
                    )
                    .await;
                let response = match fetch {
                    SnowflakeOutcome::Ok(response) => response,
                    SnowflakeOutcome::Err(error) => {
                        return abandon_with_error(cx, client, &auth, &handle, error).await;
                    }
                    SnowflakeOutcome::Cancelled(reason) => {
                        return cancel_locally(cx, client, &auth, &handle, reason).await;
                    }
                    SnowflakeOutcome::Panicked(payload) => {
                        return SnowflakeOutcome::panicked(payload);
                    }
                };
                if response.status == StatusClass::Unauthorized {
                    match refresh_after_unauthorized(provider, &mut reauth_left, "partition fetch")
                    {
                        Ok(fresh) => {
                            auth = fresh;
                            progress = Progress::FetchPartition { handle, partition };
                            continue;
                        }
                        Err(error) => {
                            return abandon_with_error(cx, client, &auth, &handle, error).await;
                        }
                    }
                }
                reauth_left = 1;
                // `response.body` is already gzip-decoded by the transport.
                progress = match machine.on_partition(
                    response_class(response.status),
                    partition,
                    &response.body,
                ) {
                    Ok(progress) => progress,
                    Err(error) => {
                        return abandon_with_error(
                            cx,
                            client,
                            &auth,
                            &handle,
                            error.into_snowflake_error(),
                        )
                        .await;
                    }
                };
            }
        }
    }
}

/// The driver is giving up on a live handle because of a local error (transport
/// failure or an undecodable response). Fire a best-effort remote cancel so the
/// statement is not left running server-side, then surface the original error.
/// A failed cleanup does not change the error the caller sees.
async fn abandon_with_error<T: StatementTransport>(
    cx: &Cx,
    client: &T,
    auth: &AuthorizationDescriptor,
    handle: &StatementHandle,
    error: SnowflakeError,
) -> StatementOutcome {
    let _ = client
        .cancel_orphaned_statement(cx, auth.clone(), handle.clone())
        .await;
    SnowflakeOutcome::err(error)
}

/// Fire the SQL API cancel endpoint through the transport's masked cleanup path,
/// then report the local outcome as `Cancelled`.
async fn cancel_locally<T: StatementTransport>(
    cx: &Cx,
    client: &T,
    auth: &AuthorizationDescriptor,
    handle: &StatementHandle,
    reason: CancelReason,
) -> StatementOutcome {
    // Best-effort: the local outcome is Cancelled regardless of whether the
    // remote cancel acknowledgement arrives.
    let _ = client
        .cancel_after_local_cancel(cx, auth.clone(), handle.clone(), reason.clone())
        .await;
    SnowflakeOutcome::cancelled(reason)
}

fn local_cancel_reason(cx: &Cx) -> CancelReason {
    cx.cancel_reason()
        .unwrap_or_else(CancelReason::parent_cancelled)
}

fn terminal_failure_error(
    code: SnowflakeErrorCode,
    failure: crate::response::QueryFailureStatus,
) -> SnowflakeError {
    SnowflakeError::new(code, redact(&failure.message).into_owned())
}

/// Wait `delay` between poll `GET`s, cancel-aware. Returns the cancellation reason
/// if the ambient `Cx` is cancelled before or during the wait, so the caller can
/// fire the remote cancel for the live statement handle.
async fn wait_poll_interval(cx: &Cx, delay: Duration) -> Result<(), CancelReason> {
    let mut remaining = delay;
    while !remaining.is_zero() {
        if cx.checkpoint().is_err() {
            return Err(local_cancel_reason(cx));
        }

        let slice = remaining.min(MIN_POLL_INTERVAL);
        if asupersync::time::budget_sleep(cx, slice, cx.now_for_observability())
            .await
            .is_err()
        {
            // `budget_sleep` reports elapsed deadlines but does not itself mark
            // the `Cx` cancelled. Checkpoint once so budget exhaustion is
            // attributed as Deadline/PollQuota/CostBudget instead of falling
            // back to ParentCancelled.
            let _ = cx.checkpoint();
            return Err(local_cancel_reason(cx));
        }

        if cx.checkpoint().is_err() {
            return Err(local_cancel_reason(cx));
        }
        remaining = remaining.saturating_sub(slice);
    }
    Ok(())
}

/// Pick the submit route, preserving every typed submit query parameter.
fn submit_route(params: &SubmitQueryParams) -> TransportRoute {
    let query = params.to_query_pairs();
    if query.is_empty() {
        TransportRoute::Submit
    } else {
        TransportRoute::SubmitWithQuery { query }
    }
}

/// Map the transport's status classification onto the lifecycle machine's
/// [`ResponseClass`] vocabulary. The transport already retries `5xx`, so
/// `ServerErrorRetryable` rarely reaches the machine; it maps to a non-terminal
/// `Other` the machine treats as unexpected.
const fn response_class(status: StatusClass) -> ResponseClass {
    match status {
        StatusClass::Completed => ResponseClass::Completed,
        StatusClass::Running => ResponseClass::Running,
        StatusClass::StatementTimeout => ResponseClass::StatementTimeout,
        StatusClass::QueryFailure => ResponseClass::StatementFailed,
        StatusClass::RateLimited => ResponseClass::RateLimited,
        StatusClass::ServerErrorRetryable => ResponseClass::Other(503),
        // The driver intercepts 401 before the machine sees it; if one ever
        // reaches here it is terminal-unexpected, never "still running".
        StatusClass::Unauthorized => ResponseClass::Other(401),
        StatusClass::Unexpected => ResponseClass::Other(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::QueryFailureStatus;
    use asupersync::{Budget, CancelKind, Time};
    use franken_snowflake_core::outcome::{OutcomeKind, SnowflakeOutcomeExt};
    use franken_snowflake_http::{
        CompressionEvidence, ContentEncoding, SnowflakeAuthTokenType, TransportError,
        TransportErrorCode,
    };
    use std::cell::RefCell;

    const RESP_202: &[u8] = include_bytes!("../tests/fixtures/resp_202_running.json");
    const RESP_200_MULTI: &[u8] =
        include_bytes!("../tests/fixtures/resp_200_resultset_multi_partition.json");
    const RESP_200_SINGLE: &[u8] =
        include_bytes!("../tests/fixtures/resp_200_resultset_single_partition.json");

    /// What the fake answers on each route; `Err` produces a transport error.
    #[derive(Clone)]
    enum Scripted {
        Ok(StatusClass, Vec<u8>),
        Err,
    }

    /// A scripted transport recording every cancel the driver issues.
    struct FakeTransport {
        submit: Scripted,
        /// Consumed by the first submit only (models a 401 on the initial POST).
        submit_first: RefCell<Option<Scripted>>,
        polls: RefCell<Vec<Scripted>>,
        partitions: RefCell<Vec<Scripted>>,
        cancels_after_local: RefCell<Vec<(StatementHandle, CancelKind)>>,
        orphan_cancels: RefCell<Vec<StatementHandle>>,
        /// Credential fingerprint attached to every submit/poll/partition, in order.
        auth_seen: RefCell<Vec<String>>,
    }

    impl FakeTransport {
        fn new(submit: Scripted) -> Self {
            Self {
                submit,
                submit_first: RefCell::new(None),
                polls: RefCell::new(Vec::new()),
                partitions: RefCell::new(Vec::new()),
                cancels_after_local: RefCell::new(Vec::new()),
                orphan_cancels: RefCell::new(Vec::new()),
                auth_seen: RefCell::new(Vec::new()),
            }
        }

        fn transport_error() -> SnowflakeError {
            TransportError::new(TransportErrorCode::NetworkError, "connection reset")
                .into_snowflake_error()
        }
    }

    impl StatementTransport for FakeTransport {
        async fn submit_statement(
            &self,
            _cx: &Cx,
            request: SubmitHttpRequest,
        ) -> TransportOutcome<SubmitHttpResponse> {
            self.auth_seen
                .borrow_mut()
                .push(request.auth.redacted_fingerprint().to_owned());
            let scripted = self
                .submit_first
                .borrow_mut()
                .take()
                .unwrap_or_else(|| self.submit.clone());
            match scripted {
                Scripted::Ok(status, body) => {
                    TransportOutcome::ok(SubmitHttpResponse { status, body })
                }
                Scripted::Err => TransportOutcome::err(Self::transport_error()),
            }
        }

        async fn poll_statement(
            &self,
            _cx: &Cx,
            request: PollHttpRequest,
        ) -> TransportOutcome<PollHttpResponse> {
            self.auth_seen
                .borrow_mut()
                .push(request.auth.redacted_fingerprint().to_owned());
            let next = self.polls.borrow_mut().remove(0);
            match next {
                Scripted::Ok(status, body) => {
                    TransportOutcome::ok(PollHttpResponse { status, body })
                }
                Scripted::Err => TransportOutcome::err(Self::transport_error()),
            }
        }

        async fn fetch_partition(
            &self,
            _cx: &Cx,
            request: PartitionHttpRequest,
        ) -> TransportOutcome<PartitionBody> {
            self.auth_seen
                .borrow_mut()
                .push(request.auth.redacted_fingerprint().to_owned());
            let next = self.partitions.borrow_mut().remove(0);
            match next {
                Scripted::Ok(status, body) => TransportOutcome::ok(PartitionBody {
                    status,
                    compression: CompressionEvidence {
                        content_encoding: ContentEncoding::Identity,
                        compressed_bytes: body.len() as u64,
                        uncompressed_bytes: body.len() as u64,
                    },
                    body,
                }),
                Scripted::Err => TransportOutcome::err(Self::transport_error()),
            }
        }

        async fn cancel_after_local_cancel(
            &self,
            _cx: &Cx,
            _auth: AuthorizationDescriptor,
            statement_handle: StatementHandle,
            reason: CancelReason,
        ) -> TransportOutcome<CancelHttpResponse> {
            self.cancels_after_local
                .borrow_mut()
                .push((statement_handle, reason.kind));
            TransportOutcome::cancelled(reason)
        }

        async fn cancel_orphaned_statement(
            &self,
            _cx: &Cx,
            _auth: AuthorizationDescriptor,
            statement_handle: StatementHandle,
        ) -> TransportOutcome<CancelHttpResponse> {
            self.orphan_cancels.borrow_mut().push(statement_handle);
            TransportOutcome::ok(CancelHttpResponse {
                status: StatusClass::Completed,
                body: Vec::new(),
            })
        }
    }

    fn fake_auth() -> AuthorizationDescriptor {
        AuthorizationDescriptor::bearer(
            SnowflakeAuthTokenType::ProgrammaticAccessToken,
            "fake-token",
            "cred_test",
        )
    }

    /// A provider whose descriptor fingerprint carries its generation, so the
    /// transport log shows exactly which requests used the re-signed token.
    struct FakeAuth {
        can_resign: bool,
        generation: u32,
        resigns: u32,
    }

    impl FakeAuth {
        fn resigning() -> Self {
            Self {
                can_resign: true,
                generation: 0,
                resigns: 0,
            }
        }

        fn frozen_lane() -> Self {
            Self {
                can_resign: false,
                generation: 0,
                resigns: 0,
            }
        }
    }

    impl AuthProvider for FakeAuth {
        fn descriptor(&mut self) -> Result<AuthorizationDescriptor, SnowflakeError> {
            Ok(AuthorizationDescriptor::bearer(
                SnowflakeAuthTokenType::KeypairJwt,
                format!("jwt-gen-{}", self.generation),
                format!("cred_gen{}", self.generation),
            ))
        }

        fn on_unauthorized(&mut self) -> Result<bool, SnowflakeError> {
            if !self.can_resign {
                return Ok(false);
            }
            self.generation += 1;
            self.resigns += 1;
            Ok(true)
        }
    }

    fn unauthorized() -> Scripted {
        Scripted::Ok(
            StatusClass::Unauthorized,
            b"{\"message\":\"JWT token is invalid.\"}".to_vec(),
        )
    }

    #[test]
    fn poll_401_resigns_once_and_retries_with_the_new_token() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            transport.polls.borrow_mut().push(unauthorized());
            transport
                .polls
                .borrow_mut()
                .push(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            transport.polls.borrow_mut().push(Scripted::Ok(
                StatusClass::Completed,
                RESP_200_SINGLE.to_vec(),
            ));
            let mut auth = FakeAuth::resigning();
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_auth(
                &cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Ok(_)), "{outcome:?}");
            assert_eq!(auth.resigns, 1);
            assert_eq!(stats.polls, 3, "the retried poll is a real GET");
            assert_eq!(
                *transport.auth_seen.borrow(),
                vec!["cred_gen0", "cred_gen0", "cred_gen1", "cred_gen1"],
                "submit + first poll used gen0; the retry and the next poll used the re-signed gen1"
            );
            assert!(transport.orphan_cancels.borrow().is_empty());
            assert!(transport.cancels_after_local.borrow().is_empty());
        });
    }

    #[test]
    fn submit_401_resigns_and_resubmits_without_a_cancel() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            *transport.submit_first.borrow_mut() = Some(unauthorized());
            transport.polls.borrow_mut().push(Scripted::Ok(
                StatusClass::Completed,
                RESP_200_SINGLE.to_vec(),
            ));
            let mut auth = FakeAuth::resigning();
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_auth(
                &cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Ok(_)), "{outcome:?}");
            assert_eq!(auth.resigns, 1);
            assert_eq!(stats.polls, 1);
            assert_eq!(
                *transport.auth_seen.borrow(),
                vec!["cred_gen0", "cred_gen1", "cred_gen1"]
            );
            assert!(transport.orphan_cancels.borrow().is_empty());
        });
    }

    #[test]
    fn poll_401_on_a_lane_that_cannot_resign_is_typed_and_cancels_the_orphan() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            transport.polls.borrow_mut().push(unauthorized());
            let mut auth = FakeAuth::frozen_lane();
            let cx = Cx::for_testing();
            let (outcome, _) = run_statement_with_auth(
                &cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
            )
            .await;
            let SnowflakeOutcome::Err(error) = outcome else {
                panic!("expected a typed error, got {outcome:?}");
            };
            assert_eq!(error.code, SnowflakeErrorCode::CredentialExpired);
            assert!(error.message.contains("401"), "{}", error.message);
            assert_eq!(auth.resigns, 0);
            assert_eq!(transport.orphan_cancels.borrow().len(), 1);
        });
    }

    #[test]
    fn frozen_descriptor_entry_point_treats_401_as_terminal() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            transport.polls.borrow_mut().push(unauthorized());
            let cx = Cx::for_testing();
            let (outcome, _) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
            )
            .await;
            let SnowflakeOutcome::Err(error) = outcome else {
                panic!("expected a typed error, got {outcome:?}");
            };
            assert_eq!(error.code, SnowflakeErrorCode::CredentialExpired);
            assert_eq!(transport.orphan_cancels.borrow().len(), 1);
        });
    }

    #[test]
    fn two_consecutive_401s_stop_after_exactly_one_resign() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            transport.polls.borrow_mut().push(unauthorized());
            transport.polls.borrow_mut().push(unauthorized());
            let mut auth = FakeAuth::resigning();
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_auth(
                &cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
            )
            .await;
            let SnowflakeOutcome::Err(error) = outcome else {
                panic!("expected a typed error, got {outcome:?}");
            };
            assert_eq!(error.code, SnowflakeErrorCode::CredentialExpired);
            assert!(
                error.message.contains("rejected again"),
                "{}",
                error.message
            );
            assert_eq!(auth.resigns, 1, "exactly one re-sign, no loop");
            assert_eq!(stats.polls, 2);
            assert_eq!(transport.orphan_cancels.borrow().len(), 1);
            assert!(transport.polls.borrow().is_empty());
        });
    }

    #[test]
    fn partition_401_resigns_once_and_refetches() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            transport.polls.borrow_mut().push(Scripted::Ok(
                StatusClass::Completed,
                RESP_200_MULTI.to_vec(),
            ));
            let multi: serde_json::Value = serde_json::from_slice(RESP_200_MULTI).unwrap();
            let partitions = multi["resultSetMetaData"]["partitionInfo"]
                .as_array()
                .unwrap()
                .clone();
            let partition_count = partitions.len();
            // First non-inline partition answers 401 once, then every partition
            // is served in the live object form with the promised rowCount.
            transport.partitions.borrow_mut().push(unauthorized());
            for info in partitions.iter().skip(1) {
                let rows = info["rowCount"].as_u64().unwrap_or(0);
                let body = format!(
                    r#"{{"data":[{}]}}"#,
                    (0..rows)
                        .map(|_| r#"["2024-01-02","ENTITY","2.50"]"#)
                        .collect::<Vec<_>>()
                        .join(",")
                );
                transport
                    .partitions
                    .borrow_mut()
                    .push(Scripted::Ok(StatusClass::Completed, body.into_bytes()));
            }
            let mut auth = FakeAuth::resigning();
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_auth(
                &cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Ok(_)), "{outcome:?}");
            assert_eq!(auth.resigns, 1);
            assert_eq!(
                stats.partitions_fetched as usize, partition_count,
                "one extra fetch for the retry"
            );
            assert!(transport.orphan_cancels.borrow().is_empty());
        });
    }

    fn fast_poll_plan(max_polls: u32) -> PollPlan {
        PollPlan {
            max_polls,
            poll_interval: Duration::ZERO,
        }
    }

    fn fixture_handle() -> StatementHandle {
        StatementHandle::new("01b2c3d4-0000-0000-0000-000000000002")
    }

    #[test]
    fn poll_transport_error_after_submit_fires_an_orphan_cancel() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            transport.polls.borrow_mut().push(Scripted::Err);
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Err(_)));
            assert_eq!(stats.polls, 1);
            assert_eq!(
                transport.orphan_cancels.borrow().as_slice(),
                &[fixture_handle()],
                "a transport error after the handle exists must cancel the orphaned statement"
            );
            assert!(transport.cancels_after_local.borrow().is_empty());
        });
    }

    #[test]
    fn undecodable_poll_body_after_submit_fires_an_orphan_cancel() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            transport
                .polls
                .borrow_mut()
                .push(Scripted::Ok(StatusClass::Completed, b"not json".to_vec()));
            let cx = Cx::for_testing();
            let (outcome, _) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Err(_)));
            assert_eq!(transport.orphan_cancels.borrow().len(), 1);
        });
    }

    #[test]
    fn partition_fetch_error_fires_an_orphan_cancel() {
        asupersync::test_utils::run_test(|| async {
            let transport = FakeTransport::new(Scripted::Ok(
                StatusClass::Completed,
                RESP_200_MULTI.to_vec(),
            ));
            transport.partitions.borrow_mut().push(Scripted::Err);
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Err(_)));
            assert_eq!(stats.partitions_fetched, 1);
            assert_eq!(transport.orphan_cancels.borrow().len(), 1);
        });
    }

    #[test]
    fn deadline_during_poll_routes_through_the_policy_cancel_with_deadline_kind() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            // Keep answering "running" so the deadline is what ends the loop.
            for _ in 0..10 {
                transport
                    .polls
                    .borrow_mut()
                    .push(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            }
            let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::from_millis(1)));
            let (outcome, _) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                PollPlan {
                    max_polls: 50,
                    poll_interval: Duration::from_millis(5),
                },
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Cancelled(_)));
            let cancels = transport.cancels_after_local.borrow();
            assert_eq!(cancels.len(), 1);
            assert_eq!(cancels[0].0, fixture_handle());
            assert_eq!(cancels[0].1, CancelKind::Deadline);
            assert!(transport.orphan_cancels.borrow().is_empty());
        });
    }

    #[test]
    fn happy_path_reports_polls_and_partitions_without_any_cancel() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            transport
                .polls
                .borrow_mut()
                .push(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            transport.polls.borrow_mut().push(Scripted::Ok(
                StatusClass::Completed,
                RESP_200_MULTI.to_vec(),
            ));
            let multi: serde_json::Value = serde_json::from_slice(RESP_200_MULTI).unwrap();
            let partitions = multi["resultSetMetaData"]["partitionInfo"]
                .as_array()
                .unwrap()
                .clone();
            let partition_count = partitions.len();
            // Each fetched partition must carry exactly the rowCount the metadata
            // promised; the machine refuses mismatches (integrity check). Bodies
            // use the live `{"data":[...]}` object form, not the bare array.
            for info in partitions.iter().skip(1) {
                let rows = info["rowCount"].as_u64().unwrap_or(0);
                let body = format!(
                    r#"{{"data":[{}]}}"#,
                    (0..rows)
                        .map(|_| r#"["2024-01-02","ENTITY","2.50"]"#)
                        .collect::<Vec<_>>()
                        .join(",")
                );
                transport
                    .partitions
                    .borrow_mut()
                    .push(Scripted::Ok(StatusClass::Completed, body.into_bytes()));
            }
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Ok(_)), "{outcome:?}");
            assert_eq!(stats.polls, 2);
            assert_eq!(stats.partitions_fetched as usize, partition_count - 1);
            assert!(transport.orphan_cancels.borrow().is_empty());
            assert!(transport.cancels_after_local.borrow().is_empty());
        });
    }

    #[test]
    fn response_class_maps_each_transport_status() {
        assert_eq!(
            response_class(StatusClass::Completed),
            ResponseClass::Completed
        );
        assert_eq!(response_class(StatusClass::Running), ResponseClass::Running);
        assert_eq!(
            response_class(StatusClass::StatementTimeout),
            ResponseClass::StatementTimeout
        );
        // 422 query failure maps to the machine's StatementFailed, never conflated
        // with a 408 timeout.
        assert_eq!(
            response_class(StatusClass::QueryFailure),
            ResponseClass::StatementFailed
        );
        assert_eq!(
            response_class(StatusClass::RateLimited),
            ResponseClass::RateLimited
        );
    }

    #[test]
    fn submit_route_requires_request_id_and_retry_for_resubmit() {
        let plain = SubmitQueryParams::default();
        assert!(matches!(submit_route(&plain), TransportRoute::Submit));

        let resubmit = SubmitQueryParams {
            request_id: Some("req-1".to_owned()),
            retry: true,
            ..SubmitQueryParams::default()
        };
        assert!(submit_route(&resubmit).has_retry_contract());

        // retry=true without a requestId cannot use the idempotent contract.
        let no_id = SubmitQueryParams {
            retry: true,
            ..SubmitQueryParams::default()
        };
        assert!(!submit_route(&no_id).has_retry_contract());
    }

    #[test]
    fn submit_route_golden_preserves_async_and_nullable_query_params() {
        let params = SubmitQueryParams {
            request_id: Some("req-async-nullable".to_owned()),
            retry: true,
            asynchronous: true,
            nullable: Some(false),
        };
        let expected_pairs = params.to_query_pairs();

        let route = submit_route(&params);
        assert!(matches!(
            &route,
            TransportRoute::SubmitWithQuery { query } if query == &expected_pairs
        ));
        assert!(route.has_retry_contract());
        assert_eq!(
            route.path_and_query(),
            "/api/v2/statements?requestId=req-async-nullable&retry=true&async=true&nullable=false"
        );
    }

    #[test]
    fn wait_poll_interval_preserves_deadline_attribution() {
        asupersync::test_utils::run_test(|| async {
            let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::from_millis(1)));

            let reason = wait_poll_interval(&cx, Duration::from_millis(10))
                .await
                .expect_err("deadline should expire during poll wait");

            assert_eq!(reason.kind, CancelKind::Deadline);
        });
    }

    #[test]
    fn terminal_statement_failures_keep_precise_error_projection() {
        let timeout = QueryFailureStatus {
            code: "000630".to_owned(),
            sql_state: Some("57014".to_owned()),
            message: "Statement reached its statement timeout and was canceled.".to_owned(),
            statement_handle: Some(StatementHandle::new("timeout-handle")),
        };
        let timeout_error = terminal_failure_error(SnowflakeErrorCode::StatementTimeout, timeout);
        let timeout_outcome: StatementOutcome = SnowflakeOutcome::err(timeout_error.clone());
        assert_eq!(timeout_error.code, SnowflakeErrorCode::StatementTimeout);
        assert_eq!(timeout_outcome.outcome_kind(), OutcomeKind::Timeout);

        let failure = QueryFailureStatus {
            code: "001003".to_owned(),
            sql_state: Some("42000".to_owned()),
            message: "SQL compilation error.".to_owned(),
            statement_handle: Some(StatementHandle::new("failed-handle")),
        };
        let failure_error = terminal_failure_error(SnowflakeErrorCode::StatementFailed, failure);
        let failure_outcome: StatementOutcome = SnowflakeOutcome::err(failure_error.clone());
        assert_eq!(failure_error.code, SnowflakeErrorCode::StatementFailed);
        assert_eq!(failure_outcome.outcome_kind(), OutcomeKind::Error);
    }

    #[test]
    fn terminal_statement_failures_redact_secret_shaped_upstream_messages() {
        let raw_token = "sfpat_driverFailureEcho001";
        let failure = QueryFailureStatus {
            code: "001003".to_owned(),
            sql_state: Some("42000".to_owned()),
            message: format!("SQL compilation error near literal '{raw_token}'"),
            statement_handle: Some(StatementHandle::new("failed-handle")),
        };

        let error = terminal_failure_error(SnowflakeErrorCode::StatementFailed, failure);

        assert_eq!(error.code, SnowflakeErrorCode::StatementFailed);
        assert!(error.message.contains("[REDACTED]"));
        assert!(!error.message.contains(raw_token));
    }
}
