//! The async statement driver: pump the pure [`StatementMachine`] against the
//! live `franken-snowflake-http` transport, cancel-correctly.
//!
//! This is the thin async glue over the pure lifecycle logic. All decisions
//! (status routing, the poll loop, partition assembly) live in
//! [`crate::lifecycle`]; this module only performs the network steps the machine
//! asks for and, crucially, **fires the SQL API cancel endpoint when the
//! ambient `Cx` is cancelled after a statement handle exists** — so no Snowflake
//! statement is orphaned. A running statement is an Asupersync `Lease`
//! obligation of the driving task, resolved on every path (see `DropGuard` and
//! `docs/asupersync_leverage.md`).
//!
//! The cancel path delegates to the transport's own
//! `cancel_after_local_cancel`, which masks local cancellation for the bounded
//! cleanup request and single-sources the cancel-policy table. Either way the
//! local outcome is `Cancelled`.

use std::future::Future;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use std::pin::Pin;
use std::task::{Context, Poll};

use asupersync::Cx;
use asupersync::record::{ObligationAbortReason, ObligationKind};
use asupersync::runtime::obligation_mailbox::ObligationToken;
use franken_snowflake_core::cancel::CancelReason;
use franken_snowflake_core::error::{SnowflakeError, SnowflakeErrorCode};
use franken_snowflake_core::ids::StatementHandle;
use franken_snowflake_core::outcome::SnowflakeOutcome;
use franken_snowflake_core::redact::redact;
use franken_snowflake_http::{
    AuthorizationDescriptor, CancelHttpResponse, PartitionBody, PartitionHttpRequest,
    PollHttpRequest, PollHttpResponse, RawHttp, SnowflakeHttpClient, StatusClass,
    SubmitHttpRequest, SubmitHttpResponse, TransportOutcome, TransportRoute,
    run_with_cancellation_mask,
};

use crate::lifecycle::{
    CompletedStatement, CostQuota, MIN_POLL_INTERVAL, PollPlan, Progress, StatementMachine,
};
use crate::request::{SubmitQueryParams, SubmitStatementRequest};
use crate::response::ResultSet;
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
    /// Remote cancel for a running statement whose driver future was dropped
    /// before it ended (reality-check bead E1): `Drop` has no `Cx` and cannot
    /// await, so this must not block on, or depend on, the caller's runtime.
    /// The default sends nothing.
    fn cancel_on_drop(&self, auth: AuthorizationDescriptor, statement_handle: StatementHandle) {
        let _ = (auth, statement_handle);
    }
}

impl<H: RawHttp> StatementTransport for SnowflakeHttpClient<H> {
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

    /// A fresh client (connections belong to the runtime that opened them) on
    /// its own thread and runtime; the cancel exchange keeps its short bound.
    fn cancel_on_drop(&self, auth: AuthorizationDescriptor, statement_handle: StatementHandle) {
        let config = self.config().clone();
        spawn_detached_cancel(move || async move {
            let (Some(cx), Ok(client)) = (Cx::current(), SnowflakeHttpClient::for_runtime(config))
            else {
                return;
            };
            let _ = client
                .cancel_orphaned_statement(&cx, auth, statement_handle)
                .await;
        });
    }
}

/// Remote cancels of dropped statements still in flight (see
/// [`wait_for_dropped_cancels`]).
static DROPPED_CANCELS: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>> =
    std::sync::Mutex::new(Vec::new());

/// Run `cancel` on a thread and runtime of its own, so a dropped statement's
/// cancel neither blocks the dropping thread nor needs its runtime (which may
/// be unwinding).
fn spawn_detached_cancel<F, Fut>(cancel: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let spawned = std::thread::Builder::new()
        .name("fsnow-drop-cancel".to_owned())
        .spawn(move || {
            if let Ok(runtime) = asupersync::runtime::RuntimeBuilder::current_thread().build() {
                runtime.block_on(cancel());
            }
        });
    if let (Ok(thread), Ok(mut pending)) = (spawned, DROPPED_CANCELS.lock()) {
        pending.retain(|thread| !thread.is_finished());
        pending.push(thread);
    }
}

/// Wait up to `timeout` for the remote cancels of dropped statements to
/// finish; a binary calls this before it exits, since a detached cancel dies
/// with the process. Returns how many were still running.
pub fn wait_for_dropped_cancels(timeout: Duration) -> usize {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let running = DROPPED_CANCELS.lock().map_or(0, |mut pending| {
            pending.retain(|thread| !thread.is_finished());
            pending.len()
        });
        if running == 0 || std::time::Instant::now() >= deadline {
            return running;
        }
        std::thread::sleep(Duration::from_millis(20));
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

/// Observed effort for one driven statement, and the bounds it ran under, for
/// `budget_consumed` reporting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DriverStats {
    /// Number of `GET /statements/{handle}` polls issued after the submit.
    pub polls: u32,
    /// Number of non-inline partitions fetched.
    pub partitions_fetched: u32,
    /// The poll quota it ran under ([`PollPlan::max_polls`]).
    pub poll_quota: u32,
    /// The client-side execution bound it ran under, if any
    /// ([`PollPlan::execution_timeout`]).
    pub execution_timeout: Option<Duration>,
    /// The credit cap it ran under, if any ([`PollPlan::cost_quota`]).
    pub cost_quota: Option<CostQuota>,
    /// How long it executed: from the submit (or resume) to its terminal
    /// status, partition downloads excluded.
    pub execution: Option<Duration>,
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
    let outcome = drive(
        cx,
        client,
        auth,
        Start::Submit { request, params },
        poll_plan,
        &mut stats,
        StatementHooks::default(),
    )
    .await;
    (outcome, stats)
}

/// Receives a statement's rows in partition order while it streams
/// (reality-check bead E5). `Send`, like every hook, so a statement can be
/// driven from a spawned task.
pub trait RowSink: Send {
    /// Take the next rows: the inline rows, then each fetched partition. An
    /// error stops the fetch and cancels the statement server-side.
    ///
    /// # Errors
    /// Whatever the sink could not do with the rows (a write failure, a
    /// row limit).
    fn accept(
        &mut self,
        result_set: &ResultSet,
        rows: Vec<Vec<Option<String>>>,
    ) -> Result<(), SnowflakeError>;
}

/// What happened during a statement run, for progress reporting
/// (reality-check bead E5). Carries no SQL text and no credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DriverEvent {
    /// The submit was answered; `running` when the statement continues
    /// asynchronously and will be polled.
    Submitted {
        /// The statement handle, when the response carried one.
        statement_handle: Option<String>,
        /// Whether the statement is still running.
        running: bool,
    },
    /// A status poll was answered (`polls` issued so far).
    Polled {
        /// Polls issued so far.
        polls: u32,
    },
    /// A result partition was fetched and parsed.
    PartitionFetched {
        /// The partition index (1-based; 0 is inline).
        index: u32,
        /// Rows in the partition.
        rows: u64,
        /// Body bytes after gzip decoding.
        bytes: u64,
    },
    /// The statement completed.
    Completed {
        /// Total rows per the result metadata.
        rows: i64,
        /// Partitions fetched, the inline partition 0 included.
        partitions: u32,
    },
    /// The driver sent the SQL API cancel for a statement it stopped
    /// following (a local cancel, or an error after the handle existed).
    RemoteCancel {
        /// The cancelled statement.
        statement_handle: String,
        /// Whether Snowflake answered the cancel with `200`.
        acknowledged: bool,
        /// The answer's status class, or why no answer arrived.
        detail: String,
    },
}

/// Receives [`DriverEvent`]s while a statement runs.
pub trait DriverObserver: Send {
    /// One event, in order.
    fn event(&mut self, event: DriverEvent);
}

/// Optional per-run hooks: a streaming row sink and a progress observer.
#[derive(Default)]
pub struct StatementHooks<'a> {
    /// Receives the rows instead of the completed statement (streaming).
    pub sink: Option<&'a mut dyn RowSink>,
    /// Receives progress events.
    pub observer: Option<&'a mut dyn DriverObserver>,
}

/// [`run_statement_with_auth`], handing rows to `sink` as each fetch window
/// completes instead of assembling them, so peak memory is one window of
/// partitions. The returned [`CompletedStatement`] keeps the metadata; its
/// `rows` are empty because every row went to the sink.
pub async fn run_statement_streaming<T: StatementTransport, A: AuthProvider>(
    cx: &Cx,
    client: &T,
    auth: &mut A,
    request: SubmitStatementRequest,
    params: SubmitQueryParams,
    poll_plan: PollPlan,
    sink: &mut dyn RowSink,
) -> (StatementOutcome, DriverStats) {
    let hooks = StatementHooks {
        sink: Some(sink),
        observer: None,
    };
    run_statement_hooked(cx, client, auth, request, params, poll_plan, hooks).await
}

/// [`run_statement_with_auth`] with optional [`StatementHooks`].
pub async fn run_statement_hooked<T: StatementTransport, A: AuthProvider>(
    cx: &Cx,
    client: &T,
    auth: &mut A,
    request: SubmitStatementRequest,
    params: SubmitQueryParams,
    poll_plan: PollPlan,
    hooks: StatementHooks<'_>,
) -> (StatementOutcome, DriverStats) {
    let mut stats = DriverStats::default();
    let outcome = drive(
        cx,
        client,
        auth,
        Start::Submit { request, params },
        poll_plan,
        &mut stats,
        hooks,
    )
    .await;
    (outcome, stats)
}

/// The results of a multi-statement request (reality-check bead L1).
#[derive(Clone, Debug, PartialEq)]
pub struct MultiStatementResult {
    /// The parent statement: its handle identifies the request; its only row
    /// is Snowflake's status message.
    pub parent: CompletedStatement,
    /// Each statement's result, in the order the SQL text listed them.
    pub statements: Vec<CompletedStatement>,
}

/// Run a request whose `MULTI_STATEMENT_COUNT` is above one (reality-check
/// bead L1): the parent statement, then each statement fetched by the handle
/// the parent lists (`GET /api/v2/statements/{handle}`), in statement order.
/// Each statement assembles like a single one (polls, partitions, the plan's
/// row cap). A failing statement fails the request with `422` before any
/// result is fetched. The observer sees every step.
pub async fn run_multi_statement_hooked<T: StatementTransport, A: AuthProvider>(
    cx: &Cx,
    client: &T,
    auth: &mut A,
    request: SubmitStatementRequest,
    params: SubmitQueryParams,
    poll_plan: PollPlan,
    mut observer: Option<&mut dyn DriverObserver>,
) -> (SnowflakeOutcome<MultiStatementResult>, DriverStats) {
    let mut stats = DriverStats::default();
    let parent = match drive(
        cx,
        client,
        auth,
        Start::Submit { request, params },
        poll_plan,
        &mut stats,
        StatementHooks {
            sink: None,
            observer: observer
                .as_mut()
                .map(|observer| &mut **observer as &mut dyn DriverObserver),
        },
    )
    .await
    {
        SnowflakeOutcome::Ok(parent) => parent,
        SnowflakeOutcome::Err(error) => return (SnowflakeOutcome::err(error), stats),
        SnowflakeOutcome::Cancelled(reason) => return (SnowflakeOutcome::cancelled(reason), stats),
        SnowflakeOutcome::Panicked(payload) => return (SnowflakeOutcome::panicked(payload), stats),
    };
    let handles = parent
        .result_set
        .statement_handles
        .clone()
        .unwrap_or_default();
    if handles.is_empty() {
        return (
            SnowflakeOutcome::err(SnowflakeError::new(
                SnowflakeErrorCode::UpstreamError,
                "the SQL API answered a multi-statement request without statementHandles",
            )),
            stats,
        );
    }
    let mut statements = Vec::with_capacity(handles.len());
    for handle in handles {
        match drive(
            cx,
            client,
            auth,
            Start::Handle(handle),
            poll_plan,
            &mut stats,
            StatementHooks {
                sink: None,
                observer: observer
                    .as_mut()
                    .map(|observer| &mut **observer as &mut dyn DriverObserver),
            },
        )
        .await
        {
            SnowflakeOutcome::Ok(done) => statements.push(done),
            SnowflakeOutcome::Err(error) => return (SnowflakeOutcome::err(error), stats),
            SnowflakeOutcome::Cancelled(reason) => {
                return (SnowflakeOutcome::cancelled(reason), stats);
            }
            SnowflakeOutcome::Panicked(payload) => {
                return (SnowflakeOutcome::panicked(payload), stats);
            }
        }
    }
    (
        SnowflakeOutcome::ok(MultiStatementResult { parent, statements }),
        stats,
    )
}

/// Where a driven statement starts.
enum Start {
    /// `POST` a new statement.
    Submit {
        request: SubmitStatementRequest,
        params: SubmitQueryParams,
    },
    /// Fetch a statement Snowflake already ran, by its handle (a
    /// multi-statement request's statements).
    Handle(StatementHandle),
}

fn notify(observer: &mut Option<&mut dyn DriverObserver>, event: DriverEvent) {
    if let Some(observer) = observer.as_mut() {
        observer.event(event);
    }
}

fn progress_handle(progress: &Progress) -> Option<String> {
    match progress {
        Progress::PollAgain(handle) | Progress::FetchPartition { handle, .. } => {
            Some(handle.as_str().to_owned())
        }
        Progress::Complete(done) => Some(done.statement_handle.as_str().to_owned()),
        Progress::TimedOut(_) | Progress::Failed(_) => None,
    }
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

/// Wraps the transport to record the result of every remote cancel the
/// driver fires; the cancel paths are best-effort and otherwise discard it.
struct CancelRecorder<'t, T> {
    inner: &'t T,
    cancels: Mutex<Vec<DriverEvent>>,
}

impl<T> CancelRecorder<'_, T> {
    fn record(&self, handle: &StatementHandle, outcome: &TransportOutcome<CancelHttpResponse>) {
        let (acknowledged, detail) = match outcome {
            SnowflakeOutcome::Ok(response) => (
                response.status == StatusClass::Completed,
                status_class_label(response.status).to_owned(),
            ),
            SnowflakeOutcome::Err(error) => (false, redact(&error.message).into_owned()),
            SnowflakeOutcome::Cancelled(reason) => (
                false,
                format!(
                    "the cancel request was itself cancelled ({:?})",
                    reason.kind
                ),
            ),
            SnowflakeOutcome::Panicked(_) => (false, "the cancel request panicked".to_owned()),
        };
        let mut cancels = self.cancels.lock().unwrap_or_else(PoisonError::into_inner);
        cancels.push(DriverEvent::RemoteCancel {
            statement_handle: handle.as_str().to_owned(),
            acknowledged,
            detail,
        });
    }
}

const fn status_class_label(status: StatusClass) -> &'static str {
    match status {
        StatusClass::Completed => "completed",
        StatusClass::Running => "running",
        StatusClass::StatementTimeout => "statement_timeout",
        StatusClass::QueryFailure => "query_failure",
        StatusClass::RateLimited => "rate_limited",
        StatusClass::ServerErrorRetryable => "server_error",
        StatusClass::Unauthorized => "unauthorized",
        StatusClass::Unexpected => "unexpected",
    }
}

impl<T: StatementTransport> StatementTransport for CancelRecorder<'_, T> {
    async fn submit_statement(
        &self,
        cx: &Cx,
        request: SubmitHttpRequest,
    ) -> TransportOutcome<SubmitHttpResponse> {
        self.inner.submit_statement(cx, request).await
    }

    async fn poll_statement(
        &self,
        cx: &Cx,
        request: PollHttpRequest,
    ) -> TransportOutcome<PollHttpResponse> {
        self.inner.poll_statement(cx, request).await
    }

    async fn fetch_partition(
        &self,
        cx: &Cx,
        request: PartitionHttpRequest,
    ) -> TransportOutcome<PartitionBody> {
        self.inner.fetch_partition(cx, request).await
    }

    async fn cancel_after_local_cancel(
        &self,
        cx: &Cx,
        auth: AuthorizationDescriptor,
        statement_handle: StatementHandle,
        reason: CancelReason,
    ) -> TransportOutcome<CancelHttpResponse> {
        let outcome = self
            .inner
            .cancel_after_local_cancel(cx, auth, statement_handle.clone(), reason)
            .await;
        self.record(&statement_handle, &outcome);
        outcome
    }

    async fn cancel_orphaned_statement(
        &self,
        cx: &Cx,
        auth: AuthorizationDescriptor,
        statement_handle: StatementHandle,
    ) -> TransportOutcome<CancelHttpResponse> {
        let outcome = self
            .inner
            .cancel_orphaned_statement(cx, auth, statement_handle.clone())
            .await;
        self.record(&statement_handle, &outcome);
        outcome
    }

    fn cancel_on_drop(&self, auth: AuthorizationDescriptor, statement_handle: StatementHandle) {
        self.inner.cancel_on_drop(auth, statement_handle);
    }
}

/// Run the statement, then report each remote cancel it fired to the
/// observer as [`DriverEvent::RemoteCancel`] (reality-check bead E1: the
/// receipt of a cancelled statement says whether the cancel reached Snowflake).
#[allow(clippy::too_many_arguments)]
async fn drive<T: StatementTransport, A: AuthProvider>(
    cx: &Cx,
    client: &T,
    provider: &mut A,
    start: Start,
    poll_plan: PollPlan,
    stats: &mut DriverStats,
    hooks: StatementHooks<'_>,
) -> StatementOutcome {
    let recorder = CancelRecorder {
        inner: client,
        cancels: Mutex::new(Vec::new()),
    };
    let StatementHooks { sink, mut observer } = hooks;
    let outcome = drive_statement(
        cx,
        &recorder,
        provider,
        start,
        poll_plan,
        stats,
        // Both hooks are reborrowed for the inner run: `StatementHooks` is
        // invariant in its lifetime, and the observer is needed again after.
        StatementHooks {
            sink: sink.map(|sink| sink as &mut dyn RowSink),
            observer: observer
                .as_mut()
                .map(|observer| &mut **observer as &mut dyn DriverObserver),
        },
    )
    .await;
    let cancels = recorder
        .cancels
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    for event in cancels {
        notify(&mut observer, event);
    }
    outcome
}

/// Submit `request` and feed Snowflake's answer to `machine`: the first
/// [`Progress`], or how the statement ended before it had a handle.
#[allow(clippy::too_many_arguments)]
async fn submit<T: StatementTransport, A: AuthProvider>(
    cx: &Cx,
    client: &T,
    provider: &mut A,
    auth: &mut AuthorizationDescriptor,
    reauth_left: &mut u8,
    request: &SubmitStatementRequest,
    params: &SubmitQueryParams,
    machine: &mut StatementMachine,
) -> SnowflakeOutcome<Progress> {
    let body = match serde_json::to_vec(request) {
        Ok(body) => body,
        Err(error) => {
            return SnowflakeOutcome::err(SnowflakeError::new(
                SnowflakeErrorCode::UsageError,
                format!("failed to serialize submit body: {error}"),
            ));
        }
    };
    let submit_response = loop {
        let submit = SubmitHttpRequest {
            route: submit_route(params),
            auth: auth.clone(),
            body: body.clone(),
            retry_resubmit: params.retry,
        };
        // Nothing is sent once the caller has given up.
        if cx.checkpoint().is_err() {
            return SnowflakeOutcome::cancelled(local_cancel_reason(cx));
        }
        // Once the POST is on the wire Snowflake may accept the statement, and
        // only its answer names the handle to cancel (a synchronous submit is
        // answered within 45 s). So a cancel that arrives meanwhile waits for
        // that answer, bounded by the transport's deadline and attempt timeout,
        // and the poll loop's first checkpoint then cancels the statement.
        // Unmasked, the cancel would abandon the answer and orphan the
        // statement until its server-side timeout.
        match run_with_cancellation_mask(cx, client.submit_statement(cx, submit)).await {
            SnowflakeOutcome::Ok(response) if response.status == StatusClass::Unauthorized => {
                // No handle was issued, so a resubmit with the same requestId
                // is safe; nothing to cancel server-side.
                match refresh_after_unauthorized(provider, reauth_left, "submit") {
                    Ok(fresh) => *auth = fresh,
                    Err(error) => return SnowflakeOutcome::err(error),
                }
            }
            SnowflakeOutcome::Ok(response) => break response,
            SnowflakeOutcome::Err(error) => return SnowflakeOutcome::err(error),
            SnowflakeOutcome::Cancelled(reason) => return SnowflakeOutcome::cancelled(reason),
            SnowflakeOutcome::Panicked(payload) => return SnowflakeOutcome::panicked(payload),
        }
    };
    *reauth_left = 1;
    match machine.on_submit(
        response_class(submit_response.status),
        &submit_response.body,
    ) {
        Ok(progress) => SnowflakeOutcome::ok(progress),
        Err(error) => SnowflakeOutcome::err(error.into_snowflake_error()),
    }
}

async fn drive_statement<T: StatementTransport, A: AuthProvider>(
    cx: &Cx,
    client: &T,
    provider: &mut A,
    start: Start,
    poll_plan: PollPlan,
    stats: &mut DriverStats,
    hooks: StatementHooks<'_>,
) -> StatementOutcome {
    // A dropped driver future must not orphan an accepted statement: the guard,
    // armed once the statement runs, cancels it unless the drive ends first.
    let mut guard = DropGuard::new(client);
    let outcome = drive_guarded(
        cx, client, provider, start, poll_plan, stats, hooks, &mut guard,
    )
    .await;
    guard.settle(&outcome);
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn drive_guarded<T: StatementTransport, A: AuthProvider>(
    cx: &Cx,
    client: &T,
    provider: &mut A,
    start: Start,
    poll_plan: PollPlan,
    stats: &mut DriverStats,
    hooks: StatementHooks<'_>,
    guard: &mut DropGuard<'_, T>,
) -> StatementOutcome {
    let StatementHooks {
        mut sink,
        mut observer,
    } = hooks;
    let mut auth = match provider.descriptor() {
        Ok(auth) => auth,
        Err(error) => return SnowflakeOutcome::err(error),
    };
    // One 401 retry per step; reset after any accepted response.
    let mut reauth_left: u8 = 1;
    // Captured before the machine takes ownership; `PollPlan` is `Copy`. The 202
    // poll loop waits this long between GETs (see `wait_poll_interval`).
    let poll_interval = poll_plan.effective_poll_interval();
    stats.poll_quota = poll_plan.max_polls;
    stats.execution_timeout = poll_plan.execution_timeout;
    stats.cost_quota = poll_plan.cost_quota;
    let started = asupersync::time::wall_now();
    let bounds = ExecutionBounds {
        deadline: poll_plan.execution_timeout.map(|timeout| started + timeout),
        cost: poll_plan
            .cost_quota
            .and_then(|quota| quota.time_bound())
            .map(|bound| started + bound),
    };
    let cost_quota = poll_plan.cost_quota;
    let mut machine = StatementMachine::new(poll_plan);
    // A statement resumed by its handle has already run: poll it at once.
    let mut poll_now = false;
    let mut progress = match start {
        Start::Handle(handle) => {
            poll_now = true;
            Progress::PollAgain(handle)
        }
        Start::Submit { request, params } => {
            if let Some(quota) = cost_quota.filter(CostQuota::below_resume_minimum) {
                return SnowflakeOutcome::err(SnowflakeError::new(
                    SnowflakeErrorCode::SafetyLimitExceeded,
                    format!(
                        "not submitted: resuming the suspended warehouse is billed a minute at \
                         least (~{} millionths of a credit), over the {}-millionth credit cap",
                        quota.estimate(Duration::ZERO),
                        quota.max_microcredits
                    ),
                ));
            }
            let progress = match submit(
                cx,
                client,
                provider,
                &mut auth,
                &mut reauth_left,
                &request,
                &params,
                &mut machine,
            )
            .await
            {
                SnowflakeOutcome::Ok(progress) => progress,
                SnowflakeOutcome::Err(error) => return SnowflakeOutcome::err(error),
                SnowflakeOutcome::Cancelled(reason) => return SnowflakeOutcome::cancelled(reason),
                SnowflakeOutcome::Panicked(payload) => return SnowflakeOutcome::panicked(payload),
            };
            notify(
                &mut observer,
                DriverEvent::Submitted {
                    statement_handle: progress_handle(&progress),
                    running: matches!(progress, Progress::PollAgain(_)),
                },
            );
            progress
        }
    };

    // From here the statement is accepted and, while it runs, guarded.
    guard.arm(cx, &auth, &progress);

    // Execution lasts while the statement is being polled; it is measured up
    // to its first non-polling progress (terminal status or partitions).
    let mut executing = true;
    loop {
        if executing {
            stats.execution = Some(elapsed_since(started));
            executing = matches!(progress, Progress::PollAgain(_));
        }
        match progress {
            Progress::Complete(mut completed) => {
                guard.finish();
                notify(
                    &mut observer,
                    DriverEvent::Completed {
                        rows: completed.result_set.total_rows(),
                        partitions: completed.fetched_partitions,
                    },
                );
                // The statement is finished server-side: a sink error needs no
                // remote cancel.
                if let Some(sink) = sink.as_mut() {
                    let rows = std::mem::take(&mut completed.rows);
                    if let Err(error) = sink.accept(&completed.result_set, rows) {
                        return SnowflakeOutcome::err(error);
                    }
                }
                return SnowflakeOutcome::ok(completed);
            }
            Progress::TimedOut(failure) => {
                guard.finish();
                return SnowflakeOutcome::err(terminal_failure_error(
                    SnowflakeErrorCode::StatementTimeout,
                    failure,
                ));
            }
            Progress::Failed(failure) => {
                guard.finish();
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
                if let Some(reason) = bounds.passed() {
                    return cancel_locally(cx, client, &auth, &handle, reason).await;
                }
                // Pace the 202 poll loop: a still-running statement returns 202
                // immediately (the transport only backs off on retryable 429/5xx),
                // so without this cancel-aware wait the loop would hammer the SQL
                // API and burn the poll quota in milliseconds. A cancellation
                // during the wait still fires the remote cancel for the live handle.
                if !std::mem::take(&mut poll_now)
                    && let Err(reason) = wait_poll_interval(cx, bounds.cap(poll_interval)).await
                {
                    return cancel_locally(cx, client, &auth, &handle, reason).await;
                }
                // Still executing after the wait (a bound may end it here).
                stats.execution = Some(elapsed_since(started));
                if let Some(reason) = bounds.passed() {
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
                guard.track(&auth);
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
                        return abandon_with_outcome(
                            cx,
                            client,
                            &auth,
                            &handle,
                            SnowflakeOutcome::panicked(payload),
                        )
                        .await;
                    }
                };
                if response.status == StatusClass::Unauthorized {
                    match refresh_after_unauthorized(provider, &mut reauth_left, "poll") {
                        Ok(fresh) => {
                            auth = fresh;
                            guard.track(&auth);
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
                notify(&mut observer, DriverEvent::Polled { polls: stats.polls });
            }
            Progress::FetchPartition { handle, partition } => {
                if cx.checkpoint().is_err() {
                    return cancel_locally(cx, client, &auth, &handle, local_cancel_reason(cx))
                        .await;
                }
                // Streaming: hand over what is assembled (the inline rows, then
                // the previous window) before fetching more.
                if let Some(sink) = sink.as_mut() {
                    let rows = machine.drain_rows();
                    if !rows.is_empty()
                        && let Some(result_set) = machine.result_set()
                        && let Err(error) = sink.accept(result_set, rows)
                    {
                        return abandon_with_error(cx, client, &auth, &handle, error).await;
                    }
                }
                let (next, total) = machine
                    .assembling_window()
                    .unwrap_or((partition, partition.saturating_add(1)));
                // Row-cap early stop: the caller already has enough rows, so do
                // not download the remaining partitions.
                if let Some(cap) = poll_plan.row_cap
                    && machine.rows_assembled() >= cap
                {
                    return match machine.complete_early() {
                        Ok(mut done) => {
                            guard.finish();
                            notify(
                                &mut observer,
                                DriverEvent::Completed {
                                    rows: done.result_set.total_rows(),
                                    partitions: done.fetched_partitions,
                                },
                            );
                            if let Some(sink) = sink.as_mut() {
                                let rows = std::mem::take(&mut done.rows);
                                if let Err(error) = sink.accept(&done.result_set, rows) {
                                    return SnowflakeOutcome::err(error);
                                }
                            }
                            SnowflakeOutcome::ok(done)
                        }
                        Err(error) => {
                            abandon_with_error(
                                cx,
                                client,
                                &auth,
                                &handle,
                                error.into_snowflake_error(),
                            )
                            .await
                        }
                    };
                }
                auth = match provider.descriptor() {
                    Ok(fresh) => fresh,
                    Err(error) => {
                        return abandon_with_error(cx, client, &auth, &handle, error).await;
                    }
                };
                guard.track(&auth);
                let window =
                    u32::try_from(poll_plan.effective_partition_concurrency()).unwrap_or(u32::MAX);
                let window_end = next.saturating_add(window).min(total);
                let window_auth = auth.clone();
                let fetched =
                    fetch_window(cx, client, &window_auth, &handle, next..window_end).await;
                stats.partitions_fetched = stats
                    .partitions_fetched
                    .saturating_add(window_end.saturating_sub(next));
                let mut after_window = None;
                for (offset, fetch) in fetched.into_iter().enumerate() {
                    let index = next.saturating_add(u32::try_from(offset).unwrap_or(u32::MAX));
                    let mut response = match fetch {
                        SnowflakeOutcome::Ok(response) => response,
                        SnowflakeOutcome::Err(error) => {
                            return abandon_with_error(cx, client, &auth, &handle, error).await;
                        }
                        SnowflakeOutcome::Cancelled(reason) => {
                            return cancel_locally(cx, client, &auth, &handle, reason).await;
                        }
                        SnowflakeOutcome::Panicked(payload) => {
                            return abandon_with_outcome(
                                cx,
                                client,
                                &auth,
                                &handle,
                                SnowflakeOutcome::panicked(payload),
                            )
                            .await;
                        }
                    };
                    if response.status == StatusClass::Unauthorized {
                        // A window shares one bearer: re-sign once for the first
                        // rejection, then refetch later rejections from the same
                        // window with the already-refreshed credential.
                        if auth == window_auth {
                            auth = match refresh_after_unauthorized(
                                provider,
                                &mut reauth_left,
                                "partition fetch",
                            ) {
                                Ok(fresh) => fresh,
                                Err(error) => {
                                    return abandon_with_error(cx, client, &auth, &handle, error)
                                        .await;
                                }
                            };
                            guard.track(&auth);
                        }
                        stats.partitions_fetched = stats.partitions_fetched.saturating_add(1);
                        let refetch = client
                            .fetch_partition(
                                cx,
                                PartitionHttpRequest {
                                    auth: auth.clone(),
                                    statement_handle: handle.clone(),
                                    partition: index,
                                },
                            )
                            .await;
                        response = match refetch {
                            SnowflakeOutcome::Ok(response)
                                if response.status == StatusClass::Unauthorized =>
                            {
                                return abandon_with_error(
                                    cx,
                                    client,
                                    &auth,
                                    &handle,
                                    unauthorized_error(
                                        "partition fetch",
                                        "the re-signed credential was rejected again; not retrying further",
                                    ),
                                )
                                .await;
                            }
                            SnowflakeOutcome::Ok(response) => response,
                            SnowflakeOutcome::Err(error) => {
                                return abandon_with_error(cx, client, &auth, &handle, error).await;
                            }
                            SnowflakeOutcome::Cancelled(reason) => {
                                return cancel_locally(cx, client, &auth, &handle, reason).await;
                            }
                            SnowflakeOutcome::Panicked(payload) => {
                                return abandon_with_outcome(
                                    cx,
                                    client,
                                    &auth,
                                    &handle,
                                    SnowflakeOutcome::panicked(payload),
                                )
                                .await;
                            }
                        };
                    }
                    reauth_left = 1;
                    // Validated against this count by `on_partition` below.
                    let partition_rows = machine
                        .result_set()
                        .and_then(|result_set| {
                            result_set
                                .result_set_meta_data
                                .partition_info
                                .get(usize::try_from(index).unwrap_or(usize::MAX))
                        })
                        .map_or(0, |info| u64::try_from(info.row_count).unwrap_or(0));
                    let partition_bytes = u64::try_from(response.body.len()).unwrap_or(u64::MAX);
                    // `response.body` is already gzip-decoded by the transport.
                    let partition_progress = match machine.on_partition(
                        response_class(response.status),
                        index,
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
                    notify(
                        &mut observer,
                        DriverEvent::PartitionFetched {
                            index,
                            rows: partition_rows,
                            bytes: partition_bytes,
                        },
                    );
                    after_window = Some(partition_progress);
                }
                progress = match after_window {
                    Some(progress) => progress,
                    None => {
                        // The machine asked for a partition at or past `total`;
                        // that is a lifecycle invariant violation, not a retry.
                        return abandon_with_error(
                            cx,
                            client,
                            &auth,
                            &handle,
                            SnowflakeError::new(
                                SnowflakeErrorCode::Internal,
                                format!("empty partition window {next}..{window_end} of {total}"),
                            ),
                        )
                        .await;
                    }
                };
            }
        }
    }
}

/// Owns a running statement's handle while the driver drives it. Dropped
/// before [`DropGuard::settle`] (the driver future itself was dropped
/// mid-flight), it asks the transport to cancel the statement; every path the
/// driver returns through leaves the statement terminal or already cancelled
/// and settles it first.
///
/// The handle is also an Asupersync [`ObligationKind::Lease`] held by the
/// driving task, so the runtime sees every accepted statement resolved:
/// committed once it ended server-side, aborted with
/// [`ObligationAbortReason::Cancel`] when the driver cancelled it or was
/// dropped (the remote cancel is then in flight), and with
/// [`ObligationAbortReason::Error`] when a local failure abandoned it behind a
/// best-effort cancel. A statement left neither way is a leaked lease, which
/// the lab runtime's obligation oracle reports. A `Cx` built without a runtime
/// (tests, request-scoped contexts) holds no lease; the guard still cancels.
struct DropGuard<'t, T: StatementTransport> {
    transport: &'t T,
    armed: Option<(AuthorizationDescriptor, StatementHandle)>,
    lease: Option<ObligationToken>,
}

impl<'t, T: StatementTransport> DropGuard<'t, T> {
    const fn new(transport: &'t T) -> Self {
        Self {
            transport,
            armed: None,
            lease: None,
        }
    }

    /// Hold the statement's handle, and take its lease, when it is still
    /// running. A refused lease (the region is closing) leaves the statement
    /// guarded by the cancel alone: it runs already, and the next checkpoint
    /// cancels it.
    fn arm(&mut self, cx: &Cx, auth: &AuthorizationDescriptor, progress: &Progress) {
        self.armed = match progress {
            Progress::PollAgain(handle) | Progress::FetchPartition { handle, .. } => {
                Some((auth.clone(), handle.clone()))
            }
            Progress::Complete(_) | Progress::TimedOut(_) | Progress::Failed(_) => None,
        };
        if self.armed.is_some() {
            self.lease = cx
                .try_register_obligation_checked(ObligationKind::Lease, cx.task_id())
                .ok()
                .flatten();
        }
    }

    /// Cancel with the latest bearer (a JWT is re-signed while polling).
    fn track(&mut self, auth: &AuthorizationDescriptor) {
        if let Some((held, _)) = self.armed.as_mut() {
            held.clone_from(auth);
        }
    }

    /// The statement ended server-side: nothing is left to cancel.
    fn finish(&mut self) {
        self.armed = None;
        if let Some(lease) = self.lease.take() {
            let _ = lease.commit();
        }
    }

    /// The driver returned `outcome`. A lease still held means it gave up on a
    /// live handle, and its remote cancel was already sent.
    fn settle(&mut self, outcome: &StatementOutcome) {
        self.armed = None;
        if let Some(lease) = self.lease.take() {
            let _ = match outcome {
                SnowflakeOutcome::Ok(_) => lease.commit(),
                SnowflakeOutcome::Cancelled(_) => lease.abort(ObligationAbortReason::Cancel),
                SnowflakeOutcome::Err(_) | SnowflakeOutcome::Panicked(_) => {
                    lease.abort(ObligationAbortReason::Error)
                }
            };
        }
    }
}

impl<T: StatementTransport> Drop for DropGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            let _ = lease.abort(ObligationAbortReason::Cancel);
        }
        if let Some((auth, handle)) = self.armed.take() {
            self.transport.cancel_on_drop(auth, handle);
        }
    }
}

/// Fetch `partitions` with every request in flight at once and return the
/// outcomes in partition order. Nothing is abandoned mid-window: each fetch runs
/// to its own terminal outcome, so a cancellation surfaces as `Cancelled` for
/// that partition rather than as a dropped request.
async fn fetch_window<T: StatementTransport>(
    cx: &Cx,
    client: &T,
    auth: &AuthorizationDescriptor,
    handle: &StatementHandle,
    partitions: std::ops::Range<u32>,
) -> Vec<TransportOutcome<PartitionBody>> {
    let pending: Vec<_> = partitions
        .map(|partition| {
            let request = PartitionHttpRequest {
                auth: auth.clone(),
                statement_handle: handle.clone(),
                partition,
            };
            Some(Box::pin(client.fetch_partition(cx, request)))
        })
        .collect();
    let done = pending.iter().map(|_| None).collect();
    JoinInOrder { pending, done }.await
}

/// Drives a fixed set of futures inside the current task: every still-pending
/// future is polled on each wake, and the join resolves once all have completed,
/// yielding their outputs in the original order. It holds the futures by their
/// own type (no trait object), so the join is `Send` whenever they are.
struct JoinInOrder<F: Future> {
    pending: Vec<Option<Pin<Box<F>>>>,
    done: Vec<Option<F::Output>>,
}

impl<F: Future> Future for JoinInOrder<F>
where
    F::Output: Unpin,
{
    type Output = Vec<F::Output>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut all_done = true;
        for (slot, done) in this.pending.iter_mut().zip(this.done.iter_mut()) {
            if let Some(future) = slot.as_mut() {
                match future.as_mut().poll(context) {
                    Poll::Ready(value) => {
                        *done = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => all_done = false,
                }
            }
        }
        if all_done {
            Poll::Ready(this.done.iter_mut().filter_map(Option::take).collect())
        } else {
            Poll::Pending
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
    abandon_with_outcome(cx, client, auth, handle, SnowflakeOutcome::err(error)).await
}

/// Drain the same handle obligation for errors and returned panic outcomes.
/// Cleanup failure cannot replace the original outcome or its panic payload.
/// This handles `Panicked` values, not an unwinding transport future.
async fn abandon_with_outcome<T: StatementTransport>(
    cx: &Cx,
    client: &T,
    auth: &AuthorizationDescriptor,
    handle: &StatementHandle,
    outcome: StatementOutcome,
) -> StatementOutcome {
    let _ = client
        .cancel_orphaned_statement(cx, auth.clone(), handle.clone())
        .await;
    outcome
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

/// Wall time since `started`.
fn elapsed_since(started: asupersync::Time) -> Duration {
    Duration::from_nanos(asupersync::time::wall_now().duration_since(started))
}

/// The client-side bounds on one statement's execution: the deadline
/// ([`PollPlan::execution_timeout`]) and the credit cap's time bound
/// ([`PollPlan::cost_quota`]).
#[derive(Clone, Copy)]
struct ExecutionBounds {
    deadline: Option<asupersync::Time>,
    cost: Option<asupersync::Time>,
}

impl ExecutionBounds {
    /// The cancel reason of a bound that has passed (the cost bound first).
    fn passed(&self) -> Option<CancelReason> {
        let now = asupersync::time::wall_now();
        if self.cost.is_some_and(|cost| now >= cost) {
            Some(CancelReason::cost_budget())
        } else if self.deadline.is_some_and(|deadline| now >= deadline) {
            Some(CancelReason::deadline())
        } else {
            None
        }
    }

    /// The wait before the next poll, cut short to end at the nearer bound.
    fn cap(&self, delay: Duration) -> Duration {
        let now = asupersync::time::wall_now();
        [self.deadline, self.cost]
            .into_iter()
            .flatten()
            .map(|bound| Duration::from_nanos(bound.duration_since(now)))
            .fold(delay, Duration::min)
    }
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
    use asupersync::lab::runtime::InvariantViolation;
    use asupersync::lab::{LabConfig, LabRuntime};
    use asupersync::trace::{TraceData, TraceEventKind};
    use asupersync::{Budget, CancelKind, PanicPayload, Time};
    use franken_snowflake_core::outcome::{OutcomeKind, SnowflakeOutcomeExt};
    use franken_snowflake_http::{
        CompressionEvidence, ContentEncoding, SnowflakeAuthTokenType, SnowflakeEndpoint,
        TransportConfig, TransportError, TransportErrorCode,
    };
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, VecDeque};

    const RESP_202: &[u8] = include_bytes!("../tests/fixtures/resp_202_running.json");
    const RESP_200_MULTI: &[u8] =
        include_bytes!("../tests/fixtures/resp_200_resultset_multi_partition.json");
    const RESP_200_SINGLE: &[u8] =
        include_bytes!("../tests/fixtures/resp_200_resultset_single_partition.json");

    /// What the fake answers on each route. `Panicked` is a caught outcome,
    /// not an unwind of the driver future.
    #[derive(Clone)]
    enum Scripted {
        Ok(StatusClass, Vec<u8>),
        Err,
        Panicked(&'static str),
    }

    /// A scripted transport recording every cancel the driver issues.
    struct FakeTransport {
        submit: Scripted,
        /// Consumed by the first submit only (models a 401 on the initial POST).
        submit_first: RefCell<Option<Scripted>>,
        polls: RefCell<Vec<Scripted>>,
        /// The handle of every poll, in order.
        polled: RefCell<Vec<String>>,
        /// Per-partition answer queues (a partition may be scripted more than
        /// once, e.g. `401` then the body).
        partitions: RefCell<BTreeMap<u32, VecDeque<Scripted>>>,
        cancels_after_local: RefCell<Vec<(StatementHandle, CancelKind)>>,
        orphan_cancels: RefCell<Vec<StatementHandle>>,
        orphan_cancel_auth: RefCell<Vec<String>>,
        orphan_cancel_result: Scripted,
        orphan_cleanup_finished: Cell<bool>,
        /// Credential fingerprint attached to every submit/poll/partition, in order.
        auth_seen: RefCell<Vec<String>>,
        /// `("start", p)` when a partition fetch is first polled and `("done", p)`
        /// when it resolves: proves whether fetches overlapped.
        partition_events: RefCell<Vec<(&'static str, u32)>>,
        /// When set, partition fetches and orphan cleanup stay pending for one
        /// poll so that draining and concurrent fetches interleave observably.
        yield_once: Cell<bool>,
        /// Every statement whose driver future was dropped mid-flight.
        dropped_cancels: RefCell<Vec<StatementHandle>>,
    }

    impl FakeTransport {
        fn new(submit: Scripted) -> Self {
            Self {
                submit,
                submit_first: RefCell::new(None),
                polls: RefCell::new(Vec::new()),
                polled: RefCell::new(Vec::new()),
                partitions: RefCell::new(BTreeMap::new()),
                cancels_after_local: RefCell::new(Vec::new()),
                orphan_cancels: RefCell::new(Vec::new()),
                orphan_cancel_auth: RefCell::new(Vec::new()),
                orphan_cancel_result: Scripted::Ok(StatusClass::Completed, Vec::new()),
                orphan_cleanup_finished: Cell::new(false),
                auth_seen: RefCell::new(Vec::new()),
                partition_events: RefCell::new(Vec::new()),
                yield_once: Cell::new(false),
                dropped_cancels: RefCell::new(Vec::new()),
            }
        }

        fn script_partition(&self, partition: u32, scripted: Scripted) {
            self.partitions
                .borrow_mut()
                .entry(partition)
                .or_default()
                .push_back(scripted);
        }

        fn events(&self) -> Vec<String> {
            self.partition_events
                .borrow()
                .iter()
                .map(|(kind, partition)| format!("{kind}{partition}"))
                .collect()
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
                Scripted::Panicked(message) => {
                    TransportOutcome::panicked(PanicPayload::new(message))
                }
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
            self.polled
                .borrow_mut()
                .push(request.statement_handle.as_str().to_owned());
            let next = self.polls.borrow_mut().remove(0);
            match next {
                Scripted::Ok(status, body) => {
                    TransportOutcome::ok(PollHttpResponse { status, body })
                }
                Scripted::Err => TransportOutcome::err(Self::transport_error()),
                Scripted::Panicked(message) => {
                    TransportOutcome::panicked(PanicPayload::new(message))
                }
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
            self.partition_events
                .borrow_mut()
                .push(("start", request.partition));
            if self.yield_once.get() {
                YieldOnce { yielded: false }.await;
            }
            self.partition_events
                .borrow_mut()
                .push(("done", request.partition));
            let next = self
                .partitions
                .borrow_mut()
                .get_mut(&request.partition)
                .and_then(VecDeque::pop_front);
            match next {
                Some(Scripted::Ok(status, body)) => TransportOutcome::ok(PartitionBody {
                    status,
                    compression: CompressionEvidence {
                        content_encoding: ContentEncoding::Identity,
                        compressed_bytes: body.len() as u64,
                        uncompressed_bytes: body.len() as u64,
                    },
                    body,
                }),
                Some(Scripted::Err) | None => TransportOutcome::err(Self::transport_error()),
                Some(Scripted::Panicked(message)) => {
                    TransportOutcome::panicked(PanicPayload::new(message))
                }
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
            auth: AuthorizationDescriptor,
            statement_handle: StatementHandle,
        ) -> TransportOutcome<CancelHttpResponse> {
            self.orphan_cancels.borrow_mut().push(statement_handle);
            self.orphan_cancel_auth
                .borrow_mut()
                .push(auth.redacted_fingerprint().to_owned());
            if self.yield_once.get() {
                YieldOnce { yielded: false }.await;
            }
            self.orphan_cleanup_finished.set(true);
            match &self.orphan_cancel_result {
                Scripted::Ok(status, body) => TransportOutcome::ok(CancelHttpResponse {
                    status: *status,
                    body: body.clone(),
                }),
                Scripted::Err => TransportOutcome::err(Self::transport_error()),
                Scripted::Panicked(message) => {
                    TransportOutcome::panicked(PanicPayload::new(*message))
                }
            }
        }

        fn cancel_on_drop(
            &self,
            _auth: AuthorizationDescriptor,
            statement_handle: StatementHandle,
        ) {
            self.dropped_cancels.borrow_mut().push(statement_handle);
        }
    }

    fn fake_auth() -> AuthorizationDescriptor {
        AuthorizationDescriptor::bearer(
            SnowflakeAuthTokenType::ProgrammaticAccessToken,
            "fake-token",
            "cred_test",
        )
    }

    /// Pending once (self-waking), then ready: lets a fake fetch be observably
    /// "in flight" across one scheduler turn.
    struct YieldOnce {
        yielded: bool,
    }

    impl Future for YieldOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                context.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    /// A completed `200` body with one TEXT column: `inline_rows` rows inline
    /// (`"p0"`) and one extra partition per entry of `partition_rows`.
    fn multi_partition_body(inline_rows: usize, partition_rows: &[usize]) -> Vec<u8> {
        let mut partition_info = vec![serde_json::json!({ "rowCount": inline_rows })];
        partition_info.extend(
            partition_rows
                .iter()
                .map(|rows| serde_json::json!({ "rowCount": rows, "uncompressedSize": 1 })),
        );
        let total: usize = inline_rows + partition_rows.iter().sum::<usize>();
        let body = serde_json::json!({
            "resultSetMetaData": {
                "numRows": total,
                "format": "jsonv2",
                "rowType": [{ "name": "P", "type": "TEXT", "nullable": false }],
                "partitionInfo": partition_info
            },
            "data": (0..inline_rows).map(|_| vec!["p0"]).collect::<Vec<_>>(),
            "code": "090001",
            "statementHandle": "01b2c3d4-0000-0000-0000-000000000002",
            "sqlState": "00000",
            "message": "Statement executed successfully.",
            "createdOn": 1_700_000_000_000_u64
        });
        serde_json::to_vec(&body).unwrap_or_default()
    }

    fn partition_body(partition: u32, rows: usize) -> Scripted {
        let body = serde_json::json!({
            "data": (0..rows).map(|_| vec![format!("p{partition}")]).collect::<Vec<_>>()
        });
        Scripted::Ok(
            StatusClass::Completed,
            serde_json::to_vec(&body).unwrap_or_default(),
        )
    }

    /// Submit completes immediately with `partition_rows.len()` extra partitions,
    /// each scripted with its rows.
    fn windowed_transport(inline_rows: usize, partition_rows: &[usize]) -> FakeTransport {
        let transport = FakeTransport::new(Scripted::Ok(
            StatusClass::Completed,
            multi_partition_body(inline_rows, partition_rows),
        ));
        for (offset, rows) in partition_rows.iter().enumerate() {
            let partition = u32::try_from(offset + 1).unwrap_or(u32::MAX);
            transport.script_partition(partition, partition_body(partition, *rows));
        }
        transport
    }

    fn column_values(done: &CompletedStatement) -> Vec<String> {
        done.rows
            .iter()
            .map(|row| row[0].clone().unwrap_or_default())
            .collect()
    }

    fn multi_parent(handles: &[&str]) -> Vec<u8> {
        let body = serde_json::json!({
            "resultSetMetaData": {
                "numRows": 1,
                "format": "jsonv2",
                "rowType": [{ "name": "multiple statement execution", "type": "text", "nullable": false }],
                // Snowflake's reference example lists more partitions than the
                // status row; a parent's partitions are never fetched.
                "partitionInfo": [{ "rowCount": 1 }, { "rowCount": 5 }]
            },
            "data": [["Multiple statements executed successfully."]],
            "code": "090001",
            "statementHandle": "01b2c3d4-0000-0000-0000-0000000000a0",
            "statementHandles": handles,
        });
        serde_json::to_vec(&body).unwrap_or_default()
    }

    fn one_value_result(handle: &str, value: &str) -> Scripted {
        let body = serde_json::json!({
            "resultSetMetaData": {
                "numRows": 1,
                "format": "jsonv2",
                "rowType": [{ "name": "V", "type": "TEXT", "nullable": false }]
            },
            "data": [[value]],
            "code": "090001",
            "statementHandle": handle,
        });
        Scripted::Ok(
            StatusClass::Completed,
            serde_json::to_vec(&body).unwrap_or_default(),
        )
    }

    /// Reality-check bead L1: the parent lists the statement handles; each
    /// statement is fetched by its handle, in order, and assembled on its own.
    #[test]
    fn a_multi_statement_request_fetches_each_statement_by_handle_in_order() {
        asupersync::test_utils::run_test(|| async {
            const FIRST: &str = "01b2c3d4-0000-0000-0000-0000000000a1";
            const SECOND: &str = "01b2c3d4-0000-0000-0000-0000000000a2";
            let transport = FakeTransport::new(Scripted::Ok(
                StatusClass::Completed,
                multi_parent(&[FIRST, SECOND]),
            ));
            *transport.polls.borrow_mut() = vec![
                one_value_result(FIRST, "first"),
                one_value_result(SECOND, "second"),
            ];
            let cx = Cx::for_testing();
            let (outcome, stats) = run_multi_statement_hooked(
                &cx,
                &transport,
                &mut fake_auth(),
                SubmitStatementRequest::new("select 'first'; select 'second'"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
                None,
            )
            .await;
            let result = match outcome {
                SnowflakeOutcome::Ok(result) => result,
                other => panic!("expected both statements, got {other:?}"),
            };
            let values: Vec<Vec<String>> = result.statements.iter().map(column_values).collect();
            assert_eq!(values, [["first"], ["second"]]);
            assert_eq!(
                result.parent.rows,
                [[Some(
                    "Multiple statements executed successfully.".to_owned()
                )]]
            );
            assert_eq!(transport.polled.borrow().as_slice(), [FIRST, SECOND]);
            assert_eq!(stats.polls, 2);
            // The parent's listed partitions were not fetched.
            assert!(transport.events().is_empty(), "{:?}", transport.events());
            assert!(transport.orphan_cancels.borrow().is_empty());
        });
    }

    #[test]
    fn a_multi_statement_parent_without_handles_is_an_upstream_error() {
        asupersync::test_utils::run_test(|| async {
            let transport = FakeTransport::new(Scripted::Ok(
                StatusClass::Completed,
                RESP_200_SINGLE.to_vec(),
            ));
            let cx = Cx::for_testing();
            let (outcome, _) = run_multi_statement_hooked(
                &cx,
                &transport,
                &mut fake_auth(),
                SubmitStatementRequest::new("select 1; select 2"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
                None,
            )
            .await;
            let error = match outcome {
                SnowflakeOutcome::Err(error) => error,
                other => panic!("expected an error, got {other:?}"),
            };
            assert_eq!(error.code, SnowflakeErrorCode::UpstreamError);
            assert!(transport.polled.borrow().is_empty());
        });
    }

    #[test]
    fn a_failing_statement_fails_the_multi_statement_request_before_any_fetch() {
        asupersync::test_utils::run_test(|| async {
            let failure = serde_json::json!({
                "code": "100132",
                "sqlState": "P0000",
                "message": "JavaScript execution error: Uncaught Execution of multiple statements failed on statement \"select * from missing_table\"",
                "statementHandle": "01b2c3d4-0000-0000-0000-0000000000a0",
            });
            let transport = FakeTransport::new(Scripted::Ok(
                StatusClass::QueryFailure,
                serde_json::to_vec(&failure).unwrap_or_default(),
            ));
            let cx = Cx::for_testing();
            let (outcome, _) = run_multi_statement_hooked(
                &cx,
                &transport,
                &mut fake_auth(),
                SubmitStatementRequest::new("select 1; select * from missing_table"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
                None,
            )
            .await;
            let error = match outcome {
                SnowflakeOutcome::Err(error) => error,
                other => panic!("expected the statement failure, got {other:?}"),
            };
            assert_eq!(error.code, SnowflakeErrorCode::StatementFailed);
            assert!(error.message.contains("missing_table"), "{}", error.message);
            assert!(transport.polled.borrow().is_empty());
        });
    }

    #[test]
    fn window_fetches_partitions_concurrently_and_assembles_in_order() {
        asupersync::test_utils::run_test(|| async {
            let transport = windowed_transport(1, &[1, 1, 1, 1, 1]);
            transport.yield_once.set(true);
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5).with_partition_concurrency(3),
            )
            .await;
            let done = match outcome {
                SnowflakeOutcome::Ok(done) => done,
                other => {
                    assert!(
                        matches!(other, SnowflakeOutcome::Ok(_)),
                        "expected completion, got {other:?}"
                    );
                    return;
                }
            };
            assert_eq!(
                column_values(&done),
                vec!["p0", "p1", "p2", "p3", "p4", "p5"]
            );
            assert_eq!(done.fetched_partitions, 6);
            assert_eq!(done.total_partitions, 6);
            assert!(!done.is_partial());
            assert_eq!(stats.partitions_fetched, 5);
            // Window [1,2,3] was fully in flight before any of it resolved, then
            // window [4,5] likewise.
            assert_eq!(
                transport.events(),
                vec![
                    "start1", "start2", "start3", "done1", "done2", "done3", "start4", "start5",
                    "done4", "done5"
                ]
            );
        });
    }

    #[test]
    fn partition_concurrency_one_is_strictly_sequential() {
        asupersync::test_utils::run_test(|| async {
            let transport = windowed_transport(1, &[1, 1, 1]);
            transport.yield_once.set(true);
            let cx = Cx::for_testing();
            let (outcome, _) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5).with_partition_concurrency(1),
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Ok(_)), "{outcome:?}");
            assert_eq!(
                transport.events(),
                vec!["start1", "done1", "start2", "done2", "start3", "done3"]
            );
        });
    }

    #[test]
    fn row_cap_stops_fetching_early_and_reports_a_partial_prefix() {
        asupersync::test_utils::run_test(|| async {
            // 1 inline row + 5 partitions of 1 row; the caller wants 3 rows.
            let transport = windowed_transport(1, &[1, 1, 1, 1, 1]);
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5)
                    .with_partition_concurrency(1)
                    .with_row_cap(Some(3)),
            )
            .await;
            let done = match outcome {
                SnowflakeOutcome::Ok(done) => done,
                other => {
                    assert!(
                        matches!(other, SnowflakeOutcome::Ok(_)),
                        "expected completion, got {other:?}"
                    );
                    return;
                }
            };
            assert_eq!(column_values(&done), vec!["p0", "p1", "p2"]);
            assert!(done.is_partial());
            assert_eq!(done.fetched_partitions, 3);
            assert_eq!(done.total_partitions, 6);
            assert_eq!(done.result_set.result_set_meta_data.num_rows, 6);
            assert_eq!(
                stats.partitions_fetched, 2,
                "partitions 3..5 were never fetched"
            );
            assert_eq!(
                transport.events(),
                vec!["start1", "done1", "start2", "done2"]
            );
            assert!(transport.orphan_cancels.borrow().is_empty());
        });
    }

    #[test]
    fn row_cap_with_a_window_stops_after_the_window_that_crossed_it() {
        asupersync::test_utils::run_test(|| async {
            let transport = windowed_transport(1, &[1, 1, 1, 1, 1]);
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5)
                    .with_partition_concurrency(3)
                    .with_row_cap(Some(3)),
            )
            .await;
            let done = match outcome {
                SnowflakeOutcome::Ok(done) => done,
                other => {
                    assert!(
                        matches!(other, SnowflakeOutcome::Ok(_)),
                        "expected completion, got {other:?}"
                    );
                    return;
                }
            };
            assert_eq!(column_values(&done), vec!["p0", "p1", "p2", "p3"]);
            assert!(done.is_partial());
            assert_eq!(done.fetched_partitions, 4);
            assert_eq!(stats.partitions_fetched, 3);
        });
    }

    #[test]
    fn row_cap_never_cuts_a_result_that_fits() {
        asupersync::test_utils::run_test(|| async {
            let transport = windowed_transport(1, &[1, 1]);
            let cx = Cx::for_testing();
            let (outcome, _) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5).with_row_cap(Some(1_000)),
            )
            .await;
            let done = match outcome {
                SnowflakeOutcome::Ok(done) => done,
                other => {
                    assert!(
                        matches!(other, SnowflakeOutcome::Ok(_)),
                        "expected completion, got {other:?}"
                    );
                    return;
                }
            };
            assert!(!done.is_partial());
            assert_eq!(done.rows.len(), 3);
        });
    }

    #[test]
    fn window_401_resigns_once_and_refetches_every_rejected_partition() {
        asupersync::test_utils::run_test(|| async {
            let transport = FakeTransport::new(Scripted::Ok(
                StatusClass::Completed,
                multi_partition_body(1, &[1, 1, 1]),
            ));
            // Partitions 1 and 3 reject the stale bearer once; 2 accepts it.
            transport.script_partition(1, unauthorized());
            transport.script_partition(1, partition_body(1, 1));
            transport.script_partition(2, partition_body(2, 1));
            transport.script_partition(3, unauthorized());
            transport.script_partition(3, partition_body(3, 1));
            let mut auth = FakeAuth::resigning();
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_auth(
                &cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5).with_partition_concurrency(3),
            )
            .await;
            let done = match outcome {
                SnowflakeOutcome::Ok(done) => done,
                other => {
                    assert!(
                        matches!(other, SnowflakeOutcome::Ok(_)),
                        "expected completion, got {other:?}"
                    );
                    return;
                }
            };
            assert_eq!(column_values(&done), vec!["p0", "p1", "p2", "p3"]);
            assert_eq!(
                auth.resigns, 1,
                "one re-sign covers every rejection in the window"
            );
            assert_eq!(
                stats.partitions_fetched, 5,
                "3 window fetches + 2 refetches"
            );
            assert_eq!(
                *transport.auth_seen.borrow(),
                vec![
                    "cred_gen0",
                    "cred_gen0",
                    "cred_gen0",
                    "cred_gen0",
                    "cred_gen1",
                    "cred_gen1"
                ],
                "submit + window used gen0; both refetches used the re-signed gen1"
            );
            assert!(transport.orphan_cancels.borrow().is_empty());
        });
    }

    #[test]
    fn partition_rejected_again_after_the_resign_is_terminal_with_an_orphan_cancel() {
        asupersync::test_utils::run_test(|| async {
            let transport = FakeTransport::new(Scripted::Ok(
                StatusClass::Completed,
                multi_partition_body(1, &[1]),
            ));
            transport.script_partition(1, unauthorized());
            transport.script_partition(1, unauthorized());
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
            let error = match outcome {
                SnowflakeOutcome::Err(error) => error,
                other => {
                    assert!(
                        matches!(other, SnowflakeOutcome::Err(_)),
                        "expected a typed error, got {other:?}"
                    );
                    return;
                }
            };
            assert_eq!(error.code, SnowflakeErrorCode::CredentialExpired);
            assert_eq!(auth.resigns, 1);
            assert_eq!(stats.partitions_fetched, 2);
            assert_eq!(transport.orphan_cancels.borrow().len(), 1);
        });
    }

    #[test]
    fn one_failed_fetch_in_a_window_abandons_the_statement_after_the_window_settles() {
        asupersync::test_utils::run_test(|| async {
            let transport = windowed_transport(1, &[1, 1, 1]);
            transport.yield_once.set(true);
            // Partition 2's scripted body is replaced by a transport error.
            transport
                .partitions
                .borrow_mut()
                .insert(2, VecDeque::from([Scripted::Err]));
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5).with_partition_concurrency(3),
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Err(_)), "{outcome:?}");
            // Every in-flight fetch of the window ran to completion (no abandoned
            // request), then the driver cancelled the orphaned handle once.
            assert_eq!(
                transport.events(),
                vec!["start1", "start2", "start3", "done1", "done2", "done3"]
            );
            assert_eq!(stats.partitions_fetched, 3);
            assert_eq!(transport.orphan_cancels.borrow().len(), 1);
        });
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
            let error = match outcome {
                SnowflakeOutcome::Err(error) => error,
                other => {
                    assert!(
                        matches!(other, SnowflakeOutcome::Err(_)),
                        "expected a typed error, got {other:?}"
                    );
                    return;
                }
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
            let error = match outcome {
                SnowflakeOutcome::Err(error) => error,
                other => {
                    assert!(
                        matches!(other, SnowflakeOutcome::Err(_)),
                        "expected a typed error, got {other:?}"
                    );
                    return;
                }
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
            let error = match outcome {
                SnowflakeOutcome::Err(error) => error,
                other => {
                    assert!(
                        matches!(other, SnowflakeOutcome::Err(_)),
                        "expected a typed error, got {other:?}"
                    );
                    return;
                }
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
            let multi: serde_json::Value =
                serde_json::from_slice(RESP_200_MULTI).unwrap_or_default();
            let partitions = multi["resultSetMetaData"]["partitionInfo"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let partition_count = partitions.len();
            // First non-inline partition answers 401 once, then every partition
            // is served in the live object form with the promised rowCount.
            transport.script_partition(1, unauthorized());
            for (index, info) in partitions.iter().enumerate().skip(1) {
                let rows = info["rowCount"].as_u64().unwrap_or(0);
                let body = format!(
                    r#"{{"data":[{}]}}"#,
                    (0..rows)
                        .map(|_| r#"["2024-01-02","ENTITY","2.50"]"#)
                        .collect::<Vec<_>>()
                        .join(",")
                );
                transport.script_partition(
                    u32::try_from(index).unwrap_or(u32::MAX),
                    Scripted::Ok(StatusClass::Completed, body.into_bytes()),
                );
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
            ..PollPlan::default()
        }
    }

    fn fixture_handle() -> StatementHandle {
        StatementHandle::new("01b2c3d4-0000-0000-0000-000000000002")
    }

    #[test]
    fn submit_panic_without_a_handle_does_not_attempt_cleanup() {
        asupersync::test_utils::run_test(|| async {
            let transport = FakeTransport::new(Scripted::Panicked("submit panic"));
            let cx = Cx::current().unwrap_or_else(Cx::for_testing);
            let (outcome, stats) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
            )
            .await;
            let payload = match outcome {
                SnowflakeOutcome::Panicked(payload) => payload,
                other => {
                    assert!(
                        matches!(other, SnowflakeOutcome::Panicked(_)),
                        "expected the submit panic, got {other:?}"
                    );
                    return;
                }
            };
            assert_eq!(payload.message(), "submit panic");
            // No effort recorded; the stats still name the plan's bound.
            assert_eq!((stats.polls, stats.partitions_fetched), (0, 0));
            assert_eq!(stats.poll_quota, 5);
            assert!(transport.orphan_cancels.borrow().is_empty());
            assert!(transport.cancels_after_local.borrow().is_empty());
            assert!(!transport.orphan_cleanup_finished.get());
        });
    }

    #[test]
    fn poll_panic_awaits_cleanup_and_preserves_the_original_payload() {
        asupersync::test_utils::run_test(|| async {
            for cleanup in [
                Scripted::Ok(StatusClass::Completed, Vec::new()),
                Scripted::Err,
                Scripted::Panicked("secondary cleanup panic"),
            ] {
                let mut transport =
                    FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
                transport.orphan_cancel_result = cleanup;
                transport.yield_once.set(true);
                transport
                    .polls
                    .borrow_mut()
                    .push(Scripted::Panicked("poll panic"));
                let cx = Cx::current().unwrap_or_else(Cx::for_testing);
                let (outcome, stats) = run_statement_with_stats(
                    &cx,
                    &transport,
                    fake_auth(),
                    SubmitStatementRequest::new("select 1"),
                    SubmitQueryParams::default(),
                    fast_poll_plan(5),
                )
                .await;
                let payload = match outcome {
                    SnowflakeOutcome::Panicked(payload) => payload,
                    other => {
                        assert!(
                            matches!(other, SnowflakeOutcome::Panicked(_)),
                            "expected the original poll panic, got {other:?}"
                        );
                        continue;
                    }
                };
                assert_eq!(payload.message(), "poll panic");
                assert_eq!(stats.polls, 1);
                assert_eq!(
                    transport.orphan_cancels.borrow().as_slice(),
                    &[fixture_handle()]
                );
                assert_eq!(
                    transport.orphan_cancel_auth.borrow().as_slice(),
                    &["cred_test"]
                );
                assert!(transport.orphan_cleanup_finished.get());
                assert!(transport.cancels_after_local.borrow().is_empty());
            }
        });
    }

    #[test]
    fn partition_panic_drains_the_window_and_yielding_cleanup_before_returning() {
        let transport = windowed_transport(1, &[1, 1, 1]);
        transport.yield_once.set(true);
        transport
            .partitions
            .borrow_mut()
            .insert(2, VecDeque::from([Scripted::Panicked("partition panic")]));
        let cx = Cx::for_testing();
        let mut driver = std::pin::pin!(run_statement_with_stats(
            &cx,
            &transport,
            fake_auth(),
            SubmitStatementRequest::new("select 1"),
            SubmitQueryParams::default(),
            fast_poll_plan(5).with_partition_concurrency(3),
        ));
        let mut context = Context::from_waker(std::task::Waker::noop());

        assert!(driver.as_mut().poll(&mut context).is_pending());
        assert_eq!(transport.events(), vec!["start1", "start2", "start3"]);
        assert!(transport.orphan_cancels.borrow().is_empty());

        // The failed partition does not abandon its sibling. Cleanup starts
        // only after all three fetches settle, and itself needs another poll.
        assert!(driver.as_mut().poll(&mut context).is_pending());
        assert_eq!(
            transport.events(),
            vec!["start1", "start2", "start3", "done1", "done2", "done3"]
        );
        assert_eq!(
            transport.orphan_cancels.borrow().as_slice(),
            &[fixture_handle()]
        );
        assert!(!transport.orphan_cleanup_finished.get());

        let poll_result = driver.as_mut().poll(&mut context);
        assert!(
            matches!(poll_result, Poll::Ready(_)),
            "driver did not return after cleanup completed"
        );
        let (outcome, stats) = match poll_result {
            Poll::Ready(ready) => ready,
            Poll::Pending => return,
        };
        let payload = match outcome {
            SnowflakeOutcome::Panicked(payload) => payload,
            other => {
                assert!(
                    matches!(other, SnowflakeOutcome::Panicked(_)),
                    "expected the partition panic, got {other:?}"
                );
                return;
            }
        };
        assert_eq!(payload.message(), "partition panic");
        assert_eq!(stats.partitions_fetched, 3);
        assert_eq!(transport.orphan_cancels.borrow().len(), 1);
        assert!(transport.orphan_cleanup_finished.get());
        assert!(transport.cancels_after_local.borrow().is_empty());
    }

    #[test]
    fn partition_retry_panic_cleans_up_with_the_refreshed_credential() {
        asupersync::test_utils::run_test(|| async {
            let transport = FakeTransport::new(Scripted::Ok(
                StatusClass::Completed,
                multi_partition_body(1, &[1]),
            ));
            transport.yield_once.set(true);
            transport.script_partition(1, unauthorized());
            transport.script_partition(1, Scripted::Panicked("retry panic"));
            let mut auth = FakeAuth::resigning();
            let cx = Cx::current().unwrap_or_else(Cx::for_testing);
            let (outcome, stats) = run_statement_with_auth(
                &cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
            )
            .await;
            let payload = match outcome {
                SnowflakeOutcome::Panicked(payload) => payload,
                other => {
                    assert!(
                        matches!(other, SnowflakeOutcome::Panicked(_)),
                        "expected the retry panic, got {other:?}"
                    );
                    return;
                }
            };
            assert_eq!(payload.message(), "retry panic");
            assert_eq!(stats.partitions_fetched, 2);
            assert_eq!(auth.resigns, 1);
            assert_eq!(
                transport.orphan_cancels.borrow().as_slice(),
                &[fixture_handle()]
            );
            assert_eq!(
                transport.orphan_cancel_auth.borrow().as_slice(),
                &["cred_gen1"]
            );
            assert!(transport.orphan_cleanup_finished.get());
            assert!(transport.cancels_after_local.borrow().is_empty());
        });
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

    /// Collects what a streaming run hands over, batch by batch.
    struct CollectingSink {
        batches: Vec<Vec<Vec<Option<String>>>>,
        refuse: bool,
    }

    impl RowSink for CollectingSink {
        fn accept(
            &mut self,
            _result_set: &ResultSet,
            rows: Vec<Vec<Option<String>>>,
        ) -> Result<(), SnowflakeError> {
            if self.refuse {
                return Err(SnowflakeError::new(
                    SnowflakeErrorCode::UsageError,
                    "the sink refused the rows",
                ));
            }
            self.batches.push(rows);
            Ok(())
        }
    }

    fn streaming_transport() -> FakeTransport {
        let transport = FakeTransport::new(Scripted::Ok(
            StatusClass::Completed,
            RESP_200_MULTI.to_vec(),
        ));
        transport.script_partition(
            1,
            Scripted::Ok(
                StatusClass::Completed,
                br#"{"data":[["p1a","x"],["p1b","x"]]}"#.to_vec(),
            ),
        );
        transport.script_partition(
            2,
            Scripted::Ok(
                StatusClass::Completed,
                br#"{"data":[["p2a","x"]]}"#.to_vec(),
            ),
        );
        transport
    }

    /// Reality-check bead E5: rows reach the sink in partition order, one
    /// window at a time (never the whole result), and the completed statement
    /// keeps only metadata.
    #[test]
    fn streaming_hands_rows_to_the_sink_one_window_at_a_time() {
        asupersync::test_utils::run_test(|| async {
            let transport = streaming_transport();
            let mut sink = CollectingSink {
                batches: Vec::new(),
                refuse: false,
            };
            let mut auth = fake_auth();
            let cx = Cx::for_testing();
            let (outcome, _) = run_statement_streaming(
                &cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5).with_partition_concurrency(1),
                &mut sink,
            )
            .await;
            let SnowflakeOutcome::Ok(done) = outcome else {
                panic!("streaming run failed: {outcome:?}");
            };
            assert!(done.rows.is_empty(), "every row went to the sink");
            assert_eq!(done.fetched_partitions, 3);
            let firsts: Vec<String> = sink
                .batches
                .iter()
                .flatten()
                .map(|row| row.first().cloned().flatten().unwrap_or_default())
                .collect();
            assert_eq!(firsts.len(), 5, "inline 2 + 2 + 1");
            assert_eq!(&firsts[2..], ["p1a", "p1b", "p2a"]);
            assert_eq!(
                sink.batches.len(),
                3,
                "one batch per partition with window 1"
            );
            assert!(
                sink.batches.iter().all(|batch| batch.len() <= 2),
                "no batch holds more than one partition"
            );
            assert!(transport.orphan_cancels.borrow().is_empty());
        });
    }

    /// Collects progress events.
    #[derive(Default)]
    struct CollectingObserver(Vec<DriverEvent>);

    /// Bead o2o: over a `Sync` transport (the production client here) and with
    /// both hooks set, the driver future is `Send`, so a statement can be
    /// driven from a spawned task, as the lab runtime's DPOR explorer does.
    /// A `RefCell` or a non-`Send` trait object held across an await in the
    /// driver would fail to compile here.
    #[test]
    fn the_driver_future_is_send_over_the_production_client() {
        fn assert_send<F: Future + Send>(_: &F) {}
        let endpoint = SnowflakeEndpoint::parse("https://xy12345.us-east-1.snowflakecomputing.com")
            .expect("a valid account endpoint");
        let client = SnowflakeHttpClient::for_runtime(TransportConfig::new(endpoint))
            .expect("the native-roots client builds");
        let cx = Cx::for_testing();
        let mut auth = fake_auth();
        let mut sink = CollectingSink {
            batches: Vec::new(),
            refuse: false,
        };
        let mut observer = CollectingObserver::default();
        let single = run_statement_hooked(
            &cx,
            &client,
            &mut auth,
            SubmitStatementRequest::new("select 1"),
            SubmitQueryParams::default(),
            PollPlan::default(),
            StatementHooks {
                sink: Some(&mut sink),
                observer: Some(&mut observer),
            },
        );
        assert_send(&single);
        drop(single);
        let multi = run_multi_statement_hooked(
            &cx,
            &client,
            &mut auth,
            SubmitStatementRequest::new("select 1; select 2"),
            SubmitQueryParams::default(),
            PollPlan::default(),
            Some(&mut observer),
        );
        assert_send(&multi);
    }

    impl DriverObserver for CollectingObserver {
        fn event(&mut self, event: DriverEvent) {
            self.0.push(event);
        }
    }

    /// Reality-check bead E1: every remote cancel reaches the observer with
    /// Snowflake's answer, acknowledged or not; a clean run sends none.
    #[test]
    fn the_observer_sees_each_remote_cancel_and_its_answer() {
        asupersync::test_utils::run_test(|| async {
            let run = |transport: FakeTransport| async move {
                let mut observer = CollectingObserver::default();
                let mut auth = fake_auth();
                let cx = Cx::for_testing();
                let hooks = StatementHooks {
                    sink: None,
                    observer: Some(&mut observer),
                };
                let (outcome, _) = run_statement_hooked(
                    &cx,
                    &transport,
                    &mut auth,
                    SubmitStatementRequest::new("select 1"),
                    SubmitQueryParams::default(),
                    fast_poll_plan(5),
                    hooks,
                )
                .await;
                (outcome, observer.0)
            };
            let cancels = |events: &[DriverEvent]| {
                events
                    .iter()
                    .filter_map(|event| match event {
                        DriverEvent::RemoteCancel {
                            statement_handle,
                            acknowledged,
                            detail,
                        } => Some((statement_handle.clone(), *acknowledged, detail.clone())),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            };

            // A poll error after the handle exists: the orphan cancel is
            // answered 200.
            let acknowledged =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            acknowledged.polls.borrow_mut().push(Scripted::Err);
            let (outcome, events) = run(acknowledged).await;
            assert!(matches!(outcome, SnowflakeOutcome::Err(_)), "{outcome:?}");
            assert_eq!(
                cancels(&events),
                vec![(
                    fixture_handle().as_str().to_owned(),
                    true,
                    "completed".to_owned()
                )],
                "{events:?}"
            );

            // The same, but the cancel itself fails: recorded, not hidden.
            let mut refused =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            refused.polls.borrow_mut().push(Scripted::Err);
            refused.orphan_cancel_result = Scripted::Err;
            let (_, events) = run(refused).await;
            let recorded = cancels(&events);
            assert_eq!(recorded.len(), 1, "{events:?}");
            assert!(!recorded[0].1, "{recorded:?}");

            // Negative: a completed statement sends no cancel.
            let (outcome, events) = run(streaming_transport()).await;
            assert!(matches!(outcome, SnowflakeOutcome::Ok(_)), "{outcome:?}");
            assert!(cancels(&events).is_empty(), "{events:?}");
        });
    }

    /// Reality-check bead E5: the observer sees the submit, each fetched
    /// partition (rows from the validated metadata, decoded bytes) and the
    /// completion, in order.
    #[test]
    fn the_observer_sees_submit_partitions_and_completion() {
        asupersync::test_utils::run_test(|| async {
            let transport = streaming_transport();
            let mut observer = CollectingObserver::default();
            let mut auth = fake_auth();
            let cx = Cx::for_testing();
            let hooks = StatementHooks {
                sink: None,
                observer: Some(&mut observer),
            };
            let (outcome, _) = run_statement_hooked(
                &cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5).with_partition_concurrency(1),
                hooks,
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Ok(_)), "{outcome:?}");
            let events = observer.0;
            assert!(
                matches!(
                    &events[0],
                    DriverEvent::Submitted {
                        running: false,
                        statement_handle: Some(_)
                    }
                ),
                "{events:?}"
            );
            assert_eq!(
                events[1],
                DriverEvent::PartitionFetched {
                    index: 1,
                    rows: 2,
                    bytes: u64::try_from(br#"{"data":[["p1a","x"],["p1b","x"]]}"#.len())
                        .unwrap_or(0),
                }
            );
            assert!(
                matches!(
                    events[2],
                    DriverEvent::PartitionFetched {
                        index: 2,
                        rows: 1,
                        ..
                    }
                ),
                "{events:?}"
            );
            assert_eq!(
                events[3],
                DriverEvent::Completed {
                    rows: 5,
                    partitions: 3
                }
            );
            assert_eq!(events.len(), 4, "{events:?}");
        });
    }

    /// Negative: a sink that fails stops the fetch and cancels the statement.
    #[test]
    fn a_failing_sink_cancels_the_statement() {
        asupersync::test_utils::run_test(|| async {
            let transport = streaming_transport();
            let mut sink = CollectingSink {
                batches: Vec::new(),
                refuse: true,
            };
            let mut auth = fake_auth();
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_streaming(
                &cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5).with_partition_concurrency(1),
                &mut sink,
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Err(_)), "{outcome:?}");
            assert_eq!(stats.partitions_fetched, 0, "stopped before any fetch");
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
            transport.script_partition(1, Scripted::Err);
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                fast_poll_plan(5).with_partition_concurrency(1),
            )
            .await;
            assert!(matches!(outcome, SnowflakeOutcome::Err(_)));
            assert_eq!(stats.partitions_fetched, 1);
            assert_eq!(transport.orphan_cancels.borrow().len(), 1);
        });
    }

    #[test]
    fn the_execution_timeout_cancels_a_statement_that_keeps_running() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            for _ in 0..200 {
                transport
                    .polls
                    .borrow_mut()
                    .push(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            }
            // No budget on the Cx: only the plan bounds execution. Unenforced,
            // the loop would run into the poll quota instead.
            let cx = Cx::for_testing();
            let (outcome, stats) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                PollPlan {
                    max_polls: 200,
                    poll_interval: Duration::from_millis(5),
                    ..PollPlan::default()
                }
                .with_execution_timeout(Some(Duration::from_millis(40))),
            )
            .await;
            assert!(
                matches!(&outcome, SnowflakeOutcome::Cancelled(reason) if reason.is_kind(CancelKind::Deadline)),
                "{outcome:?}"
            );
            let cancels = transport.cancels_after_local.borrow();
            assert_eq!(cancels.len(), 1);
            assert_eq!(cancels[0].0, fixture_handle());
            assert_eq!(cancels[0].1, CancelKind::Deadline);
            assert!(stats.polls < 200, "{stats:?}");
            // The stats name the bounds the statement ran under.
            assert_eq!(stats.poll_quota, 200);
            assert_eq!(stats.execution_timeout, Some(Duration::from_millis(40)));
        });
    }

    #[test]
    fn dropping_the_driver_mid_poll_cancels_the_statement() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            let cx = Cx::for_testing();
            {
                let mut running = std::pin::pin!(run_statement_with_stats(
                    &cx,
                    &transport,
                    fake_auth(),
                    SubmitStatementRequest::new("select 1"),
                    SubmitQueryParams::default(),
                    PollPlan::default(),
                ));
                // One poll: submitted, now waiting to poll the running statement.
                let first = std::future::poll_fn(|task| {
                    Poll::Ready(running.as_mut().poll(task).is_pending())
                })
                .await;
                assert!(first, "the statement is still running");
                assert!(transport.dropped_cancels.borrow().is_empty());
            } // the driver future is dropped here, mid-flight
            assert_eq!(*transport.dropped_cancels.borrow(), vec![fixture_handle()]);
            assert!(transport.cancels_after_local.borrow().is_empty());
        });
    }

    #[test]
    fn a_statement_driven_to_its_end_is_not_cancelled_on_drop() {
        asupersync::test_utils::run_test(|| async {
            // Completed, failed in a poll, and never accepted: nothing to cancel.
            let completed =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            completed.polls.borrow_mut().push(Scripted::Ok(
                StatusClass::Completed,
                RESP_200_SINGLE.to_vec(),
            ));
            let failed = FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            failed.polls.borrow_mut().push(Scripted::Err);
            let refused = FakeTransport::new(Scripted::Err);
            for transport in [&completed, &failed, &refused] {
                let _ = run_statement_with_stats(
                    &Cx::for_testing(),
                    transport,
                    fake_auth(),
                    SubmitStatementRequest::new("select 1"),
                    SubmitQueryParams::default(),
                    fast_poll_plan(5),
                )
                .await;
                assert!(transport.dropped_cancels.borrow().is_empty());
            }
        });
    }

    /// What the lab runtime saw of one task's statement leases.
    #[derive(Debug)]
    struct LabRun {
        /// The runtime's invariant violations (the obligation-leak oracle
        /// among them).
        violations: Vec<InvariantViolation>,
        /// Leases reserved.
        reserved: usize,
        /// Each resolution in trace order: the event and, for an abort, why.
        resolved: Vec<(TraceEventKind, Option<ObligationAbortReason>)>,
        /// Nothing left to run and no obligation pending.
        quiescent: bool,
        /// Obligations the runtime itself marked leaked.
        leaks: u64,
        /// The run report's oracle failures.
        oracle_failures: Vec<String>,
    }

    /// Run `body` as a scheduled task of a lab runtime that collects obligation
    /// leaks instead of panicking, then return its result and what the runtime
    /// saw. `body` drives the statement future by hand, inside the task, so
    /// the task is the lease's real holder. A pending lease keeps the lab from
    /// quiescing, so the run is bounded. The result travels through a slot:
    /// a task whose own `Cx` was cancelled joins as cancelled.
    fn in_lab_task<R: Send + 'static>(body: impl FnOnce(&Cx) -> R + Send + 'static) -> (R, LabRun) {
        let mut lab = LabRuntime::new(LabConfig::new(0x0045).panic_on_leak(false).max_steps(1_000));
        let root = lab.state.create_root_region(Budget::INFINITE);
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None));
        let filled = std::sync::Arc::clone(&slot);
        let (task, _handle) = lab
            .state
            .create_task(root, Budget::INFINITE, async move {
                let cx = Cx::current().expect("a lab task has a runtime context");
                let result = body(&cx);
                *filled.lock().expect("the slot is not poisoned") = Some(result);
            })
            .expect("the lab admits the task");
        lab.scheduler.lock().schedule(task, 0);
        let report = lab.run_until_quiescent_with_report();
        let quiescent = lab.is_quiescent();
        let result = slot
            .lock()
            .expect("the slot is not poisoned")
            .take()
            .expect("the task ran to its end");
        let violations = lab.check_invariants();
        let mut reserved = 0;
        let mut resolved = Vec::new();
        for event in lab.trace().snapshot() {
            if let TraceData::Obligation {
                kind: ObligationKind::Lease,
                abort_reason,
                ..
            } = event.data
            {
                if event.kind == TraceEventKind::ObligationReserve {
                    reserved += 1;
                } else {
                    resolved.push((event.kind, abort_reason));
                }
            }
        }
        let run = LabRun {
            violations,
            reserved,
            resolved,
            quiescent,
            leaks: lab.state.leak_count(),
            oracle_failures: report
                .oracle_report
                .failures()
                .iter()
                .map(|failure| format!("{}: {:?}", failure.invariant, failure.violation))
                .collect(),
        };
        (result, run)
    }

    /// No leak, nothing pending, and the leases resolved exactly as `resolved`.
    fn assert_resolved(run: &LabRun, resolved: &[(TraceEventKind, Option<ObligationAbortReason>)]) {
        assert!(run.violations.is_empty(), "{run:?}");
        assert!(run.oracle_failures.is_empty(), "{run:?}");
        assert_eq!(run.leaks, 0, "{run:?}");
        assert!(run.quiescent, "{run:?}");
        assert_eq!(run.reserved, resolved.len(), "{run:?}");
        assert_eq!(run.resolved, resolved, "{run:?}");
    }

    /// Poll `future` once, by hand (the driver future is not `Send`, so a lab
    /// task cannot hold it across an await).
    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        future.poll(&mut Context::from_waker(std::task::Waker::noop()))
    }

    /// Cancels the ambient `Cx` as soon as the statement is accepted.
    struct CancelOnSubmit(Cx);

    impl DriverObserver for CancelOnSubmit {
        fn event(&mut self, event: DriverEvent) {
            if matches!(event, DriverEvent::Submitted { running: true, .. }) {
                self.0
                    .cancel_with(CancelKind::User, Some("the caller gave up"));
            }
        }
    }

    /// Bead oj0.45: a running statement is an Asupersync lease its driving task
    /// holds, and the lab runtime sees every one resolved: dropped mid-flight it
    /// is aborted as cancelled while the remote cancel goes out; driven to its
    /// end it is committed; abandoned after a transport error it is aborted as
    /// an error; cancelled locally it is aborted as cancelled. The leak oracle
    /// finds nothing in any of them.
    #[test]
    fn every_statement_lease_is_resolved_under_the_lab_obligation_oracle() {
        use ObligationAbortReason::{Cancel, Error};
        use TraceEventKind::{ObligationAbort, ObligationCommit};
        const FIRST: &str = "01b2c3d4-0000-0000-0000-0000000000a1";
        const SECOND: &str = "01b2c3d4-0000-0000-0000-0000000000a2";

        let (dropped, run) = in_lab_task(|cx| {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            {
                let running = std::pin::pin!(run_statement_with_stats(
                    cx,
                    &transport,
                    fake_auth(),
                    SubmitStatementRequest::new("select 1"),
                    SubmitQueryParams::default(),
                    PollPlan::default(),
                ));
                assert!(poll_once(running).is_pending(), "the statement runs");
            } // dropped here, mid-flight
            transport.dropped_cancels.take()
        });
        assert_eq!(dropped, [fixture_handle()]);
        assert_resolved(&run, &[(ObligationAbort, Some(Cancel))]);

        let (polled, run) = in_lab_task(|cx| {
            let transport = FakeTransport::new(Scripted::Ok(
                StatusClass::Completed,
                multi_parent(&[FIRST, SECOND]),
            ));
            *transport.polls.borrow_mut() = vec![
                one_value_result(FIRST, "first"),
                one_value_result(SECOND, "second"),
            ];
            let mut auth = fake_auth();
            let running = std::pin::pin!(run_multi_statement_hooked(
                cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 'first'; select 'second'"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
                None,
            ));
            let Poll::Ready((outcome, _)) = poll_once(running) else {
                panic!("both statements were already complete");
            };
            assert!(matches!(outcome, SnowflakeOutcome::Ok(_)), "{outcome:?}");
            assert!(transport.dropped_cancels.borrow().is_empty());
            transport.polled.take()
        });
        assert_eq!(polled, [FIRST, SECOND]);
        assert_resolved(&run, &[(ObligationCommit, None), (ObligationCommit, None)]);

        let (abandoned, run) = in_lab_task(|cx| {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Completed, multi_parent(&[FIRST])));
            *transport.polls.borrow_mut() = vec![Scripted::Err];
            let mut auth = fake_auth();
            let running = std::pin::pin!(run_multi_statement_hooked(
                cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 'first'; select 'second'"),
                SubmitQueryParams::default(),
                fast_poll_plan(5),
                None,
            ));
            let Poll::Ready((outcome, _)) = poll_once(running) else {
                panic!("the failed poll ends the request");
            };
            assert!(matches!(outcome, SnowflakeOutcome::Err(_)), "{outcome:?}");
            transport.orphan_cancels.take()
        });
        assert_eq!(abandoned, [StatementHandle::new(FIRST)]);
        assert_resolved(&run, &[(ObligationAbort, Some(Error))]);

        let (cancelled, run) = in_lab_task(|cx| {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            let mut auth = fake_auth();
            let mut observer = CancelOnSubmit(cx.clone());
            let running = std::pin::pin!(run_statement_hooked(
                cx,
                &transport,
                &mut auth,
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                PollPlan::default(),
                StatementHooks {
                    sink: None,
                    observer: Some(&mut observer),
                },
            ));
            let Poll::Ready((outcome, _)) = poll_once(running) else {
                panic!("a cancelled statement ends at its next checkpoint");
            };
            assert!(
                matches!(outcome, SnowflakeOutcome::Cancelled(_)),
                "{outcome:?}"
            );
            transport.cancels_after_local.take()
        });
        assert_eq!(cancelled, [(fixture_handle(), CancelKind::User)]);
        assert_resolved(&run, &[(ObligationAbort, Some(Cancel))]);
    }

    /// The oracle has teeth: a driver future that is never dropped (so its
    /// guard never runs) leaves its statement's lease unresolved when the
    /// holding task ends, and the runtime reports exactly that lease leaked.
    #[test]
    fn a_statement_whose_driver_is_leaked_is_reported_as_a_leaked_lease() {
        let (dropped, run) = in_lab_task(|cx| {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            let mut running = Box::pin(run_statement_with_stats(
                cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                PollPlan::default(),
            ));
            assert!(
                poll_once(running.as_mut()).is_pending(),
                "the statement runs"
            );
            std::mem::forget(running);
            transport.dropped_cancels.take()
        });
        assert!(dropped.is_empty(), "the guard never ran");
        assert_eq!(run.reserved, 1, "{run:?}");
        assert_eq!(
            run.resolved,
            [(TraceEventKind::ObligationLeak, None)],
            "{run:?}"
        );
        assert_eq!(run.leaks, 1, "{run:?}");
        assert_eq!(run.oracle_failures.len(), 1, "{run:?}");
    }

    /// The CLI drives statements from `block_on` on a current-thread runtime,
    /// whose root task holds real leases: a dropped driver resolves its lease,
    /// and a leaked one trips the runtime's production leak response (panic).
    #[test]
    fn the_cli_runtime_flavor_tracks_statement_leases() {
        fn drive(leak: bool) -> Vec<StatementHandle> {
            let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                .build()
                .expect("the runtime starts");
            runtime.block_on(async move {
                let cx = Cx::current().expect("block_on installs a context");
                let transport =
                    FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
                let mut running = Box::pin(run_statement_with_stats(
                    &cx,
                    &transport,
                    fake_auth(),
                    SubmitStatementRequest::new("select 1"),
                    SubmitQueryParams::default(),
                    PollPlan::default(),
                ));
                assert!(
                    poll_once(running.as_mut()).is_pending(),
                    "the statement runs"
                );
                if leak {
                    std::mem::forget(running);
                } else {
                    drop(running);
                }
                transport.dropped_cancels.take()
            })
        }
        assert_eq!(drive(false), [fixture_handle()]);
        let payload = std::panic::catch_unwind(|| drive(true))
            .expect_err("the runtime refuses to retire a task holding a lease");
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        assert!(
            message.starts_with("obligation leak:") && message.contains(" Lease holder="),
            "{message}"
        );
    }

    #[test]
    fn a_credit_cap_cancels_before_the_deadline_with_the_cost_kind() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            for _ in 0..200 {
                transport
                    .polls
                    .borrow_mut()
                    .push(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            }
            // 3.6 credits/hour and a 40-millionth cap: a 40 ms bound, well
            // inside the 10 s deadline.
            let quota = CostQuota {
                microcredits_per_hour: 3_600_000,
                max_microcredits: 40,
                resumes_warehouse: false,
            };
            let (outcome, stats) = run_statement_with_stats(
                &Cx::for_testing(),
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                PollPlan {
                    max_polls: 200,
                    poll_interval: Duration::from_millis(5),
                    ..PollPlan::default()
                }
                .with_execution_timeout(Some(Duration::from_secs(10)))
                .with_cost_quota(Some(quota)),
            )
            .await;
            assert!(
                matches!(&outcome, SnowflakeOutcome::Cancelled(reason) if reason.is_kind(CancelKind::CostBudget)),
                "{outcome:?}"
            );
            let cancels = transport.cancels_after_local.borrow();
            assert_eq!(cancels.len(), 1);
            assert_eq!(cancels[0].1, CancelKind::CostBudget);
            assert_eq!(stats.cost_quota, Some(quota));
            let execution = stats.execution.unwrap_or_default();
            assert!(
                execution >= Duration::from_millis(40) && execution < Duration::from_secs(10),
                "{stats:?}"
            );
        });
    }

    #[test]
    fn a_credit_cap_below_the_resume_minimum_submits_nothing() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            // Resuming an X-Small warehouse bills ~16667 millionths at least.
            let quota = CostQuota {
                microcredits_per_hour: 1_000_000,
                max_microcredits: 1_000,
                resumes_warehouse: true,
            };
            let (outcome, _) = run_statement_with_stats(
                &Cx::for_testing(),
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                PollPlan::default().with_cost_quota(Some(quota)),
            )
            .await;
            assert!(
                matches!(&outcome, SnowflakeOutcome::Err(error) if error.code == SnowflakeErrorCode::SafetyLimitExceeded),
                "{outcome:?}"
            );
            assert!(transport.auth_seen.borrow().is_empty(), "nothing was sent");
            assert!(transport.cancels_after_local.borrow().is_empty());
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
            // The deadline falls after the submit, while the statement is polled
            // (an already expired one submits nothing: see the test below).
            let deadline = asupersync::time::wall_now() + Duration::from_millis(25);
            let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(deadline));
            let (outcome, _) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                PollPlan {
                    max_polls: 50,
                    poll_interval: Duration::from_millis(5),
                    ..PollPlan::default()
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

    /// Bead o2o: the submit runs under the cancellation mask, so the driver
    /// checks first: a caller whose deadline has already passed sends nothing,
    /// and there is nothing to cancel.
    #[test]
    fn an_already_expired_deadline_submits_nothing() {
        asupersync::test_utils::run_test(|| async {
            let transport =
                FakeTransport::new(Scripted::Ok(StatusClass::Running, RESP_202.to_vec()));
            let cx = Cx::for_testing_with_budget(Budget::new().with_deadline(Time::from_millis(1)));
            let (outcome, _) = run_statement_with_stats(
                &cx,
                &transport,
                fake_auth(),
                SubmitStatementRequest::new("select 1"),
                SubmitQueryParams::default(),
                PollPlan::default(),
            )
            .await;
            assert!(
                matches!(&outcome, SnowflakeOutcome::Cancelled(reason) if reason.is_kind(CancelKind::Deadline)),
                "{outcome:?}"
            );
            assert!(
                transport.auth_seen.borrow().is_empty(),
                "no request was sent"
            );
            assert!(transport.cancels_after_local.borrow().is_empty());
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
            let multi: serde_json::Value =
                serde_json::from_slice(RESP_200_MULTI).unwrap_or_default();
            let partitions = multi["resultSetMetaData"]["partitionInfo"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let partition_count = partitions.len();
            // Each fetched partition must carry exactly the rowCount the metadata
            // promised; the machine refuses mismatches (integrity check). Bodies
            // use the live `{"data":[...]}` object form, not the bare array.
            for (index, info) in partitions.iter().enumerate().skip(1) {
                let rows = info["rowCount"].as_u64().unwrap_or(0);
                let body = format!(
                    r#"{{"data":[{}]}}"#,
                    (0..rows)
                        .map(|_| r#"["2024-01-02","ENTITY","2.50"]"#)
                        .collect::<Vec<_>>()
                        .join(",")
                );
                transport.script_partition(
                    u32::try_from(index).unwrap_or(u32::MAX),
                    Scripted::Ok(StatusClass::Completed, body.into_bytes()),
                );
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
