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

use std::time::Duration;

use asupersync::Cx;
use franken_snowflake_core::cancel::CancelReason;
use franken_snowflake_core::error::{SnowflakeError, SnowflakeErrorCode};
use franken_snowflake_core::ids::StatementHandle;
use franken_snowflake_core::outcome::SnowflakeOutcome;
use franken_snowflake_core::redact::redact;
use franken_snowflake_http::{
    AuthorizationDescriptor, PartitionHttpRequest, PollHttpRequest, SnowflakeHttpClient,
    StatusClass, SubmitHttpRequest, TransportRoute,
};

use crate::lifecycle::{
    CompletedStatement, MIN_POLL_INTERVAL, PollPlan, Progress, StatementMachine,
};
use crate::request::{SubmitQueryParams, SubmitStatementRequest};
use crate::status::ResponseClass;

/// The driver outcome: a fully-assembled [`CompletedStatement`] or one of the
/// four `SnowflakeOutcome` terminal states.
pub type StatementOutcome = SnowflakeOutcome<CompletedStatement>;

/// Submit a statement and drive it to completion: submit -> poll/await ->
/// partition fetch -> assemble, firing the remote cancel endpoint if the ambient
/// `Cx` is cancelled mid-flight.
///
/// `request` is the SQL API submit body; `params` carries the idempotency
/// `requestId`/`retry` query contract that makes a resubmit safe.
pub async fn run_statement(
    cx: &Cx,
    client: &SnowflakeHttpClient,
    auth: AuthorizationDescriptor,
    request: SubmitStatementRequest,
    params: SubmitQueryParams,
    poll_plan: PollPlan,
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

    let submit = SubmitHttpRequest {
        route: submit_route(&params),
        auth: auth.clone(),
        body,
        retry_resubmit: params.retry,
    };
    let submit_response = match client.submit_statement(cx, submit).await {
        SnowflakeOutcome::Ok(response) => response,
        SnowflakeOutcome::Err(error) => return SnowflakeOutcome::err(error),
        SnowflakeOutcome::Cancelled(reason) => return SnowflakeOutcome::cancelled(reason),
        SnowflakeOutcome::Panicked(payload) => return SnowflakeOutcome::panicked(payload),
    };

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
                    SnowflakeOutcome::Err(error) => return SnowflakeOutcome::err(error),
                    SnowflakeOutcome::Cancelled(reason) => {
                        return cancel_locally(cx, client, &auth, &handle, reason).await;
                    }
                    SnowflakeOutcome::Panicked(payload) => {
                        return SnowflakeOutcome::panicked(payload);
                    }
                };
                progress = match machine.on_poll(response_class(response.status), &response.body) {
                    Ok(progress) => progress,
                    Err(error) => return SnowflakeOutcome::err(error.into_snowflake_error()),
                };
            }
            Progress::FetchPartition { handle, partition } => {
                if cx.checkpoint().is_err() {
                    return cancel_locally(cx, client, &auth, &handle, local_cancel_reason(cx))
                        .await;
                }
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
                    SnowflakeOutcome::Err(error) => return SnowflakeOutcome::err(error),
                    SnowflakeOutcome::Cancelled(reason) => {
                        return cancel_locally(cx, client, &auth, &handle, reason).await;
                    }
                    SnowflakeOutcome::Panicked(payload) => {
                        return SnowflakeOutcome::panicked(payload);
                    }
                };
                // `response.body` is already gzip-decoded by the transport.
                progress = match machine.on_partition(
                    response_class(response.status),
                    partition,
                    &response.body,
                ) {
                    Ok(progress) => progress,
                    Err(error) => return SnowflakeOutcome::err(error.into_snowflake_error()),
                };
            }
        }
    }
}

/// Fire the SQL API cancel endpoint through the transport's masked cleanup path,
/// then report the local outcome as `Cancelled`.
async fn cancel_locally(
    cx: &Cx,
    client: &SnowflakeHttpClient,
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
        StatusClass::Unexpected => ResponseClass::Other(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::QueryFailureStatus;
    use asupersync::{Budget, CancelKind, Time};
    use franken_snowflake_core::outcome::{OutcomeKind, SnowflakeOutcomeExt};

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
