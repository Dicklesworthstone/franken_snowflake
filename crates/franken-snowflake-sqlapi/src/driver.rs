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

use asupersync::Cx;
use franken_snowflake_core::cancel::CancelReason;
use franken_snowflake_core::error::{SnowflakeError, SnowflakeErrorCode};
use franken_snowflake_core::ids::{RequestId, StatementHandle};
use franken_snowflake_core::outcome::SnowflakeOutcome;
use franken_snowflake_http::{
    AuthorizationDescriptor, PartitionHttpRequest, PollHttpRequest, SnowflakeHttpClient,
    StatusClass, SubmitHttpRequest, TransportRoute,
};

use crate::lifecycle::{CompletedStatement, PollPlan, Progress, StatementMachine};
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
                return SnowflakeOutcome::err(SnowflakeError::new(
                    SnowflakeErrorCode::UpstreamError,
                    failure.message,
                ));
            }
            Progress::Failed(failure) => {
                return SnowflakeOutcome::err(SnowflakeError::new(
                    SnowflakeErrorCode::UpstreamError,
                    failure.message,
                ));
            }
            Progress::PollAgain(handle) => {
                if cx.checkpoint().is_err() {
                    return cancel_locally(cx, client, &auth, &handle, local_cancel_reason(cx))
                        .await;
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

/// Pick the submit route: the idempotent resubmit form
/// (`requestId=...&retry=true`) when both are present, else a plain submit.
fn submit_route(params: &SubmitQueryParams) -> TransportRoute {
    match (&params.request_id, params.retry) {
        (Some(request_id), true) => TransportRoute::SubmitRetry {
            request_id: RequestId::new(request_id.clone()),
        },
        _ => TransportRoute::Submit,
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
        assert!(matches!(
            submit_route(&resubmit),
            TransportRoute::SubmitRetry { .. }
        ));

        // retry=true without a requestId cannot use the idempotent contract.
        let no_id = SubmitQueryParams {
            retry: true,
            ..SubmitQueryParams::default()
        };
        assert!(matches!(submit_route(&no_id), TransportRoute::Submit));
    }
}
