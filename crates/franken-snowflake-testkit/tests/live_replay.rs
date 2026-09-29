//! Live wire transcripts replayed through the production driver (bead oj0.21).
//!
//! `fixtures/replay/<scenario>/` holds redacted transcripts that
//! `franken_snowflake_http::capture` wrote during a credentialed run of the CLI
//! against a production account on 2026-09-28 (key-pair JWT; synthetic
//! statements only; host, account, user and warehouse names replaced by
//! placeholders, handles by stable ids). Each scenario replays what Snowflake
//! actually sent through `run_statement`, so a decode or lifecycle regression
//! that document-derived fixtures would hide fails here: the partition bodies
//! are the object form `{"data": [...]}`, gzip-encoded, as the live API sends
//! them.

// Integration-test crate: panicking on an unexpected result IS the failure.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use asupersync::http::{ClientError, Method, Response};
use asupersync::runtime::RuntimeBuilder;
use asupersync::{Cx, Outcome};
use franken_snowflake_core::error::SnowflakeErrorCode;
use franken_snowflake_http::capture::{ReplayHttp, TranscriptBody};
use franken_snowflake_http::{
    AuthorizationDescriptor, RawHttp, SnowflakeAuthTokenType, SnowflakeEndpoint,
    SnowflakeHttpClient, TransportConfig,
};
use franken_snowflake_sqlapi::driver::{StatementOutcome, run_statement};
use franken_snowflake_sqlapi::lifecycle::PollPlan;
use franken_snowflake_sqlapi::request::{SubmitQueryParams, SubmitStatementRequest};

fn scenario(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("replay")
        .join(name)
}

/// The replay transport, shared so the test can ask what the driver left
/// untaken after the client (which owns its transport) is done.
struct Shared(Arc<ReplayHttp>);

impl RawHttp for Shared {
    async fn send(
        &self,
        cx: &Cx,
        method: Method,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        timeout: Option<Duration>,
    ) -> Result<Response, ClientError> {
        self.0.send(cx, method, url, headers, body, timeout).await
    }
}

/// Replay one scenario (the statement and parameters the live run
/// submitted); returns the outcome and how many transcripts went unused.
fn replay(name: &str) -> (StatementOutcome, usize) {
    let http = Arc::new(ReplayHttp::from_dir(&scenario(name)).expect("load transcripts"));
    let submit = http
        .transcripts()
        .iter()
        .find(|transcript| transcript.route == "submit")
        .expect("a submit transcript");
    let TranscriptBody::Json(body) = &submit.request.body else {
        panic!("{name}: the submit body is not JSON");
    };
    let statement = body["statement"].as_str().expect("statement").to_owned();
    let mut request = SubmitStatementRequest::new(statement);
    request.parameters = body["parameters"].as_object().map(|map| {
        map.iter()
            .map(|(key, value)| (key.clone(), value.as_str().unwrap_or_default().to_owned()))
            .collect()
    });
    let endpoint = SnowflakeEndpoint::parse("https://replay-account.snowflakecomputing.com")
        .expect("endpoint");
    let client =
        SnowflakeHttpClient::new(TransportConfig::new(endpoint), Shared(Arc::clone(&http)));
    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    let outcome = runtime.block_on(async {
        let cx = Cx::current().expect("cx");
        run_statement(
            &cx,
            &client,
            AuthorizationDescriptor::bearer(
                SnowflakeAuthTokenType::KeypairJwt,
                "replay-token-not-a-secret",
                "replay",
            ),
            request,
            SubmitQueryParams {
                request_id: Some("00000000-0000-4000-8000-000000000001".to_owned()),
                retry: true,
                asynchronous: false,
                nullable: None,
            },
            PollPlan::with_max_polls(3),
        )
        .await
    });
    (outcome, http.unused())
}

/// A one-row read: the inline partition 0, exactly as the live API framed it.
#[test]
fn a_live_single_row_read_replays() {
    let (outcome, unused) = replay("small_select");
    assert_eq!(unused, 0);
    let Outcome::Ok(done) = outcome else {
        panic!("small_select: {outcome:?}");
    };
    assert_eq!(done.rows, vec![vec![Some("1".to_owned())]]);
    assert_eq!(done.total_partitions, 1);
}

/// Two partitions: 12 288 inline rows, then 712 in a gzip-encoded
/// `{"data": [...]}` body; every row arrives, in order.
#[test]
fn a_live_two_partition_result_replays_in_full() {
    let (outcome, unused) = replay("partitioned_full");
    assert_eq!(
        unused, 0,
        "the submit and the gzip partition were both taken"
    );
    let Outcome::Ok(done) = outcome else {
        panic!("partitioned_full: {outcome:?}");
    };
    assert_eq!(done.total_partitions, 2);
    assert_eq!(done.fetched_partitions, 2);
    assert_eq!(done.rows.len(), 13_000);
    assert_eq!(
        done.rows[12_288],
        vec![Some("12288".to_owned())],
        "the first fetched row"
    );
    assert_eq!(done.rows[12_999], vec![Some("12999".to_owned())]);
}

/// A statement Snowflake rejects: the live 422 becomes a typed failure that
/// carries Snowflake's message.
#[test]
fn a_live_compile_error_replays_as_a_typed_failure() {
    let (outcome, unused) = replay("failed_statement");
    assert_eq!(unused, 0);
    let Outcome::Err(error) = outcome else {
        panic!("failed_statement: {outcome:?}");
    };
    assert_eq!(error.code, SnowflakeErrorCode::StatementFailed, "{error:?}");
    assert!(error.message.contains("does not exist"), "{error:?}");
}

/// A two-statement batch: the parent answers with both child handles (the CLI
/// then fetches each child; the driver's part is the parent).
#[test]
fn a_live_multi_statement_parent_replays() {
    let (outcome, unused) = replay("multi_statement");
    assert_eq!(
        unused, 2,
        "the children are the CLI's to fetch, not the driver's"
    );
    let Outcome::Ok(done) = outcome else {
        panic!("multi_statement: {outcome:?}");
    };
    assert!(done.result_set.is_multi_statement());
    assert_eq!(
        done.result_set.statement_handles.as_ref().map(Vec::len),
        Some(2)
    );
}

/// The live run was cancelled after the submit answered 202; the transcript
/// holds no poll. Replaying it, the driver finds no poll answer, abandons the
/// statement, and still sends the remote cancel the transcript recorded.
#[test]
fn an_abandoned_live_statement_is_still_cancelled_remotely() {
    let (outcome, unused) = replay("cancel_in_flight");
    assert!(
        !matches!(outcome, Outcome::Ok(_)),
        "no poll answer, so no result: {outcome:?}"
    );
    assert_eq!(unused, 0, "the submit and the remote cancel were both sent");
}
