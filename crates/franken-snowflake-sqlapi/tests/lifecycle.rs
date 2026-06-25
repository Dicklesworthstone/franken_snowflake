//! End-to-end lifecycle proofs that drive the pure [`StatementMachine`] against
//! the committed deterministic, no-account `MockSqlApi` (bead
//! `fsnow-statement-lifecycle-ofl`).
//!
//! These exercise the same submit -> poll -> partition-fetch progression the
//! async [`franken_snowflake_sqlapi::driver`] performs against the live
//! transport, but synchronously and without a runtime: the mock is a pure
//! request -> response state machine, so the whole flow is deterministic. Gzip
//! decoding is the transport's job (proven in `franken-snowflake-http`), so the
//! machine here is fed already-decoded partition bytes.

use franken_snowflake_sqlapi::lifecycle::{
    CompletedStatement, PollPlan, Progress, StatementMachine,
};
use franken_snowflake_sqlapi::status::ResponseClass;
use franken_snowflake_testkit::mock::http::{MockHttpRequest, MockHttpResponse};
use franken_snowflake_testkit::mock::scenarios;
use franken_snowflake_testkit::mock::server::MockSqlApi;

/// Drive a statement to completion against `mock`, mirroring the async driver's
/// loop: submit, then poll / fetch-partition as the machine directs.
fn drive(
    mock: &mut MockSqlApi,
    machine: &mut StatementMachine,
    submit_path: &str,
) -> Result<CompletedStatement, String> {
    let submit = mock.respond(&MockHttpRequest::post(
        submit_path,
        scenarios::SUBMIT_SELECT_REQUEST.to_vec(),
    ));
    let mut progress = machine
        .on_submit(ResponseClass::from_status(submit.status), &submit.body)
        .map_err(|error| error.to_string())?;

    for _ in 0..64 {
        match progress {
            Progress::Complete(done) => return Ok(done),
            Progress::PollAgain(handle) => {
                let path = format!("/api/v2/statements/{}", handle.as_str());
                let poll = mock.respond(&MockHttpRequest::get(path.as_str()));
                progress = machine
                    .on_poll(ResponseClass::from_status(poll.status), &poll.body)
                    .map_err(|error| error.to_string())?;
            }
            Progress::FetchPartition { handle, partition } => {
                let path = format!(
                    "/api/v2/statements/{}?partition={partition}",
                    handle.as_str()
                );
                let fetch = mock.respond(&MockHttpRequest::get(path.as_str()));
                progress = machine
                    .on_partition(
                        ResponseClass::from_status(fetch.status),
                        partition,
                        &fetch.body,
                    )
                    .map_err(|error| error.to_string())?;
            }
            Progress::TimedOut(_) => return Err("unexpected statement timeout".to_owned()),
            Progress::Failed(_) => return Err("unexpected statement failure".to_owned()),
        }
    }
    Err("lifecycle did not converge within the poll bound".to_owned())
}

#[test]
fn async_submit_poll_then_complete() -> Result<(), String> {
    // default_async_lifecycle: 202 handle, two 202 polls, then a 200 single
    // partition.
    let mut mock = scenarios::default_async_lifecycle();
    let handle = mock.statement_handle().to_owned();
    let mut machine = StatementMachine::new(PollPlan::default());

    let done = drive(&mut mock, &mut machine, "/api/v2/statements?async=true")?;

    // The single-partition fixture carries two rows (one with a NULL cell).
    assert_eq!(done.rows.len(), 2);
    // Two 202s plus the completing 200 == three poll GETs.
    assert_eq!(mock.poll_count(&handle), 3);
    Ok(())
}

#[test]
fn immediate_submit_fetches_and_assembles_all_partitions() -> Result<(), String> {
    // A synchronous (immediate) submit returning a 3-partition, 5-row result:
    // 2 rows inline + partition 1 (2 rows) + partition 2 (1 row).
    let handle = "01b2c3d4-0000-0000-0000-000000000010";
    let mut mock = MockSqlApi::new(
        handle,
        scenarios::running(),
        scenarios::ok_multi_partition(),
        scenarios::cancel(),
    )
    .immediate()
    .with_partition(
        1,
        MockHttpResponse::json(
            200,
            br#"[["18264","ENTITY125"],["18265","ENTITY126"]]"#.to_vec(),
        ),
    )
    .with_partition(
        2,
        MockHttpResponse::json(200, br#"[["18266","ENTITY127"]]"#.to_vec()),
    );
    let mut machine = StatementMachine::new(PollPlan::default());

    let done = drive(&mut mock, &mut machine, "/api/v2/statements")?;

    assert_eq!(done.rows.len(), 5);
    assert_eq!(done.statement_handle.as_str(), handle);
    // Last assembled row is the single row from partition 2.
    assert_eq!(
        done.rows[4],
        vec![Some("18266".to_owned()), Some("ENTITY127".to_owned())]
    );
    Ok(())
}

#[test]
fn gzip_partition_fixture_is_assembled_after_transport_decode() -> Result<(), String> {
    // The SQL API machine consumes decoded partition bytes. This test ties that
    // contract to the deterministic testkit gzip packet: the mock serves a
    // gzip-tagged partition 1 response, and we feed the machine the transport's
    // expected decoded bytes before continuing to partition 2.
    let handle = "01b2c3d4-0000-0000-0000-000000000010";
    let mut mock = MockSqlApi::new(
        handle,
        scenarios::running(),
        scenarios::ok_multi_partition(),
        scenarios::cancel(),
    )
    .immediate()
    .with_partition(1, scenarios::gzip_partition())
    .with_partition(
        2,
        MockHttpResponse::json(200, br#"[["5","epsilon"]]"#.to_vec()),
    );
    let mut machine = StatementMachine::new(PollPlan::default());

    let submit = mock.respond(&MockHttpRequest::post(
        "/api/v2/statements",
        scenarios::SUBMIT_SELECT_REQUEST.to_vec(),
    ));
    let Progress::FetchPartition {
        handle: first_handle,
        partition: 1,
    } = machine
        .on_submit(ResponseClass::from_status(submit.status), &submit.body)
        .map_err(|error| error.to_string())?
    else {
        return Err("expected first partition fetch after submit".to_owned());
    };

    let first_path = format!("/api/v2/statements/{}?partition=1", first_handle.as_str());
    let first = mock.respond(&MockHttpRequest::get(first_path.as_str()));
    assert_eq!(first.status, 200);
    assert!(first.has_header("Content-Encoding"));
    assert_ne!(first.body.as_slice(), scenarios::PARTITION_1_PLAIN);

    let Progress::FetchPartition {
        handle: second_handle,
        partition: 2,
    } = machine
        .on_partition(
            ResponseClass::from_status(first.status),
            1,
            scenarios::PARTITION_1_PLAIN,
        )
        .map_err(|error| error.to_string())?
    else {
        return Err("expected second partition fetch after decoded gzip partition".to_owned());
    };

    let second_path = format!("/api/v2/statements/{}?partition=2", second_handle.as_str());
    let second = mock.respond(&MockHttpRequest::get(second_path.as_str()));
    let Progress::Complete(done) = machine
        .on_partition(ResponseClass::from_status(second.status), 2, &second.body)
        .map_err(|error| error.to_string())?
    else {
        return Err("expected completion after final partition".to_owned());
    };

    assert_eq!(done.rows.len(), 5);
    assert_eq!(
        done.rows[2],
        vec![Some("3".to_owned()), Some("gamma".to_owned())]
    );
    assert_eq!(
        done.rows[3],
        vec![Some("4".to_owned()), Some("delta".to_owned())]
    );
    assert_eq!(
        done.rows[4],
        vec![Some("5".to_owned()), Some("epsilon".to_owned())]
    );
    Ok(())
}

#[test]
fn cancel_endpoint_is_acknowledged_and_recorded() -> Result<(), String> {
    // The driver's cancel_locally issues exactly this POST on local cancellation;
    // the mock acknowledges it and records the handle as cancelled.
    let mut mock = scenarios::default_async_lifecycle();
    let handle = mock.statement_handle().to_owned();

    let cancel = mock.respond(&MockHttpRequest::post(
        format!("/api/v2/statements/{handle}/cancel").as_str(),
        Vec::new(),
    ));

    assert_eq!(cancel.status, 200);
    assert!(mock.is_cancelled(&handle));
    Ok(())
}
