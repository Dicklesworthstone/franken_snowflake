//! No-account golden proofs for the SQL API protocol schemas (Lane 1,
//! `docs/proof_lanes.md`).
//!
//! Each fixture under `tests/fixtures/` is a captured SQL API payload. The
//! round-trip proof parses it into the typed schema and re-serializes it, then
//! compares the result against the fixture under the shared
//! `franken_snowflake_testkit::harness::golden` framework with
//! [`GoldenConfig::strict`] (zero volatile masking). A pass means the schema
//! captures the payload **losslessly** — no field silently dropped, none
//! invented — which is exactly the regression guard a hand-written `assert_eq!`
//! per field would miss. The fixtures double as the goldens, so no separate
//! blessed file (and thus no test execution) is needed to author them.

use std::path::PathBuf;

use franken_snowflake_sqlapi::request::SubmitStatementRequest;
use franken_snowflake_sqlapi::response::{
    QueryFailureStatus, QueryStatus, ResultSet, StatementCancelResponse,
};
use franken_snowflake_testkit::harness::golden::{GoldenConfig, assert_lf_only, compare};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Read a fixture, enforcing the Lane 7 `eol=lf` discipline, returning its text
/// and parsed JSON `Value`.
fn read_fixture(name: &str) -> Result<(String, Value), String> {
    let path = fixtures_dir().join(name);
    let bytes = std::fs::read(&path).map_err(|error| format!("read {name}: {error}"))?;
    assert_lf_only(&bytes).map_err(|violation| format!("{name}: {violation}"))?;
    let text = String::from_utf8(bytes).map_err(|_| format!("{name}: not valid UTF-8"))?;
    let value: Value =
        serde_json::from_str(&text).map_err(|error| format!("{name}: parse JSON: {error}"))?;
    Ok((text, value))
}

/// Parse `name` into `T`, re-serialize, and assert byte-exact structural
/// equality with the fixture. Returns the parsed value for further assertions.
fn assert_roundtrip<T>(name: &str) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    let (text, expected) = read_fixture(name)?;
    let typed: T =
        serde_json::from_str(&text).map_err(|error| format!("{name}: parse typed: {error}"))?;
    let actual =
        serde_json::to_value(&typed).map_err(|error| format!("{name}: re-serialize: {error}"))?;
    compare(&expected, &actual, &GoldenConfig::strict())
        .map_err(|mismatch| format!("{name}: {mismatch}"))?;
    Ok(typed)
}

#[test]
fn request_fixtures_roundtrip() -> Result<(), String> {
    assert_roundtrip::<SubmitStatementRequest>("submit_select_request.json")?;
    let bound = assert_roundtrip::<SubmitStatementRequest>("submit_with_bindings_request.json")?;
    let bindings = bound
        .bindings
        .ok_or("submit_with_bindings: expected bindings")?;
    assert_eq!(bindings.len(), 3);
    let first = bindings.get("1").ok_or("expected binding 1")?;
    assert_eq!(first.value_type, "TEXT");
    assert_eq!(first.value, "ENTITY123");
    Ok(())
}

#[test]
fn response_status_fixtures_roundtrip() -> Result<(), String> {
    assert_roundtrip::<ResultSet>("resp_200_resultset_single_partition.json")?;
    assert_roundtrip::<QueryStatus>("resp_202_running.json")?;
    assert_roundtrip::<QueryFailureStatus>("resp_408_statement_timeout.json")?;
    assert_roundtrip::<QueryFailureStatus>("resp_422_failure.json")?;
    assert_roundtrip::<StatementCancelResponse>("cancel_response.json")?;
    Ok(())
}

#[test]
fn single_partition_result_decodes_metadata_and_null_cell() -> Result<(), String> {
    let result = assert_roundtrip::<ResultSet>("resp_200_resultset_single_partition.json")?;
    assert_eq!(result.total_rows(), 2);
    assert_eq!(result.partition_count(), 1);
    assert!(!result.is_multi_statement());
    assert_eq!(result.result_set_meta_data.row_type.len(), 3);
    // The fixture's second row has a NULL VALUE cell.
    let second_row = result.data.get(1).ok_or("expected a second row")?;
    let value_cell = second_row.get(2).ok_or("expected a VALUE cell")?;
    assert!(value_cell.is_none(), "VALUE cell should decode as SQL NULL");
    Ok(())
}

#[test]
fn multi_partition_total_rows_is_sum_of_partitions() -> Result<(), String> {
    let result = assert_roundtrip::<ResultSet>("resp_200_resultset_multi_partition.json")?;
    assert_eq!(result.partition_count(), 3);
    let sum: i64 = result
        .result_set_meta_data
        .partition_info
        .iter()
        .map(|partition| partition.row_count)
        .sum();
    assert_eq!(sum, result.total_rows());
    assert_eq!(result.total_rows(), 5);
    Ok(())
}

#[test]
fn multi_statement_fan_out_is_detected() -> Result<(), String> {
    let result = assert_roundtrip::<ResultSet>("resp_200_multi_statement.json")?;
    assert!(result.is_multi_statement());
    let handles = result
        .statement_handles
        .ok_or("expected statementHandles fan-out")?;
    assert_eq!(handles.len(), 2);
    Ok(())
}
