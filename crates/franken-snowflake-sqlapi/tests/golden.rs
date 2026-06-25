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
use franken_snowflake_sqlapi::wire::{CellValue, decode_cell};
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

#[test]
fn jsonv2_codec_cells_fixture_pins_documented_wire_shape() -> Result<(), String> {
    let source_note = fixtures_dir().join("jsonv2_codec_cells.source.md");
    let source_bytes =
        std::fs::read(&source_note).map_err(|error| format!("read jsonv2 source note: {error}"))?;
    assert_lf_only(&source_bytes)
        .map_err(|violation| format!("jsonv2 source note: {violation}"))?;
    let source_text = String::from_utf8(source_bytes)
        .map_err(|_| "jsonv2 source note: not valid UTF-8".to_owned())?;
    assert!(source_text.contains("Consulted: 2026-06-25"));
    assert!(
        source_text
            .contains("https://docs.snowflake.com/en/developer-guide/sql-api/handling-responses")
    );
    assert!(source_text.contains("document-derived rather than"));

    let result = assert_roundtrip::<ResultSet>("jsonv2_codec_cells.json")?;
    assert_eq!(result.result_set_meta_data.format, "jsonv2");
    assert_eq!(result.total_rows(), 1);
    assert_eq!(result.partition_count(), 1);
    assert_eq!(result.result_set_meta_data.partition_info[0].row_count, 1);

    let row = result.data.first().ok_or("expected one jsonv2 row")?;
    let row_type = &result.result_set_meta_data.row_type;
    assert_eq!(row.len(), row_type.len());

    assert_cell(row, 0, Some("12345678901234567.89"))?;
    assert_cell(row, 1, Some("99999999999999999999"))?;
    assert_cell(row, 2, Some("1.25"))?;
    assert_cell(row, 3, Some("1.2345678901234567890123456789012345678E+39"))?;
    assert_cell(row, 4, Some("true"))?;
    assert_cell(row, 5, Some("18262"))?;
    assert_cell(row, 6, Some("82919.000000000"))?;
    assert_cell(row, 7, Some("1611871777.123456789"))?;
    assert_cell(row, 8, Some("1611871777.123456789"))?;
    assert_cell(row, 9, Some("1616173619.000000000 1500"))?;
    assert_cell(row, 10, Some("DEADBEEF"))?;
    assert_cell(row, 11, Some(r#"{"k":[1,2]}"#))?;
    assert_cell(row, 12, Some(r#"{"nested":{"ok":true}}"#))?;
    assert_cell(row, 13, Some(r#"[1,"two",null]"#))?;
    assert_cell(row, 14, None)?;

    assert_eq!(
        decode_cell(row[0].as_deref(), &row_type[0]).map_err(|error| error.to_string())?,
        CellValue::Number("12345678901234567.89".to_owned())
    );
    assert_eq!(
        decode_cell(row[5].as_deref(), &row_type[5]).map_err(|error| error.to_string())?,
        CellValue::Date(18262)
    );
    assert_eq!(
        decode_cell(row[6].as_deref(), &row_type[6]).map_err(|error| error.to_string())?,
        CellValue::Timestamp {
            seconds: 82919,
            nanos: 0
        }
    );
    assert_eq!(
        decode_cell(row[7].as_deref(), &row_type[7]).map_err(|error| error.to_string())?,
        CellValue::Timestamp {
            seconds: 1_611_871_777,
            nanos: 123_456_789
        }
    );
    assert_eq!(
        decode_cell(row[9].as_deref(), &row_type[9]).map_err(|error| error.to_string())?,
        CellValue::TimestampTz {
            seconds: 1_616_173_619,
            nanos: 0,
            offset_minutes: 60
        }
    );
    assert_eq!(
        decode_cell(row[10].as_deref(), &row_type[10]).map_err(|error| error.to_string())?,
        CellValue::Binary(vec![0xde, 0xad, 0xbe, 0xef])
    );
    assert_eq!(
        decode_cell(row[14].as_deref(), &row_type[14]).map_err(|error| error.to_string())?,
        CellValue::Null
    );

    Ok(())
}

fn assert_cell(row: &[Option<String>], index: usize, expected: Option<&str>) -> Result<(), String> {
    let actual = row
        .get(index)
        .ok_or_else(|| format!("missing jsonv2 cell {index}"))?;
    assert_eq!(actual.as_deref(), expected, "jsonv2 cell {index}");
    Ok(())
}
