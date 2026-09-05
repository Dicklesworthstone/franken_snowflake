//! Data-driven validation of the captured jsonv2 wire golden against the
//! frame codec (the validation half of bead
//! fsnow-native-snowflake-connector-w0i.13).
//!
//! `scripts/capture-jsonv2-golden.sh` produces
//! `fsnow-jsonv2-golden/jsonv2-wire-golden.json` (column rowType entries plus
//! rows whose cells are the literal wire strings Snowflake returned). This
//! test consumes that file when it exists and asserts the frame codec
//! ACCEPTS every empirical cell and lands it in the storage kind its logical
//! type dictates. Without the golden file it records a typed skip, so
//! no-account CI stays green.
//!
//! Any failure here is a finding: either the capture caught an encoding the
//! codec mishandles (fix the codec), or the codec's assumption disagrees
//! with the wire (also fix the codec — the golden is the source of truth).

#![cfg(feature = "frankenpandas")]

use std::path::{Path, PathBuf};

use franken_snowflake_frame::{FrankenPandasFrame, ResultPartition, SnowflakeColumn};
use fp_types::DType;
use serde_json::Value;

const GOLDEN_SCHEMA: &str = "franken_snowflake.jsonv2_wire_golden.v1";

fn golden_path() -> Option<PathBuf> {
    // The captured golden is checked in at this path (the capture script
    // copies it here) so the validation runs in every environment, including
    // remote workers where ambient env vars do not survive.
    let checked_in = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("captured")
        .join("jsonv2-wire-golden.json");
    checked_in.is_file().then_some(checked_in)
}

/// The deterministic storage dtype a logical type must land in when the
/// column carries no scale/precision metadata (the capture envelope omits
/// them). FIXED is excluded: without scale it may legally land Int64 or
/// DecimalString.
fn required_dtype(snowflake_type: &str) -> Option<DType> {
    match snowflake_type.to_ascii_uppercase().as_str() {
        "REAL" | "FLOAT" | "FLOAT4" | "FLOAT8" | "DOUBLE" | "DOUBLE PRECISION"
        | "DECFLOAT" => Some(DType::Float64),
        "BOOLEAN" | "BOOL" => Some(DType::Bool),
        "DATE" | "TIME" | "TIMESTAMP_NTZ" | "DATETIME" | "TIMESTAMP_LTZ"
        | "TIMESTAMP_TZ" => Some(DType::Datetime64),
        _ => None,
    }
}

#[test]
fn captured_wire_golden_decodes_through_the_frame_codec() {
    let Some(path) = golden_path() else {
        println!(
            "skip: no captured golden at crates/franken-snowflake-frame/tests/captured/ — \
             run scripts/capture-jsonv2-golden.sh against a live account and commit the result"
        );
        return;
    };
    let raw = std::fs::read_to_string(&path).expect("golden file reads");
    let golden: Value = serde_json::from_str(&raw).expect("golden parses as JSON");
    assert_eq!(
        golden.get("schema").and_then(Value::as_str),
        Some(GOLDEN_SCHEMA),
        "unexpected golden schema"
    );

    let columns = golden
        .get("columns")
        .and_then(Value::as_array)
        .expect("columns array");
    let rows = golden
        .get("rows")
        .and_then(Value::as_array)
        .expect("rows array");
    assert!(!columns.is_empty(), "golden has columns");
    assert!(!rows.is_empty(), "golden has rows");

    let snowflake_columns: Vec<SnowflakeColumn> = columns
        .iter()
        .map(|column| SnowflakeColumn {
            name: column
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            snowflake_type: column
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            scale: None,
            precision: None,
            nullable: column
                .get("nullable")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        })
        .collect();

    let partitions: Vec<Vec<Option<String>>> = rows
        .iter()
        .map(|row| {
            row.as_array()
                .expect("row is an array")
                .iter()
                .map(|cell| cell.as_str().map(str::to_owned))
                .collect()
        })
        .collect();

    // The golden's `rows` are the rows of partition 0 (the capture is a
    // single-partition response).
    let partitions = vec![ResultPartition::new(0, partitions)];
    let materialized: Result<FrankenPandasFrame, _> =
        franken_snowflake_frame::materialize_partitions(&snowflake_columns, partitions);
    let frame = match materialized {
        Ok(frame) => frame,
        Err(error) => panic!(
            "FINDING: the frame codec rejected the empirical capture ({error}); \
             the codec's encoding assumptions disagree with the wire"
        ),
    };
    assert_eq!(frame.row_count, rows.len(), "all captured rows materialize");

    for column in &snowflake_columns {
        let frame_column = frame
            .columns
            .iter()
            .find(|candidate| candidate.metadata.name == column.name)
            .unwrap_or_else(|| panic!("column {} missing from the frame", column.name));
        if let Some(dtype) = required_dtype(&column.snowflake_type) {
            // Nullable columns land in the Nullable variant of the dtype.
            let actual = frame_column.column.dtype();
            let dtype_str = format!("{dtype:?}");
            let actual_str = format!("{actual:?}");
            assert!(
                actual_str == dtype_str
                    || actual_str == format!("{dtype_str}Nullable"),
                "column {} ({}) decoded to the wrong dtype: {actual_str:?} (expected {dtype_str:?} or its Nullable variant)",
                column.name,
                column.snowflake_type
            );
        }
    }
    println!(
        "empirical jsonv2 golden validated: {} columns, {} rows",
        snowflake_columns.len(),
        rows.len()
    );
}
