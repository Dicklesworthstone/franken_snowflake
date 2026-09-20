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

use fp_types::{DType, Scalar};
use franken_snowflake_frame::{ResultPartition, SnowflakeColumn};
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
        "REAL" | "FLOAT" | "FLOAT4" | "FLOAT8" | "DOUBLE" | "DOUBLE PRECISION" | "DECFLOAT" => {
            Some(DType::Float64)
        }
        "BOOLEAN" | "BOOL" => Some(DType::Bool),
        "DATE" | "TIME" | "TIMESTAMP_NTZ" | "DATETIME" | "TIMESTAMP_LTZ" | "TIMESTAMP_TZ" => {
            Some(DType::Datetime64)
        }
        _ => None,
    }
}

#[test]
fn captured_wire_golden_decodes_through_the_frame_codec() -> Result<(), String> {
    let Some(path) = golden_path() else {
        println!(
            "skip: no captured golden at crates/franken-snowflake-frame/tests/captured/ — \
             run scripts/capture-jsonv2-golden.sh against a live account and commit the result"
        );
        return Ok(());
    };
    let raw =
        std::fs::read_to_string(&path).map_err(|e| format!("golden file read failed: {e}"))?;
    let golden: Value =
        serde_json::from_str(&raw).map_err(|e| format!("golden parses as JSON failed: {e}"))?;
    assert_eq!(
        golden.get("schema").and_then(Value::as_str),
        Some(GOLDEN_SCHEMA),
        "unexpected golden schema"
    );

    let columns = golden
        .get("columns")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing columns array".to_string())?;
    let rows = golden
        .get("rows")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing rows array".to_string())?;
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

    let mut partitions = Vec::with_capacity(rows.len());
    for row in rows {
        let row_array = row
            .as_array()
            .ok_or_else(|| "row is not an array".to_string())?;
        partitions.push(
            row_array
                .iter()
                .map(|cell| cell.as_str().map(str::to_owned))
                .collect(),
        );
    }

    // The golden's `rows` are the rows of partition 0 (the capture is a
    // single-partition response).
    let partitions = vec![ResultPartition::new(0, partitions)];
    let frame = franken_snowflake_frame::materialize_partitions(&snowflake_columns, partitions)
        .map_err(|error| {
            format!(
                "FINDING: the frame codec rejected the empirical capture ({error}); \
                 the codec's encoding assumptions disagree with the wire"
            )
        })?;
    assert_eq!(frame.row_count, rows.len(), "all captured rows materialize");

    for column in &snowflake_columns {
        let frame_column = frame
            .columns
            .iter()
            .find(|candidate| candidate.metadata.name == column.name)
            .ok_or_else(|| format!("column {} missing from the frame", column.name))?;
        if let Some(dtype) = required_dtype(&column.snowflake_type) {
            // Nullable columns land in the Nullable variant of the dtype.
            let actual = frame_column.column.dtype();
            let dtype_str = format!("{dtype:?}");
            let actual_str = format!("{actual:?}");
            assert!(
                actual_str == dtype_str || actual_str == format!("{dtype_str}Nullable"),
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
    Ok(())
}

#[test]
fn canonical_codec_cells_fixture_decodes_through_the_frame_codec() -> Result<(), String> {
    const RAW: &str =
        include_str!("../../franken-snowflake-sqlapi/tests/fixtures/jsonv2_codec_cells.json");
    let fixture: Value =
        serde_json::from_str(RAW).map_err(|e| format!("fixture JSON parse error: {e}"))?;

    let meta = fixture
        .get("resultSetMetaData")
        .ok_or_else(|| "missing resultSetMetaData".to_string())?;
    assert_eq!(meta.get("format").and_then(Value::as_str), Some("jsonv2"));

    let row_type = meta
        .get("rowType")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing rowType".to_string())?;

    let snowflake_columns: Vec<SnowflakeColumn> = row_type
        .iter()
        .map(|col| SnowflakeColumn {
            name: col
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            snowflake_type: col
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            scale: col.get("scale").and_then(Value::as_i64).map(|s| s as i32),
            precision: col.get("precision").and_then(Value::as_i64).map(|p| p as i32),
            nullable: col.get("nullable").and_then(Value::as_bool).unwrap_or(true),
        })
        .collect();

    let data = fixture
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing data array".to_string())?;

    let mut row_data = Vec::with_capacity(data.len());
    for row in data {
        let row_array = row.as_array().ok_or_else(|| "row is not an array".to_string())?;
        row_data.push(
            row_array
                .iter()
                .map(|cell| cell.as_str().map(str::to_owned))
                .collect(),
        );
    }

    let partitions = vec![ResultPartition::new(0, row_data)];
    let frame = franken_snowflake_frame::materialize_partitions(&snowflake_columns, partitions)
        .map_err(|e| format!("materialization failed: {e}"))?;

    assert_eq!(frame.row_count, 1);
    assert_eq!(frame.columns.len(), 15);

    // 1. DATE = 18262 epoch days == 2020-01-01T00:00:00Z (1_577_836_800_000_000_000 nanos)
    let event_date = frame
        .columns
        .iter()
        .find(|c| c.metadata.name == "EVENT_DATE")
        .unwrap();
    assert_eq!(event_date.column.dtype(), DType::Datetime64);
    assert_eq!(
        event_date.column.value(0),
        Some(&Scalar::Datetime64(1_577_836_800_000_000_000))
    );

    // 2. BOOLEAN = "true" -> true
    let bool_col = frame
        .columns
        .iter()
        .find(|c| c.metadata.name == "BOOL_TRUE")
        .unwrap();
    assert_eq!(bool_col.column.dtype(), DType::Bool);
    assert_eq!(bool_col.column.value(0), Some(&Scalar::Bool(true)));

    // 3. FIXED with scale 2 = "12345678901234567.89" -> DecimalString
    let n_scale = frame
        .columns
        .iter()
        .find(|c| c.metadata.name == "N_SCALE")
        .unwrap();
    assert_eq!(
        n_scale.metadata.storage_kind,
        franken_snowflake_frame::FrameStorageKind::DecimalString
    );
    assert_eq!(
        n_scale.column.value(0),
        Some(&Scalar::Utf8("12345678901234567.89".to_owned()))
    );

    // 4. REAL = "1.25" -> Float64(1.25)
    let real_col = frame
        .columns
        .iter()
        .find(|c| c.metadata.name == "REAL_VALUE")
        .unwrap();
    assert_eq!(real_col.column.dtype(), DType::Float64);
    assert_eq!(
        real_col.column.value(0),
        Some(&Scalar::Float64(1.25))
    );

    // 5. TIMESTAMP_NTZ = "1611871777.123456789" -> 1611871777123456789 nanos
    let ts_ntz = frame
        .columns
        .iter()
        .find(|c| c.metadata.name == "TS_NTZ")
        .unwrap();
    assert_eq!(ts_ntz.column.dtype(), DType::Datetime64);
    assert_eq!(
        ts_ntz.column.value(0),
        Some(&Scalar::Datetime64(1_611_871_777_123_456_789))
    );

    // 6. TIMESTAMP_TZ = "1616173619.000000000 1500" -> 1616173619000000000 nanos, offset = 1500 - 1440 = +60
    let ts_tz = frame
        .columns
        .iter()
        .find(|c| c.metadata.name == "TS_TZ")
        .unwrap();
    assert_eq!(ts_tz.column.dtype(), DType::Datetime64);
    assert_eq!(
        ts_tz.column.value(0),
        Some(&Scalar::Datetime64(1_616_173_619_000_000_000))
    );
    assert_eq!(
        ts_tz.timestamp_tz_offsets_minutes.as_ref().unwrap(),
        &[Some(60)]
    );

    // 7. BINARY = "DEADBEEF" -> BinaryHex
    let bin_col = frame
        .columns
        .iter()
        .find(|c| c.metadata.name == "BIN_VALUE")
        .unwrap();
    assert_eq!(
        bin_col.metadata.storage_kind,
        franken_snowflake_frame::FrameStorageKind::BinaryHex
    );
    assert_eq!(
        bin_col.column.value(0),
        Some(&Scalar::Utf8("DEADBEEF".to_owned()))
    );

    // 8. NULL_TEXT = null -> FrameMissingKind::SqlNull and Scalar::Null
    let null_col = frame
        .columns
        .iter()
        .find(|c| c.metadata.name == "NULL_TEXT")
        .unwrap();
    assert_eq!(
        null_col.missing_kinds[0],
        Some(franken_snowflake_frame::FrameMissingKind::SqlNull)
    );
    assert_eq!(
        null_col.column.value(0),
        Some(&Scalar::Null(fp_types::NullKind::Null))
    );

    Ok(())
}

