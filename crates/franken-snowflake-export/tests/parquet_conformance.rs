#![forbid(unsafe_code)]

//! `parquet_conformance` -- Comprehensive round-trip conformance and golden test suite
//! for franken-snowflake-export Parquet backend.
//!
//! Validates:
//! 1. Scalar round-trip equivalence across all supported Snowflake primitive types.
//! 2. Compression modes: Uncompressed, Snappy, and Gzip.
//! 3. External consumer validation: verifies generated files load in PyArrow and DuckDB.
//! 4. Golden metadata assertions: magic bytes (PAR1), footer metadata, column chunks,
//!    and BLAKE3 content-addressed receipts.

use franken_snowflake_export::parquet::{
    PARQUET_MAGIC, ParquetCompression, ParquetWriterOptions, export_parquet, read_parquet_records,
    validate_parquet,
};
use franken_snowflake_export::{ExportColumn, LocalExportInput, ResultPartition};

fn build_test_schema() -> Vec<ExportColumn> {
    vec![
        ExportColumn::new("c_int", "NUMBER(38,0)").nullable(true),
        ExportColumn::new("c_double", "FLOAT").nullable(true),
        ExportColumn::new("c_bool", "BOOLEAN").nullable(true),
        ExportColumn::new("c_date", "DATE").nullable(true),
        ExportColumn::new("c_ts", "TIMESTAMP_NTZ").nullable(true),
        ExportColumn::new("c_text", "VARCHAR").nullable(true),
    ]
}

fn build_test_rows() -> Vec<Vec<Option<String>>> {
    vec![
        vec![
            Some("42".to_owned()),
            Some("3.141592653589793".to_owned()),
            Some("true".to_owned()),
            Some("2024-01-01".to_owned()),
            Some("1704067200.000000".to_owned()),
            Some("hello snowflake parquet".to_owned()),
        ],
        vec![
            Some("-9223372036854775808".to_owned()),
            Some("-0.000001".to_owned()),
            Some("false".to_owned()),
            Some("1970-01-01".to_owned()),
            Some("0.000000".to_owned()),
            Some("utf8-🦀-emoji-and-symbols".to_owned()),
        ],
        vec![
            Some("9223372036854775807".to_owned()),
            Some("1000000000.5".to_owned()),
            Some("true".to_owned()),
            Some("1969-12-31".to_owned()),
            Some("-1000.500000".to_owned()),
            Some("".to_owned()),
        ],
        vec![None, None, None, None, None, None],
        vec![
            Some("0".to_owned()),
            Some("0.0".to_owned()),
            Some("false".to_owned()),
            Some("2026-09-19".to_owned()),
            Some("1789785600.123456".to_owned()),
            Some("deterministic local parquet export".to_owned()),
        ],
    ]
}

#[test]
fn test_parquet_round_trip_all_dtypes() {
    let columns = build_test_schema();
    let rows = build_test_rows();
    let input = LocalExportInput::new(columns.clone(), vec![ResultPartition::new(0, rows.clone())]);

    let artifact = export_parquet(&input, "@tests/roundtrip.parquet", 1700000000000, None)
        .expect("export_parquet failed");

    assert!(!artifact.bytes.is_empty());
    assert_eq!(&artifact.bytes[0..4], PARQUET_MAGIC);
    assert_eq!(&artifact.bytes[artifact.bytes.len() - 4..], PARQUET_MAGIC);

    // Verify receipt properties
    assert_eq!(artifact.receipt.row_count, Some(5));
    assert_eq!(
        artifact.receipt.format,
        Some(franken_snowflake_export::ExportFormat::Parquet)
    );
    assert_eq!(
        artifact.receipt.kind,
        franken_snowflake_export::ExportReceiptKind::LocalParquet
    );
    artifact
        .receipt
        .content_address
        .verify(&artifact.bytes)
        .expect("receipt content address verification failed");

    // Read back and verify bitwise scalar equivalence
    let re_read = read_parquet_records(&artifact.bytes).expect("read_parquet_records failed");
    assert_eq!(re_read.columns.len(), columns.len());
    assert_eq!(re_read.partitions.len(), 1);
    assert_eq!(re_read.partitions[0].rows.len(), rows.len());

    for (row_idx, (orig_row, read_row)) in rows
        .iter()
        .zip(re_read.partitions[0].rows.iter())
        .enumerate()
    {
        for (col_idx, (orig_val, read_val)) in orig_row.iter().zip(read_row.iter()).enumerate() {
            match (orig_val, read_val) {
                (None, None) => {}
                (Some(o), Some(r)) => {
                    if col_idx == 1 {
                        // Float comparison within epsilon
                        let of: f64 = o.parse().unwrap();
                        let rf: f64 = r.parse().unwrap();
                        assert!(
                            (of - rf).abs() < 1e-9,
                            "float mismatch at row {row_idx}, col {col_idx}: expected {of}, got {rf}"
                        );
                    } else if col_idx == 4 {
                        // Timestamp comparison: both format to identical microsecond representation
                        assert_eq!(
                            o, r,
                            "timestamp mismatch at row {row_idx}: expected {o}, got {r}"
                        );
                    } else {
                        assert_eq!(
                            o, r,
                            "scalar mismatch at row {row_idx}, col {col_idx}: expected {o:?}, got {r:?}"
                        );
                    }
                }
                (other_o, other_r) => {
                    panic!(
                        "nullability mismatch at row {row_idx}, col {col_idx}: expected {other_o:?}, got {other_r:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn test_parquet_compression_modes() {
    let columns = build_test_schema();
    let rows = build_test_rows();
    let input = LocalExportInput::new(columns, vec![ResultPartition::new(0, rows)]);

    let modes = [
        ParquetCompression::Uncompressed,
        ParquetCompression::Snappy,
        ParquetCompression::Gzip,
    ];

    for mode in modes {
        let opts = ParquetWriterOptions {
            compression: mode,
            created_by: "franken_snowflake_test".to_owned(),
        };

        let artifact = export_parquet(&input, "@tests/mode.parquet", 1700000000000, Some(opts))
            .unwrap_or_else(|e| panic!("compression mode {mode:?} failed: {e}"));

        assert_eq!(&artifact.bytes[0..4], PARQUET_MAGIC);
        assert_eq!(&artifact.bytes[artifact.bytes.len() - 4..], PARQUET_MAGIC);

        let inspection = validate_parquet(&artifact.bytes).expect("validate_parquet failed");
        assert!(inspection.magic_header_valid);
        assert!(inspection.magic_footer_valid);
        assert_eq!(inspection.row_count, 5);
        assert_eq!(inspection.column_count, 6);
        assert_eq!(
            inspection.created_by.as_deref(),
            Some("franken_snowflake_test")
        );

        let re_read = read_parquet_records(&artifact.bytes).expect("read_parquet_records failed");
        assert_eq!(re_read.partitions[0].rows.len(), 5);
    }
}

#[test]
fn test_parquet_golden_metadata_assertions() {
    let columns = vec![
        ExportColumn::new("id", "INTEGER").nullable(false),
        ExportColumn::new("label", "VARCHAR").nullable(true),
    ];
    let rows = vec![
        vec![Some("1".to_owned()), Some("alpha".to_owned())],
        vec![Some("2".to_owned()), None],
        vec![Some("3".to_owned()), Some("gamma".to_owned())],
    ];
    let input = LocalExportInput::new(columns, vec![ResultPartition::new(0, rows)]);

    let artifact = export_parquet(&input, "@analytics/golden.parquet", 1700000000000, None)
        .expect("export golden parquet failed");

    let inspection = validate_parquet(&artifact.bytes).expect("validation failed");
    assert!(inspection.magic_header_valid);
    assert!(inspection.magic_footer_valid);
    assert_eq!(inspection.file_version, 1);
    assert_eq!(inspection.row_count, 3);
    assert_eq!(inspection.column_count, 2);
    assert_eq!(inspection.column_names, vec!["id", "label"]);
}

#[test]
fn test_parquet_large_dataset_and_edge_cases() {
    let columns = vec![
        ExportColumn::new("seq", "INTEGER").nullable(false),
        ExportColumn::new("rep", "VARCHAR").nullable(true),
        ExportColumn::new("val", "FLOAT").nullable(true),
    ];

    // 2,000 rows with repeating runs to exercise Snappy compression and RLE runs
    let mut rows = Vec::with_capacity(2000);
    for i in 0..2000 {
        let rep = if i % 10 == 0 {
            None
        } else if i % 2 == 0 {
            Some("even_bucket".to_owned())
        } else {
            Some("odd_bucket".to_owned())
        };
        rows.push(vec![
            Some(i.to_string()),
            rep,
            Some(format!("{}.{}", i, i % 100)),
        ]);
    }

    let input = LocalExportInput::new(columns, vec![ResultPartition::new(0, rows)]);
    let artifact = export_parquet(&input, "@tests/large.parquet", 1700000000000, None)
        .expect("large parquet export failed");

    let inspection = validate_parquet(&artifact.bytes).expect("inspection failed");
    assert_eq!(inspection.row_count, 2000);
    assert_eq!(inspection.column_count, 3);

    let re_read = read_parquet_records(&artifact.bytes).expect("re-read failed");
    assert_eq!(re_read.partitions[0].rows.len(), 2000);
    assert_eq!(re_read.partitions[0].rows[0][0], Some("0".to_owned()));
    assert_eq!(re_read.partitions[0].rows[1999][0], Some("1999".to_owned()));
}

/// The live SQL API reports the bare type name (`"fixed"`, `"timestamp_ntz"`)
/// with precision/scale in separate `rowType` fields. Before 2026-09-24 the
/// writer read scale only from a `NUMBER(p,s)` string, so every live NUMBER was
/// written as INT64 and `1.50` came back as `1` (reproduced with pyarrow/duckdb).
fn live_shaped_columns() -> Vec<ExportColumn> {
    vec![
        ExportColumn::new("amount", "fixed").precision_scale(Some(10), Some(2)),
        ExportColumn::new("big", "fixed").precision_scale(Some(38), Some(0)),
        ExportColumn::new("tiny_frac", "fixed").precision_scale(Some(38), Some(10)),
        ExportColumn::new("small_int", "fixed").precision_scale(Some(5), Some(0)),
        ExportColumn::new("ts_ntz", "timestamp_ntz").precision_scale(None, Some(9)),
        ExportColumn::new("ts_ltz", "timestamp_ltz").precision_scale(None, Some(3)),
        ExportColumn::new("ts_tz", "timestamp_tz").precision_scale(None, Some(9)),
        ExportColumn::new("t", "time").precision_scale(None, Some(9)),
        ExportColumn::new("d", "date"),
        ExportColumn::new("bin", "binary"),
        ExportColumn::new("v", "variant"),
        ExportColumn::new("flag", "boolean"),
    ]
}

fn cells(values: &[Option<&str>]) -> Vec<Option<String>> {
    values.iter().map(|v| v.map(str::to_owned)).collect()
}

fn live_shaped_rows() -> Vec<Vec<Option<String>>> {
    vec![
        cells(&[
            Some("1.50"),
            Some("12345678901234567890123456789012345678"),
            Some("0.0000000001"),
            Some("42"),
            Some("1700000000.123456789"),
            Some("1700000000.123"),
            Some("1700000000.500000000 1770"),
            Some("82919.123456789"),
            Some("18262"),
            Some("DEADBEEF"),
            Some("{\"a\":1}"),
            Some("true"),
        ]),
        cells(&[
            Some("-7.99"),
            Some("-99999999999999999999999999999999999999"),
            Some("-12345.6789012345"),
            Some("-5"),
            Some("-1.500000000"),
            Some("0.000"),
            Some("-3600.000000000 1440"),
            Some("0.000000000"),
            Some("-1"),
            Some("00"),
            Some("[1,2]"),
            Some("false"),
        ]),
        vec![None; 12],
    ]
}

#[test]
fn test_live_shaped_schema_round_trips_exactly() {
    let input = LocalExportInput::new(
        live_shaped_columns(),
        vec![ResultPartition::new(0, live_shaped_rows())],
    );
    let artifact = export_parquet(
        &input,
        "@tests/live_shaped.parquet",
        1_700_000_000_000,
        None,
    )
    .expect("export_parquet failed");
    let re_read = read_parquet_records(&artifact.bytes).expect("read_parquet_records failed");

    // TIMESTAMP_TZ becomes the UTC instant plus a sibling offset column.
    let names: Vec<&str> = re_read.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "amount",
            "big",
            "tiny_frac",
            "small_int",
            "ts_ntz",
            "ts_ltz",
            "ts_tz",
            "ts_tz__tz_offset_minutes",
            "t",
            "d",
            "bin",
            "v",
            "flag",
        ]
    );
    // Canonical renderings: decimals keep their scale, time units follow the
    // declared scale (TIMESTAMP_LTZ(3) is stored in micros), dates render ISO.
    let expected = vec![
        cells(&[
            Some("1.50"),
            Some("12345678901234567890123456789012345678"),
            Some("0.0000000001"),
            Some("42"),
            Some("1700000000.123456789"),
            Some("1700000000.123000"),
            Some("1700000000.500000000"),
            Some("330"),
            Some("82919.123456789"),
            Some("2020-01-01"),
            Some("DEADBEEF"),
            Some("{\"a\":1}"),
            Some("true"),
        ]),
        cells(&[
            Some("-7.99"),
            Some("-99999999999999999999999999999999999999"),
            Some("-12345.6789012345"),
            Some("-5"),
            Some("-1.500000000"),
            Some("0.000000"),
            Some("-3600.000000000"),
            Some("0"),
            Some("0.000000000"),
            Some("1969-12-31"),
            Some("00"),
            Some("[1,2]"),
            Some("false"),
        ]),
        vec![None; 13],
    ];
    assert_eq!(re_read.partitions[0].rows, expected);

    // The schema carries the Snowflake shape back.
    let amount = &re_read.columns[0];
    assert_eq!(
        (
            amount.snowflake_type.as_str(),
            amount.precision,
            amount.scale
        ),
        ("NUMBER", Some(10), Some(2))
    );
    assert_eq!(re_read.columns[4].snowflake_type, "TIMESTAMP_NTZ");
    assert_eq!(re_read.columns[5].snowflake_type, "TIMESTAMP_LTZ");
    assert_eq!(re_read.columns[10].snowflake_type, "BINARY");
    assert_eq!(re_read.columns[11].snowflake_type, "VARIANT");
}

#[test]
fn test_lossy_values_are_refused_not_rounded() {
    let refuse = |column: ExportColumn, value: &str| {
        let input = LocalExportInput::new(
            vec![column],
            vec![ResultPartition::new(0, vec![vec![Some(value.to_owned())]])],
        );
        let error = export_parquet(&input, "@tests/lossy.parquet", 1, None)
            .expect_err("a lossy value must be refused");
        assert!(
            error.to_string().contains("without loss"),
            "{value}: {error}"
        );
    };
    let amount = || ExportColumn::new("amount", "fixed").precision_scale(Some(10), Some(2));
    refuse(amount(), "1.505"); // needs rounding
    refuse(amount(), "123456789.01"); // 11 digits > precision 10
    refuse(
        ExportColumn::new("big", "fixed").precision_scale(Some(38), Some(0)),
        "123456789012345678901234567890123456789", // 39 digits
    );
    refuse(
        ExportColumn::new("ts", "timestamp_ltz").precision_scale(None, Some(3)),
        "1.1234567", // 7 digits in a micros column
    );
    refuse(
        ExportColumn::new("n", "fixed").precision_scale(Some(10), Some(2)),
        "1e5",
    );
    refuse(ExportColumn::new("flag", "boolean"), "maybe");
    refuse(ExportColumn::new("bin", "binary"), "XYZ");
    // Extra zero digits are exact and accepted.
    let input = LocalExportInput::new(
        vec![amount()],
        vec![ResultPartition::new(
            0,
            vec![vec![Some("1.5000".to_owned())]],
        )],
    );
    let artifact = export_parquet(&input, "@tests/zeros.parquet", 1, None).expect("exact value");
    let re_read = read_parquet_records(&artifact.bytes).expect("read back");
    assert_eq!(re_read.partitions[0].rows[0][0].as_deref(), Some("1.50"));
}

/// Locate `uv` on PATH (then `$HOME/.local/bin`). `None` when absent.
fn find_uv() -> Option<std::path::PathBuf> {
    let on_path = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("uv"))
            .find(|candidate| candidate.is_file())
    });
    on_path.or_else(|| {
        std::env::var_os("HOME")
            .map(|home| std::path::Path::new(&home).join(".local/bin/uv"))
            .filter(|candidate| candidate.is_file())
    })
}

#[test]
fn test_parquet_external_pyarrow_and_duckdb_validation() {
    // In the release lane (FSNOW_REQUIRE_EXTERNAL_PARQUET=1) a missing tool is a
    // failure; elsewhere the test says plainly that it did not run.
    let Some(uv_bin) = find_uv() else {
        assert!(
            std::env::var("FSNOW_REQUIRE_EXTERNAL_PARQUET").as_deref() != Ok("1"),
            "FSNOW_REQUIRE_EXTERNAL_PARQUET=1 but `uv` was not found; external Parquet conformance did not run"
        );
        eprintln!(
            "SKIPPED (not a pass): uv not found; external PyArrow/DuckDB validation did not run"
        );
        return;
    };

    let columns = vec![
        ExportColumn::new("id", "INTEGER").nullable(false),
        ExportColumn::new("cost", "FLOAT").nullable(true),
        ExportColumn::new("active", "BOOLEAN").nullable(true),
        ExportColumn::new("title", "VARCHAR").nullable(true),
    ];

    let rows = vec![
        vec![
            Some("101".to_owned()),
            Some("19.99".to_owned()),
            Some("true".to_owned()),
            Some("widget-a".to_owned()),
        ],
        vec![
            Some("102".to_owned()),
            Some("29.99".to_owned()),
            Some("false".to_owned()),
            Some("widget-b".to_owned()),
        ],
        vec![Some("103".to_owned()), None, None, None],
        vec![
            Some("104".to_owned()),
            Some("99.95".to_owned()),
            Some("true".to_owned()),
            Some("widget-d".to_owned()),
        ],
    ];

    let input = LocalExportInput::new(columns, vec![ResultPartition::new(0, rows)]);

    let temp_dir = tempfile::tempdir().expect("tempdir failed");
    let test_file = temp_dir.path().join("external_validation.parquet");

    let artifact = export_parquet(&input, test_file.to_string_lossy(), 1700000000000, None)
        .expect("export failed");
    std::fs::write(&test_file, &artifact.bytes).expect("write file failed");

    // The live-shaped schema (bare type names + rowType precision/scale).
    let live_file = temp_dir.path().join("live_shaped.parquet");
    let live_input = LocalExportInput::new(
        live_shaped_columns(),
        vec![ResultPartition::new(0, live_shaped_rows())],
    );
    let live_artifact = export_parquet(&live_input, live_file.to_string_lossy(), 1, None)
        .expect("live-shaped export failed");
    std::fs::write(&live_file, &live_artifact.bytes).expect("write live file failed");

    // Execute Python script to validate with PyArrow and DuckDB
    let python_code = format!(
        r#"
import pyarrow.parquet as pq
import duckdb
from decimal import Decimal
import datetime

path = r"{}"
live = r"{}"

# 0. Live-shaped types: exact decimals, time units, TZ offsets, raw binary.
t2 = pq.read_table(live)
sch = t2.schema
assert str(sch.field("amount").type) == "decimal128(10, 2)", sch.field("amount").type
assert t2["amount"].to_pylist() == [Decimal("1.50"), Decimal("-7.99"), None], t2["amount"].to_pylist()
assert str(sch.field("big").type) == "decimal128(38, 0)", sch.field("big").type
assert t2["big"].to_pylist() == [Decimal("12345678901234567890123456789012345678"), Decimal("-99999999999999999999999999999999999999"), None]
assert t2["tiny_frac"].to_pylist() == [Decimal("0.0000000001"), Decimal("-12345.6789012345"), None]
assert t2["small_int"].to_pylist() == [42, -5, None]
assert str(sch.field("ts_ntz").type) == "timestamp[ns]", sch.field("ts_ntz").type
assert t2["ts_ntz"].cast("int64").to_pylist() == [1700000000123456789, -1500000000, None]
assert str(sch.field("ts_ltz").type) == "timestamp[us, tz=UTC]", sch.field("ts_ltz").type
assert t2["ts_ltz"].cast("int64").to_pylist() == [1700000000123000, 0, None]
assert str(sch.field("ts_tz").type) == "timestamp[ns, tz=UTC]", sch.field("ts_tz").type
assert t2["ts_tz"].cast("int64").to_pylist() == [1700000000500000000, -3600000000000, None]
assert t2["ts_tz__tz_offset_minutes"].to_pylist() == [330, 0, None]
assert str(sch.field("t").type) == "time64[ns]", sch.field("t").type
assert t2["t"].cast("int64").to_pylist() == [82919123456789, 0, None]
assert t2["d"].to_pylist() == [datetime.date(2020, 1, 1), datetime.date(1969, 12, 31), None]
assert t2["bin"].to_pylist() == [b"\xde\xad\xbe\xef", b"\x00", None], t2["bin"].to_pylist()
assert [str(v) if v is not None else None for v in t2["v"].to_pylist()] == ['{{"a":1}}', "[1,2]", None]
assert t2["flag"].to_pylist() == [True, False, None]
print("PyArrow live-shaped validation PASSED")
con0 = duckdb.connect()
s = con0.execute(f"SELECT CAST(sum(amount) AS VARCHAR), CAST(max(big) AS VARCHAR) FROM read_parquet('{{live}}')").fetchone()
assert s[0] == "-6.49", s
assert s[1] == "12345678901234567890123456789012345678", s
print("DuckDB live-shaped validation PASSED")

# 1. Validate with PyArrow
table = pq.read_table(path)
assert len(table) == 4, f"expected 4 rows in pyarrow, got {{len(table)}}"
assert table.column_names == ["id", "cost", "active", "title"], f"names: {{table.column_names}}"
assert table["id"].to_pylist() == [101, 102, 103, 104]
assert table["active"].to_pylist() == [True, False, None, True]
assert table["title"].to_pylist() == ["widget-a", "widget-b", None, "widget-d"]
print("PyArrow validation PASSED")

# 2. Validate with DuckDB
con = duckdb.connect()
res = con.execute(f"SELECT count(*), sum(id), max(cost) FROM read_parquet('{{path}}')").fetchall()
count, sum_id, max_cost = res[0]
assert count == 4, f"duckdb count: {{count}}"
assert sum_id == 410, f"duckdb sum(id): {{sum_id}}"
assert abs(max_cost - 99.95) < 1e-4, f"duckdb max_cost: {{max_cost}}"
print("DuckDB validation PASSED")
"#,
        test_file.display(),
        live_file.display()
    );

    let output = std::process::Command::new(&uv_bin)
        .args([
            "run",
            "--with",
            "pyarrow,duckdb",
            "python3",
            "-c",
            &python_code,
        ])
        .output()
        .expect("failed to execute uv command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        panic!(
            "external validation failed!\nstdout: {}\nstderr: {}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // Exit 0 alone is not proof: every validation block must have run.
    for marker in [
        "PyArrow live-shaped validation PASSED",
        "DuckDB live-shaped validation PASSED",
        "PyArrow validation PASSED",
        "DuckDB validation PASSED",
    ] {
        assert!(
            stdout.contains(marker),
            "missing `{marker}` in external validation output:\n{stdout}"
        );
    }
    eprintln!("{stdout}");
}
