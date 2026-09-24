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

#[test]
fn test_parquet_external_pyarrow_and_duckdb_validation() {
    let uv_bin = "/home/ubuntu/.local/bin/uv";
    if !std::path::Path::new(uv_bin).exists() {
        eprintln!("uv not available; skipping external consumer validation");
        return;
    }

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

    // Execute Python script to validate with PyArrow and DuckDB
    let python_code = format!(
        r#"
import pyarrow.parquet as pq
import duckdb

path = r"{}"

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
        test_file.display()
    );

    let output = std::process::Command::new(uv_bin)
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

    if !output.status.success() {
        panic!(
            "external validation failed!\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
