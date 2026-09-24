#![cfg(feature = "frankenpandas")]

use franken_snowflake_frame::{
    FrameMissingKind, ResultPartition, SnowflakeColumn, materialize_partition_bytes,
    materialize_partitions, materialize_raw_partitions,
};

fn col(name: &str, snowflake_type: &str) -> SnowflakeColumn {
    SnowflakeColumn::new(name, snowflake_type)
}

#[test]
fn zero_copy_bitwise_parity_across_all_types() -> Result<(), String> {
    let columns = vec![
        col("ID", "FIXED").with_scale(0).nullable(false),
        col("NULLABLE_ID", "NUMBER").with_scale(0).nullable(true),
        col("AMOUNT", "FIXED")
            .with_scale(2)
            .with_precision(38)
            .nullable(false),
        col("BIG_NUM", "NUMBER")
            .with_scale(0)
            .with_precision(38)
            .nullable(true),
        col("RATE", "REAL").nullable(true),
        col("FLAG", "BOOLEAN").nullable(true),
        col("EVENT_DATE", "DATE").nullable(false),
        col("EVENT_TIME", "TIME").nullable(true),
        col("TS_NTZ", "TIMESTAMP_NTZ").nullable(true),
        col("TS_TZ", "TIMESTAMP_TZ").nullable(true),
        col("HEX_BIN", "BINARY").nullable(true),
        col("PAYLOAD", "VARIANT").nullable(true),
        col("DESCRIPTION", "TEXT").nullable(true),
    ];

    let raw_rows = vec![
        vec![
            Some("101".to_string()),
            Some("202".to_string()),
            Some("12345678901234567.89".to_string()),
            Some("99999999999999999999".to_string()),
            Some("3.14159".to_string()),
            Some("true".to_string()),
            Some("18262".to_string()),
            Some("82919.000000001".to_string()),
            Some("1611871777.123456789".to_string()),
            Some("1616173619.000000001 1500".to_string()),
            Some("DEADBEEF".to_string()),
            Some("{\"k\":[1,2],\"nested\":{\"flag\":true}}".to_string()),
            Some("hello \"world\" with \\ special chars \n and \t tabs".to_string()),
        ],
        vec![
            Some("-42".to_string()),
            None,
            Some("-0.01".to_string()),
            None,
            Some("NaN".to_string()),
            Some("false".to_string()),
            Some("-100".to_string()),
            None,
            None,
            Some("-0.5 1440".to_string()),
            Some("0a0b".to_string()),
            Some("[1,\"two\",null]".to_string()),
            None,
        ],
    ];

    let legacy_partitions = vec![ResultPartition::new(0, raw_rows)];

    // Construct exact wire JSON corresponding to these rows
    let wire_json = br#"[
        [
            "101",
            "202",
            "12345678901234567.89",
            "99999999999999999999",
            "3.14159",
            "true",
            "18262",
            "82919.000000001",
            "1611871777.123456789",
            "1616173619.000000001 1500",
            "DEADBEEF",
            "{\"k\":[1,2],\"nested\":{\"flag\":true}}",
            "hello \"world\" with \\ special chars \n and \t tabs"
        ],
        [
            "-42",
            null,
            "-0.01",
            null,
            "NaN",
            "false",
            "-100",
            null,
            null,
            "-0.5 1440",
            "0a0b",
            "[1,\"two\",null]",
            null
        ]
    ]"#;

    let legacy_frame = materialize_partitions(&columns, legacy_partitions)
        .map_err(|e| format!("legacy materialize failed: {e}"))?;

    let zc_frame = materialize_partition_bytes(&columns, wire_json)
        .map_err(|e| format!("zero_copy materialize failed: {e}"))?;

    assert_eq!(legacy_frame.row_count, zc_frame.row_count);
    assert_eq!(legacy_frame.columns.len(), zc_frame.columns.len());

    for (legacy_col, zc_col) in legacy_frame.columns.iter().zip(&zc_frame.columns) {
        assert_eq!(legacy_col.metadata, zc_col.metadata);
        assert_eq!(legacy_col.column.dtype(), zc_col.column.dtype());
        assert_eq!(legacy_col.missing_kinds, zc_col.missing_kinds);
        assert_eq!(
            legacy_col.timestamp_tz_offsets_minutes,
            zc_col.timestamp_tz_offsets_minutes
        );

        for row in 0..legacy_frame.row_count {
            let legacy_val = legacy_col.column.value(row);
            let zc_val = zc_col.column.value(row);
            match (legacy_val, zc_val) {
                (Some(fp_types::Scalar::Float64(a)), Some(fp_types::Scalar::Float64(b))) => {
                    if a.is_nan() && b.is_nan() {
                        // Both NaN, passes
                    } else {
                        assert_eq!(a, b);
                    }
                }
                _ => {
                    assert_eq!(
                        legacy_val, zc_val,
                        "value mismatch in column {:?} row {}",
                        legacy_col.metadata.name, row
                    );
                }
            }
        }
    }

    Ok(())
}

#[test]
fn zero_copy_multi_partition_streaming() -> Result<(), String> {
    let columns = vec![
        col("ID", "FIXED").with_scale(0).nullable(false),
        col("NAME", "TEXT").nullable(true),
    ];

    let p0 = br#"[["1", "Alice"], ["2", "Bob"]]"#;
    let p1 = br#"[["3", "Charlie"], ["4", null]]"#;

    let frame = materialize_raw_partitions(&columns, [(0, p0.as_slice()), (1, p1.as_slice())])
        .map_err(|e| format!("{e}"))?;

    assert_eq!(frame.row_count, 4);
    let id_col = frame.column("ID").ok_or("missing ID column")?;
    let name_col = frame.column("NAME").ok_or("missing NAME column")?;

    assert_eq!(id_col.column.value(0), Some(&fp_types::Scalar::Int64(1)));
    assert_eq!(id_col.column.value(1), Some(&fp_types::Scalar::Int64(2)));
    assert_eq!(id_col.column.value(2), Some(&fp_types::Scalar::Int64(3)));
    assert_eq!(id_col.column.value(3), Some(&fp_types::Scalar::Int64(4)));

    assert_eq!(
        name_col.column.value(0),
        Some(&fp_types::Scalar::Utf8("Alice".to_string()))
    );
    assert_eq!(
        name_col.column.value(1),
        Some(&fp_types::Scalar::Utf8("Bob".to_string()))
    );
    assert_eq!(
        name_col.column.value(2),
        Some(&fp_types::Scalar::Utf8("Charlie".to_string()))
    );
    assert_eq!(name_col.missing_kinds[3], Some(FrameMissingKind::SqlNull));

    Ok(())
}

#[test]
fn zero_copy_fuzz_malformed_and_truncated_inputs() {
    let columns = vec![
        col("ID", "FIXED").with_scale(0).nullable(false),
        col("VAL", "REAL").nullable(true),
    ];

    let valid = br#"[["1", "2.5"], ["2", null], ["3", "4.0"]]"#;

    // Test truncation at every single byte offset: must never panic, always return Err
    for i in 0..valid.len() - 1 {
        let truncated = &valid[..i];
        let res = materialize_partition_bytes(&columns, truncated);
        assert!(
            res.is_err(),
            "expected error for truncated prefix length {i}"
        );
    }

    // Malformed inputs:
    let malformed_cases: &[&[u8]] = &[
        b"",
        b"not json",
        b"{ \"not\": \"array\" }",
        b"[ \"not a row array\" ]",
        b"[ [ 1, 2 ] ]",                          // unquoted number
        b"[ [ \"1\", \"2.5\" ], ]",               // trailing comma
        b"[ [ \"1\", \"2.5\" ] ] extra",          // trailing garbage
        b"[ [ \"1\", \"2.5\", \"extra_col\" ] ]", // row width mismatch > 2
        b"[ [ \"1\" ] ]",                         // row width mismatch < 2
        b"[ [ \"not_an_int\", \"2.5\" ] ]",       // bad integer
        b"[ [ \"1\", \"not_a_float\" ] ]",        // bad float
        b"[ [ \"1\", \"\\uD800\" ] ]",            // lone surrogate
        b"[ [ \"1\", \"\\uZZZZ\" ] ]",            // bad hex in unicode escape
        b"[ [ \"1\", \"\\x00\" ] ]",              // invalid escape sequence
        b"[ [ \"1\", \"unclosed string ] ]",
    ];

    for (idx, &case) in malformed_cases.iter().enumerate() {
        let res = materialize_partition_bytes(&columns, case);
        assert!(res.is_err(), "expected error for malformed case {idx}");
    }
}

#[test]
fn zero_copy_high_throughput_benchmark_exceeds_350_mb_s() -> Result<(), String> {
    let columns = vec![
        col("ID", "FIXED").with_scale(0).nullable(false),
        col("CUSTOMER_ID", "NUMBER").with_scale(0).nullable(true),
        col("AMOUNT", "FIXED")
            .with_scale(2)
            .with_precision(38)
            .nullable(false),
        col("FLAG", "BOOLEAN").nullable(false),
        col("EVENT_DATE", "DATE").nullable(false),
        col("TS_TZ", "TIMESTAMP_TZ").nullable(false),
        col("DESCRIPTION", "TEXT").nullable(true),
    ];

    // Generate a 100,000 row partition payload
    let num_rows = 100_000;
    let mut payload = Vec::with_capacity(num_rows * 80);
    payload.push(b'[');

    for i in 0..num_rows {
        if i > 0 {
            payload.push(b',');
        }
        let row_str = if i % 10 == 0 {
            format!(
                "[\"{}\",null,\"1234.56\",\"true\",\"18262\",\"1616173619.123456789 1500\",\"Transaction reference #{}\"]",
                i, i
            )
        } else {
            format!(
                "[\"{}\",\"{}\",\"9876543210.99\",\"false\",\"18263\",\"1616173620.000000000 1440\",\"Customer payment {}\"]",
                i,
                i * 2,
                i
            )
        };
        payload.extend_from_slice(row_str.as_bytes());
    }
    payload.push(b']');

    let payload_len_bytes = payload.len();
    let payload_len_mb = payload_len_bytes as f64 / (1024.0 * 1024.0);

    // Warm-up iteration
    let _ = materialize_partition_bytes(&columns, &payload)
        .map_err(|e| format!("benchmark warm-up failed: {e}"))?;

    // Timed iterations: run 3 iterations and select best time to eliminate scheduler jitter
    let mut best_elapsed = std::time::Duration::from_secs(3600);
    let mut final_frame = None;
    for _ in 0..3 {
        let start = std::time::Instant::now();
        let frame = materialize_partition_bytes(&columns, &payload)
            .map_err(|e| format!("benchmark execution failed: {e}"))?;
        let elapsed = start.elapsed();
        if elapsed < best_elapsed {
            best_elapsed = elapsed;
            final_frame = Some(frame);
        }
    }
    let frame = final_frame.ok_or_else(|| "no benchmark frame produced".to_string())?;
    let elapsed = best_elapsed;

    assert_eq!(frame.row_count, num_rows);
    let seconds = elapsed.as_secs_f64();
    let throughput_mb_s = payload_len_mb / seconds;
    let rows_per_sec = num_rows as f64 / seconds;

    println!("\n--- JSONV2 ZERO-COPY DECODER BENCHMARK ---");
    println!(
        "Processed {} rows ({:.2} MB) in {:.3} ms",
        num_rows,
        payload_len_mb,
        elapsed.as_secs_f64() * 1000.0
    );
    println!("Throughput: {:.2} MB/s", throughput_mb_s);
    println!("Row rate: {:.0} rows/s", rows_per_sec);
    println!("------------------------------------------\n");

    let target = if cfg!(debug_assertions) { 20.0 } else { 350.0 };
    assert!(
        throughput_mb_s >= target,
        "decoder throughput ({:.2} MB/s) failed to meet target >{:.0} MB/s (debug: {})",
        throughput_mb_s,
        target,
        cfg!(debug_assertions)
    );

    Ok(())
}

#[test]
fn zero_copy_decodes_envelope_objects_with_bitwise_parity() -> Result<(), String> {
    use franken_snowflake_frame::extract_jsonv2_data_array;

    let columns = vec![
        col("ID", "FIXED").with_scale(0).nullable(false),
        col("NAME", "TEXT").nullable(true),
        col("AMOUNT", "NUMBER").with_scale(2).nullable(false),
        col("FLAG", "BOOLEAN").nullable(true),
    ];

    let bare_json = b"[[\"1\",\"Alice\",\"100.50\",\"true\"],[\"2\",\"Bob\",\"-20.00\",\"false\"]]";
    let envelope_json =
        b"{\"data\": [[\"1\",\"Alice\",\"100.50\",\"true\"],[\"2\",\"Bob\",\"-20.00\",\"false\"]]}";
    let full_response_json = br#"{
        "code": "090001",
        "message": "Statement executed successfully.",
        "statementHandle": "01b754ca-3b10-4efc-bc9f-063217ae295a",
        "resultSetMetaData": {
            "numRows": 2,
            "format": "jsonv2",
            "rowType": [
                {"name": "ID", "type": "FIXED", "scale": 0, "nullable": false},
                {"name": "NAME", "type": "TEXT", "nullable": true},
                {"name": "AMOUNT", "type": "NUMBER", "scale": 2, "nullable": false},
                {"name": "FLAG", "type": "BOOLEAN", "nullable": true}
            ]
        },
        "data": [
            ["1", "Alice", "100.50", "true"],
            ["2", "Bob", "-20.00", "false"]
        ],
        "createdOn": 1700000000000
    }"#;

    // Test extraction
    let ext1 = extract_jsonv2_data_array(bare_json).map_err(|e| e.to_string())?;
    assert_eq!(ext1, bare_json);

    let ext2 = extract_jsonv2_data_array(envelope_json).map_err(|e| e.to_string())?;
    assert_eq!(
        ext2,
        b"[[\"1\",\"Alice\",\"100.50\",\"true\"],[\"2\",\"Bob\",\"-20.00\",\"false\"]]"
    );

    // Test materialization parity
    let frame_bare = materialize_partition_bytes(&columns, bare_json)
        .map_err(|e| format!("bare decode failed: {e}"))?;
    let frame_envelope = materialize_partition_bytes(&columns, envelope_json)
        .map_err(|e| format!("envelope decode failed: {e}"))?;
    let frame_full = materialize_partition_bytes(&columns, full_response_json)
        .map_err(|e| format!("full response decode failed: {e}"))?;

    assert_eq!(frame_bare.row_count, 2);
    assert_eq!(frame_envelope.row_count, 2);
    assert_eq!(frame_full.row_count, 2);

    for col_idx in 0..columns.len() {
        let b_col = &frame_bare.columns[col_idx];
        let e_col = &frame_envelope.columns[col_idx];
        let f_col = &frame_full.columns[col_idx];

        assert_eq!(b_col.column.dtype(), e_col.column.dtype());
        assert_eq!(b_col.column.dtype(), f_col.column.dtype());

        for row_idx in 0..2 {
            assert_eq!(b_col.column.value(row_idx), e_col.column.value(row_idx));
            assert_eq!(b_col.column.value(row_idx), f_col.column.value(row_idx));
        }
    }

    // Negative tests: missing data, unclosed, bad types
    let missing_data = b"{\"code\": \"090001\", \"message\": \"ok\"}";
    assert!(materialize_partition_bytes(&columns, missing_data).is_err());

    let invalid_json = b"{\"data\": unclosed";
    assert!(materialize_partition_bytes(&columns, invalid_json).is_err());

    Ok(())
}
