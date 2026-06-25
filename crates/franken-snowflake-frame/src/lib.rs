#![forbid(unsafe_code)]

//! `franken-snowflake-frame` -- optional frame materialization.
//!
//! The default crate has no FrankenPandas dependency. Enable the
//! `frankenpandas` feature to materialize Snowflake SQL API `jsonv2` result
//! partitions into `fp-columnar` columns using `fp-types` dtypes. This crate
//! deliberately depends on the focused `fp-columnar` and `fp-types` crates only:
//! never the umbrella `frankenpandas` crate and never `fp-io`.

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(feature = "frankenpandas")]
mod frankenpandas {
    use std::error::Error;
    use std::fmt;

    use fp_columnar::Column;
    use fp_types::{DType, NullKind, Scalar};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    const NANOS_PER_SECOND: i128 = 1_000_000_000;
    const SECONDS_PER_DAY: i128 = 86_400;

    /// Result alias for frame materialization.
    pub type FrameResult<T> = Result<T, FrameError>;

    /// A Snowflake result column as reported by `resultSetMetaData.rowType[]`.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SnowflakeColumn {
        /// Column name.
        pub name: String,
        /// Snowflake logical type, matched case-insensitively.
        pub snowflake_type: String,
        /// Decimal scale for `FIXED`/`NUMBER`.
        pub scale: Option<i32>,
        /// Decimal precision for `FIXED`/`NUMBER`.
        pub precision: Option<i32>,
        /// Whether Snowflake says the column is nullable.
        pub nullable: bool,
    }

    impl SnowflakeColumn {
        /// Construct a column descriptor.
        #[must_use]
        pub fn new(name: impl Into<String>, snowflake_type: impl Into<String>) -> Self {
            Self {
                name: name.into(),
                snowflake_type: snowflake_type.into(),
                scale: None,
                precision: None,
                nullable: true,
            }
        }

        /// Set the decimal scale.
        #[must_use]
        pub const fn with_scale(mut self, scale: i32) -> Self {
            self.scale = Some(scale);
            self
        }

        /// Set the decimal precision.
        #[must_use]
        pub const fn with_precision(mut self, precision: i32) -> Self {
            self.precision = Some(precision);
            self
        }

        /// Set nullability.
        #[must_use]
        pub const fn nullable(mut self, nullable: bool) -> Self {
            self.nullable = nullable;
            self
        }
    }

    /// One decoded/fetched result partition.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ResultPartition {
        /// Partition index. Partition 0 is the inline `ResultSet.data` payload.
        pub index: u32,
        /// Rows in this partition. Each non-null cell is a `jsonv2` string.
        pub rows: Vec<Vec<Option<String>>>,
    }

    impl ResultPartition {
        /// Build a partition.
        #[must_use]
        pub fn new(index: u32, rows: Vec<Vec<Option<String>>>) -> Self {
            Self { index, rows }
        }
    }

    /// Materialized frame: columnar data plus Snowflake logical metadata.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct FrankenPandasFrame {
        /// Number of rows across all partitions.
        pub row_count: usize,
        /// One column per `rowType[]` entry, preserving order.
        pub columns: Vec<FrameColumn>,
    }

    impl FrankenPandasFrame {
        /// Borrow a column by exact Snowflake column name.
        #[must_use]
        pub fn column(&self, name: &str) -> Option<&FrameColumn> {
            self.columns
                .iter()
                .find(|column| column.metadata.name == name)
        }
    }

    /// One materialized column.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct FrameColumn {
        /// Source and destination dtype metadata.
        pub metadata: FrameColumnMeta,
        /// `fp-columnar` storage buffer.
        pub column: Column,
        /// Missing-kind sidecar, preserving SQL NULL vs NaN vs NaT semantics.
        pub missing_kinds: Vec<Option<FrameMissingKind>>,
        /// Per-row `TIMESTAMP_TZ` offset sidecar. `None` for non-TIMESTAMP_TZ columns.
        pub timestamp_tz_offsets_minutes: Option<Vec<Option<i32>>>,
    }

    /// Column-level metadata retained alongside the lossy frame dtype.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct FrameColumnMeta {
        /// Column name.
        pub name: String,
        /// Snowflake logical type string as reported.
        pub snowflake_type: String,
        /// Normalized logical type.
        pub logical_type: SnowflakeLogicalType,
        /// Frame storage kind.
        pub storage_kind: FrameStorageKind,
        /// Destination `fp-types` dtype.
        pub fp_dtype: DType,
        /// Source scale, if any.
        pub scale: Option<i32>,
        /// Source precision, if any.
        pub precision: Option<i32>,
        /// Source nullability.
        pub nullable: bool,
    }

    impl FrameColumnMeta {
        fn from_snowflake(column: &SnowflakeColumn) -> Self {
            let logical_type = SnowflakeLogicalType::from_snowflake_type(&column.snowflake_type);
            let storage_kind = FrameStorageKind::from_logical(logical_type, column.scale);
            let fp_dtype = storage_kind.fp_dtype(column.nullable);
            Self {
                name: column.name.clone(),
                snowflake_type: column.snowflake_type.clone(),
                logical_type,
                storage_kind,
                fp_dtype,
                scale: column.scale,
                precision: column.precision,
                nullable: column.nullable,
            }
        }
    }

    /// Normalized Snowflake logical type.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum SnowflakeLogicalType {
        Fixed,
        Real,
        Text,
        Boolean,
        Date,
        Time,
        TimestampNtz,
        TimestampLtz,
        TimestampTz,
        Binary,
        StructuredJson,
        UnknownText,
    }

    impl SnowflakeLogicalType {
        fn from_snowflake_type(value: &str) -> Self {
            match value.to_ascii_uppercase().as_str() {
                "FIXED" | "NUMBER" | "DECIMAL" | "NUMERIC" | "INT" | "INTEGER" | "BIGINT"
                | "SMALLINT" | "TINYINT" | "BYTEINT" => Self::Fixed,
                "REAL" | "FLOAT" | "FLOAT4" | "FLOAT8" | "DOUBLE" | "DOUBLE PRECISION"
                | "DECFLOAT" => Self::Real,
                "TEXT" | "STRING" | "VARCHAR" | "CHAR" | "CHARACTER" => Self::Text,
                "BOOLEAN" | "BOOL" => Self::Boolean,
                "DATE" => Self::Date,
                "TIME" => Self::Time,
                "TIMESTAMP_NTZ" | "DATETIME" => Self::TimestampNtz,
                "TIMESTAMP_LTZ" => Self::TimestampLtz,
                "TIMESTAMP_TZ" => Self::TimestampTz,
                "BINARY" | "VARBINARY" => Self::Binary,
                "VARIANT" | "OBJECT" | "ARRAY" => Self::StructuredJson,
                _ => Self::UnknownText,
            }
        }
    }

    /// Destination storage class.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum FrameStorageKind {
        Int64,
        Float64,
        Bool,
        Utf8,
        Datetime64,
        StructuredJson,
        BinaryHex,
    }

    impl FrameStorageKind {
        fn from_logical(logical_type: SnowflakeLogicalType, scale: Option<i32>) -> Self {
            match logical_type {
                SnowflakeLogicalType::Fixed if scale.unwrap_or(0) == 0 => Self::Int64,
                SnowflakeLogicalType::Fixed | SnowflakeLogicalType::Real => Self::Float64,
                SnowflakeLogicalType::Boolean => Self::Bool,
                SnowflakeLogicalType::Date
                | SnowflakeLogicalType::Time
                | SnowflakeLogicalType::TimestampNtz
                | SnowflakeLogicalType::TimestampLtz
                | SnowflakeLogicalType::TimestampTz => Self::Datetime64,
                SnowflakeLogicalType::StructuredJson => Self::StructuredJson,
                SnowflakeLogicalType::Binary => Self::BinaryHex,
                SnowflakeLogicalType::Text | SnowflakeLogicalType::UnknownText => Self::Utf8,
            }
        }

        fn fp_dtype(self, nullable: bool) -> DType {
            match self {
                Self::Int64 if nullable => DType::Int64Nullable,
                Self::Int64 => DType::Int64,
                Self::Bool if nullable => DType::BoolNullable,
                Self::Bool => DType::Bool,
                Self::Float64 => DType::Float64,
                Self::Datetime64 => DType::Datetime64,
                Self::Utf8 | Self::StructuredJson | Self::BinaryHex => DType::Utf8,
            }
        }
    }

    /// Missing-value sidecar.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum FrameMissingKind {
        SqlNull,
        NaN,
        NaT,
    }

    /// Frame materialization failure.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum FrameError {
        RowWidthMismatch {
            partition_index: u32,
            row_index: usize,
            expected: usize,
            actual: usize,
        },
        RowCountOverflow,
        Decode {
            column: String,
            snowflake_type: String,
            reason: &'static str,
        },
        TimestampOutOfRange {
            column: String,
        },
        ColumnBuild {
            column: String,
            message: String,
        },
    }

    impl fmt::Display for FrameError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::RowWidthMismatch {
                    partition_index,
                    row_index,
                    expected,
                    actual,
                } => write!(
                    f,
                    "partition {partition_index} row {row_index} has width {actual}, expected {expected}"
                ),
                Self::RowCountOverflow => write!(f, "frame row count overflow"),
                Self::Decode {
                    column,
                    snowflake_type,
                    reason,
                } => write!(
                    f,
                    "jsonv2 frame decode failed for column {column:?} ({snowflake_type}): {reason}"
                ),
                Self::TimestampOutOfRange { column } => {
                    write!(
                        f,
                        "timestamp in column {column:?} is outside datetime64[ns] range"
                    )
                }
                Self::ColumnBuild { column, message } => {
                    write!(f, "failed to build frame column {column:?}: {message}")
                }
            }
        }
    }

    impl Error for FrameError {}

    struct MaterializedCell {
        scalar: Scalar,
        missing_kind: Option<FrameMissingKind>,
        timestamp_tz_offset_minutes: Option<i32>,
    }

    /// Materialize ordered result partitions into an `fp-columnar` frame.
    ///
    /// Decoding is driven exclusively by `columns` (`resultSetMetaData.rowType[]`),
    /// never by row value inspection.
    pub fn materialize_partitions<I>(
        columns: &[SnowflakeColumn],
        partitions: I,
    ) -> FrameResult<FrankenPandasFrame>
    where
        I: IntoIterator<Item = ResultPartition>,
    {
        let metadata = columns
            .iter()
            .map(FrameColumnMeta::from_snowflake)
            .collect::<Vec<_>>();
        let mut column_values = vec![Vec::<Scalar>::new(); metadata.len()];
        let mut missing_kinds = vec![Vec::<Option<FrameMissingKind>>::new(); metadata.len()];
        let mut timestamp_tz_offsets = metadata
            .iter()
            .map(|meta| {
                matches!(meta.logical_type, SnowflakeLogicalType::TimestampTz)
                    .then(Vec::<Option<i32>>::new)
            })
            .collect::<Vec<_>>();
        let mut row_count = 0usize;

        for partition in partitions {
            for (row_index, row) in partition.rows.iter().enumerate() {
                if row.len() != metadata.len() {
                    return Err(FrameError::RowWidthMismatch {
                        partition_index: partition.index,
                        row_index,
                        expected: metadata.len(),
                        actual: row.len(),
                    });
                }
                row_count = row_count
                    .checked_add(1)
                    .ok_or(FrameError::RowCountOverflow)?;
                for (column_index, raw) in row.iter().enumerate() {
                    let cell = materialize_cell(
                        raw.as_deref(),
                        &columns[column_index],
                        &metadata[column_index],
                    )?;
                    column_values[column_index].push(cell.scalar);
                    missing_kinds[column_index].push(cell.missing_kind);
                    if let Some(offsets) = &mut timestamp_tz_offsets[column_index] {
                        offsets.push(cell.timestamp_tz_offset_minutes);
                    }
                }
            }
        }

        let mut frame_columns = Vec::with_capacity(metadata.len());
        for ((meta, values), (missing, offsets)) in metadata
            .into_iter()
            .zip(column_values)
            .zip(missing_kinds.into_iter().zip(timestamp_tz_offsets))
        {
            let name = meta.name.clone();
            let column =
                Column::new(meta.fp_dtype, values).map_err(|err| FrameError::ColumnBuild {
                    column: name,
                    message: err.to_string(),
                })?;
            frame_columns.push(FrameColumn {
                metadata: meta,
                column,
                missing_kinds: missing,
                timestamp_tz_offsets_minutes: offsets,
            });
        }

        Ok(FrankenPandasFrame {
            row_count,
            columns: frame_columns,
        })
    }

    fn materialize_cell(
        raw: Option<&str>,
        source: &SnowflakeColumn,
        meta: &FrameColumnMeta,
    ) -> FrameResult<MaterializedCell> {
        let Some(text) = raw else {
            return Ok(MaterializedCell {
                scalar: Scalar::Null(NullKind::Null),
                missing_kind: Some(FrameMissingKind::SqlNull),
                timestamp_tz_offset_minutes: None,
            });
        };

        let scalar = match meta.logical_type {
            SnowflakeLogicalType::Fixed if meta.storage_kind == FrameStorageKind::Int64 => {
                Scalar::Int64(parse_scale0_int(text).ok_or_else(|| {
                    decode_error(source, "FIXED/NUMBER scale 0 must be an integer decimal")
                })?)
            }
            SnowflakeLogicalType::Fixed | SnowflakeLogicalType::Real => {
                let value = text
                    .parse::<f64>()
                    .map_err(|_| decode_error(source, "expected a numeric decimal string"))?;
                return Ok(MaterializedCell {
                    scalar: Scalar::Float64(value),
                    missing_kind: value.is_nan().then_some(FrameMissingKind::NaN),
                    timestamp_tz_offset_minutes: None,
                });
            }
            SnowflakeLogicalType::Boolean => match text {
                "true" => Scalar::Bool(true),
                "false" => Scalar::Bool(false),
                _ => {
                    return Err(decode_error(
                        source,
                        "BOOLEAN must be \"true\" or \"false\"",
                    ));
                }
            },
            SnowflakeLogicalType::Date => {
                let days = text
                    .parse::<i64>()
                    .map_err(|_| decode_error(source, "DATE must be epoch days"))?;
                Scalar::Datetime64(days_to_nanos(days, source)?)
            }
            SnowflakeLogicalType::Time
            | SnowflakeLogicalType::TimestampNtz
            | SnowflakeLogicalType::TimestampLtz => {
                let (seconds, nanos) = parse_fractional_seconds(text)
                    .ok_or_else(|| decode_error(source, "expected fractional epoch seconds"))?;
                Scalar::Datetime64(seconds_to_nanos(seconds, nanos, source)?)
            }
            SnowflakeLogicalType::TimestampTz => {
                let (seconds_part, offset_part) = text.split_once(' ').ok_or_else(|| {
                    decode_error(source, "TIMESTAMP_TZ must be \"<seconds> <offset>\"")
                })?;
                let (seconds, nanos) = parse_fractional_seconds(seconds_part)
                    .ok_or_else(|| decode_error(source, "expected fractional epoch seconds"))?;
                let encoded_offset = offset_part
                    .parse::<i32>()
                    .map_err(|_| decode_error(source, "TIMESTAMP_TZ offset must be an integer"))?;
                return Ok(MaterializedCell {
                    scalar: Scalar::Datetime64(seconds_to_nanos(seconds, nanos, source)?),
                    missing_kind: None,
                    timestamp_tz_offset_minutes: Some(encoded_offset - 1440),
                });
            }
            SnowflakeLogicalType::Binary => {
                if !is_even_hex(text) {
                    return Err(decode_error(
                        source,
                        "BINARY must be an even-length hex string",
                    ));
                }
                Scalar::Utf8(text.to_owned())
            }
            SnowflakeLogicalType::StructuredJson => {
                let value = serde_json::from_str::<Value>(text)
                    .map_err(|_| decode_error(source, "semi-structured cell must be JSON"))?;
                Scalar::Utf8(value.to_string())
            }
            SnowflakeLogicalType::Text | SnowflakeLogicalType::UnknownText => {
                Scalar::Utf8(text.to_owned())
            }
        };

        Ok(MaterializedCell {
            scalar,
            missing_kind: None,
            timestamp_tz_offset_minutes: None,
        })
    }

    fn decode_error(source: &SnowflakeColumn, reason: &'static str) -> FrameError {
        FrameError::Decode {
            column: source.name.clone(),
            snowflake_type: source.snowflake_type.clone(),
            reason,
        }
    }

    fn parse_scale0_int(text: &str) -> Option<i64> {
        if let Some((int_part, frac_part)) = text.split_once('.') {
            if frac_part.bytes().all(|byte| byte == b'0') {
                return int_part.parse::<i64>().ok();
            }
            return None;
        }
        text.parse::<i64>().ok()
    }

    fn parse_fractional_seconds(text: &str) -> Option<(i64, u32)> {
        let negative = text.starts_with('-');
        let (int_str, frac_nanos) = match text.split_once('.') {
            Some((int_str, frac)) => (int_str, frac_to_nanos(frac)?),
            None => (text, 0),
        };
        let int_part = int_str.parse::<i64>().ok()?;
        if !negative || frac_nanos == 0 {
            Some((int_part, frac_nanos))
        } else {
            Some((int_part.checked_sub(1)?, 1_000_000_000 - frac_nanos))
        }
    }

    fn frac_to_nanos(frac: &str) -> Option<u32> {
        if frac.is_empty() || !frac.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let mut nanos = String::with_capacity(9);
        nanos.extend(frac.chars().take(9));
        while nanos.len() < 9 {
            nanos.push('0');
        }
        nanos.parse::<u32>().ok()
    }

    fn days_to_nanos(days: i64, source: &SnowflakeColumn) -> FrameResult<i64> {
        checked_i128_to_i64(
            i128::from(days) * SECONDS_PER_DAY * NANOS_PER_SECOND,
            source,
        )
    }

    fn seconds_to_nanos(seconds: i64, nanos: u32, source: &SnowflakeColumn) -> FrameResult<i64> {
        checked_i128_to_i64(
            i128::from(seconds) * NANOS_PER_SECOND + i128::from(nanos),
            source,
        )
    }

    fn checked_i128_to_i64(value: i128, source: &SnowflakeColumn) -> FrameResult<i64> {
        i64::try_from(value).map_err(|_| FrameError::TimestampOutOfRange {
            column: source.name.clone(),
        })
    }

    fn is_even_hex(text: &str) -> bool {
        text.len() % 2 == 0 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn col(name: &str, snowflake_type: &str) -> SnowflakeColumn {
            SnowflakeColumn::new(name, snowflake_type)
        }

        fn frame_column<'a>(
            frame: &'a FrankenPandasFrame,
            name: &str,
        ) -> Result<&'a FrameColumn, String> {
            frame
                .column(name)
                .ok_or_else(|| format!("missing column {name}"))
        }

        #[test]
        fn maps_snowflake_types_to_destination_dtypes() {
            let cases = [
                (
                    col("A", "FIXED").with_scale(0).nullable(false),
                    SnowflakeLogicalType::Fixed,
                    FrameStorageKind::Int64,
                    DType::Int64,
                ),
                (
                    col("B", "FIXED").with_scale(0).nullable(true),
                    SnowflakeLogicalType::Fixed,
                    FrameStorageKind::Int64,
                    DType::Int64Nullable,
                ),
                (
                    col("C", "FIXED").with_scale(2),
                    SnowflakeLogicalType::Fixed,
                    FrameStorageKind::Float64,
                    DType::Float64,
                ),
                (
                    col("D", "REAL"),
                    SnowflakeLogicalType::Real,
                    FrameStorageKind::Float64,
                    DType::Float64,
                ),
                (
                    col("E", "TEXT"),
                    SnowflakeLogicalType::Text,
                    FrameStorageKind::Utf8,
                    DType::Utf8,
                ),
                (
                    col("F", "BOOLEAN"),
                    SnowflakeLogicalType::Boolean,
                    FrameStorageKind::Bool,
                    DType::BoolNullable,
                ),
                (
                    col("G", "DATE"),
                    SnowflakeLogicalType::Date,
                    FrameStorageKind::Datetime64,
                    DType::Datetime64,
                ),
                (
                    col("H", "TIME"),
                    SnowflakeLogicalType::Time,
                    FrameStorageKind::Datetime64,
                    DType::Datetime64,
                ),
                (
                    col("I", "TIMESTAMP_TZ"),
                    SnowflakeLogicalType::TimestampTz,
                    FrameStorageKind::Datetime64,
                    DType::Datetime64,
                ),
                (
                    col("J", "VARIANT"),
                    SnowflakeLogicalType::StructuredJson,
                    FrameStorageKind::StructuredJson,
                    DType::Utf8,
                ),
                (
                    col("K", "BINARY"),
                    SnowflakeLogicalType::Binary,
                    FrameStorageKind::BinaryHex,
                    DType::Utf8,
                ),
            ];

            for (source, logical, storage, dtype) in cases {
                let meta = FrameColumnMeta::from_snowflake(&source);
                assert_eq!(meta.logical_type, logical);
                assert_eq!(meta.storage_kind, storage);
                assert_eq!(meta.fp_dtype, dtype);
            }
        }

        #[test]
        fn materializes_multi_partition_jsonv2_rows() -> Result<(), String> {
            let columns = vec![
                col("ID", "FIXED").with_scale(0).nullable(false),
                col("AMOUNT", "FIXED").with_scale(2),
                col("FLAG", "BOOLEAN"),
                col("DATE_COL", "DATE"),
                col("TS_TZ", "TIMESTAMP_TZ"),
                col("PAYLOAD", "VARIANT"),
                col("BIN", "BINARY"),
            ];
            let partitions = vec![
                ResultPartition::new(
                    0,
                    vec![vec![
                        Some("1".to_owned()),
                        Some("12.34".to_owned()),
                        Some("true".to_owned()),
                        Some("1".to_owned()),
                        Some("82919.000000001 960".to_owned()),
                        Some("{\"a\":1}".to_owned()),
                        Some("0A0b".to_owned()),
                    ]],
                ),
                ResultPartition::new(
                    1,
                    vec![vec![
                        Some("2".to_owned()),
                        None,
                        None,
                        Some("2".to_owned()),
                        Some("-0.5 1440".to_owned()),
                        Some("[1,2]".to_owned()),
                        Some("ff".to_owned()),
                    ]],
                ),
            ];

            let frame = materialize_partitions(&columns, partitions).map_err(|e| e.to_string())?;
            assert_eq!(frame.row_count, 2);
            assert_eq!(frame.columns.len(), 7);

            let id = frame_column(&frame, "ID")?;
            assert_eq!(id.column.dtype(), DType::Int64);
            assert_eq!(id.column.value(0), Some(&Scalar::Int64(1)));
            assert_eq!(id.column.value(1), Some(&Scalar::Int64(2)));

            let amount = frame_column(&frame, "AMOUNT")?;
            assert_eq!(amount.column.dtype(), DType::Float64);
            assert_eq!(amount.column.value(0), Some(&Scalar::Float64(12.34)));
            assert_eq!(amount.missing_kinds[1], Some(FrameMissingKind::SqlNull));

            let date = frame_column(&frame, "DATE_COL")?;
            assert_eq!(
                date.column.value(0),
                Some(&Scalar::Datetime64(86_400_000_000_000))
            );

            let ts = frame_column(&frame, "TS_TZ")?;
            assert_eq!(
                ts.timestamp_tz_offsets_minutes.as_ref(),
                Some(&vec![Some(-480), Some(0)])
            );
            assert_eq!(ts.column.value(1), Some(&Scalar::Datetime64(-500_000_000)));

            let payload = frame_column(&frame, "PAYLOAD")?;
            assert_eq!(
                payload.column.value(0),
                Some(&Scalar::Utf8("{\"a\":1}".to_owned()))
            );
            assert_eq!(
                payload.column.value(1),
                Some(&Scalar::Utf8("[1,2]".to_owned()))
            );

            let binary = frame_column(&frame, "BIN")?;
            assert_eq!(binary.metadata.storage_kind, FrameStorageKind::BinaryHex);
            assert_eq!(
                binary.column.value(0),
                Some(&Scalar::Utf8("0A0b".to_owned()))
            );

            Ok(())
        }

        #[test]
        fn separates_sql_null_nan_and_nat_storage() -> Result<(), String> {
            let columns = vec![col("F", "REAL"), col("T", "TIMESTAMP_NTZ")];
            let partitions = vec![ResultPartition::new(
                0,
                vec![
                    vec![None, None],
                    vec![Some("NaN".to_owned()), Some("0.000000001".to_owned())],
                ],
            )];

            let frame = materialize_partitions(&columns, partitions).map_err(|e| e.to_string())?;
            let floats = frame_column(&frame, "F")?;
            assert_eq!(floats.missing_kinds[0], Some(FrameMissingKind::SqlNull));
            assert_eq!(floats.missing_kinds[1], Some(FrameMissingKind::NaN));
            match floats.column.value(1) {
                Some(Scalar::Float64(value)) => assert!(value.is_nan()),
                other => return Err(format!("expected NaN float, got {other:?}")),
            }

            let timestamps = frame_column(&frame, "T")?;
            assert_eq!(timestamps.missing_kinds[0], Some(FrameMissingKind::SqlNull));
            assert_eq!(
                timestamps.column.value(0),
                Some(&Scalar::Datetime64(i64::MIN))
            );
            assert_eq!(timestamps.column.value(1), Some(&Scalar::Datetime64(1)));
            assert_eq!(FrameMissingKind::NaT, FrameMissingKind::NaT);
            Ok(())
        }

        #[test]
        fn rejects_malformed_rows_and_cells() {
            let columns = vec![col("B", "BINARY")];
            let bad_width = materialize_partitions(
                &columns,
                vec![ResultPartition::new(
                    0,
                    vec![vec![Some("ff".to_owned()), None]],
                )],
            );
            assert!(matches!(
                bad_width,
                Err(FrameError::RowWidthMismatch { .. })
            ));

            let bad_binary = materialize_partitions(
                &columns,
                vec![ResultPartition::new(0, vec![vec![Some("abc".to_owned())]])],
            );
            assert!(matches!(bad_binary, Err(FrameError::Decode { .. })));
        }
    }
}

#[cfg(feature = "frankenpandas")]
pub use frankenpandas::*;
