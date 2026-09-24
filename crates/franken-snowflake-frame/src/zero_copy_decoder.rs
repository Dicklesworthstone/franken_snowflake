use fp_columnar::{Column, ValidityMask};
use fp_types::{DType, Scalar};

use crate::frankenpandas::{
    FrameColumn, FrameColumnMeta, FrameError, FrameMissingKind, FrameResult, FrameStorageKind,
    FrankenPandasFrame, SnowflakeColumn, SnowflakeLogicalType, days_to_nanos, decode_error,
    is_even_hex, is_fixed_decimal, seconds_to_nanos,
};

/// A raw result partition referencing uncompressed `jsonv2` bytes directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawResultPartition<'a> {
    /// Partition index. Partition 0 is the inline `ResultSet.data` payload.
    pub index: u32,
    /// Raw uncompressed JSON 2D-array byte slice, e.g. `b"[[\"1\", \"val\"], ...]"`
    pub bytes: &'a [u8],
}

impl<'a> RawResultPartition<'a> {
    /// Construct a raw partition reference.
    #[must_use]
    pub const fn new(index: u32, bytes: &'a [u8]) -> Self {
        Self { index, bytes }
    }
}

/// A borrowed or unescaped cell slice scanned directly from the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellSlice<'a> {
    /// JSON `null`.
    Null,
    /// JSON string without escapes, pointing directly into the input byte buffer (100% zero copy).
    Borrowed(&'a str),
    /// JSON string containing escape sequences (`\"`, `\n`, etc.), unescaped into scanner scratch.
    Unescaped(&'a str),
}

impl<'a> CellSlice<'a> {
    /// Return the string slice if non-null.
    #[must_use]
    pub const fn as_str(&self) -> Option<&'a str> {
        match *self {
            Self::Null => None,
            Self::Borrowed(s) | Self::Unescaped(s) => Some(s),
        }
    }
}

/// Fast streaming byte scanner for Snowflake SQL API `jsonv2` 2D arrays.
#[inline(always)]
fn skip_json_string(bytes: &[u8], mut pos: usize) -> Option<usize> {
    let len = bytes.len();
    while pos < len {
        let rel = find_quote_or_escape(&bytes[pos..])?;
        let hit = pos + rel;
        if bytes[hit] == b'"' {
            return Some(hit + 1);
        } else if bytes[hit] == b'\\' {
            pos = hit + 2;
        } else {
            pos = hit + 1;
        }
    }
    None
}

/// Extract the raw `jsonv2` 2D array byte slice from either a bare array (`[[...]]`)
/// or a Snowflake SQL API response envelope containing a top-level `"data"` array
/// (`{"data": [[...]]}` or `{"resultSetMetaData": {...}, "data": [[...]]}`).
///
/// Operates directly on the input byte slice with zero heap allocations.
pub fn extract_jsonv2_data_array(bytes: &[u8]) -> FrameResult<&[u8]> {
    let len = bytes.len();
    let pos = skip_whitespace(bytes, 0);
    if pos >= len {
        return Err(FrameError::Decode {
            column: String::new(),
            snowflake_type: String::new(),
            reason: "unexpected EOF: expected '[' or '{' at start of jsonv2 payload",
        });
    }

    match bytes[pos] {
        b'[' => Ok(&bytes[pos..]),
        b'{' => {
            let mut curr = pos + 1;
            let mut depth = 1usize;
            while curr < len && depth > 0 {
                curr = skip_whitespace(bytes, curr);
                if curr >= len {
                    break;
                }
                match bytes[curr] {
                    b'"' => {
                        let str_start = curr + 1;
                        let after_quote = skip_json_string(bytes, str_start).ok_or_else(|| {
                            FrameError::Decode {
                                column: String::new(),
                                snowflake_type: String::new(),
                                reason: "unterminated string in jsonv2 envelope",
                            }
                        })?;
                        let str_end = after_quote - 1;
                        let key_bytes = &bytes[str_start..str_end];
                        curr = after_quote;

                        if depth == 1 && key_bytes == b"data" {
                            curr = skip_whitespace(bytes, curr);
                            if curr >= len || bytes[curr] != b':' {
                                return Err(FrameError::Decode {
                                    column: String::new(),
                                    snowflake_type: String::new(),
                                    reason: "expected ':' after 'data' key in envelope",
                                });
                            }
                            curr += 1;
                            curr = skip_whitespace(bytes, curr);
                            if curr >= len || bytes[curr] != b'[' {
                                return Err(FrameError::Decode {
                                    column: String::new(),
                                    snowflake_type: String::new(),
                                    reason: "expected '[' at start of 'data' array in envelope",
                                });
                            }
                            let array_start = curr;
                            let mut arr_depth = 1usize;
                            curr += 1;
                            while curr < len && arr_depth > 0 {
                                match bytes[curr] {
                                    b'"' => {
                                        curr = skip_json_string(bytes, curr + 1).ok_or_else(
                                            || FrameError::Decode {
                                                column: String::new(),
                                                snowflake_type: String::new(),
                                                reason: "unterminated string inside 'data' array",
                                            },
                                        )?;
                                    }
                                    b'[' => {
                                        arr_depth += 1;
                                        curr += 1;
                                    }
                                    b']' => {
                                        arr_depth -= 1;
                                        curr += 1;
                                    }
                                    _ => {
                                        curr += 1;
                                    }
                                }
                            }
                            if arr_depth != 0 {
                                return Err(FrameError::Decode {
                                    column: String::new(),
                                    snowflake_type: String::new(),
                                    reason: "unclosed 'data' array in envelope",
                                });
                            }
                            let array_end = curr;
                            return Ok(&bytes[array_start..array_end]);
                        }
                    }
                    b'{' => {
                        depth += 1;
                        curr += 1;
                    }
                    b'}' => {
                        depth -= 1;
                        curr += 1;
                    }
                    _ => {
                        curr += 1;
                    }
                }
            }
            Err(FrameError::Decode {
                column: String::new(),
                snowflake_type: String::new(),
                reason: "missing 'data' array in jsonv2 envelope object",
            })
        }
        _ => Err(FrameError::Decode {
            column: String::new(),
            snowflake_type: String::new(),
            reason: "expected '[' or '{' at start of jsonv2 payload",
        }),
    }
}

/// Fast streaming byte scanner for Snowflake SQL API `jsonv2` 2D arrays.
///
/// Operates directly on `&'a [u8]` without intermediate `serde_json::Value` or
/// per-cell `String` allocations. Uses SWAR (SIMD Within A Register) chunk
/// scanning to locate string delimiters and escapes at multiple gigabytes per second.
#[derive(Debug, Default)]
pub struct ZeroCopyJsonv2Scanner {
    scratch: Vec<u8>,
}

impl ZeroCopyJsonv2Scanner {
    /// Create a new scanner with preallocated scratch buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scratch: Vec::with_capacity(256),
        }
    }

    /// Stream all rows from a `jsonv2` byte slice, calling `visit_row` with each row's cells.
    ///
    /// Accepts either a bare 2D JSON array (`[[...]]`) or an envelope object containing
    /// a `"data"` array (`{"data": [[...]]}`), operating with zero allocations.
    pub fn scan_rows<F>(
        &mut self,
        bytes: &[u8],
        partition_index: u32,
        expected_columns: usize,
        mut visit_cell: F,
    ) -> FrameResult<usize>
    where
        F: FnMut(usize, usize, CellSlice<'_>) -> FrameResult<()>,
    {
        let bytes = extract_jsonv2_data_array(bytes)?;
        let len = bytes.len();
        let mut pos = skip_whitespace(bytes, 0);
        if pos >= len {
            return Err(FrameError::Decode {
                column: String::new(),
                snowflake_type: String::new(),
                reason: "unexpected EOF: expected '[' at start of jsonv2 array",
            });
        }

        if bytes[pos] != b'[' {
            return Err(FrameError::Decode {
                column: String::new(),
                snowflake_type: String::new(),
                reason: "expected '[' at start of jsonv2 array",
            });
        }
        pos += 1;
        pos = skip_whitespace(bytes, pos);
        if pos >= len {
            return Err(FrameError::Decode {
                column: String::new(),
                snowflake_type: String::new(),
                reason: "unexpected EOF: unclosed '[' at start of jsonv2 array",
            });
        }
        if bytes[pos] == b']' {
            pos += 1;
            pos = skip_whitespace(bytes, pos);
            if pos < len {
                return Err(FrameError::Decode {
                    column: String::new(),
                    snowflake_type: String::new(),
                    reason: "trailing bytes after jsonv2 array closure",
                });
            }
            return Ok(0);
        }

        let mut row_index = 0usize;
        let mut closed = false;

        while pos < len {
            if bytes[pos] != b'[' {
                return Err(FrameError::Decode {
                    column: String::new(),
                    snowflake_type: String::new(),
                    reason: "expected '[' at start of jsonv2 row",
                });
            }
            pos += 1;
            pos = skip_whitespace(bytes, pos);

            let mut col_index = 0usize;
            if pos < len && bytes[pos] == b']' {
                // Empty row `[]`
                if expected_columns != 0 {
                    return Err(FrameError::RowWidthMismatch {
                        partition_index,
                        row_index,
                        expected: expected_columns,
                        actual: 0,
                    });
                }
                pos += 1;
            } else {
                loop {
                    if pos >= len {
                        return Err(FrameError::Decode {
                            column: String::new(),
                            snowflake_type: String::new(),
                            reason: "unexpected EOF in jsonv2 row",
                        });
                    }

                    let cell = match bytes[pos] {
                        b'n' => {
                            if pos + 4 <= len && match_null(&bytes[pos..pos + 4]) {
                                pos += 4;
                                CellSlice::Null
                            } else {
                                return Err(FrameError::Decode {
                                    column: String::new(),
                                    snowflake_type: String::new(),
                                    reason: "invalid null literal in cell",
                                });
                            }
                        }
                        b'"' => {
                            pos += 1;
                            let start = pos;
                            let hit = find_quote_or_escape(&bytes[pos..]);
                            let Some(rel_hit) = hit else {
                                return Err(FrameError::Decode {
                                    column: String::new(),
                                    snowflake_type: String::new(),
                                    reason: "unterminated string quote in cell",
                                });
                            };

                            if bytes[pos + rel_hit] == b'"' {
                                // Zero-copy fast path: no escapes in this string
                                let cell_bytes = &bytes[start..pos + rel_hit];
                                pos += rel_hit + 1; // skip past closing quote
                                let cell_str = core::str::from_utf8(cell_bytes).map_err(|_| {
                                    FrameError::Decode {
                                        column: String::new(),
                                        snowflake_type: String::new(),
                                        reason: "invalid UTF-8 in cell string",
                                    }
                                })?;
                                CellSlice::Borrowed(cell_str)
                            } else {
                                // Escape sequence encountered: unescape into scratch
                                self.scratch.clear();
                                self.scratch.extend_from_slice(&bytes[start..pos + rel_hit]);
                                pos += rel_hit;
                                pos = decode_escapes_into(bytes, pos, &mut self.scratch)?;
                                let cell_str =
                                    core::str::from_utf8(&self.scratch).map_err(|_| {
                                        FrameError::Decode {
                                            column: String::new(),
                                            snowflake_type: String::new(),
                                            reason: "invalid UTF-8 after unescaping cell string",
                                        }
                                    })?;
                                CellSlice::Unescaped(cell_str)
                            }
                        }
                        _ => {
                            return Err(FrameError::Decode {
                                column: String::new(),
                                snowflake_type: String::new(),
                                reason: "unexpected token in jsonv2 cell: expected '\"' or 'null'",
                            });
                        }
                    };

                    if col_index >= expected_columns {
                        return Err(FrameError::RowWidthMismatch {
                            partition_index,
                            row_index,
                            expected: expected_columns,
                            actual: col_index + 1,
                        });
                    }

                    visit_cell(row_index, col_index, cell)?;
                    col_index += 1;

                    pos = skip_whitespace(bytes, pos);
                    if pos >= len {
                        return Err(FrameError::Decode {
                            column: String::new(),
                            snowflake_type: String::new(),
                            reason: "unexpected EOF after cell",
                        });
                    }

                    match bytes[pos] {
                        b',' => {
                            pos += 1;
                            pos = skip_whitespace(bytes, pos);
                        }
                        b']' => {
                            pos += 1;
                            break;
                        }
                        _ => {
                            return Err(FrameError::Decode {
                                column: String::new(),
                                snowflake_type: String::new(),
                                reason: "expected ',' or ']' after cell",
                            });
                        }
                    }
                }

                if col_index != expected_columns {
                    return Err(FrameError::RowWidthMismatch {
                        partition_index,
                        row_index,
                        expected: expected_columns,
                        actual: col_index,
                    });
                }
            }

            row_index = row_index
                .checked_add(1)
                .ok_or(FrameError::RowCountOverflow)?;

            pos = skip_whitespace(bytes, pos);
            if pos >= len {
                return Err(FrameError::Decode {
                    column: String::new(),
                    snowflake_type: String::new(),
                    reason: "unexpected EOF after row",
                });
            }

            match bytes[pos] {
                b',' => {
                    pos += 1;
                    pos = skip_whitespace(bytes, pos);
                }
                b']' => {
                    pos += 1;
                    closed = true;
                    break;
                }
                _ => {
                    return Err(FrameError::Decode {
                        column: String::new(),
                        snowflake_type: String::new(),
                        reason: "expected ',' or ']' after row",
                    });
                }
            }
        }

        if !closed {
            return Err(FrameError::Decode {
                column: String::new(),
                snowflake_type: String::new(),
                reason: "unexpected EOF: unclosed jsonv2 outer array",
            });
        }

        pos = skip_whitespace(bytes, pos);
        if pos < len {
            return Err(FrameError::Decode {
                column: String::new(),
                snowflake_type: String::new(),
                reason: "trailing bytes after jsonv2 array closure",
            });
        }

        Ok(row_index)
    }
}

/// Bitwise validity mask builder backed by contiguous `u64` words.
#[derive(Clone, Debug)]
pub struct ValidityBuilder {
    words: Vec<u64>,
    len: usize,
    all_valid: bool,
}

impl ValidityBuilder {
    /// Preallocate storage for `capacity` rows.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            words: vec![0_u64; capacity.div_ceil(64)],
            len: 0,
            all_valid: true,
        }
    }

    /// Record a valid (non-null) row slot.
    #[inline(always)]
    pub fn push_valid(&mut self) {
        let word_idx = self.len >> 6;
        let bit_idx = self.len & 63;
        if word_idx < self.words.len() {
            self.words[word_idx] |= 1_u64 << bit_idx;
        } else {
            self.words.push(1_u64 << bit_idx);
        }
        self.len += 1;
    }

    /// Record a null (invalid) row slot.
    #[inline(always)]
    pub fn push_null(&mut self) {
        let word_idx = self.len >> 6;
        if word_idx >= self.words.len() {
            self.words.push(0);
        }
        self.all_valid = false;
        self.len += 1;
    }

    /// Finish building and construct the `fp_columnar::ValidityMask`.
    #[must_use]
    pub fn finish(mut self) -> ValidityMask {
        if self.len == 0 {
            return ValidityMask::all_valid(0);
        }
        if self.all_valid {
            ValidityMask::all_valid(self.len)
        } else {
            self.words.truncate(self.len.div_ceil(64));
            ValidityMask::from_words(self.words, self.len)
        }
    }
}

/// Column builder for Int64 and Int64Nullable storage.
struct Int64Builder {
    values: Vec<i64>,
    validity: ValidityBuilder,
    missing_kinds: Vec<Option<FrameMissingKind>>,
    is_nullable: bool,
}

impl Int64Builder {
    fn with_capacity(capacity: usize, is_nullable: bool) -> Self {
        Self {
            values: Vec::with_capacity(capacity),
            validity: ValidityBuilder::with_capacity(capacity),
            missing_kinds: Vec::with_capacity(capacity),
            is_nullable,
        }
    }

    fn push_null(&mut self) {
        self.values.push(0);
        self.validity.push_null();
        self.missing_kinds.push(Some(FrameMissingKind::SqlNull));
    }

    fn push_value(&mut self, val: i64) {
        self.values.push(val);
        self.validity.push_valid();
        self.missing_kinds.push(None);
    }

    fn finish(self) -> (Column, Vec<Option<FrameMissingKind>>) {
        let mask = self.validity.finish();
        let mut col = if mask.all() {
            Column::from_i64_values(self.values)
        } else {
            Column::from_i64_values_with_validity(self.values, mask)
        };
        if self.is_nullable {
            col = col.with_dtype(DType::Int64Nullable);
        }
        (col, self.missing_kinds)
    }
}

/// Column builder for Float64 storage.
struct Float64Builder {
    values: Vec<f64>,
    validity: ValidityBuilder,
    missing_kinds: Vec<Option<FrameMissingKind>>,
}

impl Float64Builder {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            values: Vec::with_capacity(capacity),
            validity: ValidityBuilder::with_capacity(capacity),
            missing_kinds: Vec::with_capacity(capacity),
        }
    }

    fn push_null(&mut self) {
        self.values.push(f64::NAN);
        self.validity.push_null();
        self.missing_kinds.push(Some(FrameMissingKind::SqlNull));
    }

    fn push_nan(&mut self) {
        self.values.push(f64::NAN);
        self.validity.push_null();
        self.missing_kinds.push(Some(FrameMissingKind::NaN));
    }

    fn push_value(&mut self, val: f64) {
        if val.is_nan() {
            self.push_nan();
        } else {
            self.values.push(val);
            self.validity.push_valid();
            self.missing_kinds.push(None);
        }
    }

    fn finish(self) -> (Column, Vec<Option<FrameMissingKind>>) {
        let mask = self.validity.finish();
        let col = Column::from_f64_values_with_validity(self.values, mask);
        (col, self.missing_kinds)
    }
}

/// Column builder for Bool and BoolNullable storage.
struct BoolBuilder {
    values: Vec<bool>,
    validity: ValidityBuilder,
    missing_kinds: Vec<Option<FrameMissingKind>>,
    is_nullable: bool,
}

impl BoolBuilder {
    fn with_capacity(capacity: usize, is_nullable: bool) -> Self {
        Self {
            values: Vec::with_capacity(capacity),
            validity: ValidityBuilder::with_capacity(capacity),
            missing_kinds: Vec::with_capacity(capacity),
            is_nullable,
        }
    }

    fn push_null(&mut self) {
        self.values.push(false);
        self.validity.push_null();
        self.missing_kinds.push(Some(FrameMissingKind::SqlNull));
    }

    fn push_value(&mut self, val: bool) {
        self.values.push(val);
        self.validity.push_valid();
        self.missing_kinds.push(None);
    }

    fn finish(self) -> (Column, Vec<Option<FrameMissingKind>>) {
        let mask = self.validity.finish();
        let mut col = Column::from_bool_values_with_validity(self.values, mask);
        if self.is_nullable {
            col = col.with_dtype(DType::BoolNullable);
        }
        (col, self.missing_kinds)
    }
}

/// Column builder for Datetime64 (nanosecond epoch) storage.
struct Datetime64Builder {
    values: Vec<i64>,
    validity: ValidityBuilder,
    missing_kinds: Vec<Option<FrameMissingKind>>,
}

impl Datetime64Builder {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            values: Vec::with_capacity(capacity),
            validity: ValidityBuilder::with_capacity(capacity),
            missing_kinds: Vec::with_capacity(capacity),
        }
    }

    fn push_null(&mut self) {
        self.values.push(i64::MIN);
        self.validity.push_null();
        self.missing_kinds.push(Some(FrameMissingKind::SqlNull));
    }

    fn push_value(&mut self, nanos: i64) {
        self.values.push(nanos);
        self.validity.push_valid();
        self.missing_kinds.push(None);
    }

    fn finish(self) -> Result<(Column, Vec<Option<FrameMissingKind>>), FrameError> {
        let mask = self.validity.finish();
        let col = if mask.all() {
            Column::from_datetime64_values(self.values)
        } else {
            let scalars = self
                .values
                .into_iter()
                .map(|n| {
                    if n == i64::MIN {
                        Scalar::Datetime64(i64::MIN)
                    } else {
                        Scalar::Datetime64(n)
                    }
                })
                .collect();
            Column::new(DType::Datetime64, scalars).map_err(|err| FrameError::ColumnBuild {
                column: "datetime64".to_string(),
                message: err.to_string(),
            })?
        };
        Ok((col, self.missing_kinds))
    }
}

type TimestampTzParts = (Column, Vec<Option<FrameMissingKind>>, Vec<Option<i32>>);

/// Column builder for TIMESTAMP_TZ storage.
struct TimestampTzBuilder {
    datetime_builder: Datetime64Builder,
    tz_offsets: Vec<Option<i32>>,
}

impl TimestampTzBuilder {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            datetime_builder: Datetime64Builder::with_capacity(capacity),
            tz_offsets: Vec::with_capacity(capacity),
        }
    }

    fn push_null(&mut self) {
        self.datetime_builder.push_null();
        self.tz_offsets.push(None);
    }

    fn push_value(&mut self, nanos: i64, offset_minutes: i32) {
        self.datetime_builder.push_value(nanos);
        self.tz_offsets.push(Some(offset_minutes));
    }

    fn finish(self) -> Result<TimestampTzParts, FrameError> {
        let (col, missing) = self.datetime_builder.finish()?;
        Ok((col, missing, self.tz_offsets))
    }
}

/// Column builder for contiguous rolling Utf8 string buffer.
struct ContiguousUtf8Builder {
    bytes: Vec<u8>,
    offsets: Vec<usize>,
    validity: ValidityBuilder,
    missing_kinds: Vec<Option<FrameMissingKind>>,
}

impl ContiguousUtf8Builder {
    fn with_capacity(row_capacity: usize, byte_capacity: usize) -> Self {
        let mut offsets = Vec::with_capacity(row_capacity + 1);
        offsets.push(0);
        Self {
            bytes: Vec::with_capacity(byte_capacity),
            offsets,
            validity: ValidityBuilder::with_capacity(row_capacity),
            missing_kinds: Vec::with_capacity(row_capacity),
        }
    }

    fn push_null(&mut self) {
        self.offsets.push(self.bytes.len());
        self.validity.push_null();
        self.missing_kinds.push(Some(FrameMissingKind::SqlNull));
    }

    fn push_str(&mut self, text: &str) {
        self.bytes.extend_from_slice(text.as_bytes());
        self.offsets.push(self.bytes.len());
        self.validity.push_valid();
        self.missing_kinds.push(None);
    }

    fn finish(self) -> (Column, Vec<Option<FrameMissingKind>>) {
        let col = Column::from_utf8_values_with_validity(
            self.bytes,
            self.offsets,
            self.validity.finish(),
        );
        (col, self.missing_kinds)
    }
}

enum ColumnBuilderKind {
    Int64(Int64Builder),
    Float64(Float64Builder),
    Bool(BoolBuilder),
    Datetime(Datetime64Builder),
    TimestampTz(TimestampTzBuilder),
    Utf8(ContiguousUtf8Builder),
}

/// Materialize a raw `jsonv2` result partition byte slice into an `fp-columnar` frame.
///
/// Parsing is zero-copy: non-escaped cell tokens are borrowed directly from `bytes`,
/// and values are written directly into contiguous columnar storage without intermediate
/// `serde_json::Value` or per-cell `String` allocations.
pub fn materialize_partition_bytes(
    columns: &[SnowflakeColumn],
    bytes: &[u8],
) -> FrameResult<FrankenPandasFrame> {
    materialize_raw_partitions(columns, [(0, bytes)])
}

/// Materialize ordered raw `jsonv2` result partitions into an `fp-columnar` frame.
pub fn materialize_raw_partitions<'a, I>(
    columns: &[SnowflakeColumn],
    partitions: I,
) -> FrameResult<FrankenPandasFrame>
where
    I: IntoIterator<Item = (u32, &'a [u8])>,
{
    let metadata = columns
        .iter()
        .map(FrameColumnMeta::from_snowflake)
        .collect::<Vec<_>>();

    let partition_list: Vec<(u32, &'a [u8])> = partitions.into_iter().collect();
    let total_bytes: usize = partition_list.iter().map(|(_, b)| b.len()).sum();
    let min_bytes_per_row = (columns.len().max(1) * 3).max(6);
    let estimated_rows = (total_bytes / min_bytes_per_row).clamp(1, 2_000_000);
    let estimated_utf8_bytes = (total_bytes / columns.len().max(1)).max(64);

    let mut builders = metadata
        .iter()
        .map(|meta| match meta.storage_kind {
            FrameStorageKind::Int64 => {
                ColumnBuilderKind::Int64(Int64Builder::with_capacity(estimated_rows, meta.nullable))
            }
            FrameStorageKind::Float64 => {
                ColumnBuilderKind::Float64(Float64Builder::with_capacity(estimated_rows))
            }
            FrameStorageKind::Bool => {
                ColumnBuilderKind::Bool(BoolBuilder::with_capacity(estimated_rows, meta.nullable))
            }
            FrameStorageKind::Datetime64 => match meta.logical_type {
                SnowflakeLogicalType::TimestampTz => ColumnBuilderKind::TimestampTz(
                    TimestampTzBuilder::with_capacity(estimated_rows),
                ),
                _ => ColumnBuilderKind::Datetime(Datetime64Builder::with_capacity(estimated_rows)),
            },
            FrameStorageKind::DecimalString
            | FrameStorageKind::Utf8
            | FrameStorageKind::StructuredJson
            | FrameStorageKind::BinaryHex => ColumnBuilderKind::Utf8(
                ContiguousUtf8Builder::with_capacity(estimated_rows, estimated_utf8_bytes),
            ),
        })
        .collect::<Vec<_>>();

    let mut scanner = ZeroCopyJsonv2Scanner::new();
    let mut total_rows = 0usize;

    for (partition_index, partition_bytes) in partition_list {
        let partition_rows = scanner.scan_rows(
            partition_bytes,
            partition_index,
            columns.len(),
            |_, col_idx, cell| {
                feed_cell(
                    &mut builders[col_idx],
                    cell,
                    &columns[col_idx],
                    &metadata[col_idx],
                )
            },
        )?;
        total_rows = total_rows
            .checked_add(partition_rows)
            .ok_or(FrameError::RowCountOverflow)?;
    }

    let mut frame_columns = Vec::with_capacity(metadata.len());
    for (meta, builder) in metadata.into_iter().zip(builders) {
        let (column, missing_kinds, timestamp_tz_offsets_minutes) = match builder {
            ColumnBuilderKind::Int64(b) => {
                let (col, missing) = b.finish();
                (col, missing, None)
            }
            ColumnBuilderKind::Float64(b) => {
                let (col, missing) = b.finish();
                (col, missing, None)
            }
            ColumnBuilderKind::Bool(b) => {
                let (col, missing) = b.finish();
                (col, missing, None)
            }
            ColumnBuilderKind::Datetime(b) => {
                let (col, missing) = b.finish()?;
                (col, missing, None)
            }
            ColumnBuilderKind::TimestampTz(b) => {
                let (col, missing, offsets) = b.finish()?;
                (col, missing, Some(offsets))
            }
            ColumnBuilderKind::Utf8(b) => {
                let (col, missing) = b.finish();
                (col, missing, None)
            }
        };

        frame_columns.push(FrameColumn {
            metadata: meta,
            column,
            missing_kinds,
            timestamp_tz_offsets_minutes,
        });
    }

    Ok(FrankenPandasFrame {
        row_count: total_rows,
        columns: frame_columns,
    })
}

/// Materialize raw result partition slices into an `fp-columnar` frame.
pub fn materialize_raw_partition_slices<'a, I>(
    columns: &[SnowflakeColumn],
    partitions: I,
) -> FrameResult<FrankenPandasFrame>
where
    I: IntoIterator<Item = RawResultPartition<'a>>,
{
    materialize_raw_partitions(columns, partitions.into_iter().map(|p| (p.index, p.bytes)))
}

fn feed_cell(
    builder: &mut ColumnBuilderKind,
    cell: CellSlice<'_>,
    source: &SnowflakeColumn,
    meta: &FrameColumnMeta,
) -> FrameResult<()> {
    let Some(text) = cell.as_str() else {
        match builder {
            ColumnBuilderKind::Int64(b) => b.push_null(),
            ColumnBuilderKind::Float64(b) => b.push_null(),
            ColumnBuilderKind::Bool(b) => b.push_null(),
            ColumnBuilderKind::Datetime(b) => b.push_null(),
            ColumnBuilderKind::TimestampTz(b) => b.push_null(),
            ColumnBuilderKind::Utf8(b) => b.push_null(),
        }
        return Ok(());
    };

    match (builder, meta.logical_type) {
        (ColumnBuilderKind::Int64(b), SnowflakeLogicalType::Fixed) => {
            let val = parse_scale0_int_fast(text).ok_or_else(|| {
                decode_error(source, "FIXED/NUMBER scale 0 must be an integer decimal")
            })?;
            b.push_value(val);
        }
        (ColumnBuilderKind::Float64(b), SnowflakeLogicalType::Real) => {
            if text == "NaN" {
                b.push_nan();
            } else {
                let val = text
                    .parse::<f64>()
                    .map_err(|_| decode_error(source, "expected a numeric decimal string"))?;
                b.push_value(val);
            }
        }
        (ColumnBuilderKind::Bool(b), SnowflakeLogicalType::Boolean) => match text {
            "true" => b.push_value(true),
            "false" => b.push_value(false),
            _ => {
                return Err(decode_error(
                    source,
                    "BOOLEAN must be \"true\" or \"false\"",
                ));
            }
        },
        (ColumnBuilderKind::Datetime(b), SnowflakeLogicalType::Date) => {
            let days = text
                .parse::<i64>()
                .map_err(|_| decode_error(source, "DATE must be epoch days"))?;
            let nanos = days_to_nanos(days, source)?;
            b.push_value(nanos);
        }
        (
            ColumnBuilderKind::Datetime(b),
            SnowflakeLogicalType::Time
            | SnowflakeLogicalType::TimestampNtz
            | SnowflakeLogicalType::TimestampLtz,
        ) => {
            let (seconds, nanos_part) = parse_fractional_seconds_fast(text)
                .ok_or_else(|| decode_error(source, "expected fractional epoch seconds"))?;
            let nanos = seconds_to_nanos(seconds, nanos_part, source)?;
            b.push_value(nanos);
        }
        (ColumnBuilderKind::TimestampTz(b), SnowflakeLogicalType::TimestampTz) => {
            let (seconds_part, offset_part) = text.split_once(' ').ok_or_else(|| {
                decode_error(source, "TIMESTAMP_TZ must be \"<seconds> <offset>\"")
            })?;
            let (seconds, nanos_part) = parse_fractional_seconds_fast(seconds_part)
                .ok_or_else(|| decode_error(source, "expected fractional epoch seconds"))?;
            let encoded_offset = offset_part
                .parse::<i32>()
                .map_err(|_| decode_error(source, "TIMESTAMP_TZ offset must be an integer"))?;
            if !(0..=2880).contains(&encoded_offset) {
                return Err(decode_error(source, "TIMESTAMP_TZ offset is out of range"));
            }
            let nanos = seconds_to_nanos(seconds, nanos_part, source)?;
            b.push_value(nanos, encoded_offset - 1440);
        }
        (ColumnBuilderKind::Utf8(b), SnowflakeLogicalType::Fixed) => {
            if !is_fixed_decimal(text, meta.scale) {
                return Err(decode_error(
                    source,
                    "FIXED/NUMBER must be a decimal string",
                ));
            }
            b.push_str(text);
        }
        (ColumnBuilderKind::Utf8(b), SnowflakeLogicalType::Binary) => {
            if !is_even_hex(text) {
                return Err(decode_error(
                    source,
                    "BINARY must be an even-length hex string",
                ));
            }
            b.push_str(text);
        }
        (ColumnBuilderKind::Utf8(b), SnowflakeLogicalType::StructuredJson) => {
            serde_json::from_str::<serde::de::IgnoredAny>(text)
                .map_err(|_| decode_error(source, "semi-structured cell must be JSON"))?;
            b.push_str(text);
        }
        (
            ColumnBuilderKind::Utf8(b),
            SnowflakeLogicalType::Text | SnowflakeLogicalType::UnknownText,
        ) => {
            b.push_str(text);
        }
        _ => {
            return Err(decode_error(
                source,
                "type mismatch between column metadata and storage builder",
            ));
        }
    }

    Ok(())
}

#[inline(always)]
fn parse_scale0_int_fast(text: &str) -> Option<i64> {
    if let Some((int_part, frac_part)) = text.split_once('.') {
        if frac_part.bytes().all(|byte| byte == b'0') {
            return int_part.parse::<i64>().ok();
        }
        return None;
    }
    text.parse::<i64>().ok()
}

#[inline(always)]
fn parse_fractional_seconds_fast(text: &str) -> Option<(i64, u32)> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let negative = bytes[0] == b'-';
    let (int_str, frac_nanos) = match text.split_once('.') {
        Some((int_str, frac)) => (int_str, frac_to_nanos_fast(frac.as_bytes())?),
        None => (text, 0),
    };
    let int_part = int_str.parse::<i64>().ok()?;
    if !negative || frac_nanos == 0 {
        Some((int_part, frac_nanos))
    } else {
        Some((int_part.checked_sub(1)?, 1_000_000_000 - frac_nanos))
    }
}

#[inline(always)]
fn frac_to_nanos_fast(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut nanos: u32 = 0;
    let mut factor: u32 = 100_000_000;
    for &b in bytes.iter().take(9) {
        if !b.is_ascii_digit() {
            return None;
        }
        nanos = nanos.checked_add((b - b'0') as u32 * factor)?;
        factor /= 10;
    }
    Some(nanos)
}

#[inline(always)]
fn skip_whitespace(bytes: &[u8], mut pos: usize) -> usize {
    while pos < bytes.len() {
        let b = bytes[pos];
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            pos += 1;
        } else {
            break;
        }
    }
    pos
}

#[inline(always)]
fn match_null(bytes: &[u8]) -> bool {
    bytes == b"null"
}

/// SWAR (SIMD Within A Register) fast byte scanner.
///
/// Checks 8 bytes per iteration for `"` (0x22) or `\` (0x5c).
#[inline(always)]
fn find_quote_or_escape(bytes: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i + 8 <= bytes.len() {
        let chunk_slice = match bytes.get(i..i + 8) {
            Some(s) => s,
            None => break,
        };
        let mut arr = [0u8; 8];
        arr.copy_from_slice(chunk_slice);
        let chunk = u64::from_ne_bytes(arr);

        let m1 = chunk ^ 0x2222_2222_2222_2222_u64;
        let m2 = chunk ^ 0x5c5c_5c5c_5c5c_5c5c_u64;
        let r1 = m1.wrapping_sub(0x0101_0101_0101_0101_u64) & !m1;
        let r2 = m2.wrapping_sub(0x0101_0101_0101_0101_u64) & !m2;
        if (r1 | r2) & 0x8080_8080_8080_8080_u64 != 0 {
            for j in 0..8 {
                let b = bytes[i + j];
                if b == b'"' || b == b'\\' {
                    return Some(i + j);
                }
            }
        }
        i += 8;
    }

    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' || b == b'\\' {
            return Some(i);
        }
        i += 1;
    }

    None
}

fn decode_escapes_into(bytes: &[u8], mut pos: usize, scratch: &mut Vec<u8>) -> FrameResult<usize> {
    let len = bytes.len();
    loop {
        if pos >= len {
            return Err(FrameError::Decode {
                column: String::new(),
                snowflake_type: String::new(),
                reason: "unexpected EOF in escaped string",
            });
        }

        if bytes[pos] != b'\\' {
            return Err(FrameError::Decode {
                column: String::new(),
                snowflake_type: String::new(),
                reason: "expected '\\' in escape decoder",
            });
        }
        pos += 1;

        if pos >= len {
            return Err(FrameError::Decode {
                column: String::new(),
                snowflake_type: String::new(),
                reason: "unexpected EOF after '\\'",
            });
        }

        match bytes[pos] {
            b'"' => scratch.push(b'"'),
            b'\\' => scratch.push(b'\\'),
            b'/' => scratch.push(b'/'),
            b'b' => scratch.push(0x08),
            b'f' => scratch.push(0x0c),
            b'n' => scratch.push(b'\n'),
            b'r' => scratch.push(b'\r'),
            b't' => scratch.push(b'\t'),
            b'u' => {
                if pos + 4 >= len {
                    return Err(FrameError::Decode {
                        column: String::new(),
                        snowflake_type: String::new(),
                        reason: "unterminated unicode escape",
                    });
                }
                let hex_slice = match bytes.get(pos + 1..pos + 5) {
                    Some(s) => s,
                    None => {
                        return Err(FrameError::Decode {
                            column: String::new(),
                            snowflake_type: String::new(),
                            reason: "unterminated unicode escape",
                        });
                    }
                };
                let hex_str = core::str::from_utf8(hex_slice).map_err(|_| FrameError::Decode {
                    column: String::new(),
                    snowflake_type: String::new(),
                    reason: "invalid UTF-8 in unicode escape",
                })?;
                let code = u16::from_str_radix(hex_str, 16).map_err(|_| FrameError::Decode {
                    column: String::new(),
                    snowflake_type: String::new(),
                    reason: "invalid hex digits in unicode escape",
                })?;
                pos += 4;

                if (0xd800..=0xdbff).contains(&code) {
                    // High surrogate: expect `\uXXXX` low surrogate
                    if pos + 6 < len && bytes[pos + 1] == b'\\' && bytes[pos + 2] == b'u' {
                        let low_slice = match bytes.get(pos + 3..pos + 7) {
                            Some(s) => s,
                            None => {
                                return Err(FrameError::Decode {
                                    column: String::new(),
                                    snowflake_type: String::new(),
                                    reason: "unterminated low surrogate escape",
                                });
                            }
                        };
                        let low_str =
                            core::str::from_utf8(low_slice).map_err(|_| FrameError::Decode {
                                column: String::new(),
                                snowflake_type: String::new(),
                                reason: "invalid UTF-8 in low surrogate",
                            })?;
                        let low_code =
                            u16::from_str_radix(low_str, 16).map_err(|_| FrameError::Decode {
                                column: String::new(),
                                snowflake_type: String::new(),
                                reason: "invalid hex in low surrogate",
                            })?;
                        if (0xdc00..=0xdfff).contains(&low_code) {
                            pos += 6;
                            let scalar = 0x10000
                                + (((u32::from(code) - 0xd800) << 10)
                                    | (u32::from(low_code) - 0xdc00));
                            if let Some(ch) = char::from_u32(scalar) {
                                let mut buf = [0u8; 4];
                                let enc = ch.encode_utf8(&mut buf);
                                scratch.extend_from_slice(enc.as_bytes());
                            } else {
                                return Err(FrameError::Decode {
                                    column: String::new(),
                                    snowflake_type: String::new(),
                                    reason: "invalid surrogate scalar codepoint",
                                });
                            }
                        } else {
                            return Err(FrameError::Decode {
                                column: String::new(),
                                snowflake_type: String::new(),
                                reason: "expected low surrogate after high surrogate",
                            });
                        }
                    } else {
                        return Err(FrameError::Decode {
                            column: String::new(),
                            snowflake_type: String::new(),
                            reason: "lone high surrogate without low surrogate",
                        });
                    }
                } else if let Some(ch) = char::from_u32(u32::from(code)) {
                    let mut buf = [0u8; 4];
                    let enc = ch.encode_utf8(&mut buf);
                    scratch.extend_from_slice(enc.as_bytes());
                } else {
                    return Err(FrameError::Decode {
                        column: String::new(),
                        snowflake_type: String::new(),
                        reason: "invalid unicode codepoint",
                    });
                }
            }
            _ => {
                return Err(FrameError::Decode {
                    column: String::new(),
                    snowflake_type: String::new(),
                    reason: "unknown escape sequence",
                });
            }
        }
        pos += 1;

        // Scan for next quote or escape
        let hit = find_quote_or_escape(&bytes[pos..]);
        let Some(rel_hit) = hit else {
            return Err(FrameError::Decode {
                column: String::new(),
                snowflake_type: String::new(),
                reason: "unterminated string after escape",
            });
        };

        scratch.extend_from_slice(&bytes[pos..pos + rel_hit]);
        pos += rel_hit;
        if bytes[pos] == b'"' {
            pos += 1; // skip closing quote
            break;
        }
    }

    Ok(pos)
}
