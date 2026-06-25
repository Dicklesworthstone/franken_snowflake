//! The `jsonv2` wire codec: decode a result `data` cell per its column type.
//!
//! Every cell in a [`crate::response::ResultSet`]'s `data` is a JSON **string**
//! (including numbers and booleans), or JSON `null`. The decode is driven by the
//! column's [`ColumnType`] (matched case-insensitively), **never** by JSON shape.
//! These are the load-bearing rules where connector bugs hide:
//!
//! | Type | Wire string | Rule |
//! |---|---|---|
//! | `FIXED`/`NUMBER` | `"1.0"` | keep the decimal verbatim — do **not** divide by 10^scale |
//! | `REAL`/`FLOAT` | numeric | parse as `f64` |
//! | `BOOLEAN` | `"true"`/`"false"` | string compare, not JSON bool |
//! | `DATE` | `"18262"` | epoch **days** |
//! | `TIME`/`TIMESTAMP_NTZ`/`TIMESTAMP_LTZ` | `"82919.000000000"` | fractional epoch **seconds** (not nanos) |
//! | `TIMESTAMP_TZ` | `"<sec.frac> <offset>"` | offset = minutes encoded as `offset_minutes + 1440` |
//! | `BINARY` | hex | hex-decode |
//! | `VARIANT`/`OBJECT`/`ARRAY` | embedded JSON | preserve as structured JSON |
//! | SQL `NULL` | JSON `null` | [`CellValue::Null`] |
//!
//! The docs are internally inconsistent on the timestamp unit (one passage says
//! nanoseconds); this codec follows the fractional-**seconds** reading and is
//! pinned against an empirically captured live golden in
//! `fsnow-native-snowflake-connector-w0i.13`. [`CellValue`] is a neutral decoded
//! value; the frame crate maps it onto a dtype later.

use serde_json::Value;

use crate::response::ColumnType;

/// A decoded result cell. Deliberately *lossless and neutral*: numerics stay as
/// their exact decimal strings, timestamps stay as `(seconds, nanos)` pairs, and
/// semi-structured values stay as JSON — frame materialization (a later crate)
/// owns the dtype projection.
#[derive(Clone, Debug, PartialEq)]
pub enum CellValue {
    /// SQL `NULL`.
    Null,
    /// `FIXED`/`NUMBER`: the decimal exactly as written (no scale division).
    Number(String),
    /// `REAL`/`FLOAT`/`DOUBLE`.
    Float(f64),
    /// `BOOLEAN`.
    Bool(bool),
    /// `TEXT`/`STRING`/`VARCHAR` and any unmodeled type (decoded leniently).
    Text(String),
    /// `DATE`: days since the Unix epoch.
    Date(i64),
    /// `TIME`/`TIMESTAMP_NTZ`/`TIMESTAMP_LTZ`: fractional epoch seconds split into
    /// whole `seconds` and `nanos`.
    Timestamp {
        /// Whole seconds since the Unix epoch (as encoded).
        seconds: i64,
        /// Fractional nanoseconds (0..=999_999_999).
        nanos: u32,
    },
    /// `TIMESTAMP_TZ`: a [`CellValue::Timestamp`] plus a timezone offset in
    /// minutes, already decoded from the wire's `offset_minutes + 1440`.
    TimestampTz {
        /// Whole seconds since the Unix epoch (as encoded).
        seconds: i64,
        /// Fractional nanoseconds (0..=999_999_999).
        nanos: u32,
        /// Timezone offset in minutes (e.g. `-480` for UTC-08:00).
        offset_minutes: i32,
    },
    /// `BINARY`: hex-decoded bytes.
    Binary(Vec<u8>),
    /// `VARIANT`/`OBJECT`/`ARRAY`: the embedded JSON value.
    Json(Value),
}

/// A `jsonv2` decode failure. Carries the column name and Snowflake type plus a
/// static reason — **never** the raw cell value, which may be sensitive
/// (`docs/security_model.md`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireError {
    /// The offending column's name.
    pub column: String,
    /// The column's Snowflake logical type.
    pub snowflake_type: String,
    /// A short, value-free explanation.
    pub reason: &'static str,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "jsonv2 decode error in column {:?} ({}): {}",
            self.column, self.snowflake_type, self.reason
        )
    }
}

impl std::error::Error for WireError {}

/// Decode one `data` cell against its [`ColumnType`]. `raw` is `None` for SQL
/// `NULL`.
///
/// # Errors
/// Returns a [`WireError`] when the cell does not match its declared type (e.g. a
/// non-numeric `DATE`, a malformed `TIMESTAMP_TZ`, or odd-length `BINARY`).
pub fn decode_cell(raw: Option<&str>, column: &ColumnType) -> Result<CellValue, WireError> {
    let Some(text) = raw else {
        return Ok(CellValue::Null);
    };
    let make_err = |reason: &'static str| WireError {
        column: column.name.clone(),
        snowflake_type: column.column_type.clone(),
        reason,
    };

    match column.column_type.to_ascii_uppercase().as_str() {
        "FIXED" | "NUMBER" | "DECIMAL" | "NUMERIC" | "INT" | "INTEGER" | "BIGINT" | "SMALLINT"
        | "TINYINT" | "BYTEINT" => Ok(CellValue::Number(text.to_owned())),

        "REAL" | "FLOAT" | "FLOAT4" | "FLOAT8" | "DOUBLE" | "DOUBLE PRECISION" => text
            .parse::<f64>()
            .map(CellValue::Float)
            .map_err(|_| make_err("expected a numeric REAL/FLOAT")),

        "BOOLEAN" | "BOOL" => match text {
            "true" => Ok(CellValue::Bool(true)),
            "false" => Ok(CellValue::Bool(false)),
            _ => Err(make_err("BOOLEAN must be the string \"true\" or \"false\"")),
        },

        "DATE" => text
            .parse::<i64>()
            .map(CellValue::Date)
            .map_err(|_| make_err("DATE must be an integer epoch-day count")),

        "TIME" | "TIMESTAMP_NTZ" | "TIMESTAMP_LTZ" | "DATETIME" => {
            let (seconds, nanos) = parse_fractional_seconds(text)
                .ok_or_else(|| make_err("expected fractional epoch seconds"))?;
            Ok(CellValue::Timestamp { seconds, nanos })
        }

        "TIMESTAMP_TZ" => {
            let (sec_part, offset_part) = text
                .split_once(' ')
                .ok_or_else(|| make_err("TIMESTAMP_TZ must be \"<seconds> <offset>\""))?;
            let (seconds, nanos) = parse_fractional_seconds(sec_part)
                .ok_or_else(|| make_err("expected fractional epoch seconds"))?;
            let encoded_offset = offset_part
                .parse::<i32>()
                .map_err(|_| make_err("TIMESTAMP_TZ offset must be an integer"))?;
            // The wire encodes the offset as offset_minutes + 1440 (UTC == 1440),
            // so the encoded value is in [0, 2880]. Validate the range before
            // subtracting so a malformed cell cannot underflow i32.
            if !(0..=2880).contains(&encoded_offset) {
                return Err(make_err("TIMESTAMP_TZ offset is out of range"));
            }
            Ok(CellValue::TimestampTz {
                seconds,
                nanos,
                offset_minutes: encoded_offset - 1440,
            })
        }

        "BINARY" | "VARBINARY" => decode_hex(text)
            .map(CellValue::Binary)
            .ok_or_else(|| make_err("BINARY must be an even-length hex string")),

        "VARIANT" | "OBJECT" | "ARRAY" => serde_json::from_str(text)
            .map(CellValue::Json)
            .map_err(|_| make_err("VARIANT/OBJECT/ARRAY must hold embedded JSON")),

        // TEXT/STRING/VARCHAR/CHAR and any not-yet-modeled type: keep the string.
        _ => Ok(CellValue::Text(text.to_owned())),
    }
}

/// Parse `"<seconds>"` or `"<seconds>.<frac>"` into `(whole_seconds, nanos)`.
/// Fractions are taken to nanosecond precision (extra digits truncated). Returns
/// `None` on a non-integer seconds part or non-digit fraction.
///
/// The result obeys `value = seconds + nanos / 1e9` with `nanos` in
/// `[0, 1e9)`. For **negative (pre-1970) epoch values with a nonzero fraction**
/// this needs a borrow — `"-1.5"` is `-1.5s = (-2, 500_000_000)`, and `"-0.5"`
/// is `-0.5s = (-1, 500_000_000)`. Note the integer part of `"-0.5"` parses to
/// `0`, so the sign is read from the string, not from the parsed integer.
fn parse_fractional_seconds(text: &str) -> Option<(i64, u32)> {
    let negative = text.starts_with('-');
    let (int_str, frac_nanos) = match text.split_once('.') {
        Some((int_str, frac)) => (int_str, frac_to_nanos(frac)?),
        None => (text, 0),
    };
    let int_part = int_str.parse::<i64>().ok()?;
    if !negative || frac_nanos == 0 {
        // Positive, or an exact second (no fractional remainder to borrow).
        Some((int_part, frac_nanos))
    } else {
        // Negative with a fractional remainder: borrow one whole second so the
        // fraction stays non-negative. `frac_nanos` is in `(0, 1e9)` here, so
        // `1e9 - frac_nanos` is also in `(0, 1e9)`.
        let seconds = int_part.checked_sub(1)?;
        Some((seconds, 1_000_000_000 - frac_nanos))
    }
}

/// Convert a decimal fraction string (the part after `.`) to nanoseconds,
/// padding/truncating to 9 digits. Returns `None` if empty or non-digit.
fn frac_to_nanos(frac: &str) -> Option<u32> {
    if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut nanos = String::with_capacity(9);
    nanos.extend(frac.chars().take(9));
    while nanos.len() < 9 {
        nanos.push('0');
    }
    nanos.parse::<u32>().ok()
}

/// Decode an even-length hex string into bytes. Returns `None` on odd length or a
/// non-hex digit.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?))
        .collect()
}

/// Map one ASCII hex digit to its nibble value.
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(snowflake_type: &str) -> ColumnType {
        ColumnType {
            name: "C".to_owned(),
            column_type: snowflake_type.to_owned(),
            scale: None,
            precision: None,
            nullable: true,
            length: None,
            byte_length: None,
            database: None,
            schema: None,
            table: None,
            collation: None,
        }
    }

    #[test]
    fn null_cell_decodes_to_null() -> Result<(), String> {
        let value = decode_cell(None, &col("TEXT")).map_err(|e| e.to_string())?;
        assert_eq!(value, CellValue::Null);
        Ok(())
    }

    #[test]
    fn number_is_kept_verbatim_without_scale_division() -> Result<(), String> {
        // scale=2, but the wire value is NOT divided by 100.
        let mut column = col("FIXED");
        column.scale = Some(2);
        let value = decode_cell(Some("1.50"), &column).map_err(|e| e.to_string())?;
        assert_eq!(value, CellValue::Number("1.50".to_owned()));
        Ok(())
    }

    #[test]
    fn boolean_is_string_not_json_bool() -> Result<(), String> {
        assert_eq!(
            decode_cell(Some("true"), &col("BOOLEAN")).map_err(|e| e.to_string())?,
            CellValue::Bool(true)
        );
        assert_eq!(
            decode_cell(Some("false"), &col("boolean")).map_err(|e| e.to_string())?,
            CellValue::Bool(false)
        );
        // A JSON-bool-shaped or numeric value is a typed error, not a silent coerce.
        assert!(decode_cell(Some("1"), &col("BOOLEAN")).is_err());
        Ok(())
    }

    #[test]
    fn date_is_epoch_days() -> Result<(), String> {
        // 2020-01-01 is day 18262.
        assert_eq!(
            decode_cell(Some("18262"), &col("DATE")).map_err(|e| e.to_string())?,
            CellValue::Date(18262)
        );
        assert!(decode_cell(Some("2020-01-01"), &col("DATE")).is_err());
        Ok(())
    }

    #[test]
    fn timestamp_is_fractional_epoch_seconds_not_nanos() -> Result<(), String> {
        let value = decode_cell(Some("82919.000000000"), &col("TIMESTAMP_NTZ"))
            .map_err(|e| e.to_string())?;
        assert_eq!(
            value,
            CellValue::Timestamp {
                seconds: 82919,
                nanos: 0
            }
        );
        // Sub-second precision is preserved as nanos.
        let value = decode_cell(Some("100.5"), &col("TIME")).map_err(|e| e.to_string())?;
        assert_eq!(
            value,
            CellValue::Timestamp {
                seconds: 100,
                nanos: 500_000_000
            }
        );
        Ok(())
    }

    #[test]
    fn timestamp_tz_decodes_offset_minus_1440() -> Result<(), String> {
        // offset encoded as offset_minutes + 1440; 960 → -480 minutes (UTC-08:00).
        let value = decode_cell(Some("1700000000.000000000 960"), &col("TIMESTAMP_TZ"))
            .map_err(|e| e.to_string())?;
        assert_eq!(
            value,
            CellValue::TimestampTz {
                seconds: 1_700_000_000,
                nanos: 0,
                offset_minutes: -480
            }
        );
        assert!(decode_cell(Some("1700000000.0"), &col("TIMESTAMP_TZ")).is_err());
        Ok(())
    }

    #[test]
    fn negative_pre_1970_timestamps_decode_with_borrow() -> Result<(), String> {
        // Regression (bead fsnow-agent-ergonomic-cli-aq2): pre-epoch fractional
        // timestamps must satisfy value = seconds + nanos/1e9 with nanos in
        // [0, 1e9). Before the fix, "-1.5" decoded to (-1, 5e8) = -0.5s.
        let cases: &[(&str, i64, u32)] = &[
            ("-1.5", -2, 500_000_000),                 // -1.5s
            ("-0.5", -1, 500_000_000),                 // -0.5s; integer part "-0" parses to 0
            ("-1.0", -1, 0),                           // exact: no borrow
            ("-1", -1, 0),                             // no fraction at all
            ("-86400.250000000", -86401, 750_000_000), // one day before epoch, .25s
        ];
        for (raw, seconds, nanos) in cases {
            let value = decode_cell(Some(raw), &col("TIMESTAMP_NTZ")).map_err(|e| e.to_string())?;
            assert_eq!(
                value,
                CellValue::Timestamp {
                    seconds: *seconds,
                    nanos: *nanos,
                },
                "decode of {raw:?}"
            );
        }
        // The positive path is unchanged.
        assert_eq!(
            decode_cell(Some("1.5"), &col("TIMESTAMP_NTZ")).map_err(|e| e.to_string())?,
            CellValue::Timestamp {
                seconds: 1,
                nanos: 500_000_000
            }
        );
        Ok(())
    }

    #[test]
    fn negative_timestamp_tz_decodes_with_borrow() -> Result<(), String> {
        // 1969-12-31T23:59:59.5 at UTC-08:00 → "-0.5 960" (offset 960 = -480 + 1440).
        let value =
            decode_cell(Some("-0.5 960"), &col("TIMESTAMP_TZ")).map_err(|e| e.to_string())?;
        assert_eq!(
            value,
            CellValue::TimestampTz {
                seconds: -1,
                nanos: 500_000_000,
                offset_minutes: -480,
            }
        );
        Ok(())
    }

    #[test]
    fn binary_is_hex_decoded() -> Result<(), String> {
        assert_eq!(
            decode_cell(Some("deadBEEF"), &col("BINARY")).map_err(|e| e.to_string())?,
            CellValue::Binary(vec![0xde, 0xad, 0xbe, 0xef])
        );
        assert!(decode_cell(Some("abc"), &col("BINARY")).is_err()); // odd length
        assert!(decode_cell(Some("zz"), &col("BINARY")).is_err()); // non-hex
        Ok(())
    }

    #[test]
    fn variant_preserves_embedded_json() -> Result<(), String> {
        let value =
            decode_cell(Some(r#"{"k":[1,2]}"#), &col("VARIANT")).map_err(|e| e.to_string())?;
        match value {
            CellValue::Json(json) => assert_eq!(json["k"][1], serde_json::json!(2)),
            other => return Err(format!("expected Json, got {other:?}")),
        }
        Ok(())
    }

    #[test]
    fn unknown_type_falls_back_to_text() -> Result<(), String> {
        assert_eq!(
            decode_cell(Some("hello"), &col("GEOGRAPHY")).map_err(|e| e.to_string())?,
            CellValue::Text("hello".to_owned())
        );
        Ok(())
    }
}
