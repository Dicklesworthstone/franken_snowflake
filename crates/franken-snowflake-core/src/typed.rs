//! Typed decoding of Snowflake SQL API `jsonv2` result cells (reality-check
//! bead C1, `typed.v1`).
//!
//! The SQL API returns every cell as a JSON string (or `null`) whose meaning
//! depends on the column's `rowType`: a DATE is days since the epoch, a
//! TIMESTAMP is fractional epoch seconds, a BOOLEAN is the text `"true"`, and so
//! on. [`ColumnCodec`] decides one JSON representation per column (never per
//! value) and decodes each cell into it, so an agent reading an envelope gets a
//! date as `"2020-01-01"` rather than `"18262"`.
//!
//! Wire conventions follow the SQL API reference ("Handling responses",
//! docs.snowflake.com/en/developer-guide/sql-api/handling-responses, consulted
//! 2026-09-24) and the testkit's `jsonv2_codec_cells.json`; they are
//! document-derived until a live capture pins them (beads w0i.13, D4):
//!
//! | rowType | wire | typed.v1 |
//! |---|---|---|
//! | FIXED, scale 0, precision <= 15 | `"42"` | JSON number |
//! | other FIXED, DECFLOAT | `"12.50"` | the exact decimal string (never a float) |
//! | REAL | `"1.25"`, `"NaN"`, `"inf"` | JSON number; `"NaN"`, `"Infinity"`, `"-Infinity"` |
//! | BOOLEAN | `"true"` | JSON bool |
//! | TEXT | text | string |
//! | BINARY | hex | the hex string |
//! | DATE | days since 1970-01-01 | `"YYYY-MM-DD"` |
//! | TIME | seconds since midnight | `"HH:MM:SS.fffffffff"` |
//! | TIMESTAMP_NTZ | epoch seconds | `"YYYY-MM-DDTHH:MM:SS.fffffffff"` (no offset) |
//! | TIMESTAMP_LTZ | epoch seconds | the same instant in UTC with `Z` |
//! | TIMESTAMP_TZ | `"<epoch seconds> <offset minutes + 1440>"` | wall clock at that offset, `+HH:MM` |
//! | VARIANT, OBJECT, ARRAY | JSON text | the parsed JSON value |
//! | anything else (GEOGRAPHY, ...) | text | the wire string unchanged |
//!
//! SQL NULL is `null` for every type.

use serde_json::Value;

/// `data.row_encoding` of a typed envelope.
pub const TYPED_ROW_ENCODING: &str = "typed.v1";
/// `data.row_encoding` when the wire strings are passed through (`--raw-cells`).
pub const WIRE_ROW_ENCODING: &str = "jsonv2.wire";

/// The Snowflake type family a `rowType.type` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalType {
    /// FIXED / NUMBER / DECIMAL and the integer aliases.
    Fixed,
    /// REAL / FLOAT / DOUBLE.
    Real,
    /// DECFLOAT.
    Decfloat,
    /// TEXT / VARCHAR / STRING / CHAR.
    Text,
    /// BINARY / VARBINARY.
    Binary,
    /// BOOLEAN.
    Boolean,
    /// DATE.
    Date,
    /// TIME.
    Time,
    /// TIMESTAMP_NTZ.
    TimestampNtz,
    /// TIMESTAMP_LTZ.
    TimestampLtz,
    /// TIMESTAMP_TZ.
    TimestampTz,
    /// VARIANT.
    Variant,
    /// OBJECT.
    Object,
    /// ARRAY.
    Array,
    /// Anything this codec does not interpret (GEOGRAPHY, GEOMETRY, VECTOR, ...).
    Other,
}

impl LogicalType {
    /// Classify a `rowType.type` value (case-insensitive; a parameter list such
    /// as `NUMBER(38,0)` is ignored). An unknown name is [`LogicalType::Other`],
    /// which keeps the wire string.
    #[must_use]
    pub fn from_row_type(type_name: &str) -> Self {
        let base = type_name
            .split('(')
            .next()
            .unwrap_or(type_name)
            .trim()
            .to_ascii_lowercase();
        match base.as_str() {
            "fixed" | "number" | "decimal" | "numeric" | "int" | "integer" | "bigint"
            | "smallint" | "tinyint" | "byteint" => Self::Fixed,
            "real" | "float" | "float4" | "float8" | "double" | "double precision" => Self::Real,
            "decfloat" => Self::Decfloat,
            "text" | "varchar" | "string" | "char" | "character" => Self::Text,
            "binary" | "varbinary" => Self::Binary,
            "boolean" => Self::Boolean,
            "date" => Self::Date,
            "time" => Self::Time,
            "timestamp_ntz" | "datetime" => Self::TimestampNtz,
            "timestamp_ltz" => Self::TimestampLtz,
            "timestamp_tz" => Self::TimestampTz,
            "variant" => Self::Variant,
            "object" => Self::Object,
            "array" => Self::Array,
            _ => Self::Other,
        }
    }
}

/// How a column's cells are represented in `typed.v1` (`columns[].json_repr`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonRepr {
    /// A JSON integer.
    Integer,
    /// An exact decimal string.
    DecimalString,
    /// A JSON number, or `"NaN"` / `"Infinity"` / `"-Infinity"`.
    Float,
    /// A JSON bool.
    Bool,
    /// A string.
    String,
    /// A hex string of the bytes.
    Hex,
    /// `"YYYY-MM-DD"`.
    Date,
    /// `"HH:MM:SS.fffffffff"`.
    Time,
    /// `"YYYY-MM-DDTHH:MM:SS.fffffffff"`, no offset.
    TimestampNtz,
    /// RFC 3339 in UTC (`Z`).
    TimestampUtc,
    /// RFC 3339 with the value's own offset.
    TimestampOffset,
    /// A parsed JSON value.
    Json,
    /// The wire string, uninterpreted.
    Wire,
}

impl JsonRepr {
    /// The stable token used in envelopes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Integer => "integer",
            Self::DecimalString => "decimal_string",
            Self::Float => "float",
            Self::Bool => "bool",
            Self::String => "string",
            Self::Hex => "hex",
            Self::Date => "date",
            Self::Time => "time",
            Self::TimestampNtz => "timestamp_ntz",
            Self::TimestampUtc => "timestamp_utc",
            Self::TimestampOffset => "timestamp_offset",
            Self::Json => "json",
            Self::Wire => "wire",
        }
    }
}

/// A cell that does not match its column's wire convention. The value itself
/// is never included: it may be sensitive data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TypedCellError {
    /// What was wrong, e.g. "not a decimal".
    pub reason: &'static str,
}

impl std::fmt::Display for TypedCellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason)
    }
}

impl std::error::Error for TypedCellError {}

/// The decoder for one result column, chosen from its `rowType` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColumnCodec {
    /// The type family.
    pub logical: LogicalType,
    /// `rowType.precision`, when present.
    pub precision: Option<i64>,
    /// `rowType.scale`, when present.
    pub scale: Option<i64>,
}

/// Largest FIXED precision that is always exact as a JSON number (2^53 > 10^15).
const MAX_EXACT_INTEGER_PRECISION: i64 = 15;
const NANOS_PER_SECOND: i128 = 1_000_000_000;
const SECONDS_PER_DAY: i128 = 86_400;

impl ColumnCodec {
    /// The codec for a `rowType` entry.
    #[must_use]
    pub fn new(type_name: &str, precision: Option<i64>, scale: Option<i64>) -> Self {
        Self {
            logical: LogicalType::from_row_type(type_name),
            precision,
            scale,
        }
    }

    /// The representation every cell of this column gets.
    #[must_use]
    pub fn json_repr(&self) -> JsonRepr {
        match self.logical {
            LogicalType::Fixed
                if self.scale.unwrap_or(0) == 0
                    && self
                        .precision
                        .is_some_and(|precision| precision <= MAX_EXACT_INTEGER_PRECISION) =>
            {
                JsonRepr::Integer
            }
            LogicalType::Fixed | LogicalType::Decfloat => JsonRepr::DecimalString,
            LogicalType::Real => JsonRepr::Float,
            LogicalType::Boolean => JsonRepr::Bool,
            LogicalType::Text => JsonRepr::String,
            LogicalType::Binary => JsonRepr::Hex,
            LogicalType::Date => JsonRepr::Date,
            LogicalType::Time => JsonRepr::Time,
            LogicalType::TimestampNtz => JsonRepr::TimestampNtz,
            LogicalType::TimestampLtz => JsonRepr::TimestampUtc,
            LogicalType::TimestampTz => JsonRepr::TimestampOffset,
            LogicalType::Variant | LogicalType::Object | LogicalType::Array => JsonRepr::Json,
            LogicalType::Other => JsonRepr::Wire,
        }
    }

    /// Decode one wire cell (`None` is SQL NULL).
    pub fn decode(&self, wire: Option<&str>) -> Result<Value, TypedCellError> {
        let Some(wire) = wire else {
            return Ok(Value::Null);
        };
        match self.json_repr() {
            JsonRepr::Integer => wire
                .parse::<i64>()
                .map(Value::from)
                .map_err(|_| TypedCellError {
                    reason: "not an integer",
                }),
            JsonRepr::DecimalString => {
                // FIXED arrives as plain digits; only DECFLOAT uses an exponent.
                if is_decimal(wire, self.logical == LogicalType::Decfloat) {
                    Ok(Value::String(wire.to_owned()))
                } else {
                    Err(TypedCellError {
                        reason: "not a decimal",
                    })
                }
            }
            JsonRepr::Float => decode_float(wire),
            JsonRepr::Bool => match wire.to_ascii_lowercase().as_str() {
                "true" | "1" => Ok(Value::Bool(true)),
                "false" | "0" => Ok(Value::Bool(false)),
                _ => Err(TypedCellError {
                    reason: "not a boolean",
                }),
            },
            JsonRepr::String | JsonRepr::Wire => Ok(Value::String(wire.to_owned())),
            JsonRepr::Hex => {
                if wire.len() % 2 == 0 && wire.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    Ok(Value::String(wire.to_owned()))
                } else {
                    Err(TypedCellError { reason: "not hex" })
                }
            }
            JsonRepr::Date => {
                let days = wire.parse::<i64>().map_err(|_| TypedCellError {
                    reason: "not a day count",
                })?;
                Ok(Value::String(format_date(i128::from(days))))
            }
            JsonRepr::Time => {
                let nanos = parse_epoch_nanos(wire)?;
                if !(0..SECONDS_PER_DAY * NANOS_PER_SECOND).contains(&nanos) {
                    return Err(TypedCellError {
                        reason: "time of day out of range",
                    });
                }
                Ok(Value::String(format_time_of_day(nanos)))
            }
            JsonRepr::TimestampNtz => {
                let nanos = parse_epoch_nanos(wire)?;
                Ok(Value::String(format_timestamp(nanos)))
            }
            JsonRepr::TimestampUtc => {
                let nanos = parse_epoch_nanos(wire)?;
                Ok(Value::String(format!("{}Z", format_timestamp(nanos))))
            }
            JsonRepr::TimestampOffset => decode_timestamp_tz(wire),
            JsonRepr::Json => {
                if !json_numbers_are_exact(wire) {
                    return Err(TypedCellError {
                        reason: "holds a number a JSON number cannot carry exactly",
                    });
                }
                serde_json::from_str(wire).map_err(|_| TypedCellError { reason: "not JSON" })
            }
        }
    }
}

/// Whether every number literal in a JSON text survives a round trip through
/// an `i64` or `f64` JSON number: integers within `i64`, other numbers with at
/// most 15 significant digits. A VARIANT holding `99999999999999999999` would
/// otherwise become `1e20`.
fn json_numbers_are_exact(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            match byte {
                b'\\' => index += 1,
                b'"' => in_string = false,
                _ => {}
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            while index < bytes.len()
                && matches!(bytes[index], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
            {
                index += 1;
            }
            if !number_is_exact(&text[start..index]) {
                return false;
            }
            continue;
        }
        index += 1;
    }
    true
}

fn number_is_exact(token: &str) -> bool {
    if token
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'-')
    {
        return token.parse::<i64>().is_ok();
    }
    let mantissa = token.split(['e', 'E']).next().unwrap_or(token);
    let significant = mantissa
        .bytes()
        .filter(u8::is_ascii_digit)
        .skip_while(|&digit| digit == b'0')
        .count();
    significant <= 15 && token.parse::<f64>().is_ok_and(f64::is_finite)
}

/// `[-+]digits[.digits]`, as FIXED and DECFLOAT arrive; DECFLOAT may carry an
/// exponent (`1.5E+39`).
fn is_decimal(text: &str, allow_exponent: bool) -> bool {
    let unsigned = text.strip_prefix(['-', '+']).unwrap_or(text);
    let (mantissa, exponent) = match unsigned.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, Some(exponent)),
        None => (unsigned, None),
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    let mantissa_ok = match mantissa.split_once('.') {
        Some((whole, fraction)) => digits(whole) && digits(fraction),
        None => digits(mantissa),
    };
    let exponent_ok = match exponent {
        None => true,
        Some(exponent) => {
            allow_exponent && digits(exponent.strip_prefix(['-', '+']).unwrap_or(exponent))
        }
    };
    mantissa_ok && exponent_ok
}

fn decode_float(wire: &str) -> Result<Value, TypedCellError> {
    match wire.to_ascii_lowercase().as_str() {
        "nan" => return Ok(Value::String("NaN".to_owned())),
        "inf" | "+inf" | "infinity" => return Ok(Value::String("Infinity".to_owned())),
        "-inf" | "-infinity" => return Ok(Value::String("-Infinity".to_owned())),
        _ => {}
    }
    let value = wire.parse::<f64>().map_err(|_| TypedCellError {
        reason: "not a float",
    })?;
    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .ok_or(TypedCellError {
            reason: "not a finite float",
        })
}

/// `"<seconds>[.<fraction>]"` (optionally negative) as nanoseconds; at most nine
/// fraction digits.
fn parse_epoch_nanos(text: &str) -> Result<i128, TypedCellError> {
    let bad = TypedCellError {
        reason: "not fractional seconds",
    };
    let (negative, unsigned) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let (whole, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 9
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(bad);
    }
    let seconds = whole.parse::<i128>().map_err(|_| bad)?;
    let mut nanos = 0_i128;
    for (index, byte) in fraction.bytes().enumerate() {
        let position = u32::try_from(8 - index).map_err(|_| bad)?;
        nanos += i128::from(byte - b'0') * 10_i128.pow(position);
    }
    let total = seconds
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(bad)?;
    Ok(if negative { -total } else { total })
}

fn decode_timestamp_tz(wire: &str) -> Result<Value, TypedCellError> {
    let (instant, offset) = wire.split_once(' ').ok_or(TypedCellError {
        reason: "TIMESTAMP_TZ without an offset",
    })?;
    let raw_offset = offset.trim().parse::<i128>().map_err(|_| TypedCellError {
        reason: "not an offset",
    })?;
    if !(0..=2_880).contains(&raw_offset) {
        return Err(TypedCellError {
            reason: "offset out of range",
        });
    }
    let offset_minutes = raw_offset - 1_440;
    let local = parse_epoch_nanos(instant)? + offset_minutes * 60 * NANOS_PER_SECOND;
    let sign = if offset_minutes < 0 { '-' } else { '+' };
    let magnitude = offset_minutes.abs();
    Ok(Value::String(format!(
        "{}{sign}{:02}:{:02}",
        format_timestamp(local),
        magnitude / 60,
        magnitude % 60
    )))
}

/// `"YYYY-MM-DDTHH:MM:SS.fffffffff"` for nanoseconds since the epoch.
fn format_timestamp(nanos: i128) -> String {
    let day_nanos = SECONDS_PER_DAY * NANOS_PER_SECOND;
    let days = nanos.div_euclid(day_nanos);
    let within_day = nanos.rem_euclid(day_nanos);
    format!("{}T{}", format_date(days), format_time_of_day(within_day))
}

/// `"HH:MM:SS.fffffffff"` for nanoseconds since midnight.
fn format_time_of_day(nanos: i128) -> String {
    let seconds = nanos / NANOS_PER_SECOND;
    let fraction = nanos % NANOS_PER_SECOND;
    format!(
        "{:02}:{:02}:{:02}.{fraction:09}",
        seconds / 3_600,
        (seconds / 60) % 60,
        seconds % 60
    )
}

/// `"YYYY-MM-DD"` for days since 1970-01-01 (proleptic Gregorian; years
/// outside 0..=9999 keep their sign and extra digits).
fn format_date(days: i128) -> String {
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i128::from(month <= 2);
    if year < 0 {
        format!("-{:04}-{month:02}-{day:02}", -year)
    } else {
        format!("{year:04}-{month:02}-{day:02}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(type_name: &str, precision: Option<i64>, scale: Option<i64>, wire: &str) -> Value {
        ColumnCodec::new(type_name, precision, scale)
            .decode(Some(wire))
            .unwrap_or_else(|error| panic!("{type_name} {wire}: {error}"))
    }

    /// The testkit fixture row, cell by cell.
    #[test]
    fn documented_wire_conventions_decode_to_typed_values() {
        assert_eq!(
            decode("FIXED", Some(38), Some(2), "12345678901234567.89"),
            "12345678901234567.89"
        );
        assert_eq!(
            decode("NUMBER", Some(38), Some(0), "99999999999999999999"),
            "99999999999999999999"
        );
        assert_eq!(decode("REAL", None, None, "1.25"), 1.25);
        assert_eq!(
            decode(
                "DECFLOAT",
                None,
                None,
                "1.2345678901234567890123456789012345678E+39"
            ),
            "1.2345678901234567890123456789012345678E+39"
        );
        assert_eq!(decode("BOOLEAN", None, None, "true"), true);
        assert_eq!(decode("DATE", None, None, "18262"), "2020-01-01");
        assert_eq!(
            decode("TIME", None, Some(9), "82919.000000000"),
            "23:01:59.000000000"
        );
        assert_eq!(
            decode("TIMESTAMP_NTZ", None, Some(9), "1611871777.123456789"),
            "2021-01-28T22:09:37.123456789"
        );
        assert_eq!(
            decode("TIMESTAMP_LTZ", None, Some(9), "1611871777.123456789"),
            "2021-01-28T22:09:37.123456789Z"
        );
        assert_eq!(
            decode("TIMESTAMP_TZ", None, Some(9), "1616173619.000000000 1500"),
            "2021-03-19T18:06:59.000000000+01:00"
        );
        assert_eq!(decode("BINARY", None, None, "DEADBEEF"), "DEADBEEF");
        assert_eq!(
            decode("VARIANT", None, None, r#"{"k":[1,2]}"#),
            serde_json::json!({"k": [1, 2]})
        );
        assert_eq!(
            decode("OBJECT", None, None, r#"{"nested":{"ok":true}}"#),
            serde_json::json!({"nested": {"ok": true}})
        );
        assert_eq!(
            decode("ARRAY", None, None, r#"[1,"two",null]"#),
            serde_json::json!([1, "two", null])
        );
        assert_eq!(
            ColumnCodec::new("TEXT", None, None).decode(None),
            Ok(Value::Null)
        );
    }

    #[test]
    fn small_integers_are_numbers_and_everything_else_stays_exact() {
        assert_eq!(decode("fixed", Some(10), Some(0), "-42"), -42);
        assert_eq!(
            decode("fixed", Some(15), Some(0), "999999999999999"),
            999_999_999_999_999_i64
        );
        // Precision 16+ can exceed 2^53: a string, never a lossy number.
        assert_eq!(
            decode(
                "fixed",
                Some(38),
                Some(0),
                "10000000000000000000000000000000000000"
            ),
            "10000000000000000000000000000000000000"
        );
        // Unknown precision: exact string.
        assert_eq!(decode("fixed", None, Some(0), "7"), "7");
        // Scale > 0 is never divided or parsed through f64 (0.1 + 0.2 stays exact).
        assert_eq!(decode("fixed", Some(38), Some(2), "0.30"), "0.30");
        assert_eq!(
            decode(
                "fixed",
                Some(38),
                Some(37),
                "0.1000000000000000000000000000000000001"
            ),
            "0.1000000000000000000000000000000000001"
        );
        assert_eq!(
            ColumnCodec::new("fixed", Some(38), Some(2)).json_repr(),
            JsonRepr::DecimalString
        );
        assert!(
            ColumnCodec::new("fixed", Some(10), Some(0))
                .decode(Some("1.5"))
                .is_err()
        );
        assert!(
            ColumnCodec::new("fixed", Some(38), Some(2))
                .decode(Some("1e5"))
                .is_err()
        );
        assert!(
            ColumnCodec::new("fixed", Some(38), Some(2))
                .decode(Some("12."))
                .is_err()
        );
    }

    #[test]
    fn floats_keep_special_values_as_strings() {
        assert_eq!(decode("real", None, None, "NaN"), "NaN");
        assert_eq!(decode("float", None, None, "inf"), "Infinity");
        assert_eq!(decode("double", None, None, "-inf"), "-Infinity");
        assert_eq!(decode("real", None, None, "-0.5"), -0.5);
        assert!(
            ColumnCodec::new("real", None, None)
                .decode(Some("abc"))
                .is_err()
        );
    }

    #[test]
    fn dates_and_times_before_the_epoch_and_at_the_edges() {
        assert_eq!(decode("date", None, None, "-1"), "1969-12-31");
        assert_eq!(decode("date", None, None, "-719162"), "0001-01-01");
        assert_eq!(decode("date", None, None, "2932896"), "9999-12-31");
        assert_eq!(decode("date", None, None, "0"), "1970-01-01");
        // Leap day.
        assert_eq!(decode("date", None, None, "11016"), "2000-02-29");
        // Negative epoch seconds floor toward the past, not toward zero.
        assert_eq!(
            decode("timestamp_ntz", None, Some(9), "-1.500000000"),
            "1969-12-31T23:59:58.500000000"
        );
        assert_eq!(
            decode("timestamp_ltz", None, Some(3), "0.001"),
            "1970-01-01T00:00:00.001000000Z"
        );
        assert_eq!(decode("time", None, Some(0), "0"), "00:00:00.000000000");
        assert_eq!(
            decode("time", None, Some(9), "86399.999999999"),
            "23:59:59.999999999"
        );
        assert!(
            ColumnCodec::new("time", None, Some(0))
                .decode(Some("86400"))
                .is_err()
        );
        assert!(
            ColumnCodec::new("timestamp_ntz", None, Some(9))
                .decode(Some("1.1234567890"))
                .is_err(),
            "ten fraction digits are not a Snowflake timestamp"
        );
    }

    #[test]
    fn timestamp_tz_offsets_span_both_extremes() {
        assert_eq!(
            decode("timestamp_tz", None, Some(9), "0.000000000 1440"),
            "1970-01-01T00:00:00.000000000+00:00"
        );
        assert_eq!(
            decode("timestamp_tz", None, Some(9), "0.000000000 0"),
            "1969-12-31T00:00:00.000000000-24:00"
        );
        assert_eq!(
            decode("timestamp_tz", None, Some(9), "0.000000000 2880"),
            "1970-01-02T00:00:00.000000000+24:00"
        );
        assert_eq!(
            decode("timestamp_tz", None, Some(0), "1616173619 1110"),
            "2021-03-19T11:36:59.000000000-05:30"
        );
        let codec = ColumnCodec::new("timestamp_tz", None, Some(9));
        assert!(codec.decode(Some("1616173619.0")).is_err(), "no offset");
        assert!(codec.decode(Some("1616173619.0 2881")).is_err());
    }

    #[test]
    fn json_and_binary_and_booleans_are_validated() {
        assert_eq!(decode("variant", None, None, "{}"), serde_json::json!({}));
        assert_eq!(
            decode("variant", None, None, "[[1,[2]],{\"a\":null}]"),
            serde_json::json!([[1, [2]], {"a": null}])
        );
        assert!(
            ColumnCodec::new("variant", None, None)
                .decode(Some("{"))
                .is_err()
        );
        // Numbers a JSON number cannot carry exactly are refused (the caller
        // then keeps the column's wire strings), never rounded.
        let variant = ColumnCodec::new("variant", None, None);
        assert!(
            variant
                .decode(Some(r#"{"big":99999999999999999999}"#))
                .is_err()
        );
        assert!(
            variant.decode(Some("18446744073709551615")).is_err(),
            "u64 beyond i64"
        );
        assert!(variant.decode(Some("[0.12345678901234567]")).is_err());
        assert_eq!(
            decode(
                "variant",
                None,
                None,
                r#"{"id":-9223372036854775808,"x":1.5e-3}"#
            ),
            serde_json::json!({"id": i64::MIN, "x": 0.0015})
        );
        // Digits inside strings are text, not numbers.
        assert_eq!(
            decode("variant", None, None, r#"{"s":"99999999999999999999\"1"}"#),
            serde_json::json!({"s": "99999999999999999999\"1"})
        );
        assert!(
            ColumnCodec::new("binary", None, None)
                .decode(Some("ABC"))
                .is_err()
        );
        assert!(
            ColumnCodec::new("binary", None, None)
                .decode(Some("ZZ"))
                .is_err()
        );
        assert_eq!(decode("boolean", None, None, "FALSE"), false);
        assert!(
            ColumnCodec::new("boolean", None, None)
                .decode(Some("yes"))
                .is_err()
        );
    }

    #[test]
    fn unknown_types_keep_the_wire_string() {
        let codec = ColumnCodec::new("GEOGRAPHY", None, None);
        assert_eq!(codec.json_repr(), JsonRepr::Wire);
        assert_eq!(
            codec.decode(Some("POINT(1 2)")),
            Ok(Value::String("POINT(1 2)".to_owned()))
        );
        assert_eq!(
            LogicalType::from_row_type("NUMBER(38,0)"),
            LogicalType::Fixed
        );
        assert_eq!(
            LogicalType::from_row_type("timestamp_tz"),
            LogicalType::TimestampTz
        );
    }

    /// A decode error never carries the cell value (it may be sensitive).
    #[test]
    fn errors_do_not_echo_the_value() {
        let error = ColumnCodec::new("date", None, None)
            .decode(Some("secret-ish-value"))
            .err()
            .unwrap_or(TypedCellError { reason: "" });
        assert!(!error.to_string().contains("secret"));
        assert!(!error.reason.is_empty());
    }
}
