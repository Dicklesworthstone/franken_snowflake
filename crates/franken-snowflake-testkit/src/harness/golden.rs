//! Deterministic golden-comparison framework.
//!
//! Goldens are compared as **canonical bytes**: object keys are emitted in
//! sorted order (independent of `serde_json`'s `Map` ordering, so enabling the
//! `preserve_order` feature elsewhere in the workspace cannot perturb a golden),
//! and **volatile fields** — wall-clock timestamps, hostnames, content hashes,
//! and per-run identifiers — are replaced with [`CANONICAL_PLACEHOLDER`] before
//! comparison so a re-run is byte-identical.
//!
//! When two numeric leaves disagree the mismatch report includes their exact
//! IEEE-754 bit patterns ([`FloatBits`]), because "0.1 + 0.2 != 0.3" failures
//! are invisible in decimal but obvious in hex.
//!
//! Cross-platform discipline: [`assert_no_cr`] / [`assert_lf_only`] enforce the
//! `eol=lf` golden rule (`docs/proof_lanes.md`, Lane 7) so a golden written on
//! Windows cannot silently carry `\r`.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

use serde_json::Value;

/// The text every volatile field is rewritten to before comparison.
pub const CANONICAL_PLACEHOLDER: &str = "<volatile>";

/// The environment variable that, when set to `1`, makes [`check_golden_file`]
/// rewrite the golden on disk instead of failing — the usual "bless" workflow.
pub const UPDATE_GOLDENS_ENV: &str = "FSNOW_UPDATE_GOLDENS";

/// Which volatile fields canonicalization zeroes, and how leaves are compared.
///
/// [`GoldenConfig::default`] zeroes the time / host / hash families plus the
/// common per-run identifiers. [`GoldenConfig::strict`] zeroes nothing (exact
/// structural comparison). Extend either with [`GoldenConfig::with_volatile_key`]
/// / [`GoldenConfig::with_volatile_suffix`].
#[derive(Clone, Debug)]
pub struct GoldenConfig {
    volatile_exact: BTreeSet<String>,
    volatile_suffixes: Vec<String>,
}

/// Exact (lower-cased) key names treated as volatile by [`GoldenConfig::default`].
///
/// Deliberately excludes *stable* identifiers like `command_id` and `request_id`
/// (the envelope contract makes those deterministic and they are often the value
/// under test) and server/domain ids like `query_id` / `statement_handle` — add
/// those per-fixture via [`GoldenConfig::with_volatile_key`] when a particular
/// golden needs them zeroed.
const DEFAULT_VOLATILE_EXACT: &[&str] = &[
    // host / process identity
    "host",
    "hostname",
    "pid",
    "ppid",
    "tid",
    "thread_id",
    // wall-clock
    "time",
    "now",
    "date",
    "today",
    "timestamp",
    "uptime",
    // per-run correlation identifiers (ephemeral noise, never under test)
    "trace_id",
    "run_id",
    "session_id",
    "span_id",
    "parent_id",
    "correlation_id",
    "nonce",
    "uuid",
    "etag",
    "seed",
];

/// Key suffixes (lower-cased) treated as volatile by [`GoldenConfig::default`].
const DEFAULT_VOLATILE_SUFFIXES: &[&str] = &[
    // time
    "_at",
    "_ms",
    "_ns",
    "_us",
    "_secs",
    "_seconds",
    "_time",
    "_timestamp",
    "_ts",
    "_duration",
    "_elapsed",
    "_latency",
    // host
    "_host",
    "_hostname",
    // hash / content address
    "_hash",
    "_sha256",
    "_fingerprint",
    "_etag",
    "_uuid",
];

impl Default for GoldenConfig {
    fn default() -> Self {
        Self {
            volatile_exact: DEFAULT_VOLATILE_EXACT
                .iter()
                .map(|k| (*k).to_owned())
                .collect(),
            volatile_suffixes: DEFAULT_VOLATILE_SUFFIXES
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        }
    }
}

impl GoldenConfig {
    /// A configuration that zeroes nothing: keys are sorted and bytes compared
    /// exactly. Use this for fixtures where an id/timestamp is the value under
    /// test.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            volatile_exact: BTreeSet::new(),
            volatile_suffixes: Vec::new(),
        }
    }

    /// Treat `key` (matched case-insensitively, exactly) as volatile.
    #[must_use]
    pub fn with_volatile_key(mut self, key: impl Into<String>) -> Self {
        self.volatile_exact.insert(key.into().to_ascii_lowercase());
        self
    }

    /// Treat any key ending in `suffix` (case-insensitively) as volatile.
    #[must_use]
    pub fn with_volatile_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.volatile_suffixes
            .push(suffix.into().to_ascii_lowercase());
        self
    }

    /// Whether `key` is treated as volatile under this configuration.
    #[must_use]
    pub fn is_volatile(&self, key: &str) -> bool {
        let lowered = key.to_ascii_lowercase();
        self.volatile_exact.contains(&lowered)
            || self
                .volatile_suffixes
                .iter()
                .any(|suffix| lowered.ends_with(suffix.as_str()))
    }
}

/// Return a copy of `value` with every volatile field replaced by
/// [`CANONICAL_PLACEHOLDER`]. Object key order is irrelevant here — sorting
/// happens at serialization in [`to_canonical_json`].
#[must_use]
pub fn canonicalize(value: &Value, cfg: &GoldenConfig) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (key, child) in map {
                if cfg.is_volatile(key) {
                    out.insert(key.clone(), Value::String(CANONICAL_PLACEHOLDER.to_owned()));
                } else {
                    out.insert(key.clone(), canonicalize(child, cfg));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| canonicalize(item, cfg)).collect())
        }
        other => other.clone(),
    }
}

/// Serialize `value` to canonical JSON: volatile fields zeroed, object keys
/// sorted, compact separators, **LF only**. The output is byte-stable across
/// runs and platforms.
#[must_use]
pub fn to_canonical_json(value: &Value, cfg: &GoldenConfig) -> String {
    let canonical = canonicalize(value, cfg);
    let mut out = String::new();
    write_canonical(&canonical, &mut out);
    out
}

/// The canonical bytes of `value` (see [`to_canonical_json`]).
#[must_use]
pub fn canonical_bytes(value: &Value, cfg: &GoldenConfig) -> Vec<u8> {
    to_canonical_json(value, cfg).into_bytes()
}

/// Recursive canonical writer: sorts object keys itself so the result does not
/// depend on `serde_json::Map`'s ordering semantics.
fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => write_json_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                if let Some(child) = map.get(*key) {
                    write_canonical(child, out);
                }
            }
            out.push('}');
        }
    }
}

/// Append `text` as a JSON string literal (delegating escaping to `serde_json`).
fn write_json_string(text: &str, out: &mut String) {
    match serde_json::to_string(text) {
        Ok(escaped) => out.push_str(&escaped),
        // A `&str` always serializes; on the unreachable error path fall back to
        // a clearly-bogus literal rather than panicking under the workspace's
        // `clippy::panic` deny.
        Err(_) => out.push_str("\"<unserializable-string>\""),
    }
}

/// The class of a golden mismatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MismatchKind {
    /// Same JSON type, different value.
    Value,
    /// Different JSON types (e.g. number vs string).
    Type,
    /// Arrays of different length.
    Length,
    /// A key present in the expected golden is absent from the actual value.
    MissingKey,
    /// A key present in the actual value is absent from the expected golden.
    ExtraKey,
}

impl MismatchKind {
    /// A short human label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Value => "value mismatch",
            Self::Type => "type mismatch",
            Self::Length => "array length mismatch",
            Self::MissingKey => "missing key",
            Self::ExtraKey => "unexpected key",
        }
    }
}

/// The IEEE-754 bit patterns of a numeric mismatch — the part of a float diff a
/// decimal rendering hides.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FloatBits {
    /// Expected value as `f64`.
    pub expected: f64,
    /// Actual value as `f64`.
    pub actual: f64,
    /// `expected.to_bits()`.
    pub expected_bits: u64,
    /// `actual.to_bits()`.
    pub actual_bits: u64,
}

/// The first structural difference between an expected golden and an actual
/// value, located by a JSON path (`$.a.b[2]`).
#[derive(Clone, Debug, PartialEq)]
pub struct GoldenMismatch {
    /// JSON path to the differing node.
    pub path: String,
    /// The class of difference.
    pub kind: MismatchKind,
    /// Canonical rendering of the expected node.
    pub expected: String,
    /// Canonical rendering of the actual node.
    pub actual: String,
    /// IEEE-754 bits, populated only for numeric value mismatches.
    pub float_bits: Option<FloatBits>,
}

impl fmt::Display for GoldenMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "golden {} at {}: expected {}, got {}",
            self.kind.label(),
            self.path,
            self.expected,
            self.actual
        )?;
        if let Some(bits) = self.float_bits {
            write!(
                f,
                "\n  ieee754 expected: {} = {:#018x}\n  ieee754 actual:   {} = {:#018x}",
                bits.expected, bits.expected_bits, bits.actual, bits.actual_bits
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for GoldenMismatch {}

/// Compare `actual` against the `expected` golden under `cfg`, returning the
/// first difference. Both sides are canonicalized first, so volatile fields are
/// ignored and key order is irrelevant.
///
/// # Errors
/// Returns a [`GoldenMismatch`] describing the first differing node.
pub fn compare(expected: &Value, actual: &Value, cfg: &GoldenConfig) -> Result<(), GoldenMismatch> {
    let expected = canonicalize(expected, cfg);
    let actual = canonicalize(actual, cfg);
    compare_canonical(&expected, &actual, "$")
}

fn compare_canonical(expected: &Value, actual: &Value, path: &str) -> Result<(), GoldenMismatch> {
    match (expected, actual) {
        (Value::Null, Value::Null) => Ok(()),
        (Value::Bool(left), Value::Bool(right)) => {
            if left == right {
                Ok(())
            } else {
                Err(value_mismatch(
                    path,
                    left.to_string(),
                    right.to_string(),
                    None,
                ))
            }
        }
        (Value::String(left), Value::String(right)) => {
            if left == right {
                Ok(())
            } else {
                Err(value_mismatch(
                    path,
                    format!("{left:?}"),
                    format!("{right:?}"),
                    None,
                ))
            }
        }
        (Value::Number(left), Value::Number(right)) => {
            if left.to_string() == right.to_string() {
                Ok(())
            } else {
                let float_bits = match (left.as_f64(), right.as_f64()) {
                    (Some(expected), Some(actual)) => Some(FloatBits {
                        expected,
                        actual,
                        expected_bits: expected.to_bits(),
                        actual_bits: actual.to_bits(),
                    }),
                    _ => None,
                };
                Err(value_mismatch(
                    path,
                    left.to_string(),
                    right.to_string(),
                    float_bits,
                ))
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            if left.len() != right.len() {
                return Err(GoldenMismatch {
                    path: path.to_owned(),
                    kind: MismatchKind::Length,
                    expected: left.len().to_string(),
                    actual: right.len().to_string(),
                    float_bits: None,
                });
            }
            for (index, (left_item, right_item)) in left.iter().zip(right.iter()).enumerate() {
                compare_canonical(left_item, right_item, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        (Value::Object(left), Value::Object(right)) => {
            let mut keys: BTreeSet<&String> = left.keys().collect();
            keys.extend(right.keys());
            for key in keys {
                match (left.get(key), right.get(key)) {
                    (Some(left_child), Some(right_child)) => {
                        compare_canonical(left_child, right_child, &format!("{path}.{key}"))?;
                    }
                    (Some(left_child), None) => {
                        return Err(GoldenMismatch {
                            path: format!("{path}.{key}"),
                            kind: MismatchKind::MissingKey,
                            expected: short_render(left_child),
                            actual: "<absent>".to_owned(),
                            float_bits: None,
                        });
                    }
                    (None, Some(right_child)) => {
                        return Err(GoldenMismatch {
                            path: format!("{path}.{key}"),
                            kind: MismatchKind::ExtraKey,
                            expected: "<absent>".to_owned(),
                            actual: short_render(right_child),
                            float_bits: None,
                        });
                    }
                    (None, None) => {}
                }
            }
            Ok(())
        }
        _ => Err(GoldenMismatch {
            path: path.to_owned(),
            kind: MismatchKind::Type,
            expected: type_name(expected).to_owned(),
            actual: type_name(actual).to_owned(),
            float_bits: None,
        }),
    }
}

fn value_mismatch(
    path: &str,
    expected: String,
    actual: String,
    float_bits: Option<FloatBits>,
) -> GoldenMismatch {
    GoldenMismatch {
        path: path.to_owned(),
        kind: MismatchKind::Value,
        expected,
        actual,
        float_bits,
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn short_render(value: &Value) -> String {
    let rendered = value.to_string();
    if rendered.len() > 80 {
        // Truncate at or below byte 79, but never inside a multi-byte UTF-8
        // sequence — `&rendered[..79]` would panic when byte 79 is not a char
        // boundary (e.g. a non-ASCII value over 80 bytes), which the workspace's
        // `clippy::panic` deny forbids on this diagnostics path.
        let mut end = 79;
        while end > 0 && !rendered.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &rendered[..end])
    } else {
        rendered
    }
}

/// Whether `text` contains a carriage return (`\r`).
#[must_use]
pub fn has_cr(text: &str) -> bool {
    text.contains('\r')
}

/// The cross-platform golden discipline error: a stray `\r` in golden content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrlfViolation {
    /// Byte offset of the first carriage return.
    pub byte_offset: usize,
    /// 1-based line number of the first carriage return.
    pub line: usize,
}

impl fmt::Display for CrlfViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "carriage return at byte {} (line {}); goldens must be LF-only (eol=lf)",
            self.byte_offset, self.line
        )
    }
}

impl std::error::Error for CrlfViolation {}

/// Assert `text` is LF-only, as goldens must be (`docs/proof_lanes.md`, Lane 7).
///
/// # Errors
/// Returns a [`CrlfViolation`] locating the first `\r`.
pub fn assert_no_cr(text: &str) -> Result<(), CrlfViolation> {
    assert_lf_only(text.as_bytes())
}

/// Byte-level variant of [`assert_no_cr`] for golden file contents.
///
/// # Errors
/// Returns a [`CrlfViolation`] locating the first `\r`.
pub fn assert_lf_only(bytes: &[u8]) -> Result<(), CrlfViolation> {
    let mut line = 1usize;
    for (offset, byte) in bytes.iter().enumerate() {
        match byte {
            b'\r' => {
                return Err(CrlfViolation {
                    byte_offset: offset,
                    line,
                });
            }
            b'\n' => line += 1,
            _ => {}
        }
    }
    Ok(())
}

/// An error from a golden file operation.
#[derive(Debug)]
pub enum GoldenError {
    /// The golden file could not be read or written.
    Io(std::io::Error),
    /// The golden file was not valid UTF-8.
    Utf8,
    /// The golden file contained a `\r` (violates `eol=lf`).
    Crlf(CrlfViolation),
    /// The golden file was not valid JSON.
    Parse(serde_json::Error),
    /// The value did not match the golden.
    Mismatch(GoldenMismatch),
}

impl fmt::Display for GoldenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "golden io error: {error}"),
            Self::Utf8 => write!(f, "golden file is not valid UTF-8"),
            Self::Crlf(violation) => write!(f, "golden file has CRLF: {violation}"),
            Self::Parse(error) => write!(f, "golden file is not valid JSON: {error}"),
            Self::Mismatch(mismatch) => write!(f, "{mismatch}"),
        }
    }
}

impl std::error::Error for GoldenError {}

impl From<std::io::Error> for GoldenError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Write `value` to `path` as a canonical golden: sorted keys, volatile fields
/// zeroed, trailing newline, LF only.
///
/// # Errors
/// Returns [`GoldenError::Io`] if the file cannot be written.
pub fn write_golden(path: &Path, value: &Value, cfg: &GoldenConfig) -> Result<(), GoldenError> {
    let mut body = to_canonical_json(value, cfg);
    body.push('\n');
    std::fs::write(path, body)?;
    Ok(())
}

/// Compare `actual` against the golden stored at `path`.
///
/// If `UPDATE_GOLDENS_ENV` (`FSNOW_UPDATE_GOLDENS=1`) is set the golden is
/// (re)written from `actual` and the comparison succeeds — the "bless" flow.
///
/// # Errors
/// Returns [`GoldenError`] on read/parse/CRLF/mismatch.
pub fn check_golden_file(
    path: &Path,
    actual: &Value,
    cfg: &GoldenConfig,
) -> Result<(), GoldenError> {
    if std::env::var(UPDATE_GOLDENS_ENV).as_deref() == Ok("1") {
        return write_golden(path, actual, cfg);
    }
    let bytes = std::fs::read(path)?;
    assert_lf_only(&bytes).map_err(GoldenError::Crlf)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| GoldenError::Utf8)?;
    let expected: Value = serde_json::from_str(text).map_err(GoldenError::Parse)?;
    compare(&expected, actual, cfg).map_err(GoldenError::Mismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonicalization_zeroes_volatile_and_sorts_keys() {
        let cfg = GoldenConfig::default();
        let run_a = json!({
            "trace_id": "abc-123",
            "started_at": "2026-06-24T00:00:00Z",
            "host": "builder-7",
            "result_hash": "deadbeef",
            "rows": 3,
            "name": "scan",
        });
        let run_b = json!({
            "name": "scan",
            "rows": 3,
            "trace_id": "zzz-999",
            "started_at": "2026-06-25T11:22:33Z",
            "host": "builder-42",
            "result_hash": "cafef00d",
        });
        // Different volatile values, same logical payload, different key order.
        assert!(compare(&run_a, &run_b, &cfg).is_ok());
        assert_eq!(
            to_canonical_json(&run_a, &cfg),
            to_canonical_json(&run_b, &cfg)
        );
    }

    #[test]
    fn float_mismatch_reports_ieee754_bits() -> Result<(), String> {
        let cfg = GoldenConfig::strict();
        let expected = json!({ "ratio": 0.3_f64 });
        let actual = json!({ "ratio": 0.1_f64 + 0.2_f64 });
        let mismatch = compare(&expected, &actual, &cfg)
            .err()
            .ok_or_else(|| "0.1 + 0.2 should not byte-equal 0.3".to_owned())?;
        let bits = mismatch
            .float_bits
            .ok_or_else(|| "numeric mismatch must carry IEEE-754 bits".to_owned())?;
        assert_ne!(bits.expected_bits, bits.actual_bits);
        assert!(format!("{mismatch}").contains("ieee754"));
        Ok(())
    }

    #[test]
    fn crlf_discipline_locates_carriage_return() -> Result<(), String> {
        assert!(assert_no_cr("clean\nlf\nonly\n").is_ok());
        let violation = assert_no_cr("first\r\nsecond")
            .err()
            .ok_or_else(|| "CR must be rejected".to_owned())?;
        assert_eq!(violation.byte_offset, 5);
        assert_eq!(violation.line, 1);
        Ok(())
    }

    #[test]
    fn type_mismatch_is_reported_with_type_names() -> Result<(), String> {
        let cfg = GoldenConfig::strict();
        let mismatch = compare(&json!({ "v": 1 }), &json!({ "v": "1" }), &cfg)
            .err()
            .ok_or_else(|| "number vs string must mismatch".to_owned())?;
        assert_eq!(mismatch.kind, MismatchKind::Type);
        assert_eq!(mismatch.path, "$.v");
        assert_eq!(mismatch.expected, "number");
        assert_eq!(mismatch.actual, "string");
        Ok(())
    }

    #[test]
    fn array_length_mismatch_is_reported() -> Result<(), String> {
        let cfg = GoldenConfig::strict();
        let mismatch = compare(&json!({ "xs": [1, 2, 3] }), &json!({ "xs": [1, 2] }), &cfg)
            .err()
            .ok_or_else(|| "length difference must mismatch".to_owned())?;
        assert_eq!(mismatch.kind, MismatchKind::Length);
        assert_eq!(mismatch.path, "$.xs");
        assert_eq!(mismatch.expected, "3");
        assert_eq!(mismatch.actual, "2");
        Ok(())
    }

    #[test]
    fn missing_key_diff_truncates_long_multibyte_values_without_panicking() -> Result<(), String> {
        // Regression: short_render truncated with a raw byte slice `[..79]`, which
        // panics when byte 79 lands inside a multi-byte UTF-8 sequence. A missing
        // key whose value is a >80-byte string with `é` straddling that boundary
        // must produce a clean, ellipsized diff rather than a panic.
        let cfg = GoldenConfig::strict();
        let long_value = format!("{}é{}", "a".repeat(77), "b".repeat(40));
        let mismatch = compare(&json!({ "k": long_value }), &json!({}), &cfg)
            .err()
            .ok_or_else(|| "missing key must mismatch".to_owned())?;
        assert_eq!(mismatch.kind, MismatchKind::MissingKey);
        assert_eq!(mismatch.path, "$.k");
        assert!(
            mismatch.expected.ends_with('…'),
            "long value should be ellipsized: {}",
            mismatch.expected
        );
        Ok(())
    }

    #[test]
    fn missing_and_extra_keys_are_distinguished() -> Result<(), String> {
        let cfg = GoldenConfig::strict();
        let missing = compare(&json!({ "a": 1, "b": 2 }), &json!({ "a": 1 }), &cfg)
            .err()
            .ok_or_else(|| "missing key must mismatch".to_owned())?;
        assert_eq!(missing.kind, MismatchKind::MissingKey);
        assert_eq!(missing.path, "$.b");

        let extra = compare(&json!({ "a": 1 }), &json!({ "a": 1, "c": 3 }), &cfg)
            .err()
            .ok_or_else(|| "extra key must mismatch".to_owned())?;
        assert_eq!(extra.kind, MismatchKind::ExtraKey);
        assert_eq!(extra.path, "$.c");
        Ok(())
    }

    #[test]
    fn strict_config_does_not_zero_identifiers() -> Result<(), String> {
        // Under the default config trace_id is volatile, so differing ids match;
        // under strict() they are compared exactly and must mismatch.
        let left = json!({ "trace_id": "aaa" });
        let right = json!({ "trace_id": "bbb" });
        assert!(compare(&left, &right, &GoldenConfig::default()).is_ok());
        let mismatch = compare(&left, &right, &GoldenConfig::strict())
            .err()
            .ok_or_else(|| "strict compare must see differing ids".to_owned())?;
        assert_eq!(mismatch.path, "$.trace_id");
        Ok(())
    }

    #[test]
    fn stable_command_id_is_not_zeroed_by_default() -> Result<(), String> {
        // command_id is a deterministic envelope field; it must survive
        // canonicalization so two different commands do not collide.
        let cfg = GoldenConfig::default();
        let run = compare(
            &json!({ "command_id": "query.run" }),
            &json!({ "command_id": "catalog.scan" }),
            &cfg,
        );
        let mismatch = run
            .err()
            .ok_or_else(|| "command_id must stay stable".to_owned())?;
        assert_eq!(mismatch.path, "$.command_id");
        Ok(())
    }

    #[test]
    fn canonical_json_is_sorted_compact_and_lf_only() -> Result<(), String> {
        let cfg = GoldenConfig::strict();
        let value = json!({ "b": 1, "a": { "y": 2, "x": 1 }, "c": [3, 2, 1] });
        let canonical = to_canonical_json(&value, &cfg);
        assert_eq!(canonical, r#"{"a":{"x":1,"y":2},"b":1,"c":[3,2,1]}"#);
        assert!(assert_no_cr(&canonical).is_ok());
        Ok(())
    }

    #[test]
    fn write_then_check_golden_file_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = GoldenConfig::default();
        let dir = std::env::temp_dir().join("fsnow-harness-golden");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("envelope.golden.json");

        let golden = json!({ "command_id": "x", "trace_id": "run-A", "n": 7 });
        write_golden(&path, &golden, &cfg)?;

        // Written golden is LF-only, sorted, and newline-terminated.
        let bytes = std::fs::read(&path)?;
        assert_lf_only(&bytes)?;
        assert_eq!(bytes.last().copied(), Some(b'\n'));

        // A re-run with a *different* volatile trace_id still matches.
        let rerun = json!({ "command_id": "x", "trace_id": "run-B", "n": 7 });
        check_golden_file(&path, &rerun, &cfg)?;

        // A real difference (n: 7 -> 8) is caught.
        let drifted = json!({ "command_id": "x", "trace_id": "run-C", "n": 8 });
        assert!(check_golden_file(&path, &drifted, &cfg).is_err());

        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn on_disk_fixture_matches_a_fresh_run() -> Result<(), Box<dyn std::error::Error>> {
        let cfg = GoldenConfig::default();
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/golden/sample_run.golden.json"
        ));
        // The committed fixture is LF-only.
        assert_lf_only(&std::fs::read(path)?)?;

        // A fresh run with different volatile time/host/hash/trace values but the
        // same logical payload matches the committed golden.
        let fresh = json!({
            "command_id": "query.run",
            "data_source": "fixture",
            "ok": true,
            "outcome_kind": "success",
            "rows": [
                { "id": 1, "name": "alpha", "ratio": 0.25 },
                { "id": 2, "name": "beta", "ratio": 0.5 }
            ],
            "result_hash": "ffffffffffffffff",
            "row_count": 2,
            "started_at": "2030-01-01T12:34:56Z",
            "trace_id": "fixture-trace-9999"
        });
        check_golden_file(path, &fresh, &cfg)?;
        Ok(())
    }

    #[test]
    fn canonical_json_is_deterministic_and_idempotent() {
        let cfg = GoldenConfig::default();
        // Same logical value, different key-insertion orders, plus a volatile id.
        let a = json!({ "z": 1, "a": 2, "m": { "q": 1, "b": 2 }, "trace_id": "x" });
        let b = json!({ "a": 2, "trace_id": "y", "m": { "b": 2, "q": 1 }, "z": 1 });
        // Determinism: order-independent, byte-identical output.
        assert_eq!(to_canonical_json(&a, &cfg), to_canonical_json(&b, &cfg));
        // Idempotence: canonicalizing an already-canonical value is a no-op.
        let once = canonicalize(&a, &cfg);
        let twice = canonicalize(&once, &cfg);
        assert_eq!(once, twice);
    }
}
