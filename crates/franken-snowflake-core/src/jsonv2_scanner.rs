#![forbid(unsafe_code)]

//! Zero-copy SWAR (SIMD Within A Register) byte scanner for Snowflake SQL API
//! `jsonv2` result partitions.
//!
//! Operates directly on uncompressed `&[u8]` partition slices (`[[...]]` or
//! `{"data": [[...]]}` envelopes) without intermediate `serde_json::Value` ASTs
//! or per-cell `String` allocations when cells contain no JSON escape sequences.

use std::fmt;

/// A raw result partition referencing uncompressed `jsonv2` bytes directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawResultPartition<'a> {
    /// Partition index. Partition 0 is the inline `ResultSet.data` payload.
    pub index: u32,
    /// Raw uncompressed JSON 2D-array or envelope byte slice.
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

/// Structural or lexical error while scanning a raw `jsonv2` partition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Jsonv2ScanError {
    /// A row's cell count differed from the expected schema width.
    RowWidthMismatch {
        partition_index: u32,
        row_index: usize,
        expected: usize,
        actual: usize,
    },
    /// Row count overflowed `usize`.
    RowCountOverflow,
    /// Malformed JSON structure or invalid UTF-8/escape sequence.
    Decode { reason: &'static str },
}

impl fmt::Display for Jsonv2ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RowWidthMismatch {
                partition_index,
                row_index,
                expected,
                actual,
            } => write!(
                f,
                "row width mismatch in partition {partition_index}, row {row_index}: expected {expected} columns, got {actual}"
            ),
            Self::RowCountOverflow => write!(f, "row count overflowed usize"),
            Self::Decode { reason } => write!(f, "failed to decode jsonv2 partition: {reason}"),
        }
    }
}

impl std::error::Error for Jsonv2ScanError {}

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
pub fn extract_jsonv2_data_array(bytes: &[u8]) -> Result<&[u8], Jsonv2ScanError> {
    let len = bytes.len();
    let pos = skip_whitespace(bytes, 0);
    if pos >= len {
        return Err(Jsonv2ScanError::Decode {
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
                        let after_quote =
                            skip_json_string(bytes, str_start).ok_or(Jsonv2ScanError::Decode {
                                reason: "unterminated string in jsonv2 envelope",
                            })?;
                        let str_end = after_quote - 1;
                        let key_bytes = &bytes[str_start..str_end];
                        curr = skip_whitespace(bytes, after_quote);

                        // In valid JSON, a string at depth == 1 is an object key
                        // iff the next non-whitespace token is ':'.
                        if depth == 1 && key_bytes == b"data" && curr < len && bytes[curr] == b':' {
                            curr += 1;
                            curr = skip_whitespace(bytes, curr);
                            if curr >= len || bytes[curr] != b'[' {
                                return Err(Jsonv2ScanError::Decode {
                                    reason: "expected '[' at start of 'data' array in envelope",
                                });
                            }
                            let array_start = curr;
                            let mut arr_depth = 1usize;
                            curr += 1;
                            while curr < len && arr_depth > 0 {
                                match bytes[curr] {
                                    b'"' => {
                                        curr = skip_json_string(bytes, curr + 1).ok_or(
                                            Jsonv2ScanError::Decode {
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
                                return Err(Jsonv2ScanError::Decode {
                                    reason: "unclosed 'data' array in envelope",
                                });
                            }
                            let array_end = curr;
                            let after_array = skip_whitespace(bytes, array_end);
                            if after_array >= len || !matches!(bytes[after_array], b',' | b'}') {
                                return Err(Jsonv2ScanError::Decode {
                                    reason: "expected ',' or '}' after 'data' array in envelope",
                                });
                            }
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
            Err(Jsonv2ScanError::Decode {
                reason: "missing 'data' array in jsonv2 envelope object",
            })
        }
        _ => Err(Jsonv2ScanError::Decode {
            reason: "expected '[' or '{' at start of jsonv2 payload",
        }),
    }
}

/// Fast streaming byte scanner for Snowflake SQL API `jsonv2` 2D arrays.
///
/// Operates directly on `&[u8]` without intermediate `serde_json::Value` or
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

    /// Stream all rows from a `jsonv2` byte slice, calling `visit_cell` with each
    /// `(row_index, col_index, cell)` and mapping structural errors via `map_err`.
    pub fn scan_rows_with<E, M, F>(
        &mut self,
        bytes: &[u8],
        partition_index: u32,
        expected_columns: usize,
        mut map_err: M,
        mut visit_cell: F,
    ) -> Result<usize, E>
    where
        M: FnMut(Jsonv2ScanError) -> E,
        F: FnMut(usize, usize, CellSlice<'_>) -> Result<(), E>,
    {
        let bytes = extract_jsonv2_data_array(bytes).map_err(&mut map_err)?;
        let len = bytes.len();
        let mut pos = skip_whitespace(bytes, 0);
        if pos >= len {
            return Err(map_err(Jsonv2ScanError::Decode {
                reason: "unexpected EOF: expected '[' at start of jsonv2 array",
            }));
        }

        if bytes[pos] != b'[' {
            return Err(map_err(Jsonv2ScanError::Decode {
                reason: "expected '[' at start of jsonv2 array",
            }));
        }
        pos += 1;
        pos = skip_whitespace(bytes, pos);
        if pos >= len {
            return Err(map_err(Jsonv2ScanError::Decode {
                reason: "unexpected EOF: unclosed '[' at start of jsonv2 array",
            }));
        }
        if bytes[pos] == b']' {
            pos += 1;
            pos = skip_whitespace(bytes, pos);
            if pos < len {
                return Err(map_err(Jsonv2ScanError::Decode {
                    reason: "trailing bytes after jsonv2 array closure",
                }));
            }
            return Ok(0);
        }

        let mut row_index = 0usize;
        let mut closed = false;

        while pos < len {
            if bytes[pos] != b'[' {
                return Err(map_err(Jsonv2ScanError::Decode {
                    reason: "expected '[' at start of jsonv2 row",
                }));
            }
            pos += 1;
            pos = skip_whitespace(bytes, pos);

            let mut col_index = 0usize;
            if pos < len && bytes[pos] == b']' {
                if expected_columns != 0 {
                    return Err(map_err(Jsonv2ScanError::RowWidthMismatch {
                        partition_index,
                        row_index,
                        expected: expected_columns,
                        actual: 0,
                    }));
                }
                pos += 1;
            } else {
                loop {
                    if pos >= len {
                        return Err(map_err(Jsonv2ScanError::Decode {
                            reason: "unexpected EOF in jsonv2 row",
                        }));
                    }

                    let cell = match bytes[pos] {
                        b'n' => {
                            if pos + 4 <= len && match_null(&bytes[pos..pos + 4]) {
                                pos += 4;
                                CellSlice::Null
                            } else {
                                return Err(map_err(Jsonv2ScanError::Decode {
                                    reason: "invalid null literal in cell",
                                }));
                            }
                        }
                        b'"' => {
                            pos += 1;
                            let start = pos;
                            let hit = find_quote_or_escape(&bytes[pos..]);
                            let Some(rel_hit) = hit else {
                                return Err(map_err(Jsonv2ScanError::Decode {
                                    reason: "unterminated string quote in cell",
                                }));
                            };

                            if bytes[pos + rel_hit] == b'"' {
                                let cell_bytes = &bytes[start..pos + rel_hit];
                                pos += rel_hit + 1;
                                let cell_str = core::str::from_utf8(cell_bytes).map_err(|_| {
                                    map_err(Jsonv2ScanError::Decode {
                                        reason: "invalid UTF-8 in cell string",
                                    })
                                })?;
                                CellSlice::Borrowed(cell_str)
                            } else {
                                self.scratch.clear();
                                self.scratch.extend_from_slice(&bytes[start..pos + rel_hit]);
                                pos += rel_hit;
                                pos = decode_escapes_into(bytes, pos, &mut self.scratch)
                                    .map_err(&mut map_err)?;
                                let cell_str =
                                    core::str::from_utf8(&self.scratch).map_err(|_| {
                                        map_err(Jsonv2ScanError::Decode {
                                            reason: "invalid UTF-8 after unescaping cell string",
                                        })
                                    })?;
                                CellSlice::Unescaped(cell_str)
                            }
                        }
                        _ => {
                            return Err(map_err(Jsonv2ScanError::Decode {
                                reason: "unexpected token in jsonv2 cell: expected '\"' or 'null'",
                            }));
                        }
                    };

                    if col_index < expected_columns {
                        visit_cell(row_index, col_index, cell)?;
                    }
                    col_index += 1;

                    pos = skip_whitespace(bytes, pos);
                    if pos >= len {
                        return Err(map_err(Jsonv2ScanError::Decode {
                            reason: "unexpected EOF after cell",
                        }));
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
                            return Err(map_err(Jsonv2ScanError::Decode {
                                reason: "expected ',' or ']' after cell",
                            }));
                        }
                    }
                }

                if col_index != expected_columns {
                    return Err(map_err(Jsonv2ScanError::RowWidthMismatch {
                        partition_index,
                        row_index,
                        expected: expected_columns,
                        actual: col_index,
                    }));
                }
            }

            row_index = row_index
                .checked_add(1)
                .ok_or_else(|| map_err(Jsonv2ScanError::RowCountOverflow))?;

            pos = skip_whitespace(bytes, pos);
            if pos >= len {
                return Err(map_err(Jsonv2ScanError::Decode {
                    reason: "unexpected EOF after row",
                }));
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
                    return Err(map_err(Jsonv2ScanError::Decode {
                        reason: "expected ',' or ']' after row",
                    }));
                }
            }
        }

        if !closed {
            return Err(map_err(Jsonv2ScanError::Decode {
                reason: "unexpected EOF: unclosed jsonv2 outer array",
            }));
        }

        pos = skip_whitespace(bytes, pos);
        if pos < len {
            return Err(map_err(Jsonv2ScanError::Decode {
                reason: "trailing bytes after jsonv2 array closure",
            }));
        }

        Ok(row_index)
    }

    /// Decode a raw `jsonv2` partition (`[[...]]` or `{"data": [[...]]}`) into
    /// `Vec<Vec<Option<String>>>` in a single SWAR-accelerated pass without
    /// requiring a fixed column count up front.
    pub fn decode_partition_rows(
        &mut self,
        bytes: &[u8],
    ) -> Result<Vec<Vec<Option<String>>>, Jsonv2ScanError> {
        let bytes = extract_jsonv2_data_array(bytes)?;
        let len = bytes.len();
        let mut pos = skip_whitespace(bytes, 0);
        if pos >= len || bytes[pos] != b'[' {
            return Err(Jsonv2ScanError::Decode {
                reason: "expected '[' at start of jsonv2 array",
            });
        }
        pos += 1;
        pos = skip_whitespace(bytes, pos);
        if pos >= len {
            return Err(Jsonv2ScanError::Decode {
                reason: "unexpected EOF: unclosed '[' at start of jsonv2 array",
            });
        }
        if bytes[pos] == b']' {
            pos += 1;
            pos = skip_whitespace(bytes, pos);
            if pos < len {
                return Err(Jsonv2ScanError::Decode {
                    reason: "trailing bytes after jsonv2 array closure",
                });
            }
            return Ok(Vec::new());
        }

        let mut rows = Vec::new();
        let mut expected_width: Option<usize> = None;
        let mut closed = false;

        while pos < len {
            if bytes[pos] != b'[' {
                return Err(Jsonv2ScanError::Decode {
                    reason: "expected '[' at start of jsonv2 row",
                });
            }
            pos += 1;
            pos = skip_whitespace(bytes, pos);

            let mut row = Vec::with_capacity(expected_width.unwrap_or(8));
            if pos < len && bytes[pos] == b']' {
                pos += 1;
            } else {
                loop {
                    if pos >= len {
                        return Err(Jsonv2ScanError::Decode {
                            reason: "unexpected EOF in jsonv2 row",
                        });
                    }
                    let cell = match bytes[pos] {
                        b'n' => {
                            if pos + 4 <= len && match_null(&bytes[pos..pos + 4]) {
                                pos += 4;
                                None
                            } else {
                                return Err(Jsonv2ScanError::Decode {
                                    reason: "invalid null literal in cell",
                                });
                            }
                        }
                        b'"' => {
                            pos += 1;
                            let start = pos;
                            let hit = find_quote_or_escape(&bytes[pos..]).ok_or(
                                Jsonv2ScanError::Decode {
                                    reason: "unterminated string quote in cell",
                                },
                            )?;
                            if bytes[pos + hit] == b'"' {
                                let cell_bytes = &bytes[start..pos + hit];
                                pos += hit + 1;
                                let s = core::str::from_utf8(cell_bytes).map_err(|_| {
                                    Jsonv2ScanError::Decode {
                                        reason: "invalid UTF-8 in cell string",
                                    }
                                })?;
                                Some(s.to_owned())
                            } else {
                                self.scratch.clear();
                                self.scratch.extend_from_slice(&bytes[start..pos + hit]);
                                pos += hit;
                                pos = decode_escapes_into(bytes, pos, &mut self.scratch)?;
                                let s = core::str::from_utf8(&self.scratch).map_err(|_| {
                                    Jsonv2ScanError::Decode {
                                        reason: "invalid UTF-8 after unescaping cell string",
                                    }
                                })?;
                                Some(s.to_owned())
                            }
                        }
                        _ => {
                            return Err(Jsonv2ScanError::Decode {
                                reason: "unexpected token in jsonv2 cell: expected '\"' or 'null'",
                            });
                        }
                    };
                    row.push(cell);

                    pos = skip_whitespace(bytes, pos);
                    if pos >= len {
                        return Err(Jsonv2ScanError::Decode {
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
                            return Err(Jsonv2ScanError::Decode {
                                reason: "expected ',' or ']' after cell",
                            });
                        }
                    }
                }
            }

            if expected_width.is_none() {
                expected_width = Some(row.len());
            }
            rows.push(row);

            pos = skip_whitespace(bytes, pos);
            if pos >= len {
                return Err(Jsonv2ScanError::Decode {
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
                    return Err(Jsonv2ScanError::Decode {
                        reason: "expected ',' or ']' after row",
                    });
                }
            }
        }

        if !closed {
            return Err(Jsonv2ScanError::Decode {
                reason: "unexpected EOF: unclosed jsonv2 outer array",
            });
        }
        pos = skip_whitespace(bytes, pos);
        if pos < len {
            return Err(Jsonv2ScanError::Decode {
                reason: "trailing bytes after jsonv2 array closure",
            });
        }
        Ok(rows)
    }
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

fn decode_escapes_into(
    bytes: &[u8],
    mut pos: usize,
    scratch: &mut Vec<u8>,
) -> Result<usize, Jsonv2ScanError> {
    let len = bytes.len();
    loop {
        if pos >= len {
            return Err(Jsonv2ScanError::Decode {
                reason: "unexpected EOF in escaped string",
            });
        }

        if bytes[pos] != b'\\' {
            return Err(Jsonv2ScanError::Decode {
                reason: "expected '\\' in escape decoder",
            });
        }
        pos += 1;

        if pos >= len {
            return Err(Jsonv2ScanError::Decode {
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
                    return Err(Jsonv2ScanError::Decode {
                        reason: "unterminated unicode escape",
                    });
                }
                let hex_slice = bytes.get(pos + 1..pos + 5).ok_or(Jsonv2ScanError::Decode {
                    reason: "unterminated unicode escape",
                })?;
                let hex_str =
                    core::str::from_utf8(hex_slice).map_err(|_| Jsonv2ScanError::Decode {
                        reason: "invalid UTF-8 in unicode escape",
                    })?;
                let code =
                    u16::from_str_radix(hex_str, 16).map_err(|_| Jsonv2ScanError::Decode {
                        reason: "invalid hex digits in unicode escape",
                    })?;
                pos += 4;

                if (0xd800..=0xdbff).contains(&code) {
                    if pos + 6 < len && bytes[pos + 1] == b'\\' && bytes[pos + 2] == b'u' {
                        let low_slice =
                            bytes.get(pos + 3..pos + 7).ok_or(Jsonv2ScanError::Decode {
                                reason: "unterminated low surrogate escape",
                            })?;
                        let low_str = core::str::from_utf8(low_slice).map_err(|_| {
                            Jsonv2ScanError::Decode {
                                reason: "invalid UTF-8 in low surrogate",
                            }
                        })?;
                        let low_code = u16::from_str_radix(low_str, 16).map_err(|_| {
                            Jsonv2ScanError::Decode {
                                reason: "invalid hex in low surrogate",
                            }
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
                                return Err(Jsonv2ScanError::Decode {
                                    reason: "invalid surrogate scalar codepoint",
                                });
                            }
                        } else {
                            return Err(Jsonv2ScanError::Decode {
                                reason: "expected low surrogate after high surrogate",
                            });
                        }
                    } else {
                        return Err(Jsonv2ScanError::Decode {
                            reason: "lone high surrogate without low surrogate",
                        });
                    }
                } else if let Some(ch) = char::from_u32(u32::from(code)) {
                    let mut buf = [0u8; 4];
                    let enc = ch.encode_utf8(&mut buf);
                    scratch.extend_from_slice(enc.as_bytes());
                } else {
                    return Err(Jsonv2ScanError::Decode {
                        reason: "invalid unicode codepoint",
                    });
                }
            }
            _ => {
                return Err(Jsonv2ScanError::Decode {
                    reason: "unknown escape sequence",
                });
            }
        }
        pos += 1;

        let rel_hit = find_quote_or_escape(&bytes[pos..]).ok_or(Jsonv2ScanError::Decode {
            reason: "unterminated string after escape",
        })?;

        scratch.extend_from_slice(&bytes[pos..pos + rel_hit]);
        pos += rel_hit;
        if bytes[pos] == b'"' {
            pos += 1;
            break;
        }
    }

    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_data_array_when_earlier_field_value_is_data() {
        let envelope =
            br#"{"message": "data", "data": [["1", null, "hello\nworld"]], "code": "090001"}"#;
        let arr = extract_jsonv2_data_array(envelope).expect("extract data array");
        assert_eq!(arr, br#"[["1", null, "hello\nworld"]]"#);

        let mut scanner = ZeroCopyJsonv2Scanner::new();
        let rows = scanner
            .decode_partition_rows(envelope)
            .expect("decode rows");
        assert_eq!(
            rows,
            vec![vec![
                Some("1".to_owned()),
                None,
                Some("hello\nworld".to_owned())
            ]]
        );
    }
}
