#![forbid(unsafe_code)]

//! `franken-snowflake-export::parquet` -- Clean-room, Tokio-free, pure safe Rust
//! Apache Parquet file format encoder and reader.
//!
//! # Specification Conformance
//! Writes Parquet files with `FileMetaData` version 1 and `DATA_PAGE` (V1) pages,
//! serialized with the Thrift Compact Protocol, carrying both `LogicalType` and
//! (where the legacy semantics match exactly) `ConvertedType` annotations.
//! Supports PLAIN value encoding, RLE/Bit-Packing hybrid definition levels for
//! nullable columns, optional statistics (null count, min/max values), and
//! compression modes (Uncompressed, Snappy, Gzip). No dictionary encoding.
//!
//! # Type mapping (exact or refused)
//! Columns are typed from the SQL API `rowType` (type + precision + scale):
//! `FIXED`/`NUMBER` with scale 0 and precision ≤ 18 → `INT64`; any other
//! `NUMBER(p,s)` → `DECIMAL(p,s)` on `INT32`/`INT64`/`FIXED_LEN_BYTE_ARRAY` by
//! precision; `REAL` → `DOUBLE`; `DATE` → `DATE`; `TIME` → `TIME` (local);
//! `TIMESTAMP_NTZ` → `TIMESTAMP` (not UTC-adjusted); `TIMESTAMP_LTZ` →
//! `TIMESTAMP` (UTC-adjusted); `TIMESTAMP_TZ` → the UTC instant plus a sibling
//! `<name>__tz_offset_minutes` `INT32` column; time units are micros for scale
//! ≤ 6 and nanos above; `BINARY` → raw bytes; `VARIANT`/`OBJECT`/`ARRAY` →
//! `JSON`; everything else (incl. `DECFLOAT`, `GEOGRAPHY`) → UTF-8 `STRING`.
//! A value that cannot be represented exactly (extra fractional digits, more
//! digits than the precision, out of range) is a typed error, never rounded.

use serde::{Deserialize, Serialize};

use crate::local::{
    ExportByteSink, ExportColumn, LocalExportArtifact, LocalExportInput, ResultPartition,
};
use crate::{
    ExportError, ExportFormat, ExportLogEvent, ExportReceipt, ExportReceiptKind, ExportResult,
};

/// 4-byte Parquet file magic marker.
pub const PARQUET_MAGIC: &[u8; 4] = b"PAR1";

/// Parquet compression codec selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParquetCompression {
    /// Uncompressed page data.
    Uncompressed,
    /// Google Snappy block compression (Parquet default).
    #[default]
    Snappy,
    /// Gzip / Deflate compression.
    Gzip,
}

impl ParquetCompression {
    /// Thrift CompressionCodec enum numeric value.
    #[must_use]
    pub const fn thrift_codec_id(self) -> i32 {
        match self {
            Self::Uncompressed => 0,
            Self::Snappy => 1,
            Self::Gzip => 2,
        }
    }

    /// Parse from Thrift CompressionCodec enum value.
    pub fn from_thrift_codec_id(id: i32) -> ExportResult<Self> {
        match id {
            0 => Ok(Self::Uncompressed),
            1 => Ok(Self::Snappy),
            2 => Ok(Self::Gzip),
            other => Err(ExportError::Sink {
                message: format!("unsupported Parquet compression codec id: {other}"),
            }),
        }
    }
}

/// Options for Parquet file generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParquetWriterOptions {
    /// Page compression codec. Default is Snappy.
    pub compression: ParquetCompression,
    /// Creator application string for FileMetaData.
    pub created_by: String,
}

impl Default for ParquetWriterOptions {
    fn default() -> Self {
        Self {
            compression: ParquetCompression::Snappy,
            created_by: format!("franken_snowflake version {}", env!("CARGO_PKG_VERSION")),
        }
    }
}

// ─── Thrift Compact Protocol Encoders & Decoders ─────────────────────────────

/// Thrift Compact Protocol type identifiers.
mod thrift_type {
    pub const STOP: u8 = 0x00;
    pub const BOOLEAN_TRUE: u8 = 0x01;
    pub const BOOLEAN_FALSE: u8 = 0x02;
    pub const BYTE: u8 = 0x03;
    pub const I16: u8 = 0x04;
    pub const I32: u8 = 0x05;
    pub const I64: u8 = 0x06;
    pub const DOUBLE: u8 = 0x07;
    pub const BINARY: u8 = 0x08;
    pub const LIST: u8 = 0x09;
    pub const SET: u8 = 0x0A;
    pub const MAP: u8 = 0x0B;
    pub const STRUCT: u8 = 0x0C;
}

/// Pure safe Rust Thrift Compact Protocol serializer.
#[derive(Debug, Default)]
pub struct ThriftCompactWriter {
    out: Vec<u8>,
    field_stack: Vec<i16>,
}

impl ThriftCompactWriter {
    /// Create a new Thrift compact writer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            out: Vec::new(),
            field_stack: vec![0],
        }
    }

    /// Enter a new nested struct scope.
    pub fn push_struct(&mut self) {
        self.field_stack.push(0);
    }

    /// Terminate current struct with STOP (0x00) and restore parent scope.
    pub fn pop_struct(&mut self) {
        self.out.push(thrift_type::STOP);
        if self.field_stack.len() > 1 {
            self.field_stack.pop();
        }
    }

    /// Write field header using short delta form when delta <= 15, else full zigzag.
    pub fn write_field_header(&mut self, field_id: i16, type_code: u8) {
        let last_id = self.field_stack.last().copied().unwrap_or(0);
        if field_id > last_id && (field_id - last_id) <= 15 {
            let delta = ((field_id - last_id) as u8) << 4;
            self.out.push(delta | (type_code & 0x0F));
        } else {
            self.out.push(type_code & 0x0F);
            write_zigzag_i16(field_id, &mut self.out);
        }
        if let Some(top) = self.field_stack.last_mut() {
            *top = field_id;
        }
    }

    /// Write a boolean field directly in the field header.
    pub fn write_bool_field(&mut self, field_id: i16, value: bool) {
        let type_code = if value {
            thrift_type::BOOLEAN_TRUE
        } else {
            thrift_type::BOOLEAN_FALSE
        };
        self.write_field_header(field_id, type_code);
    }

    /// Write an i32 field.
    pub fn write_i32_field(&mut self, field_id: i16, value: i32) {
        self.write_field_header(field_id, thrift_type::I32);
        write_zigzag_i32(value, &mut self.out);
    }

    /// Write an i64 field.
    pub fn write_i64_field(&mut self, field_id: i16, value: i64) {
        self.write_field_header(field_id, thrift_type::I64);
        write_zigzag_i64(value, &mut self.out);
    }

    /// Write a double (f64) field.
    pub fn write_double_field(&mut self, field_id: i16, value: f64) {
        self.write_field_header(field_id, thrift_type::DOUBLE);
        self.out.extend_from_slice(&value.to_bits().to_le_bytes());
    }

    /// Write a string field as UTF-8 binary.
    pub fn write_string_field(&mut self, field_id: i16, value: &str) {
        self.write_binary_field(field_id, value.as_bytes());
    }

    /// Write a binary field (length prefix varint followed by bytes).
    pub fn write_binary_field(&mut self, field_id: i16, bytes: &[u8]) {
        self.write_field_header(field_id, thrift_type::BINARY);
        write_varint(bytes.len() as u64, &mut self.out);
        self.out.extend_from_slice(bytes);
    }

    /// Begin a nested struct field.
    pub fn write_struct_field_begin(&mut self, field_id: i16) {
        self.write_field_header(field_id, thrift_type::STRUCT);
        self.push_struct();
    }

    /// Begin a list field.
    pub fn write_list_field_begin(&mut self, field_id: i16, elem_type: u8, size: usize) {
        self.write_field_header(field_id, thrift_type::LIST);
        if size < 15 {
            self.out.push(((size as u8) << 4) | (elem_type & 0x0F));
        } else {
            self.out.push(0xF0 | (elem_type & 0x0F));
            write_varint(size as u64, &mut self.out);
        }
    }

    /// Consume the serializer and return the serialized bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }
}

/// Pure safe Rust Thrift Compact Protocol deserializer.
#[derive(Debug)]
pub struct ThriftCompactReader<'a> {
    buf: &'a [u8],
    pos: usize,
    field_stack: Vec<i16>,
}

impl<'a> ThriftCompactReader<'a> {
    /// Create a reader over a byte slice.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            field_stack: vec![0],
        }
    }

    /// Remaining bytes in stream.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Current read position.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Read one byte.
    pub fn read_byte(&mut self) -> ExportResult<u8> {
        if self.pos >= self.buf.len() {
            return Err(ExportError::Sink {
                message: "unexpected end of Thrift compact stream".to_owned(),
            });
        }
        let b = self.buf[self.pos];
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    /// Push nested struct context.
    pub fn push_struct(&mut self) {
        self.field_stack.push(0);
    }

    /// Pop struct context.
    pub fn pop_struct(&mut self) {
        if self.field_stack.len() > 1 {
            self.field_stack.pop();
        }
    }

    /// Read ULEB128 varint.
    pub fn read_varint(&mut self) -> ExportResult<u64> {
        let mut result = 0_u64;
        let mut shift = 0_u32;
        loop {
            let b = self.read_byte()?;
            let val = (b & 0x7F) as u64;
            if shift >= 64 {
                return Err(ExportError::Sink {
                    message: "Thrift varint overflow".to_owned(),
                });
            }
            result |= val << shift;
            if (b & 0x80) == 0 {
                break;
            }
            shift = shift.saturating_add(7);
        }
        Ok(result)
    }

    /// Read zigzag-encoded i16.
    pub fn read_zigzag_i16(&mut self) -> ExportResult<i16> {
        let v = self.read_varint()?;
        Ok(from_zigzag_i16(v))
    }

    /// Read zigzag-encoded i32.
    pub fn read_zigzag_i32(&mut self) -> ExportResult<i32> {
        let v = self.read_varint()?;
        Ok(from_zigzag_i32(v))
    }

    /// Read zigzag-encoded i64.
    pub fn read_zigzag_i64(&mut self) -> ExportResult<i64> {
        let v = self.read_varint()?;
        Ok(from_zigzag_i64(v))
    }

    /// Read IEEE 754 double (f64).
    pub fn read_double(&mut self) -> ExportResult<f64> {
        if self.pos.saturating_add(8) > self.buf.len() {
            return Err(ExportError::Sink {
                message: "unexpected end of Thrift double".to_owned(),
            });
        }
        let bytes: [u8; 8] = match self.buf[self.pos..self.pos + 8].try_into() {
            Ok(b) => b,
            Err(_) => {
                return Err(ExportError::Sink {
                    message: "slice conversion error".to_owned(),
                });
            }
        };
        self.pos = self.pos.saturating_add(8);
        Ok(f64::from_bits(u64::from_le_bytes(bytes)))
    }

    /// Read raw binary slice.
    pub fn read_binary(&mut self) -> ExportResult<&'a [u8]> {
        let len = self.read_varint()? as usize;
        if self.pos.saturating_add(len) > self.buf.len() {
            return Err(ExportError::Sink {
                message: "binary field length exceeds remaining buffer".to_owned(),
            });
        }
        let slice = &self.buf[self.pos..self.pos + len];
        self.pos = self.pos.saturating_add(len);
        Ok(slice)
    }

    /// Read UTF-8 string.
    pub fn read_string(&mut self) -> ExportResult<String> {
        let bytes = self.read_binary()?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|e| ExportError::Sink {
                message: format!("invalid UTF-8 in Thrift string: {e}"),
            })
    }

    /// Read next field header. Returns `(None, STOP)` when struct terminates.
    pub fn read_field_header(&mut self) -> ExportResult<(Option<i16>, u8)> {
        let b = self.read_byte()?;
        if b == thrift_type::STOP {
            self.pop_struct();
            return Ok((None, thrift_type::STOP));
        }
        let type_code = b & 0x0F;
        let delta = b >> 4;
        let field_id = if delta == 0 {
            self.read_zigzag_i16()?
        } else {
            let last = self.field_stack.last().copied().unwrap_or(0);
            last.saturating_add(delta as i16)
        };
        if let Some(top) = self.field_stack.last_mut() {
            *top = field_id;
        }
        Ok((Some(field_id), type_code))
    }

    /// Read list header: returns (element_type, size).
    pub fn read_list_header(&mut self) -> ExportResult<(u8, usize)> {
        let b = self.read_byte()?;
        let elem_type = b & 0x0F;
        let size_hint = b >> 4;
        let size = if size_hint == 0x0F {
            self.read_varint()? as usize
        } else {
            size_hint as usize
        };
        Ok((elem_type, size))
    }

    /// Skip a field of the specified type code.
    pub fn skip_field(&mut self, type_code: u8) -> ExportResult<()> {
        match type_code {
            thrift_type::BOOLEAN_TRUE | thrift_type::BOOLEAN_FALSE | thrift_type::STOP => Ok(()),
            thrift_type::BYTE => {
                let _ = self.read_byte()?;
                Ok(())
            }
            thrift_type::I16 | thrift_type::I32 | thrift_type::I64 => {
                let _ = self.read_varint()?;
                Ok(())
            }
            thrift_type::DOUBLE => {
                let _ = self.read_double()?;
                Ok(())
            }
            thrift_type::BINARY => {
                let _ = self.read_binary()?;
                Ok(())
            }
            thrift_type::STRUCT => {
                self.push_struct();
                loop {
                    let (field_opt, child_type) = self.read_field_header()?;
                    if field_opt.is_none() {
                        break;
                    }
                    self.skip_field(child_type)?;
                }
                Ok(())
            }
            thrift_type::LIST | thrift_type::SET => {
                let (elem_type, len) = self.read_list_header()?;
                for _ in 0..len {
                    self.skip_field(elem_type)?;
                }
                Ok(())
            }
            thrift_type::MAP => {
                let len = self.read_varint()? as usize;
                if len > 0 {
                    let types = self.read_byte()?;
                    let ktype = types >> 4;
                    let vtype = types & 0x0F;
                    for _ in 0..len {
                        self.skip_field(ktype)?;
                        self.skip_field(vtype)?;
                    }
                }
                Ok(())
            }
            other => Err(ExportError::Sink {
                message: format!("cannot skip unknown Thrift type: 0x{other:02X}"),
            }),
        }
    }
}

fn write_varint(mut val: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

fn write_zigzag_i16(n: i16, out: &mut Vec<u8>) {
    let z = ((n as i64) << 1) ^ ((n as i64) >> 63);
    write_varint(z as u64, out);
}

fn write_zigzag_i32(n: i32, out: &mut Vec<u8>) {
    let z = ((n as i64) << 1) ^ ((n as i64) >> 63);
    write_varint(z as u64, out);
}

fn write_zigzag_i64(n: i64, out: &mut Vec<u8>) {
    let z = (n << 1) ^ (n >> 63);
    write_varint(z as u64, out);
}

const fn from_zigzag_i16(z: u64) -> i16 {
    ((z >> 1) as i16) ^ (-((z & 1) as i16))
}

const fn from_zigzag_i32(z: u64) -> i32 {
    ((z >> 1) as i32) ^ (-((z & 1) as i32))
}

const fn from_zigzag_i64(z: u64) -> i64 {
    ((z >> 1) as i64) ^ (-((z & 1) as i64))
}

// ─── Pure Safe Rust Snappy Block Compression ─────────────────────────────────

/// Compress a buffer using the Apache Snappy raw block format.
#[must_use]
pub fn snappy_compress(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len().saturating_add(32));
    write_varint(input.len() as u64, &mut out);

    if input.is_empty() {
        return out;
    }

    if input.len() < 16 {
        emit_snappy_literal(input, &mut out);
        return out;
    }

    // Fast 4096-entry hash table for finding 4-byte matches.
    let mut table = [0_u16; 4096];
    let mut lit_start = 0_usize;
    let mut pos = 0_usize;

    while pos.saturating_add(4) <= input.len() {
        let b0 = input[pos] as u32;
        let b1 = input[pos.saturating_add(1)] as u32;
        let b2 = input[pos.saturating_add(2)] as u32;
        let b3 = input[pos.saturating_add(3)] as u32;
        let u4 = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
        let h = ((u4.wrapping_mul(0x1e35_a7bd)) >> 20) as usize & 0x0FFF;

        let candidate = table[h] as usize;
        table[h] = (pos & 0xFFFF) as u16;

        let offset = pos.saturating_sub(candidate);
        if candidate < pos
            && offset <= 65535
            && candidate.saturating_add(4) <= input.len()
            && input[candidate] == input[pos]
            && input[candidate.saturating_add(1)] == input[pos.saturating_add(1)]
            && input[candidate.saturating_add(2)] == input[pos.saturating_add(2)]
            && input[candidate.saturating_add(3)] == input[pos.saturating_add(3)]
        {
            if lit_start < pos {
                emit_snappy_literal(&input[lit_start..pos], &mut out);
            }

            let mut match_len = 4_usize;
            while pos.saturating_add(match_len) < input.len()
                && input[pos.saturating_add(match_len)]
                    == input[candidate.saturating_add(match_len)]
                && match_len < 64
            {
                match_len = match_len.saturating_add(1);
            }

            emit_snappy_copy(offset, match_len, &mut out);
            pos = pos.saturating_add(match_len);
            lit_start = pos;
        } else {
            pos = pos.saturating_add(1);
        }
    }

    if lit_start < input.len() {
        emit_snappy_literal(&input[lit_start..], &mut out);
    }

    out
}

fn emit_snappy_literal(lit: &[u8], out: &mut Vec<u8>) {
    let len = lit.len();
    if len == 0 {
        return;
    }
    if len <= 60 {
        out.push((len.saturating_sub(1) as u8) << 2);
    } else if len <= 256 {
        out.push(0xF0);
        out.push(len.saturating_sub(1) as u8);
    } else {
        out.push(0xF4);
        let val = len.saturating_sub(1) as u16;
        out.extend_from_slice(&val.to_le_bytes());
    }
    out.extend_from_slice(lit);
}

fn emit_snappy_copy(offset: usize, len: usize, out: &mut Vec<u8>) {
    if (4..=11).contains(&len) && offset < 2048 {
        let tag = 0x01
            | (((len.saturating_sub(4) as u8) & 0x07) << 2)
            | (((offset >> 8) as u8 & 0x07) << 5);
        out.push(tag);
        out.push((offset & 0xFF) as u8);
    } else {
        let clamped_len = len.min(64);
        out.push(0x02 | ((clamped_len.saturating_sub(1) as u8) << 2));
        let off16 = offset as u16;
        out.extend_from_slice(&off16.to_le_bytes());
    }
}

/// Decompress raw Snappy block bytes.
pub fn snappy_decompress(compressed: &[u8]) -> ExportResult<Vec<u8>> {
    let mut reader = ThriftCompactReader::new(compressed);
    let uncompressed_len = reader.read_varint()? as usize;
    let mut out = Vec::with_capacity(uncompressed_len);

    while reader.remaining() > 0 && out.len() < uncompressed_len {
        let tag_byte = reader.read_byte()?;
        let tag_type = tag_byte & 0x03;

        match tag_type {
            0 => {
                let raw_len = (tag_byte >> 2) as usize;
                let lit_len = if raw_len < 60 {
                    raw_len.saturating_add(1)
                } else if raw_len == 60 {
                    (reader.read_byte()? as usize).saturating_add(1)
                } else if raw_len == 61 {
                    let b0 = reader.read_byte()? as usize;
                    let b1 = reader.read_byte()? as usize;
                    (b0 | (b1 << 8)).saturating_add(1)
                } else {
                    return Err(ExportError::Sink {
                        message: "large literal lengths not supported".to_owned(),
                    });
                };
                for _ in 0..lit_len {
                    out.push(reader.read_byte()?);
                }
            }
            1 => {
                let len = (((tag_byte >> 2) & 0x07) as usize).saturating_add(4);
                let high = ((tag_byte >> 5) as usize) << 8;
                let low = reader.read_byte()? as usize;
                let offset = high | low;
                if offset == 0 || offset > out.len() {
                    return Err(ExportError::Sink {
                        message: "invalid Snappy copy-1 offset".to_owned(),
                    });
                }
                for _ in 0..len {
                    let src = out.len().saturating_sub(offset);
                    let byte = out[src];
                    out.push(byte);
                }
            }
            2 => {
                let len = ((tag_byte >> 2) as usize).saturating_add(1);
                let b0 = reader.read_byte()? as usize;
                let b1 = reader.read_byte()? as usize;
                let offset = b0 | (b1 << 8);
                if offset == 0 || offset > out.len() {
                    return Err(ExportError::Sink {
                        message: "invalid Snappy copy-2 offset".to_owned(),
                    });
                }
                for _ in 0..len {
                    let src = out.len().saturating_sub(offset);
                    let byte = out[src];
                    out.push(byte);
                }
            }
            _ => {
                return Err(ExportError::Sink {
                    message: "unsupported Snappy tag mode".to_owned(),
                });
            }
        }
    }

    Ok(out)
}

// ─── Gzip Compression & Decompression ────────────────────────────────────────

/// Gzip-compress payload bytes using asupersync's embedded compressor.
pub fn gzip_compress(input: &[u8]) -> ExportResult<Vec<u8>> {
    use asupersync::http::compress::{Compressor, GzipCompressor};
    let mut compressor = GzipCompressor::new();
    let mut out = Vec::new();
    compressor
        .compress(input, &mut out)
        .map_err(|e| ExportError::Sink {
            message: format!("gzip compression error: {e}"),
        })?;
    compressor.finish(&mut out).map_err(|e| ExportError::Sink {
        message: format!("gzip finish error: {e}"),
    })?;
    Ok(out)
}

/// Gzip-decompress payload bytes using asupersync's embedded decompressor.
pub fn gzip_decompress(compressed: &[u8]) -> ExportResult<Vec<u8>> {
    use asupersync::http::compress::{Decompressor, GzipDecompressor};
    let mut decompressor = GzipDecompressor::new(Some(64 * 1024 * 1024));
    let mut out = Vec::new();
    decompressor
        .decompress(compressed, &mut out)
        .map_err(|e| ExportError::Sink {
            message: format!("gzip decompression error: {e}"),
        })?;
    decompressor
        .finish(&mut out)
        .map_err(|e| ExportError::Sink {
            message: format!("gzip finish error: {e}"),
        })?;
    Ok(out)
}

// ─── Parquet Type System & Layout ────────────────────────────────────────────

/// Physical Parquet storage types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParquetType {
    Boolean = 0,
    Int32 = 1,
    Int64 = 2,
    Double = 5,
    ByteArray = 6,
    FixedLenByteArray = 7,
}

impl ParquetType {
    const fn from_thrift(id: i32) -> Option<Self> {
        match id {
            0 => Some(Self::Boolean),
            1 => Some(Self::Int32),
            2 => Some(Self::Int64),
            5 => Some(Self::Double),
            6 => Some(Self::ByteArray),
            7 => Some(Self::FixedLenByteArray),
            _ => None,
        }
    }
}

/// Legacy converted types written for older readers (the logical type below is
/// authoritative). Only annotations whose legacy semantics match exactly are
/// written: `TIMESTAMP_MICROS` implies UTC-adjusted, so local (`_NTZ`) and
/// nanosecond timestamps carry the logical type alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParquetConvertedType {
    Utf8 = 0,
    Decimal = 5,
    Date = 6,
    TimestampMicros = 10,
    Json = 19,
}

impl ParquetConvertedType {
    const fn from_thrift(id: i32) -> Option<Self> {
        match id {
            0 => Some(Self::Utf8),
            5 => Some(Self::Decimal),
            6 => Some(Self::Date),
            10 => Some(Self::TimestampMicros),
            19 => Some(Self::Json),
            _ => None,
        }
    }
}

/// Unit of a `TIME` / `TIMESTAMP` logical type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeUnit {
    Micros,
    Nanos,
}

impl TimeUnit {
    /// Fractional-second digits the unit represents exactly.
    #[must_use]
    pub const fn digits(self) -> u32 {
        match self {
            Self::Micros => 6,
            Self::Nanos => 9,
        }
    }

    /// Choose the unit that represents a column's declared fractional-second
    /// scale exactly: micros up to scale 6 (wide range), nanos above.
    #[must_use]
    pub const fn for_scale(scale: Option<u32>) -> Self {
        match scale {
            Some(scale) if scale > 6 => Self::Nanos,
            _ => Self::Micros,
        }
    }

    /// Field id of the unit inside the Thrift `TimeUnit` union.
    const fn thrift_field(self) -> i16 {
        match self {
            Self::Micros => 2,
            Self::Nanos => 3,
        }
    }
}

/// Parquet logical type annotation (the Thrift `LogicalType` union).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParquetLogicalType {
    String,
    Decimal {
        precision: u32,
        scale: u32,
    },
    Date,
    Time {
        unit: TimeUnit,
    },
    Timestamp {
        adjusted_to_utc: bool,
        unit: TimeUnit,
    },
    Json,
}

/// How one Snowflake `jsonv2` cell string becomes a Parquet value. Every codec
/// is exact: a value that cannot be represented without loss is a typed error,
/// never a rounded or truncated value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CellCodec {
    /// UTF-8 text stored verbatim (TEXT, VARIANT JSON, DECFLOAT, GEOGRAPHY, ...).
    Text,
    /// BINARY: the hex wire string decoded to raw bytes.
    HexBytes,
    Boolean,
    /// An exact integer that must fit `i64`.
    Integer,
    Float,
    /// An exact decimal stored as its unscaled integer.
    Decimal {
        precision: u32,
        scale: u32,
    },
    /// Days since the epoch (or an ISO `YYYY-MM-DD` date).
    Date,
    /// `TIME`: seconds since midnight, stored in `unit`.
    TimeOfDay {
        unit: TimeUnit,
    },
    /// `TIMESTAMP_NTZ` / `_LTZ`: epoch seconds, stored in `unit`.
    Epoch {
        unit: TimeUnit,
    },
    /// `TIMESTAMP_TZ` `"<epoch seconds> <offset minutes + 1440>"`: the UTC instant.
    TzInstant {
        unit: TimeUnit,
    },
    /// `TIMESTAMP_TZ`: the offset in minutes (`raw - 1440`).
    TzOffsetMinutes,
}

/// Parquet field repetition type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldRepetitionType {
    Required = 0,
    Optional = 1,
}

/// Column physical and logical type classification for a Snowflake column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParquetColumnDescriptor {
    pub physical: ParquetType,
    pub converted: Option<ParquetConvertedType>,
    pub logical: Option<ParquetLogicalType>,
    /// Byte width of a `FIXED_LEN_BYTE_ARRAY` column.
    pub type_length: Option<i32>,
    pub nullable: bool,
    pub codec: CellCodec,
}

/// One physical Parquet column and the result column its cells come from. A
/// `TIMESTAMP_TZ` result column becomes two physical columns: the UTC instant
/// under its own name and `<name>__tz_offset_minutes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParquetColumnPlan {
    pub name: String,
    pub source: usize,
    pub desc: ParquetColumnDescriptor,
}

/// Suffix of the sibling column that carries a `TIMESTAMP_TZ` column's offset.
pub const TZ_OFFSET_SUFFIX: &str = "__tz_offset_minutes";

/// Smallest byte width whose signed range holds every decimal of `precision`
/// digits (the Parquet `FIXED_LEN_BYTE_ARRAY` rule; 16 bytes for 38 digits).
#[must_use]
pub fn decimal_byte_width(precision: u32) -> i32 {
    let max_unscaled = 10_i128.saturating_pow(precision.min(38)) - 1;
    (1_i32..=16)
        .find(|width| (1_i128 << (8 * width - 1)) > max_unscaled)
        .unwrap_or(16)
}

impl ParquetColumnDescriptor {
    /// Resolve the Parquet column for a Snowflake result column from its type
    /// name plus the result metadata's precision and scale. `NUMBER(p,s)` type
    /// strings (used by callers that only have a type label) are honored when the
    /// metadata fields are absent.
    #[must_use]
    pub fn resolve(column: &ExportColumn) -> Self {
        let type_name = column.snowflake_type.as_str();
        let base = type_name
            .split('(')
            .next()
            .unwrap_or(type_name)
            .trim()
            .to_ascii_uppercase();
        let (declared_precision, declared_scale) = parse_declared_precision_scale(type_name);
        let precision = column.precision.or(declared_precision);
        let scale = column.scale.or(declared_scale);
        let nullable = column.nullable;
        let plain = |physical, codec| Self {
            physical,
            converted: None,
            logical: None,
            type_length: None,
            nullable,
            codec,
        };

        match base.as_str() {
            "BOOLEAN" | "BOOL" => plain(ParquetType::Boolean, CellCodec::Boolean),
            "DATE" => Self {
                converted: Some(ParquetConvertedType::Date),
                logical: Some(ParquetLogicalType::Date),
                ..plain(ParquetType::Int32, CellCodec::Date)
            },
            "TIME" => {
                let unit = TimeUnit::for_scale(scale);
                Self {
                    logical: Some(ParquetLogicalType::Time { unit }),
                    ..plain(ParquetType::Int64, CellCodec::TimeOfDay { unit })
                }
            }
            "TIMESTAMP" | "TIMESTAMP_NTZ" | "DATETIME" => {
                let unit = TimeUnit::for_scale(scale);
                Self {
                    logical: Some(ParquetLogicalType::Timestamp {
                        adjusted_to_utc: false,
                        unit,
                    }),
                    ..plain(ParquetType::Int64, CellCodec::Epoch { unit })
                }
            }
            "TIMESTAMP_LTZ" | "TIMESTAMP_TZ" => {
                let unit = TimeUnit::for_scale(scale);
                let codec = if base == "TIMESTAMP_TZ" {
                    CellCodec::TzInstant { unit }
                } else {
                    CellCodec::Epoch { unit }
                };
                Self {
                    converted: (unit == TimeUnit::Micros)
                        .then_some(ParquetConvertedType::TimestampMicros),
                    logical: Some(ParquetLogicalType::Timestamp {
                        adjusted_to_utc: true,
                        unit,
                    }),
                    ..plain(ParquetType::Int64, codec)
                }
            }
            "FLOAT" | "FLOAT4" | "FLOAT8" | "DOUBLE" | "DOUBLE PRECISION" | "REAL" => {
                plain(ParquetType::Double, CellCodec::Float)
            }
            "INT" | "INTEGER" | "BIGINT" | "SMALLINT" | "TINYINT" | "BYTEINT" => {
                plain(ParquetType::Int64, CellCodec::Integer)
            }
            "NUMBER" | "FIXED" | "DECIMAL" | "NUMERIC" => {
                let scale = scale.unwrap_or(0).min(37);
                let precision = precision.unwrap_or(38).clamp(1, 38).max(scale);
                if scale == 0 && precision <= 18 {
                    return plain(ParquetType::Int64, CellCodec::Integer);
                }
                let (physical, type_length) = match precision {
                    0..=9 => (ParquetType::Int32, None),
                    10..=18 => (ParquetType::Int64, None),
                    _ => (
                        ParquetType::FixedLenByteArray,
                        Some(decimal_byte_width(precision)),
                    ),
                };
                Self {
                    converted: Some(ParquetConvertedType::Decimal),
                    logical: Some(ParquetLogicalType::Decimal { precision, scale }),
                    type_length,
                    ..plain(physical, CellCodec::Decimal { precision, scale })
                }
            }
            "BINARY" | "VARBINARY" => plain(ParquetType::ByteArray, CellCodec::HexBytes),
            "VARIANT" | "OBJECT" | "ARRAY" => Self {
                converted: Some(ParquetConvertedType::Json),
                logical: Some(ParquetLogicalType::Json),
                ..plain(ParquetType::ByteArray, CellCodec::Text)
            },
            // TEXT/VARCHAR/STRING/CHAR, DECFLOAT (up to 38 significant digits with
            // an exponent: kept exact as text), GEOGRAPHY/GEOMETRY and anything
            // unknown are written as UTF-8 text.
            _ => Self {
                converted: Some(ParquetConvertedType::Utf8),
                logical: Some(ParquetLogicalType::String),
                ..plain(ParquetType::ByteArray, CellCodec::Text)
            },
        }
    }
}

/// Plan the physical Parquet columns for a result schema (expands each
/// `TIMESTAMP_TZ` column into its instant and offset columns).
#[must_use]
pub fn plan_parquet_columns(columns: &[ExportColumn]) -> Vec<ParquetColumnPlan> {
    let mut plans = Vec::with_capacity(columns.len());
    for (source, column) in columns.iter().enumerate() {
        let desc = ParquetColumnDescriptor::resolve(column);
        let is_tz = matches!(desc.codec, CellCodec::TzInstant { .. });
        plans.push(ParquetColumnPlan {
            name: column.name.clone(),
            source,
            desc,
        });
        if is_tz {
            plans.push(ParquetColumnPlan {
                name: format!("{}{TZ_OFFSET_SUFFIX}", column.name),
                source,
                desc: ParquetColumnDescriptor {
                    physical: ParquetType::Int32,
                    converted: None,
                    logical: None,
                    type_length: None,
                    nullable: column.nullable,
                    codec: CellCodec::TzOffsetMinutes,
                },
            });
        }
    }
    plans
}

/// `(p, s)` from a `NUMBER(p,s)` / `TIMESTAMP_NTZ(s)`-style type label.
fn parse_declared_precision_scale(type_name: &str) -> (Option<u32>, Option<u32>) {
    let Some(args) = type_name
        .split_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(args, _)| args)
    else {
        return (None, None);
    };
    let mut parts = args.split(',').map(|part| part.trim().parse::<u32>().ok());
    let first = parts.next().flatten();
    let second = parts.next().flatten();
    let upper = type_name.trim_start().to_ascii_uppercase();
    let numeric = ["NUMBER", "DECIMAL", "NUMERIC", "FIXED"]
        .iter()
        .any(|prefix| upper.starts_with(prefix));
    if numeric {
        (first, second)
    } else {
        // TIMESTAMP_NTZ(3) / TIME(9): the single argument is the scale.
        (None, first)
    }
}

// ─── RLE / Bit-Packing Definition Levels ──────────────────────────────────────

/// Encode definition levels for nullable columns using Parquet RLE hybrid encoding.
///
/// Returns 4-byte little-endian length prefix followed by encoded RLE runs.
#[must_use]
pub fn encode_definition_levels(defs: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    if defs.is_empty() {
        let mut out = Vec::with_capacity(4);
        out.extend_from_slice(&0_u32.to_le_bytes());
        return out;
    }

    let mut i = 0;
    while i < defs.len() {
        let current = defs[i];
        let mut run_len = 1_usize;
        while i.saturating_add(run_len) < defs.len() && defs[i.saturating_add(run_len)] == current {
            run_len = run_len.saturating_add(1);
        }

        // RLE run header: (run_len << 1) | 0
        write_varint((run_len as u64) << 1, &mut payload);
        // Repeated value: round_up_to_next_byte(1 bit) = 1 byte
        payload.push(current);
        i = i.saturating_add(run_len);
    }

    let mut out = Vec::with_capacity(payload.len().saturating_add(4));
    let len_u32 = payload.len() as u32;
    out.extend_from_slice(&len_u32.to_le_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Decode definition levels from a DataPage v1 buffer.
pub fn decode_definition_levels(
    data: &[u8],
    total_values: usize,
) -> ExportResult<(Vec<u8>, usize)> {
    if total_values == 0 {
        return Ok((Vec::new(), 0));
    }
    if data.len() < 4 {
        return Err(ExportError::Sink {
            message: "definition levels buffer too short for length prefix".to_owned(),
        });
    }

    let def_len_bytes: [u8; 4] = match data[0..4].try_into() {
        Ok(b) => b,
        Err(_) => {
            return Err(ExportError::Sink {
                message: "slice conversion error".to_owned(),
            });
        }
    };
    let def_bytes_len = u32::from_le_bytes(def_len_bytes) as usize;
    let def_slice = &data[4..4_usize.saturating_add(def_bytes_len).min(data.len())];
    let bytes_consumed = 4_usize.saturating_add(def_bytes_len);

    let mut reader = ThriftCompactReader::new(def_slice);
    let mut defs = Vec::with_capacity(total_values);

    while defs.len() < total_values && reader.remaining() > 0 {
        let header = reader.read_varint()?;
        if (header & 1) == 0 {
            // RLE run
            let count = (header >> 1) as usize;
            let val = reader.read_byte()?;
            for _ in 0..count {
                if defs.len() < total_values {
                    defs.push(val);
                }
            }
        } else {
            // Bit-packed run: (num_groups << 1) | 1, each group has 8 values (1 byte)
            let num_groups = (header >> 1) as usize;
            for _ in 0..num_groups {
                let byte = reader.read_byte()?;
                for bit in 0..8 {
                    if defs.len() < total_values {
                        defs.push((byte >> bit) & 1);
                    }
                }
            }
        }
    }

    Ok((defs, bytes_consumed))
}

// ─── PLAIN Value Encoding & Decoding ─────────────────────────────────────────

/// Column statistics accumulated during encoding.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ColumnStats {
    pub null_count: u64,
    pub min_i64: Option<i64>,
    pub max_i64: Option<i64>,
    pub min_f64: Option<f64>,
    pub max_f64: Option<f64>,
    pub min_i32: Option<i32>,
    pub max_i32: Option<i32>,
    pub min_str: Option<String>,
    pub max_str: Option<String>,
}

impl ColumnStats {
    pub fn update_i64(&mut self, val: i64) {
        self.min_i64 = Some(self.min_i64.map_or(val, |m| m.min(val)));
        self.max_i64 = Some(self.max_i64.map_or(val, |m| m.max(val)));
    }

    pub fn update_f64(&mut self, val: f64) {
        self.min_f64 = Some(self.min_f64.map_or(val, |m| m.min(val)));
        self.max_f64 = Some(self.max_f64.map_or(val, |m| m.max(val)));
    }

    pub fn update_i32(&mut self, val: i32) {
        self.min_i32 = Some(self.min_i32.map_or(val, |m| m.min(val)));
        self.max_i32 = Some(self.max_i32.map_or(val, |m| m.max(val)));
    }

    pub fn update_str(&mut self, val: &str) {
        self.min_str = Some(match &self.min_str {
            Some(curr) if curr.as_str() <= val => curr.clone(),
            _ => val.to_owned(),
        });
        self.max_str = Some(match &self.max_str {
            Some(curr) if curr.as_str() >= val => curr.clone(),
            _ => val.to_owned(),
        });
    }
}

/// Encode scalar values into a DataPage payload according to Parquet PLAIN format.
pub fn encode_column_plain(
    desc: &ParquetColumnDescriptor,
    cells: &[Option<String>],
) -> ExportResult<(Vec<u8>, ColumnStats)> {
    let mut stats = ColumnStats::default();
    let mut defs = Vec::with_capacity(cells.len());
    let mut values = Vec::new();
    let mut bool_bits = Vec::new();

    for cell in cells {
        match cell {
            None => {
                defs.push(0_u8);
                stats.null_count = stats.null_count.saturating_add(1);
            }
            Some(s) => {
                defs.push(1_u8);
                match encode_cell(desc, s)? {
                    PlainValue::I64(val) => {
                        stats.update_i64(val);
                        values.extend_from_slice(&val.to_le_bytes());
                    }
                    PlainValue::I32(val) => {
                        stats.update_i32(val);
                        values.extend_from_slice(&val.to_le_bytes());
                    }
                    PlainValue::F64(val) => {
                        stats.update_f64(val);
                        values.extend_from_slice(&val.to_bits().to_le_bytes());
                    }
                    PlainValue::Bool(val) => bool_bits.push(val),
                    PlainValue::Bytes(bytes) => {
                        if desc.codec == CellCodec::Text {
                            stats.update_str(s);
                        }
                        let len_u32 = u32::try_from(bytes.len()).map_err(|_| {
                            cell_error(s, "a Parquet BYTE_ARRAY", "longer than 4 GiB")
                        })?;
                        values.extend_from_slice(&len_u32.to_le_bytes());
                        values.extend_from_slice(&bytes);
                    }
                    PlainValue::Fixed(bytes) => values.extend_from_slice(&bytes),
                }
            }
        }
    }

    if desc.physical == ParquetType::Boolean && !bool_bits.is_empty() {
        // PLAIN boolean encoding: 1 bit per value, packed LSB-first
        let num_bytes = (bool_bits.len().saturating_add(7)) / 8;
        let mut packed = vec![0_u8; num_bytes];
        for (idx, bit) in bool_bits.iter().enumerate() {
            if *bit {
                let byte_idx = idx / 8;
                let bit_idx = idx % 8;
                packed[byte_idx] |= 1 << bit_idx;
            }
        }
        values.extend_from_slice(&packed);
    }

    let mut page_data = Vec::new();
    if desc.nullable {
        let def_bytes = encode_definition_levels(&defs);
        page_data.extend_from_slice(&def_bytes);
    }
    page_data.extend_from_slice(&values);

    Ok((page_data, stats))
}

/// One encoded PLAIN value.
enum PlainValue {
    Bool(bool),
    I32(i32),
    I64(i64),
    F64(f64),
    /// A length-prefixed `BYTE_ARRAY` value.
    Bytes(Vec<u8>),
    /// A `FIXED_LEN_BYTE_ARRAY` value (exactly `type_length` bytes).
    Fixed(Vec<u8>),
}

fn cell_error(cell: &str, target: &str, detail: impl std::fmt::Display) -> ExportError {
    let shown: String = cell.chars().take(64).collect();
    ExportError::Sink {
        message: format!("cannot encode `{shown}` as {target} without loss: {detail}"),
    }
}

/// Encode one `jsonv2` cell for `desc`. Exact or a typed error: no rounding, no
/// truncation, no saturation.
fn encode_cell(desc: &ParquetColumnDescriptor, s: &str) -> ExportResult<PlainValue> {
    let trimmed = s.trim();
    match desc.codec {
        CellCodec::Text => Ok(PlainValue::Bytes(s.as_bytes().to_vec())),
        CellCodec::HexBytes => decode_hex(trimmed)
            .map(PlainValue::Bytes)
            .ok_or_else(|| cell_error(s, "BINARY", "not an even-length hex string")),
        CellCodec::Boolean => match trimmed.to_ascii_lowercase().as_str() {
            "true" | "t" | "1" => Ok(PlainValue::Bool(true)),
            "false" | "f" | "0" => Ok(PlainValue::Bool(false)),
            _ => Err(cell_error(s, "BOOLEAN", "not true/false")),
        },
        CellCodec::Integer => {
            let value = parse_scaled_decimal(trimmed, 0).map_err(|e| cell_error(s, "INT64", e))?;
            i64::try_from(value)
                .map(PlainValue::I64)
                .map_err(|_| cell_error(s, "INT64", "outside the 64-bit range"))
        }
        CellCodec::Float => trimmed
            .parse::<f64>()
            .map(PlainValue::F64)
            .map_err(|e| cell_error(s, "DOUBLE", e)),
        CellCodec::Decimal { precision, scale } => {
            let target = || format!("DECIMAL({precision},{scale})");
            let unscaled =
                parse_scaled_decimal(trimmed, scale).map_err(|e| cell_error(s, &target(), e))?;
            let limit = 10_i128.pow(precision.min(38));
            if unscaled.abs() >= limit {
                return Err(cell_error(
                    s,
                    &target(),
                    "more digits than the declared precision",
                ));
            }
            match desc.physical {
                ParquetType::Int32 => i32::try_from(unscaled)
                    .map(PlainValue::I32)
                    .map_err(|_| cell_error(s, &target(), "outside INT32")),
                ParquetType::Int64 => i64::try_from(unscaled)
                    .map(PlainValue::I64)
                    .map_err(|_| cell_error(s, &target(), "outside INT64")),
                _ => {
                    let width = desc.type_length.unwrap_or(16).clamp(1, 16) as usize;
                    let be = unscaled.to_be_bytes();
                    Ok(PlainValue::Fixed(be[16 - width..].to_vec()))
                }
            }
        }
        CellCodec::Date => {
            let days = trimmed
                .parse::<i32>()
                .ok()
                .or_else(|| parse_iso_date_to_days(trimmed))
                .ok_or_else(|| cell_error(s, "DATE", "not days-since-epoch or YYYY-MM-DD"))?;
            Ok(PlainValue::I32(days))
        }
        CellCodec::TimeOfDay { unit } | CellCodec::Epoch { unit } => {
            scaled_seconds_i64(trimmed, unit)
                .map(PlainValue::I64)
                .map_err(|e| cell_error(s, "TIME/TIMESTAMP", e))
        }
        CellCodec::TzInstant { unit } => {
            let instant = trimmed.split_whitespace().next().unwrap_or_default();
            scaled_seconds_i64(instant, unit)
                .map(PlainValue::I64)
                .map_err(|e| cell_error(s, "TIMESTAMP_TZ", e))
        }
        CellCodec::TzOffsetMinutes => {
            let raw = trimmed
                .split_whitespace()
                .nth(1)
                .and_then(|offset| offset.parse::<i32>().ok())
                .ok_or_else(|| cell_error(s, "TIMESTAMP_TZ offset", "missing `<offset+1440>`"))?;
            let minutes = raw - 1440;
            if !(-1440..=1440).contains(&minutes) {
                return Err(cell_error(s, "TIMESTAMP_TZ offset", "outside ±24h"));
            }
            Ok(PlainValue::I32(minutes))
        }
    }
}

fn scaled_seconds_i64(seconds: &str, unit: TimeUnit) -> Result<i64, String> {
    let value = parse_scaled_decimal(seconds, unit.digits())?;
    i64::try_from(value).map_err(|_| format!("outside the INT64 range for {unit:?}"))
}

/// Parse a plain decimal string (`-12.3400`) into its unscaled integer at
/// `scale` digits. Fractional digits beyond `scale` are accepted only when they
/// are zeros; anything else would need rounding and is refused.
fn parse_scaled_decimal(text: &str, scale: u32) -> Result<i128, String> {
    let (negative, body) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let (int_part, frac_part) = body.split_once('.').unwrap_or((body, ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return Err("empty number".to_owned());
    }
    if !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("not a plain decimal".to_owned());
    }
    let keep = (scale as usize).min(frac_part.len());
    if frac_part[keep..].bytes().any(|b| b != b'0') {
        return Err(format!(
            "more than {scale} fractional digits (refusing to round)"
        ));
    }
    let overflow = || "outside the 128-bit range".to_owned();
    let mut value: i128 = 0;
    for digit in int_part.bytes().chain(frac_part[..keep].bytes()) {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(i128::from(digit - b'0')))
            .ok_or_else(overflow)?;
    }
    for _ in keep..scale as usize {
        value = value.checked_mul(10).ok_or_else(overflow)?;
    }
    Ok(if negative { -value } else { value })
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16)?;
            let lo = (pair[1] as char).to_digit(16)?;
            u8::try_from(hi * 16 + lo).ok()
        })
        .collect()
}

/// Render an unscaled integer at `scale` as a plain decimal string.
fn format_scaled(unscaled: i128, scale: u32) -> String {
    let negative = unscaled < 0;
    let digits = unscaled.unsigned_abs().to_string();
    let scale = scale as usize;
    let body = if scale == 0 {
        digits
    } else if digits.len() > scale {
        format!(
            "{}.{}",
            &digits[..digits.len() - scale],
            &digits[digits.len() - scale..]
        )
    } else {
        format!("0.{}{digits}", "0".repeat(scale - digits.len()))
    };
    if negative { format!("-{body}") } else { body }
}

/// Howard Hinnant's algorithm for converting civil date to days since 1970-01-01.
fn parse_iso_date_to_days(s: &str) -> Option<i32> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let y = parts[0].parse::<i32>().ok()?;
    let m = parts[1].parse::<u32>().ok()?;
    let d = parts[2].parse::<u32>().ok()?;
    Some(days_from_civil(y, m, d))
}

fn days_from_civil(mut y: i32, mut m: u32, d: u32) -> i32 {
    if m <= 2 {
        y -= 1;
        m += 9;
    } else {
        m -= 3;
    }
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + (doe as i32) - 719468
}

fn civil_from_days(z: i32) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1024 + doe / 1461 - doe / 142400) / 365;
    let y = yoe as i32 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ─── Thrift PageHeader & FileMetaData Serializers ────────────────────────────

fn serialize_page_header(
    uncompressed_size: i32,
    compressed_size: i32,
    num_values: i32,
    stats: &ColumnStats,
    desc: &ParquetColumnDescriptor,
) -> Vec<u8> {
    let mut writer = ThriftCompactWriter::new();
    // 1: required PageType type (DATA_PAGE = 0)
    writer.write_i32_field(1, 0);
    // 2: required i32 uncompressed_page_size
    writer.write_i32_field(2, uncompressed_size);
    // 3: required i32 compressed_page_size
    writer.write_i32_field(3, compressed_size);

    // 5: optional DataPageHeader data_page_header
    writer.write_struct_field_begin(5);
    // DataPageHeader 1: required i32 num_values
    writer.write_i32_field(1, num_values);
    // DataPageHeader 2: required Encoding encoding (PLAIN = 0)
    writer.write_i32_field(2, 0);
    // DataPageHeader 3: required Encoding definition_level_encoding (RLE = 3)
    writer.write_i32_field(3, 3);
    // DataPageHeader 4: required Encoding repetition_level_encoding (RLE = 3)
    writer.write_i32_field(4, 3);

    // DataPageHeader 5: optional Statistics statistics
    writer.write_struct_field_begin(5);
    writer.write_i64_field(3, stats.null_count as i64);
    match desc.physical {
        ParquetType::Int64 => {
            if let (Some(min), Some(max)) = (stats.min_i64, stats.max_i64) {
                writer.write_binary_field(5, &max.to_le_bytes());
                writer.write_binary_field(6, &min.to_le_bytes());
            }
        }
        ParquetType::Int32 => {
            if let (Some(min), Some(max)) = (stats.min_i32, stats.max_i32) {
                writer.write_binary_field(5, &max.to_le_bytes());
                writer.write_binary_field(6, &min.to_le_bytes());
            }
        }
        ParquetType::Double => {
            if let (Some(min), Some(max)) = (stats.min_f64, stats.max_f64) {
                writer.write_binary_field(5, &max.to_bits().to_le_bytes());
                writer.write_binary_field(6, &min.to_bits().to_le_bytes());
            }
        }
        ParquetType::ByteArray => {
            if let (Some(min), Some(max)) = (&stats.min_str, &stats.max_str) {
                writer.write_binary_field(5, max.as_bytes());
                writer.write_binary_field(6, min.as_bytes());
            }
        }
        // Optional min/max are omitted for booleans and fixed-length decimals.
        ParquetType::Boolean | ParquetType::FixedLenByteArray => {}
    }
    writer.pop_struct(); // end statistics
    writer.pop_struct(); // end data_page_header
    writer.pop_struct(); // end PageHeader

    writer.into_bytes()
}

/// Metadata captured for one written column chunk.
#[derive(Clone, Debug)]
pub struct WrittenColumnChunk {
    pub name: String,
    pub desc: ParquetColumnDescriptor,
    pub codec: ParquetCompression,
    pub num_values: i64,
    pub total_uncompressed_size: i64,
    pub total_compressed_size: i64,
    pub data_page_offset: i64,
    pub stats: ColumnStats,
}

fn serialize_file_metadata(
    chunks: &[WrittenColumnChunk],
    total_rows: i64,
    options: &ParquetWriterOptions,
) -> Vec<u8> {
    let mut writer = ThriftCompactWriter::new();
    // 1: required i32 version = 1
    writer.write_i32_field(1, 1);

    // 2: required list<SchemaElement> schema
    writer.write_list_field_begin(2, thrift_type::STRUCT, chunks.len().saturating_add(1));

    // Root SchemaElement (name = "schema", num_children = chunks.len())
    writer.push_struct();
    writer.write_string_field(4, "schema");
    writer.write_i32_field(5, chunks.len() as i32);
    writer.pop_struct();

    // Leaf SchemaElements (field ids written in ascending order)
    for chunk in chunks {
        let desc = &chunk.desc;
        writer.push_struct();
        // 1: optional Type type
        writer.write_i32_field(1, desc.physical as i32);
        // 2: optional i32 type_length (FIXED_LEN_BYTE_ARRAY only)
        if let Some(type_length) = desc.type_length {
            writer.write_i32_field(2, type_length);
        }
        // 3: optional FieldRepetitionType repetition_type (REQUIRED = 0, OPTIONAL = 1)
        writer.write_i32_field(
            3,
            if desc.nullable {
                FieldRepetitionType::Optional as i32
            } else {
                FieldRepetitionType::Required as i32
            },
        );
        // 4: required string name
        writer.write_string_field(4, &chunk.name);

        // 6: optional ConvertedType converted_type
        if let Some(converted) = desc.converted {
            writer.write_i32_field(6, converted as i32);
        }
        // 7/8: optional i32 scale / precision (DECIMAL)
        if let Some(ParquetLogicalType::Decimal { precision, scale }) = desc.logical {
            writer.write_i32_field(7, scale as i32);
            writer.write_i32_field(8, precision as i32);
        }

        // 10: optional LogicalType logicalType
        if let Some(logical) = desc.logical {
            writer.write_struct_field_begin(10);
            write_logical_type(&mut writer, logical);
            writer.pop_struct(); // end logicalType
        }

        writer.pop_struct(); // end SchemaElement
    }

    // 3: required i64 num_rows
    writer.write_i64_field(3, total_rows);

    // 4: required list<RowGroup> row_groups (single row group)
    writer.write_list_field_begin(4, thrift_type::STRUCT, 1);
    writer.push_struct(); // RowGroup

    // RowGroup 1: required list<ColumnChunk> columns
    writer.write_list_field_begin(1, thrift_type::STRUCT, chunks.len());
    for chunk in chunks {
        writer.push_struct(); // ColumnChunk
        writer.write_i64_field(2, 0); // file_offset = 0

        // ColumnChunk 3: optional ColumnMetaData meta_data
        writer.write_struct_field_begin(3);
        // 1: required Type type
        writer.write_i32_field(1, chunk.desc.physical as i32);
        // 2: required list<Encoding> encodings [PLAIN, RLE]
        writer.write_list_field_begin(2, thrift_type::I32, 2);
        write_zigzag_i32(0, &mut writer.out); // PLAIN = 0
        write_zigzag_i32(3, &mut writer.out); // RLE = 3
        // 3: required list<string> path_in_schema [name]
        writer.write_list_field_begin(3, thrift_type::BINARY, 1);
        write_varint(chunk.name.len() as u64, &mut writer.out);
        writer.out.extend_from_slice(chunk.name.as_bytes());
        // 4: required CompressionCodec codec
        writer.write_i32_field(4, chunk.codec.thrift_codec_id());
        // 5: required i64 num_values
        writer.write_i64_field(5, chunk.num_values);
        // 6: required i64 total_uncompressed_size
        writer.write_i64_field(6, chunk.total_uncompressed_size);
        // 7: required i64 total_compressed_size
        writer.write_i64_field(7, chunk.total_compressed_size);
        // 9: required i64 data_page_offset
        writer.write_i64_field(9, chunk.data_page_offset);

        // 12: optional Statistics statistics
        writer.write_struct_field_begin(12);
        writer.write_i64_field(3, chunk.stats.null_count as i64);
        match chunk.desc.physical {
            ParquetType::Int64 => {
                if let (Some(min), Some(max)) = (chunk.stats.min_i64, chunk.stats.max_i64) {
                    writer.write_binary_field(5, &max.to_le_bytes());
                    writer.write_binary_field(6, &min.to_le_bytes());
                }
            }
            ParquetType::Int32 => {
                if let (Some(min), Some(max)) = (chunk.stats.min_i32, chunk.stats.max_i32) {
                    writer.write_binary_field(5, &max.to_le_bytes());
                    writer.write_binary_field(6, &min.to_le_bytes());
                }
            }
            ParquetType::Double => {
                if let (Some(min), Some(max)) = (chunk.stats.min_f64, chunk.stats.max_f64) {
                    writer.write_binary_field(5, &max.to_bits().to_le_bytes());
                    writer.write_binary_field(6, &min.to_bits().to_le_bytes());
                }
            }
            ParquetType::ByteArray => {
                if let (Some(min), Some(max)) = (&chunk.stats.min_str, &chunk.stats.max_str) {
                    writer.write_binary_field(5, max.as_bytes());
                    writer.write_binary_field(6, min.as_bytes());
                }
            }
            ParquetType::Boolean | ParquetType::FixedLenByteArray => {}
        }
        writer.pop_struct(); // end statistics

        writer.pop_struct(); // end ColumnMetaData
        writer.pop_struct(); // end ColumnChunk
    }

    // RowGroup 2: required i64 total_byte_size
    let total_uncompressed: i64 = chunks.iter().map(|c| c.total_uncompressed_size).sum();
    writer.write_i64_field(2, total_uncompressed);
    // RowGroup 3: required i64 num_rows
    writer.write_i64_field(3, total_rows);
    // RowGroup 6: optional i64 total_compressed_size
    let total_compressed: i64 = chunks.iter().map(|c| c.total_compressed_size).sum();
    writer.write_i64_field(6, total_compressed);

    writer.pop_struct(); // end RowGroup

    // 6: optional string created_by
    writer.write_string_field(6, &options.created_by);

    writer.pop_struct(); // end FileMetaData

    writer.into_bytes()
}

/// Write one member of the Thrift `LogicalType` union (the caller has opened the
/// union struct).
fn write_logical_type(writer: &mut ThriftCompactWriter, logical: ParquetLogicalType) {
    let write_unit = |writer: &mut ThriftCompactWriter, unit: TimeUnit| {
        writer.write_struct_field_begin(2); // unit: TimeUnit union
        writer.write_struct_field_begin(unit.thrift_field()); // MICROS=2 / NANOS=3
        writer.pop_struct();
        writer.pop_struct();
    };
    match logical {
        ParquetLogicalType::String => {
            writer.write_struct_field_begin(1); // STRING
            writer.pop_struct();
        }
        ParquetLogicalType::Decimal { precision, scale } => {
            writer.write_struct_field_begin(5); // DECIMAL
            writer.write_i32_field(1, scale as i32);
            writer.write_i32_field(2, precision as i32);
            writer.pop_struct();
        }
        ParquetLogicalType::Date => {
            writer.write_struct_field_begin(6); // DATE
            writer.pop_struct();
        }
        ParquetLogicalType::Time { unit } => {
            writer.write_struct_field_begin(7); // TIME
            writer.write_bool_field(1, false); // isAdjustedToUTC: Snowflake TIME is local
            write_unit(writer, unit);
            writer.pop_struct();
        }
        ParquetLogicalType::Timestamp {
            adjusted_to_utc,
            unit,
        } => {
            writer.write_struct_field_begin(8); // TIMESTAMP
            writer.write_bool_field(1, adjusted_to_utc);
            write_unit(writer, unit);
            writer.pop_struct();
        }
        ParquetLogicalType::Json => {
            writer.write_struct_field_begin(12); // JSON
            writer.pop_struct();
        }
    }
}

// ─── Public Streaming and In-Memory Exporters ────────────────────────────────

/// Stream Parquet file bytes to a caller-provided byte sink.
pub fn write_parquet_stream<'a, I, S>(
    columns: &[ExportColumn],
    partitions: I,
    sink: &mut S,
    options: &ParquetWriterOptions,
) -> ExportResult<u64>
where
    I: IntoIterator<Item = &'a ResultPartition>,
    S: ExportByteSink,
{
    if columns.is_empty() {
        return Err(ExportError::EmptySchema);
    }

    // Plan the physical columns (TIMESTAMP_TZ adds an offset column) and
    // validate name uniqueness over the physical schema.
    let plans = plan_parquet_columns(columns);
    let mut seen = std::collections::BTreeSet::new();
    for plan in &plans {
        if !seen.insert(plan.name.as_str()) {
            return Err(ExportError::DuplicateColumn {
                name: plan.name.clone(),
            });
        }
    }

    let mut column_cells: Vec<Vec<Option<String>>> = vec![Vec::new(); columns.len()];
    let mut total_rows = 0_u64;
    let mut previous_partition = None;

    for partition in partitions {
        if let Some(prev) = previous_partition.filter(|&prev| partition.index <= prev) {
            return Err(ExportError::PartitionOrder {
                previous: prev,
                next: partition.index,
            });
        }
        previous_partition = Some(partition.index);

        for (row_idx, row) in partition.rows.iter().enumerate() {
            if row.len() != columns.len() {
                return Err(ExportError::RowWidthMismatch {
                    partition_index: partition.index,
                    row_index: row_idx,
                    expected: columns.len(),
                    actual: row.len(),
                });
            }
            for (col_idx, cell) in row.iter().enumerate() {
                column_cells[col_idx].push(cell.clone());
            }
            total_rows = total_rows.saturating_add(1);
        }
    }

    // 1. Write PAR1 magic header
    sink.write_chunk(PARQUET_MAGIC)?;
    let mut current_offset = 4_i64;

    let mut written_chunks = Vec::with_capacity(plans.len());

    // 2. Encode and write ColumnChunks
    for plan in &plans {
        let desc = &plan.desc;
        let (page_uncompressed, stats) = encode_column_plain(desc, &column_cells[plan.source])?;

        let page_compressed = match options.compression {
            ParquetCompression::Uncompressed => page_uncompressed.clone(),
            ParquetCompression::Snappy => snappy_compress(&page_uncompressed),
            ParquetCompression::Gzip => gzip_compress(&page_uncompressed)?,
        };

        let page_header_bytes = serialize_page_header(
            page_uncompressed.len() as i32,
            page_compressed.len() as i32,
            total_rows as i32,
            &stats,
            desc,
        );

        let data_page_offset = current_offset;
        let chunk_compressed_size = (page_header_bytes.len() + page_compressed.len()) as i64;
        let chunk_uncompressed_size = (page_header_bytes.len() + page_uncompressed.len()) as i64;

        sink.write_chunk(&page_header_bytes)?;
        sink.write_chunk(&page_compressed)?;
        current_offset = current_offset.saturating_add(chunk_compressed_size);

        written_chunks.push(WrittenColumnChunk {
            name: plan.name.clone(),
            desc: *desc,
            codec: options.compression,
            num_values: total_rows as i64,
            total_uncompressed_size: chunk_uncompressed_size,
            total_compressed_size: chunk_compressed_size,
            data_page_offset,
            stats,
        });
    }

    // 3. Serialize and write FileMetaData footer
    let file_meta_bytes = serialize_file_metadata(&written_chunks, total_rows as i64, options);
    sink.write_chunk(&file_meta_bytes)?;

    // 4. Write 4-byte LE FileMetaData length
    let footer_len = file_meta_bytes.len() as u32;
    sink.write_chunk(&footer_len.to_le_bytes())?;

    // 5. Write PAR1 magic footer
    sink.write_chunk(PARQUET_MAGIC)?;

    Ok(total_rows)
}

/// Export result partitions to an in-memory Parquet artifact and content-addressed receipt.
pub fn export_parquet(
    input: &LocalExportInput,
    target_uri_redacted: impl Into<String>,
    created_at_ms: u64,
    options: Option<ParquetWriterOptions>,
) -> ExportResult<LocalExportArtifact> {
    let opts = options.unwrap_or_default();
    let mut sink = crate::local::AddressingSink::new(Vec::new());
    let row_count =
        write_parquet_stream(&input.columns, input.partitions.iter(), &mut sink, &opts)?;
    let (bytes, address) = sink.finish();
    address.verify(&bytes)?;

    let target = target_uri_redacted.into();
    let schema_digest = blake3::hash(serde_json::to_string(&input.columns)?.as_bytes())
        .to_hex()
        .to_string();

    let receipt = ExportReceipt::new(
        ExportReceiptKind::LocalParquet,
        Some(ExportFormat::Parquet),
        crate::redact_to_owned(&target),
        address,
        Some(row_count),
        Some(schema_digest),
        None,
        created_at_ms,
        vec![format!(
            "codec:{}",
            serde_json::to_string(&opts.compression)?
        )],
    );
    let log_line = ExportLogEvent::from_receipt(&receipt)?.to_json_line()?;

    Ok(LocalExportArtifact {
        bytes,
        receipt,
        log_line,
    })
}

// ─── Pure Safe Rust Parquet Validator & Reader ───────────────────────────────

/// Detailed metadata parsed from a Parquet file inspection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParquetInspection {
    pub magic_header_valid: bool,
    pub magic_footer_valid: bool,
    pub file_version: i32,
    pub row_count: i64,
    pub column_count: usize,
    pub column_names: Vec<String>,
    pub created_by: Option<String>,
}

/// Inspect and validate standard Parquet file headers, footers, and metadata.
pub fn validate_parquet(bytes: &[u8]) -> ExportResult<ParquetInspection> {
    if bytes.len() < 12 {
        return Err(ExportError::Sink {
            message: "file is too small to be a valid Parquet file".to_owned(),
        });
    }

    let header_valid = &bytes[0..4] == PARQUET_MAGIC;
    let footer_valid = &bytes[bytes.len() - 4..] == PARQUET_MAGIC;

    if !header_valid || !footer_valid {
        return Err(ExportError::Sink {
            message: format!(
                "invalid Parquet magic bytes: header={header_valid}, footer={footer_valid}"
            ),
        });
    }

    let footer_len_bytes: [u8; 4] = match bytes[bytes.len() - 8..bytes.len() - 4].try_into() {
        Ok(b) => b,
        Err(_) => {
            return Err(ExportError::Sink {
                message: "slice conversion error".to_owned(),
            });
        }
    };
    let footer_len = u32::from_le_bytes(footer_len_bytes) as usize;

    if bytes.len() < 8_usize.saturating_add(footer_len) {
        return Err(ExportError::Sink {
            message: "Parquet footer length exceeds file size".to_owned(),
        });
    }

    let footer_start = bytes.len() - 8 - footer_len;
    let footer_slice = &bytes[footer_start..footer_start + footer_len];

    let mut reader = ThriftCompactReader::new(footer_slice);
    let mut file_version = 0_i32;
    let mut row_count = 0_i64;
    let mut column_names = Vec::new();
    let mut created_by = None;

    loop {
        let (field_opt, type_code) = reader.read_field_header()?;
        match field_opt {
            None => break,
            Some(1) => {
                file_version = reader.read_zigzag_i32()?;
            }
            Some(2) => {
                // schema list<SchemaElement>
                let (_, schema_len) = reader.read_list_header()?;
                for idx in 0..schema_len {
                    reader.push_struct();
                    let mut name = String::new();
                    loop {
                        let (child_field, child_type) = reader.read_field_header()?;
                        match child_field {
                            None => break,
                            Some(4) => {
                                name = reader.read_string()?;
                            }
                            Some(_) => {
                                reader.skip_field(child_type)?;
                            }
                        }
                    }
                    if idx > 0 {
                        column_names.push(name);
                    }
                }
            }
            Some(3) => {
                row_count = reader.read_zigzag_i64()?;
            }
            Some(6) => {
                created_by = Some(reader.read_string()?);
            }
            Some(_) => {
                reader.skip_field(type_code)?;
            }
        }
    }

    Ok(ParquetInspection {
        magic_header_valid: header_valid,
        magic_footer_valid: footer_valid,
        file_version,
        row_count,
        column_count: column_names.len(),
        column_names,
        created_by,
    })
}

/// Read one member of the Thrift `LogicalType` union after its field header
/// (field 10 of a `SchemaElement`). Unknown members and units yield `None`.
fn read_logical_type(
    reader: &mut ThriftCompactReader<'_>,
) -> ExportResult<Option<ParquetLogicalType>> {
    reader.push_struct(); // the union
    let (member, member_type) = reader.read_field_header()?;
    let Some(member) = member else {
        return Ok(None);
    };
    let mut logical = None;
    if member_type == thrift_type::STRUCT {
        reader.push_struct(); // the member struct
        let mut ints = (None, None);
        let mut adjusted_to_utc = false;
        let mut unit = None;
        loop {
            let (field, field_type) = reader.read_field_header()?;
            match field {
                None => break,
                Some(1) if field_type == thrift_type::BOOLEAN_TRUE => adjusted_to_utc = true,
                Some(1) if field_type == thrift_type::BOOLEAN_FALSE => adjusted_to_utc = false,
                Some(1) if field_type == thrift_type::I32 => {
                    ints.0 = Some(reader.read_zigzag_i32()?)
                }
                Some(2) if field_type == thrift_type::I32 => {
                    ints.1 = Some(reader.read_zigzag_i32()?)
                }
                Some(2) if field_type == thrift_type::STRUCT => {
                    reader.push_struct(); // the TimeUnit union
                    let (unit_member, unit_type) = reader.read_field_header()?;
                    unit = match unit_member {
                        Some(2) => Some(TimeUnit::Micros),
                        Some(3) => Some(TimeUnit::Nanos),
                        _ => None,
                    };
                    if unit_member.is_some() {
                        reader.skip_field(unit_type)?;
                        // Consume the union's STOP.
                        let _ = reader.read_field_header()?;
                    }
                }
                Some(_) => reader.skip_field(field_type)?,
            }
        }
        let as_u32 = |value: Option<i32>| value.and_then(|v| u32::try_from(v).ok());
        logical = match member {
            1 => Some(ParquetLogicalType::String),
            5 => match (as_u32(ints.0), as_u32(ints.1)) {
                (Some(scale), Some(precision)) => {
                    Some(ParquetLogicalType::Decimal { precision, scale })
                }
                _ => None,
            },
            6 => Some(ParquetLogicalType::Date),
            7 => unit.map(|unit| ParquetLogicalType::Time { unit }),
            8 => unit.map(|unit| ParquetLogicalType::Timestamp {
                adjusted_to_utc,
                unit,
            }),
            12 => Some(ParquetLogicalType::Json),
            _ => None,
        };
    } else {
        reader.skip_field(member_type)?;
    }
    // Consume the union's STOP.
    let _ = reader.read_field_header()?;
    Ok(logical)
}

/// Rebuild a column descriptor (including the decode codec) from the schema
/// annotations a Parquet file carries.
fn descriptor_from_schema(
    physical: ParquetType,
    type_length: Option<i32>,
    converted: Option<ParquetConvertedType>,
    logical: Option<ParquetLogicalType>,
    (precision, scale): (Option<u32>, Option<u32>),
    nullable: bool,
) -> ParquetColumnDescriptor {
    let logical = logical.or(match converted {
        Some(ParquetConvertedType::Utf8) => Some(ParquetLogicalType::String),
        Some(ParquetConvertedType::Date) => Some(ParquetLogicalType::Date),
        Some(ParquetConvertedType::Json) => Some(ParquetLogicalType::Json),
        Some(ParquetConvertedType::TimestampMicros) => Some(ParquetLogicalType::Timestamp {
            adjusted_to_utc: true,
            unit: TimeUnit::Micros,
        }),
        Some(ParquetConvertedType::Decimal) => Some(ParquetLogicalType::Decimal {
            precision: precision.unwrap_or(38),
            scale: scale.unwrap_or(0),
        }),
        None => None,
    });
    let codec = match (logical, physical) {
        (Some(ParquetLogicalType::Decimal { precision, scale }), _) => {
            CellCodec::Decimal { precision, scale }
        }
        (Some(ParquetLogicalType::Date), _) => CellCodec::Date,
        (Some(ParquetLogicalType::Time { unit }), _) => CellCodec::TimeOfDay { unit },
        (Some(ParquetLogicalType::Timestamp { unit, .. }), _) => CellCodec::Epoch { unit },
        (Some(ParquetLogicalType::String | ParquetLogicalType::Json), _) => CellCodec::Text,
        (None, ParquetType::Boolean) => CellCodec::Boolean,
        (None, ParquetType::Double) => CellCodec::Float,
        (None, ParquetType::Int32 | ParquetType::Int64) => CellCodec::Integer,
        (None, ParquetType::ByteArray | ParquetType::FixedLenByteArray) => CellCodec::HexBytes,
    };
    ParquetColumnDescriptor {
        physical,
        converted,
        logical,
        type_length,
        nullable,
        codec,
    }
}

/// The Snowflake type label (plus precision/scale) a descriptor corresponds to.
fn snowflake_type_of(desc: &ParquetColumnDescriptor) -> (Option<u32>, Option<u32>, &'static str) {
    match desc.logical {
        Some(ParquetLogicalType::Decimal { precision, scale }) => {
            (Some(precision), Some(scale), "NUMBER")
        }
        Some(ParquetLogicalType::Date) => (None, None, "DATE"),
        Some(ParquetLogicalType::Time { unit }) => (None, Some(unit.digits()), "TIME"),
        Some(ParquetLogicalType::Timestamp {
            adjusted_to_utc,
            unit,
        }) => (
            None,
            Some(unit.digits()),
            if adjusted_to_utc {
                "TIMESTAMP_LTZ"
            } else {
                "TIMESTAMP_NTZ"
            },
        ),
        Some(ParquetLogicalType::Json) => (None, None, "VARIANT"),
        Some(ParquetLogicalType::String) => (None, None, "TEXT"),
        None => match desc.physical {
            ParquetType::Boolean => (None, None, "BOOLEAN"),
            ParquetType::Double => (None, None, "FLOAT"),
            ParquetType::Int32 | ParquetType::Int64 => (None, None, "NUMBER"),
            ParquetType::ByteArray | ParquetType::FixedLenByteArray => (None, None, "BINARY"),
        },
    }
}

/// A bounds-checked cursor over PLAIN-encoded values that renders each value
/// back into the canonical `jsonv2`-style text the writer accepts.
struct PlainCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
    bool_idx: usize,
}

impl PlainCursor<'_> {
    fn take(&mut self, len: usize) -> ExportResult<&[u8]> {
        let end = self.pos.saturating_add(len);
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| ExportError::Sink {
                message: "Parquet page ends before its values".to_owned(),
            })?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> ExportResult<[u8; N]> {
        let slice = self.take(N)?;
        let mut out = [0_u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn decode(&mut self, desc: &ParquetColumnDescriptor) -> ExportResult<String> {
        let integer: i128 = match desc.physical {
            ParquetType::Boolean => {
                let byte = *self
                    .bytes
                    .get(self.bool_idx / 8)
                    .ok_or_else(|| ExportError::Sink {
                        message: "Parquet page ends before its booleans".to_owned(),
                    })?;
                let bit = (byte >> (self.bool_idx % 8)) & 1;
                self.bool_idx = self.bool_idx.saturating_add(1);
                return Ok(if bit == 1 { "true" } else { "false" }.to_owned());
            }
            ParquetType::Double => {
                let value = f64::from_bits(u64::from_le_bytes(self.array::<8>()?));
                return Ok(value.to_string());
            }
            ParquetType::ByteArray => {
                let len = u32::from_le_bytes(self.array::<4>()?) as usize;
                let raw = self.take(len)?;
                return if desc.codec == CellCodec::Text {
                    std::str::from_utf8(raw)
                        .map(str::to_owned)
                        .map_err(|e| ExportError::Sink {
                            message: format!("invalid UTF-8 in Parquet string: {e}"),
                        })
                } else {
                    Ok(raw.iter().map(|b| format!("{b:02X}")).collect())
                };
            }
            ParquetType::FixedLenByteArray => {
                let width = desc.type_length.unwrap_or(16).clamp(1, 16) as usize;
                let raw = self.take(width)?;
                if desc.codec == CellCodec::HexBytes {
                    return Ok(raw.iter().map(|b| format!("{b:02X}")).collect());
                }
                // Sign-extend the big-endian two's complement value.
                let fill = if raw.first().is_some_and(|b| b & 0x80 != 0) {
                    0xFF
                } else {
                    0x00
                };
                let mut be = [fill; 16];
                be[16 - width..].copy_from_slice(raw);
                i128::from_be_bytes(be)
            }
            ParquetType::Int32 => i128::from(i32::from_le_bytes(self.array::<4>()?)),
            ParquetType::Int64 => i128::from(i64::from_le_bytes(self.array::<8>()?)),
        };
        Ok(match desc.codec {
            CellCodec::Decimal { scale, .. } => format_scaled(integer, scale),
            CellCodec::Date => {
                let days = i32::try_from(integer).map_err(|_| ExportError::Sink {
                    message: "DATE value outside the INT32 range".to_owned(),
                })?;
                let (y, m, d) = civil_from_days(days);
                format!("{y:04}-{m:02}-{d:02}")
            }
            CellCodec::TimeOfDay { unit }
            | CellCodec::Epoch { unit }
            | CellCodec::TzInstant { unit } => format_scaled(integer, unit.digits()),
            _ => integer.to_string(),
        })
    }
}

/// Fully deserialize a Parquet file back into `LocalExportInput` for bitwise scalar verification.
pub fn read_parquet_records(bytes: &[u8]) -> ExportResult<LocalExportInput> {
    let inspection = validate_parquet(bytes)?;

    let footer_len_bytes: [u8; 4] = match bytes[bytes.len() - 8..bytes.len() - 4].try_into() {
        Ok(b) => b,
        Err(_) => {
            return Err(ExportError::Sink {
                message: "slice conversion error".to_owned(),
            });
        }
    };
    let footer_len = u32::from_le_bytes(footer_len_bytes) as usize;
    let footer_start = bytes.len() - 8 - footer_len;
    let footer_slice = &bytes[footer_start..footer_start + footer_len];

    let mut reader = ThriftCompactReader::new(footer_slice);
    let mut columns = Vec::new();
    let mut descriptors: Vec<ParquetColumnDescriptor> = Vec::new();
    let mut chunk_offsets: Vec<(i64, i32)> = Vec::new();

    loop {
        let (field_opt, type_code) = reader.read_field_header()?;
        match field_opt {
            None => break,
            Some(2) => {
                // schema
                let (_, schema_len) = reader.read_list_header()?;
                for idx in 0..schema_len {
                    reader.push_struct();
                    let mut name = String::new();
                    let mut ptype = ParquetType::ByteArray;
                    let mut type_length = None;
                    let mut converted = None;
                    let mut logical = None;
                    let mut decimal = (None, None);
                    let mut nullable = true;

                    loop {
                        let (child_field, child_type) = reader.read_field_header()?;
                        match child_field {
                            None => break,
                            Some(1) => {
                                let t_id = reader.read_zigzag_i32()?;
                                ptype = ParquetType::from_thrift(t_id).ok_or_else(|| {
                                    ExportError::Sink {
                                        message: format!(
                                            "unsupported Parquet physical type {t_id}"
                                        ),
                                    }
                                })?;
                            }
                            Some(2) => type_length = Some(reader.read_zigzag_i32()?),
                            Some(3) => {
                                let rep = reader.read_zigzag_i32()?;
                                nullable = rep == 1; // OPTIONAL
                            }
                            Some(4) => {
                                name = reader.read_string()?;
                            }
                            Some(6) => {
                                converted =
                                    ParquetConvertedType::from_thrift(reader.read_zigzag_i32()?);
                            }
                            Some(7) => decimal.1 = u32::try_from(reader.read_zigzag_i32()?).ok(),
                            Some(8) => decimal.0 = u32::try_from(reader.read_zigzag_i32()?).ok(),
                            Some(10) if child_type == thrift_type::STRUCT => {
                                logical = read_logical_type(&mut reader)?;
                            }
                            Some(_) => {
                                reader.skip_field(child_type)?;
                            }
                        }
                    }

                    if idx > 0 {
                        let desc = descriptor_from_schema(
                            ptype,
                            type_length,
                            converted,
                            logical,
                            decimal,
                            nullable,
                        );
                        let (precision, scale, sf_type) = snowflake_type_of(&desc);
                        columns.push(
                            ExportColumn::new(name, sf_type)
                                .nullable(nullable)
                                .precision_scale(precision, scale),
                        );
                        descriptors.push(desc);
                    }
                }
            }
            Some(4) => {
                // row_groups
                let (_, rg_len) = reader.read_list_header()?;
                for _ in 0..rg_len {
                    reader.push_struct();
                    loop {
                        let (rg_field, rg_type) = reader.read_field_header()?;
                        match rg_field {
                            None => break,
                            Some(1) => {
                                // columns
                                let (_, col_len) = reader.read_list_header()?;
                                for _ in 0..col_len {
                                    reader.push_struct();
                                    let mut data_page_offset = 0_i64;
                                    let mut codec = 0_i32;

                                    loop {
                                        let (chunk_field, chunk_type) =
                                            reader.read_field_header()?;
                                        match chunk_field {
                                            None => break,
                                            Some(3) => {
                                                // meta_data
                                                reader.push_struct();
                                                loop {
                                                    let (m_field, m_type) =
                                                        reader.read_field_header()?;
                                                    match m_field {
                                                        None => break,
                                                        Some(4) => {
                                                            codec = reader.read_zigzag_i32()?;
                                                        }
                                                        Some(9) => {
                                                            data_page_offset =
                                                                reader.read_zigzag_i64()?;
                                                        }
                                                        Some(_) => {
                                                            reader.skip_field(m_type)?;
                                                        }
                                                    }
                                                }
                                            }
                                            Some(_) => {
                                                reader.skip_field(chunk_type)?;
                                            }
                                        }
                                    }
                                    chunk_offsets.push((data_page_offset, codec));
                                }
                            }
                            Some(_) => {
                                reader.skip_field(rg_type)?;
                            }
                        }
                    }
                }
            }
            Some(_) => {
                reader.skip_field(type_code)?;
            }
        }
    }

    // Now decode each column chunk
    let mut reconstructed_cols: Vec<Vec<Option<String>>> = vec![Vec::new(); columns.len()];

    for (col_idx, (offset, codec_id)) in chunk_offsets.iter().enumerate() {
        let desc = descriptors
            .get(col_idx)
            .copied()
            .ok_or_else(|| ExportError::Sink {
                message: "Parquet row group has more column chunks than the schema".to_owned(),
            })?;
        let chunk_slice = bytes
            .get(*offset as usize..)
            .ok_or_else(|| ExportError::Sink {
                message: "column chunk offset exceeds the file".to_owned(),
            })?;
        let mut page_reader = ThriftCompactReader::new(chunk_slice);
        let mut comp_size = 0_i32;

        loop {
            let (ph_field, ph_type) = page_reader.read_field_header()?;
            match ph_field {
                None => break,
                Some(3) => {
                    comp_size = page_reader.read_zigzag_i32()?;
                }
                Some(_) => {
                    page_reader.skip_field(ph_type)?;
                }
            }
        }

        let header_len = page_reader.position();
        let payload_slice = chunk_slice
            .get(header_len..header_len.saturating_add(comp_size.max(0) as usize))
            .ok_or_else(|| ExportError::Sink {
                message: "page payload exceeds the file".to_owned(),
            })?;

        let decompressed = match ParquetCompression::from_thrift_codec_id(*codec_id)? {
            ParquetCompression::Uncompressed => payload_slice.to_vec(),
            ParquetCompression::Snappy => snappy_decompress(payload_slice)?,
            ParquetCompression::Gzip => gzip_decompress(payload_slice)?,
        };

        let (defs, data_start) = if desc.nullable {
            decode_definition_levels(&decompressed, inspection.row_count as usize)?
        } else {
            (vec![1_u8; inspection.row_count as usize], 0)
        };

        let mut values = PlainCursor {
            bytes: decompressed.get(data_start..).unwrap_or_default(),
            pos: 0,
            bool_idx: 0,
        };
        for def in defs {
            let cell = if def == 0 {
                None
            } else {
                Some(values.decode(&desc)?)
            };
            reconstructed_cols[col_idx].push(cell);
        }
    }

    // Pivot columns back into rows
    let row_count = inspection.row_count as usize;
    let mut rows: Vec<Vec<Option<String>>> = (0..row_count)
        .map(|_| Vec::with_capacity(columns.len()))
        .collect();
    for col in &reconstructed_cols {
        for (row_idx, cell) in col.iter().enumerate().take(row_count) {
            rows[row_idx].push(cell.clone());
        }
    }

    Ok(LocalExportInput::new(
        columns,
        vec![ResultPartition::new(0, rows)],
    ))
}
