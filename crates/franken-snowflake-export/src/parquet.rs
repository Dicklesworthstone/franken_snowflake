#![forbid(unsafe_code)]

//! `franken-snowflake-export::parquet` -- Clean-room, Tokio-free, pure safe Rust
//! Apache Parquet file format encoder and reader.
//!
//! # Specification Conformance
//! Implements Apache Parquet format specification v2.0 using the standard Thrift
//! Compact Protocol for `FileMetaData`, `ColumnMetaData`, and `PageHeader`.
//! Supports PLAIN value encoding, RLE/Bit-Packing hybrid definition levels for
//! nullable columns, optional statistics (null count, min/max values), and
//! compression modes (Uncompressed, Snappy, Gzip).

use serde::{Deserialize, Serialize};

use crate::local::{ExportByteSink, ExportColumn, LocalExportArtifact, LocalExportInput, ResultPartition};
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
                && input[pos.saturating_add(match_len)] == input[candidate.saturating_add(match_len)]
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
        let tag = 0x01 | (((len.saturating_sub(4) as u8) & 0x07) << 2) | (((offset >> 8) as u8 & 0x07) << 5);
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
    compressor.compress(input, &mut out).map_err(|e| ExportError::Sink {
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
    decompressor.finish(&mut out).map_err(|e| ExportError::Sink {
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
}

/// Logical / Converted types for Parquet metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParquetConvertedType {
    Utf8 = 0,
    Date = 6,
    TimestampMicros = 10,
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
    pub nullable: bool,
}

impl ParquetColumnDescriptor {
    /// Resolve physical and converted type from Snowflake logical type string.
    #[must_use]
    pub fn resolve(snowflake_type: &str, nullable: bool) -> Self {
        let base = snowflake_type
            .split('(')
            .next()
            .unwrap_or(snowflake_type)
            .trim()
            .to_ascii_uppercase();

        match base.as_str() {
            "BOOLEAN" | "BOOL" => Self {
                physical: ParquetType::Boolean,
                converted: None,
                nullable,
            },
            "DATE" => Self {
                physical: ParquetType::Int32,
                converted: Some(ParquetConvertedType::Date),
                nullable,
            },
            "TIMESTAMP" | "TIMESTAMP_NTZ" | "TIMESTAMP_LTZ" | "TIMESTAMP_TZ" => Self {
                physical: ParquetType::Int64,
                converted: Some(ParquetConvertedType::TimestampMicros),
                nullable,
            },
            "FLOAT" | "FLOAT4" | "FLOAT8" | "DOUBLE" | "DOUBLE PRECISION" | "REAL" => Self {
                physical: ParquetType::Double,
                converted: None,
                nullable,
            },
            "NUMBER" | "FIXED" | "DECIMAL" | "NUMERIC" => {
                // If scale is specified and non-zero, map to Double; otherwise Int64.
                if let Some(scale_str) = snowflake_type.split(',').nth(1) {
                    let scale = scale_str.trim().trim_end_matches(')').parse::<i32>().unwrap_or(0);
                    if scale > 0 {
                        return Self {
                            physical: ParquetType::Double,
                            converted: None,
                            nullable,
                        };
                    }
                }
                Self {
                    physical: ParquetType::Int64,
                    converted: None,
                    nullable,
                }
            }
            "INT" | "INTEGER" | "BIGINT" | "SMALLINT" | "TINYINT" | "BYTEINT" => Self {
                physical: ParquetType::Int64,
                converted: None,
                nullable,
            },
            _ => Self {
                physical: ParquetType::ByteArray,
                converted: Some(ParquetConvertedType::Utf8),
                nullable,
            },
        }
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
pub fn decode_definition_levels(data: &[u8], total_values: usize) -> ExportResult<(Vec<u8>, usize)> {
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
                match desc.physical {
                    ParquetType::Int64 => {
                        let val = parse_i64_cell(s, desc.converted)?;
                        stats.update_i64(val);
                        values.extend_from_slice(&val.to_le_bytes());
                    }
                    ParquetType::Int32 => {
                        let val = parse_i32_cell(s, desc.converted)?;
                        stats.update_i32(val);
                        values.extend_from_slice(&val.to_le_bytes());
                    }
                    ParquetType::Double => {
                        let val = parse_f64_cell(s)?;
                        stats.update_f64(val);
                        values.extend_from_slice(&val.to_bits().to_le_bytes());
                    }
                    ParquetType::Boolean => {
                        let val = matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1" | "t");
                        bool_bits.push(val);
                    }
                    ParquetType::ByteArray => {
                        stats.update_str(s);
                        let bytes = s.as_bytes();
                        let len_u32 = bytes.len() as u32;
                        values.extend_from_slice(&len_u32.to_le_bytes());
                        values.extend_from_slice(bytes);
                    }
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

fn parse_i64_cell(s: &str, converted: Option<ParquetConvertedType>) -> ExportResult<i64> {
    let trimmed = s.trim();
    if converted == Some(ParquetConvertedType::TimestampMicros) {
        if trimmed.contains('.') {
            let mut parts = trimmed.split('.');
            if let (Some(sec_str), Some(frac_str)) = (parts.next(), parts.next()) {
                let sec = sec_str.parse::<i64>().map_err(|e| ExportError::Sink {
                    message: format!("cannot parse timestamp seconds `{sec_str}`: {e}"),
                })?;
                let frac_micros = parse_fractional_micros(frac_str);
                let total = if sec >= 0 && !sec_str.starts_with('-') {
                    sec.saturating_mul(1_000_000).saturating_add(frac_micros)
                } else {
                    sec.saturating_mul(1_000_000).saturating_sub(frac_micros)
                };
                return Ok(total);
            }
        }
        if let Ok(v) = trimmed.parse::<i64>() {
            return Ok(if v.abs() >= 100_000_000_000 {
                v
            } else {
                v.saturating_mul(1_000_000)
            });
        }
    }
    if let Ok(v) = trimmed.parse::<i64>() {
        return Ok(v);
    }
    // Handle floating decimal integer representation e.g. "123.0"
    if let Ok(f) = trimmed.parse::<f64>() {
        return Ok(f as i64);
    }
    // Handle timestamp microseconds with decimal fractional seconds e.g. "1704067200.123456"
    if let Some((sec_str, frac_str)) = trimmed.split_once('.') {
        let frac_micros = parse_fractional_micros(frac_str);
        if let Ok(sec) = sec_str.parse::<i64>() {
            return Ok(sec.saturating_mul(1_000_000).saturating_add(frac_micros));
        }
    }
    Err(ExportError::Sink {
        message: format!("cannot parse i64 Parquet cell from `{s}`"),
    })
}

fn parse_i32_cell(s: &str, converted: Option<ParquetConvertedType>) -> ExportResult<i32> {
    let trimmed = s.trim();
    if let Ok(v) = trimmed.parse::<i32>() {
        return Ok(v);
    }
    if converted == Some(ParquetConvertedType::Date) {
        // Parse ISO date "YYYY-MM-DD"
        if let Some(days) = parse_iso_date_to_days(trimmed) {
            return Ok(days);
        }
    }
    Err(ExportError::Sink {
        message: format!("cannot parse i32 Parquet cell from `{s}`"),
    })
}

fn parse_f64_cell(s: &str) -> ExportResult<f64> {
    s.trim().parse::<f64>().map_err(|e| ExportError::Sink {
        message: format!("cannot parse f64 Parquet cell from `{s}`: {e}"),
    })
}

fn parse_fractional_micros(frac: &str) -> i64 {
    let digits = frac.as_bytes();
    let mut val = 0_i64;
    for i in 0..6 {
        val = val.saturating_mul(10);
        if i < digits.len() && digits[i].is_ascii_digit() {
            val = val.saturating_add((digits[i] - b'0') as i64);
        }
    }
    val
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
        ParquetType::Boolean => {}
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
    columns: &[ExportColumn],
    chunks: &[WrittenColumnChunk],
    total_rows: i64,
    options: &ParquetWriterOptions,
) -> Vec<u8> {
    let mut writer = ThriftCompactWriter::new();
    // 1: required i32 version = 1
    writer.write_i32_field(1, 1);

    // 2: required list<SchemaElement> schema
    writer.write_list_field_begin(2, thrift_type::STRUCT, columns.len().saturating_add(1));

    // Root SchemaElement (name = "schema", num_children = columns.len())
    writer.push_struct();
    writer.write_string_field(4, "schema");
    writer.write_i32_field(5, columns.len() as i32);
    writer.pop_struct();

    // Leaf SchemaElements
    for (col, chunk) in columns.iter().zip(chunks.iter()) {
        writer.push_struct();
        // 1: optional Type type
        writer.write_i32_field(1, chunk.desc.physical as i32);
        // 3: optional FieldRepetitionType repetition_type (REQUIRED = 0, OPTIONAL = 1)
        writer.write_i32_field(
            3,
            if chunk.desc.nullable {
                FieldRepetitionType::Optional as i32
            } else {
                FieldRepetitionType::Required as i32
            },
        );
        // 4: required string name
        writer.write_string_field(4, &col.name);

        // 6: optional ConvertedType converted_type
        if let Some(converted) = chunk.desc.converted {
            writer.write_i32_field(6, converted as i32);
        }

        // 10: optional LogicalType logicalType
        if let Some(converted) = chunk.desc.converted {
            writer.write_struct_field_begin(10);
            match converted {
                ParquetConvertedType::Utf8 => {
                    // 1: StringType STRING
                    writer.write_struct_field_begin(1);
                    writer.pop_struct();
                }
                ParquetConvertedType::Date => {
                    // 6: DateType DATE
                    writer.write_struct_field_begin(6);
                    writer.pop_struct();
                }
                ParquetConvertedType::TimestampMicros => {
                    // 8: TimestampType TIMESTAMP
                    writer.write_struct_field_begin(8);
                    writer.write_bool_field(1, true); // isAdjustedToUTC
                    writer.write_struct_field_begin(2); // unit
                    writer.write_struct_field_begin(2); // MicroSeconds
                    writer.pop_struct();
                    writer.pop_struct();
                    writer.pop_struct();
                }
            }
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
            ParquetType::Boolean => {}
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

    // Validate column name uniqueness
    let mut seen = std::collections::BTreeSet::new();
    for col in columns {
        if !seen.insert(col.name.as_str()) {
            return Err(ExportError::DuplicateColumn {
                name: col.name.clone(),
            });
        }
    }

    // Gather and flatten rows preserving column order
    let descriptors: Vec<ParquetColumnDescriptor> = columns
        .iter()
        .map(|col| ParquetColumnDescriptor::resolve(&col.snowflake_type, col.nullable))
        .collect();

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

    let mut written_chunks = Vec::with_capacity(columns.len());

    // 2. Encode and write ColumnChunks
    for (col_idx, desc) in descriptors.iter().enumerate() {
        let (page_uncompressed, stats) = encode_column_plain(desc, &column_cells[col_idx])?;

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
            name: columns[col_idx].name.clone(),
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
    let file_meta_bytes =
        serialize_file_metadata(columns, &written_chunks, total_rows as i64, options);
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
    let row_count = write_parquet_stream(&input.columns, input.partitions.iter(), &mut sink, &opts)?;
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
        vec![format!("codec:{}", serde_json::to_string(&opts.compression)?)],
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
            message: format!("invalid Parquet magic bytes: header={header_valid}, footer={footer_valid}"),
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
    let mut chunk_offsets: Vec<(i64, i32, ParquetType, Option<ParquetConvertedType>, bool)> = Vec::new();

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
                    let mut converted = None;
                    let mut nullable = true;

                    loop {
                        let (child_field, child_type) = reader.read_field_header()?;
                        match child_field {
                            None => break,
                            Some(1) => {
                                let t_id = reader.read_zigzag_i32()?;
                                ptype = match t_id {
                                    0 => ParquetType::Boolean,
                                    1 => ParquetType::Int32,
                                    2 => ParquetType::Int64,
                                    5 => ParquetType::Double,
                                    _ => ParquetType::ByteArray,
                                };
                            }
                            Some(3) => {
                                let rep = reader.read_zigzag_i32()?;
                                nullable = rep == 1; // OPTIONAL
                            }
                            Some(4) => {
                                name = reader.read_string()?;
                            }
                            Some(6) => {
                                let conv = reader.read_zigzag_i32()?;
                                converted = match conv {
                                    0 => Some(ParquetConvertedType::Utf8),
                                    6 => Some(ParquetConvertedType::Date),
                                    10 => Some(ParquetConvertedType::TimestampMicros),
                                    _ => None,
                                };
                            }
                            Some(_) => {
                                reader.skip_field(child_type)?;
                            }
                        }
                    }

                    if idx > 0 {
                        let sf_type = match ptype {
                            ParquetType::Int64 => {
                                if converted == Some(ParquetConvertedType::TimestampMicros) {
                                    "TIMESTAMP_NTZ"
                                } else {
                                    "NUMBER"
                                }
                            }
                            ParquetType::Int32 => {
                                if converted == Some(ParquetConvertedType::Date) {
                                    "DATE"
                                } else {
                                    "NUMBER"
                                }
                            }
                            ParquetType::Double => "FLOAT",
                            ParquetType::Boolean => "BOOLEAN",
                            ParquetType::ByteArray => "TEXT",
                        };
                        columns.push(ExportColumn::new(name, sf_type).nullable(nullable));
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
                                for col_idx in 0..col_len {
                                    reader.push_struct();
                                    let mut data_page_offset = 0_i64;
                                    let mut codec = 0_i32;

                                    loop {
                                        let (chunk_field, chunk_type) = reader.read_field_header()?;
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
                                    let ptype = match columns.get(col_idx).map(|c| c.snowflake_type.as_str()) {
                                        Some("BOOLEAN") => ParquetType::Boolean,
                                        Some("DATE") => ParquetType::Int32,
                                        Some("FLOAT") => ParquetType::Double,
                                        Some("TEXT") => ParquetType::ByteArray,
                                        _ => ParquetType::Int64,
                                    };
                                    let conv = match columns.get(col_idx).map(|c| c.snowflake_type.as_str()) {
                                        Some("DATE") => Some(ParquetConvertedType::Date),
                                        Some("TIMESTAMP_NTZ") => Some(ParquetConvertedType::TimestampMicros),
                                        Some("TEXT") => Some(ParquetConvertedType::Utf8),
                                        _ => None,
                                    };
                                    let nullable = columns.get(col_idx).is_none_or(|c| c.nullable);
                                    chunk_offsets.push((data_page_offset, codec, ptype, conv, nullable));
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

    for (col_idx, (offset, codec_id, ptype, conv, nullable)) in chunk_offsets.iter().enumerate() {
        let chunk_slice = &bytes[*offset as usize..];
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
        let payload_slice = &chunk_slice[header_len..header_len + comp_size as usize];

        let decompressed = match ParquetCompression::from_thrift_codec_id(*codec_id)? {
            ParquetCompression::Uncompressed => payload_slice.to_vec(),
            ParquetCompression::Snappy => snappy_decompress(payload_slice)?,
            ParquetCompression::Gzip => gzip_decompress(payload_slice)?,
        };

        let (defs, data_start) = if *nullable {
            decode_definition_levels(&decompressed, inspection.row_count as usize)?
        } else {
            (vec![1_u8; inspection.row_count as usize], 0)
        };

        let values_slice = &decompressed[data_start..];
        let mut val_pos = 0_usize;
        let mut bool_idx = 0_usize;

        for def in defs {
            if def == 0 {
                reconstructed_cols[col_idx].push(None);
            } else {
                match ptype {
                    ParquetType::Int64 => {
                        let b: [u8; 8] = match values_slice[val_pos..val_pos + 8].try_into() {
                            Ok(x) => x,
                            Err(_) => {
                                return Err(ExportError::Sink {
                                    message: "slice conversion error".to_owned(),
                                });
                            }
                        };
                        val_pos = val_pos.saturating_add(8);
                        let val = i64::from_le_bytes(b);
                        let str_val = if *conv == Some(ParquetConvertedType::TimestampMicros) {
                            let sec = val / 1_000_000;
                            let frac = (val % 1_000_000).abs();
                            if val < 0 && sec == 0 {
                                format!("-0.{frac:06}")
                            } else {
                                format!("{sec}.{frac:06}")
                            }
                        } else {
                            val.to_string()
                        };
                        reconstructed_cols[col_idx].push(Some(str_val));
                    }
                    ParquetType::Int32 => {
                        let b: [u8; 4] = match values_slice[val_pos..val_pos + 4].try_into() {
                            Ok(x) => x,
                            Err(_) => {
                                return Err(ExportError::Sink {
                                    message: "slice conversion error".to_owned(),
                                });
                            }
                        };
                        val_pos = val_pos.saturating_add(4);
                        let val = i32::from_le_bytes(b);
                        if *conv == Some(ParquetConvertedType::Date) {
                            let (y, m, d) = civil_from_days(val);
                            reconstructed_cols[col_idx].push(Some(format!("{y:04}-{m:02}-{d:02}")));
                        } else {
                            reconstructed_cols[col_idx].push(Some(val.to_string()));
                        }
                    }
                    ParquetType::Double => {
                        let b: [u8; 8] = match values_slice[val_pos..val_pos + 8].try_into() {
                            Ok(x) => x,
                            Err(_) => {
                                return Err(ExportError::Sink {
                                    message: "slice conversion error".to_owned(),
                                });
                            }
                        };
                        val_pos = val_pos.saturating_add(8);
                        let val = f64::from_bits(u64::from_le_bytes(b));
                        reconstructed_cols[col_idx].push(Some(val.to_string()));
                    }
                    ParquetType::Boolean => {
                        let byte = values_slice[bool_idx / 8];
                        let bit = (byte >> (bool_idx % 8)) & 1;
                        bool_idx = bool_idx.saturating_add(1);
                        reconstructed_cols[col_idx].push(Some(if bit == 1 {
                            "true".to_owned()
                        } else {
                            "false".to_owned()
                        }));
                    }
                    ParquetType::ByteArray => {
                        let b: [u8; 4] = match values_slice[val_pos..val_pos + 4].try_into() {
                            Ok(x) => x,
                            Err(_) => {
                                return Err(ExportError::Sink {
                                    message: "slice conversion error".to_owned(),
                                });
                            }
                        };
                        val_pos = val_pos.saturating_add(4);
                        let str_len = u32::from_le_bytes(b) as usize;
                        let s = std::str::from_utf8(&values_slice[val_pos..val_pos + str_len])
                            .map_err(|e| ExportError::Sink {
                                message: format!("invalid UTF-8 in Parquet string: {e}"),
                            })?;
                        val_pos = val_pos.saturating_add(str_len);
                        reconstructed_cols[col_idx].push(Some(s.to_owned()));
                    }
                }
            }
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

    Ok(LocalExportInput::new(columns, vec![ResultPartition::new(0, rows)]))
}
