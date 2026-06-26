#![forbid(unsafe_code)]

//! `franken-snowflake-export` -- content-addressed result export.
//!
//! COPY INTO plans are always available because large exports should run
//! Snowflake-side. Local CSV/JSONL writers are compiled for proof coverage here,
//! but their public API is re-exported only behind the `export` feature. This
//! crate deliberately avoids `fp-io`, Arrow, Parquet, ORC, Tokio, and any
//! Snowflake driver dependency.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use franken_snowflake_core::redact::redact;
use serde::{Deserialize, Serialize};

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Contract id for deterministic COPY INTO export plans.
pub const COPY_INTO_PLAN_CONTRACT_ID: &str = "fsnow.export.copy_into_plan.v1";

/// Contract id for content-addressed export receipts.
pub const EXPORT_RECEIPT_CONTRACT_ID: &str = "fsnow.export.receipt.v1";

/// Contract id for structured JSON-line export logs.
pub const EXPORT_LOG_CONTRACT_ID: &str = "fsnow.export.log.v1";

/// Whether the public local CSV/JSONL backend API is enabled.
pub const LOCAL_BACKENDS_ENABLED: bool = cfg!(feature = "export");

/// Result alias for export operations.
pub type ExportResult<T> = Result<T, ExportError>;

/// Export error vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportError {
    /// A result set had no columns.
    EmptySchema,
    /// A column name was duplicated, which would make JSONL objects ambiguous.
    DuplicateColumn { name: String },
    /// Result partitions must be streamed in increasing partition-index order.
    PartitionOrder { previous: u32, next: u32 },
    /// A row width did not match the schema width.
    RowWidthMismatch {
        partition_index: u32,
        row_index: usize,
        expected: usize,
        actual: usize,
    },
    /// The COPY INTO location is not a safe Snowflake stage URI.
    InvalidCopyLocation { location: String, reason: String },
    /// The COPY INTO query/source text is empty or unsafe for a single statement.
    UnsafeCopySource { reason: String },
    /// Content address verification failed because byte length differed.
    ByteLengthMismatch { expected: u64, actual: u64 },
    /// Content address verification failed because the BLAKE3 digest differed.
    HashMismatch { expected: String, actual: String },
    /// A non-BLAKE3 content address was supplied.
    UnsupportedAddressAlgorithm { algorithm: String },
    /// The caller-provided sink rejected a streamed byte chunk.
    Sink { message: String },
    /// Deterministic JSON serialization failed.
    Json { message: String },
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptySchema => write!(f, "local export requires at least one column"),
            Self::DuplicateColumn { name } => {
                write!(f, "local export column name is duplicated: {name}")
            }
            Self::PartitionOrder { previous, next } => write!(
                f,
                "result partitions must be streamed in increasing order: {next} followed {previous}"
            ),
            Self::RowWidthMismatch {
                partition_index,
                row_index,
                expected,
                actual,
            } => write!(
                f,
                "row width mismatch in partition {partition_index}, row {row_index}: expected {expected}, got {actual}"
            ),
            Self::InvalidCopyLocation { location, reason } => {
                write!(f, "invalid COPY INTO location {location:?}: {reason}")
            }
            Self::UnsafeCopySource { reason } => write!(f, "unsafe COPY INTO source: {reason}"),
            Self::ByteLengthMismatch { expected, actual } => {
                write!(
                    f,
                    "content byte length mismatch: expected {expected}, got {actual}"
                )
            }
            Self::HashMismatch { expected, actual } => {
                write!(
                    f,
                    "content hash mismatch: expected {expected}, got {actual}"
                )
            }
            Self::UnsupportedAddressAlgorithm { algorithm } => write!(
                f,
                "unsupported content-address algorithm {algorithm:?}; only blake3 is verifiable"
            ),
            Self::Sink { message } => write!(f, "export sink rejected bytes: {message}"),
            Self::Json { message } => write!(f, "export JSON serialization failed: {message}"),
        }
    }
}

impl Error for ExportError {}

impl From<serde_json::Error> for ExportError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json {
            message: value.to_string(),
        }
    }
}

/// A byte-length-verified content address.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentAddress {
    /// Hash algorithm label. Only `blake3` is verifiable in this crate.
    pub algorithm: String,
    /// Lowercase hex digest.
    pub digest_hex: String,
    /// Canonical byte length.
    pub byte_len: u64,
}

impl ContentAddress {
    /// Construct a verified BLAKE3 address from canonical bytes.
    #[must_use]
    pub fn blake3(payload: &[u8]) -> Self {
        Self {
            algorithm: "blake3".to_owned(),
            digest_hex: blake3_hex(payload),
            byte_len: usize_to_u64(payload.len()),
        }
    }

    /// Verify byte length and digest against canonical bytes.
    pub fn verify(&self, payload: &[u8]) -> ExportResult<()> {
        let actual_len = usize_to_u64(payload.len());
        if self.byte_len != actual_len {
            return Err(ExportError::ByteLengthMismatch {
                expected: self.byte_len,
                actual: actual_len,
            });
        }
        if self.algorithm != "blake3" {
            return Err(ExportError::UnsupportedAddressAlgorithm {
                algorithm: self.algorithm.clone(),
            });
        }
        let actual = blake3_hex(payload);
        if self.digest_hex != actual {
            return Err(ExportError::HashMismatch {
                expected: self.digest_hex.clone(),
                actual,
            });
        }
        Ok(())
    }
}

/// Export artifact format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    /// RFC 4180-style comma-separated text with LF record separators.
    Csv,
    /// One JSON object per row.
    Jsonl,
}

impl ExportFormat {
    /// Stable format label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Jsonl => "jsonl",
        }
    }
}

impl fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// COPY INTO output compression.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyCompression {
    /// No compression.
    None,
    /// Snowflake-side gzip compression.
    Gzip,
}

impl CopyCompression {
    fn snowflake_sql(self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Gzip => "GZIP",
        }
    }
}

/// Source rows for a Snowflake-side COPY INTO export.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CopySource {
    /// A single read-only SELECT query. Semicolons are refused to prevent
    /// multi-statement export plans.
    Query { sql: String },
    /// Re-fetch a completed query through RESULT_SCAN using its query id.
    ResultScan { query_id: String },
}

impl CopySource {
    /// Render the source SELECT for a COPY INTO plan.
    pub fn to_sql(&self) -> ExportResult<String> {
        match self {
            Self::Query { sql } => {
                validate_single_statement_sql(sql)?;
                Ok(sql.trim().to_owned())
            }
            Self::ResultScan { query_id } => {
                validate_result_scan_query_id(query_id)?;
                Ok(format!(
                    "SELECT * FROM TABLE(RESULT_SCAN({}))",
                    sql_string_literal(query_id)
                ))
            }
        }
    }
}

/// Deterministic COPY INTO plan options.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyIntoOptions {
    /// Snowflake file format.
    pub format: ExportFormat,
    /// Snowflake-side compression.
    pub compression: CopyCompression,
    /// Include a header row for CSV unloads.
    pub header: bool,
    /// Ask Snowflake to overwrite target files.
    pub overwrite: bool,
    /// Ask Snowflake to emit one output file.
    pub single: bool,
    /// Optional Snowflake MAX_FILE_SIZE.
    pub max_file_size: Option<u64>,
}

impl Default for CopyIntoOptions {
    fn default() -> Self {
        Self {
            format: ExportFormat::Csv,
            compression: CopyCompression::None,
            header: true,
            overwrite: false,
            single: false,
            max_file_size: Some(16 * 1024 * 1024),
        }
    }
}

/// A Snowflake-side large-export plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyIntoPlan {
    /// Snowflake stage URI, for example `@analytics_exports/run_001`.
    pub location: String,
    /// Source rows to unload.
    pub source: CopySource,
    /// Deterministic unload options.
    pub options: CopyIntoOptions,
    /// Redacted profile/account label for receipts and logs.
    pub profile_ref_redacted: Option<String>,
}

impl CopyIntoPlan {
    /// Build a COPY INTO plan with default CSV options.
    #[must_use]
    pub fn new(location: impl Into<String>, source: CopySource) -> Self {
        Self {
            location: location.into(),
            source,
            options: CopyIntoOptions::default(),
            profile_ref_redacted: None,
        }
    }

    /// Override COPY INTO options.
    #[must_use]
    pub fn with_options(mut self, options: CopyIntoOptions) -> Self {
        self.options = options;
        self
    }

    /// Attach a redacted profile/account label.
    #[must_use]
    pub fn with_profile_ref_redacted(mut self, profile_ref_redacted: impl Into<String>) -> Self {
        let value = profile_ref_redacted.into();
        self.profile_ref_redacted = Some(redact_to_owned(&value));
        self
    }

    /// Render deterministic COPY INTO SQL.
    pub fn to_sql(&self) -> ExportResult<String> {
        let location_sql = copy_location_sql(&self.location)?;
        let source_sql = self.source.to_sql()?;
        let mut sql = format!(
            "COPY INTO {} FROM ({}) FILE_FORMAT = ({})",
            location_sql,
            source_sql,
            self.file_format_clause()
        );
        if self.options.format == ExportFormat::Csv {
            sql.push_str(if self.options.header {
                " HEADER = TRUE"
            } else {
                " HEADER = FALSE"
            });
        }
        sql.push_str(if self.options.overwrite {
            " OVERWRITE = TRUE"
        } else {
            " OVERWRITE = FALSE"
        });
        sql.push_str(if self.options.single {
            " SINGLE = TRUE"
        } else {
            " SINGLE = FALSE"
        });
        if let Some(max_file_size) = self.options.max_file_size {
            sql.push_str(&format!(" MAX_FILE_SIZE = {max_file_size}"));
        }
        Ok(sql)
    }

    /// Content-address the rendered plan SQL.
    pub fn plan_address(&self) -> ExportResult<ContentAddress> {
        Ok(ContentAddress::blake3(self.to_sql()?.as_bytes()))
    }

    /// Build a receipt for the plan itself. Execution is external to this crate.
    pub fn plan_receipt(&self, created_at_ms: u64) -> ExportResult<ExportReceipt> {
        let sql = self.to_sql()?;
        let address = ContentAddress::blake3(sql.as_bytes());
        Ok(ExportReceipt::new(
            ExportReceiptKind::CopyIntoPlan,
            Some(self.options.format),
            redact_to_owned(&self.location),
            address,
            None,
            None,
            Some(self.plan_hash()?),
            created_at_ms,
            vec!["copy_into_plan_only_execution_deferred".to_owned()],
        ))
    }

    /// Stable BLAKE3 digest of the rendered COPY INTO SQL.
    pub fn plan_hash(&self) -> ExportResult<String> {
        Ok(blake3_hex(self.to_sql()?.as_bytes()))
    }

    fn file_format_clause(&self) -> String {
        match self.options.format {
            ExportFormat::Csv => format!(
                "TYPE = CSV COMPRESSION = {} FIELD_OPTIONALLY_ENCLOSED_BY = '\"' NULL_IF = () EMPTY_FIELD_AS_NULL = FALSE",
                self.options.compression.snowflake_sql()
            ),
            ExportFormat::Jsonl => format!(
                "TYPE = JSON COMPRESSION = {}",
                self.options.compression.snowflake_sql()
            ),
        }
    }
}

/// Receipt kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportReceiptKind {
    /// Local CSV artifact.
    LocalCsv,
    /// Local JSONL artifact.
    LocalJsonl,
    /// Snowflake-side COPY INTO plan.
    CopyIntoPlan,
}

impl ExportReceiptKind {
    /// Stable kind label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalCsv => "local_csv",
            Self::LocalJsonl => "local_jsonl",
            Self::CopyIntoPlan => "copy_into_plan",
        }
    }
}

/// Content-addressed export receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportReceipt {
    /// Stable export id keyed by the content digest.
    pub export_id: String,
    /// Receipt contract id.
    pub output_contract_id: String,
    /// Export kind.
    pub kind: ExportReceiptKind,
    /// Artifact format, when applicable.
    pub format: Option<ExportFormat>,
    /// Redacted local path or Snowflake stage URI.
    pub target_uri_redacted: String,
    /// Artifact or plan content address.
    pub content_address: ContentAddress,
    /// Number of exported result rows when known.
    pub row_count: Option<u64>,
    /// BLAKE3 digest of the canonical schema, for local exports.
    pub schema_hash: Option<String>,
    /// BLAKE3 digest of the rendered COPY INTO SQL, for COPY INTO plans.
    pub plan_hash: Option<String>,
    /// Caller-supplied deterministic timestamp.
    pub created_at_ms: u64,
    /// Non-fatal warnings emitted with the receipt.
    pub warnings: Vec<String>,
}

impl ExportReceipt {
    /// Construct a content-addressed receipt.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        kind: ExportReceiptKind,
        format: Option<ExportFormat>,
        target_uri_redacted: String,
        content_address: ContentAddress,
        row_count: Option<u64>,
        schema_hash: Option<String>,
        plan_hash: Option<String>,
        created_at_ms: u64,
        warnings: Vec<String>,
    ) -> Self {
        let export_id = format!("fsnow-export-{}", content_address.digest_hex);
        Self {
            export_id,
            output_contract_id: EXPORT_RECEIPT_CONTRACT_ID.to_owned(),
            kind,
            format,
            target_uri_redacted,
            content_address,
            row_count,
            schema_hash,
            plan_hash,
            created_at_ms,
            warnings,
        }
    }

    /// Deterministic JSON representation.
    pub fn canonical_json(&self) -> ExportResult<String> {
        serde_json::to_string(self).map_err(ExportError::from)
    }

    /// BLAKE3 digest of the deterministic receipt JSON.
    pub fn record_hash(&self) -> ExportResult<String> {
        Ok(blake3_hex(self.canonical_json()?.as_bytes()))
    }
}

/// Structured JSON-line export log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportLogEvent {
    /// Log contract id.
    pub output_contract_id: String,
    /// Stable event kind.
    pub event_kind: String,
    /// Export id.
    pub export_id: String,
    /// BLAKE3 digest of the export receipt record.
    pub record_hash: String,
    /// Artifact or plan content hash.
    pub content_hash: String,
    /// Artifact or plan byte length.
    pub byte_len: u64,
    /// Number of rows when known.
    pub row_count: Option<u64>,
}

impl ExportLogEvent {
    /// Build a log event from an export receipt.
    pub fn from_receipt(receipt: &ExportReceipt) -> ExportResult<Self> {
        Ok(Self {
            output_contract_id: EXPORT_LOG_CONTRACT_ID.to_owned(),
            event_kind: "export_recorded".to_owned(),
            export_id: receipt.export_id.clone(),
            record_hash: receipt.record_hash()?,
            content_hash: receipt.content_address.digest_hex.clone(),
            byte_len: receipt.content_address.byte_len,
            row_count: receipt.row_count,
        })
    }

    /// Deterministic JSON line with a trailing newline.
    pub fn to_json_line(&self) -> ExportResult<String> {
        let mut line = serde_json::to_string(self)?;
        line.push('\n');
        Ok(line)
    }
}

#[allow(dead_code)]
mod local {
    use super::*;

    /// A Snowflake result column as reported by result metadata.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ExportColumn {
        /// Column name.
        pub name: String,
        /// Snowflake logical type label.
        pub snowflake_type: String,
        /// Whether Snowflake reports the column as nullable.
        pub nullable: bool,
    }

    impl ExportColumn {
        /// Construct an export column descriptor.
        #[must_use]
        pub fn new(name: impl Into<String>, snowflake_type: impl Into<String>) -> Self {
            Self {
                name: name.into(),
                snowflake_type: snowflake_type.into(),
                nullable: true,
            }
        }

        /// Set nullability.
        #[must_use]
        pub const fn nullable(mut self, nullable: bool) -> Self {
            self.nullable = nullable;
            self
        }
    }

    /// One fetched result partition. Non-null cells are SQL API `jsonv2` strings.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ResultPartition {
        /// Partition index. Partition 0 is the inline result payload.
        pub index: u32,
        /// Rows in this partition.
        pub rows: Vec<Vec<Option<String>>>,
    }

    impl ResultPartition {
        /// Build a partition.
        #[must_use]
        pub fn new(index: u32, rows: Vec<Vec<Option<String>>>) -> Self {
            Self { index, rows }
        }
    }

    /// Local export input.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct LocalExportInput {
        /// Schema columns, preserving result-set order.
        pub columns: Vec<ExportColumn>,
        /// Fetched partitions, already in stream order.
        pub partitions: Vec<ResultPartition>,
    }

    impl LocalExportInput {
        /// Build local export input.
        #[must_use]
        pub fn new(columns: Vec<ExportColumn>, partitions: Vec<ResultPartition>) -> Self {
            Self {
                columns,
                partitions,
            }
        }

        /// Count rows without materializing new row buffers.
        #[must_use]
        pub fn row_count(&self) -> u64 {
            self.partitions
                .iter()
                .map(|partition| usize_to_u64(partition.rows.len()))
                .sum()
        }
    }

    /// Caller-provided byte sink for streaming local exports.
    pub trait ExportByteSink {
        /// Write one chunk. Writers call this for headers and every row.
        fn write_chunk(&mut self, chunk: &[u8]) -> ExportResult<()>;
    }

    impl ExportByteSink for Vec<u8> {
        fn write_chunk(&mut self, chunk: &[u8]) -> ExportResult<()> {
            self.extend_from_slice(chunk);
            Ok(())
        }
    }

    /// Sink wrapper that computes a BLAKE3 address while streaming bytes onward.
    #[derive(Debug)]
    pub struct AddressingSink<S> {
        inner: S,
        hasher: blake3::Hasher,
        byte_len: u64,
        write_count: u64,
        max_chunk_len: usize,
    }

    impl<S> AddressingSink<S> {
        /// Wrap a sink.
        #[must_use]
        pub fn new(inner: S) -> Self {
            Self {
                inner,
                hasher: blake3::Hasher::new(),
                byte_len: 0,
                write_count: 0,
                max_chunk_len: 0,
            }
        }

        /// Finish hashing and return the wrapped sink plus content address.
        #[must_use]
        pub fn finish(self) -> (S, ContentAddress) {
            let digest_hex = self.hasher.finalize().to_hex().to_string();
            (
                self.inner,
                ContentAddress {
                    algorithm: "blake3".to_owned(),
                    digest_hex,
                    byte_len: self.byte_len,
                },
            )
        }

        /// Number of write calls observed.
        #[must_use]
        pub const fn write_count(&self) -> u64 {
            self.write_count
        }

        /// Maximum streamed chunk length observed.
        #[must_use]
        pub const fn max_chunk_len(&self) -> usize {
            self.max_chunk_len
        }
    }

    impl<S: ExportByteSink> ExportByteSink for AddressingSink<S> {
        fn write_chunk(&mut self, chunk: &[u8]) -> ExportResult<()> {
            self.hasher.update(chunk);
            self.byte_len = self.byte_len.saturating_add(usize_to_u64(chunk.len()));
            self.write_count = self.write_count.saturating_add(1);
            self.max_chunk_len = self.max_chunk_len.max(chunk.len());
            self.inner.write_chunk(chunk)
        }
    }

    /// Local export artifact held in memory by the convenience helpers.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct LocalExportArtifact {
        /// Export bytes.
        pub bytes: Vec<u8>,
        /// Content-addressed receipt.
        pub receipt: ExportReceipt,
        /// Structured JSON-line log event.
        pub log_line: String,
    }

    /// Stream CSV bytes to a caller-provided sink.
    pub fn write_csv_stream<'a, I, S>(
        columns: &[ExportColumn],
        partitions: I,
        sink: &mut S,
    ) -> ExportResult<u64>
    where
        I: IntoIterator<Item = &'a ResultPartition>,
        S: ExportByteSink,
    {
        validate_columns(columns)?;
        let header = csv_record(columns.iter().map(|column| Some(column.name.as_str())));
        sink.write_chunk(header.as_bytes())?;
        stream_rows(columns, partitions, sink, |row, sink| {
            let record = csv_record(row.iter().map(|cell| cell.as_deref()));
            sink.write_chunk(record.as_bytes())
        })
    }

    /// Stream JSONL bytes to a caller-provided sink.
    pub fn write_jsonl_stream<'a, I, S>(
        columns: &[ExportColumn],
        partitions: I,
        sink: &mut S,
    ) -> ExportResult<u64>
    where
        I: IntoIterator<Item = &'a ResultPartition>,
        S: ExportByteSink,
    {
        validate_columns(columns)?;
        stream_rows(columns, partitions, sink, |row, sink| {
            let line = jsonl_record(columns, row)?;
            sink.write_chunk(line.as_bytes())
        })
    }

    /// Build an in-memory CSV artifact and receipt.
    pub fn export_csv(
        input: &LocalExportInput,
        target_uri_redacted: impl Into<String>,
        created_at_ms: u64,
    ) -> ExportResult<LocalExportArtifact> {
        let mut sink = AddressingSink::new(Vec::new());
        let row_count = write_csv_stream(&input.columns, input.partitions.iter(), &mut sink)?;
        let (bytes, address) = sink.finish();
        address.verify(&bytes)?;
        local_artifact(
            bytes,
            address,
            ExportReceiptKind::LocalCsv,
            ExportFormat::Csv,
            target_uri_redacted,
            Some(row_count),
            Some(schema_hash(&input.columns)?),
            created_at_ms,
        )
    }

    /// Build an in-memory JSONL artifact and receipt.
    pub fn export_jsonl(
        input: &LocalExportInput,
        target_uri_redacted: impl Into<String>,
        created_at_ms: u64,
    ) -> ExportResult<LocalExportArtifact> {
        let mut sink = AddressingSink::new(Vec::new());
        let row_count = write_jsonl_stream(&input.columns, input.partitions.iter(), &mut sink)?;
        let (bytes, address) = sink.finish();
        address.verify(&bytes)?;
        local_artifact(
            bytes,
            address,
            ExportReceiptKind::LocalJsonl,
            ExportFormat::Jsonl,
            target_uri_redacted,
            Some(row_count),
            Some(schema_hash(&input.columns)?),
            created_at_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn local_artifact(
        bytes: Vec<u8>,
        address: ContentAddress,
        kind: ExportReceiptKind,
        format: ExportFormat,
        target_uri_redacted: impl Into<String>,
        row_count: Option<u64>,
        schema_hash: Option<String>,
        created_at_ms: u64,
    ) -> ExportResult<LocalExportArtifact> {
        let target = target_uri_redacted.into();
        let receipt = ExportReceipt::new(
            kind,
            Some(format),
            redact_to_owned(&target),
            address,
            row_count,
            schema_hash,
            None,
            created_at_ms,
            Vec::new(),
        );
        let log_line = ExportLogEvent::from_receipt(&receipt)?.to_json_line()?;
        Ok(LocalExportArtifact {
            bytes,
            receipt,
            log_line,
        })
    }

    fn stream_rows<'a, I, S, F>(
        columns: &[ExportColumn],
        partitions: I,
        sink: &mut S,
        mut write_row: F,
    ) -> ExportResult<u64>
    where
        I: IntoIterator<Item = &'a ResultPartition>,
        S: ExportByteSink,
        F: FnMut(&[Option<String>], &mut S) -> ExportResult<()>,
    {
        let mut previous_partition = None;
        let mut row_count = 0_u64;
        for partition in partitions {
            if let Some(previous) = previous_partition {
                if partition.index <= previous {
                    return Err(ExportError::PartitionOrder {
                        previous,
                        next: partition.index,
                    });
                }
            }
            previous_partition = Some(partition.index);
            for (row_index, row) in partition.rows.iter().enumerate() {
                if row.len() != columns.len() {
                    return Err(ExportError::RowWidthMismatch {
                        partition_index: partition.index,
                        row_index,
                        expected: columns.len(),
                        actual: row.len(),
                    });
                }
                write_row(row, sink)?;
                row_count = row_count.saturating_add(1);
            }
        }
        Ok(row_count)
    }

    fn validate_columns(columns: &[ExportColumn]) -> ExportResult<()> {
        if columns.is_empty() {
            return Err(ExportError::EmptySchema);
        }
        let mut seen = BTreeSet::new();
        for column in columns {
            if !seen.insert(column.name.as_str()) {
                return Err(ExportError::DuplicateColumn {
                    name: column.name.clone(),
                });
            }
        }
        Ok(())
    }

    fn csv_record<'a, I>(fields: I) -> String
    where
        I: IntoIterator<Item = Option<&'a str>>,
    {
        let mut record = String::new();
        for (index, field) in fields.into_iter().enumerate() {
            if index > 0 {
                record.push(',');
            }
            if let Some(value) = field {
                push_csv_field(&mut record, value);
            }
        }
        record.push('\n');
        record
    }

    fn push_csv_field(out: &mut String, value: &str) {
        let requires_quotes = value
            .chars()
            .any(|ch| matches!(ch, ',' | '"' | '\n' | '\r'));
        if requires_quotes {
            out.push('"');
            for ch in value.chars() {
                if ch == '"' {
                    out.push('"');
                    out.push('"');
                } else {
                    out.push(ch);
                }
            }
            out.push('"');
        } else {
            out.push_str(value);
        }
    }

    fn jsonl_record(columns: &[ExportColumn], row: &[Option<String>]) -> ExportResult<String> {
        let mut line = String::new();
        line.push('{');
        for (index, (column, cell)) in columns.iter().zip(row.iter()).enumerate() {
            if index > 0 {
                line.push(',');
            }
            line.push_str(&serde_json::to_string(&column.name)?);
            line.push(':');
            match cell {
                Some(value) => line.push_str(&json_cell_value(column, value)?),
                None => line.push_str("null"),
            }
        }
        line.push('}');
        line.push('\n');
        Ok(line)
    }

    fn json_cell_value(column: &ExportColumn, value: &str) -> ExportResult<String> {
        match snowflake_type_family(&column.snowflake_type) {
            SnowflakeTypeFamily::Boolean if matches!(value, "true" | "false") => {
                Ok(value.to_owned())
            }
            SnowflakeTypeFamily::Number if is_json_number(value) => Ok(value.to_owned()),
            SnowflakeTypeFamily::SemiStructured => {
                // Snowflake returns VARIANT/OBJECT/ARRAY cells as already-compact
                // JSON text. Round-tripping through `serde_json::Value` would
                // silently corrupt it: without the `arbitrary_precision` feature an
                // integer beyond u64 (a `NUMBER(38,0)` is routine) collapses to f64
                // (e.g. `99999999999999999999` -> `1e20`), and without
                // `preserve_order` object keys are re-sorted. Validate that the cell
                // is well-formed JSON, then emit the source bytes verbatim.
                serde_json::from_str::<serde::de::IgnoredAny>(value)?;
                Ok(value.to_owned())
            }
            _ => serde_json::to_string(value).map_err(ExportError::from),
        }
    }

    fn schema_hash(columns: &[ExportColumn]) -> ExportResult<String> {
        Ok(blake3_hex(serde_json::to_string(columns)?.as_bytes()))
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SnowflakeTypeFamily {
        Boolean,
        Number,
        SemiStructured,
        Other,
    }

    fn snowflake_type_family(snowflake_type: &str) -> SnowflakeTypeFamily {
        match snowflake_type.to_ascii_uppercase().as_str() {
            "BOOLEAN" | "BOOL" => SnowflakeTypeFamily::Boolean,
            "NUMBER" | "DECIMAL" | "NUMERIC" | "INT" | "INTEGER" | "BIGINT" | "SMALLINT"
            | "TINYINT" | "BYTEINT" | "FLOAT" | "FLOAT4" | "FLOAT8" | "DOUBLE"
            | "DOUBLE PRECISION" | "REAL" => SnowflakeTypeFamily::Number,
            "VARIANT" | "OBJECT" | "ARRAY" => SnowflakeTypeFamily::SemiStructured,
            _ => SnowflakeTypeFamily::Other,
        }
    }

    fn is_json_number(value: &str) -> bool {
        serde_json::from_str::<serde_json::Number>(value).is_ok()
    }
}

#[cfg(feature = "export")]
pub use local::{
    export_csv, export_jsonl, write_csv_stream, write_jsonl_stream, AddressingSink, ExportByteSink,
    ExportColumn, LocalExportArtifact, LocalExportInput, ResultPartition,
};

/// Convenient re-exports for callers.
pub mod prelude {
    pub use super::{
        ContentAddress, CopyCompression, CopyIntoOptions, CopyIntoPlan, CopySource, ExportError,
        ExportFormat, ExportLogEvent, ExportReceipt, ExportReceiptKind, ExportResult,
        COPY_INTO_PLAN_CONTRACT_ID, EXPORT_LOG_CONTRACT_ID, EXPORT_RECEIPT_CONTRACT_ID,
        LOCAL_BACKENDS_ENABLED, VERSION,
    };

    #[cfg(feature = "export")]
    pub use super::{
        export_csv, export_jsonl, write_csv_stream, write_jsonl_stream, AddressingSink,
        ExportByteSink, ExportColumn, LocalExportArtifact, LocalExportInput, ResultPartition,
    };
}

fn copy_location_sql(location: &str) -> ExportResult<String> {
    let trimmed = location.trim();
    if trimmed.is_empty() || !trimmed.starts_with('@') {
        return Err(ExportError::InvalidCopyLocation {
            location: location.to_owned(),
            reason: "location must be a Snowflake stage URI starting with @".to_owned(),
        });
    }
    if trimmed != location {
        return Err(ExportError::InvalidCopyLocation {
            location: location.to_owned(),
            reason: "leading or trailing whitespace is not allowed".to_owned(),
        });
    }
    if location.len() == 1 {
        return Err(ExportError::InvalidCopyLocation {
            location: location.to_owned(),
            reason: "location must name a stage or stage path after @".to_owned(),
        });
    }
    if franken_snowflake_core::redact::contains_secret(location) {
        return Err(ExportError::InvalidCopyLocation {
            location: redact_to_owned(location),
            reason: "location appears to contain a secret-shaped token".to_owned(),
        });
    }
    if !location.bytes().all(is_copy_location_byte) {
        return Err(ExportError::InvalidCopyLocation {
            location: location.to_owned(),
            reason: "location contains characters outside the safe stage URI allowlist".to_owned(),
        });
    }
    if location.contains("--") {
        return Err(ExportError::InvalidCopyLocation {
            location: location.to_owned(),
            reason: "location must not contain SQL comment markers".to_owned(),
        });
    }
    Ok(location.to_owned())
}

fn is_copy_location_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'@' | b'~' | b'%' | b'_' | b'/' | b'.' | b'-' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'
    )
}

fn validate_single_statement_sql(sql: &str) -> ExportResult<()> {
    let trimmed = sql.trim();
    if trimmed.is_empty() {
        return Err(ExportError::UnsafeCopySource {
            reason: "source query is empty".to_owned(),
        });
    }
    if trimmed.contains(';') {
        return Err(ExportError::UnsafeCopySource {
            reason: "source query must be one statement without semicolons".to_owned(),
        });
    }
    if !starts_with_keyword(trimmed, "select") && !starts_with_keyword(trimmed, "with") {
        return Err(ExportError::UnsafeCopySource {
            reason: "source query must begin with SELECT or WITH".to_owned(),
        });
    }
    validate_wrapped_copy_source_sql(trimmed)?;
    Ok(())
}

fn validate_wrapped_copy_source_sql(sql: &str) -> ExportResult<()> {
    let mut paren_depth = 0i32;
    let mut chars = sql.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        match ch {
            '\'' => scan_single_quoted_sql_string(&mut chars)?,
            '"' => scan_double_quoted_sql_identifier(&mut chars)?,
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => {
                paren_depth -= 1;
                if paren_depth < 0 {
                    return Err(ExportError::UnsafeCopySource {
                        reason: "source query closes the COPY INTO wrapper".to_owned(),
                    });
                }
            }
            '-' if matches!(chars.peek(), Some((_, '-'))) => {
                return Err(ExportError::UnsafeCopySource {
                    reason: "source query must not contain SQL comments".to_owned(),
                });
            }
            '/' if matches!(chars.peek(), Some((_, '*'))) => {
                return Err(ExportError::UnsafeCopySource {
                    reason: "source query must not contain SQL comments".to_owned(),
                });
            }
            _ => {}
        }
    }
    if paren_depth != 0 {
        return Err(ExportError::UnsafeCopySource {
            reason: "source query has unbalanced parentheses".to_owned(),
        });
    }
    Ok(())
}

fn scan_single_quoted_sql_string<I>(chars: &mut std::iter::Peekable<I>) -> ExportResult<()>
where
    I: Iterator<Item = (usize, char)>,
{
    while let Some((_, ch)) = chars.next() {
        if ch == '\\' {
            if chars.next().is_none() {
                break;
            }
            continue;
        }
        if ch == '\'' {
            if matches!(chars.peek(), Some((_, '\''))) {
                chars.next();
            } else {
                return Ok(());
            }
        }
    }
    Err(ExportError::UnsafeCopySource {
        reason: "source query has an unterminated string literal".to_owned(),
    })
}

fn scan_double_quoted_sql_identifier<I>(chars: &mut std::iter::Peekable<I>) -> ExportResult<()>
where
    I: Iterator<Item = (usize, char)>,
{
    while let Some((_, ch)) = chars.next() {
        if ch == '"' {
            if matches!(chars.peek(), Some((_, '"'))) {
                chars.next();
            } else {
                return Ok(());
            }
        }
    }
    Err(ExportError::UnsafeCopySource {
        reason: "source query has an unterminated quoted identifier".to_owned(),
    })
}

fn starts_with_keyword(input: &str, keyword: &str) -> bool {
    if input.len() < keyword.len() {
        return false;
    }
    let (head, rest) = input.split_at(keyword.len());
    if !head.eq_ignore_ascii_case(keyword) {
        return false;
    }
    match rest.chars().next() {
        Some(ch) => ch.is_ascii_whitespace() || ch == '(',
        None => true,
    }
}

fn validate_result_scan_query_id(query_id: &str) -> ExportResult<()> {
    if query_id.trim().is_empty() {
        return Err(ExportError::UnsafeCopySource {
            reason: "RESULT_SCAN query id is empty".to_owned(),
        });
    }
    if query_id.trim() != query_id {
        return Err(ExportError::UnsafeCopySource {
            reason: "RESULT_SCAN query id must not contain leading or trailing whitespace"
                .to_owned(),
        });
    }
    if franken_snowflake_core::redact::contains_secret(query_id) {
        return Err(ExportError::UnsafeCopySource {
            reason: "RESULT_SCAN query id appears to contain a secret-shaped token".to_owned(),
        });
    }
    if !query_id.bytes().all(is_result_scan_query_id_byte) {
        return Err(ExportError::UnsafeCopySource {
            reason: "RESULT_SCAN query id contains characters outside the safe allowlist"
                .to_owned(),
        });
    }
    Ok(())
}

fn is_result_scan_query_id_byte(byte: u8) -> bool {
    matches!(byte, b'-' | b'_' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

fn sql_string_literal(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('\'');
    for ch in input.chars() {
        match ch {
            '\'' => {
                out.push('\'');
                out.push('\'');
            }
            '\\' => {
                out.push('\\');
                out.push('\\');
            }
            _ => out.push(ch),
        }
    }
    out.push('\'');
    out
}

fn redact_to_owned(input: &str) -> String {
    match redact(input) {
        Cow::Borrowed(value) => value.to_owned(),
        Cow::Owned(value) => value,
    }
}

fn blake3_hex(payload: &[u8]) -> String {
    blake3::hash(payload).to_hex().to_string()
}

fn usize_to_u64(value: usize) -> u64 {
    value as u64
}

#[cfg(test)]
mod tests {
    use super::local::*;
    use super::*;

    fn fixture_input() -> LocalExportInput {
        LocalExportInput::new(
            vec![
                ExportColumn::new("id", "NUMBER").nullable(false),
                ExportColumn::new("name", "TEXT"),
                ExportColumn::new("active", "BOOLEAN"),
                ExportColumn::new("payload", "VARIANT"),
            ],
            vec![
                ResultPartition::new(
                    0,
                    vec![
                        vec![
                            Some("1".to_owned()),
                            Some("Ada".to_owned()),
                            Some("true".to_owned()),
                            Some("{\"rank\":1}".to_owned()),
                        ],
                        vec![
                            Some("2".to_owned()),
                            Some("Grace, Hopper".to_owned()),
                            Some("false".to_owned()),
                            None,
                        ],
                    ],
                ),
                ResultPartition::new(
                    1,
                    vec![vec![
                        Some("3".to_owned()),
                        Some("quote \"inside\"".to_owned()),
                        Some("true".to_owned()),
                        Some("[1,2]".to_owned()),
                    ]],
                ),
            ],
        )
    }

    #[test]
    fn copy_into_plan_renders_deterministic_csv_sql() {
        let plan = CopyIntoPlan::new(
            "@exports/run_001",
            CopySource::Query {
                sql: "select id, name from analytics.people".to_owned(),
            },
        );
        let sql = plan.to_sql();
        assert_eq!(
            sql.as_deref(),
            Ok(
                "COPY INTO @exports/run_001 FROM (select id, name from analytics.people) FILE_FORMAT = (TYPE = CSV COMPRESSION = NONE FIELD_OPTIONALLY_ENCLOSED_BY = '\"' NULL_IF = () EMPTY_FIELD_AS_NULL = FALSE) HEADER = TRUE OVERWRITE = FALSE SINGLE = FALSE MAX_FILE_SIZE = 16777216"
            )
        );
        let address = plan.plan_address();
        assert!(address.is_ok());
        assert_eq!(
            address.map(|value| value.algorithm),
            Ok("blake3".to_owned())
        );
    }

    #[test]
    fn copy_into_plan_refuses_multistatement_sql() {
        let plan = CopyIntoPlan::new(
            "@exports/run_001",
            CopySource::Query {
                sql: "select 1; drop table t".to_owned(),
            },
        );
        assert!(matches!(
            plan.to_sql(),
            Err(ExportError::UnsafeCopySource { .. })
        ));
    }

    #[test]
    fn copy_into_plan_refuses_injectable_stage_locations() {
        let source = CopySource::Query {
            sql: "select id from analytics.people".to_owned(),
        };
        for location in [
            "@evil FROM (SELECT * FROM SENSITIVE) FILE_FORMAT=(TYPE=CSV) --",
            "@evil/path'quote",
            "@evil/path;drop",
            "@evil/path(comment)",
            "@evil/path--comment",
        ] {
            let plan = CopyIntoPlan::new(location, source.clone());
            assert!(matches!(
                plan.to_sql(),
                Err(ExportError::InvalidCopyLocation { .. })
            ));
        }
    }

    #[test]
    fn copy_into_plan_refuses_source_breakout_attempts() {
        for sql in [
            "select 1) FILE_FORMAT=(TYPE=CSV) --",
            "select (1",
            "select 1 -- hide wrapper",
            "select 1 /* hide wrapper */",
            "select 'safe\\'s fine') FILE_FORMAT=(TYPE=CSV)",
        ] {
            let plan = CopyIntoPlan::new(
                "@exports/run_001",
                CopySource::Query {
                    sql: sql.to_owned(),
                },
            );
            assert!(matches!(
                plan.to_sql(),
                Err(ExportError::UnsafeCopySource { .. })
            ));
        }
    }

    #[test]
    fn copy_into_plan_handles_snowflake_backslash_escaped_source_literals() {
        // Snowflake string literal escapes checked 2026-06-25:
        // https://docs.snowflake.com/en/sql-reference/data-types-text
        let plan = CopyIntoPlan::new(
            "@exports/run_001",
            CopySource::Query {
                sql: "select 'it\\'s fine', 'path\\\\file'".to_owned(),
            },
        );

        assert!(plan.to_sql().is_ok());
    }

    #[test]
    fn copy_into_plan_keeps_backslash_escaped_breakout_inside_source_literal() {
        let plan = CopyIntoPlan::new(
            "@exports/run_001",
            CopySource::Query {
                sql: "select 'safe\\') FILE_FORMAT=(TYPE=CSV) --'".to_owned(),
            },
        );

        assert!(plan.to_sql().is_ok());
    }

    #[test]
    fn copy_into_plan_refuses_trailing_backslash_source_literal() {
        let plan = CopyIntoPlan::new(
            "@exports/run_001",
            CopySource::Query {
                sql: "select 'unterminated\\".to_owned(),
            },
        );

        assert!(matches!(
            plan.to_sql(),
            Err(ExportError::UnsafeCopySource { .. })
        ));
    }

    #[test]
    fn copy_into_result_scan_refuses_source_id_injection_attempts() {
        for query_id in [
            "01bad) FILE_FORMAT=(TYPE=CSV)--",
            " 01bcaafe-0000 ",
            "01bcaafe.0000",
            "sfpat_resultScanCredential001",
            "01bcaafe\\",
        ] {
            let plan = CopyIntoPlan::new(
                "@exports/run_001",
                CopySource::ResultScan {
                    query_id: query_id.to_owned(),
                },
            );
            assert!(matches!(
                plan.to_sql(),
                Err(ExportError::UnsafeCopySource { .. })
            ));
        }
    }

    #[test]
    fn copy_into_plan_allows_comment_markers_inside_string_literals() {
        let plan = CopyIntoPlan::new(
            "@exports/run_001",
            CopySource::Query {
                sql: "select '--not-comment', '/*not-comment*/'".to_owned(),
            },
        );
        assert!(plan.to_sql().is_ok());
    }

    #[test]
    fn local_csv_export_has_golden_bytes_and_receipt() {
        let artifact = export_csv(&fixture_input(), "artifacts/people.csv", 1234);
        assert!(artifact.is_ok());
        let artifact = match artifact {
            Ok(value) => value,
            Err(error) => {
                assert_eq!(error.to_string(), "");
                return;
            }
        };
        assert_eq!(
            String::from_utf8_lossy(&artifact.bytes),
            "id,name,active,payload\n1,Ada,true,\"{\"\"rank\"\":1}\"\n2,\"Grace, Hopper\",false,\n3,\"quote \"\"inside\"\"\",true,\"[1,2]\"\n"
        );
        assert_eq!(artifact.receipt.row_count, Some(3));
        assert_eq!(artifact.receipt.content_address.byte_len, 108);
        assert!(artifact
            .receipt
            .content_address
            .verify(&artifact.bytes)
            .is_ok());
        assert!(artifact.log_line.contains("\"record_hash\""));
    }

    #[test]
    fn local_jsonl_export_has_golden_bytes_and_receipt() {
        let artifact = export_jsonl(&fixture_input(), "artifacts/people.jsonl", 1234);
        assert!(artifact.is_ok());
        let artifact = match artifact {
            Ok(value) => value,
            Err(error) => {
                assert_eq!(error.to_string(), "");
                return;
            }
        };
        assert_eq!(
            String::from_utf8_lossy(&artifact.bytes),
            "{\"id\":1,\"name\":\"Ada\",\"active\":true,\"payload\":{\"rank\":1}}\n{\"id\":2,\"name\":\"Grace, Hopper\",\"active\":false,\"payload\":null}\n{\"id\":3,\"name\":\"quote \\\"inside\\\"\",\"active\":true,\"payload\":[1,2]}\n"
        );
        assert_eq!(artifact.receipt.row_count, Some(3));
        assert!(artifact
            .receipt
            .content_address
            .verify(&artifact.bytes)
            .is_ok());
    }

    #[test]
    fn jsonl_variant_cells_preserve_key_order_and_large_integers() {
        // VARIANT/OBJECT/ARRAY cells must be emitted verbatim. Round-tripping
        // through `serde_json::Value` (no `arbitrary_precision`/`preserve_order`)
        // would reorder the keys and collapse the `NUMBER(38,0)` `big` value
        // (> u64) to `1e20`. Emit-raw must keep the source bytes intact.
        let raw = "{\"z\":1,\"a\":2,\"big\":99999999999999999999,\"dec\":12345678901234567.89}";
        let input = LocalExportInput::new(
            vec![ExportColumn::new("v", "VARIANT")],
            vec![ResultPartition::new(0, vec![vec![Some(raw.to_owned())]])],
        );
        let artifact = export_jsonl(&input, "artifacts/variant.jsonl", 1).expect("export");
        let line = String::from_utf8(artifact.bytes).expect("utf8 export bytes");
        assert_eq!(line, format!("{{\"v\":{raw}}}\n"));
    }

    #[test]
    fn jsonl_variant_cell_rejects_malformed_json() {
        let input = LocalExportInput::new(
            vec![ExportColumn::new("v", "VARIANT")],
            vec![ResultPartition::new(
                0,
                vec![vec![Some("{not valid json".to_owned())]],
            )],
        );
        assert!(export_jsonl(&input, "artifacts/bad.jsonl", 1).is_err());
    }

    #[test]
    fn streaming_writer_does_not_buffer_full_result() {
        let input = fixture_input();
        let mut sink = AddressingSink::new(Vec::new());
        let row_count = write_csv_stream(&input.columns, input.partitions.iter(), &mut sink);
        assert_eq!(row_count, Ok(3));
        assert!(sink.write_count() >= 4);
        assert!(sink.max_chunk_len() < 64);
        let (bytes, address) = sink.finish();
        assert!(address.verify(&bytes).is_ok());
    }

    #[test]
    fn content_address_verifies_length_and_digest() {
        let payload = b"id\n1\n";
        let address = ContentAddress::blake3(payload);
        assert!(address.verify(payload).is_ok());
        assert!(matches!(
            address.verify(b"id\n2\n"),
            Err(ExportError::HashMismatch { .. })
        ));
        let mut wrong_len = address.clone();
        wrong_len.byte_len = 99;
        assert!(matches!(
            wrong_len.verify(payload),
            Err(ExportError::ByteLengthMismatch { .. })
        ));
    }

    #[test]
    fn export_feature_gate_reports_backend_availability() {
        assert_eq!(LOCAL_BACKENDS_ENABLED, cfg!(feature = "export"));
    }

    #[test]
    fn json_line_log_contains_record_hash() {
        let receipt = ExportReceipt::new(
            ExportReceiptKind::CopyIntoPlan,
            Some(ExportFormat::Csv),
            "@exports/run_001".to_owned(),
            ContentAddress::blake3(b"copy into"),
            None,
            None,
            Some(blake3_hex(b"copy into")),
            9,
            Vec::new(),
        );
        let line = ExportLogEvent::from_receipt(&receipt).and_then(|event| event.to_json_line());
        assert!(line.is_ok());
        let line = match line {
            Ok(value) => value,
            Err(error) => {
                assert_eq!(error.to_string(), "");
                return;
            }
        };
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"record_hash\""));
        assert!(line.contains("\"content_hash\""));
    }
}
