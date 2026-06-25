//! `franken-snowflake-cache` -- local repository contracts for connector state.
//!
//! This first slice defines the cache boundary and a no-account in-memory
//! backend. Default builds intentionally do **not** pull `fsqlite`,
//! `sqlmodel-*`, `fp-*`, or export/frame writer dependencies into the graph.
//! The FrankenSQLite/sqlmodel repository implementation is available through
//! the non-default `frankensqlite` feature.
//!
//! The crate owns durable metadata shapes: secret-free profiles, catalog
//! snapshots, dataset manifests, query plans, content-addressed receipts,
//! partition evidence, export records, replay bundles, and append-only audit
//! events.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::sync::Mutex;

pub use franken_snowflake_core::redact::SECRET_PREFIXES;
use serde::{Deserialize, Serialize};
#[cfg(feature = "frankensqlite")]
use sqlmodel_core::{Row, Value};
#[cfg(feature = "frankensqlite")]
use sqlmodel_frankensqlite::FrankenConnection;

/// Crate version string.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Result alias for repository operations.
pub type CacheResult<T> = Result<T, CacheError>;

/// The currently supported schema version for the repository contract.
pub const CURRENT_SCHEMA_VERSION: SchemaVersion = SchemaVersion(1);

/// Schema version tracked by explicit migrations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SchemaVersion(pub u32);

/// Local cache error vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CacheError {
    /// A repository record was not found.
    NotFound { entity: &'static str, id: String },
    /// Profile metadata looked like it contained a raw secret.
    SecretRefused {
        field: &'static str,
        reason: &'static str,
    },
    /// A content-addressed payload's recorded length did not match its bytes.
    ByteLengthMismatch {
        entity: &'static str,
        expected: u64,
        actual: u64,
    },
    /// A content-addressed payload's BLAKE3 digest did not match.
    HashMismatch {
        entity: &'static str,
        expected: String,
        actual: String,
    },
    /// A stored numeric value could not be represented by the local database.
    NumericOverflow { field: &'static str, value: u64 },
    /// A database row did not match the repository schema expected by this crate.
    InvalidRow {
        field: &'static str,
        message: String,
    },
    /// FrankenSQLite/sqlmodel driver failure.
    SqlModel { message: String },
    /// A migration or raw SQL fragment attempted to mutate the append-only audit table.
    AuditMutationRefused { statement: String },
    /// Serialized access wrapper observed a poisoned lock.
    PoisonedSerializedAccess,
}

impl fmt::Display for CacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { entity, id } => write!(f, "{entity} not found: {id}"),
            Self::SecretRefused { field, reason } => {
                write!(
                    f,
                    "secret-shaped profile metadata refused in {field}: {reason}"
                )
            }
            Self::ByteLengthMismatch {
                entity,
                expected,
                actual,
            } => write!(
                f,
                "{entity} byte length mismatch: expected {expected}, got {actual}"
            ),
            Self::HashMismatch {
                entity,
                expected,
                actual,
            } => write!(
                f,
                "{entity} hash mismatch: expected {expected}, got {actual}"
            ),
            Self::NumericOverflow { field, value } => {
                write!(f, "{field} value does not fit SQLite INTEGER: {value}")
            }
            Self::InvalidRow { field, message } => {
                write!(f, "invalid cache row {field}: {message}")
            }
            Self::SqlModel { message } => write!(f, "frankensqlite/sqlmodel error: {message}"),
            Self::AuditMutationRefused { statement } => {
                write!(
                    f,
                    "append-only query_audit_log mutation refused: {statement}"
                )
            }
            Self::PoisonedSerializedAccess => write!(f, "serialized cache access lock is poisoned"),
        }
    }
}

impl Error for CacheError {}

#[cfg(feature = "frankensqlite")]
impl From<sqlmodel_core::Error> for CacheError {
    fn from(value: sqlmodel_core::Error) -> Self {
        Self::SqlModel {
            message: value.to_string(),
        }
    }
}

/// Supported profile authentication lanes.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthLane {
    /// Programmatic access token lane.
    ProgrammaticAccessToken,
    /// Key-pair JWT lane.
    KeyPairJwt,
    /// OAuth bearer lane.
    OAuthBearer,
}

/// Secret reference kind. The cache stores references, never raw values.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRefKind {
    /// Environment variable name.
    Env,
    /// External secret-provider handle.
    Provider,
    /// No credential required for an offline/fixture profile.
    None,
}

/// A reference to a credential, not the credential itself.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialRef {
    /// Reference kind.
    pub kind: CredentialRefKind,
    /// Environment variable name or provider handle. Must not contain raw secret material.
    pub name: Option<String>,
}

impl fmt::Debug for CredentialRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialRef")
            .field("kind", &self.kind)
            .field("name", &self.name.as_ref().map(|_| "<redacted-reference>"))
            .finish()
    }
}

impl CredentialRef {
    /// A no-credential reference for offline/fixture profiles.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            kind: CredentialRefKind::None,
            name: None,
        }
    }

    /// Create an environment variable reference.
    #[must_use]
    pub fn env(name: impl Into<String>) -> Self {
        Self {
            kind: CredentialRefKind::Env,
            name: Some(name.into()),
        }
    }
}

/// Secret-free Snowflake profile metadata.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRecord {
    /// Stable local profile id.
    pub profile_id: String,
    /// Human-readable label.
    pub display_name: String,
    /// Optional redacted account locator.
    pub account_locator_redacted: Option<String>,
    /// Auth lane.
    pub auth_lane: AuthLane,
    /// Reference to the credential source, never the credential value.
    pub credential_ref: CredentialRef,
    /// Optional default database.
    pub default_database: Option<String>,
    /// Optional default schema.
    pub default_schema: Option<String>,
    /// Optional default warehouse.
    pub default_warehouse: Option<String>,
    /// Optional default role.
    pub default_role: Option<String>,
    /// Deterministic creation timestamp in tests.
    pub created_at_ms: u64,
    /// Deterministic update timestamp in tests.
    pub updated_at_ms: u64,
}

impl fmt::Debug for ProfileRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProfileRecord")
            .field("profile_id", &self.profile_id)
            .field("display_name", &self.display_name)
            .field("account_locator_redacted", &self.account_locator_redacted)
            .field("auth_lane", &self.auth_lane)
            .field("credential_ref", &self.credential_ref)
            .field("default_database", &self.default_database)
            .field("default_schema", &self.default_schema)
            .field("default_warehouse", &self.default_warehouse)
            .field("default_role", &self.default_role)
            .field("created_at_ms", &self.created_at_ms)
            .field("updated_at_ms", &self.updated_at_ms)
            .finish()
    }
}

impl ProfileRecord {
    /// Validate the no-secret invariant for profile metadata.
    pub fn validate_secret_free(&self) -> CacheResult<()> {
        if let Some(name) = &self.credential_ref.name {
            reject_secret_shape("credential_ref.name", name)?;
        }
        if let Some(account) = &self.account_locator_redacted {
            reject_secret_shape("account_locator_redacted", account)?;
        }
        Ok(())
    }
}

/// A byte-length-verified content address.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentAddress {
    /// Hash algorithm label, normally `blake3`.
    pub algorithm: String,
    /// Hex digest produced by the owning caller.
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

    /// Construct a BLAKE3 address from a caller-provided digest and payload.
    #[must_use]
    pub fn blake3_reference(digest_hex: impl Into<String>, payload: &[u8]) -> Self {
        let byte_len = usize_to_u64(payload.len());
        Self {
            algorithm: "blake3".to_owned(),
            digest_hex: digest_hex.into(),
            byte_len,
        }
    }

    /// Verify byte length and BLAKE3 digest against a canonical payload.
    pub fn verify(&self, entity: &'static str, payload: &[u8]) -> CacheResult<()> {
        let actual = usize_to_u64(payload.len());
        if self.byte_len != actual {
            return Err(CacheError::ByteLengthMismatch {
                entity,
                expected: self.byte_len,
                actual,
            });
        }
        if self.algorithm != "blake3" {
            // Fail closed: an unrecognized algorithm label must not bypass digest
            // verification. Previously the digest check was gated on
            // `algorithm == "blake3"`, so any other label (corruption, tampering,
            // or a future algorithm) silently passed after only the length check,
            // defeating content-address integrity on every insert path.
            return Err(CacheError::InvalidRow {
                field: entity,
                message: format!(
                    "unsupported content-address algorithm {:?}; only blake3 is verifiable",
                    self.algorithm
                ),
            });
        }
        let actual_hash = blake3_hex(payload);
        if self.digest_hex != actual_hash {
            return Err(CacheError::HashMismatch {
                entity,
                expected: self.digest_hex.clone(),
                actual: actual_hash,
            });
        }
        Ok(())
    }

    /// Validate that the address is internally well-formed without the addressed
    /// payload.
    ///
    /// Some addressed content lives at an external location — exports are written
    /// to object storage or local files — so the cache never holds the bytes and
    /// cannot recompute the digest. This checks the address shape and fails closed
    /// on an unsupported algorithm or an empty digest, mirroring the fail-closed
    /// policy of [`ContentAddress::verify`].
    pub fn verify_well_formed(&self, entity: &'static str) -> CacheResult<()> {
        if self.algorithm != "blake3" {
            return Err(CacheError::InvalidRow {
                field: entity,
                message: format!(
                    "unsupported content-address algorithm {:?}; only blake3 is verifiable",
                    self.algorithm
                ),
            });
        }
        if self.digest_hex.is_empty() {
            return Err(CacheError::InvalidRow {
                field: entity,
                message: "content-address digest is empty".to_owned(),
            });
        }
        Ok(())
    }
}

/// Canonical payload plus its content address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedPayload {
    /// Canonical JSON or other canonical UTF-8 payload.
    pub canonical: String,
    /// Content address and byte length.
    pub address: ContentAddress,
}

impl VerifiedPayload {
    /// Validate the recorded byte length.
    pub fn verify(&self, entity: &'static str) -> CacheResult<()> {
        self.address.verify(entity, self.canonical.as_bytes())
    }
}

/// Catalog snapshot stored by content address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSnapshotRecord {
    pub snapshot_id: String,
    pub profile_id: String,
    pub source_kind: String,
    pub database_name: Option<String>,
    pub schema_name: Option<String>,
    pub captured_at_ms: u64,
    pub payload: VerifiedPayload,
}

/// Dataset manifest cache record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetManifestRecord {
    pub dataset_id: String,
    pub profile_id: String,
    pub snapshot_id: Option<String>,
    pub database_name: String,
    pub schema_name: String,
    pub object_name: String,
    pub rights_class: String,
    pub default_limit: u64,
    pub max_rows_without_export: u64,
    pub manifest: VerifiedPayload,
    pub created_at_ms: u64,
}

/// Query plan cache record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryPlanRecord {
    pub plan_id: String,
    pub profile_id: String,
    pub dataset_id: Option<String>,
    pub mode: String,
    pub normalized_sql_hash: String,
    pub normalized_sql_redacted: String,
    pub bindings_shape_json: String,
    pub safety_class: String,
    pub estimated_row_limit: Option<u64>,
    pub requires_export: bool,
    pub created_at_ms: u64,
}

/// Query receipt record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryReceiptRecord {
    pub receipt_id: String,
    pub plan_id: String,
    pub profile_id: String,
    pub command_id: String,
    pub trace_id: String,
    pub outcome_kind: String,
    pub receipt_state: String,
    pub statement_handle: Option<String>,
    pub snowflake_query_id: Option<String>,
    pub request_id: Option<String>,
    pub row_count: Option<u64>,
    pub receipt: VerifiedPayload,
    pub created_at_ms: u64,
}

impl QueryReceiptRecord {
    /// Whether this receipt can seed a RESULT_SCAN lookup.
    #[must_use]
    pub fn is_successful_result_scan_candidate(&self) -> bool {
        self.outcome_kind == "ok" && self.snowflake_query_id.is_some()
    }
}

/// Per-partition metadata for a receipt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionMetadataRecord {
    pub receipt_id: String,
    pub partition_index: u32,
    pub row_count: u64,
    pub compressed_bytes: Option<u64>,
    pub uncompressed_bytes: Option<u64>,
    pub payload_hash: Option<String>,
    pub content_encoding: Option<String>,
}

/// Export kind recorded by the cache. Writers live outside this crate.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportKind {
    /// Server-side Snowflake COPY INTO location.
    CopyInto,
    /// Local CSV writer.
    LocalCsv,
    /// Local JSONL writer.
    LocalJsonl,
}

/// Content-addressed export record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRecord {
    pub export_id: String,
    pub receipt_id: String,
    pub export_kind: ExportKind,
    pub target_uri_redacted: String,
    pub content_address: ContentAddress,
    pub row_count: Option<u64>,
    pub created_at_ms: u64,
}

/// Cost, byte, and row-count history row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostHistoryRecord {
    pub history_id: String,
    pub profile_id: String,
    pub plan_id: Option<String>,
    pub receipt_id: Option<String>,
    pub row_count: Option<u64>,
    pub compressed_bytes: Option<u64>,
    pub uncompressed_bytes: Option<u64>,
    pub cost_vector_json: String,
    pub created_at_ms: u64,
}

/// Offline replay bundle pointer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineReplayBundleRecord {
    pub bundle_id: String,
    pub source_receipt_id: Option<String>,
    pub snapshot_id: Option<String>,
    pub artifact_dir: String,
    pub manifest: VerifiedPayload,
    pub created_at_ms: u64,
}

/// Append-only audit event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEventRecord {
    pub event_id: String,
    pub receipt_id: Option<String>,
    pub command_id: String,
    pub trace_id: String,
    pub event_kind: String,
    pub event_json: String,
    pub created_at_ms: u64,
}

/// Cache backend contract shared by production and no-account tests.
pub trait CacheBackend {
    fn schema_version(&self) -> SchemaVersion;

    fn upsert_profile(&self, record: ProfileRecord) -> CacheResult<()>;
    fn profile(&self, profile_id: &str) -> CacheResult<Option<ProfileRecord>>;
    fn profiles(&self) -> CacheResult<Vec<ProfileRecord>>;

    fn insert_catalog_snapshot(&self, record: CatalogSnapshotRecord) -> CacheResult<()>;
    fn catalog_snapshot(&self, snapshot_id: &str) -> CacheResult<Option<CatalogSnapshotRecord>>;

    fn upsert_dataset_manifest(&self, record: DatasetManifestRecord) -> CacheResult<()>;
    fn dataset_manifest(&self, dataset_id: &str) -> CacheResult<Option<DatasetManifestRecord>>;

    fn upsert_query_plan(&self, record: QueryPlanRecord) -> CacheResult<()>;
    fn query_plan(&self, plan_id: &str) -> CacheResult<Option<QueryPlanRecord>>;

    fn append_query_receipt(&self, record: QueryReceiptRecord) -> CacheResult<()>;
    fn latest_successful_receipt(&self, plan_id: &str) -> CacheResult<Option<QueryReceiptRecord>>;
    fn receipt_by_snowflake_query_id(
        &self,
        profile_id: &str,
        snowflake_query_id: &str,
    ) -> CacheResult<Option<QueryReceiptRecord>>;

    fn append_partition_metadata(&self, record: PartitionMetadataRecord) -> CacheResult<()>;
    fn partitions_for_receipt(&self, receipt_id: &str)
    -> CacheResult<Vec<PartitionMetadataRecord>>;

    fn append_export(&self, record: ExportRecord) -> CacheResult<()>;
    fn exports_for_receipt(&self, receipt_id: &str) -> CacheResult<Vec<ExportRecord>>;

    fn append_cost_history(&self, record: CostHistoryRecord) -> CacheResult<()>;
    fn cost_history_for_profile(&self, profile_id: &str) -> CacheResult<Vec<CostHistoryRecord>>;

    fn append_replay_bundle(&self, record: OfflineReplayBundleRecord) -> CacheResult<()>;

    fn append_audit_event(&self, record: AuditEventRecord) -> CacheResult<()>;
    fn audit_events(&self) -> CacheResult<Vec<AuditEventRecord>>;
}

/// Dependency-light in-memory backend for unit tests and offline harnesses.
#[derive(Debug)]
pub struct InMemoryCache {
    schema_version: SchemaVersion,
    profiles: RefCell<BTreeMap<String, ProfileRecord>>,
    catalog_snapshots: RefCell<BTreeMap<String, CatalogSnapshotRecord>>,
    dataset_manifests: RefCell<BTreeMap<String, DatasetManifestRecord>>,
    query_plans: RefCell<BTreeMap<String, QueryPlanRecord>>,
    query_receipts: RefCell<BTreeMap<String, QueryReceiptRecord>>,
    partition_metadata: RefCell<BTreeMap<(String, u32), PartitionMetadataRecord>>,
    exports: RefCell<BTreeMap<String, ExportRecord>>,
    cost_history: RefCell<BTreeMap<String, CostHistoryRecord>>,
    replay_bundles: RefCell<BTreeMap<String, OfflineReplayBundleRecord>>,
    audit_events: RefCell<BTreeMap<String, AuditEventRecord>>,
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCache {
    /// Create an empty in-memory cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            profiles: RefCell::new(BTreeMap::new()),
            catalog_snapshots: RefCell::new(BTreeMap::new()),
            dataset_manifests: RefCell::new(BTreeMap::new()),
            query_plans: RefCell::new(BTreeMap::new()),
            query_receipts: RefCell::new(BTreeMap::new()),
            partition_metadata: RefCell::new(BTreeMap::new()),
            exports: RefCell::new(BTreeMap::new()),
            cost_history: RefCell::new(BTreeMap::new()),
            replay_bundles: RefCell::new(BTreeMap::new()),
            audit_events: RefCell::new(BTreeMap::new()),
        }
    }
}

impl CacheBackend for InMemoryCache {
    fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    fn upsert_profile(&self, record: ProfileRecord) -> CacheResult<()> {
        record.validate_secret_free()?;
        self.profiles
            .borrow_mut()
            .insert(record.profile_id.clone(), record);
        Ok(())
    }

    fn profile(&self, profile_id: &str) -> CacheResult<Option<ProfileRecord>> {
        Ok(self.profiles.borrow().get(profile_id).cloned())
    }

    fn profiles(&self) -> CacheResult<Vec<ProfileRecord>> {
        Ok(self.profiles.borrow().values().cloned().collect())
    }

    fn insert_catalog_snapshot(&self, record: CatalogSnapshotRecord) -> CacheResult<()> {
        record.payload.verify("catalog_snapshot")?;
        // First-write-wins, mirroring the SQLite backend's `INSERT OR IGNORE`.
        // `BTreeMap::insert` is last-write-wins, which silently overwrote a
        // snapshot that production would have preserved — a contract drift that
        // made the in-memory test backend model different behavior than the
        // FrankenSQLite backend on any duplicate primary key.
        self.catalog_snapshots
            .borrow_mut()
            .entry(record.snapshot_id.clone())
            .or_insert(record);
        Ok(())
    }

    fn catalog_snapshot(&self, snapshot_id: &str) -> CacheResult<Option<CatalogSnapshotRecord>> {
        Ok(self.catalog_snapshots.borrow().get(snapshot_id).cloned())
    }

    fn upsert_dataset_manifest(&self, record: DatasetManifestRecord) -> CacheResult<()> {
        record.manifest.verify("dataset_manifest")?;
        self.dataset_manifests
            .borrow_mut()
            .insert(record.dataset_id.clone(), record);
        Ok(())
    }

    fn dataset_manifest(&self, dataset_id: &str) -> CacheResult<Option<DatasetManifestRecord>> {
        Ok(self.dataset_manifests.borrow().get(dataset_id).cloned())
    }

    fn upsert_query_plan(&self, record: QueryPlanRecord) -> CacheResult<()> {
        self.query_plans
            .borrow_mut()
            .insert(record.plan_id.clone(), record);
        Ok(())
    }

    fn query_plan(&self, plan_id: &str) -> CacheResult<Option<QueryPlanRecord>> {
        Ok(self.query_plans.borrow().get(plan_id).cloned())
    }

    fn append_query_receipt(&self, record: QueryReceiptRecord) -> CacheResult<()> {
        record.receipt.verify("query_receipt")?;
        // Append-only ledger: a duplicate receipt_id keeps the first write, like
        // the SQLite `INSERT OR IGNORE`. Overwriting here let a later state row
        // (e.g. an `error` re-append under a reused id) clobber the committed
        // receipt in tests while production silently ignored it.
        self.query_receipts
            .borrow_mut()
            .entry(record.receipt_id.clone())
            .or_insert(record);
        Ok(())
    }

    fn latest_successful_receipt(&self, plan_id: &str) -> CacheResult<Option<QueryReceiptRecord>> {
        let latest = self
            .query_receipts
            .borrow()
            .values()
            .filter(|receipt| receipt.plan_id == plan_id && receipt.outcome_kind == "ok")
            .max_by_key(|receipt| receipt.created_at_ms)
            .cloned();
        Ok(latest)
    }

    fn receipt_by_snowflake_query_id(
        &self,
        profile_id: &str,
        snowflake_query_id: &str,
    ) -> CacheResult<Option<QueryReceiptRecord>> {
        // Match the SQLite backend's `ORDER BY created_at_ms DESC LIMIT 1`: a
        // snowflake_query_id is not unique across receipt rows, so selecting the
        // newest matching receipt is the contract. `Iterator::find` returned the
        // lexicographically-first receipt_id instead, so the two backends could
        // hand back different receipts for the same lookup.
        let receipt = self
            .query_receipts
            .borrow()
            .values()
            .filter(|receipt| {
                receipt.profile_id == profile_id
                    && receipt.snowflake_query_id.as_deref() == Some(snowflake_query_id)
            })
            .max_by_key(|receipt| receipt.created_at_ms)
            .cloned();
        Ok(receipt)
    }

    fn append_partition_metadata(&self, record: PartitionMetadataRecord) -> CacheResult<()> {
        let key = (record.receipt_id.clone(), record.partition_index);
        self.partition_metadata.borrow_mut().insert(key, record);
        Ok(())
    }

    fn partitions_for_receipt(
        &self,
        receipt_id: &str,
    ) -> CacheResult<Vec<PartitionMetadataRecord>> {
        Ok(self
            .partition_metadata
            .borrow()
            .values()
            .filter(|partition| partition.receipt_id == receipt_id)
            .cloned()
            .collect())
    }

    fn append_export(&self, record: ExportRecord) -> CacheResult<()> {
        // The export content lives at an external target (object storage / local
        // file), so the cache cannot recompute its digest; only the address shape
        // can be checked here. Verifying against `target_uri_redacted` was wrong —
        // that string is the destination, not the addressed content — and rejected
        // every real export while the SQLite backend accepted it.
        record.content_address.verify_well_formed("export_record")?;
        // First-write-wins, mirroring the SQLite `INSERT OR IGNORE`.
        self.exports
            .borrow_mut()
            .entry(record.export_id.clone())
            .or_insert(record);
        Ok(())
    }

    fn exports_for_receipt(&self, receipt_id: &str) -> CacheResult<Vec<ExportRecord>> {
        // Mirror the SQLite `ORDER BY created_at_ms DESC`: callers expect the most
        // recent export first. Iterating the BTreeMap returned export_id order, so
        // the in-memory backend handed back a different sequence than production.
        let mut exports: Vec<ExportRecord> = self
            .exports
            .borrow()
            .values()
            .filter(|export| export.receipt_id == receipt_id)
            .cloned()
            .collect();
        exports.sort_by(|a, b| {
            b.created_at_ms
                .cmp(&a.created_at_ms)
                .then_with(|| a.export_id.cmp(&b.export_id))
        });
        Ok(exports)
    }

    fn append_cost_history(&self, record: CostHistoryRecord) -> CacheResult<()> {
        // First-write-wins, mirroring the SQLite `INSERT OR IGNORE`.
        self.cost_history
            .borrow_mut()
            .entry(record.history_id.clone())
            .or_insert(record);
        Ok(())
    }

    fn cost_history_for_profile(&self, profile_id: &str) -> CacheResult<Vec<CostHistoryRecord>> {
        // Mirror the SQLite `ORDER BY created_at_ms DESC` (newest cost row first).
        let mut history: Vec<CostHistoryRecord> = self
            .cost_history
            .borrow()
            .values()
            .filter(|record| record.profile_id == profile_id)
            .cloned()
            .collect();
        history.sort_by(|a, b| {
            b.created_at_ms
                .cmp(&a.created_at_ms)
                .then_with(|| a.history_id.cmp(&b.history_id))
        });
        Ok(history)
    }

    fn append_replay_bundle(&self, record: OfflineReplayBundleRecord) -> CacheResult<()> {
        record.manifest.verify("offline_replay_bundle")?;
        // First-write-wins, mirroring the SQLite `INSERT OR IGNORE`.
        self.replay_bundles
            .borrow_mut()
            .entry(record.bundle_id.clone())
            .or_insert(record);
        Ok(())
    }

    fn append_audit_event(&self, record: AuditEventRecord) -> CacheResult<()> {
        // The audit log is append-only and immutable (the SQLite path enforces it
        // with `INSERT OR IGNORE` plus `lint_append_only_audit_sql`). Overwriting
        // an event with a reused event_id would silently mutate a record the rest
        // of the system treats as tamper-evident, so keep the first write.
        self.audit_events
            .borrow_mut()
            .entry(record.event_id.clone())
            .or_insert(record);
        Ok(())
    }

    fn audit_events(&self) -> CacheResult<Vec<AuditEventRecord>> {
        // Mirror the SQLite `ORDER BY created_at_ms, event_id`: the audit log is a
        // chronological ledger and consumers read it in time order. The BTreeMap
        // iterated by event_id alone, so an event written later but with a smaller
        // event_id would have surfaced out of chronological order in tests only.
        let mut events: Vec<AuditEventRecord> =
            self.audit_events.borrow().values().cloned().collect();
        events.sort_by(|a, b| {
            a.created_at_ms
                .cmp(&b.created_at_ms)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });
        Ok(events)
    }
}

/// FrankenSQLite-backed local cache using the `sqlmodel-frankensqlite` driver.
#[cfg(feature = "frankensqlite")]
pub struct FrankenSqliteCache {
    conn: FrankenConnection,
}

#[cfg(feature = "frankensqlite")]
impl fmt::Debug for FrankenSqliteCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrankenSqliteCache")
            .field("driver", &"sqlmodel-frankensqlite")
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "frankensqlite")]
impl FrankenSqliteCache {
    /// Open an in-memory FrankenSQLite cache and apply migrations.
    pub fn open_memory() -> CacheResult<Self> {
        Self::from_connection(FrankenConnection::open_memory()?)
    }

    /// Open a file-backed FrankenSQLite cache and apply migrations.
    pub fn open_file(path: impl Into<String>) -> CacheResult<Self> {
        Self::from_connection(FrankenConnection::open_file(path)?)
    }

    /// Build from an existing `sqlmodel-frankensqlite` connection.
    pub fn from_connection(conn: FrankenConnection) -> CacheResult<Self> {
        let cache = Self { conn };
        cache.migrate_up()?;
        Ok(cache)
    }

    /// Apply the current explicit migration set.
    pub fn migrate_up(&self) -> CacheResult<()> {
        execute_batch(&self.conn, MIGRATION_1_UP)?;
        let hash = blake3_hex(MIGRATION_1_UP.as_bytes());
        self.conn.execute_sync(
            "INSERT OR IGNORE INTO schema_migrations \
             (version, name, applied_at_ms, content_hash) VALUES (?1, ?2, ?3, ?4)",
            &[
                Value::BigInt(i64::from(CURRENT_SCHEMA_VERSION.0)),
                Value::Text("initial_cache_repository".to_owned()),
                Value::BigInt(0),
                Value::Text(hash),
            ],
        )?;
        Ok(())
    }

    /// Roll back the current migration set. Intended for no-account tests.
    pub fn migrate_down(&self) -> CacheResult<()> {
        execute_batch(&self.conn, MIGRATION_1_DOWN)
    }

    fn execute(&self, sql: &str, params: &[Value]) -> CacheResult<()> {
        lint_append_only_audit_sql(sql)?;
        self.conn.execute_sync(sql, params)?;
        Ok(())
    }

    fn query(&self, sql: &str, params: &[Value]) -> CacheResult<Vec<Row>> {
        Ok(self.conn.query_sync(sql, params)?)
    }
}

#[cfg(feature = "frankensqlite")]
impl CacheBackend for FrankenSqliteCache {
    fn schema_version(&self) -> SchemaVersion {
        CURRENT_SCHEMA_VERSION
    }

    fn upsert_profile(&self, record: ProfileRecord) -> CacheResult<()> {
        record.validate_secret_free()?;
        self.execute(
            "INSERT OR REPLACE INTO profiles \
             (profile_id, display_name, account_locator_redacted, auth_lane, \
              credential_ref_kind, credential_ref_name, default_database, default_schema, \
              default_warehouse, default_role, created_at_ms, updated_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            &[
                Value::Text(record.profile_id),
                Value::Text(record.display_name),
                opt_text(record.account_locator_redacted),
                Value::Text(auth_lane_to_str(&record.auth_lane).to_owned()),
                Value::Text(credential_ref_kind_to_str(&record.credential_ref.kind).to_owned()),
                opt_text(record.credential_ref.name),
                opt_text(record.default_database),
                opt_text(record.default_schema),
                opt_text(record.default_warehouse),
                opt_text(record.default_role),
                u64_value("created_at_ms", record.created_at_ms)?,
                u64_value("updated_at_ms", record.updated_at_ms)?,
            ],
        )
    }

    fn profile(&self, profile_id: &str) -> CacheResult<Option<ProfileRecord>> {
        let rows = self.query(
            "SELECT profile_id, display_name, account_locator_redacted, auth_lane, \
                    credential_ref_kind, credential_ref_name, default_database, default_schema, \
                    default_warehouse, default_role, created_at_ms, updated_at_ms \
             FROM profiles WHERE profile_id = ?1",
            &[Value::Text(profile_id.to_owned())],
        )?;
        rows.first().map(row_profile).transpose()
    }

    fn profiles(&self) -> CacheResult<Vec<ProfileRecord>> {
        self.query(
            "SELECT profile_id, display_name, account_locator_redacted, auth_lane, \
                    credential_ref_kind, credential_ref_name, default_database, default_schema, \
                    default_warehouse, default_role, created_at_ms, updated_at_ms \
             FROM profiles ORDER BY profile_id",
            &[],
        )?
        .iter()
        .map(row_profile)
        .collect()
    }

    fn insert_catalog_snapshot(&self, record: CatalogSnapshotRecord) -> CacheResult<()> {
        record.payload.verify("catalog_snapshot")?;
        self.execute(
            "INSERT OR IGNORE INTO catalog_snapshots \
             (snapshot_id, profile_id, source_kind, database_name, schema_name, captured_at_ms, \
              payload_json, payload_hash, payload_bytes) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            &[
                Value::Text(record.snapshot_id),
                Value::Text(record.profile_id),
                Value::Text(record.source_kind),
                opt_text(record.database_name),
                opt_text(record.schema_name),
                u64_value("captured_at_ms", record.captured_at_ms)?,
                Value::Text(record.payload.canonical),
                Value::Text(record.payload.address.digest_hex),
                u64_value("payload_bytes", record.payload.address.byte_len)?,
            ],
        )
    }

    fn catalog_snapshot(&self, snapshot_id: &str) -> CacheResult<Option<CatalogSnapshotRecord>> {
        let rows = self.query(
            "SELECT snapshot_id, profile_id, source_kind, database_name, schema_name, \
                    captured_at_ms, payload_json, payload_hash, payload_bytes \
             FROM catalog_snapshots WHERE snapshot_id = ?1",
            &[Value::Text(snapshot_id.to_owned())],
        )?;
        rows.first().map(row_catalog_snapshot).transpose()
    }

    fn upsert_dataset_manifest(&self, record: DatasetManifestRecord) -> CacheResult<()> {
        record.manifest.verify("dataset_manifest")?;
        self.execute(
            "INSERT OR REPLACE INTO dataset_manifests \
             (dataset_id, profile_id, snapshot_id, database_name, schema_name, object_name, \
              rights_class, default_limit, max_rows_without_export, manifest_json, \
              manifest_hash, manifest_bytes, created_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            &[
                Value::Text(record.dataset_id),
                Value::Text(record.profile_id),
                opt_text(record.snapshot_id),
                Value::Text(record.database_name),
                Value::Text(record.schema_name),
                Value::Text(record.object_name),
                Value::Text(record.rights_class),
                u64_value("default_limit", record.default_limit)?,
                u64_value("max_rows_without_export", record.max_rows_without_export)?,
                Value::Text(record.manifest.canonical),
                Value::Text(record.manifest.address.digest_hex),
                u64_value("manifest_bytes", record.manifest.address.byte_len)?,
                u64_value("created_at_ms", record.created_at_ms)?,
            ],
        )
    }

    fn dataset_manifest(&self, dataset_id: &str) -> CacheResult<Option<DatasetManifestRecord>> {
        let rows = self.query(
            "SELECT dataset_id, profile_id, snapshot_id, database_name, schema_name, object_name, \
                    rights_class, default_limit, max_rows_without_export, manifest_json, \
                    manifest_hash, manifest_bytes, created_at_ms \
             FROM dataset_manifests WHERE dataset_id = ?1",
            &[Value::Text(dataset_id.to_owned())],
        )?;
        rows.first().map(row_dataset_manifest).transpose()
    }

    fn upsert_query_plan(&self, record: QueryPlanRecord) -> CacheResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO query_plans \
             (plan_id, profile_id, dataset_id, mode, normalized_sql_hash, normalized_sql_redacted, \
              bindings_shape_json, safety_class, estimated_row_limit, requires_export, created_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            &[
                Value::Text(record.plan_id),
                Value::Text(record.profile_id),
                opt_text(record.dataset_id),
                Value::Text(record.mode),
                Value::Text(record.normalized_sql_hash),
                Value::Text(record.normalized_sql_redacted),
                Value::Text(record.bindings_shape_json),
                Value::Text(record.safety_class),
                opt_u64("estimated_row_limit", record.estimated_row_limit)?,
                Value::BigInt(if record.requires_export { 1 } else { 0 }),
                u64_value("created_at_ms", record.created_at_ms)?,
            ],
        )
    }

    fn query_plan(&self, plan_id: &str) -> CacheResult<Option<QueryPlanRecord>> {
        let rows = self.query(
            "SELECT plan_id, profile_id, dataset_id, mode, normalized_sql_hash, \
                    normalized_sql_redacted, bindings_shape_json, safety_class, \
                    estimated_row_limit, requires_export, created_at_ms \
             FROM query_plans WHERE plan_id = ?1",
            &[Value::Text(plan_id.to_owned())],
        )?;
        rows.first().map(row_query_plan).transpose()
    }

    fn append_query_receipt(&self, record: QueryReceiptRecord) -> CacheResult<()> {
        record.receipt.verify("query_receipt")?;
        self.execute(
            "INSERT OR IGNORE INTO query_receipts \
             (receipt_id, plan_id, profile_id, command_id, trace_id, outcome_kind, receipt_state, \
              statement_handle, snowflake_query_id, request_id, row_count, receipt_json, \
              receipt_hash, receipt_bytes, created_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            &[
                Value::Text(record.receipt_id),
                Value::Text(record.plan_id),
                Value::Text(record.profile_id),
                Value::Text(record.command_id),
                Value::Text(record.trace_id),
                Value::Text(record.outcome_kind),
                Value::Text(record.receipt_state),
                opt_text(record.statement_handle),
                opt_text(record.snowflake_query_id),
                opt_text(record.request_id),
                opt_u64("row_count", record.row_count)?,
                Value::Text(record.receipt.canonical),
                Value::Text(record.receipt.address.digest_hex),
                u64_value("receipt_bytes", record.receipt.address.byte_len)?,
                u64_value("created_at_ms", record.created_at_ms)?,
            ],
        )
    }

    fn latest_successful_receipt(&self, plan_id: &str) -> CacheResult<Option<QueryReceiptRecord>> {
        let rows = self.query(
            "SELECT receipt_id, plan_id, profile_id, command_id, trace_id, outcome_kind, \
                    receipt_state, statement_handle, snowflake_query_id, request_id, row_count, \
                    receipt_json, receipt_hash, receipt_bytes, created_at_ms \
             FROM query_receipts \
             WHERE plan_id = ?1 AND outcome_kind = 'ok' \
             ORDER BY created_at_ms DESC LIMIT 1",
            &[Value::Text(plan_id.to_owned())],
        )?;
        rows.first().map(row_query_receipt).transpose()
    }

    fn receipt_by_snowflake_query_id(
        &self,
        profile_id: &str,
        snowflake_query_id: &str,
    ) -> CacheResult<Option<QueryReceiptRecord>> {
        let rows = self.query(
            "SELECT receipt_id, plan_id, profile_id, command_id, trace_id, outcome_kind, \
                    receipt_state, statement_handle, snowflake_query_id, request_id, row_count, \
                    receipt_json, receipt_hash, receipt_bytes, created_at_ms \
             FROM query_receipts \
             WHERE profile_id = ?1 AND snowflake_query_id = ?2 \
             ORDER BY created_at_ms DESC LIMIT 1",
            &[
                Value::Text(profile_id.to_owned()),
                Value::Text(snowflake_query_id.to_owned()),
            ],
        )?;
        rows.first().map(row_query_receipt).transpose()
    }

    fn append_partition_metadata(&self, record: PartitionMetadataRecord) -> CacheResult<()> {
        self.execute(
            "INSERT OR REPLACE INTO partition_metadata \
             (receipt_id, partition_index, row_count, compressed_bytes, uncompressed_bytes, \
              payload_hash, content_encoding) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                Value::Text(record.receipt_id),
                Value::BigInt(i64::from(record.partition_index)),
                u64_value("row_count", record.row_count)?,
                opt_u64("compressed_bytes", record.compressed_bytes)?,
                opt_u64("uncompressed_bytes", record.uncompressed_bytes)?,
                opt_text(record.payload_hash),
                opt_text(record.content_encoding),
            ],
        )
    }

    fn partitions_for_receipt(
        &self,
        receipt_id: &str,
    ) -> CacheResult<Vec<PartitionMetadataRecord>> {
        self.query(
            "SELECT receipt_id, partition_index, row_count, compressed_bytes, uncompressed_bytes, \
                    payload_hash, content_encoding \
             FROM partition_metadata WHERE receipt_id = ?1 ORDER BY partition_index",
            &[Value::Text(receipt_id.to_owned())],
        )?
        .iter()
        .map(row_partition_metadata)
        .collect()
    }

    fn append_export(&self, record: ExportRecord) -> CacheResult<()> {
        // Symmetric with the in-memory backend: validate the address shape (the
        // exported bytes live at an external target, so the digest is not
        // recomputable here) and fail closed on a malformed address.
        record.content_address.verify_well_formed("export_record")?;
        self.execute(
            "INSERT OR IGNORE INTO exports \
             (export_id, receipt_id, export_kind, target_uri_redacted, content_hash, byte_len, \
              row_count, created_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            &[
                Value::Text(record.export_id),
                Value::Text(record.receipt_id),
                Value::Text(export_kind_to_str(&record.export_kind).to_owned()),
                Value::Text(record.target_uri_redacted),
                Value::Text(record.content_address.digest_hex),
                u64_value("byte_len", record.content_address.byte_len)?,
                opt_u64("row_count", record.row_count)?,
                u64_value("created_at_ms", record.created_at_ms)?,
            ],
        )
    }

    fn exports_for_receipt(&self, receipt_id: &str) -> CacheResult<Vec<ExportRecord>> {
        self.query(
            "SELECT export_id, receipt_id, export_kind, target_uri_redacted, content_hash, \
                    byte_len, row_count, created_at_ms \
             FROM exports WHERE receipt_id = ?1 ORDER BY created_at_ms DESC",
            &[Value::Text(receipt_id.to_owned())],
        )?
        .iter()
        .map(row_export)
        .collect()
    }

    fn append_cost_history(&self, record: CostHistoryRecord) -> CacheResult<()> {
        self.execute(
            "INSERT OR IGNORE INTO cost_history \
             (history_id, profile_id, plan_id, receipt_id, row_count, compressed_bytes, \
              uncompressed_bytes, cost_vector_json, created_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            &[
                Value::Text(record.history_id),
                Value::Text(record.profile_id),
                opt_text(record.plan_id),
                opt_text(record.receipt_id),
                opt_u64("row_count", record.row_count)?,
                opt_u64("compressed_bytes", record.compressed_bytes)?,
                opt_u64("uncompressed_bytes", record.uncompressed_bytes)?,
                Value::Text(record.cost_vector_json),
                u64_value("created_at_ms", record.created_at_ms)?,
            ],
        )
    }

    fn cost_history_for_profile(&self, profile_id: &str) -> CacheResult<Vec<CostHistoryRecord>> {
        self.query(
            "SELECT history_id, profile_id, plan_id, receipt_id, row_count, compressed_bytes, \
                    uncompressed_bytes, cost_vector_json, created_at_ms \
             FROM cost_history WHERE profile_id = ?1 ORDER BY created_at_ms DESC",
            &[Value::Text(profile_id.to_owned())],
        )?
        .iter()
        .map(row_cost_history)
        .collect()
    }

    fn append_replay_bundle(&self, record: OfflineReplayBundleRecord) -> CacheResult<()> {
        record.manifest.verify("offline_replay_bundle")?;
        self.execute(
            "INSERT OR IGNORE INTO offline_replay_bundles \
             (bundle_id, source_receipt_id, snapshot_id, artifact_dir, manifest_json, \
              manifest_hash, manifest_bytes, created_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            &[
                Value::Text(record.bundle_id),
                opt_text(record.source_receipt_id),
                opt_text(record.snapshot_id),
                Value::Text(record.artifact_dir),
                Value::Text(record.manifest.canonical),
                Value::Text(record.manifest.address.digest_hex),
                u64_value("manifest_bytes", record.manifest.address.byte_len)?,
                u64_value("created_at_ms", record.created_at_ms)?,
            ],
        )
    }

    fn append_audit_event(&self, record: AuditEventRecord) -> CacheResult<()> {
        self.execute(
            "INSERT OR IGNORE INTO query_audit_log \
             (event_id, receipt_id, command_id, trace_id, event_kind, event_json, created_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            &[
                Value::Text(record.event_id),
                opt_text(record.receipt_id),
                Value::Text(record.command_id),
                Value::Text(record.trace_id),
                Value::Text(record.event_kind),
                Value::Text(record.event_json),
                u64_value("created_at_ms", record.created_at_ms)?,
            ],
        )
    }

    fn audit_events(&self) -> CacheResult<Vec<AuditEventRecord>> {
        self.query(
            "SELECT event_id, receipt_id, command_id, trace_id, event_kind, event_json, created_at_ms \
             FROM query_audit_log ORDER BY created_at_ms, event_id",
            &[],
        )?
        .iter()
        .map(row_audit_event)
        .collect()
    }
}

/// Serialized access wrapper documenting the `fsqlite::Connection` reality:
/// callers enter one repository critical section at a time.
#[derive(Debug)]
pub struct SerializedCache<B> {
    backend: Mutex<B>,
}

impl<B> SerializedCache<B> {
    /// Wrap a backend behind serialized access.
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self {
            backend: Mutex::new(backend),
        }
    }

    /// Run a repository operation while holding the serialized-access gate.
    pub fn with_cache<T>(&self, f: impl FnOnce(&mut B) -> CacheResult<T>) -> CacheResult<T> {
        match self.backend.lock() {
            Ok(mut guard) => f(&mut guard),
            Err(_) => Err(CacheError::PoisonedSerializedAccess),
        }
    }
}

/// Reject migrations or hand-written statements that mutate `query_audit_log`.
pub fn lint_append_only_audit_sql(sql: &str) -> CacheResult<()> {
    let tokens: Vec<String> = sql
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_uppercase)
        .collect();

    // Only statements that reference the audit table are constrained.
    if !tokens.iter().any(|token| token == "QUERY_AUDIT_LOG") {
        return Ok(());
    }

    // The audit log is append-only: a referencing statement may INSERT, SELECT, or
    // run DDL (CREATE/DROP for migrations), but never mutate existing rows. Reject
    // any row-mutating verb anywhere in the statement rather than scanning a fixed
    // token window next to the table name — a positional `windows(2)` check missed
    // `REPLACE INTO query_audit_log`, `INSERT OR REPLACE`, and
    // `INSERT ... ON CONFLICT ... DO UPDATE` (where `UPDATE` is far from the name).
    // `UPDATE` also catches `ON CONFLICT DO UPDATE`; `REPLACE` catches both
    // `REPLACE INTO` and `INSERT OR REPLACE`. None of the legitimate audit
    // statements (INSERT OR IGNORE, SELECT, CREATE TABLE/INDEX, DROP TABLE) contain
    // these verbs, so this is a sound allowlist-by-exclusion.
    const FORBIDDEN_VERBS: &[&str] = &["UPDATE", "DELETE", "REPLACE", "TRUNCATE"];
    if tokens
        .iter()
        .any(|token| FORBIDDEN_VERBS.contains(&token.as_str()))
    {
        return Err(CacheError::AuditMutationRefused {
            statement: sql.to_owned(),
        });
    }

    Ok(())
}

fn reject_secret_shape(field: &'static str, value: &str) -> CacheResult<()> {
    if value.contains('\n') {
        return Err(CacheError::SecretRefused {
            field,
            reason: "multi-line values are not valid credential references",
        });
    }

    let upper = value.to_ascii_uppercase();
    if upper.contains("BEGIN PRIVATE KEY") || upper.contains("BEGIN RSA PRIVATE KEY") {
        return Err(CacheError::SecretRefused {
            field,
            reason: "private-key material",
        });
    }

    for prefix in SECRET_PREFIXES {
        if value.starts_with(prefix) {
            return Err(CacheError::SecretRefused {
                field,
                reason: "well-known secret prefix",
            });
        }
    }

    Ok(())
}

fn usize_to_u64(value: usize) -> u64 {
    match u64::try_from(value) {
        Ok(value) => value,
        Err(_) => u64::MAX,
    }
}

fn blake3_hex(payload: &[u8]) -> String {
    blake3::hash(payload).to_hex().to_string()
}

#[cfg(feature = "frankensqlite")]
fn execute_batch(conn: &FrankenConnection, sql: &str) -> CacheResult<()> {
    for statement in sql
        .split(';')
        .map(str::trim)
        .filter(|stmt| !stmt.is_empty())
    {
        lint_append_only_audit_sql(statement)?;
        conn.execute_raw(statement)?;
    }
    Ok(())
}

#[cfg(feature = "frankensqlite")]
fn auth_lane_to_str(value: &AuthLane) -> &'static str {
    match value {
        AuthLane::ProgrammaticAccessToken => "pat",
        AuthLane::KeyPairJwt => "key_pair_jwt",
        AuthLane::OAuthBearer => "oauth",
    }
}

#[cfg(feature = "frankensqlite")]
fn auth_lane_from_str(value: &str) -> CacheResult<AuthLane> {
    match value {
        "pat" => Ok(AuthLane::ProgrammaticAccessToken),
        "key_pair_jwt" => Ok(AuthLane::KeyPairJwt),
        "oauth" => Ok(AuthLane::OAuthBearer),
        _ => Err(CacheError::InvalidRow {
            field: "auth_lane",
            message: format!("unknown auth lane {value}"),
        }),
    }
}

#[cfg(feature = "frankensqlite")]
fn credential_ref_kind_to_str(value: &CredentialRefKind) -> &'static str {
    match value {
        CredentialRefKind::Env => "env",
        CredentialRefKind::Provider => "provider",
        CredentialRefKind::None => "none",
    }
}

#[cfg(feature = "frankensqlite")]
fn credential_ref_kind_from_str(value: &str) -> CacheResult<CredentialRefKind> {
    match value {
        "env" => Ok(CredentialRefKind::Env),
        "provider" => Ok(CredentialRefKind::Provider),
        "none" => Ok(CredentialRefKind::None),
        _ => Err(CacheError::InvalidRow {
            field: "credential_ref_kind",
            message: format!("unknown credential reference kind {value}"),
        }),
    }
}

#[cfg(feature = "frankensqlite")]
fn export_kind_to_str(value: &ExportKind) -> &'static str {
    match value {
        ExportKind::CopyInto => "copy_into",
        ExportKind::LocalCsv => "local_csv",
        ExportKind::LocalJsonl => "local_jsonl",
    }
}

#[cfg(feature = "frankensqlite")]
fn export_kind_from_str(value: &str) -> CacheResult<ExportKind> {
    match value {
        "copy_into" => Ok(ExportKind::CopyInto),
        "local_csv" => Ok(ExportKind::LocalCsv),
        "local_jsonl" => Ok(ExportKind::LocalJsonl),
        _ => Err(CacheError::InvalidRow {
            field: "export_kind",
            message: format!("unknown export kind {value}"),
        }),
    }
}

#[cfg(feature = "frankensqlite")]
fn opt_text(value: Option<String>) -> Value {
    match value {
        Some(value) => Value::Text(value),
        None => Value::Null,
    }
}

#[cfg(feature = "frankensqlite")]
fn u64_value(field: &'static str, value: u64) -> CacheResult<Value> {
    match i64::try_from(value) {
        Ok(value) => Ok(Value::BigInt(value)),
        Err(_) => Err(CacheError::NumericOverflow { field, value }),
    }
}

#[cfg(feature = "frankensqlite")]
fn opt_u64(field: &'static str, value: Option<u64>) -> CacheResult<Value> {
    match value {
        Some(value) => u64_value(field, value),
        None => Ok(Value::Null),
    }
}

#[cfg(feature = "frankensqlite")]
fn row_text(row: &Row, index: usize, field: &'static str) -> CacheResult<String> {
    match row.get(index) {
        Some(Value::Text(value)) => Ok(value.clone()),
        Some(value) => Err(CacheError::InvalidRow {
            field,
            message: format!("expected TEXT, got {}", value.type_name()),
        }),
        None => Err(CacheError::InvalidRow {
            field,
            message: "missing column".to_owned(),
        }),
    }
}

#[cfg(feature = "frankensqlite")]
fn row_opt_text(row: &Row, index: usize, field: &'static str) -> CacheResult<Option<String>> {
    match row.get(index) {
        Some(Value::Text(value)) => Ok(Some(value.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(value) => Err(CacheError::InvalidRow {
            field,
            message: format!("expected nullable TEXT, got {}", value.type_name()),
        }),
    }
}

#[cfg(feature = "frankensqlite")]
fn row_u64(row: &Row, index: usize, field: &'static str) -> CacheResult<u64> {
    match row.get(index) {
        Some(Value::BigInt(value)) if *value >= 0 => Ok(*value as u64),
        Some(value) => Err(CacheError::InvalidRow {
            field,
            message: format!("expected non-negative INTEGER, got {}", value.type_name()),
        }),
        None => Err(CacheError::InvalidRow {
            field,
            message: "missing column".to_owned(),
        }),
    }
}

#[cfg(feature = "frankensqlite")]
fn row_u32(row: &Row, index: usize, field: &'static str) -> CacheResult<u32> {
    let value = row_u64(row, index, field)?;
    // Narrow with a checked conversion: a stored value >= 2^32 must surface as a
    // typed overflow, never silently wrap (a truncating `as u32` of e.g.
    // 4_294_967_296 would read back as 0 and collide with partition 0).
    u32::try_from(value).map_err(|_| CacheError::NumericOverflow { field, value })
}

#[cfg(feature = "frankensqlite")]
fn row_opt_u64(row: &Row, index: usize, field: &'static str) -> CacheResult<Option<u64>> {
    match row.get(index) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::BigInt(value)) if *value >= 0 => Ok(Some(*value as u64)),
        Some(value) => Err(CacheError::InvalidRow {
            field,
            message: format!(
                "expected nullable non-negative INTEGER, got {}",
                value.type_name()
            ),
        }),
    }
}

#[cfg(feature = "frankensqlite")]
fn row_bool(row: &Row, index: usize, field: &'static str) -> CacheResult<bool> {
    match row.get(index) {
        Some(Value::BigInt(0)) => Ok(false),
        Some(Value::BigInt(1)) => Ok(true),
        Some(value) => Err(CacheError::InvalidRow {
            field,
            message: format!("expected 0/1 INTEGER, got {}", value.type_name()),
        }),
        None => Err(CacheError::InvalidRow {
            field,
            message: "missing column".to_owned(),
        }),
    }
}

#[cfg(feature = "frankensqlite")]
fn payload_from_row(
    row: &Row,
    json_index: usize,
    hash_index: usize,
    bytes_index: usize,
    entity: &'static str,
) -> CacheResult<VerifiedPayload> {
    let canonical = row_text(row, json_index, entity)?;
    let address = ContentAddress {
        algorithm: "blake3".to_owned(),
        digest_hex: row_text(row, hash_index, entity)?,
        byte_len: row_u64(row, bytes_index, entity)?,
    };
    let payload = VerifiedPayload { canonical, address };
    payload.verify(entity)?;
    Ok(payload)
}

#[cfg(feature = "frankensqlite")]
fn row_profile(row: &Row) -> CacheResult<ProfileRecord> {
    let auth_lane = auth_lane_from_str(&row_text(row, 3, "auth_lane")?)?;
    let kind = credential_ref_kind_from_str(&row_text(row, 4, "credential_ref_kind")?)?;
    Ok(ProfileRecord {
        profile_id: row_text(row, 0, "profile_id")?,
        display_name: row_text(row, 1, "display_name")?,
        account_locator_redacted: row_opt_text(row, 2, "account_locator_redacted")?,
        auth_lane,
        credential_ref: CredentialRef {
            kind,
            name: row_opt_text(row, 5, "credential_ref_name")?,
        },
        default_database: row_opt_text(row, 6, "default_database")?,
        default_schema: row_opt_text(row, 7, "default_schema")?,
        default_warehouse: row_opt_text(row, 8, "default_warehouse")?,
        default_role: row_opt_text(row, 9, "default_role")?,
        created_at_ms: row_u64(row, 10, "created_at_ms")?,
        updated_at_ms: row_u64(row, 11, "updated_at_ms")?,
    })
}

#[cfg(feature = "frankensqlite")]
fn row_catalog_snapshot(row: &Row) -> CacheResult<CatalogSnapshotRecord> {
    Ok(CatalogSnapshotRecord {
        snapshot_id: row_text(row, 0, "snapshot_id")?,
        profile_id: row_text(row, 1, "profile_id")?,
        source_kind: row_text(row, 2, "source_kind")?,
        database_name: row_opt_text(row, 3, "database_name")?,
        schema_name: row_opt_text(row, 4, "schema_name")?,
        captured_at_ms: row_u64(row, 5, "captured_at_ms")?,
        payload: payload_from_row(row, 6, 7, 8, "catalog_snapshot")?,
    })
}

#[cfg(feature = "frankensqlite")]
fn row_dataset_manifest(row: &Row) -> CacheResult<DatasetManifestRecord> {
    Ok(DatasetManifestRecord {
        dataset_id: row_text(row, 0, "dataset_id")?,
        profile_id: row_text(row, 1, "profile_id")?,
        snapshot_id: row_opt_text(row, 2, "snapshot_id")?,
        database_name: row_text(row, 3, "database_name")?,
        schema_name: row_text(row, 4, "schema_name")?,
        object_name: row_text(row, 5, "object_name")?,
        rights_class: row_text(row, 6, "rights_class")?,
        default_limit: row_u64(row, 7, "default_limit")?,
        max_rows_without_export: row_u64(row, 8, "max_rows_without_export")?,
        manifest: payload_from_row(row, 9, 10, 11, "dataset_manifest")?,
        created_at_ms: row_u64(row, 12, "created_at_ms")?,
    })
}

#[cfg(feature = "frankensqlite")]
fn row_query_plan(row: &Row) -> CacheResult<QueryPlanRecord> {
    Ok(QueryPlanRecord {
        plan_id: row_text(row, 0, "plan_id")?,
        profile_id: row_text(row, 1, "profile_id")?,
        dataset_id: row_opt_text(row, 2, "dataset_id")?,
        mode: row_text(row, 3, "mode")?,
        normalized_sql_hash: row_text(row, 4, "normalized_sql_hash")?,
        normalized_sql_redacted: row_text(row, 5, "normalized_sql_redacted")?,
        bindings_shape_json: row_text(row, 6, "bindings_shape_json")?,
        safety_class: row_text(row, 7, "safety_class")?,
        estimated_row_limit: row_opt_u64(row, 8, "estimated_row_limit")?,
        requires_export: row_bool(row, 9, "requires_export")?,
        created_at_ms: row_u64(row, 10, "created_at_ms")?,
    })
}

#[cfg(feature = "frankensqlite")]
fn row_query_receipt(row: &Row) -> CacheResult<QueryReceiptRecord> {
    Ok(QueryReceiptRecord {
        receipt_id: row_text(row, 0, "receipt_id")?,
        plan_id: row_text(row, 1, "plan_id")?,
        profile_id: row_text(row, 2, "profile_id")?,
        command_id: row_text(row, 3, "command_id")?,
        trace_id: row_text(row, 4, "trace_id")?,
        outcome_kind: row_text(row, 5, "outcome_kind")?,
        receipt_state: row_text(row, 6, "receipt_state")?,
        statement_handle: row_opt_text(row, 7, "statement_handle")?,
        snowflake_query_id: row_opt_text(row, 8, "snowflake_query_id")?,
        request_id: row_opt_text(row, 9, "request_id")?,
        row_count: row_opt_u64(row, 10, "row_count")?,
        receipt: payload_from_row(row, 11, 12, 13, "query_receipt")?,
        created_at_ms: row_u64(row, 14, "created_at_ms")?,
    })
}

#[cfg(feature = "frankensqlite")]
fn row_partition_metadata(row: &Row) -> CacheResult<PartitionMetadataRecord> {
    Ok(PartitionMetadataRecord {
        receipt_id: row_text(row, 0, "receipt_id")?,
        partition_index: row_u32(row, 1, "partition_index")?,
        row_count: row_u64(row, 2, "row_count")?,
        compressed_bytes: row_opt_u64(row, 3, "compressed_bytes")?,
        uncompressed_bytes: row_opt_u64(row, 4, "uncompressed_bytes")?,
        payload_hash: row_opt_text(row, 5, "payload_hash")?,
        content_encoding: row_opt_text(row, 6, "content_encoding")?,
    })
}

#[cfg(feature = "frankensqlite")]
fn row_export(row: &Row) -> CacheResult<ExportRecord> {
    Ok(ExportRecord {
        export_id: row_text(row, 0, "export_id")?,
        receipt_id: row_text(row, 1, "receipt_id")?,
        export_kind: export_kind_from_str(&row_text(row, 2, "export_kind")?)?,
        target_uri_redacted: row_text(row, 3, "target_uri_redacted")?,
        content_address: ContentAddress {
            algorithm: "blake3".to_owned(),
            digest_hex: row_text(row, 4, "content_hash")?,
            byte_len: row_u64(row, 5, "byte_len")?,
        },
        row_count: row_opt_u64(row, 6, "row_count")?,
        created_at_ms: row_u64(row, 7, "created_at_ms")?,
    })
}

#[cfg(feature = "frankensqlite")]
fn row_cost_history(row: &Row) -> CacheResult<CostHistoryRecord> {
    Ok(CostHistoryRecord {
        history_id: row_text(row, 0, "history_id")?,
        profile_id: row_text(row, 1, "profile_id")?,
        plan_id: row_opt_text(row, 2, "plan_id")?,
        receipt_id: row_opt_text(row, 3, "receipt_id")?,
        row_count: row_opt_u64(row, 4, "row_count")?,
        compressed_bytes: row_opt_u64(row, 5, "compressed_bytes")?,
        uncompressed_bytes: row_opt_u64(row, 6, "uncompressed_bytes")?,
        cost_vector_json: row_text(row, 7, "cost_vector_json")?,
        created_at_ms: row_u64(row, 8, "created_at_ms")?,
    })
}

#[cfg(feature = "frankensqlite")]
fn row_audit_event(row: &Row) -> CacheResult<AuditEventRecord> {
    Ok(AuditEventRecord {
        event_id: row_text(row, 0, "event_id")?,
        receipt_id: row_opt_text(row, 1, "receipt_id")?,
        command_id: row_text(row, 2, "command_id")?,
        trace_id: row_text(row, 3, "trace_id")?,
        event_kind: row_text(row, 4, "event_kind")?,
        event_json: row_text(row, 5, "event_json")?,
        created_at_ms: row_u64(row, 6, "created_at_ms")?,
    })
}

#[cfg(feature = "frankensqlite")]
const MIGRATION_1_UP: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at_ms INTEGER NOT NULL,
  content_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS profiles (
  profile_id TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  account_locator_redacted TEXT,
  auth_lane TEXT NOT NULL,
  credential_ref_kind TEXT NOT NULL,
  credential_ref_name TEXT,
  default_database TEXT,
  default_schema TEXT,
  default_warehouse TEXT,
  default_role TEXT,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS catalog_snapshots (
  snapshot_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL,
  source_kind TEXT NOT NULL,
  database_name TEXT,
  schema_name TEXT,
  captured_at_ms INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  payload_bytes INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_catalog_snapshots_profile_time
  ON catalog_snapshots(profile_id, captured_at_ms);
CREATE INDEX IF NOT EXISTS idx_catalog_snapshots_scope
  ON catalog_snapshots(profile_id, database_name, schema_name, captured_at_ms);
CREATE INDEX IF NOT EXISTS idx_catalog_snapshots_hash
  ON catalog_snapshots(payload_hash);
CREATE TABLE IF NOT EXISTS dataset_manifests (
  dataset_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL,
  snapshot_id TEXT,
  database_name TEXT NOT NULL,
  schema_name TEXT NOT NULL,
  object_name TEXT NOT NULL,
  rights_class TEXT NOT NULL,
  default_limit INTEGER NOT NULL,
  max_rows_without_export INTEGER NOT NULL,
  manifest_json TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  manifest_bytes INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dataset_manifests_profile_dataset
  ON dataset_manifests(profile_id, dataset_id);
CREATE INDEX IF NOT EXISTS idx_dataset_manifests_object
  ON dataset_manifests(profile_id, database_name, schema_name, object_name);
CREATE INDEX IF NOT EXISTS idx_dataset_manifests_hash
  ON dataset_manifests(manifest_hash);
CREATE TABLE IF NOT EXISTS query_plans (
  plan_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL,
  dataset_id TEXT,
  mode TEXT NOT NULL,
  normalized_sql_hash TEXT NOT NULL,
  normalized_sql_redacted TEXT NOT NULL,
  bindings_shape_json TEXT NOT NULL,
  safety_class TEXT NOT NULL,
  estimated_row_limit INTEGER,
  requires_export INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_query_plans_profile_plan
  ON query_plans(profile_id, plan_id);
CREATE INDEX IF NOT EXISTS idx_query_plans_sql_hash
  ON query_plans(profile_id, normalized_sql_hash);
CREATE INDEX IF NOT EXISTS idx_query_plans_dataset_time
  ON query_plans(dataset_id, created_at_ms);
CREATE TABLE IF NOT EXISTS query_receipts (
  receipt_id TEXT PRIMARY KEY,
  plan_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  command_id TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  outcome_kind TEXT NOT NULL,
  receipt_state TEXT NOT NULL,
  statement_handle TEXT,
  snowflake_query_id TEXT,
  request_id TEXT,
  row_count INTEGER,
  receipt_json TEXT NOT NULL,
  receipt_hash TEXT NOT NULL,
  receipt_bytes INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_query_receipts_plan_time
  ON query_receipts(profile_id, plan_id, created_at_ms);
CREATE INDEX IF NOT EXISTS idx_query_receipts_query_id
  ON query_receipts(profile_id, snowflake_query_id);
CREATE INDEX IF NOT EXISTS idx_query_receipts_statement_handle
  ON query_receipts(profile_id, statement_handle);
CREATE INDEX IF NOT EXISTS idx_query_receipts_command
  ON query_receipts(command_id);
CREATE INDEX IF NOT EXISTS idx_query_receipts_trace
  ON query_receipts(trace_id);
CREATE INDEX IF NOT EXISTS idx_query_receipts_outcome_time
  ON query_receipts(outcome_kind, created_at_ms);
CREATE TABLE IF NOT EXISTS partition_metadata (
  receipt_id TEXT NOT NULL,
  partition_index INTEGER NOT NULL,
  row_count INTEGER NOT NULL,
  compressed_bytes INTEGER,
  uncompressed_bytes INTEGER,
  payload_hash TEXT,
  content_encoding TEXT,
  PRIMARY KEY (receipt_id, partition_index)
);
CREATE TABLE IF NOT EXISTS exports (
  export_id TEXT PRIMARY KEY,
  receipt_id TEXT NOT NULL,
  export_kind TEXT NOT NULL,
  target_uri_redacted TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  byte_len INTEGER NOT NULL,
  row_count INTEGER,
  created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exports_receipt_time
  ON exports(receipt_id, created_at_ms);
CREATE INDEX IF NOT EXISTS idx_exports_hash
  ON exports(content_hash);
CREATE INDEX IF NOT EXISTS idx_exports_kind_time
  ON exports(export_kind, created_at_ms);
CREATE TABLE IF NOT EXISTS cost_history (
  history_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL,
  plan_id TEXT,
  receipt_id TEXT,
  row_count INTEGER,
  compressed_bytes INTEGER,
  uncompressed_bytes INTEGER,
  cost_vector_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cost_history_profile_time
  ON cost_history(profile_id, created_at_ms);
CREATE TABLE IF NOT EXISTS offline_replay_bundles (
  bundle_id TEXT PRIMARY KEY,
  source_receipt_id TEXT,
  snapshot_id TEXT,
  artifact_dir TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  manifest_bytes INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS query_audit_log (
  event_id TEXT PRIMARY KEY,
  receipt_id TEXT,
  command_id TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  event_kind TEXT NOT NULL,
  event_json TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_query_audit_log_receipt
  ON query_audit_log(receipt_id);
CREATE INDEX IF NOT EXISTS idx_query_audit_log_command
  ON query_audit_log(command_id);
"#;

#[cfg(feature = "frankensqlite")]
const MIGRATION_1_DOWN: &str = r#"
DROP TABLE IF EXISTS query_audit_log;
DROP TABLE IF EXISTS offline_replay_bundles;
DROP TABLE IF EXISTS cost_history;
DROP TABLE IF EXISTS exports;
DROP TABLE IF EXISTS partition_metadata;
DROP TABLE IF EXISTS query_receipts;
DROP TABLE IF EXISTS query_plans;
DROP TABLE IF EXISTS dataset_manifests;
DROP TABLE IF EXISTS catalog_snapshots;
DROP TABLE IF EXISTS profiles;
DROP TABLE IF EXISTS schema_migrations;
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_prefixes_are_reexported_from_core() {
        assert_eq!(
            SECRET_PREFIXES,
            franken_snowflake_core::redact::SECRET_PREFIXES
        );
    }

    #[test]
    fn content_address_verify_rejects_unsupported_algorithm() {
        let payload: &[u8] = b"franken-snowflake-cache-content";
        let address = ContentAddress::blake3(payload);

        // The canonical blake3 address still verifies.
        assert!(address.verify("unit", payload).is_ok());

        // A non-blake3 algorithm must fail closed instead of skipping the digest
        // check. Regression: verification previously returned Ok for any label
        // other than "blake3", silently bypassing content-address integrity.
        // The foreign address carries a correct digest on purpose, so the test
        // pins that the algorithm is rejected before (and regardless of) the
        // digest comparison.
        let foreign = ContentAddress {
            algorithm: "sha256".to_owned(),
            digest_hex: address.digest_hex.clone(),
            byte_len: address.byte_len,
        };
        assert!(matches!(
            foreign.verify("unit", payload),
            Err(CacheError::InvalidRow { field: "unit", .. })
        ));

        // A genuine blake3 digest mismatch still surfaces as HashMismatch.
        let tampered = ContentAddress {
            algorithm: "blake3".to_owned(),
            digest_hex: "00".to_owned(),
            byte_len: address.byte_len,
        };
        assert!(matches!(
            tampered.verify("unit", payload),
            Err(CacheError::HashMismatch { .. })
        ));
    }

    #[test]
    fn append_export_accepts_external_content_address_and_rejects_malformed() -> CacheResult<()> {
        let cache = InMemoryCache::new();
        // The export bytes live at an external target, so the cache never holds
        // them. The content address covers that external content and is unrelated
        // to the redacted target URI; appending must not recompute it against the
        // URI string. Regression: append_export previously verified the address
        // against `target_uri_redacted.as_bytes()`, rejecting every real export on
        // the in-memory backend while the SQLite backend accepted it.
        let exported_content = b"row-a,row-b\n";
        let record = ExportRecord {
            export_id: "exp-1".to_owned(),
            receipt_id: "r1".to_owned(),
            export_kind: ExportKind::LocalCsv,
            target_uri_redacted: "file:///exports/[REDACTED]/part-0.csv".to_owned(),
            content_address: ContentAddress::blake3(exported_content),
            row_count: Some(2),
            created_at_ms: 7,
        };
        cache.append_export(record.clone())?;
        assert_eq!(cache.exports_for_receipt("r1")?, vec![record]);

        // A malformed address still fails closed: unsupported algorithm.
        let mut malformed = ExportRecord {
            export_id: "exp-2".to_owned(),
            receipt_id: "r1".to_owned(),
            export_kind: ExportKind::LocalCsv,
            target_uri_redacted: "file:///exports/[REDACTED]/part-1.csv".to_owned(),
            content_address: ContentAddress {
                algorithm: "md5".to_owned(),
                digest_hex: "00".to_owned(),
                byte_len: 12,
            },
            row_count: Some(2),
            created_at_ms: 8,
        };
        assert!(matches!(
            cache.append_export(malformed.clone()),
            Err(CacheError::InvalidRow {
                field: "export_record",
                ..
            })
        ));

        // ...and an empty digest under the blake3 label.
        malformed.content_address = ContentAddress {
            algorithm: "blake3".to_owned(),
            digest_hex: String::new(),
            byte_len: 12,
        };
        assert!(matches!(
            cache.append_export(malformed),
            Err(CacheError::InvalidRow {
                field: "export_record",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn profile_storage_rejects_secret_shaped_reference() {
        let cache = InMemoryCache::new();
        let mut profile = sample_profile("demo");
        profile.credential_ref = CredentialRef::env("sk-test-secret");

        let result = cache.upsert_profile(profile);

        assert!(matches!(
            result,
            Err(CacheError::SecretRefused {
                field: "credential_ref.name",
                ..
            })
        ));
    }

    #[test]
    fn profile_storage_rejects_recently_added_secret_prefixes() {
        // Regression: the needle list previously omitted these shapes, so a
        // profile reference carrying one would have been stored as a "reference".
        // Each must now be refused.
        for needle in [
            "ASIAEXAMPLE0000",
            "gho_EXAMPLE0000",
            "github_pat_EXAMPLE0000",
            "xoxp-EXAMPLE-0000",
        ] {
            let cache = InMemoryCache::new();
            let mut profile = sample_profile("demo");
            profile.credential_ref = CredentialRef::env(needle);
            assert!(
                matches!(
                    cache.upsert_profile(profile),
                    Err(CacheError::SecretRefused { .. })
                ),
                "secret-shaped reference {needle} was not rejected"
            );
        }
    }

    #[test]
    fn profile_storage_accepts_env_reference() -> CacheResult<()> {
        let cache = InMemoryCache::new();
        cache.upsert_profile(sample_profile("demo"))?;

        let stored = cache.profile("demo")?;

        assert_eq!(stored, Some(sample_profile("demo")));
        Ok(())
    }

    #[test]
    fn receipt_byte_length_is_checked() {
        let cache = InMemoryCache::new();
        let mut receipt = sample_receipt("r1", "plan-a", 10, "ok");
        receipt.receipt.address.byte_len = 999;

        let result = cache.append_query_receipt(receipt);

        assert!(matches!(
            result,
            Err(CacheError::ByteLengthMismatch {
                entity: "query_receipt",
                expected: 999,
                ..
            })
        ));
    }

    #[test]
    fn latest_successful_receipt_uses_plan_and_timestamp() -> CacheResult<()> {
        let cache = InMemoryCache::new();
        cache.append_query_receipt(sample_receipt("older", "plan-a", 10, "ok"))?;
        cache.append_query_receipt(sample_receipt("failed", "plan-a", 30, "error"))?;
        cache.append_query_receipt(sample_receipt("newer", "plan-a", 20, "ok"))?;

        let latest = cache.latest_successful_receipt("plan-a")?;

        assert_eq!(
            latest.map(|receipt| receipt.receipt_id),
            Some("newer".to_owned())
        );
        Ok(())
    }

    #[test]
    fn append_only_audit_lint_rejects_update_and_delete() {
        let update = lint_append_only_audit_sql("UPDATE query_audit_log SET event_json = '{}'");
        let delete = lint_append_only_audit_sql("DELETE FROM query_audit_log WHERE 1 = 1");

        assert!(matches!(
            update,
            Err(CacheError::AuditMutationRefused { .. })
        ));
        assert!(matches!(
            delete,
            Err(CacheError::AuditMutationRefused { .. })
        ));
    }

    #[test]
    fn append_only_audit_lint_rejects_replace_and_on_conflict_paths() {
        // These destructive forms were missed by the old token-window scan.
        for statement in [
            "REPLACE INTO query_audit_log (event_id) VALUES ('x')",
            "INSERT OR REPLACE INTO query_audit_log (event_id) VALUES ('x')",
            "INSERT INTO query_audit_log (event_id) VALUES ('x') ON CONFLICT(event_id) DO UPDATE SET event_json = '{}'",
            "DROP TABLE other; UPDATE query_audit_log SET created_at_ms = 0",
        ] {
            assert!(
                matches!(
                    lint_append_only_audit_sql(statement),
                    Err(CacheError::AuditMutationRefused { .. })
                ),
                "expected refusal for: {statement}"
            );
        }
    }

    #[test]
    fn append_only_audit_lint_allows_append_select_and_ddl() {
        // The legitimate audit statements must still pass: idempotent insert,
        // select, the create/index migration, the down-migration drop, and an
        // unrelated statement that does not touch the audit table.
        for statement in [
            "INSERT OR IGNORE INTO query_audit_log (event_id) VALUES ('x')",
            "SELECT event_id FROM query_audit_log ORDER BY created_at_ms, event_id",
            "CREATE TABLE IF NOT EXISTS query_audit_log (event_id TEXT PRIMARY KEY)",
            "CREATE INDEX IF NOT EXISTS idx_audit ON query_audit_log(receipt_id)",
            "DROP TABLE IF EXISTS query_audit_log",
            "UPDATE query_plans SET plan_json = '{}' WHERE plan_id = 'p'",
        ] {
            assert!(
                lint_append_only_audit_sql(statement).is_ok(),
                "expected acceptance for: {statement}"
            );
        }
    }

    #[test]
    fn serialized_cache_runs_repository_work_under_one_gate() -> CacheResult<()> {
        let cache = SerializedCache::new(InMemoryCache::new());
        cache.with_cache(|backend| backend.upsert_profile(sample_profile("a")))?;
        cache.with_cache(|backend| backend.upsert_profile(sample_profile("b")))?;

        let count = cache.with_cache(|backend| Ok(backend.profiles()?.len()))?;

        assert_eq!(count, 2);
        Ok(())
    }

    #[test]
    fn append_methods_are_first_write_wins_like_sqlite_insert_or_ignore() -> CacheResult<()> {
        // The SQLite backend uses `INSERT OR IGNORE` for every append-only table
        // (catalog snapshots, receipts, exports, cost history, replay bundles,
        // audit events), so a second write under an existing primary key keeps the
        // first row. The in-memory backend must model the same contract. Before
        // this fix it used `BTreeMap::insert` (last-write-wins), so identical code
        // diverged between the test backend and production on any duplicate id.
        let cache = InMemoryCache::new();

        // A reused receipt_id must keep the first committed receipt, not the later
        // re-append (here at created_at_ms 99) that production would have ignored.
        cache.append_query_receipt(sample_receipt("r1", "plan-a", 10, "ok"))?;
        cache.append_query_receipt(sample_receipt("r1", "plan-a", 99, "ok"))?;
        assert_eq!(
            cache
                .latest_successful_receipt("plan-a")?
                .map(|receipt| receipt.created_at_ms),
            Some(10),
            "duplicate receipt_id must not overwrite the first append"
        );

        // The audit log is explicitly append-only: a duplicate event_id is ignored.
        let audit_event = |json: &str| AuditEventRecord {
            event_id: "e1".to_owned(),
            receipt_id: None,
            command_id: "cmd".to_owned(),
            trace_id: "trace".to_owned(),
            event_kind: "kind".to_owned(),
            event_json: json.to_owned(),
            created_at_ms: 1,
        };
        cache.append_audit_event(audit_event("{\"v\":1}"))?;
        cache.append_audit_event(audit_event("{\"v\":2}"))?;
        let events = cache.audit_events()?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_json, "{\"v\":1}");

        // upsert_* keeps last-write-wins (it maps to SQLite `INSERT OR REPLACE`),
        // so the distinction between append and upsert is preserved.
        let mut profile = sample_profile("demo");
        cache.upsert_profile(profile.clone())?;
        profile.display_name = "Renamed".to_owned();
        cache.upsert_profile(profile)?;
        assert_eq!(
            cache.profile("demo")?.map(|record| record.display_name),
            Some("Renamed".to_owned())
        );

        Ok(())
    }

    #[test]
    fn list_queries_match_sqlite_ordering() -> CacheResult<()> {
        // The in-memory list queries must return rows in the same order as the
        // SQLite backend's `ORDER BY` clauses, not BTreeMap primary-key order.
        let cache = InMemoryCache::new();

        // audit_events: SQLite orders by (created_at_ms, event_id). Insert a later
        // event with a smaller event_id to expose the previous event_id-only order.
        let audit_event = |id: &str, at: u64| AuditEventRecord {
            event_id: id.to_owned(),
            receipt_id: None,
            command_id: "cmd".to_owned(),
            trace_id: "trace".to_owned(),
            event_kind: "kind".to_owned(),
            event_json: "{}".to_owned(),
            created_at_ms: at,
        };
        cache.append_audit_event(audit_event("zzz", 1))?;
        cache.append_audit_event(audit_event("aaa", 2))?;
        assert_eq!(
            cache
                .audit_events()?
                .into_iter()
                .map(|event| event.event_id)
                .collect::<Vec<_>>(),
            vec!["zzz".to_owned(), "aaa".to_owned()],
            "audit events must be chronological, not event_id order"
        );

        // exports_for_receipt: SQLite orders by created_at_ms DESC (newest first).
        let export = |id: &str, at: u64| ExportRecord {
            export_id: id.to_owned(),
            receipt_id: "r1".to_owned(),
            export_kind: ExportKind::LocalCsv,
            target_uri_redacted: "file:///[REDACTED]".to_owned(),
            content_address: ContentAddress::blake3(id.as_bytes()),
            row_count: Some(1),
            created_at_ms: at,
        };
        cache.append_export(export("aaa-old", 10))?;
        cache.append_export(export("zzz-new", 20))?;
        assert_eq!(
            cache
                .exports_for_receipt("r1")?
                .into_iter()
                .map(|record| record.export_id)
                .collect::<Vec<_>>(),
            vec!["zzz-new".to_owned(), "aaa-old".to_owned()],
            "exports must be newest-first, not export_id order"
        );
        Ok(())
    }

    #[test]
    fn receipt_by_snowflake_query_id_returns_latest_like_sqlite() -> CacheResult<()> {
        // The SQLite backend selects the newest matching receipt
        // (`ORDER BY created_at_ms DESC LIMIT 1`). A snowflake_query_id is not
        // unique across receipt rows, so the in-memory backend must also return
        // the newest, not the lexicographically-first receipt_id that `find` gave.
        let cache = InMemoryCache::new();
        let mut older = sample_receipt("aaa-older", "plan-a", 10, "ok");
        older.snowflake_query_id = Some("shared-qid".to_owned());
        let mut newer = sample_receipt("zzz-newer", "plan-a", 50, "ok");
        newer.snowflake_query_id = Some("shared-qid".to_owned());
        // Re-address the mutated receipts so the byte-length/digest checks pass.
        for receipt in [&mut older, &mut newer] {
            receipt.receipt.address = ContentAddress::blake3(receipt.receipt.canonical.as_bytes());
        }
        cache.append_query_receipt(older)?;
        cache.append_query_receipt(newer)?;

        assert_eq!(
            cache
                .receipt_by_snowflake_query_id("demo", "shared-qid")?
                .map(|receipt| receipt.receipt_id),
            Some("zzz-newer".to_owned())
        );
        Ok(())
    }

    fn sample_profile(id: &str) -> ProfileRecord {
        ProfileRecord {
            profile_id: id.to_owned(),
            display_name: "Demo".to_owned(),
            account_locator_redacted: Some("acct-redacted".to_owned()),
            auth_lane: AuthLane::ProgrammaticAccessToken,
            credential_ref: CredentialRef::env("SNOWFLAKE_PAT_ENV"),
            default_database: None,
            default_schema: None,
            default_warehouse: None,
            default_role: None,
            created_at_ms: 1,
            updated_at_ms: 1,
        }
    }

    fn sample_receipt(
        receipt_id: &str,
        plan_id: &str,
        created_at_ms: u64,
        outcome_kind: &str,
    ) -> QueryReceiptRecord {
        let payload = format!("{{\"receipt_id\":\"{receipt_id}\"}}");
        QueryReceiptRecord {
            receipt_id: receipt_id.to_owned(),
            plan_id: plan_id.to_owned(),
            profile_id: "demo".to_owned(),
            command_id: "cmd".to_owned(),
            trace_id: "trace".to_owned(),
            outcome_kind: outcome_kind.to_owned(),
            receipt_state: "completed".to_owned(),
            statement_handle: Some("stmt".to_owned()),
            snowflake_query_id: Some(format!("qid-{receipt_id}")),
            request_id: None,
            row_count: Some(1),
            receipt: VerifiedPayload {
                address: ContentAddress::blake3(payload.as_bytes()),
                canonical: payload,
            },
            created_at_ms,
        }
    }
}
