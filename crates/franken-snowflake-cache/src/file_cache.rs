//! `FileCache`: a durable, cross-platform, append-only JSONL backend.
//!
//! Every repository table is one `<table>.jsonl` file under a data directory.
//! A write appends exactly one JSON line; a read folds the log through the
//! same [`InMemoryCache`] semantics used by the no-account tests (first-write-
//! wins on append tables, upsert on profiles/manifests/plans, newest-first
//! orderings). Because nothing in this backend can rewrite or delete a line, the
//! audit log is append-only by construction, not by lint.
//!
//! This is the default local store for the CLI on every platform. The
//! FrankenSQLite backend stays available behind the `frankensqlite` feature for
//! integrations that want a real database; the two backends share the
//! [`CacheBackend`] contract and the record types, so callers do not care which
//! one is underneath.
//!
//! Concurrency note: each append is a single `write_all` of one line on a file
//! opened in append mode. That is sufficient for one agent per machine; if
//! several CLI processes race on the same data dir, lines may interleave only
//! at line granularity, and a malformed line is skipped on load (reported through
//! [`FileCache::skipped_lines`]) rather than poisoning the whole store.

use std::cell::Cell;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    AuditEventRecord, CacheBackend, CacheError, CacheResult, CatalogSnapshotRecord,
    CostHistoryRecord, DatasetManifestRecord, ExportRecord, InMemoryCache,
    OfflineReplayBundleRecord, PartitionMetadataRecord, ProfileRecord, QueryPlanRecord,
    QueryReceiptRecord, SchemaVersion,
};

/// Log-line format version. Bump only with a migration path.
const LINE_VERSION: u32 = 1;

/// The on-disk table files, one per repository.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Table {
    Profiles,
    CatalogSnapshots,
    DatasetManifests,
    QueryPlans,
    QueryReceipts,
    PartitionMetadata,
    Exports,
    CostHistory,
    ReplayBundles,
    AuditLog,
}

impl Table {
    const fn file_name(self) -> &'static str {
        match self {
            Self::Profiles => "profiles.jsonl",
            Self::CatalogSnapshots => "catalog_snapshots.jsonl",
            Self::DatasetManifests => "dataset_manifests.jsonl",
            Self::QueryPlans => "query_plans.jsonl",
            Self::QueryReceipts => "query_receipts.jsonl",
            Self::PartitionMetadata => "partition_metadata.jsonl",
            Self::Exports => "exports.jsonl",
            Self::CostHistory => "cost_history.jsonl",
            Self::ReplayBundles => "replay_bundles.jsonl",
            Self::AuditLog => "query_audit_log.jsonl",
        }
    }
}

/// One appended log line.
#[derive(Serialize, Deserialize)]
struct Line<T> {
    v: u32,
    r: T,
}

/// Append-only JSONL-per-table cache backend. See the module docs.
#[derive(Debug)]
pub struct FileCache {
    dir: PathBuf,
    inner: InMemoryCache,
    skipped_lines: Cell<u64>,
}

impl FileCache {
    /// Open (creating if needed) the store under `dir` and fold every table log
    /// into memory. Malformed lines are skipped and counted, never fatal.
    pub fn open(dir: impl AsRef<Path>) -> CacheResult<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(|error| io_error("create data dir", &dir, &error))?;
        let cache = Self {
            dir,
            inner: InMemoryCache::new(),
            skipped_lines: Cell::new(0),
        };
        cache.load_all()?;
        Ok(cache)
    }

    /// The data directory backing this store.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Number of log lines that could not be parsed or failed validation while
    /// loading. Non-zero means the store was partially recovered.
    #[must_use]
    pub fn skipped_lines(&self) -> u64 {
        self.skipped_lines.get()
    }

    fn load_all(&self) -> CacheResult<()> {
        self.load_table(Table::Profiles, |record: ProfileRecord| {
            self.inner.upsert_profile(record)
        })?;
        self.load_table(Table::CatalogSnapshots, |record: CatalogSnapshotRecord| {
            self.inner.insert_catalog_snapshot(record)
        })?;
        self.load_table(Table::DatasetManifests, |record: DatasetManifestRecord| {
            self.inner.upsert_dataset_manifest(record)
        })?;
        self.load_table(Table::QueryPlans, |record: QueryPlanRecord| {
            self.inner.upsert_query_plan(record)
        })?;
        self.load_table(Table::QueryReceipts, |record: QueryReceiptRecord| {
            self.inner.append_query_receipt(record)
        })?;
        self.load_table(Table::PartitionMetadata, |record: PartitionMetadataRecord| {
            self.inner.append_partition_metadata(record)
        })?;
        self.load_table(Table::Exports, |record: ExportRecord| {
            self.inner.append_export(record)
        })?;
        self.load_table(Table::CostHistory, |record: CostHistoryRecord| {
            self.inner.append_cost_history(record)
        })?;
        self.load_table(Table::ReplayBundles, |record: OfflineReplayBundleRecord| {
            self.inner.append_replay_bundle(record)
        })?;
        self.load_table(Table::AuditLog, |record: AuditEventRecord| {
            self.inner.append_audit_event(record)
        })?;
        Ok(())
    }

    fn load_table<T: DeserializeOwned>(
        &self,
        table: Table,
        mut apply: impl FnMut(T) -> CacheResult<()>,
    ) -> CacheResult<()> {
        let path = self.dir.join(table.file_name());
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(io_error("open table log", &path, &error)),
        };
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|error| io_error("read table log", &path, &error))?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Line<T>>(&line) {
                Ok(parsed) if parsed.v == LINE_VERSION => {
                    if apply(parsed.r).is_err() {
                        self.skipped_lines.set(self.skipped_lines.get() + 1);
                    }
                }
                _ => self.skipped_lines.set(self.skipped_lines.get() + 1),
            }
        }
        Ok(())
    }

    fn append_line<T: Serialize>(&self, table: Table, record: &T) -> CacheResult<()> {
        let path = self.dir.join(table.file_name());
        let mut encoded = serde_json::to_string(&Line {
            v: LINE_VERSION,
            r: record,
        })
        .map_err(|error| CacheError::InvalidRow {
            field: table.file_name(),
            message: format!("could not serialize record: {error}"),
        })?;
        encoded.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| io_error("open table log for append", &path, &error))?;
        file.write_all(encoded.as_bytes())
            .map_err(|error| io_error("append table log", &path, &error))
    }
}

fn io_error(action: &str, path: &Path, error: &std::io::Error) -> CacheError {
    CacheError::Io {
        message: format!("{action} {}: {error}", path.display()),
    }
}

impl CacheBackend for FileCache {
    fn schema_version(&self) -> SchemaVersion {
        self.inner.schema_version()
    }

    fn upsert_profile(&self, record: ProfileRecord) -> CacheResult<()> {
        self.inner.upsert_profile(record.clone())?;
        self.append_line(Table::Profiles, &record)
    }

    fn profile(&self, profile_id: &str) -> CacheResult<Option<ProfileRecord>> {
        self.inner.profile(profile_id)
    }

    fn profiles(&self) -> CacheResult<Vec<ProfileRecord>> {
        self.inner.profiles()
    }

    fn insert_catalog_snapshot(&self, record: CatalogSnapshotRecord) -> CacheResult<()> {
        self.inner.insert_catalog_snapshot(record.clone())?;
        self.append_line(Table::CatalogSnapshots, &record)
    }

    fn catalog_snapshot(&self, snapshot_id: &str) -> CacheResult<Option<CatalogSnapshotRecord>> {
        self.inner.catalog_snapshot(snapshot_id)
    }

    fn upsert_dataset_manifest(&self, record: DatasetManifestRecord) -> CacheResult<()> {
        self.inner.upsert_dataset_manifest(record.clone())?;
        self.append_line(Table::DatasetManifests, &record)
    }

    fn dataset_manifest(&self, dataset_id: &str) -> CacheResult<Option<DatasetManifestRecord>> {
        self.inner.dataset_manifest(dataset_id)
    }

    fn upsert_query_plan(&self, record: QueryPlanRecord) -> CacheResult<()> {
        self.inner.upsert_query_plan(record.clone())?;
        self.append_line(Table::QueryPlans, &record)
    }

    fn query_plan(&self, plan_id: &str) -> CacheResult<Option<QueryPlanRecord>> {
        self.inner.query_plan(plan_id)
    }

    fn append_query_receipt(&self, record: QueryReceiptRecord) -> CacheResult<()> {
        self.inner.append_query_receipt(record.clone())?;
        self.append_line(Table::QueryReceipts, &record)
    }

    fn query_receipt(&self, receipt_id: &str) -> CacheResult<Option<QueryReceiptRecord>> {
        self.inner.query_receipt(receipt_id)
    }

    fn latest_successful_receipt(&self, plan_id: &str) -> CacheResult<Option<QueryReceiptRecord>> {
        self.inner.latest_successful_receipt(plan_id)
    }

    fn receipt_by_snowflake_query_id(
        &self,
        profile_id: &str,
        snowflake_query_id: &str,
    ) -> CacheResult<Option<QueryReceiptRecord>> {
        self.inner
            .receipt_by_snowflake_query_id(profile_id, snowflake_query_id)
    }

    fn append_partition_metadata(&self, record: PartitionMetadataRecord) -> CacheResult<()> {
        self.inner.append_partition_metadata(record.clone())?;
        self.append_line(Table::PartitionMetadata, &record)
    }

    fn partitions_for_receipt(
        &self,
        receipt_id: &str,
    ) -> CacheResult<Vec<PartitionMetadataRecord>> {
        self.inner.partitions_for_receipt(receipt_id)
    }

    fn append_export(&self, record: ExportRecord) -> CacheResult<()> {
        self.inner.append_export(record.clone())?;
        self.append_line(Table::Exports, &record)
    }

    fn exports_for_receipt(&self, receipt_id: &str) -> CacheResult<Vec<ExportRecord>> {
        self.inner.exports_for_receipt(receipt_id)
    }

    fn append_cost_history(&self, record: CostHistoryRecord) -> CacheResult<()> {
        self.inner.append_cost_history(record.clone())?;
        self.append_line(Table::CostHistory, &record)
    }

    fn cost_history_for_profile(&self, profile_id: &str) -> CacheResult<Vec<CostHistoryRecord>> {
        self.inner.cost_history_for_profile(profile_id)
    }

    fn append_replay_bundle(&self, record: OfflineReplayBundleRecord) -> CacheResult<()> {
        self.inner.append_replay_bundle(record.clone())?;
        self.append_line(Table::ReplayBundles, &record)
    }

    fn append_audit_event(&self, record: AuditEventRecord) -> CacheResult<()> {
        self.inner.append_audit_event(record.clone())?;
        self.append_line(Table::AuditLog, &record)
    }

    fn audit_events(&self) -> CacheResult<Vec<AuditEventRecord>> {
        self.inner.audit_events()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContentAddress, VerifiedPayload};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_dir(label: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nonce = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("fsnow-file-cache-{label}-{pid}-{nanos}-{nonce}"))
    }

    fn payload(text: &str) -> VerifiedPayload {
        VerifiedPayload {
            canonical: text.to_owned(),
            address: ContentAddress::blake3(text.as_bytes()),
        }
    }

    fn receipt(id: &str, plan: &str, outcome: &str, created_at_ms: u64) -> QueryReceiptRecord {
        QueryReceiptRecord {
            receipt_id: id.to_owned(),
            plan_id: plan.to_owned(),
            profile_id: "demo".to_owned(),
            command_id: "query.run".to_owned(),
            trace_id: format!("trace-{id}"),
            outcome_kind: outcome.to_owned(),
            receipt_state: "completed".to_owned(),
            statement_handle: Some(format!("handle-{id}")),
            snowflake_query_id: Some(format!("qid-{id}")),
            request_id: Some(format!("req-{id}")),
            row_count: Some(3),
            receipt: payload(&format!("{{\"receipt\":\"{id}\"}}")),
            created_at_ms,
        }
    }

    fn audit(id: &str, created_at_ms: u64) -> AuditEventRecord {
        AuditEventRecord {
            event_id: id.to_owned(),
            receipt_id: None,
            command_id: "query.run".to_owned(),
            trace_id: "trace".to_owned(),
            event_kind: "statement_executed".to_owned(),
            event_json: "{}".to_owned(),
            created_at_ms,
        }
    }

    #[test]
    fn file_cache_persists_across_reopen_and_keeps_first_write() -> CacheResult<()> {
        let dir = temp_dir("reopen");
        {
            let cache = FileCache::open(&dir)?;
            cache.append_query_receipt(receipt("r1", "plan-a", "ok", 10))?;
            cache.append_query_receipt(receipt("r2", "plan-a", "ok", 20))?;
            // Duplicate receipt id: append-only ledgers keep the first write.
            cache.append_query_receipt(receipt("r1", "plan-a", "error", 30))?;
            cache.append_audit_event(audit("e2", 200))?;
            cache.append_audit_event(audit("e1", 100))?;
            cache.upsert_dataset_manifest(DatasetManifestRecord {
                dataset_id: "ds".to_owned(),
                profile_id: "demo".to_owned(),
                snapshot_id: Some("snap".to_owned()),
                database_name: "DB".to_owned(),
                schema_name: "PUBLIC".to_owned(),
                object_name: "T".to_owned(),
                rights_class: "restricted".to_owned(),
                default_limit: 1000,
                max_rows_without_export: 50_000,
                manifest: payload("{\"v\":1}"),
                created_at_ms: 1,
            })?;
            cache.upsert_dataset_manifest(DatasetManifestRecord {
                dataset_id: "ds".to_owned(),
                profile_id: "demo".to_owned(),
                snapshot_id: Some("snap2".to_owned()),
                database_name: "DB".to_owned(),
                schema_name: "PUBLIC".to_owned(),
                object_name: "T".to_owned(),
                rights_class: "restricted".to_owned(),
                default_limit: 1000,
                max_rows_without_export: 50_000,
                manifest: payload("{\"v\":2}"),
                created_at_ms: 2,
            })?;
        }

        let reopened = FileCache::open(&dir)?;
        assert_eq!(reopened.skipped_lines(), 0);
        let r1 = reopened.query_receipt("r1")?.expect("r1 persisted");
        assert_eq!(r1.outcome_kind, "ok", "first write wins across reopen");
        assert_eq!(r1.created_at_ms, 10);
        let latest = reopened
            .latest_successful_receipt("plan-a")?
            .expect("latest receipt");
        assert_eq!(latest.receipt_id, "r2");
        let events = reopened.audit_events()?;
        assert_eq!(
            events.iter().map(|e| e.event_id.as_str()).collect::<Vec<_>>(),
            vec!["e1", "e2"],
            "audit events replay in chronological order"
        );
        let manifest = reopened.dataset_manifest("ds")?.expect("manifest");
        assert_eq!(
            manifest.snapshot_id.as_deref(),
            Some("snap2"),
            "manifests upsert (last write wins)"
        );
        assert_eq!(reopened.query_receipt("missing")?, None);

        let audit_log = fs::read_to_string(dir.join("query_audit_log.jsonl")).expect("audit file");
        assert_eq!(audit_log.lines().count(), 2, "one line per appended event");

        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn file_cache_skips_malformed_lines_instead_of_failing_open() -> CacheResult<()> {
        let dir = temp_dir("malformed");
        {
            let cache = FileCache::open(&dir)?;
            cache.append_query_receipt(receipt("good", "plan", "ok", 1))?;
        }
        let path = dir.join("query_receipts.jsonl");
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("append");
        file.write_all(b"{this is not json}\n{\"v\":99,\"r\":{}}\n")
            .expect("write junk");
        drop(file);

        let reopened = FileCache::open(&dir)?;
        assert_eq!(reopened.skipped_lines(), 2);
        assert!(reopened.query_receipt("good")?.is_some());
        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn file_cache_rejects_tampered_content_addresses_on_write() -> CacheResult<()> {
        let dir = temp_dir("tamper");
        let cache = FileCache::open(&dir)?;
        let mut bad = receipt("bad", "plan", "ok", 1);
        bad.receipt.address.digest_hex = "00".to_owned();
        assert!(matches!(
            cache.append_query_receipt(bad),
            Err(CacheError::HashMismatch { .. })
        ));
        assert!(
            !dir.join("query_receipts.jsonl").exists(),
            "a rejected record must not reach the log"
        );
        fs::remove_dir_all(&dir).ok();
        Ok(())
    }
}
