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
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    AuditEventRecord, CacheBackend, CacheError, CacheResult, CatalogSnapshotRecord,
    CompactionReport, CostHistoryRecord, DatasetManifestRecord, ExportRecord, InMemoryCache,
    OfflineReplayBundleRecord, PartitionMetadataRecord, ProfileRecord, QueryPlanRecord,
    QueryReceiptRecord, RetentionPolicy, SchemaVersion,
};

/// Log-line format version. Bump only with a migration path.
const LINE_VERSION: u32 = 1;

/// Automatic lazy compaction triggers when an upsert table accumulates at least
/// this many superseded lines and its on-disk line count is at least `2x` canonical entries.
const LAZY_COMPACT_MIN_SUPERSEDED_LINES: u64 = 64;

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
    const ALL: [Self; 10] = [
        Self::Profiles,
        Self::CatalogSnapshots,
        Self::DatasetManifests,
        Self::QueryPlans,
        Self::QueryReceipts,
        Self::PartitionMetadata,
        Self::Exports,
        Self::CostHistory,
        Self::ReplayBundles,
        Self::AuditLog,
    ];

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

    const fn index(self) -> usize {
        match self {
            Self::Profiles => 0,
            Self::CatalogSnapshots => 1,
            Self::DatasetManifests => 2,
            Self::QueryPlans => 3,
            Self::QueryReceipts => 4,
            Self::PartitionMetadata => 5,
            Self::Exports => 6,
            Self::CostHistory => 7,
            Self::ReplayBundles => 8,
            Self::AuditLog => 9,
        }
    }

    const fn bit(self) -> u16 {
        1_u16 << self.index()
    }
}

/// One appended log line.
#[derive(Serialize, Deserialize)]
struct Line<T> {
    v: u32,
    r: T,
}

/// Append-only JSONL-per-table cache backend with per-table lazy loading and
/// atomic upsert compaction. See the module docs.
#[derive(Debug)]
pub struct FileCache {
    dir: PathBuf,
    inner: InMemoryCache,
    skipped_lines: Cell<u64>,
    loaded_tables: Cell<u16>,
    table_line_counts: [Cell<u64>; 10],
}

impl FileCache {
    /// Open (creating if needed) the store under `dir`. Individual table logs
    /// are loaded lazily on first access so single-table CLI invocations start
    /// in $O(1)$ without parsing unrelated tables.
    pub fn open(dir: impl AsRef<Path>) -> CacheResult<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).map_err(|error| io_error("create data dir", &dir, &error))?;
        Ok(Self {
            dir,
            inner: InMemoryCache::new(),
            skipped_lines: Cell::new(0),
            loaded_tables: Cell::new(0),
            table_line_counts: std::array::from_fn(|_| Cell::new(0)),
        })
    }

    /// The data directory backing this store.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Number of table logs folded into memory so far on this handle.
    #[must_use]
    pub fn loaded_table_count(&self) -> u32 {
        self.loaded_tables.get().count_ones()
    }

    /// Number of log lines that could not be parsed or failed validation while
    /// loading. Ensures all table logs are scanned so health checks observe the
    /// complete store status.
    #[must_use]
    pub fn skipped_lines(&self) -> u64 {
        let _ = self.ensure_all_loaded();
        self.skipped_lines.get()
    }

    /// Replay every table log, in file order, into `target`: the one-shot
    /// import of this store into another backend (the FrankenSQLite store,
    /// reality-check bead oj0.40). Appends replay first-write-wins and upserts
    /// replay in order, so the target then answers every lookup as this store
    /// does, and a replay repeated after an interruption changes nothing.
    /// Returns how many lines were not replayed (malformed, or refused by the
    /// target).
    ///
    /// # Errors
    /// An unreadable table log.
    pub fn replay_into(&self, target: &dyn CacheBackend) -> CacheResult<u64> {
        let before = self.skipped_lines.get();
        let replayed = self.replay_logs(target);
        let not_replayed = self.skipped_lines.get().saturating_sub(before);
        self.skipped_lines.set(before);
        replayed.map(|()| not_replayed)
    }

    /// Atomically compact upsert tables (`profiles.jsonl`, `dataset_manifests.jsonl`,
    /// `query_plans.jsonl`) by writing canonical deduplicated lines to a temporary
    /// file and renaming over the table log. Never touches `query_audit_log.jsonl`.
    pub fn compact_upsert_tables(&self) -> CacheResult<CompactionReport> {
        self.ensure_table_loaded(Table::Profiles)?;
        self.ensure_table_loaded(Table::DatasetManifests)?;
        self.ensure_table_loaded(Table::QueryPlans)?;

        let mut report = CompactionReport::default();

        let profiles = self.inner.profiles()?;
        self.compact_single_table(Table::Profiles, &profiles, &mut report)?;

        let manifests = self.inner.all_dataset_manifests();
        self.compact_single_table(Table::DatasetManifests, &manifests, &mut report)?;

        let plans = self.inner.all_query_plans();
        self.compact_single_table(Table::QueryPlans, &plans, &mut report)?;

        Ok(report)
    }

    fn compact_single_table<T: Serialize>(
        &self,
        table: Table,
        canonical_records: &[T],
        report: &mut CompactionReport,
    ) -> CacheResult<()> {
        let idx = table.index();
        let before = self.table_line_counts[idx].get();
        let after = u64::try_from(canonical_records.len()).unwrap_or(u64::MAX);
        report.lines_before = report.lines_before.saturating_add(before);
        report.lines_after = report.lines_after.saturating_add(after);
        if before <= after {
            return Ok(());
        }
        self.rewrite_table_atomic(table, canonical_records)?;
        self.table_line_counts[idx].set(after);
        report.tables_rewritten += 1;
        Ok(())
    }

    fn maybe_lazy_compact_upsert<T: Serialize>(
        &self,
        table: Table,
        canonical_fn: impl FnOnce(&InMemoryCache) -> Vec<T>,
    ) -> CacheResult<()> {
        let idx = table.index();
        let lines = self.table_line_counts[idx].get();
        if lines < LAZY_COMPACT_MIN_SUPERSEDED_LINES {
            return Ok(());
        }
        let canonical = canonical_fn(&self.inner);
        let canonical_len = u64::try_from(canonical.len()).unwrap_or(u64::MAX);
        if lines.saturating_sub(canonical_len) >= LAZY_COMPACT_MIN_SUPERSEDED_LINES
            && lines >= canonical_len.saturating_mul(2)
        {
            self.rewrite_table_atomic(table, &canonical)?;
            self.table_line_counts[idx].set(canonical_len);
        }
        Ok(())
    }

    fn rewrite_table_atomic<T: Serialize>(&self, table: Table, records: &[T]) -> CacheResult<()> {
        debug_assert_ne!(
            table,
            Table::AuditLog,
            "query_audit_log.jsonl must never be rewritten"
        );
        let path = self.dir.join(table.file_name());
        let tmp_path = self.dir.join(format!("{}.tmp", table.file_name()));
        let mut buf = String::new();
        for record in records {
            let line = serde_json::to_string(&Line {
                v: LINE_VERSION,
                r: record,
            })
            .map_err(|error| CacheError::InvalidRow {
                field: table.file_name(),
                message: format!("could not serialize record: {error}"),
            })?;
            buf.push_str(&line);
            buf.push('\n');
        }
        fs::write(&tmp_path, buf.as_bytes())
            .map_err(|error| io_error("write compacted table temp file", &tmp_path, &error))?;
        fs::rename(&tmp_path, &path)
            .map_err(|error| io_error("rename compacted table file", &path, &error))
    }

    fn ensure_all_loaded(&self) -> CacheResult<()> {
        for table in Table::ALL {
            self.ensure_table_loaded(table)?;
        }
        Ok(())
    }

    fn ensure_table_loaded(&self, table: Table) -> CacheResult<()> {
        let mask = self.loaded_tables.get();
        let bit = table.bit();
        if (mask & bit) != 0 {
            return Ok(());
        }
        let target = &self.inner;
        let lines = match table {
            Table::Profiles => {
                self.load_table(table, |record: ProfileRecord| target.upsert_profile(record))?
            }
            Table::CatalogSnapshots => self
                .load_table(table, |record: CatalogSnapshotRecord| {
                    target.insert_catalog_snapshot(record)
                })?,
            Table::DatasetManifests => self
                .load_table(table, |record: DatasetManifestRecord| {
                    target.upsert_dataset_manifest(record)
                })?,
            Table::QueryPlans => self.load_table(table, |record: QueryPlanRecord| {
                target.upsert_query_plan(record)
            })?,
            Table::QueryReceipts => self.load_table(table, |record: QueryReceiptRecord| {
                target.append_query_receipt(record)
            })?,
            Table::PartitionMetadata => self
                .load_table(table, |record: PartitionMetadataRecord| {
                    target.append_partition_metadata(record)
                })?,
            Table::Exports => {
                self.load_table(table, |record: ExportRecord| target.append_export(record))?
            }
            Table::CostHistory => self.load_table(table, |record: CostHistoryRecord| {
                target.append_cost_history(record)
            })?,
            Table::ReplayBundles => self
                .load_table(table, |record: OfflineReplayBundleRecord| {
                    target.append_replay_bundle(record)
                })?,
            Table::AuditLog => self.load_table(table, |record: AuditEventRecord| {
                target.append_audit_event(record)
            })?,
        };
        self.table_line_counts[table.index()].set(lines);
        self.loaded_tables.set(self.loaded_tables.get() | bit);
        Ok(())
    }

    fn replay_logs(&self, target: &dyn CacheBackend) -> CacheResult<()> {
        self.load_table(Table::Profiles, |record: ProfileRecord| {
            target.upsert_profile(record)
        })?;
        self.load_table(Table::CatalogSnapshots, |record: CatalogSnapshotRecord| {
            target.insert_catalog_snapshot(record)
        })?;
        self.load_table(Table::DatasetManifests, |record: DatasetManifestRecord| {
            target.upsert_dataset_manifest(record)
        })?;
        self.load_table(Table::QueryPlans, |record: QueryPlanRecord| {
            target.upsert_query_plan(record)
        })?;
        self.load_table(Table::QueryReceipts, |record: QueryReceiptRecord| {
            target.append_query_receipt(record)
        })?;
        self.load_table(
            Table::PartitionMetadata,
            |record: PartitionMetadataRecord| target.append_partition_metadata(record),
        )?;
        self.load_table(Table::Exports, |record: ExportRecord| {
            target.append_export(record)
        })?;
        self.load_table(Table::CostHistory, |record: CostHistoryRecord| {
            target.append_cost_history(record)
        })?;
        self.load_table(Table::ReplayBundles, |record: OfflineReplayBundleRecord| {
            target.append_replay_bundle(record)
        })?;
        self.load_table(Table::AuditLog, |record: AuditEventRecord| {
            target.append_audit_event(record)
        })?;
        Ok(())
    }

    fn load_table<T: DeserializeOwned>(
        &self,
        table: Table,
        mut apply: impl FnMut(T) -> CacheResult<()>,
    ) -> CacheResult<u64> {
        let path = self.dir.join(table.file_name());
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(io_error("open table log", &path, &error)),
        };
        let mut content = String::new();
        BufReader::new(file)
            .read_to_string(&mut content)
            .map_err(|error| io_error("read table log", &path, &error))?;
        // A concurrent writer may be mid-append: the final unterminated fragment
        // is in flight, not corruption, so it is ignored without counting as a
        // skipped line. Only newline-terminated records are complete.
        let complete = match content.rfind('\n') {
            Some(last_newline) => &content[..=last_newline],
            None => "",
        };
        let mut valid_lines = 0_u64;
        for line in complete.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Line<T>>(line) {
                Ok(parsed) if parsed.v == LINE_VERSION => {
                    if apply(parsed.r).is_err() {
                        self.skipped_lines.set(self.skipped_lines.get() + 1);
                    } else {
                        valid_lines += 1;
                    }
                }
                _ => self.skipped_lines.set(self.skipped_lines.get() + 1),
            }
        }
        Ok(valid_lines)
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
            .map_err(|error| io_error("append table log", &path, &error))?;
        let idx = table.index();
        self.table_line_counts[idx].set(self.table_line_counts[idx].get().saturating_add(1));
        Ok(())
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

    fn skipped_lines(&self) -> u64 {
        FileCache::skipped_lines(self)
    }

    fn compact(&self) -> CacheResult<CompactionReport> {
        self.compact_upsert_tables()
    }

    fn apply_retention(&self, policy: &RetentionPolicy) -> CacheResult<u64> {
        if policy.max_receipts_per_profile.is_some() {
            self.ensure_table_loaded(Table::QueryReceipts)?;
            self.ensure_table_loaded(Table::PartitionMetadata)?;
        }
        if policy.max_snapshots_per_scope.is_some() {
            self.ensure_table_loaded(Table::CatalogSnapshots)?;
        }
        let evicted = self.inner.apply_retention_in_memory(policy);
        if evicted > 0 {
            if policy.max_receipts_per_profile.is_some() {
                let receipts = self.inner.all_query_receipts();
                self.rewrite_table_atomic(Table::QueryReceipts, &receipts)?;
                self.table_line_counts[Table::QueryReceipts.index()]
                    .set(u64::try_from(receipts.len()).unwrap_or(u64::MAX));
                let partitions = self.inner.all_partition_metadata();
                self.rewrite_table_atomic(Table::PartitionMetadata, &partitions)?;
                self.table_line_counts[Table::PartitionMetadata.index()]
                    .set(u64::try_from(partitions.len()).unwrap_or(u64::MAX));
            }
            if policy.max_snapshots_per_scope.is_some() {
                let snapshots = self.inner.all_catalog_snapshots();
                self.rewrite_table_atomic(Table::CatalogSnapshots, &snapshots)?;
                self.table_line_counts[Table::CatalogSnapshots.index()]
                    .set(u64::try_from(snapshots.len()).unwrap_or(u64::MAX));
            }
        }
        Ok(evicted)
    }

    fn upsert_profile(&self, record: ProfileRecord) -> CacheResult<()> {
        self.ensure_table_loaded(Table::Profiles)?;
        self.inner.upsert_profile(record.clone())?;
        self.append_line(Table::Profiles, &record)?;
        self.maybe_lazy_compact_upsert(Table::Profiles, |inner| {
            inner.profiles().unwrap_or_default()
        })
    }

    fn profile(&self, profile_id: &str) -> CacheResult<Option<ProfileRecord>> {
        self.ensure_table_loaded(Table::Profiles)?;
        self.inner.profile(profile_id)
    }

    fn profiles(&self) -> CacheResult<Vec<ProfileRecord>> {
        self.ensure_table_loaded(Table::Profiles)?;
        self.inner.profiles()
    }

    fn insert_catalog_snapshot(&self, record: CatalogSnapshotRecord) -> CacheResult<()> {
        self.ensure_table_loaded(Table::CatalogSnapshots)?;
        self.inner.insert_catalog_snapshot(record.clone())?;
        self.append_line(Table::CatalogSnapshots, &record)
    }

    fn catalog_snapshot(&self, snapshot_id: &str) -> CacheResult<Option<CatalogSnapshotRecord>> {
        self.ensure_table_loaded(Table::CatalogSnapshots)?;
        self.inner.catalog_snapshot(snapshot_id)
    }

    fn latest_catalog_snapshot(
        &self,
        profile_id: &str,
        database_name: Option<&str>,
        schema_name: Option<&str>,
    ) -> CacheResult<Option<CatalogSnapshotRecord>> {
        self.ensure_table_loaded(Table::CatalogSnapshots)?;
        self.inner
            .latest_catalog_snapshot(profile_id, database_name, schema_name)
    }

    fn catalog_snapshots(
        &self,
        profile_id: &str,
        database_name: Option<&str>,
        schema_name: Option<&str>,
    ) -> CacheResult<Vec<CatalogSnapshotRecord>> {
        self.ensure_table_loaded(Table::CatalogSnapshots)?;
        self.inner
            .catalog_snapshots(profile_id, database_name, schema_name)
    }

    fn upsert_dataset_manifest(&self, record: DatasetManifestRecord) -> CacheResult<()> {
        self.ensure_table_loaded(Table::DatasetManifests)?;
        self.inner.upsert_dataset_manifest(record.clone())?;
        self.append_line(Table::DatasetManifests, &record)?;
        self.maybe_lazy_compact_upsert(
            Table::DatasetManifests,
            InMemoryCache::all_dataset_manifests,
        )
    }

    fn dataset_manifest(&self, dataset_id: &str) -> CacheResult<Option<DatasetManifestRecord>> {
        self.ensure_table_loaded(Table::DatasetManifests)?;
        self.inner.dataset_manifest(dataset_id)
    }

    fn dataset_ids(&self) -> CacheResult<Vec<String>> {
        self.ensure_table_loaded(Table::DatasetManifests)?;
        self.inner.dataset_ids()
    }

    fn upsert_query_plan(&self, record: QueryPlanRecord) -> CacheResult<()> {
        self.ensure_table_loaded(Table::QueryPlans)?;
        self.inner.upsert_query_plan(record.clone())?;
        self.append_line(Table::QueryPlans, &record)?;
        self.maybe_lazy_compact_upsert(Table::QueryPlans, InMemoryCache::all_query_plans)
    }

    fn query_plan(&self, plan_id: &str) -> CacheResult<Option<QueryPlanRecord>> {
        self.ensure_table_loaded(Table::QueryPlans)?;
        self.inner.query_plan(plan_id)
    }

    fn append_query_receipt(&self, record: QueryReceiptRecord) -> CacheResult<()> {
        self.ensure_table_loaded(Table::QueryReceipts)?;
        self.inner.append_query_receipt(record.clone())?;
        self.append_line(Table::QueryReceipts, &record)
    }

    fn query_receipt(&self, receipt_id: &str) -> CacheResult<Option<QueryReceiptRecord>> {
        self.ensure_table_loaded(Table::QueryReceipts)?;
        self.inner.query_receipt(receipt_id)
    }

    fn latest_successful_receipt(&self, plan_id: &str) -> CacheResult<Option<QueryReceiptRecord>> {
        self.ensure_table_loaded(Table::QueryReceipts)?;
        self.inner.latest_successful_receipt(plan_id)
    }

    fn receipt_by_snowflake_query_id(
        &self,
        profile_id: &str,
        snowflake_query_id: &str,
    ) -> CacheResult<Option<QueryReceiptRecord>> {
        self.ensure_table_loaded(Table::QueryReceipts)?;
        self.inner
            .receipt_by_snowflake_query_id(profile_id, snowflake_query_id)
    }

    fn append_partition_metadata(&self, record: PartitionMetadataRecord) -> CacheResult<()> {
        self.ensure_table_loaded(Table::PartitionMetadata)?;
        self.inner.append_partition_metadata(record.clone())?;
        self.append_line(Table::PartitionMetadata, &record)
    }

    fn partitions_for_receipt(
        &self,
        receipt_id: &str,
    ) -> CacheResult<Vec<PartitionMetadataRecord>> {
        self.ensure_table_loaded(Table::PartitionMetadata)?;
        self.inner.partitions_for_receipt(receipt_id)
    }

    fn append_export(&self, record: ExportRecord) -> CacheResult<()> {
        self.ensure_table_loaded(Table::Exports)?;
        self.inner.append_export(record.clone())?;
        self.append_line(Table::Exports, &record)
    }

    fn exports_for_receipt(&self, receipt_id: &str) -> CacheResult<Vec<ExportRecord>> {
        self.ensure_table_loaded(Table::Exports)?;
        self.inner.exports_for_receipt(receipt_id)
    }

    fn export(&self, export_id: &str) -> CacheResult<Option<ExportRecord>> {
        self.ensure_table_loaded(Table::Exports)?;
        self.inner.export(export_id)
    }

    fn append_cost_history(&self, record: CostHistoryRecord) -> CacheResult<()> {
        self.ensure_table_loaded(Table::CostHistory)?;
        self.inner.append_cost_history(record.clone())?;
        self.append_line(Table::CostHistory, &record)
    }

    fn cost_history_for_profile(&self, profile_id: &str) -> CacheResult<Vec<CostHistoryRecord>> {
        self.ensure_table_loaded(Table::CostHistory)?;
        self.inner.cost_history_for_profile(profile_id)
    }

    fn append_replay_bundle(&self, record: OfflineReplayBundleRecord) -> CacheResult<()> {
        self.ensure_table_loaded(Table::ReplayBundles)?;
        self.inner.append_replay_bundle(record.clone())?;
        self.append_line(Table::ReplayBundles, &record)
    }

    fn append_audit_event(&self, record: AuditEventRecord) -> CacheResult<()> {
        self.ensure_table_loaded(Table::AuditLog)?;
        self.inner.append_audit_event(record.clone())?;
        self.append_line(Table::AuditLog, &record)
    }

    fn audit_events(&self) -> CacheResult<Vec<AuditEventRecord>> {
        self.ensure_table_loaded(Table::AuditLog)?;
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

    /// One of every record the CLI writes, with a duplicate receipt id so
    /// first-write-wins is part of what is compared.
    #[cfg(feature = "frankensqlite")]
    fn fill(backend: &dyn CacheBackend) -> CacheResult<()> {
        backend.upsert_query_plan(QueryPlanRecord {
            plan_id: "plan-a".to_owned(),
            profile_id: "demo".to_owned(),
            dataset_id: None,
            mode: "raw_sql".to_owned(),
            normalized_sql_hash: "hash-a".to_owned(),
            normalized_sql_redacted: "select 1".to_owned(),
            bindings_shape_json: "[]".to_owned(),
            safety_class: "read".to_owned(),
            estimated_row_limit: Some(10),
            requires_export: false,
            created_at_ms: 5,
        })?;
        backend.append_query_receipt(receipt("r1", "plan-a", "ok", 10))?;
        backend.append_query_receipt(receipt("r2", "plan-a", "ok", 20))?;
        backend.append_query_receipt(receipt("r1", "plan-a", "error", 30))?;
        backend.append_partition_metadata(PartitionMetadataRecord {
            receipt_id: "r1".to_owned(),
            partition_index: 0,
            row_count: 3,
            compressed_bytes: Some(10),
            uncompressed_bytes: Some(30),
            payload_hash: Some("p0".to_owned()),
            content_encoding: None,
        })?;
        backend.append_export(ExportRecord {
            export_id: "x1".to_owned(),
            receipt_id: "r1".to_owned(),
            export_kind: crate::ExportKind::LocalCsv,
            target_uri_redacted: "file:///tmp/out.csv".to_owned(),
            content_address: ContentAddress::blake3(b"a,b\n"),
            row_count: Some(1),
            created_at_ms: 40,
        })?;
        for (id, schema, at) in [("s1", "PUBLIC", 50), ("s2", "ANALYTICS", 60)] {
            backend.insert_catalog_snapshot(CatalogSnapshotRecord {
                snapshot_id: id.to_owned(),
                profile_id: "demo".to_owned(),
                source_kind: "information_schema".to_owned(),
                database_name: Some("DB".to_owned()),
                schema_name: Some(schema.to_owned()),
                captured_at_ms: at,
                payload: payload(&format!("{{\"snapshot\":\"{id}\"}}")),
            })?;
        }
        backend.upsert_dataset_manifest(DatasetManifestRecord {
            dataset_id: "events".to_owned(),
            profile_id: "demo".to_owned(),
            snapshot_id: Some("s1".to_owned()),
            database_name: "DB".to_owned(),
            schema_name: "PUBLIC".to_owned(),
            object_name: "EVENTS".to_owned(),
            rights_class: "internal".to_owned(),
            default_limit: 100,
            max_rows_without_export: 1_000,
            manifest: payload("{\"dataset\":\"events\"}"),
            created_at_ms: 70,
        })?;
        backend.append_audit_event(audit("e2", 200))?;
        backend.append_audit_event(audit("e1", 100))?;
        Ok(())
    }

    /// Every lookup the CLI makes, as one comparable value.
    #[cfg(feature = "frankensqlite")]
    fn lookups(backend: &dyn CacheBackend) -> CacheResult<String> {
        Ok(format!(
            "{:?}",
            (
                backend.query_plan("plan-a")?,
                backend.query_receipt("r1")?,
                backend.latest_successful_receipt("plan-a")?,
                backend.receipt_by_snowflake_query_id("demo", "qid-r2")?,
                backend.partitions_for_receipt("r1")?,
                backend.exports_for_receipt("r1")?,
                backend.export("x1")?,
                backend.latest_catalog_snapshot("demo", Some("DB"), None)?,
                backend.catalog_snapshots("demo", None, None)?,
                backend.dataset_manifest("events")?,
                backend.dataset_ids()?,
                backend.audit_events()?,
            )
        ))
    }

    /// Bead oj0.40: the file store and the FrankenSQLite store answer every
    /// lookup alike for the same writes, and replaying a file store into an
    /// empty FrankenSQLite store reproduces it (a second replay changes
    /// nothing).
    #[cfg(feature = "frankensqlite")]
    #[test]
    fn the_file_and_sqlite_stores_answer_alike_and_a_replay_reproduces_one() -> CacheResult<()> {
        let dir = temp_dir("parity");
        let file = FileCache::open(&dir)?;
        let sqlite = crate::FrankenSqliteCache::open_memory()?;
        fill(&file)?;
        fill(&sqlite)?;
        let expected = lookups(&file)?;
        assert_eq!(lookups(&sqlite)?, expected);

        let imported = crate::FrankenSqliteCache::open_memory()?;
        assert_ne!(lookups(&imported)?, expected, "an empty store differs");
        let reopened = FileCache::open(&dir)?;
        assert_eq!(reopened.replay_into(&imported)?, 0);
        assert_eq!(lookups(&imported)?, expected);
        assert_eq!(reopened.replay_into(&imported)?, 0);
        assert_eq!(lookups(&imported)?, expected);
        let _ = fs::remove_dir_all(&dir);
        Ok(())
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
        let r1 = reopened
            .query_receipt("r1")?
            .ok_or_else(|| CacheError::NotFound {
                entity: "query_receipt",
                id: "r1".to_owned(),
            })?;
        assert_eq!(r1.outcome_kind, "ok", "first write wins across reopen");
        assert_eq!(r1.created_at_ms, 10);
        let latest = reopened
            .latest_successful_receipt("plan-a")?
            .ok_or_else(|| CacheError::NotFound {
                entity: "query_receipt",
                id: "plan-a".to_owned(),
            })?;
        assert_eq!(latest.receipt_id, "r2");
        let events = reopened.audit_events()?;
        assert_eq!(
            events
                .iter()
                .map(|e| e.event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["e1", "e2"],
            "audit events replay in chronological order"
        );
        let manifest = reopened
            .dataset_manifest("ds")?
            .ok_or_else(|| CacheError::NotFound {
                entity: "dataset_manifest",
                id: "ds".to_owned(),
            })?;
        assert_eq!(
            manifest.snapshot_id.as_deref(),
            Some("snap2"),
            "manifests upsert (last write wins)"
        );
        assert_eq!(reopened.query_receipt("missing")?, None);

        let audit_path = dir.join("query_audit_log.jsonl");
        let audit_log = fs::read_to_string(&audit_path)
            .map_err(|e| io_error("read audit log", &audit_path, &e))?;
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
            .map_err(|e| io_error("open query receipts", &path, &e))?;
        file.write_all(b"{this is not json}\n{\"v\":99,\"r\":{}}\n")
            .map_err(|e| io_error("write junk receipts", &path, &e))?;
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

    #[test]
    fn file_cache_round_trips_catalog_snapshots_and_orders_newest_first() -> CacheResult<()> {
        let dir = temp_dir("snapshots");
        {
            let cache = FileCache::open(&dir)?;
            let snap = |id: &str, time: u64| CatalogSnapshotRecord {
                snapshot_id: id.to_owned(),
                profile_id: "demo".to_owned(),
                source_kind: "information_schema".to_owned(),
                database_name: Some("DB".to_owned()),
                schema_name: Some("PUBLIC".to_owned()),
                captured_at_ms: time,
                payload: payload(&format!("{{\"id\":\"{id}\"}}")),
            };
            cache.insert_catalog_snapshot(snap("snap-1", 100))?;
            cache.insert_catalog_snapshot(snap("snap-2", 200))?;
        }

        let reopened = FileCache::open(&dir)?;
        let snapshots = reopened.catalog_snapshots("demo", Some("DB"), Some("PUBLIC"))?;
        let ids: Vec<_> = snapshots.into_iter().map(|s| s.snapshot_id).collect();
        assert_eq!(ids, vec!["snap-2", "snap-1"]);
        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn file_cache_loads_tables_lazily_and_compacts_superseded_upserts() -> CacheResult<()> {
        let dir = temp_dir("lazy-compact");
        {
            let cache = FileCache::open(&dir)?;
            assert_eq!(cache.loaded_table_count(), 0);
            cache.append_query_receipt(receipt("r1", "plan-a", "ok", 10))?;
            assert_eq!(
                cache.loaded_table_count(),
                1,
                "only query_receipts is loaded"
            );
            cache.append_audit_event(audit("e1", 100))?;
            assert_eq!(cache.loaded_table_count(), 2);

            for version in 0..80_u64 {
                cache.upsert_dataset_manifest(DatasetManifestRecord {
                    dataset_id: "events".to_owned(),
                    profile_id: "demo".to_owned(),
                    snapshot_id: Some(format!("snap-{version}")),
                    database_name: "DB".to_owned(),
                    schema_name: "PUBLIC".to_owned(),
                    object_name: "EVENTS".to_owned(),
                    rights_class: "internal".to_owned(),
                    default_limit: 100,
                    max_rows_without_export: 1_000,
                    manifest: payload(&format!("{{\"v\":{version}}}")),
                    created_at_ms: version,
                })?;
            }
        }

        // Lazy compaction should have rewritten dataset_manifests.jsonl once superseded lines >= 64.
        let manifest_lines = fs::read_to_string(dir.join("dataset_manifests.jsonl"))
            .map_err(|e| io_error("read dataset manifests", &dir, &e))?
            .lines()
            .count();
        assert!(
            manifest_lines < 20,
            "expected lazy compaction to shrink 80 upserts, got {manifest_lines} lines"
        );

        let reopened = FileCache::open(&dir)?;
        assert_eq!(reopened.loaded_table_count(), 0);
        let manifest =
            reopened
                .dataset_manifest("events")?
                .ok_or_else(|| CacheError::NotFound {
                    entity: "dataset_manifest",
                    id: "events".to_owned(),
                })?;
        assert_eq!(manifest.snapshot_id.as_deref(), Some("snap-79"));
        assert_eq!(
            reopened.loaded_table_count(),
            1,
            "reading dataset_manifest must not load query_receipts or audit_log"
        );

        let report = reopened.compact()?;
        assert_eq!(report.lines_after, 1);
        let final_lines = fs::read_to_string(dir.join("dataset_manifests.jsonl"))
            .map_err(|e| io_error("read dataset manifests", &dir, &e))?
            .lines()
            .count();
        assert_eq!(final_lines, 1);

        // Audit log remains untouched.
        assert_eq!(reopened.audit_events()?.len(), 1);
        fs::remove_dir_all(&dir).ok();
        Ok(())
    }

    #[test]
    fn file_cache_retention_policy_evicts_oldest_receipts_and_snapshots_preserving_audit()
    -> CacheResult<()> {
        let dir = temp_dir("retention");
        let cache = FileCache::open(&dir)?;
        for idx in 1..=5_u64 {
            cache.append_query_receipt(receipt(&format!("r{idx}"), "plan-a", "ok", idx * 10))?;
            cache.insert_catalog_snapshot(CatalogSnapshotRecord {
                snapshot_id: format!("s{idx}"),
                profile_id: "demo".to_owned(),
                source_kind: "information_schema".to_owned(),
                database_name: Some("DB".to_owned()),
                schema_name: Some("PUBLIC".to_owned()),
                captured_at_ms: idx * 100,
                payload: payload(&format!("{{\"snap\":{idx}}}")),
            })?;
        }
        cache.append_audit_event(audit("e1", 1))?;

        let evicted = cache.apply_retention(&RetentionPolicy {
            max_receipts_per_profile: Some(2),
            max_snapshots_per_scope: Some(2),
        })?;
        assert_eq!(evicted, 6);

        let reopened = FileCache::open(&dir)?;
        assert!(reopened.query_receipt("r1")?.is_none());
        assert!(reopened.query_receipt("r3")?.is_none());
        assert!(reopened.query_receipt("r4")?.is_some());
        assert!(reopened.query_receipt("r5")?.is_some());
        let snaps = reopened.catalog_snapshots("demo", Some("DB"), Some("PUBLIC"))?;
        let snap_ids: Vec<_> = snaps.into_iter().map(|s| s.snapshot_id).collect();
        assert_eq!(snap_ids, vec!["s5", "s4"]);
        assert_eq!(reopened.audit_events()?.len(), 1);
        fs::remove_dir_all(&dir).ok();
        Ok(())
    }
}
