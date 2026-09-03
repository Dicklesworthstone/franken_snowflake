//! The CLI's local store: where receipts, the append-only audit log, catalog
//! snapshots, and dataset manifests live between invocations.
//!
//! Backed by [`franken_snowflake_cache::FileCache`] under the platform data
//! directory (`FRANKEN_SNOWFLAKE_DATA_DIR` overrides it). Every command that
//! needs the store opens it lazily; a store that cannot be opened degrades to a
//! typed warning or a `FSNOW-7001` error, never a fabricated result.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(test))]
use franken_snowflake_cache::default_data_dir;
use franken_snowflake_cache::{
    AuditEventRecord, CacheBackend, CacheError, ContentAddress, DATA_DIR_ENV, FileCache,
};

/// An opened local store plus the directory it lives in.
pub struct Store {
    /// The append-only file-backed cache.
    pub cache: FileCache,
    /// Resolved data directory.
    pub dir: PathBuf,
}

/// Why the local store could not be opened.
#[derive(Debug)]
pub enum StoreError {
    /// No data directory could be derived (no override, no HOME/APPDATA).
    NoDataDir,
    /// The directory or its logs could not be opened.
    Open(String),
}

impl StoreError {
    /// Human-readable, secret-free explanation with the repair hint inline.
    pub fn message(&self) -> String {
        match self {
            Self::NoDataDir => format!(
                "no local data directory could be resolved; set {DATA_DIR_ENV} to a writable directory"
            ),
            Self::Open(detail) => format!("local store could not be opened: {detail}"),
        }
    }
}

/// The data directory this process uses. Unit tests get a per-process temp
/// directory so they never touch (or race on) the developer's real store; the
/// workspace forbids mutating the process environment in tests, so this is the
/// isolation seam instead of an env override.
pub fn data_dir() -> Option<PathBuf> {
    #[cfg(test)]
    {
        Some(std::env::temp_dir().join(format!("fsnow-cli-tests-{}", std::process::id())))
    }
    #[cfg(not(test))]
    {
        default_data_dir()
    }
}

/// Open the local store at the resolved data directory.
pub fn open_store() -> Result<Store, StoreError> {
    let dir = data_dir().ok_or(StoreError::NoDataDir)?;
    let cache = FileCache::open(&dir).map_err(|error| StoreError::Open(error.to_string()))?;
    Ok(Store { cache, dir })
}

/// Milliseconds since the Unix epoch (0 if the clock is before the epoch).
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Whole seconds since the Unix epoch.
pub fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(0)
}

/// Format Unix seconds as an RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`)
/// without pulling a date-time crate into the production graph. Uses the
/// civil-from-days algorithm (Howard Hinnant), valid for the proleptic
/// Gregorian calendar.
pub fn rfc3339_utc(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let secs_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

/// A UUID-shaped, per-invocation identifier: unique across runs (time + pid
/// + a caller-supplied seed) while still deterministic in shape for goldens.
pub fn invocation_id(seed: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u128::from(elapsed.as_nanos() as u64))
        .unwrap_or(0);
    let pid = u128::from(std::process::id());
    let seed_hash = ContentAddress::blake3(seed.as_bytes()).digest_hex;
    let seed_bits = u128::from_str_radix(&seed_hash[..8], 16).unwrap_or(0);
    let mixed = nanos ^ (pid << 64) ^ (seed_bits << 96);
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        (mixed >> 96) as u32,
        ((mixed >> 80) & 0xffff) as u16,
        ((mixed >> 68) & 0xfff) as u16,
        ((mixed >> 56) & 0xfff) as u16,
        (mixed & 0xffff_ffff_ffff) as u64,
    )
}

/// Append one audit event to the local store (no receipt attached). Used for
/// write refusals and other policy decisions an operator wants on the ledger.
/// Returns the event id.
pub fn append_audit(
    store: &Store,
    command_id: &str,
    trace_id: &str,
    event_kind: &str,
    event: &serde_json::Value,
    receipt_id: Option<&str>,
) -> Result<String, CacheError> {
    let created_at_ms = now_unix_ms();
    let event_json = serde_json::to_string(event).unwrap_or_else(|_| "{}".to_owned());
    let event_id = format!(
        "evt-{}",
        ContentAddress::blake3(
            format!("{command_id}|{trace_id}|{event_kind}|{created_at_ms}|{event_json}").as_bytes()
        )
        .digest_hex
    );
    store.cache.append_audit_event(AuditEventRecord {
        event_id: event_id.clone(),
        receipt_id: receipt_id.map(str::to_owned),
        command_id: command_id.to_owned(),
        trace_id: trace_id.to_owned(),
        event_kind: event_kind.to_owned(),
        event_json,
        created_at_ms,
    })?;
    Ok(event_id)
}

/// BLAKE3 hex of any text (used for normalized-SQL hashes and plan ids).
#[cfg(feature = "live")]
pub fn blake3_hex(text: &str) -> String {
    ContentAddress::blake3(text.as_bytes()).digest_hex
}

/// Facts about one completed live execution, turned into a content-addressed
/// receipt plus partition evidence plus an audit event by
/// [`record_execution`]. Secret-free by construction: the SQL is stored only
/// as a redacted, compacted preview plus its hash.
#[cfg(feature = "live")]
pub struct ExecutionFacts<'a> {
    pub command_id: &'a str,
    pub profile: &'a str,
    pub trace_id: &'a str,
    pub sql_preview_redacted: &'a str,
    pub statement_handle: &'a str,
    pub sql_api_request_id: Option<&'a str>,
    pub row_count: u64,
    pub partitions: &'a [(u32, u64, Option<u64>, Option<u64>)],
    pub columns: &'a [(String, String)],
    pub warehouse: Option<&'a str>,
    pub database: Option<&'a str>,
    pub schema: Option<&'a str>,
    pub role: Option<&'a str>,
    pub statement_timeout_seconds: u32,
    pub polls: u64,
    pub event_kind: &'a str,
    pub extra: serde_json::Value,
}

/// Write the receipt, partition metadata, plan record, and audit event for one
/// live execution. Returns the receipt hash (the `receipt_id`).
#[cfg(feature = "live")]
pub fn record_execution(store: &Store, facts: &ExecutionFacts<'_>) -> Result<String, CacheError> {
    use franken_snowflake_cache::{
        PartitionMetadataRecord, QueryPlanRecord, QueryReceiptRecord, VerifiedPayload,
    };

    let created_at_ms = now_unix_ms();
    let normalized_sql_hash = blake3_hex(facts.sql_preview_redacted);
    let plan_id = blake3_hex(&format!(
        "{}|{}|{}|{}|{}",
        facts.profile,
        facts.database.unwrap_or(""),
        facts.schema.unwrap_or(""),
        facts.warehouse.unwrap_or(""),
        normalized_sql_hash
    ));
    store.cache.upsert_query_plan(QueryPlanRecord {
        plan_id: plan_id.clone(),
        profile_id: facts.profile.to_owned(),
        dataset_id: None,
        mode: "raw_sql".to_owned(),
        normalized_sql_hash: normalized_sql_hash.clone(),
        normalized_sql_redacted: facts.sql_preview_redacted.to_owned(),
        bindings_shape_json: "{}".to_owned(),
        safety_class: if facts.command_id == "query.write" {
            "write".to_owned()
        } else {
            "read".to_owned()
        },
        estimated_row_limit: None,
        requires_export: false,
        created_at_ms,
    })?;

    let partitions_json: Vec<serde_json::Value> = facts
        .partitions
        .iter()
        .map(|(index, rows, compressed, uncompressed)| {
            serde_json::json!({
                "partition_index": index,
                "row_count": rows,
                "compressed_bytes": compressed,
                "uncompressed_bytes": uncompressed,
            })
        })
        .collect();
    let columns_json: Vec<serde_json::Value> = facts
        .columns
        .iter()
        .map(|(name, snowflake_type)| serde_json::json!({ "name": name, "type": snowflake_type }))
        .collect();
    // serde_json's Value::Object is key-sorted, so this canonical form is
    // deterministic regardless of insertion order.
    let receipt = serde_json::json!({
        "schema_version": "fsnow.query_receipt.v1",
        "command_id": facts.command_id,
        "profile_id": facts.profile,
        "trace_id": facts.trace_id,
        "plan_id": plan_id,
        "normalized_sql_hash": normalized_sql_hash,
        "sql_preview_redacted": facts.sql_preview_redacted,
        "statement_handle": facts.statement_handle,
        "snowflake_query_id": facts.statement_handle,
        "sql_api_request_id": facts.sql_api_request_id,
        "session": {
            "warehouse": facts.warehouse,
            "database": facts.database,
            "schema": facts.schema,
            "role": facts.role,
            "statement_timeout_seconds": facts.statement_timeout_seconds,
        },
        "row_count": facts.row_count,
        "partition_count": facts.partitions.len(),
        "partitions": partitions_json,
        "columns": columns_json,
        "budget_consumed": { "polls": facts.polls, "rows": facts.row_count },
        "outcome_kind": "success",
        "created_at_ms": created_at_ms,
        "extra": facts.extra,
    });
    let canonical = serde_json::to_string(&receipt).map_err(|error| CacheError::InvalidRow {
        field: "query_receipt",
        message: error.to_string(),
    })?;
    let address = ContentAddress::blake3(canonical.as_bytes());
    let receipt_id = address.digest_hex.clone();

    store.cache.append_query_receipt(QueryReceiptRecord {
        receipt_id: receipt_id.clone(),
        plan_id: plan_id.clone(),
        profile_id: facts.profile.to_owned(),
        command_id: facts.command_id.to_owned(),
        trace_id: facts.trace_id.to_owned(),
        outcome_kind: "ok".to_owned(),
        receipt_state: "completed".to_owned(),
        statement_handle: Some(facts.statement_handle.to_owned()),
        snowflake_query_id: Some(facts.statement_handle.to_owned()),
        request_id: facts.sql_api_request_id.map(str::to_owned),
        row_count: Some(facts.row_count),
        receipt: VerifiedPayload { canonical, address },
        created_at_ms,
    })?;
    for (index, rows, compressed, uncompressed) in facts.partitions {
        store
            .cache
            .append_partition_metadata(PartitionMetadataRecord {
                receipt_id: receipt_id.clone(),
                partition_index: *index,
                row_count: *rows,
                compressed_bytes: *compressed,
                uncompressed_bytes: *uncompressed,
                payload_hash: None,
                content_encoding: None,
            })?;
    }
    append_audit(
        store,
        facts.command_id,
        facts.trace_id,
        facts.event_kind,
        &serde_json::json!({
            "profile_id": facts.profile,
            "statement_handle": facts.statement_handle,
            "row_count": facts.row_count,
            "normalized_sql_hash": normalized_sql_hash,
            "plan_id": plan_id,
        }),
        Some(&receipt_id),
    )?;
    Ok(receipt_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_756_857_600), "2025-09-03T00:00:00Z");
        assert_eq!(rfc3339_utc(-1), "1969-12-31T23:59:59Z");
    }

    #[cfg(feature = "live")]
    #[test]
    fn record_execution_writes_receipt_partitions_and_audit_event() {
        let dir = std::env::temp_dir().join(format!(
            "fsnow-receipt-test-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        let store = Store {
            cache: FileCache::open(&dir).expect("open temp store"),
            dir: dir.clone(),
        };
        let partitions = [
            (0_u32, 2_u64, None, Some(64_u64)),
            (1, 3, Some(40), Some(90)),
        ];
        let columns = [("ID".to_string(), "FIXED".to_string())];
        let facts = ExecutionFacts {
            command_id: "query.run",
            profile: "demo",
            trace_id: "trace-1",
            sql_preview_redacted: "select 1",
            statement_handle: "01aa-handle",
            sql_api_request_id: Some("req-1"),
            row_count: 5,
            partitions: &partitions,
            columns: &columns,
            warehouse: Some("WH"),
            database: Some("DB"),
            schema: None,
            role: None,
            statement_timeout_seconds: 60,
            polls: 2,
            event_kind: "statement_executed",
            extra: serde_json::json!({"note": "unit"}),
        };
        let hash = record_execution(&store, &facts).expect("receipt recorded");
        assert_eq!(hash.len(), 64, "blake3 hex digest");

        let receipt = store
            .cache
            .query_receipt(&hash)
            .expect("lookup")
            .expect("receipt stored under its content hash");
        assert_eq!(receipt.statement_handle.as_deref(), Some("01aa-handle"));
        assert_eq!(receipt.row_count, Some(5));
        assert_eq!(receipt.receipt.address.digest_hex, hash);
        let body: serde_json::Value =
            serde_json::from_str(&receipt.receipt.canonical).expect("canonical json");
        assert_eq!(body["budget_consumed"]["polls"], 2);
        assert_eq!(body["session"]["warehouse"], "WH");
        assert_eq!(store.cache.partitions_for_receipt(&hash).unwrap().len(), 2);
        let events = store.cache.audit_events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].receipt_id.as_deref(), Some(hash.as_str()));
        assert_eq!(events[0].event_kind, "statement_executed");
        // The plan record links back through the same plan id.
        assert!(store.cache.query_plan(&receipt.plan_id).unwrap().is_some());
        // Re-recording identical facts yields a different receipt only through
        // created_at_ms; the ledger keeps both (append-only).
        let again = record_execution(&store, &facts).expect("second receipt");
        assert!(store.cache.query_receipt(&again).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invocation_ids_are_uuid_shaped_and_distinct() {
        let a = invocation_id("capabilities");
        let b = invocation_id("capabilities");
        assert_eq!(a.len(), 36);
        assert_eq!(a.matches('-').count(), 4);
        assert_eq!(&a[14..15], "4");
        assert_ne!(a, b, "two invocations must not share a request id");
    }
}
