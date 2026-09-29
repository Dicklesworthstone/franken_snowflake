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
    // Every audit event names the build that wrote it (reality-check bead H1),
    // and every string in it passes the shared redactor at this sink, whatever
    // the caller did (reality-check bead B5: the audit log is append-only).
    let mut event = event.clone();
    redact_json_strings(&mut event);
    if let Some(body) = event.as_object_mut() {
        body.insert(
            "build_git_sha".to_owned(),
            serde_json::Value::String(crate::BUILD_GIT_SHA.to_owned()),
        );
    }
    let event_json = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_owned());
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

fn redact_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => {
            let redacted = franken_snowflake_core::redact::redact(text).into_owned();
            if redacted != *text {
                *text = redacted;
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(redact_json_strings),
        serde_json::Value::Object(entries) => entries.values_mut().for_each(redact_json_strings),
        _ => {}
    }
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
    /// `None` when the statement never got a handle (it failed or was
    /// cancelled before the SQL API accepted it).
    pub statement_handle: Option<&'a str>,
    pub sql_api_request_id: Option<&'a str>,
    /// The QUERY_TAG the statement ran with (reality-check bead L5).
    pub query_tag: Option<&'a str>,
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
    /// `None` for a statement that completed with rows; otherwise how it ended.
    pub terminal_failure: Option<TerminalFailure<'a>>,
}

/// How a statement ended when it produced no rows: failed, cancelled, or
/// timed out (reality-check bead C6; the core cancel policy promises a receipt
/// for a user cancel).
#[cfg(feature = "live")]
#[derive(Clone, Copy)]
pub struct TerminalFailure<'a> {
    /// Envelope vocabulary: `error`, `cancelled`, or `timeout`.
    pub outcome_kind: &'a str,
    /// Stable `FSNOW-*` code.
    pub error_code: &'a str,
    /// Already-redacted message.
    pub message: &'a str,
    /// Asupersync cancel kind, for cancellations.
    pub cancel_kind: Option<&'a str>,
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
    let mut receipt = serde_json::json!({
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
            "query_tag": facts.query_tag,
        },
        "row_count": facts.row_count,
        "partition_count": facts.partitions.len(),
        "partitions": partitions_json,
        "columns": columns_json,
        "budget_consumed": { "polls": facts.polls, "rows": facts.row_count },
        "outcome_kind": facts.terminal_failure.map_or("success", |failure| failure.outcome_kind),
        "created_at_ms": created_at_ms,
        "extra": facts.extra,
        "build": {
            "version": env!("CARGO_PKG_VERSION"),
            "git_sha": crate::BUILD_GIT_SHA,
            "source_digest": env!("FSNOW_BUILD_SOURCE_DIGEST"),
        },
    });
    // Only failure receipts carry `error`, so a completed statement's canonical
    // form (and hash) is unchanged.
    if let (Some(failure), Some(body)) = (facts.terminal_failure, receipt.as_object_mut()) {
        body.insert(
            "error".to_owned(),
            serde_json::json!({
                "code": failure.error_code,
                "message": failure.message,
                "cancel_kind": failure.cancel_kind,
            }),
        );
    }
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
        outcome_kind: facts
            .terminal_failure
            .map_or("ok", |failure| failure.outcome_kind)
            .to_owned(),
        receipt_state: match facts.terminal_failure.map(|failure| failure.outcome_kind) {
            None => "completed",
            Some("cancelled") => "cancelled",
            Some("timeout") => "timed_out",
            Some(_) => "failed",
        }
        .to_owned(),
        statement_handle: facts.statement_handle.map(str::to_owned),
        snowflake_query_id: facts.statement_handle.map(str::to_owned),
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
            "outcome_kind": facts.terminal_failure.map_or("success", |failure| failure.outcome_kind),
        }),
        Some(&receipt_id),
    )?;
    Ok(receipt_id)
}

/// A dry run the write ladder issued a confirmation token for (reality-check
/// bead B4). Recorded on the append-only audit log; a `--confirm` must name one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedConfirmation {
    /// Random, unguessable id; the token is `confirm:<kind>:<id>` and a
    /// confirmed write submits it as the SQL API `requestId`.
    pub confirm_id: String,
    pub profile: String,
    /// Keyed digest of the exact statement ([`keyed_sql_digest`]).
    pub sql_digest: String,
    /// Statement-kind token (`insert`, `merge`, ...).
    pub statement_kind: String,
    pub issued_at_ms: u64,
}

const DRY_RUN_EVENT: &str = "write_dry_run";
const CONSUMED_EVENT: &str = "write_confirm_consumed";
const CONFIRM_KEY_FILE: &str = "write_confirm.key";

/// A fresh random UUID-shaped id from the OS random source.
///
/// # Errors
/// The OS random source failed.
pub fn random_id() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| format!("random source unavailable: {error}"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// The per-data-directory key for keyed SQL digests: 32 random bytes in
/// `<data dir>/write_confirm.key`, created on first use (owner-only on Unix).
fn confirm_key(store: &Store) -> Result<Vec<u8>, String> {
    let path = store.dir.join(CONFIRM_KEY_FILE);
    if let Ok(key) = std::fs::read(&path)
        && key.len() == 32
    {
        return Ok(key);
    }
    let mut key = [0_u8; 32];
    getrandom::fill(&mut key).map_err(|error| format!("random source unavailable: {error}"))?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&path) {
        Ok(mut file) => {
            use std::io::Write as _;
            file.write_all(&key)
                .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
            Ok(key.to_vec())
        }
        // Another process created it first: use theirs.
        Err(_) => std::fs::read(&path)
            .ok()
            .filter(|key| key.len() == 32)
            .ok_or_else(|| format!("cannot create or read {}", path.display())),
    }
}

/// HMAC-SHA256 of `profile` and the exact statement under the store's key, so
/// the audit log binds a token to one statement without letting anyone who
/// reads the log test guesses at a secret inside it.
///
/// # Errors
/// The key could not be created or read.
pub fn keyed_sql_digest(store: &Store, profile: &str, sql: &str) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    let key = confirm_key(store)?;
    let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&key)
        .map_err(|error| format!("bad confirmation key: {error}"))?;
    mac.update(profile.as_bytes());
    mac.update(&[0x1f]);
    mac.update(sql.as_bytes());
    Ok(mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Record a dry run's confirmation on the audit log.
///
/// # Errors
/// The audit log could not be appended.
pub fn record_dry_run(
    store: &Store,
    trace_id: &str,
    issued: &IssuedConfirmation,
) -> Result<String, CacheError> {
    append_audit(
        store,
        "query.write",
        trace_id,
        DRY_RUN_EVENT,
        &serde_json::json!({
            "confirm_id": issued.confirm_id,
            "profile_id": issued.profile,
            "sql_digest": issued.sql_digest,
            "statement_kind": issued.statement_kind,
            "issued_at_ms": issued.issued_at_ms,
        }),
        None,
    )
}

fn audit_events_of(store: &Store, kind: &str) -> Vec<serde_json::Value> {
    store
        .cache
        .audit_events()
        .unwrap_or_default()
        .into_iter()
        .filter(|event| event.event_kind == kind)
        .filter_map(|event| serde_json::from_str(&event.event_json).ok())
        .collect()
}

/// The dry run a confirmation id names, if this store issued it.
#[must_use]
pub fn find_dry_run(store: &Store, confirm_id: &str) -> Option<IssuedConfirmation> {
    audit_events_of(store, DRY_RUN_EVENT)
        .into_iter()
        .find(|event| event["confirm_id"] == confirm_id)
        .map(|event| IssuedConfirmation {
            confirm_id: confirm_id.to_owned(),
            profile: event["profile_id"].as_str().unwrap_or_default().to_owned(),
            sql_digest: event["sql_digest"].as_str().unwrap_or_default().to_owned(),
            statement_kind: event["statement_kind"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            issued_at_ms: event["issued_at_ms"].as_u64().unwrap_or(0),
        })
}

/// The receipt of the completed write that already used this confirmation, if
/// any (tokens are single-use once a write succeeds).
#[must_use]
pub fn confirmation_consumed_by(store: &Store, confirm_id: &str) -> Option<String> {
    audit_events_of(store, CONSUMED_EVENT)
        .into_iter()
        .find(|event| event["confirm_id"] == confirm_id)
        .map(|event| {
            event["receipt_hash"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
}

/// Record that a confirmed write completed, so its token cannot run it again.
///
/// # Errors
/// The audit log could not be appended.
#[cfg(any(feature = "live", test))]
pub fn record_confirmation_consumed(
    store: &Store,
    trace_id: &str,
    confirm_id: &str,
    receipt_hash: Option<&str>,
) -> Result<String, CacheError> {
    append_audit(
        store,
        "query.write",
        trace_id,
        CONSUMED_EVENT,
        &serde_json::json!({ "confirm_id": confirm_id, "receipt_hash": receipt_hash }),
        receipt_hash,
    )
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
    fn record_execution_writes_receipt_partitions_and_audit_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "fsnow-receipt-test-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        let store = Store {
            cache: FileCache::open(&dir)?,
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
            statement_handle: Some("01aa-handle"),
            sql_api_request_id: Some("req-1"),
            query_tag: Some("fsnow:query.run:trace-1"),
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
            terminal_failure: None,
        };
        let hash =
            record_execution(&store, &facts).map_err(|e| format!("receipt recorded: {e}"))?;
        assert_eq!(hash.len(), 64, "blake3 hex digest");

        let receipt = store
            .cache
            .query_receipt(&hash)?
            .ok_or("receipt stored under its content hash")?;
        assert_eq!(receipt.statement_handle.as_deref(), Some("01aa-handle"));
        assert_eq!(receipt.row_count, Some(5));
        assert_eq!(receipt.receipt.address.digest_hex, hash);
        let body: serde_json::Value = serde_json::from_str(&receipt.receipt.canonical)?;
        assert_eq!(body["budget_consumed"]["polls"], 2);
        assert_eq!(body["session"]["warehouse"], "WH");
        assert_eq!(body["session"]["query_tag"], "fsnow:query.run:trace-1");
        assert_eq!(body["build"]["git_sha"], crate::BUILD_GIT_SHA);
        assert_eq!(
            body["build"]["source_digest"].as_str().map(str::len),
            Some(64)
        );
        assert_eq!(store.cache.partitions_for_receipt(&hash)?.len(), 2);
        let events = store.cache.audit_events()?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].receipt_id.as_deref(), Some(hash.as_str()));
        assert_eq!(events[0].event_kind, "statement_executed");
        assert!(
            events[0]
                .event_json
                .contains(&format!("\"build_git_sha\":\"{}\"", crate::BUILD_GIT_SHA)),
            "{}",
            events[0].event_json
        );
        // The plan record links back through the same plan id.
        assert!(store.cache.query_plan(&receipt.plan_id)?.is_some());
        // Re-recording identical facts yields a different receipt only through
        // created_at_ms; the ledger keeps both (append-only).
        let again = record_execution(&store, &facts).map_err(|e| format!("second receipt: {e}"))?;
        assert!(store.cache.query_receipt(&again)?.is_some());

        // A statement cancelled before it had a handle still gets a receipt
        // that says how it ended (reality-check bead C6).
        let cancelled = ExecutionFacts {
            statement_handle: None,
            sql_api_request_id: None,
            row_count: 0,
            partitions: &[],
            columns: &[],
            polls: 0,
            event_kind: "statement_terminal",
            extra: serde_json::json!({}),
            terminal_failure: Some(TerminalFailure {
                outcome_kind: "timeout",
                error_code: "FSNOW-5004",
                message: "the statement was cancelled before completion",
                cancel_kind: Some("Deadline"),
            }),
            ..facts
        };
        let failed = record_execution(&store, &cancelled)
            .map_err(|e| format!("terminal receipt recorded: {e}"))?;
        let record = store
            .cache
            .query_receipt(&failed)?
            .ok_or("terminal receipt stored")?;
        assert_eq!(record.receipt_state, "timed_out");
        assert_eq!(record.outcome_kind, "timeout");
        assert_eq!(record.statement_handle, None);
        let body: serde_json::Value = serde_json::from_str(&record.receipt.canonical)?;
        assert_eq!(body["outcome_kind"], "timeout");
        assert_eq!(body["error"]["code"], "FSNOW-5004");
        assert_eq!(body["error"]["cancel_kind"], "Deadline");
        // The completed receipt carries no `error` key at all.
        let completed = store
            .cache
            .query_receipt(&hash)?
            .ok_or("completed receipt")?;
        let completed: serde_json::Value = serde_json::from_str(&completed.receipt.canonical)?;
        assert!(completed.get("error").is_none(), "{completed}");
        assert_eq!(completed["outcome_kind"], "success");
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Reality-check bead B4: confirmation records bind a random id to one
    /// statement under a keyed digest; consumption is recorded.
    #[test]
    fn confirmations_are_random_keyed_and_single_use() -> Result<(), Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "fsnow-confirm-test-{}-{}",
            std::process::id(),
            now_unix_ms()
        ));
        let store = Store {
            cache: FileCache::open(&dir)?,
            dir: dir.clone(),
        };
        let a = random_id()?;
        let b = random_id()?;
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");

        let digest = keyed_sql_digest(&store, "p", "insert into t values (1)")?;
        assert_eq!(digest.len(), 64);
        // Stable for the same statement under the same key...
        assert_eq!(
            digest,
            keyed_sql_digest(&store, "p", "insert into t values (1)")?
        );
        // ...different for another statement or profile...
        assert_ne!(
            digest,
            keyed_sql_digest(&store, "p", "insert into t values (2)")?
        );
        assert_ne!(
            digest,
            keyed_sql_digest(&store, "q", "insert into t values (1)")?
        );
        // ...and keyed: not the plain SHA-256 of the input.
        use sha2::Digest as _;
        let plain: String = sha2::Sha256::digest(b"p\x1finsert into t values (1)")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_ne!(digest, plain);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(CONFIRM_KEY_FILE))?
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "the key is owner-only");
        }

        let issued = IssuedConfirmation {
            confirm_id: a.clone(),
            profile: "p".to_owned(),
            sql_digest: digest,
            statement_kind: "insert".to_owned(),
            issued_at_ms: now_unix_ms(),
        };
        record_dry_run(&store, "trace-1", &issued)?;
        assert_eq!(find_dry_run(&store, &a), Some(issued));
        assert_eq!(find_dry_run(&store, &b), None);
        assert_eq!(confirmation_consumed_by(&store, &a), None);
        record_confirmation_consumed(&store, "trace-2", &a, Some("receipt-1"))?;
        assert_eq!(
            confirmation_consumed_by(&store, &a).as_deref(),
            Some("receipt-1")
        );
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
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
