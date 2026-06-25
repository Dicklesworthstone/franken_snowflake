# Cache Repository Design

Date: 2026-06-25

Status: prep for bead `fsnow-local-cache-repository-afb`; owner lane is pane 9
(`franken-snowflake-cache`, `franken-snowflake-frame`, and
`franken-snowflake-export`). This document pins the first
`franken-snowflake-cache` design before the crate exists. The implementation must
use FrankenSQLite through the `sqlmodel-frankensqlite` driver where typed models
improve clarity; it must not use the C-FFI `sqlmodel-sqlite` driver, and it must
not store Snowflake secrets.

The cache is local, durable metadata for agent workflows. It is not a shared
coordination service, not a credential store, and not a replacement for
Snowflake's own result cache. Its job is to make catalog discovery, query planning,
query receipts, replay, and `RESULT_SCAN` reuse deterministic and auditable.

## Scope

The first cache crate owns:

- profile records without secret values;
- catalog snapshots and offline catalog replay bundles;
- dataset manifests, column catalogs, and operator catalogs;
- normalized query plans and their pushed-down SQL;
- query receipts keyed by content hash and normalized-plan hash;
- result partition metadata and per-partition byte/hash evidence;
- cost, row-count, and export histories;
- append-only query audit events.

The cache does not own:

- raw PATs, OAuth bearer tokens, private keys, refresh tokens, or account secrets;
- large result payload storage;
- frame materialization internals;
- export file writing;
- cross-agent distributed cache semantics.

## Backend Boundary

Expose all durable state through a backend trait so tests can use an in-memory or
fixture backend while production uses FrankenSQLite:

```rust
pub trait CacheBackend {
    type Error;

    fn schema_version(&self) -> Result<SchemaVersion, Self::Error>;
    fn profiles(&self) -> &dyn ProfileRepository<Error = Self::Error>;
    fn catalog_snapshots(&self) -> &dyn CatalogSnapshotRepository<Error = Self::Error>;
    fn dataset_manifests(&self) -> &dyn DatasetManifestRepository<Error = Self::Error>;
    fn query_plans(&self) -> &dyn QueryPlanRepository<Error = Self::Error>;
    fn query_receipts(&self) -> &dyn QueryReceiptRepository<Error = Self::Error>;
    fn partition_metadata(&self) -> &dyn PartitionMetadataRepository<Error = Self::Error>;
    fn audit_log(&self) -> &dyn AuditLogRepository<Error = Self::Error>;
}
```

`FrankenSqliteCache` is the default backend. A future shared backend can implement
the same trait, but it must remain opt-in and must keep the same no-secret
contract.

## Concurrency Model

`fsqlite::Connection` is `!Send`. The production backend should own one local
connection behind serialized access. This is acceptable because the cache is
read-mostly and local. Do not hide the model behind an async facade that implies
concurrent database access; expose blocking repository calls and let higher layers
schedule them under an Asupersync capability/budget boundary.

Implementation notes:

- use one writer at a time;
- keep transactions short and explicit;
- record `last_insert_rowid` through the adapter-tracked path, not ad hoc SQL;
- avoid long-running migrations while a query lifecycle is active;
- add a serialized-access test that proves concurrent callers are ordered rather
  than racing the `!Send` connection.

## Logical Schema

The SQL below is the intended shape, not a final migration file. Migrations must
be explicit, versioned, and reversible where data loss is not inherent.

### `schema_migrations`

Tracks applied migrations.

| Column | Type | Notes |
|---|---|---|
| `version` | INTEGER PRIMARY KEY | Monotonic migration version. |
| `name` | TEXT NOT NULL | Stable migration name. |
| `applied_at_ms` | INTEGER NOT NULL | Deterministic clock in tests. |
| `content_hash` | TEXT NOT NULL | Hash of migration text. |

### `profiles`

Stores profile metadata only. Secret fields store environment variable names or
secret-provider handles, never raw secret values.

| Column | Type | Notes |
|---|---|---|
| `profile_id` | TEXT PRIMARY KEY | Stable local profile id. |
| `display_name` | TEXT NOT NULL | Human-readable label. |
| `account_locator_redacted` | TEXT | Redacted account identifier, optional. |
| `auth_lane` | TEXT NOT NULL | `pat`, `key_pair_jwt`, `oauth`, or future lane. |
| `credential_ref_kind` | TEXT NOT NULL | `env`, `provider`, or `none`. |
| `credential_ref_name` | TEXT | Env var or provider handle name. |
| `default_database` | TEXT | Optional default. |
| `default_schema` | TEXT | Optional default. |
| `default_warehouse` | TEXT | Optional default. |
| `default_role` | TEXT | Optional default. |
| `created_at_ms` | INTEGER NOT NULL | Deterministic in tests. |
| `updated_at_ms` | INTEGER NOT NULL | Updated on metadata changes. |

Secret-free invariants:

- no column named `token`, `secret`, `private_key`, `password`, or `bearer`;
- `credential_ref_name` is a reference name, not a value;
- `Debug`, JSON, and test logs must redact account identifiers when requested;
- canary-secret tests scan all serialized profile output.

### `catalog_snapshots`

An immutable snapshot of catalog discovery output from `INFORMATION_SCHEMA` or an
offline replay bundle.

| Column | Type | Notes |
|---|---|---|
| `snapshot_id` | TEXT PRIMARY KEY | BLAKE3 over canonical payload. |
| `profile_id` | TEXT NOT NULL | FK to `profiles`. |
| `source_kind` | TEXT NOT NULL | `information_schema`, `fixture`, or `replay`. |
| `database_name` | TEXT | Optional scope. |
| `schema_name` | TEXT | Optional scope. |
| `captured_at_ms` | INTEGER NOT NULL | Deterministic in tests. |
| `payload_json` | TEXT NOT NULL | Canonical JSON. |
| `payload_hash` | TEXT NOT NULL | BLAKE3 over canonical bytes. |
| `payload_bytes` | INTEGER NOT NULL | Byte-length verification. |

Indexes:

- `(profile_id, captured_at_ms DESC)`
- `(profile_id, database_name, schema_name, captured_at_ms DESC)`
- `(payload_hash)`

### `catalog_objects` and `catalog_columns`

Derived searchable tables for object and column lookup. The canonical snapshot
payload remains in `catalog_snapshots`.

`catalog_objects`:

| Column | Type | Notes |
|---|---|---|
| `object_id` | TEXT PRIMARY KEY | Stable hash of profile + fully qualified name. |
| `snapshot_id` | TEXT NOT NULL | FK to snapshot. |
| `database_name` | TEXT NOT NULL | Snowflake database. |
| `schema_name` | TEXT NOT NULL | Snowflake schema. |
| `object_name` | TEXT NOT NULL | Table, view, or function. |
| `object_kind` | TEXT NOT NULL | `table`, `view`, etc. |
| `comment` | TEXT | Optional. |
| `tags_json` | TEXT | Optional canonical JSON. |

`catalog_columns`:

| Column | Type | Notes |
|---|---|---|
| `column_id` | TEXT PRIMARY KEY | Stable hash of object + column name. |
| `object_id` | TEXT NOT NULL | FK to catalog object. |
| `ordinal` | INTEGER NOT NULL | Column order. |
| `column_name` | TEXT NOT NULL | Snowflake column. |
| `logical_type` | TEXT NOT NULL | Snowflake logical type. |
| `precision` | INTEGER | Numeric precision. |
| `scale` | INTEGER | Numeric scale. |
| `nullable` | INTEGER NOT NULL | Boolean as 0/1. |
| `length` | INTEGER | Character length. |
| `semantic_role` | TEXT | Candidate role, if discovered. |

Indexes:

- `(snapshot_id, database_name, schema_name, object_name)` on objects;
- `(object_id, ordinal)` on columns;
- `(object_id, lower(column_name))` on columns.

### `dataset_manifests`

Stores the three-part dataset manifest model from
`docs/dataset_manifest_contract.md`.

| Column | Type | Notes |
|---|---|---|
| `dataset_id` | TEXT PRIMARY KEY | Public dataset id. |
| `profile_id` | TEXT NOT NULL | FK to profile. |
| `snapshot_id` | TEXT | Catalog snapshot used to derive it. |
| `database_name` | TEXT NOT NULL | Target database. |
| `schema_name` | TEXT NOT NULL | Target schema. |
| `object_name` | TEXT NOT NULL | Target object. |
| `object_kind` | TEXT NOT NULL | `table`, `view`, etc. |
| `rights_class` | TEXT NOT NULL | Fail-closed rights label. |
| `default_limit` | INTEGER NOT NULL | Interactive default. |
| `max_rows_without_export` | INTEGER NOT NULL | Export threshold. |
| `manifest_json` | TEXT NOT NULL | Canonical manifest. |
| `manifest_hash` | TEXT NOT NULL | BLAKE3 over canonical bytes. |
| `created_at_ms` | INTEGER NOT NULL | Deterministic in tests. |

Indexes:

- `(profile_id, dataset_id)`;
- `(profile_id, database_name, schema_name, object_name)`;
- `(manifest_hash)`.

### `query_plans`

Stores deterministic plans, not raw secrets or volatile handles.

| Column | Type | Notes |
|---|---|---|
| `plan_id` | TEXT PRIMARY KEY | Normalized-plan hash. |
| `profile_id` | TEXT NOT NULL | FK to profile. |
| `dataset_id` | TEXT | Dataset mode, optional. |
| `mode` | TEXT NOT NULL | `raw_sql` or `dataset`. |
| `normalized_sql_hash` | TEXT NOT NULL | Hash of canonical SQL. |
| `normalized_sql_redacted` | TEXT NOT NULL | SQL with literals/binds redacted. |
| `bindings_shape_json` | TEXT NOT NULL | Types and positions, no secret values. |
| `safety_class` | TEXT NOT NULL | Planner safety classification. |
| `estimated_row_limit` | INTEGER | Planner limit. |
| `requires_export` | INTEGER NOT NULL | 0/1. |
| `created_at_ms` | INTEGER NOT NULL | Deterministic in tests. |

Indexes:

- `(profile_id, plan_id)`;
- `(profile_id, normalized_sql_hash)`;
- `(dataset_id, created_at_ms DESC)`.

### `query_receipts`

Receipts are append-only records of a query lifecycle. They are content-addressed
and link a normalized plan to Snowflake's statement handle/query id when those
exist.

| Column | Type | Notes |
|---|---|---|
| `receipt_id` | TEXT PRIMARY KEY | BLAKE3 over canonical receipt JSON. |
| `plan_id` | TEXT NOT NULL | FK to query plan. |
| `profile_id` | TEXT NOT NULL | FK to profile. |
| `command_id` | TEXT NOT NULL | CLI/MCP command id. |
| `trace_id` | TEXT NOT NULL | End-to-end trace id. |
| `outcome_kind` | TEXT NOT NULL | `ok`, `error`, `cancelled`, or `panicked`. |
| `receipt_state` | TEXT NOT NULL | More specific lifecycle state. |
| `statement_handle` | TEXT | Snowflake statement handle if submitted. |
| `snowflake_query_id` | TEXT | Used for `RESULT_SCAN`. |
| `request_id` | TEXT | Idempotent submit UUID. |
| `query_tag` | TEXT | Snowflake `QUERY_TAG`. |
| `row_count` | INTEGER | Total rows, if known. |
| `compressed_bytes` | INTEGER | Sum across partitions, if known. |
| `uncompressed_bytes` | INTEGER | Sum across partitions, if known. |
| `cost_vector_json` | TEXT NOT NULL | Warehouse/cost telemetry. |
| `redaction_evidence_json` | TEXT NOT NULL | Proof of secret-free serialization. |
| `receipt_json` | TEXT NOT NULL | Canonical receipt payload. |
| `receipt_bytes` | INTEGER NOT NULL | Byte-length verification. |
| `created_at_ms` | INTEGER NOT NULL | Deterministic in tests. |

Result-cache indexes:

- `(profile_id, plan_id, created_at_ms DESC)` for latest receipt by plan;
- `(profile_id, normalized_plan_hash, created_at_ms DESC)` if denormalized;
- `(profile_id, snowflake_query_id)` for `RESULT_SCAN`;
- `(profile_id, statement_handle)` for cancel/status lookup;
- `(command_id)` and `(trace_id)` for diagnostics;
- `(outcome_kind, created_at_ms DESC)` for failure triage.

The `RESULT_SCAN` lookup path is: normalized plan hash -> latest successful
receipt -> `snowflake_query_id` -> age/retention check -> re-fetch plan. If the
receipt is too old for Snowflake's result-cache retention, return a typed refusal
or run a fresh query according to the caller's policy.

### `partition_metadata`

Stores per-partition evidence for receipts.

| Column | Type | Notes |
|---|---|---|
| `receipt_id` | TEXT NOT NULL | FK to receipt. |
| `partition_index` | INTEGER NOT NULL | 0-based partition number. |
| `row_count` | INTEGER NOT NULL | Rows in partition. |
| `compressed_bytes` | INTEGER | Snowflake compressed size. |
| `uncompressed_bytes` | INTEGER | Snowflake uncompressed size. |
| `payload_hash` | TEXT | BLAKE3 if captured. |
| `content_encoding` | TEXT | `identity`, `gzip`, etc. |

Primary key: `(receipt_id, partition_index)`.

### `exports`

Tracks export records without owning export writer internals.

| Column | Type | Notes |
|---|---|---|
| `export_id` | TEXT PRIMARY KEY | BLAKE3 over canonical export record. |
| `receipt_id` | TEXT NOT NULL | FK to query receipt. |
| `export_kind` | TEXT NOT NULL | `copy_into`, `local_csv`, `local_jsonl`. |
| `target_uri_redacted` | TEXT NOT NULL | Redacted location or local path. |
| `content_hash` | TEXT NOT NULL | Export record hash. |
| `byte_len` | INTEGER NOT NULL | Byte-length verification. |
| `row_count` | INTEGER | Rows exported, if known. |
| `created_at_ms` | INTEGER NOT NULL | Deterministic in tests. |

Indexes:

- `(receipt_id, created_at_ms DESC)`;
- `(content_hash)`;
- `(export_kind, created_at_ms DESC)`.

### `offline_replay_bundles`

Stores pointers and hashes for offline replay data, not arbitrary unbounded files.

| Column | Type | Notes |
|---|---|---|
| `bundle_id` | TEXT PRIMARY KEY | Stable bundle id. |
| `source_receipt_id` | TEXT | Optional source receipt. |
| `snapshot_id` | TEXT | Optional catalog snapshot. |
| `artifact_dir` | TEXT NOT NULL | Relative run-dir path or content-addressed root. |
| `manifest_json` | TEXT NOT NULL | Canonical bundle manifest. |
| `manifest_hash` | TEXT NOT NULL | BLAKE3 over canonical bytes. |
| `created_at_ms` | INTEGER NOT NULL | Deterministic in tests. |

### `query_audit_log`

Append-only audit events. No UPDATE or DELETE migration/query is allowed against
this table after insertion.

| Column | Type | Notes |
|---|---|---|
| `event_id` | TEXT PRIMARY KEY | BLAKE3 over canonical event JSON. |
| `receipt_id` | TEXT | Optional FK to receipt. |
| `command_id` | TEXT NOT NULL | Command id. |
| `trace_id` | TEXT NOT NULL | Trace id. |
| `event_kind` | TEXT NOT NULL | `planned`, `submitted`, `cancelled`, etc. |
| `event_json` | TEXT NOT NULL | Canonical event. |
| `created_at_ms` | INTEGER NOT NULL | Deterministic in tests. |

Append-only enforcement:

- migration lint rejects `UPDATE query_audit_log` and `DELETE FROM query_audit_log`;
- repository APIs expose `append` and read methods only;
- tests inject a forbidden migration/query and assert the gate fails;
- audit events are canonicalized before hashing so repeated inserts are
  idempotent by `event_id`.

## Repository API Slices

Keep repositories small and domain-shaped:

- `ProfileRepository`: upsert/get/list profile metadata, validate no-secret
  fields, never expose raw credentials.
- `CatalogSnapshotRepository`: insert immutable snapshots, derive/search objects
  and columns, fetch latest snapshot by profile/scope.
- `DatasetManifestRepository`: store/get/list manifests, resolve by dataset id,
  check rights class and row-limit policy.
- `QueryPlanRepository`: insert normalized plans, find by `plan_id` or SQL hash,
  link raw SQL and dataset-mode plans to their safety metadata.
- `QueryReceiptRepository`: append receipts, fetch latest successful receipt by
  plan, resolve `RESULT_SCAN` candidate by `snowflake_query_id`.
- `PartitionMetadataRepository`: append per-partition metadata and verify
  aggregate row/byte counts against the receipt.
- `ExportRepository`: append content-addressed export records and query by
  receipt/hash.
- `AuditLogRepository`: append and scan audit events only.

## Hashing And Canonicalization

Use BLAKE3 for content addresses. Hash canonical UTF-8 JSON bytes with sorted
object keys and deterministic numeric/string encoding. Store both hash and byte
length for receipts, snapshots, exports, and replay bundle manifests.

Minimum hash inputs:

- `snapshot_id`: canonical catalog snapshot payload;
- `manifest_hash`: canonical dataset manifest;
- `plan_id`: profile id + normalized SQL + typed binding shape + safety policy;
- `receipt_id`: canonical receipt payload excluding database row metadata;
- `export_id`: canonical export record;
- `event_id`: canonical audit event.

Tests must include a byte-length mismatch refusal and a changed-payload
hash-mismatch refusal.

## Frame And Export Constraints

The cache crate may reference frame/export records, but it must not pull their
heavy optional dependencies into the default graph.

Frame materialization:

- use `fp-columnar` and `fp-types` only;
- add `fp-frame` only when full DataFrame semantics are required;
- never depend on the umbrella `frankenpandas` crate;
- never depend on `fp-io`, because its non-optional `orc-rust` dependency pulls
  Tokio;
- preserve Snowflake logical type alongside lossy frame dtypes.

Export:

- `COPY INTO <location>` is the primary large-export path;
- local export is CSV/JSONL only;
- local writers are hand-written or use `fp-columnar` alone;
- ORC is out of scope;
- Arrow IPC remains deferred until a forbidden-dependency-clean writer is proven;
- export records are content-addressed and byte-length verified in the cache.

## Cross-Platform Constraint

Do not target the cache crate for Windows until the upstream FrankenSQLite
prerequisite is fixed: `fsqlite-vfs` and `fsqlite-mvcc` currently gate the
Unix-only `nix` dependency under `cfg(not(target_arch = "wasm32"))`, which is true
on Windows. The dependency must be re-gated to `cfg(unix)` upstream, and
FrankenSQLite CI must include a full-workspace Windows build before this cache
crate can claim Windows support.

The cache crate itself should still avoid Unix path assumptions. Use the shared
config/cache/artifact directory policy: explicit flag > environment variable >
platform default.

## Test Plan For `afb`

The implementation bead should land no-account tests before live behavior:

- migration up/down test with `schema_migrations`;
- repository CRUD tests per entity;
- secret-free profile storage test with planted canary values;
- receipt content-addressing and byte-length verification tests;
- latest-successful-receipt lookup by normalized plan hash;
- `RESULT_SCAN` candidate lookup with retention-age refusal;
- partition metadata aggregate verification;
- append-only audit-log gate test that rejects UPDATE/DELETE;
- serialized-access test documenting the `!Send` connection model;
- export-record hash/byte-length test for local CSV/JSONL and `COPY INTO` plans;
- structured JSON-line logs through the shared test harness once `w0i.15` lands.

No live Snowflake credentials are required for these tests.
