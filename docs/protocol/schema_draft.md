# SQL API Protocol Schema Draft (franken-snowflake-sqlapi)

Status: **draft / prep** for bead `fsnow-sqlapi-protocol-schemas-kx6` (Phase 1).
Owner: pane 3 (`franken-snowflake-sqlapi` domain). This is the implementation
contract the `kx6` bead converts into real `serde` types + golden fixtures the
moment it unblocks (it is gated on `fsnow-native-snowflake-connector-w0i.15`, the
shared test/observability harness). Nothing here is committed crate code yet.

Behavioral sources are Snowflake's official docs (clean-room: docs + live
protocol observations + our own fixtures only — never a third-party Rust driver).
Consulted 2026-06-24:

- SQL API overview — https://docs.snowflake.com/en/developer-guide/sql-api/index
- SQL API reference — https://docs.snowflake.com/en/developer-guide/sql-api/reference
- Submitting requests — https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests
- Handling responses — https://docs.snowflake.com/en/developer-guide/sql-api/handling-responses
- Authenticating — https://docs.snowflake.com/en/developer-guide/sql-api/authenticating

The wire-codec timestamp unit is **pinned by an empirically captured live golden**
(`fsnow-native-snowflake-connector-w0i.13`, Phase 7) because the docs are
internally inconsistent (one passage says nanoseconds). Until that golden exists,
the codec follows the fractional-epoch-**seconds** reading and the unit tests are
written to flip in one place if the live golden contradicts them.

## Endpoints

| Operation | Method + path |
|---|---|
| Submit a statement | `POST /api/v2/statements` |
| Check status / fetch rows | `GET /api/v2/statements/{statementHandle}` |
| Fetch partition *n* | `GET /api/v2/statements/{statementHandle}?partition={n}` |
| Cancel a statement | `POST /api/v2/statements/{statementHandle}/cancel` |

Submit query params: `requestId=<uuid>` (idempotency), `retry=true` (safe
resubmit of a non-idempotent POST — returns the prior result if it already ran),
`async=true` (immediate handle), `nullable=<bool>` (how NULL cells render — `null`
vs the string `"null"`; unrelated to `rowType[].nullable`).

## Status-Code Routing (distinct states — never conflated)

This is the load-bearing state machine. Each code is a separate `enum` arm with
its own receipt state and `OutcomeKind`:

| HTTP | Meaning | Body type | Action |
|---|---|---|---|
| `200` | Completed | `ResultSet` | decode rows; fetch remaining partitions |
| `202` | Still running / accepted async | `QueryStatus` | **poll again** (GET the handle / `statementStatusUrl`) |
| `408` | Statement timed out (`STATEMENT_TIMEOUT_IN_SECONDS`) | `QueryFailureStatus` | typed `timeout` outcome (distinct from a SQL failure) |
| `422` | Statement failed (SQL compile/exec error) | `QueryFailureStatus` | typed `error` outcome |
| `429` | Server overloaded / rate limited | (none reliable) | jittered backoff + retry; **never** a query-status code; `Retry-After` not guaranteed |

A 5xx is a transport error (retry the idempotent GET; the POST is retried only via
our own backoff guarded by the `requestId`+`retry` contract). "Cancelled during
TLS connect" is its own receipt state (the handshake is not cancel-safe) — there
is no statement handle yet, so no remote cancel is owed.

## Type Sketch (serde)

Snowflake JSON keys are camelCase, so the default is
`#[serde(rename_all = "camelCase")]`; the few keys that don't fit get explicit
`#[serde(rename = "...")]`. Identifiers reuse the `franken-snowflake-core`
newtypes (`StatementHandle`, `RequestId`, `QueryId`, `SnowflakeErrorCode`). All
numeric-but-string wire fields stay `String` at the schema layer; the **wire
codec** (below), not serde, interprets them.

```rust
// ---- Request ---------------------------------------------------------------
#[serde(rename_all = "camelCase")]
struct SubmitStatementRequest {
    statement: String,                       // the SQL text
    timeout: Option<u32>,                    // server STATEMENT_TIMEOUT_IN_SECONDS
    database: Option<DatabaseName>,
    schema: Option<SchemaName>,
    warehouse: Option<WarehouseName>,
    role: Option<RoleName>,
    bindings: Option<BTreeMap<String, Binding>>,  // 1-based string keys, ordered
    parameters: Option<BTreeMap<String, String>>, // session params (see below)
}

#[serde(rename_all = "UPPERCASE")]           // type tag is UPPERCASE on the wire
struct Binding { r#type: BindType, value: String } // value is ALWAYS a JSON string

// ---- 200: completed --------------------------------------------------------
#[serde(rename_all = "camelCase")]
struct ResultSet {
    result_set_meta_data: ResultSetMetaData,
    data: Vec<Vec<Option<String>>>,          // jsonv2: every non-null cell is a String
    code: String,
    statement_handle: StatementHandle,
    statement_status_url: Option<String>,
    statement_handles: Option<Vec<StatementHandle>>, // multi-statement fan-out
    sql_state: Option<String>,
    message: Option<String>,
    request_id: Option<RequestId>,
    created_on: Option<i64>,
    stats: Option<serde_json::Value>,
}

#[serde(rename_all = "camelCase")]
struct ResultSetMetaData {
    num_rows: i64,                           // total across ALL partitions
    format: String,                          // "jsonv2"
    row_type: Vec<ColumnType>,
    partition_info: Vec<PartitionInfo>,      // partition 0 is inline with this body
}

#[serde(rename_all = "camelCase")]
struct ColumnType {
    name: String,
    r#type: String,                          // FIXED|REAL|TEXT|BOOLEAN|DATE|TIME|
                                             // TIMESTAMP_*|VARIANT|OBJECT|ARRAY|BINARY...
    scale: Option<i32>,
    precision: Option<i32>,
    nullable: bool,                          // column nullability (NOT the `nullable` param)
    length: Option<i64>,
    byte_length: Option<i64>,
    database: Option<String>, schema: Option<String>, table: Option<String>,
    collation: Option<String>,
}

#[serde(rename_all = "camelCase")]
struct PartitionInfo { row_count: i64, compressed_size: i64, uncompressed_size: i64 }

// ---- 202: running ----------------------------------------------------------
#[serde(rename_all = "camelCase")]
struct QueryStatus {
    code: String, sql_state: Option<String>, message: Option<String>,
    statement_handle: StatementHandle, statement_status_url: Option<String>,
}

// ---- 408/422: timeout / failure -------------------------------------------
#[serde(rename_all = "camelCase")]
struct QueryFailureStatus {
    code: String, sql_state: Option<String>, message: String,
    statement_handle: Option<StatementHandle>,
}

// ---- cancel ----------------------------------------------------------------
#[serde(rename_all = "camelCase")]
struct StatementCancelResponse { code: String, message: Option<String>, statement_handle: Option<StatementHandle> }
```

`data` cells are `Option<String>`: SQL `NULL` deserializes to JSON `null` →
`None` (the default `nullable` behavior); with `nullable=false` Snowflake renders
the literal string `"null"`, which the codec layer treats as a value, not a NULL.

### Partitions

Partition 0 ships inline in the first 200 body. Partitions `1..N` are fetched with
`GET ...?partition=n` and **do not repeat metadata**; their bodies are the bare
`data` array and may be `Content-Encoding: gzip` (decompressed manually via
`GzipDecompressor` — not auto-applied; see `docs/asupersync_leverage.md`).

### Session parameters to pin (determinism)

`TIMEZONE`, the `*_OUTPUT_FORMAT` params (`DATE_OUTPUT_FORMAT`,
`TIME_OUTPUT_FORMAT`, `TIMESTAMP_*_OUTPUT_FORMAT`), `BINARY_OUTPUT_FORMAT`,
`USE_CACHED_RESULT`, and `MULTI_STATEMENT_COUNT` (exact N, or `0` for variable).
Pin these in the request rather than relying on account defaults. Bindings are
**not** supported in multi-statement mode (a refusal case).

## jsonv2 Wire Codec (where bugs hide)

The schema keeps cells as `String`; this codec decodes each per its `rowType`
entry (matched **case-insensitively**), never by JSON shape:

| Snowflake type | Wire string | Decode rule |
|---|---|---|
| `FIXED`/`NUMBER` | plain decimal `"1.0"` | parse decimal directly — do **not** divide by 10^scale |
| `REAL`/`FLOAT` | numeric string (sci. past 38 digits) | float / arbitrary-precision decimal |
| `BOOLEAN` | `"true"`/`"false"` | string compare, not JSON bool |
| `DATE` | days since epoch `"18262"` | epoch-day → date |
| `TIME`,`TIMESTAMP_NTZ`,`TIMESTAMP_LTZ` | fractional epoch **seconds** `"82919.000000000"` | seconds (not nanos) → timestamp |
| `TIMESTAMP_TZ` | `"<epoch_sec.frac> <offset>"` | offset = minutes encoded as `offset_minutes + 1440` |
| `BINARY` | hex string | hex-decode |
| `VARIANT`/`OBJECT`/`ARRAY` | embedded JSON text | preserve as structured JSON |
| SQL `NULL` | JSON `null` (or `"null"` if `nullable` off) | NULL |

## Golden-Fixture Plan

Fixtures live under `crates/franken-snowflake-sqlapi/tests/fixtures/` (request +
response JSON, lowercase names, `eol=lf` per `.gitattributes`, compared as raw
bytes). Each proves one routing/codec behavior so a regression names itself:

| Fixture | Proves |
|---|---|
| `submit_select_request.json` | request serialization: statement + db/schema/wh/role + params |
| `submit_with_bindings_request.json` | positional typed bindings `{"1":{type,value}}` |
| `resp_200_resultset_single_partition.json` | 200 decode; `rowType`/`numRows`/inline partition 0 |
| `resp_200_resultset_multi_partition.json` | `partitionInfo[]` with 3 partitions; `numRows` = sum |
| `partition_1.json` + `partition_1.json.gz` | bare-array later partition + gzip variant decode to identical rows |
| `resp_202_running.json` | 202 → `QueryStatus`; poll-again, not an error |
| `resp_408_statement_timeout.json` | 408 → typed timeout, distinct from 422 |
| `resp_422_failure.json` | 422 → `QueryFailureStatus` (code/sqlState/message) |
| `resp_429_overloaded.json` | 429 body + header shape; backoff path, never a status code |
| `idempotent_resubmit_request.json` | `requestId`+`retry=true` resubmit returns prior result |
| `multi_statement_count_request.json` + `resp_200_statement_handles.json` | `MULTI_STATEMENT_COUNT` + `statementHandles[]` fan-out |
| `multi_statement_with_bindings_refusal.json` | bindings + multi-statement → typed refusal |
| `jsonv2_codec_cells.json` | one row per type covering every wire-codec rule above |
| `cancel_response.json` | cancel endpoint response shape |

Round-trip discipline: deserialize → re-serialize → key-sorted byte-compare
against the golden (canonicalizing time/host/hash fields; IEEE-754 bits reported
on float mismatch), per `docs/proof_lanes.md` Lane 1 and the shared harness from
`w0i.15`. The DPOR cancel/retry race coverage (Lane 2) layers on top once the
transport (`fsnow-asupersync-native-https-ofq`) and lifecycle
(`fsnow-statement-lifecycle-ofl`) land.
