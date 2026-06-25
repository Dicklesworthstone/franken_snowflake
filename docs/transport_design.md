# Asupersync-Native HTTPS Transport Design

Date: 2026-06-25
Status: design artifact for `fsnow-asupersync-native-https-ofq`; crate work waits
until `fsnow-native-snowflake-connector-w0i.3` and
`fsnow-native-snowflake-connector-w0i.6` land.

This document defines the intended `franken-snowflake-http` boundary before the
crate exists. It is the implementation contract for Snowflake SQL API transport:
native HTTPS on Asupersync, pooled HTTP/1.1 connections, explicit TLS root
policy, deterministic retry budgets, manual gzip partition handling, and
cancel-correct statement cleanup. Production code in this layer must not depend
on Tokio, reqwest, hyper, axum, tower, sqlx, diesel, sea-orm, or any
third-party Snowflake driver.

Authoritative project references:

- `AGENTS.md`
- `README.md`
- `docs/asupersync_leverage.md`
- `COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md`
- Snowflake SQL API docs recorded in the comprehensive plan on 2026-06-24:
  `https://docs.snowflake.com/en/developer-guide/sql-api/index`

## Scope

The HTTP crate owns transport effects only. It does not own SQL API schemas,
auth signing, result decoding, catalog semantics, receipts, CLI envelopes, or
live credential discovery. It accepts typed request bodies and auth/header
inputs from upstream crates, performs bounded HTTPS calls, and returns typed
transport outcomes plus redacted attempt evidence.

Initial operations:

- submit a SQL API statement with `POST /api/v2/statements`
- poll a statement with `GET /api/v2/statements/{statementHandle}`
- fetch a result partition with
  `GET /api/v2/statements/{statementHandle}?partition=<n>`
- cancel a statement with
  `POST /api/v2/statements/{statementHandle}/cancel`
- stream multiple partitions under one bounded Asupersync region

Non-goals for this crate:

- no SQL parsing or statement safety checks
- no credential lookup or JWT signing
- no JSON envelope or process exit-code policy
- no local cache, receipt store, or catalog graph
- no fallback from live transport to fixtures

## Asupersync Contract

Every effectful transport API takes `&Cx` first. The transport boundary receives
a narrowed context with IO, TIME, and SPAWN authority, but never REMOTE. Pure
planning code stays outside this crate and can use `cx_readonly()` /
`Cx<cap::None>`.

Cancellation remains a first-class outcome. The transport layer must preserve
these distinctions for the SQL API and CLI layers:

- cancelled before a statement handle exists
- cancelled during connect or TLS handshake
- cancelled after submit, requiring remote cancel
- deadline or poll-quota budget exhaustion
- server statement timeout (`408`)
- query failure (`422`)
- overload or rate limit (`429`)
- ordinary network/protocol error

The submitted statement handle is an obligation. Once a handle exists, local
user cancellation, deadline cancellation, or parent-region cancellation must
attempt a bounded remote cancel unless policy explicitly says to drain quietly
(`RaceLost` or `ParentCancelled`).

## Public API Shape

Names are provisional, but the shape is intentional.

```rust,ignore
pub struct SnowflakeHttpClient {
    config: TransportConfig,
    pool: ConnectionPool,
}

impl SnowflakeHttpClient {
    pub async fn submit_statement(
        &self,
        cx: &Cx,
        request: SubmitHttpRequest,
    ) -> TransportOutcome<SubmitHttpResponse>;

    pub async fn poll_statement(
        &self,
        cx: &Cx,
        request: PollHttpRequest,
    ) -> TransportOutcome<PollHttpResponse>;

    pub async fn fetch_partition(
        &self,
        cx: &Cx,
        request: PartitionHttpRequest,
    ) -> TransportOutcome<PartitionBody>;

    pub async fn stream_partitions(
        &self,
        cx: &Cx,
        request: PartitionStreamRequest,
        sink: impl PartitionSink,
    ) -> TransportOutcome<PartitionStreamSummary>;

    pub async fn cancel_statement(
        &self,
        cx: &Cx,
        request: CancelHttpRequest,
    ) -> TransportOutcome<CancelHttpResponse>;
}
```

`TransportOutcome<T>` should preserve the Asupersync four-state outcome until a
higher policy layer maps it to an envelope. Domain errors use stable transport
codes, not free-form strings.

```rust,ignore
pub enum TransportErrorCode {
    TlsRootPolicyRefused,
    InvalidSnowflakeHost,
    BodyLimitExceeded,
    HeaderRejected,
    RetryBudgetExhausted,
    CancelledDuringConnect,
    CancelAfterSubmitFailed,
    HttpStatusUnexpected,
    ResponseDecodeFailed,
    GzipDecodeFailed,
}
```

## Configuration

```rust,ignore
pub struct TransportConfig {
    pub endpoint: SnowflakeEndpoint,
    pub tls_roots: TlsRootPolicy,
    pub pool: PoolConfig,
    pub limits: BodyLimits,
    pub retry: RetryPolicy,
    pub log: AttemptLogPolicy,
}

pub enum TlsRootPolicy {
    NativeRoots,
    ExplicitPemBundle(PathBuf),
    TestOnlyInsecureDisabledByDefault,
}

pub struct BodyLimits {
    pub max_submit_response_bytes: u64,
    pub max_poll_response_bytes: u64,
    pub max_partition_compressed_bytes: u64,
    pub max_partition_uncompressed_bytes: u64,
}
```

TLS uses Asupersync native TLS/rustls support with `tls` and
`tls-native-roots`. The default is `NativeRoots`. Test-only insecure transport
is not compiled into production features and must never silently activate.

The endpoint type validates:

- HTTPS scheme only
- Snowflake account host form from the profile layer
- no embedded credentials
- no query string on base endpoint
- canonical path joining for `/api/v2/statements`

## Header Construction

The auth crate supplies a redacted authorization descriptor. The HTTP crate only
turns that descriptor into wire headers and logs redacted fingerprints.

Required headers:

- `Authorization: Bearer <token-or-jwt>`
- `X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN`,
  `KEYPAIR_JWT`, or OAuth equivalent
- `Content-Type: application/json`
- `Accept: application/json`
- request correlation header once the project standardizes its exact name

Optional headers:

- query tag metadata, when represented as SQL API parameters upstream
- request fingerprint header, if the project adopts one for diagnostics

Never log raw `Authorization`, token type payloads, private key material,
account identifiers when redaction asks for them, or full SQL text when the
caller requests redacted evidence. Attempt logs use a hash of the canonical
redacted request: method, route kind, request id, statement handle if present,
partition index if present, retry attempt, and body hash.

## Request Submission

Submit uses `POST /api/v2/statements`. The SQL API crate owns the body schema:
statement text, binds, parameters, async mode, nullable handling, and request id.
The HTTP crate enforces the transport semantics:

1. Build the canonical URI.
2. Attach auth and deterministic headers.
3. Apply body-size limits before sending.
4. Send over a pooled HTTPS HTTP/1.1 connection.
5. Route the status code without conflating protocol states.
6. Emit one redacted JSON-line attempt log.

Submit retry is special. The Asupersync client retry layer must not retry the
initial POST as if it were idempotent. Custom submit retry is allowed only when
the upstream request carries a stable Snowflake `requestId` and the resubmitted
URI includes `retry=true`. Without those inputs, submit retry is refused before
the first retry attempt.

Status routing:

- `200`: completed result body
- `202`: accepted or still running body
- `408`: server-side statement timeout
- `422`: query failure body
- `429`: overload/rate limit, eligible for retry if budget remains
- `5xx`: eligible for retry if policy and budget allow
- other status: typed transport/protocol error

## Polling

Polling uses `GET /api/v2/statements/{statementHandle}` and is idempotent.
The Asupersync service/retry stack may help here, but this crate still owns the
overall retry budget and status-code routing.

Polling loops must call `cx.checkpoint()` on every iteration. The loop stops on:

- completed result (`200`)
- query still running (`202`) with poll quota exhausted
- server timeout (`408`)
- query failure (`422`)
- local cancellation or parent-region cancellation
- retry budget exhaustion
- body-limit refusal

Poll cadence is budgeted. The retry/backoff scheduler consumes a total retry
budget, not merely per-attempt sleeps.

## Partition Fetching

Partition zero normally arrives inline with the completed result response. Later
partitions use:

```text
GET /api/v2/statements/{statementHandle}?partition=<n>
```

The partition fetcher must:

- inherit a tighter child budget via `meet()`
- run fetchers under one bounded `Scope`
- cap concurrent partition downloads
- preserve result ordering for the downstream consumer
- enforce compressed and uncompressed byte limits
- checkpoint before each network call and before each sink write
- drain or cancel sibling fetchers when the parent region is cancelled

`stream_partitions` should not require holding the full result set in memory.
It hands each decoded partition body to a sink that can feed the SQL API decoder,
frame materializer, local export writer, or test harness.

```rust,ignore
pub trait PartitionSink {
    async fn accept(
        &mut self,
        cx: &Cx,
        partition: DecodedPartition,
    ) -> Result<(), TransportError>;
}
```

## Gzip Handling

Asupersync response JSON helpers return raw bytes; gzip is not automatic.
Snowflake later partition responses can carry `Content-Encoding: gzip`. The
HTTP crate checks that header and manually wires Asupersync's gzip decompressor
from the `compression` feature.

Rules:

- only decompress when `Content-Encoding` says gzip
- fail closed on unknown content encodings
- count both compressed and uncompressed bytes
- enforce expansion limits during streaming decompression
- surface gzip failures as `GzipDecodeFailed`
- include compression metadata in redacted attempt evidence

The crate should support a raw-bytes test seam so no-account fixtures can prove
gzip partition handling without live Snowflake credentials.

## Cancellation

The transport layer has three cancellation phases:

1. Before connect or before submit reaches Snowflake: local cancellation only.
2. During TCP connect or TLS handshake: drop the connection and return
   `CancelledDuringConnect`; TLS handshake is not assumed cancel-safe.
3. After a statement handle exists: enter bounded cleanup and call the remote
   cancel endpoint.

Remote cancel is masked only for the narrow cleanup section and only with a
short cleanup budget. Cleanup evidence records:

- statement handle
- cancellation reason kind
- cancel endpoint status
- whether cancel was skipped by policy
- whether cleanup budget expired
- redacted attempt fingerprint

Local cancellation must not turn into an ordinary network error. The caller must
be able to distinguish user cancellation, deadline exhaustion, cost-budget
breach, shutdown, and race-loser drain.

## Retry Budget And Backoff

Retry policy is explicit input, not ambient behavior.

```rust,ignore
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay_ms: u64,
    pub max_delay_ms: u64,
    pub total_budget_ms: u64,
    pub respect_retry_after: bool,
    pub deterministic_jitter: bool,
}
```

Backoff order:

1. If `Retry-After` is present and policy allows it, use it within the remaining
   budget.
2. Otherwise use capped exponential backoff.
3. Add deterministic jitter derived from request id, route kind, and attempt
   number. Do not use ambient randomness.
4. Stop before sleeping if the retry budget or parent budget is exhausted.

Retryable cases:

- `429`
- transient `5xx`
- connection reset before response when the operation is idempotent
- submit POST only when stable `requestId` plus `retry=true` is available

Never retry:

- auth failures
- invalid request shape
- body-limit refusal
- gzip decode failure
- non-idempotent submit without retry contract
- local user cancellation

## Connection Reuse

The client uses Asupersync's HTTP connection pool (`src/http/pool.rs` in
Asupersync) and HTTP/1.1 keep-alive. HTTP/2 multiplexing is not assumed for the
MVP. Pooling is per canonical Snowflake endpoint and TLS root policy so that
different profiles or trust settings cannot accidentally share connections.

Pool behavior:

- reuse connections across submit, poll, partition, and cancel calls
- cap max idle connections per endpoint
- cap max in-flight requests per endpoint
- evict failed TLS or protocol connections
- never return a connection to the pool after a cancelled handshake
- close connections that exceed response body limits

Connection reuse is an optimization, not a correctness dependency. Every request
must still be valid on a fresh connection.

## Structured Attempt Logs

The crate emits JSON-line events through the shared test/observability harness
once that harness exists. Until then, the schema below is the target.

```json
{
  "schema": "franken_snowflake.transport_attempt.v1",
  "trace_id": "redacted-or-generated",
  "route": "submit|poll|partition|cancel",
  "method": "POST|GET",
  "attempt": 1,
  "request_fingerprint": "blake3-redacted",
  "statement_handle_hash": "optional",
  "partition": null,
  "status": 202,
  "retryable": false,
  "retry_after_ms": null,
  "elapsed_ms": 12,
  "compressed_bytes": 0,
  "uncompressed_bytes": 0,
  "outcome": "ok|error|cancelled",
  "error_code": null
}
```

Stdout remains data-only at CLI boundaries. Transport diagnostics go to stderr
or artifact files via the outer layer.

## Test Seams

The high-level Asupersync HTTP client does not accept an injected transport, so
deterministic tests use lower-level seams:

- HTTP/1.1 codec tests over `VirtualTcpStream` pairs
- raw response-body fixtures for gzip partition decoding
- deterministic clock for retry and `Retry-After`
- fixed request-id based jitter
- body-limit fixtures
- cancel-during-connect fixture that drops the in-progress connection
- connection-pool reuse fixture with a fake endpoint

Required no-account tests when the crate is implemented:

- header construction and bearer/token-type wiring
- gzip decompression of a fixture partition
- retry schedule: `Retry-After` first, then exponential deterministic backoff
- submit retry refusal without `requestId` plus `retry=true`
- cancel-during-connect distinct outcome
- remote cancel called after submitted handle on local cancellation
- compressed and uncompressed body-limit enforcement
- redacted JSON-line attempt log per attempt
- no forbidden production dependencies in the crate feature graph

## Feature Flags

Expected feature shape:

- `default`: types, config, header builder, and non-live test seams
- `live`: Asupersync native HTTPS transport
- `testkit`: codec and fixture helpers for no-account tests
- `compression`: gzip partition handling through Asupersync compression

If Asupersync exposes TLS and compression through its own feature flags, this
crate mirrors them explicitly and documents the required workspace patch state.

## Implementation Order Once Unblocked

1. Create `crates/franken-snowflake-http` with no Tokio-family dependencies.
2. Add config, endpoint validation, header builder, limits, and error codes.
3. Add deterministic retry schedule and attempt-log structs.
4. Add gzip decode helper with fixture tests.
5. Add native HTTPS client wrapper and pooled request primitive.
6. Add submit, poll, partition, and cancel route wrappers.
7. Add cancellation cleanup hook for submitted handles.
8. Add streaming partition scope with bounded concurrency.
9. Add dependency proof for no Tokio/reqwest/hyper/axum/tower.

This design artifact intentionally stops before crate creation because the
transport bead remains blocked by core Asupersync semantics and dependency
unification work.
