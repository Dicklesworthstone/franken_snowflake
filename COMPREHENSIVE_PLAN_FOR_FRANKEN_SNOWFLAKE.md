# Comprehensive Plan For FrankenSnowflake

Date: 2026-06-24

## Executive Recommendation

Build `franken_snowflake` as a clean-room, Asupersync-native Rust connector for
Snowflake SQL API and Snowflake-backed data lakes. The project should be a
public, reusable FrankenSuite component: protocol-first, deterministic,
agent-friendly, memory-safe, and independent of any private downstream product
or deployment.

The center of gravity should be:

1. Native Rust SQL API client using Asupersync for networking, cancellation,
   polling, retries, budgets, and deterministic tests.
2. Agent-first surfaces — both a CLI and a feature-gated MCP server — with
   capabilities, robot-docs, doctor, deterministic JSON, exact error
   remediation, dry-run plans, and stable handles.
3. No-account testkit that proves protocol behavior before any live Snowflake
   credential exists, including deterministic cancellation/retry race tests.
4. Optional FrankenSuite integrations that add public value without bloating the
   core: FrankenSQLite/sqlmodel for local metadata, FrankenPandas for frames and
   columnar export, fastapi_rust for the integration mock server, and
   Frankensearch for text-heavy data.

The differentiator over Snowflake's official drivers is not "Rust" — it is being
the *safe, self-describing Snowflake access layer for autonomous agents*, resting
on three properties those drivers do not provide together: (1) it **cannot leak
secrets** (compile-time credential `Debug`-leak gate, single-source redactor,
opaque credential handles); (2) it **cannot run away with cost** (server-side
`STATEMENT_TIMEOUT`, result row caps, receipts, advisory cost budget); and (3) an
agent **cannot get lost** (the dataset-manifest semantic catalog, `did_you_mean`,
`describe-operator --jsonschema`, and the binary-embedded agent-handbook). The
dataset-manifest model is the headline feature; everything else makes it safe to
hand to an unattended agent.

This revision strengthens four things over the first draft: it adopts the
Asupersync `Budget`/`Outcome`/capability control plane as a first-class semantic
contract (see `docs/asupersync_leverage.md`); it adds a feature-gated MCP server
surface so agents can call the connector natively; it pins the concrete,
forbidden-dependency-free crypto path for key-pair JWT; and it hardens the
toolchain and dependency-unification story that these multi-crate FrankenSuite
integrations require.

## Snowflake Facts That Shape The Design

Official references consulted on 2026-06-24:

- SQL API overview: https://docs.snowflake.com/en/developer-guide/sql-api/index
- SQL API reference: https://docs.snowflake.com/en/developer-guide/sql-api/reference
- SQL API authentication: https://docs.snowflake.com/en/developer-guide/sql-api/authenticating
- SQL API response handling: https://docs.snowflake.com/en/developer-guide/sql-api/handling-responses
- Programmatic access tokens: https://docs.snowflake.com/en/user-guide/programmatic-access-tokens
- Key-pair authentication: https://docs.snowflake.com/en/user-guide/key-pair-auth
- Drivers: https://docs.snowflake.com/en/developer-guide/drivers
- Information Schema: https://docs.snowflake.com/en/sql-reference/info-schema
- Trial accounts: https://docs.snowflake.com/en/user-guide/admin-trial-account
- COPY INTO location: https://docs.snowflake.com/en/sql-reference/sql/copy-into-location
- Query history / QUERY_TAG: https://docs.snowflake.com/en/sql-reference/parameters#query-tag
- Time Travel (AT/BEFORE): https://docs.snowflake.com/en/user-guide/data-time-travel
- RESULT_SCAN: https://docs.snowflake.com/en/sql-reference/functions/result_scan

Protocol facts:

- SQL API submits statements with `POST /api/v2/statements`.
- SQL API checks status and retrieves rows with
  `GET /api/v2/statements/{statementHandle}`.
- SQL API cancels statements with
  `POST /api/v2/statements/{statementHandle}/cancel`.
- `async=true` returns a handle for asynchronous execution. Without async, a
  statement that runs longer than ~45 seconds still returns a handle (HTTP 202)
  for polling.
- HTTP status codes are distinct signals, not interchangeable: `200` = completed
  (ResultSet body); `202` = still running / accepted async (QueryStatus body) —
  this is the poll-again signal; `408` = statement timed out
  (`STATEMENT_TIMEOUT_IN_SECONDS`); `422` = statement failed (QueryFailureStatus
  body); `429` = server overloaded / rate limited (back off and retry, unrelated
  to result readiness). A `Retry-After` header is not guaranteed on `429`, so use
  jittered exponential backoff.
- The submit `POST` is not idempotent on its own; a client-supplied `requestId`
  (UUID) plus a `retry=true` query param makes resubmission safe — if the original
  already executed, Snowflake returns the existing result instead of re-running it.
- Snowflake can return result partition metadata (`partitionInfo[]` with
  `rowCount`/`compressedSize`/`uncompressedSize`; top-level `numRows` is the total
  across partitions). Partition 0 arrives inline with the first response; later
  partitions are fetched with `GET /api/v2/statements/<handle>?partition=<n>`.
- Later partition responses can be gzip-compressed (`Content-Encoding: gzip`) and
  do not repeat metadata.
- Authentication lanes include OAuth, key-pair JWT, workload identity
  federation, and programmatic access tokens.
- Key-pair auth requires at least a 2048-bit RSA key pair, signs an RS256 JWT,
  and sets `X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT`. The claim formats
  differ: `iss = "<ACCOUNT>.<USER>.SHA256:<fp>"` (with the public-key fingerprint)
  but `sub = "<ACCOUNT>.<USER>"` (no fingerprint). ACCOUNT/USER are UPPERCASE; if
  the account identifier uses the org-account form containing a `.`, replace it
  with `-`. The fingerprint is `SHA256:<base64(SHA-256 of the DER public key)>`.
  Snowflake caps effective JWT validity at **1 hour** regardless of the requested
  `exp`, so long-polled queries must re-sign mid-flight.
- Programmatic access tokens authenticate via bearer headers with
  `X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN`. PATs default
  to a 15-day expiry (policy-capped, max 365), limited to ~15 per user. OAuth
  access tokens are short-lived (~10 min) and need refresh during long polls.
- `resultSetMetaData.rowType[]` carries each column's `type`, `scale`,
  `precision`, `nullable`, and `length`. That metadata, not row inspection, is
  the authoritative source for typed frame materialization.
- Bind values are positional and typed, keyed by 1-based string indices, and the
  `value` is always a JSON string:
  `"bindings": { "1": { "type": "TEXT", "value": "..." } }`.
- The result `data` array uses the `jsonv2` encoding: every cell is a JSON
  **string** decoded per its `rowType` entry, not by JSON shape. The load-bearing
  rules: `NUMBER`/`FIXED` is a plain decimal string (do **not** divide by
  10^scale); `BOOLEAN` is the strings `"true"`/`"false"`; `DATE` is days-since-
  epoch (`"18262"`); `TIME`/`TIMESTAMP_NTZ`/`TIMESTAMP_LTZ` are fractional epoch
  **seconds** (`"82919.000000000"`); `TIMESTAMP_TZ` is `"<epoch_sec.frac>
  <offset>"` where offset is minutes encoded as `offset_minutes + 1440`. The docs
  are internally inconsistent on timestamp units (one passage says nanoseconds), so
  pin the encoding with an empirically captured live golden (see "Test Plan").
- Multiple statements are gated by the `MULTI_STATEMENT_COUNT` parameter (exact N,
  or `0` for variable); the response returns a `statementHandles[]` array fetched
  per sub-handle. Bindings are **not** supported in multi-statement mode.
- The submit body's `parameters` object pins session behavior (e.g. `timezone`,
  the `*_output_format` params, `binary_output_format`, `use_cached_result`,
  `MULTI_STATEMENT_COUNT`); pin these for deterministic output rather than relying
  on account defaults. The `nullable` query param controls how NULL cells render
  (`null` vs the string `"null"`) and is unrelated to the `rowType[].nullable` flag.
- Snowflake's official driver page lists Go, JDBC, .NET, Node.js, ODBC, PHP,
  and Python driver support, but not an official Rust driver.
- Every database has an `INFORMATION_SCHEMA` with metadata views and table
  functions. That is the right first catalog-discovery path. `ACCOUNT_USAGE`
  views are richer but have latency and broader permission requirements.
- Time Travel `AT(TIMESTAMP => ...)` / `BEFORE(STATEMENT => ...)` enables
  point-in-time reads. `RESULT_SCAN('<query_id>')` re-fetches a still-cached prior
  result cheaply (Snowflake retains results about 24h); `LAST_QUERY_ID()` is the
  session-immediate convenience form. `QUERY_TAG` threads a caller-chosen tag into
  Snowflake's own query history.
- Warehouse compute bills per second with a **60-second minimum charged on every
  start/resume**, so auto-suspend/resume thrash re-incurs the minimum each resume.
  A per-query cost model must account for the 60s floor, not pure per-second.
- Information Schema metadata has no latency but short retention; `ACCOUNT_USAGE`
  views have 45 min–3 hr latency and 365-day retention — relevant when choosing a
  catalog-discovery source.
- Trial accounts are available for evaluation with a valid email address and no
  payment information requirement according to Snowflake's trial documentation.

Consequence: the first implementation should use SQL API over HTTPS, not ODBC,
JDBC, or a third-party Rust driver. It should implement enough HTTP/TLS, auth,
statement lifecycle, partition handling, and catalog discovery to be reliable,
then layer higher-level data-lake ergonomics on top.

## Non-Goals

- Do not add a production dependency on a third-party Rust Snowflake crate.
- Do not use Tokio, reqwest, hyper, axum, tower, sqlx, diesel, or sea-orm in
  production crates.
- Do not require Python, ODBC, JDBC, Node, or Java to query Snowflake.
- Do not store Snowflake tokens, private keys, account identifiers, or sensitive
  deployment details in repo files.
- Do not make write/update support the MVP. Read/query/catalog/export comes
  first.
- Do not silently fall back from live Snowflake to fixtures. Provenance is
  stamped and a fixture must never be mistakable for a live result.
- Do not include private downstream product names, non-public use cases, or
  deployment-specific business context in this public repository.
- Do not pull Tokio/reqwest/hyper into the production graph. Concretely: do not
  depend on the FrankenPandas umbrella crate or `fp-io` (its non-optional
  `orc-rust` dependency pulls Tokio — note the `sql-*` features pull *sync*
  drivers and are not the leak), and do not enable the Frankensearch
  `fastembed`/`download` features (ort/ONNX + openssl).

## Asupersync Leverage Contract

Asupersync is the foundation, and its value appears only when its semantic
control plane is adopted, not just its executor. The full mapping lives in
`docs/asupersync_leverage.md`; the load-bearing decisions are:

- `franken-snowflake-core` builds `SnowflakeOutcome<T>` on Asupersync's
  four-valued `Outcome<T, E>` (Ok / Err / `Cancelled` / `Panicked`) and preserves
  all four states to the CLI/MCP edge, collapsing them only at the policy
  boundary (exit code, MCP error, receipt status).
- Cancellation policy keys off `reason.kind` (`CancelKind`), not a flat enum.
  `CancelReason` is a struct; its `kind` is one of `User`/`Timeout`/`Deadline`/
  `PollQuota`/`CostBudget`/`FailFast`/`RaceLost`/`ParentCancelled`/`Shutdown`/...
  A budgeted query that exhausts its deadline surfaces as `Deadline` and a cost
  ceiling breach as `CostBudget` (**not** `Timeout`, which is the explicit
  timeout-combinator path) — the policy table must route `Deadline`/`CostBudget`
  explicitly: retry or degrade. `User` triggers the remote cancel endpoint plus a
  receipt; `Shutdown` stops acquiring work and drains within a bounded budget;
  `RaceLost`/`ParentCancelled` drain quietly.
- `Budget` carries a deadline, poll quota, and **cost quota**. The cost quota is
  the warehouse-credit ceiling; a breach surfaces as `Cancelled(CostBudget)` and
  maps to a distinct `outcome_kind`/exit code. Client-side credit accounting is
  advisory (see "Reliability Strategy"); the enforceable server-side guardrail is
  `STATEMENT_TIMEOUT_IN_SECONDS` plus result row caps. Per-query budgets propagate
  to partition fetchers via `meet()` (tighter child budgets); cancel/cleanup runs
  under a short masked budget.
- Read-only is enforced at the type level, but at the right layer: the pure
  planning/validation/SQL-compile path runs under `cx_readonly()` (which is
  `Cx<cap::None>` — zero capabilities, including no IO), while the transport layer
  runs under a narrowed `Cx` that grants `IO` (and `TIME`/`SPAWN`) but never
  `REMOTE`. Only the write-intent ladder widens authority further.
- A submitted statement handle is modeled as an obligation under `bracket`, so
  the remote cancel endpoint always fires on drop/cancel and no Snowflake
  statement is orphaned. Concurrent partition fetch runs under one bounded
  `Scope`. The submit `POST` is not auto-retried by the client `RetryPolicy`
  (which excludes non-idempotent methods); our own jittered backoff owns submit
  retries, made safe by the idempotency `requestId` + `retry=true` resubmit
  contract. The built-in retry only assists the idempotent GET poll/partition path.
- The MCP/HTTP `serve` surface wraps each agent call in a `web::request_region`
  so a disconnect drains the statement `bracket` plus partition `Scope` as one
  owned region, not merely a `checkpoint()`. Failed cancel/retry race runs emit a
  crashpack (`asupersync` `trace::crashpack`) whose replay command and fingerprint
  are stamped into the receipt's artifact pointers.

## Repository Shape

Target workspace:

```text
franken_snowflake/
  AGENTS.md
  README.md
  Cargo.toml
  rust-toolchain.toml
  deny.toml
  crates/
    franken-snowflake-core/
    franken-snowflake-auth/
    franken-snowflake-http/
    franken-snowflake-sqlapi/
    franken-snowflake-catalog/
    franken-snowflake-frame/
    franken-snowflake-export/
    franken-snowflake-graph/
    franken-snowflake-cache/
    franken-snowflake-cli/
    franken-snowflake-tui/
    franken-snowflake-mcp/
    franken-snowflake-testkit/
  docs/
    asupersync_leverage.md
    protocol/
    agent_cli_contract.md
    security_model.md
    dataset_manifest_contract.md
    proof_lanes.md
  tests/
  scripts/
    e2e/
  artifacts/
  .beads/
```

Do not create all crates in one blind sweep. Start with the minimum crate set
that proves protocol and ergonomics:

1. `franken-snowflake-core`
2. `franken-snowflake-auth`
3. `franken-snowflake-sqlapi`
4. `franken-snowflake-testkit`
5. `franken-snowflake-cli`

Add `http`, `catalog`, `frame`, `export`, `cache`, `graph`, `tui`, and `mcp`
crates when the boundary is clear. The large multi-crate FrankenSuite siblings
are a warning, not a model: keep the crate count justified by real boundaries.

The `--toon` output mode and the `graph` crate's `catalog graph --mermaid`/SVG
rendering are intended as default-on agent-legibility capabilities, not
afterthoughts (see "Default Human And Agent Affordances"). The sequencing resolves
the tension with the candidate-dependency rule below: the lean JSON-only agent core
(the minimal five crates) is the day-1 rock-solid product, and `--toon` and the
graph rendering flip to default-on **only after** their per-crate cargo-tree
admissibility proof passes; a `--no-default-features` minimal build can always drop
them for the leanest possible agent binary.

The `tui` crate is treated differently: it stays **first-class but default-off /
opt-in** (behind a `tui` feature) until its cargo-tree admissibility *and* Windows
cross-platform proofs are boring. It is the heaviest, most platform-sensitive
(crossterm-compat, Windows console), and least agent-relevant surface, so it should
not gate or bloat the default build before the core connector is real. Promoting it
to default-on later is a one-line feature change once those proofs are green.

## Crate Responsibilities

### `franken-snowflake-core`

Own shared types:

- `AccountIdentifier`
- `ProfileName`
- `DatabaseName`
- `SchemaName`
- `WarehouseName`
- `RoleName`
- `StatementHandle`
- `RequestId`
- `QueryId`
- `DatasetId`
- `ReceiptHash`
- `SnowflakeErrorCode`
- `SnowflakeOutcome<T>` built on Asupersync `Outcome<T, E>`
- `OutcomeKind` enum (`success | partial_success | refusal | cancelled |
  timeout | error`) for the envelope, kept separate from the process exit code
- `DataSource` provenance enum (`live | fixture | empty | unspecified`)
- deterministic JSON envelope metadata

This crate also owns stable error code ranges, the error registry that maps each
code to default `safe_next_commands`/`repair_commands`, redaction helpers, the
exit-code dictionary, and feature flags. It must have no live network code.

### `franken-snowflake-auth`

Own auth construction:

- PAT bearer header support.
- Key-pair JWT signing and rotation metadata (see "Auth Crypto Path").
- OAuth bearer pass-through.
- Workload identity federation placeholder types.
- Secret source descriptors that reference env vars or external secret handles,
  never raw secret values.

Auth constructors must return redacted debug output by default. The real env var
name is `#[serde(skip_serializing)]`. Tests assert that secrets cannot appear in
`Debug`, `Display`, JSON envelopes, or error messages, and a compile-time gate
(see "Security Model") fails the build if any credential-shaped field has a
derived `Debug`.

### `franken-snowflake-http`

Own the Asupersync-native HTTPS transport. This may initially live inside
`sqlapi` if splitting it early adds friction, but the boundary should eventually
be explicit because other FrankenSuite projects may want a small native HTTPS
client.

Responsibilities:

- TLS with explicit root policy (`tls` + `tls-native-roots`).
- Header construction (bearer auth, token-type, request id, query tag).
- Request/response body limits.
- Retry budgets, including jittered exponential backoff layered over the client's
  built-in `Retry-After` handling.
- Circuit-breaker / backpressure via `ServiceBuilder` where it fits.
- Manual gzip decompression of partition responses via `GzipDecompressor`.
- Cancellation that closes local work and, when a Snowflake statement has been
  submitted, calls the remote cancel endpoint.
- No Tokio, reqwest, hyper, axum, or tower.

The five HTTP client realities to engineer around (gzip is not auto-applied; the
high-level client takes no injected transport; the TLS handshake is not
cancel-safe; the client is HTTP/1.1 only; built-in retry only honors
`Retry-After`) are documented in `docs/asupersync_leverage.md` and must be
reflected in this crate's design and tests.

### `franken-snowflake-sqlapi`

Own Snowflake SQL API protocol:

- `SubmitStatementRequest`
- `SubmitStatementResponse`
- `QueryStatus`
- `QueryFailureStatus`
- `ResultSet`
- `ResultSetMetaData` (including `rowType[]` with `type`/`scale`/`precision`)
- `PartitionInfo`
- `StatementCancelResponse`
- typed, positional parameter bindings
- session parameters
- query tags
- nullable handling
- request IDs for idempotency

This crate is the protocol heart. It should be testable against canned JSON and
the deterministic codec harness before any live Snowflake account exists. The
statement lifecycle is modeled as a `bracket` so cancellation always reaches the
remote cancel endpoint.

### `franken-snowflake-catalog`

Own metadata discovery:

- databases
- schemas
- tables
- views
- columns (with Snowflake logical type, scale, nullability)
- stages
- file formats
- primary filter candidates
- time-axis candidates
- entity-axis candidates
- table comments and tags where accessible

The first implementation should rely on `INFORMATION_SCHEMA` and explicit SQL
queries. Later versions can add `ACCOUNT_USAGE` views if permissions allow.
Catalog output feeds the three-part dataset manifest model (see below) and may be
rendered as a lineage/dependency graph (optional `frankenmermaid` output).

### `franken-snowflake-frame`

Own conversion from SQL API JSON rows into typed frame structures:

- dtype inference driven by `resultSetMetaData.rowType[]`, not row inspection
- a pinned Snowflake-type → frame-dtype mapping table (see "Result Handling")
- VARIANT/OBJECT/ARRAY preserved as structured JSON values
- null/NaN/NaT separation
- optional columnar materialization via FrankenPandas `fp-columnar` + `fp-types`
  (and `fp-frame` only when full DataFrame semantics are needed)
- streaming conversion for large partitions

This crate depends on the focused `fp-*` crates, never the aggregate
`frankenpandas` umbrella crate (whose IO path pulls Parquet/ORC/Tokio). The core
protocol client must not require frame materialization at all.

### `franken-snowflake-export`

Own content-addressed export of result sets:

- **`COPY INTO <location>` is the primary large-export path** — server-side,
  pushes the heavy work to Snowflake, and pulls no heavy local dependencies. This
  also aligns with the "pushdown first" performance philosophy.
- Local export is limited to **CSV and JSONL**, written by hand or via
  `fp-columnar` alone. Do **not** depend on `fp-io`: it pulls Tokio
  non-optionally through `orc-rust`, which would break the forbidden-dependency
  gate. ORC export is dropped entirely (it is the Tokio vector and is unrequested).
- Local Arrow IPC export is added only if a forbidden-dependency-clean writer is
  proven via cargo-tree; otherwise it is deferred in favor of `COPY INTO`.
- content-addressed export records (BLAKE3) with byte-length verification.

Feature-gated so the default agent build stays lean; the `export` verb itself is
always present, but the columnar/local-file backends are pulled only when the
`export` feature is enabled.

### `franken-snowflake-graph`

Own the catalog-as-graph model and its rendering, an integral default capability:

- model databases → schemas → tables/views → columns as a typed graph, plus
  foreign-key, view-dependency, and lineage edges discovered from the catalog
- graph algorithms for agent discovery: `what-relates-to <object>`, ancestors /
  descendants (lineage up/down), reachability, and dependency-cycle detection
- build on the FrankenNetworkX Rust crates (`fnx-classes`, `fnx-algorithms`, ...)
  via path dependency; if their internal API proves unstable, fall back to a thin
  in-house adjacency structure exposing the same query surface (the capability is
  not lost either way)
- render to Mermaid text and SVG via FrankenMermaid for `catalog graph --mermaid`
  so an agent or human gets a legible lineage/ERD diagram, not just JSON edges

### `franken-snowflake-tui`

Own the default-off / opt-in human-facing terminal UI (behind a `tui` feature),
built on FrankenTUI (Asupersync-native + crossterm; pin the `crossterm-compat`
feature for Windows; never `charmed_rust`, which pulls Tokio):

- catalog browser (navigate databases → schemas → tables → columns)
- interactive query runner with the same planner, safety, and receipts as the CLI
- live statement and partition-fetch progress driven by the Asupersync
  structured-concurrency progress model (the same `Scope`/`Budget` a query uses)

The TUI is a presentation layer over the same handlers as the CLI and MCP; it
introduces no new product contract, secrets handling, or mutation path. It stays
**default-off / opt-in behind a `tui` feature** until its cargo-tree admissibility
and Windows cross-platform proofs are boring — it is the heaviest and most
platform-sensitive surface and must not gate or bloat the default build before the
core connector is real.

### Default Human And Agent Affordances

Two agent-legibility surfaces beyond raw `--json` are part of the default product
(once cargo-tree-proven) because they materially improve both human and agent
legibility at low risk:

- `--toon` output mode alongside `--json` on every read command, using the TOON
  (token-oriented object notation) encoder to cut token cost on large catalog and
  result payloads fed back to an agent.
- `catalog graph --mermaid` (and SVG) lineage/ERD rendering from the `graph`
  crate, so structure is visible at a glance.

`franken-snowflake tui` for interactive human exploration is first-class but
**default-off / opt-in** (see the `tui` crate above) until its cross-platform proof
is boring; promoting it to default-on later is a one-line feature change.

Each underlying dependency (`toon`, FrankenMermaid, the FrankenNetworkX Rust
crates, FrankenTUI) is a candidate dependency until a cargo-tree forbidden-
dependency scan proves it clean in the production feature graph.

### `franken-snowflake-cache`

Own local state using FrankenSQLite and sqlmodel_rust:

- profiles without secrets
- catalog snapshots
- dataset manifests
- query plans
- query receipts
- result partition metadata
- cost and row-count histories
- offline replay bundles
- an append-only query audit log (with a build-failing UPDATE/DELETE gate)

This crate provides typed repository APIs via the `sqlmodel-frankensqlite` driver
(not the C-FFI `sqlmodel-sqlite` driver). Note the concurrency model:
`fsqlite::Connection` is `!Send` and access is blocking-under-mutex, which is
appropriate for a read-mostly local cache; `last_insert_rowid` is adapter-tracked.

Expose the cache behind a backend trait. The default backend is the local
FrankenSQLite store. A future optional backend (e.g. FrankenRedis) could provide a
*shared cross-agent* catalog/receipt cache for multi-agent swarms hitting one
Snowflake account, behind the same trait — explicitly opt-in, never core, and
never holding secrets.

### `franken-snowflake-cli`

Own the CLI product:

- `capabilities --json`
- `robot-docs guide` / `agent-handbook`
- `doctor --json`
- `selftest --json` (run the no-account testkit fixtures so an agent can verify
  the binary's protocol behavior offline, before any credential exists)
- `profile validate`
- `catalog scan`
- `dataset inspect`
- `dataset profile` (column stats / cardinality / null-rate via SQL pushdown —
  `APPROX_*` aggregates, not local computation)
- `query plan`
- `query run`
- `query cancel`
- `receipt show <hash>` (look up a content-addressed receipt the connector emitted)
- `export`
- later, `write-intent`

The CLI must be optimized for agent users: deterministic JSON, stable exit
codes, exact next commands in errors, no interactive prompt in non-TTY mode, and
no ANSI in JSON. Hold it to the `agent-ergonomics-and-intuitiveness-maximization-
for-cli-tools` polish bar.

### `franken-snowflake-mcp`

Own a feature-gated MCP server surface (`franken-snowflake mcp serve`) built on
`fastmcp-rust`:

- each read verb (`query run`, `query plan`, `catalog scan`, `dataset inspect`,
  `doctor`, `capabilities`, receipt lookup) is exposed as an MCP `#[tool]` whose
  JSON schema is generated from the handler signature
- each call wrapped in an Asupersync `web::request_region` so an agent disconnect
  drains the statement `bracket` plus the partition `Scope` as one owned region;
  `ctx.checkpoint()` provides the cooperative cancel points inside it
- the same read-only-by-default capability posture as the CLI

The MCP surface is not a second product contract. It must expose exactly the same
capabilities, JSON envelopes, error codes, receipts, and safety classes as the
CLI by sharing the same command handlers; the MCP crate is a thin adapter, not a
parallel implementation. Sequencing: `run_stdio()` and read-only tools first
(the agent-spawn / Claude Desktop path), `run_http()` second once stdio is
proven, and write tools deferred behind the same write-intent ladder as the CLI.
Gate it behind an `mcp` feature so the leanest agent build can omit it.
`fastmcp-rust` is Asupersync-native and is a candidate dependency until a
cargo-tree scan proves it pulls no forbidden dependencies.

### `franken-snowflake-testkit`

Own deterministic tests, in two lanes:

Primary deterministic lane (no socket):

- `Http1Client::request<IO>` codec driven over a `VirtualTcpStream` pair under
  `LabRuntime`, with DPOR exploration of cancellation/retry interleavings
- obligation-leak / quiescence oracles asserting zero leaked connections,
  statements, or partition fetchers after a cancel
- canned response fixtures: 200 result sets, 202 running, 429 backoff, 422
  failure, gzip partition payloads, multiple-statement refusal

Integration lane:

- mock SQL API server using fastapi_rust (Asupersync-native, no forbidden deps;
  `ResponseFactory`/`TestClient`) for stateful end-to-end CLI ↔ HTTP flows: a
  first GET returns 202, later GETs return 200 with partitions, gzip bodies, and
  custom headers
- auth-header inspection with redaction
- local free-trial smoke test harness, disabled unless credentials are present

Shared testkit infrastructure: deterministic key-sorted JSON golden files with
time/host/hash fields canonicalized and IEEE-754 bits reported on float mismatch;
an injected clock for deterministic backoff/TTL; canary-secret leak guards; and
the forbidden-dependency scan.

fastapi_rust is a testkit dependency, not a production core dependency.

## Auth Crypto Path

Key-pair JWT signing must be forbidden-dependency-free. The concrete path:

- `jsonwebtoken` v10 with `default-features = false, features = ["rust_crypto",
  "use_pem"]`. The `rust_crypto` feature uses the pure-Rust `rsa` + `sha2` crates
  for RS256 — no OpenSSL, no ring signing API, no Tokio.
- Load the PKCS#8 PEM private key, sign an RS256 JWT with the exact Snowflake
  claim set: `iss = "<ACCOUNT>.<USER>.SHA256:<fp>"`, `sub = "<ACCOUNT>.<USER>"`
  (no fingerprint in `sub`), `iat`, `exp`. Uppercase ACCOUNT/USER; for the
  org-account form, replace `.` with `-` in the account segment.
- Compute the public-key fingerprint `SHA256:<base64(SHA-256 of DER public key)>`
  with `sha2` + `base64`.
- Cap effective `exp` at ≤ 3600s (Snowflake ignores anything longer), and support
  re-signing inside the statement `bracket` so a query polled past ~1 hour does
  not lose auth mid-flight.
- Set `X-Snowflake-Authorization-Token-Type: KEYPAIR_JWT` and the bearer header.

Do not reach for `openssl` or `ring`'s signing API. This exact `rust_crypto`
`use_pem` JWT path already ships in `fastmcp-server` (its `jwt` feature), so it is
a known-good clean-room precedent. (Note: `mcp_agent_mail_rust` uses jsonwebtoken
with the `aws_lc_rs` C-backed feature — do **not** copy that config here.)

## Toolchain, Dependency Unification, And CI Gates

These multi-crate FrankenSuite integrations have real operational requirements:

- `rust-toolchain.toml` pins a nightly toolchain and edition 2024. The
  FrankenSQLite / sqlmodel / FrankenPandas stack requires it; state it up front.
- Workspace lints: `unsafe_code = "forbid"`; `deny` on `unwrap_used`,
  `expect_used`, `panic`, `todo`, `dbg_macro`.
- A `[patch.crates-io]` block unifies `asupersync`, `fsqlite`/`fsqlite-*`,
  `sqlmodel-*`, `fp-*`, `fastmcp-rust`, `frankensearch` (and, if the optional
  reranker is enabled, `frankensearch-rerank` + the `frankentorch` `ft-*` crates)
  to one consistent local checkout set.
- A CI gate fails if `cargo tree` reports more than one `asupersync` version.
- A forbidden-dependency scan (`deny.toml` / `cargo tree`) fails the production
  feature graph if Tokio, reqwest, hyper, axum, tower, sqlx, diesel, or sea-orm
  appear.
- Dependency admissibility is proven, not assumed. Every non-`asupersync`
  FrankenSuite dependency (`fastmcp-rust`, the `fp-*` crates, `jsonwebtoken`,
  `fastapi-rust`, `frankensearch`, `frankensearch-rerank` + `frankentorch`
  `ft-*`, `frankentui`, `frankenmermaid`, the FrankenNetworkX `fnx-*` crates,
  `toon`) is a *candidate* dependency until a per-crate `cargo tree` proof shows no
  forbidden crate appears in the production feature graph it pulls. Dev-only and
  feature-gated paths are scanned in their own configurations so a dev-only Tokio
  (if any) can never reach production.
- Cold builds are slow (LTO, single codegen unit, large engine). Use a remote
  build cache where available and avoid `--release` during development.

## FrankenSuite Dependency Wiring

| Crate | Role | Wiring rule |
|---|---|---|
| `asupersync` (`tls`, `tls-native-roots`, `compression`, `proc-macros`) | Runtime, HTTP/1.1 client, TLS, gzip, Budget/Outcome/capabilities, Lab/DPOR | One version across the whole graph |
| `fsqlite` + `sqlmodel-frankensqlite` | Local cache repositories | Use the frankensqlite driver, not the C-FFI `sqlmodel-sqlite`. **Windows prerequisite:** fsqlite currently mis-gates the `nix` crate under `cfg(not(wasm32))`, which breaks the Windows build; this must be re-gated to `cfg(unix)` upstream before the cache crate compiles on Windows |
| `fp-columnar` + `fp-types` (+ `fp-frame` as needed) | Frame materialization and local CSV/JSONL export | Never the umbrella `frankenpandas` crate and **never `fp-io`** (its non-optional `orc-rust` pulls Tokio); large export goes via `COPY INTO` |
| `fastmcp-rust` | `mcp serve` surface | Feature-gated `mcp`; Asupersync-native |
| `jsonwebtoken` (`rust_crypto`, `use_pem`) | Key-pair RS256 JWT | `default-features = false` |
| `fastapi-rust` | Integration mock server | Dev-dependency only; candidate until cargo-tree-proven |
| `frankentui` | Interactive TUI (**default-off / opt-in** behind a `tui` feature until cross-platform-proven) | Candidate dep; not `charmed_rust` (pulls Tokio). Pin the `crossterm-compat` feature so the TUI builds on Windows (the native termios backend is Unix-only) |
| `frankenmermaid` | Catalog/lineage diagram output (`catalog graph --mermaid`) | Candidate dep |
| FrankenNetworkX `fnx-*` crates | Catalog/lineage graph model + algorithms | Candidate dep via path; in-house adjacency fallback if API unstable |
| `toon` | `--toon` output mode alongside `--json` | Candidate dep |
| `frankensearch` (`hash`/`lexical`) | Optional text indexing of unstructured columns | Candidate dep; never the `fastembed`/`download` features |
| `frankensearch-rerank` (`native`) + `frankentorch` `ft-*` | Optional pure-Rust semantic reranker (top-K refinement only) | Candidate dep; the `native` cross-encoder runs on pure-Rust frankentorch tensors (no ort/ONNX/openssl, cross-platform). Behind a `rerank` feature with a no-op default; never the `fastembed-reranker` path |

Every row except `asupersync` is a *candidate dependency* until its own
`cargo tree` proof confirms no Tokio/hyper/reqwest/axum/tower/sqlx/diesel/sea-orm
in the production feature graph it contributes (see "Toolchain, Dependency
Unification, And CI Gates").

## Cross-Platform Support

Linux, macOS, and Windows are tier-1 targets. This is feasible because the
load-bearing runtime is portable: Asupersync selects its reactor per OS (epoll on
Linux, kqueue on macOS, IOCP via the `polling` crate on Windows); `io_uring` is an
optional Linux-only feature, **not** required, and the connector's exact feature
surface (`tls`, `tls-native-roots`, `compression`) is built and tested on all
three OSes in Asupersync's own CI. The HTTP/TLS/gzip client path has no
platform-specific code. The remaining work is discipline the plan must enforce
from Phase 0:

- **CI OS matrix.** A `test` job with `os: [ubuntu-latest, macos-latest,
  windows-latest]`, `fail-fast: false`, building the *full* workspace with
  `--features tls,tls-native-roots,compression`. Do not test only one sub-crate on
  Windows (the mistake that hid the fsqlite blocker below).
- **Portable dependency pins.** rustls + `rustls-native-certs` for native roots
  (schannel/security-framework/`/etc/ssl`); `flate2`'s default `miniz_oxide`
  backend (**never** the `zlib`/`zlib-ng` C backends); `jsonwebtoken`
  `rust_crypto`+`use_pem` (pure Rust); `frankentui` with `crossterm-compat`
  (the native termios backend is Unix-only). TLS's `ring` crypto provider needs a
  C/asm build toolchain (MSVC on Windows) — a build-time prerequisite to document,
  not a runtime issue.
- **fsqlite Windows prerequisite.** fsqlite mis-gates the Unix-only `nix` crate
  under `cfg(not(wasm32))` (true on Windows), so the Windows build fails even
  though call sites are `cfg(unix)`-gated. Re-gate `nix` to `cfg(unix)` upstream
  before the cache crate targets Windows.
- **Config / cache / artifacts directories.** Use `directories`/`dirs`
  (`ProjectDirs`): profiles in `config_dir()` (XDG on Linux, `~/Library/...` on
  macOS, `%APPDATA%` on Windows), cache in `cache_dir()`, receipts/artifacts in
  `data_dir()` or a `--run-dir` override. Precedence: explicit flag > env var >
  platform default. Never hard-code Unix paths.
- **Golden-file newline discipline.** Deterministic JSON goldens will mismatch on
  Windows checkouts with `autocrlf`. Commit a `.gitattributes` forcing
  `eol=lf` on `*.json`/`*.golden`/`*.toml` fixtures, compare goldens as raw bytes,
  and add a CI check that no golden contains `\r`. Enforce lowercase, non-case-
  colliding fixture filenames (case-insensitive FS on Windows/macOS).
- **Portable e2e.** `scripts/e2e/*.sh` will not run on native Windows; add a
  `cargo xtask e2e` (or pure-Rust integration-test) entrypoint that drives the same
  flows so Windows CI exercises them without bash. Document the Git-Bash/WSL fallback.
- **Ctrl+C → cancel mapping.** Map a console interrupt to `CancelReason`/
  `CancelKind::User` portably (signal-hook on Unix; a `windows-sys` console-ctrl
  handler or the `ctrlc` crate on Windows). TTY/`NO_COLOR` detection uses
  `IsTerminal`, which is already portable.

A cross-platform proof lane in the test plan asserts the build + no-account testkit
pass on all three OSes.

## Agent CLI And MCP Contract

The agent surfaces should satisfy the agent-ergonomics polish bar from day one.

Required CLI command families:

```bash
franken-snowflake capabilities --json
franken-snowflake robot-docs guide
franken-snowflake agent-handbook --json
franken-snowflake doctor --json
franken-snowflake selftest --json
franken-snowflake profile validate <profile> --json
franken-snowflake profile doctor <profile> --json
franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json
franken-snowflake catalog graph <profile> --mermaid
franken-snowflake dataset inspect <dataset-id> --json
franken-snowflake dataset profile <dataset-id> --json
franken-snowflake dataset describe-operator <operator> --jsonschema
franken-snowflake query plan --profile <profile> --sql <sql> --json
franken-snowflake query run --profile <profile> --sql <sql> --json
franken-snowflake query cancel <statement-handle> --json
franken-snowflake receipt show <receipt-hash> --json
franken-snowflake tui --profile <profile>
franken-snowflake mcp serve [--stdio | --http <addr>]
```

Every read command accepts `--json` (default) or `--toon` for token-efficient
output. `catalog graph` additionally accepts `--mermaid`/`--svg`.

`agent-handbook` returns the whole contract in one binary-embedded call:
envelope-key spec, the exit-code dictionary, the first ~10 commands a new agent
should try, an error-code → next-command recovery map, and explicit non-goals.
`capabilities` returns a self-describing command registry where each command
carries `input_schema` (JSON Schema 2020-12), `output_contract_id`,
`error_families`, examples, and boolean safety facets (`mutates_local_state`,
`provider_network`, `read_only`, `sensitive_output`). Commands default to
non-mutating and non-sensitive; a command must opt into danger.

Every JSON envelope should include:

- `ok`
- `outcome_kind` (`success | partial_success | refusal | cancelled | timeout |
  error`), separate from `ok` and from the exit code
- `command_id`
- `output_contract_id`
- `schema_version`
- `data_source` (`live | fixture | empty`; omitted when `unspecified`)
- `profile_id`
- `request_id`
- `query_id` when applicable
- `statement_handle` when applicable
- `receipt_hash`
- `started_at`
- `finished_at`
- `duration_ms`
- `warnings`
- `safe_next_commands`
- `repair_commands` and `did_you_mean` on errors
- `budget_consumed`
- `redactions_applied`

Error envelopes carry a stable `error.code`, `retryable`, `policy_boundary`, and
redacted evidence handles. `safe_next_commands`/`repair_commands` are
auto-populated from the central error registry when the caller passes none, so
every error code ships a default recovery path. `did_you_mean` uses Levenshtein
distance over known command/column/dataset names.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | success, including empty-but-valid results (an empty result set returns `[]` / an empty typed payload, never a non-zero exit) |
| 1 | completed with non-fatal findings/warnings needing attention (e.g. `doctor` detected problems, `profile validate` surfaced warnings) |
| 2 | safety refusal |
| 3 | credential/profile error |
| 4 | upstream Snowflake error |
| 5 | network or retry budget exhausted |
| 6 | query still running (async handle returned, not yet complete) |
| 7 | local cache or metadata error |
| 64 | usage |
| 74 | I/O error |

An empty query result is success (exit 0), not a finding. Exit 1 is reserved for
non-fatal findings/warnings on a valid run; exits 2 and above are refusals and
errors. `outcome_kind` in the envelope carries the finer-grained class
independently of the exit code.

Errors should teach. A missing profile error should name what failed, which
profile was requested, where profiles are read from, the exact command to
validate or create the profile, and whether live transport was attempted.

For large catalog or result payloads fed back to an agent, an optional `--toon`
output mode (token-oriented encoding) reduces token cost alongside `--json`.
Long-running queries emit typed NDJSON progress events on stderr while the final
envelope goes to stdout.

## Profile And Credential Model

Profiles should be non-secret TOML:

```toml
[profiles.demo-prod]
account = "xy12345.us-east-1"
host = "xy12345.us-east-1.snowflakecomputing.com"
user = "SNOWFLAKE_SERVICE"
role = "SNOWFLAKE_READONLY"
warehouse = "SNOWFLAKE_XS"
database = "ANALYTICS"
schema = "PUBLIC"
auth = { kind = "pat", env = "SNOWFLAKE_PAT" }
```

Alternate auth:

```toml
auth = { kind = "key_pair_jwt", private_key_env = "SNOWFLAKE_PRIVATE_KEY_PEM", private_key_passphrase_env = "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE" }
```

The profile file never stores the PAT or private key. `profile validate --json`
checks shape and environment presence without contacting Snowflake unless
`--online` is passed. `profile doctor --online --json` can attempt a minimal
`select current_version()` if live transport is enabled.

`profile doctor` should also surface credential-lifetime warnings where derivable
without leaking the secret: a PAT nearing its 15-day default expiry, a JWT signer
that would request an `exp` beyond the 1-hour cap, or an OAuth token near its
~10-minute lifetime. The goal is "your token expires in N days/minutes" guidance
rather than a surprise 401 mid-poll.

## Dataset Manifest Model

Agents should not need to remember raw database names and column conventions.
Catalog discovery produces a three-part model, which is more robust and more
agent-discoverable than embedding operator sets inline in each filter:

1. A dataset manifest describing the object, its rights class, default and max
   row limits, and a per-field role assignment.
2. A column catalog mapping each column to its Snowflake logical type, scale,
   nullability, and aliases (which power `did_you_mean`).
3. An operator catalog mapping each operator to its input arity, output-dtype
   rule, and refusal codes.

Filters are a dumb predicate AST over column names. Operator-vs-dtype legality is
checked by a separate validation pass that emits typed refusals, not stored
inline on each filter. Because the operator catalog is a first-class model,
`dataset describe-operator <operator> --jsonschema` can hand an agent a JSON
Schema 2020-12 document for each operator's parameters, so the agent constructs a
valid filter without trial and error.

```toml
[[datasets]]
id = "events_daily"
profile = "demo-prod"
database = "ANALYTICS"
schema = "PUBLIC"
object = "EVENTS_DAILY"
kind = "table"
rights_class = "private"
default_limit = 1000
max_rows_without_export = 50000

# Axis assignment is a per-field role, not a top-level string.
[[datasets.fields]]
column = "EVENT_DATE"
role = "time_index"
dtype = "date"

[[datasets.fields]]
column = "ENTITY_ID"
role = "entity_key"
dtype = "string"

[[datasets.fields]]
column = "VALUE"
role = "feature"
dtype = "number"
```

Field roles are drawn from a fixed enum (`entity_key`, `time_index`, `known_at`,
`feature`, `label`, `metadata`). This is the bridge from raw Snowflake catalog to
agent intuition: an agent can ask for rows in a date range without guessing SQL
syntax or table names, and the optional `known_at` role anticipates point-in-time
reads via Time Travel.

## Query Planning

Support two query modes:

1. Raw SQL mode for expert users.
2. Dataset mode for agents.

Dataset mode:

```bash
franken-snowflake query run \
  --profile demo-prod \
  --dataset events_daily \
  --entity ENTITY123 \
  --from 2024-01-01 \
  --to 2024-12-31 \
  --as-of 2024-12-31T23:59:59Z \
  --select EVENT_DATE,ENTITY_ID,VALUE \
  --json
```

The planner should:

- quote identifiers correctly
- use Snowflake positional typed bindings, never string interpolation, for values
- push down projection and predicates
- compile `--as-of` to a Time Travel `AT(TIMESTAMP => ...)` clause when the
  dataset declares a `known_at`/`time_index` axis
- require a limit or export mode for large result sets
- set an enforceable server-side guardrail (`STATEMENT_TIMEOUT_IN_SECONDS` plus a
  result row cap) on every query; the client-side `Budget` cost quota and the
  unconstrained-query warning are advisory telemetry layered on top, not the
  enforcement mechanism (warehouse credits cannot be metered precisely client-side)
- generate deterministic plan identifiers (a normalized-plan hash over plan +
  profile + time window), distinct from Snowflake's assigned `query_id`
- set `QUERY_TAG` to the envelope `command_id`/`trace_id` for end-to-end
  traceability into Snowflake's query history
- record query tag fields for traceability

Raw SQL mode should still support `--dry-run`/`query plan`, typed bind values,
and explicit safety checks. The MVP refuses non-SELECT statements and multiple
statements unless explicitly allowed.

## Result Handling

The result engine must handle:

- immediate 200 result sets
- 202 still running (the not-yet-ready signal; poll by re-`GET`ting the statement
  handle / `statementStatusUrl`)
- 429 rate limiting / too-many-requests (`Retry-After` is not guaranteed; use
  jittered backoff) — distinct from 202; never treat 429 as a query-status code
- 408 statement timeout (exceeded `STATEMENT_TIMEOUT_IN_SECONDS`) — a typed
  timeout outcome, distinct from a query failure
- 422 query failures (SQL compilation or execution error)
- the cancelled-during-connect state (the TLS handshake is not cancel-safe), as a
  distinct receipt state separate from a submitted-then-cancelled statement
- partition metadata
- gzip partitions (decompressed manually via `GzipDecompressor`)
- JSON row arrays
- SQL NULL as JSON null
- Snowflake date/time/timestamp formatting choices
- multiple-statement handles
- `RESULT_SCAN('<query_id>')` re-fetch using the stored Snowflake `query_id` from
  the receipt store (keyed by the normalized-plan hash), subject to Snowflake's
  result-cache retention (about 24h) and result-reuse rules; `LAST_QUERY_ID()`
  only addresses the immediately prior statement in the same session

For MVP, reject multiple statements unless `--allow-multiple-statements` is
explicitly passed.

The frame layer maps `resultSetMetaData.rowType[]` to dtypes using a pinned
table, carrying the Snowflake logical type alongside the frame dtype because the
frame dtype is lossy for some Snowflake types:

| Snowflake type | Frame dtype | Note |
|---|---|---|
| `FIXED` (scale 0) | Int64 / Int64-nullable | from `scale`/`precision` |
| `FIXED` (scale > 0), `REAL` | Float64 | NUMBER with scale collapses to float |
| `TEXT` | Utf8 | |
| `BOOLEAN` | Bool / Bool-nullable | |
| `DATE`, `TIME`, `TIMESTAMP_*` | Datetime64 | frame collapses these; keep Snowflake logical type alongside |
| `VARIANT`, `OBJECT`, `ARRAY` | Utf8 (structured JSON) | no native semi-structured frame dtype; preserve JSON |
| `BINARY` | Binary/Utf8 (hex) | |

The dtype table above is the *destination* mapping. It is distinct from the
*wire codec* — how each `jsonv2` string cell is decoded — which is where bugs hide.
Every cell is a JSON string (including numbers and booleans), parsed by its
`rowType` entry (matched case-insensitively), never inferred from JSON shape:

| Snowflake type | Wire encoding (the JSON string) | Decode rule |
|---|---|---|
| `FIXED`/`NUMBER` | plain decimal, e.g. `"1.0"` | parse decimal directly; do **not** divide by 10^scale |
| `REAL`/`FLOAT` | numeric string; `DECFLOAT` → scientific past 38 digits | parse as float / arbitrary-precision decimal |
| `BOOLEAN` | the strings `"true"`/`"false"` | string compare, not JSON bool |
| `DATE` | days since epoch, e.g. `"18262"` | epoch-day → date |
| `TIME`,`TIMESTAMP_NTZ`,`TIMESTAMP_LTZ` | fractional epoch **seconds**, e.g. `"82919.000000000"` | seconds (not nanos) → timestamp |
| `TIMESTAMP_TZ` | `"<epoch_sec.frac> <offset>"` | offset is minutes encoded as `offset_minutes + 1440` |
| `BINARY` | hex string | hex-decode |
| `VARIANT`/`OBJECT`/`ARRAY` | embedded JSON text | preserve as structured JSON |
| SQL `NULL` | JSON `null` (or `"null"` if the `nullable` param is off) | NULL |

The docs are internally inconsistent on timestamp units (one passage says
nanoseconds), so this codec must be pinned against an empirically captured live
golden before it is trusted (see "Test Plan").

## Performance Strategy

Use Snowflake pushdown first. Do not pull large tables locally and aggregate in
Rust when Snowflake can execute the filter/group/projection.

Hot paths:

- compile dataset filters into pushed-down SQL with positional bindings
- fetch partitions concurrently under one bounded Asupersync `Scope`, each
  fetcher inheriting a tighter child `Budget` via `meet()`
- reuse pooled keep-alive connections across submit/poll/partition GETs
- stream partitions into frames or local exports without holding full result
  sets in memory
- decompress gzip partitions streaming
- cache catalog metadata and query receipts locally; use `RESULT_SCAN` for cheap
  re-query of a known prior `query_id`
- offer `COPY INTO <location>` export plans for large result sets after the core
  SQL API path is stable

The CLI defaults to safe row limits for interactive queries. Large result sets
require `--export`, `--max-rows`, or an explicit confirmation token.

## Reliability Strategy

Asupersync carries the hard parts (see `docs/asupersync_leverage.md`):

- structured regions for each query
- per-query `Budget` (deadline + poll quota + cost quota) and `meet()` propagation;
  the cost quota is advisory, enforced server-side via `STATEMENT_TIMEOUT_IN_SECONDS`
- checkpointed cancellation keyed on `reason.kind` (`CancelKind`), routing
  `Deadline`/`CostBudget`/`User`/`Shutdown` distinctly
- statement lifecycle as a `bracket` so the remote cancel call always fires
- idempotent submit: a stable `requestId` + `retry=true` resubmit makes the
  custom jittered backoff safe (the client `RetryPolicy` does not retry `POST`)
- bounded retry/backoff on network and 429 statuses, with jitter
- no orphan partition fetchers (region ownership)
- deterministic Lab/DPOR test scheduling for cancellation and retry races, with
  the `obligation-leak` and `quiescence` oracles asserted as CI gates (not just
  exploration), plus fixed-seed chaos presets on the 429-storm and
  partial-partition-failure suites
- failed race/cancel runs emit a crashpack whose replay command is stamped into
  the receipt artifact pointers

Every query ends with a receipt:

- submitted request fingerprint (a hash of the redacted canonical request string:
  `account|database|schema|warehouse|role|normalized_sql|bind_shape`)
- normalized SQL hash
- profile hash without secrets
- Snowflake statement handle and `query_id`
- partition metadata hashes
- rows returned
- bytes compressed/uncompressed
- a cost vector (`statements_run`, `partitions_fetched`, `bytes_scanned`,
  `warehouse_credits_estimate`)
- status and final `OutcomeKind`
- redaction markers
- local cache handles

Receipts are content-addressed (BLAKE3) and never contain secret values. The
query audit log is append-only, enforced by a build-failing test that forbids any
UPDATE/DELETE against it.

## Security Model

Security defaults:

- read-only by default, enforced at the type level via narrowed capability rows
- no secret values in config, `Debug`, JSON output, or panic text
- a compile-time gate that scans crate sources and fails the build if any
  `#[derive(Debug)]` struct has a credential-shaped field (`*_api_key`,
  `*_password`, `*_private_key`, `*_token`, ...) without a hand-rolled redacting
  `Debug`
- one composable redactor sourcing its needle list from a single shared constant
  so the redactor and the last-mile output scanner cannot drift; longest-prefix
  secret detection (`eyJ`, `AKIA`, `ghp_`, `sk-`, `xoxb-`, `glpat-`, `AIza`, ...)
- opaque `cred_*` handles in diagnostics; the env var name is never serialized
- fail-closed rights: an unknown rights label parses to the most restrictive
  class; an expired entitlement is treated as missing, not as default-allow
- no live query without explicit profile and credential source
- no mutation without the explicit write-intent ladder
- optional private connectivity host allowlist
- TLS required

Private connectivity support is not special-cased into the protocol client. It is
a host/profile setting plus connectivity doctor checks. AWS PrivateLink, Azure
Private Link, and GCP Private Service Connect all reduce to "this account host
resolves/routes privately from this environment" from the client perspective.

## Write And Update Support

Defer write/update support until read/query/catalog is strong.

When added, use a write-intent ladder:

1. `write plan --dry-run --json`
2. typed safety classification
3. explicit allowlist of statements
4. idempotency request ID
5. exact confirmation token
6. execution receipt
7. append-only audit

The write-intent ladder is the only code path permitted to request a capability
row wider than read-only.

Supported first write operations should be narrow:

- `INSERT` into explicitly configured staging tables
- `MERGE` with explicit key manifest
- `COPY INTO <table>` from explicitly configured stages

DDL should remain disabled until there is a clear, public, documented use case.

## Test Plan

No-account tests:

- JSON schema round trips for official SQL API examples.
- Submit/poll/cancel lifecycle against the deterministic codec harness and the
  fastapi_rust mock server.
- Result partition streaming with gzip fixture.
- Status-code routing fixtures proving 200/202/408/422/429 are handled as distinct
  states: a 202→200 poll-continue sequence, a 429-backoff (no `Retry-After`)
  retry, a 408 statement-timeout outcome, and a 422 failure — none conflated.
- Idempotent-submit fixture: a `requestId` + `retry=true` resubmit returns the
  prior result rather than re-executing.
- JWT claim-format golden: `iss = ACCOUNT.USER.SHA256:<fp>`, `sub = ACCOUNT.USER`
  (no fp), uppercasing, org-account `.`→`-`, and the ≤3600s `exp` cap.
- `jsonv2` wire-codec unit tests for `DATE` (epoch days), `TIME`/`TIMESTAMP_*`
  (fractional epoch seconds), `TIMESTAMP_TZ` (offset+1440), `NUMBER` (no scale
  division), and `BOOLEAN` (string) — plus an empirically captured live golden
  (Phase 7) that pins the timestamp unit the docs are ambiguous about.
- Multiple-statement refusal fixture by default; when allowed, a
  `MULTI_STATEMENT_COUNT` + `statementHandles[]` fan-out fixture and a
  bindings-with-multi-statement refusal.
- Cancelled-during-connect receipt-state fixture (TLS handshake not cancel-safe).
- Secret redaction fixture and the credential `Debug`-leak compile gate.
- Deterministic DPOR race suite: cancel-during-submit, cancel-during-poll,
  cancel-during-partition-fetch, 429-storm, partial-partition-failure — each with
  obligation-leak and quiescence oracles.
- CLI deterministic JSON golden fixture and an MCP tool-schema golden fixture.
- CLI/MCP parity test: the same logical operation produces the same envelope,
  error code, receipt, and safety class through both surfaces.
- `--toon` output golden fixture (round-trips to the same data as `--json`).
- `catalog graph --mermaid` golden fixture and graph-algorithm unit tests
  (ancestors/descendants/what-relates-to/cycle detection) over a fixture catalog.
- `export` golden fixtures for local CSV/JSONL (content-addressed records) and a
  `COPY INTO <location>` export-plan golden (the primary large-export path).
- TUI model/update unit tests (no real terminal) over scripted catalog state.
- `NO_COLOR`, `CI`, and non-TTY fixture.
- `data_source` provenance fixture and a `--require-live` refusal fixture.
- Forbidden dependency scan and single-asupersync-version gate.
- Per-candidate-dependency cargo-tree admissibility proof.
- Cross-platform proof lane: the full-workspace build and the no-account testkit
  pass on Linux, macOS, and Windows; a `.gitattributes`/golden `\r`-absence check;
  a config-dir resolution test per OS.

Comprehensive testing and observability standards (apply to every crate):

- Unit tests live beside the code; each public behavior has at least one positive
  and one negative/refusal case. Coverage is tracked and a floor is enforced in
  CI so coverage cannot silently regress.
- A runnable end-to-end test harness (`tests/e2e/` plus a top-level
  `scripts/e2e/*.sh`) drives the real CLI binary and the MCP `serve` surface
  against the fastapi_rust mock server through full flows: profile validate →
  catalog scan → dataset inspect → query plan → query run (202 → 200 with gzip
  partitions) → query cancel → receipt lookup → export. Scripts are idempotent,
  hermetic (secret env vars stripped, live transport disabled), and exit non-zero
  on any deviation from the expected envelope/exit-code.
- Every test emits structured JSON-line logs (one event per step) with the
  `trace_id`, `command_id`, step name, timing, and outcome, written to a
  per-run artifacts directory so a failed run is legible and replayable without
  re-instrumentation. The deterministic clock and fixed seeds make timings and
  ordering reproducible; canonicalization zeroes time/host/hash fields before
  golden comparison and reports IEEE-754 bits on float mismatch.
- Canary-secret leak guards plant fake-but-detectable secrets in fixtures and
  scan all CLI/MCP output (stdout, stderr, receipts, logs, exports) for secret
  shapes; any leak fails the build.

Live opt-in tests:

- `profile doctor --online` minimal query.
- `catalog scan` against a trial account.
- small `select` query.
- async long-running query plus cancel.
- partitioned result query.

Live tests must skip/refuse clearly when credentials are absent, returning a typed
skip outcome with evidence, never silently passing. The spawned-CLI test helper
strips secret env vars and disables live transport from the other side to enforce
hermeticity.

## Free Trial Recommendation

Create a Snowflake trial account when practical. Snowflake's official trial
documentation says a trial account is available for evaluation with a valid email
address and no payment information. Use it for protocol learning and live smoke
tests, but keep the MVP independent of it by building the mock testkit first.

## Access Checklist For Any Live Deployment

Ask the Snowflake administrator for:

1. Account identifier and exact host.
2. Preferred auth lane: PAT, key-pair JWT, OAuth, or workload identity.
3. Read-only role name.
4. Warehouse name and size.
5. Database and schema list.
6. Whether network access is public Snowflake endpoint or private connectivity.
7. Which tables/views are in scope.
8. Expected row counts and large-export use cases.
9. Primary time columns and entity columns.
10. Sensitive data classes and redistribution restrictions.
11. Whether write-back is ever required.
12. Whether query history/cost visibility is allowed.

## Implementation Phases

### Phase 0: Repo And Task Graph

Create AGENTS.md, README.md, this plan, the Asupersync leverage doc, Beads graph,
`rust-toolchain.toml`, the `[patch.crates-io]` unification block, `deny.toml`, and
the single-asupersync-version CI gate. No connector code.

### Phase 1: Protocol Schemas And Test Fixtures

Implement core types (built on Asupersync `Outcome`) and SQL API
request/response schemas. Add official-example fixtures and deterministic JSON
tests.

### Phase 2: Auth

Implement PAT first, then key-pair JWT via the pinned `jsonwebtoken` `rust_crypto`
path. Add redaction tests, the credential `Debug`-leak compile gate, and profile
validation. OAuth follows once the core path is stable.

### Phase 3: Transport, Mock Server, And Statement Lifecycle

Build the Asupersync HTTPS transport (with manual gzip and jittered backoff) and
the two-lane testkit. Implement submit, poll, cancel (as a `bracket`), partition
fetch, and failure handling, with the DPOR race suite.

### Phase 4: CLI MVP And MCP Surface

Ship capabilities, robot-docs/agent-handbook, doctor, profile validate, query
plan, query run, and query cancel with deterministic JSON (`--json` default,
`--toon` available). Wrap the same handlers in the feature-gated
`franken-snowflake mcp serve` surface (stdio + read-only first).

### Phase 5: Catalog, Dataset Manifests, And Lineage Graph

Use Information Schema to build catalog snapshots and the three-part dataset
manifest model, plus the catalog lineage graph with default `catalog graph
--mermaid`/SVG output.

### Phase 6: Frame, Export, Cache, And TUI Integration

Add the FrankenSQLite/sqlmodel cache, optional FrankenPandas frame
materialization (`fp-columnar`/`fp-types`), content-addressed local CSV/JSONL
export plus `COPY INTO` export plans, and the opt-in (default-off) interactive TUI
behind the `tui` feature. Optional Frankensearch text indexing (`hash`/`lexical`
only). Establish the cross-platform
CI matrix and discipline here if not already in place from Phase 0. Define a
`Reranker` trait with a no-op default; the pure-Rust `frankensearch-rerank`
`native` cross-encoder (forbidden-dep-clean, cross-platform) is a deferred,
feature-gated drop-in for top-K refinement over long-text columns — added only if
a long-text retrieval surface emerges, never enabled by default.

### Phase 7: Live Trial Hardening

Run opt-in live tests against a trial account or other explicitly configured
Snowflake environment. Record exact proof and update docs.

## MVP Definition

The first genuinely useful MVP is:

- no-account testkit green, including the DPOR race suite
- single-asupersync-version gate and forbidden-dependency scan green
- PAT auth implemented; key-pair JWT crypto path implemented and redaction-tested
- SQL API submit/poll/cancel implemented as a cancel-correct `bracket`
- partition streaming with gzip implemented
- `capabilities --json`, `robot-docs guide` / `agent-handbook`, `doctor --json`,
  `profile validate --json`, and `query run --json` (raw SQL) implemented, with
  `--toon` output available on read commands
- `data_source` provenance stamped and `--require-live` honored
- secret redaction tests and the credential `Debug`-leak compile gate green
- `franken-snowflake mcp serve` exposing the read verbs as MCP tools
- catalog scan and the three-part manifest model documented, even if not fully
  implemented

## Why This Is Accretive

For FrankenSuite, this creates a reusable Snowflake connector built on the same
principles as Asupersync and related projects: structural concurrency,
deterministic testing, strong agent interfaces, and explicit proof artifacts. It
also exercises and hardens the FrankenSuite integration story — one unified
Asupersync version, the focused `fp-*` crates, the frankensqlite cache, the
fastmcp MCP surface, and the pure-Rust JWT path — in a clean public component.

For agents, it replaces "figure out Snowflake from scattered secrets and raw SQL"
with a discoverable, deterministic, self-documenting tool — callable as both a CLI
and an MCP server — that can explain what data exists, how to query it safely, how
to avoid expensive mistakes, and how to export or materialize results.
