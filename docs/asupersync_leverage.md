# Asupersync Leverage Contract

Date: 2026-06-24

This document maps every hard part of a Snowflake SQL API connector to a
concrete Asupersync primitive. It exists because Asupersync is not "a runtime
that does networking and cancellation." Its `Budget` / `Outcome` / capability
control plane is the application semantics layer, and `franken_snowflake` should
adopt it as a contract, not as decoration.

Read these skill references before implementing the connector spine:

- `asupersync-mega-skill` → `NATIVE-GREENFIELD.md`
- `asupersync-mega-skill` → `GREENFIELD-PATTERNS.md`
- `asupersync-mega-skill` → `BUDGET-OUTCOME-CAPABILITIES.md`
- `asupersync-mega-skill` → `LEVERAGE-PLAYBOOK.md`
- `asupersync-mega-skill` → `TESTING-FORENSICS.md`
- `asupersync-mega-skill` → `LAB-TRACE-DPOR.md`
- `asupersync-mega-skill` → `WEB-GRPC-HTTP.md` (request-region pattern, for the MCP/HTTP surface)

## Mapping

Each line is `concern → primitive — payoff`, kept compact deliberately:

- **Query outcome** → `Outcome<T,E>` (Ok/Err/`Cancelled`/`Panicked`) — a cancelled
  query is not an error; preserve all four states to the CLI/MCP edge so retry,
  drain, and receipt behavior stay correct. `SnowflakeOutcome<T>` wraps this.
- **Cancellation classes** → match `reason.kind` (`CancelKind`), where
  `CancelReason` is a **struct** (not a flat enum). Kinds:
  `User`/`Timeout`/`Deadline`/`PollQuota`/`CostBudget`/`FailFast`/`RaceLost`/
  `ParentCancelled`/`Shutdown`/... A budgeted query that runs out of time surfaces
  as `Deadline` (and cost-quota breach as `CostBudget`) — **not** `Timeout`, which
  is the explicit timeout-combinator path; route both like a timeout (retry or
  degrade). `User` calls remote cancel + writes a receipt; `Shutdown` drains
  within budget; `RaceLost`/`ParentCancelled` drain quietly.
- **Warehouse cost / row cap / deadline** → `Budget` (deadline + poll quota +
  **cost quota** + priority) with `meet()` — Snowflake cost is the cost quota and
  a breach surfaces as `Cancelled(CostBudget)`; partition fetchers inherit a
  tighter child budget; cancel/cleanup runs masked. The cost quota is advisory;
  the enforceable ceiling is server-side `STATEMENT_TIMEOUT_IN_SECONDS` + row caps.
- **Read-only by default** → capability rows `[SPAWN,TIME,RANDOM,IO,REMOTE]` with
  compile-time `SubsetOf`. Mind the layer: `cx_readonly()` is `Cx<cap::None>` —
  **zero capabilities, no IO** — so it fits only the pure planning/validation/
  SQL-compile path. The transport layer needs a narrowed `Cx` granting `IO` (and
  `TIME`/`SPAWN`) but never `REMOTE`. Only the write-intent ladder widens further.
  Read-only is compiler-enforced.
- **No orphan statement handles** → `bracket` (acquire/use/release) — a submitted
  handle is an obligation; the remote cancel endpoint always fires on drop/cancel.
- **No orphan partition fetchers** → `Scope` + bounded child regions — concurrent
  fetch under one capped region; cancellation drains the whole region.
- **Tail latency on fetch** → Asupersync's optional backup-request combinator
  (`Scope`-level; see the mega-skill) — a deliberate backup fetch with loser-drain,
  not ad-hoc future racing.
- **429 storms / overload** → `ServiceBuilder` (retry/rate_limit/concurrency_limit/
  timeout). The built-in client `RetryPolicy` only auto-retries **idempotent GET**
  (poll/partition) and only honors `Retry-After`/fixed delay — it does **not**
  retry the submit `POST` (excluded as non-idempotent). Our own jittered
  exponential backoff owns submit retries, made safe by the `requestId` +
  `retry=true` idempotent-resubmit contract. `Retry-After` is not guaranteed on a
  Snowflake 429, so do not depend on it.
- **Per-call cancellation region (MCP/HTTP serve)** → `web::request_region` —
  wrap each agent call so a disconnect drains the statement `bracket` + partition
  `Scope` as one owned region, beyond cooperative `checkpoint()` points.
- **Long-query progress** → the native `cli::progress::ProgressEvent`
  (`kind`/`current`/`total`/`message`/`elapsed_ms`, serde-derived) for
  partition-fetch progress on stderr, rather than a hand-rolled NDJSON schema.
- **Connection reuse** → the `src/http/pool.rs` pool — keep-alive across the
  submit → poll → partition sequence.
- **Cancel/retry race correctness** → `LabRuntime` + DPOR + `VirtualTcp` +
  obligation-leak/quiescence oracles — prove zero leaks at any interleaving.
- **Deterministic backoff/TTL in tests** → injected lab clock — no real sleeping.
- **Replayable forensics** → trace capture / crashpack / replay manifest — failed
  runs replay; receipts carry artifact pointers.

## HTTP Client Realities To Engineer Around

The Asupersync HTTP client is real and pooled, but five facts shape the design:

1. **Gzip is not auto-decompressed.** `Response::json()` returns raw bytes. Later
   Snowflake partitions are gzip. Wire `GzipDecompressor` (the `compression`
   feature) manually off the `content-encoding` header in the SQL API layer.
2. **The high-level `HttpClient` does not accept an injected transport.** It calls
   `TcpStream::connect` internally, so deterministic tests drive the lower-level
   `Http1Client::request<IO>(io, req)` codec over a `VirtualTcpStream` pair.
3. **The TLS handshake is not cancel-safe.** Cancel mid-handshake means drop the
   connection. Treat "cancelled during connect" as a distinct receipt state.
4. **The high-level client is HTTP/1.1 only** (ALPN advertises `http/1.1`).
   Snowflake's SQL API works over 1.1. Concurrency comes from the connection
   pool, not HTTP/2 stream multiplexing.
5. **Built-in retry only honors `Retry-After` / fixed delay.** Layer jittered
   exponential backoff on top for general 429/5xx handling.

## Dependency Unification Rule

Every FrankenSuite dependency (`asupersync`, `fsqlite`, `sqlmodel-*`, `fp-*`,
`fastmcp-rust`, `frankensearch`) must resolve to a single `asupersync` version.
Use `[patch.crates-io]` to point them at one consistent set, and add a CI gate
that fails if `cargo tree` reports more than one `asupersync`. This is the single
most common failure mode when composing these crates.

## Surfaces To Avoid Leading With

Per the skill's guidance, do not build the connector around Browser Edition,
QUIC / HTTP3, the messaging integrations, remote/distributed execution, or
RaptorQ snapshot distribution. The highest-leverage path is `RuntimeBuilder` +
`Cx` + `Scope`, request/call regions for the MCP/HTTP surface, the native HTTP
client + TLS, native channels/sync/combinators, and deterministic Lab/DPOR tests
from the start.
