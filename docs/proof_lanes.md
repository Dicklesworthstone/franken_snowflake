# Proof Lanes

Date: 2026-06-24

The proof lanes `franken_snowflake` must keep green. This distills the "Test
Plan" and "Testing Expectations" sections of
`COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md` and `AGENTS.md`. The governing rule:
**the first implementation must be testable without a live Snowflake account**;
no-account golden fixtures land before any live test, and a live test missing
credentials emits a typed skip/refusal, never a silent pass.

## Lane 1 — No-Account Protocol Goldens

- JSON schema round trips for the official SQL API examples.
- Status-code routing fixtures proving 200 / 202 / 408 / 422 / 429 are distinct
  states, none conflated: a 202→200 poll-continue sequence, a 429-backoff (no
  `Retry-After`) retry, a 408 statement-timeout outcome, and a 422 failure.
- Idempotent-submit fixture: a `requestId` + `retry=true` resubmit returns the
  prior result rather than re-executing.
- JWT claim-format golden: `iss = ACCOUNT.USER.SHA256:<fp>`, `sub = ACCOUNT.USER`
  (no fp), uppercasing, org-account `.`→`-`, and the ≤ 3600s `exp` cap.
- `jsonv2` wire-codec unit tests: `DATE` (epoch days), `TIME` / `TIMESTAMP_*`
  (fractional epoch **seconds**, not nanos), `TIMESTAMP_TZ` (offset encoded as
  `offset_minutes + 1440`), `NUMBER` (no scale division), `BOOLEAN` (string).
- Multiple-statement refusal by default; when allowed, a `MULTI_STATEMENT_COUNT`
  + `statementHandles[]` fan-out fixture and a bindings-with-multi-statement
  refusal.
- Partition streaming with a gzip fixture.
- Cancelled-during-connect receipt-state fixture (the TLS handshake is not
  cancel-safe — a distinct state from a submitted-then-cancelled statement).
- `data_source` provenance fixture and a `--require-live` refusal fixture.

## Lane 2 — Deterministic Cancel/Retry Races (DPOR)

`Http1Client::request<IO>` codec driven over a `VirtualTcpStream` pair under
`LabRuntime`, with DPOR exploration of cancellation/retry interleavings:

- cancel-during-submit, cancel-during-poll, cancel-during-partition-fetch,
  429-storm, partial-partition-failure;
- each asserted by the **obligation-leak** and **quiescence** oracles (zero
  leaked connections, statements, or partition fetchers after a cancel) — run as
  CI gates, not just exploration, plus fixed-seed chaos presets;
- failed runs emit an Asupersync crashpack whose replay command and fingerprint
  are stamped into the receipt's artifact pointers.

## Lane 3 — Integration (Mock SQL API Server)

A stateful mock built on `fastapi_rust` (Asupersync-native, **dev-dependency
only**, candidate until cargo-tree-proven): a first GET returns 202, later GETs
return 200 with partitions, gzip bodies, and custom headers. Auth-header
inspection asserts redaction. A runnable end-to-end harness (`tests/e2e/` plus
top-level `scripts/e2e/*.sh`, with a `cargo xtask e2e` entrypoint for Windows)
drives the real CLI binary and the MCP `serve` surface through full flows:
profile validate → catalog scan → dataset inspect → query plan → query run
(202 → 200 with gzip partitions) → query cancel → receipt lookup → export. The
scripts are idempotent, hermetic (secret env vars stripped, live transport
disabled), and exit non-zero on any envelope/exit-code deviation.

## Lane 4 — Secret-Safety Gates

- Secret redaction fixture and the credential `Debug`-leak compile gate
  (`docs/security_model.md`).
- Canary-secret leak guards: plant fake-but-detectable secrets in fixtures, scan
  all stdout / stderr / receipts / logs / exports for secret shapes; any leak
  fails the build.

## Lane 5 — Surface Goldens (CLI / MCP / Output Modes)

- CLI deterministic JSON golden and an MCP tool-schema golden.
- CLI/MCP parity test: the same logical operation yields the same envelope, error
  code, receipt, and safety class through both surfaces.
- `--toon` output golden (round-trips to the same data as `--json`).
- `catalog graph --mermaid` golden + graph-algorithm unit tests
  (ancestors / descendants / what-relates-to / cycle detection) over a fixture
  catalog.
- `export` goldens for local CSV/JSONL (content-addressed records) and a
  `COPY INTO <location>` export-plan golden.
- TUI model/update unit tests (no real terminal) over scripted catalog state.
- `NO_COLOR` / `CI` / non-TTY fixture.

## Lane 6 — Dependency And Toolchain Gates

> Owned by the toolchain bead (`fsnow-native-snowflake-connector-w0i.3`) and the
> per-dependency admissibility bead (`fsnow-native-snowflake-connector-w0i.7`);
> listed here so the proof surface is complete.

- Forbidden-dependency scan: the production feature graph fails if Tokio,
  reqwest, hyper, axum, tower, sqlx, diesel, or sea-orm appear.
- Single-`asupersync`-version gate: CI fails if `cargo tree` reports more than one
  `asupersync`.
- Per-candidate-dependency cargo-tree admissibility proof, with dev-only and
  feature-gated paths scanned in their own configurations.

## Lane 7 — Cross-Platform Proof

The full-workspace build (`--features tls,tls-native-roots,compression`) and the
no-account testkit pass on Linux, macOS, and Windows (`os: [ubuntu-latest,
macos-latest, windows-latest]`, `fail-fast: false` — never test only one
sub-crate on Windows). A `.gitattributes` forces `eol=lf` on
`*.json`/`*.golden`/`*.toml` fixtures; a CI check asserts no golden contains
`\r`; goldens compare as raw bytes; fixture filenames are lowercase and
non-case-colliding. A config-dir resolution test runs per OS.

## Lane 8 — Live Opt-In (Phase 7)

Opt-in tests against a trial or explicitly configured account: `profile doctor
--online` minimal query, `catalog scan`, a small `select`, an async long-running
query plus cancel, and a partitioned-result query. They skip/refuse clearly with
a typed skip outcome and evidence when credentials are absent — never a silent
pass. The empirically captured `jsonv2` timestamp-unit golden is pinned here,
resolving the doc ambiguity Lane 1's codec tests are written against.

## Cross-Cutting Standards

- Unit tests live beside the code; each public behavior has ≥ 1 positive and ≥ 1
  negative/refusal case. Coverage is tracked with a CI-enforced floor so it
  cannot silently regress.
- Every test emits structured JSON-line logs (one event per step: `trace_id`,
  `command_id`, step name, timing, outcome) to a per-run artifacts directory, so
  a failed run is legible and replayable without re-instrumentation.
- A deterministic injected clock and fixed seeds make timings and ordering
  reproducible; canonicalization zeroes time/host/hash fields before golden
  comparison and reports IEEE-754 bits on float mismatch.

## Shared Harness (implemented)

These cross-cutting standards are implemented **once** in the generic
`franken_snowflake_testkit::harness` module (bead
`fsnow-native-snowflake-connector-w0i.15`, closed). Every crate consumes it as a
dev-dependency rather than re-rolling logging or golden comparison; the
Snowflake-specific fixtures and the `fastapi_rust` mock build on top of it
(`fsnow-deterministic-testkit-bak`). It carries no Snowflake protocol knowledge
and performs no live IO.

- `harness::golden` — `GoldenConfig` (volatile time/host/hash/run-id zeroing;
  stable `command_id`/`request_id`/domain ids excluded by default, opt-in via
  `with_volatile_key`), `to_canonical_json` (sorted-key, compact, LF-only),
  `compare` (structural, IEEE-754 bits on float mismatch), `check_golden_file` /
  `write_golden` (with the `FSNOW_UPDATE_GOLDENS=1` bless flow), and
  `assert_no_cr` / `assert_lf_only` for the Lane 7 `eol=lf` rule.
- `harness::logger` — `RunLogger` writes one JSON-line `StepEvent`
  (`trace_id`/`command_id`/`seq`/`elapsed_ms`/`outcome`, plus expected-vs-actual
  on failure) to `‹artifacts_root›/‹trace_id›/events.jsonl`, then `finish()`
  emits `summary.json` + `summary.txt` and returns a `RunSummary`.
- `harness::clock` — the injected `Clock` (`SystemClock` / `ManualClock`), a
  seeded SplitMix64 `DeterministicRng`, a `Deadline` TTL, and a reproducible
  `backoff_schedule(policy, seed)`.
- `harness::canary` — `CanaryGuard` scans stdout/stderr/files for planted
  canaries and for production secret shapes via the single shared needle list in
  `franken_snowflake_core::redact` (so the guard and the redactor cannot drift,
  per `docs/security_model.md`).

A committed golden fixture lives at
`crates/franken-snowflake-testkit/fixtures/golden/sample_run.golden.json`; each
module ships beside-the-code self-tests with positive and negative cases.
