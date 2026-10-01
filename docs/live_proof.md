# Live Proof Lanes

The live proof lane is opt-in and safe in no-account CI. By default it does not
resolve credentials and does not contact Snowflake. Instead, it writes a typed
`skip` event through the shared proof logger.

Official Snowflake docs consulted on 2026-06-25:

- https://docs.snowflake.com/en/developer-guide/sql-api/index
- https://docs.snowflake.com/en/developer-guide/sql-api/reference
- https://docs.snowflake.com/en/developer-guide/sql-api/handling-responses
- https://docs.snowflake.com/en/sql-reference/functions/system_wait
- https://docs.snowflake.com/en/sql-reference/functions/generator

## Command

```bash
export CARGO_TARGET_DIR=/data/tmp/fsnow_targets/pane6
scripts/live-proof.sh
```

The same lane can be run directly:

```bash
export CARGO_TARGET_DIR=/data/tmp/fsnow_targets/pane6
cargo test -p franken-snowflake-sqlapi --test live_proof -- --nocapture
```

Artifacts are written under
`${FRANKEN_SNOWFLAKE_LIVE_ARTIFACTS_DIR:-$CARGO_TARGET_DIR/fsnow-live-proof}`.

The crate also carries its own gated end-to-end lane next to the battery:
`cargo test -p franken-snowflake-cli --test cli_live_proof` spawns the real
binary (profile validate, `profile doctor --online`, `query run
--require-live`, `receipt show`, secret scan) under the same
`FRANKEN_SNOWFLAKE_LIVE=1` + `FRANKEN_SNOWFLAKE_LIVE_PROFILE=<profile>` opt-in
and records a typed `franken_snowflake.cli_live_gate.v1` skip event when the
opt-in or the profile handles are absent.


`scripts/live-proof.sh` runs two lanes: the driver-level test above, then the
**CLI battery** `scripts/live-proof-cli.sh`, which builds the binary with
`--features live,mcp` (or uses `FSNOW_BIN`) and drives the wired surfaces end
to end with `--json`, asserting the typed fields with `jq`:

| step | asserts |
|---|---|
| `binary_identity` | the binary's self-reported `exe_sha256` equals the file on disk, and its `build.source_digest` equals the digest of the working tree's crate sources and Cargo.lock (the git sha is recorded too); a build of other sources (or an unverifiable one) is refused unless `FSNOW_ALLOW_STALE_BIN=1`, which records `stale: true` in `summary.json` |
| `profile_validate`, `profile_doctor_online` | `ok`, `data_source=live`, a 64-hex `receipt_hash` |
| `query_run_small` then `receipt_show` | rows returned; the receipt reads back from the local store and names the statement handle |
| `query_run_partitioned` (+ `partition_early_stop`) | `--limit 10` returns 10 rows and stops fetching partitions early (a single-partition trial result is a finding, not a failure) |
| `query_cancel_completed_handle` | the cancel endpoint answers with a well-formed typed envelope |
| `catalog_scan`, `dataset_inspect`, `query_plan_dataset`, `query_run_dataset`, `dataset_profile_execute` | the snapshot persists, dataset mode plans and runs with typed bindings, profiling executes |
| `export_plan`, `export_run_csv`, `export_file` | a `COPY INTO` plan; a CSV written to disk |
| `secret_scan` | no secret handle value, private-key line, or bearer-token shape appears in anything captured |

Every step's envelope is saved as `<step>.json` next to `events.jsonl` and
`summary.json` in a fresh run directory that also holds the run's own local
store (`data/`), so receipts and snapshots are inspectable afterwards. The
script exits non-zero on the first hard failure. `scripts/live-proof-cli.sh
--selftest` proves the harness offline: a planted commit mismatch (the
identity check must refuse it), an offline command, an offline refusal, and a
planted-canary scan (the scan must report the hit).

The credentialed run of this battery is the evidence that closes bead
`fsnow-agent-ergonomic-cli-cli-live-e2e-and-receipts-bvf`; the offline
scope is complete (receipts wired, `--require-live` gate, the gated
in-crate `cli_live_proof` test), and only the credentialed evidence run —
against a fresh Snowflake trial account — remains.

## Required Opt-In

```bash
export FRANKEN_SNOWFLAKE_LIVE=1
export FRANKEN_SNOWFLAKE_LIVE_PROFILE=trial
```

The profile name maps to an env prefix by uppercasing ASCII letters/digits and
turning `.`, `-`, and `_` into `_`. For `trial`, the prefix is
`FRANKEN_SNOWFLAKE_TRIAL`.

Required non-secret profile handles:

```bash
export FRANKEN_SNOWFLAKE_TRIAL_ACCOUNT=<account-identifier-or-https-url>
export FRANKEN_SNOWFLAKE_TRIAL_USER=<user>
export FRANKEN_SNOWFLAKE_TRIAL_AUTH=pat
export FRANKEN_SNOWFLAKE_TRIAL_DATABASE=<database>
export FRANKEN_SNOWFLAKE_TRIAL_SCHEMA=<schema>
export FRANKEN_SNOWFLAKE_TRIAL_WAREHOUSE=<warehouse>
```

Auth-specific secret handles:

```bash
export FRANKEN_SNOWFLAKE_TRIAL_PAT=<redacted>
# or:
export FRANKEN_SNOWFLAKE_TRIAL_AUTH=oauth_bearer
export FRANKEN_SNOWFLAKE_TRIAL_OAUTH_BEARER=<redacted>
# or:
export FRANKEN_SNOWFLAKE_TRIAL_AUTH=key_pair_jwt
export FRANKEN_SNOWFLAKE_TRIAL_PRIVATE_KEY_PEM=<redacted>
export FRANKEN_SNOWFLAKE_TRIAL_PRIVATE_KEY_PASSPHRASE=<redacted> # optional
```

Optional handles:

```bash
export FRANKEN_SNOWFLAKE_TRIAL_ROLE=<role>
export FRANKEN_SNOWFLAKE_TRIAL_MAX_POLLS=120
export FRANKEN_SNOWFLAKE_TRIAL_PROFILE_SQL='SELECT CURRENT_VERSION() AS SNOWFLAKE_VERSION'
export FRANKEN_SNOWFLAKE_TRIAL_CATALOG_SQL='SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES ORDER BY TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME LIMIT 1'
export FRANKEN_SNOWFLAKE_TRIAL_SMALL_SQL='SELECT 1 AS FSNOW_LIVE_PROOF'
export FRANKEN_SNOWFLAKE_TRIAL_CANCEL_SQL="CALL SYSTEM$WAIT(30, 'SECONDS')"
export FRANKEN_SNOWFLAKE_TRIAL_PARTITION_SQL='SELECT SEQ4() AS N FROM TABLE(GENERATOR(ROWCOUNT => 50000))'
```

## Covered Lanes

- `credential_gate`: proves opt-in/profile/env handles and constructs the
  auth descriptor without logging secret values.
- `profile_doctor_online`: runs a small online probe through the real SQL API
  driver.
- `catalog_scan`: runs an `INFORMATION_SCHEMA.TABLES` query through the real SQL
  API driver. Empty results are valid.
- `small_select`: runs a deterministic one-row read.
- `async_cancel`: submits `CALL SYSTEM$WAIT(...)` asynchronously and calls the
  SQL API cancel endpoint for the returned statement handle.
- `partitioned_result`: runs a synthetic `GENERATOR(ROWCOUNT => 50000)` read and
  requires Snowflake to return more than one partition. If a trial account does
  not partition that default query, set `FRANKEN_SNOWFLAKE_TRIAL_PARTITION_SQL`
  to a larger read-only query.

Missing credentials are not a pass-by-omission: the test writes a structured
`franken_snowflake.live_gate.v1` skip event with the missing env handle names.
Secrets are never written to the events or summaries.

## Live Runs

### 2026-09-28: first end-to-end CLI run

This run used a production Snowflake account (not a trial) through the key-pair
JWT lane. The account, user, warehouse and database names are withheld. The
binary was a release build of `bcc10fe` with `--features live,mcp` (source
digest `3edc59aa…`), run from the operator's host. The artifacts stayed local.

| Step | Verdict |
|---|---|
| `profile validate`, `profile doctor --online` | pass (login 6.5 s, receipt recorded) |
| `query run`: small read; a 50 000-row GENERATOR read with `--limit 10` | pass; the fetch stopped early (`partition_early_stop`) |
| `receipt show` | pass |
| 10 statement-count probes (`sql_guard_*`, bead oj0.23) | pass: Snowflake's count matched the lexer's on every shape, including a trailing `;` followed by a comment |
| `query cancel` of a completed handle | pass |
| `catalog scan` (with and without `--tags`), `catalog graph` | pass; the scratch schema had no tables, so the dataset lanes, `catalog search` and `catalog lineage` did not run |
| `export plan`, `export run --format csv` | pass |
| Differential against snowflake-connector-python 4.7.5 (bead oj0.22) | pass: 27/27 type-matrix columns match, compared to the microsecond |
| `export run --format parquet` read back with pyarrow | pass: 27/27 columns equal the typed rows at nanosecond precision (a one-off check) |
| In-flight cancel: SIGINT during `SELECT SYSTEM$WAIT(60)` | pass: `cancelled`, exit 130, and the remote cancel was acknowledged. **Finding:** the first Ctrl-C took effect only when the synchronous submit answered, about 40 s later |
| jsonv2 capture (`capture-jsonv2-golden.sh`, bead w0i.13) | pass. It confirmed DATE as epoch days, TIME/NTZ/LTZ as fractional epoch **seconds** (not nanoseconds), TIMESTAMP_TZ as `<seconds> <offset+1440>`, and lower-case `rowType.type`. The golden is `crates/franken-snowflake-frame/tests/captured/jsonv2-wire-golden.json` |
| Upstream error: a missing database | pass: typed `FSNOW-4002` carrying Snowflake's message |
| Secret scan over every artifact and transcript | pass |

These did not run:

- write steps, which await the operator's go-ahead for this account;
- the PAT lane, which the account's network policy blocks;
- OAuth;
- the dataset round trip, because the scratch schema had no table.

## Wire Transcripts

Every `scripts/live-proof-cli.sh` step runs with
`FRANKEN_SNOWFLAKE_CAPTURE_DIR=<run dir>/transcripts/<step>`, so each live HTTP
exchange is written as `<seq>-<route>.json`, where route is `submit`, `poll`,
`partition` or `cancel` (bead oj0.21). The recorder
(`franken_snowflake_http::capture`) makes these changes before writing:

- it keeps only the path and query, never the host;
- it replaces the account host and name wherever else they appear;
- it writes `Authorization`, cookie and token header values as `[REDACTED]`;
- it maps statement handles and request ids to stable placeholders;
- it decodes gzip bodies and marks them.

A transcript that still holds one of the profile's secret env values, or a
bearer-token shape, is not written. A `refused-<seq>.txt` with the reason is
left in its place, and the battery's secret scan covers the transcripts as well.

`franken_snowflake_http::capture::ReplayHttp` serves a transcript directory
back as the transport, so the production driver can run against what
Snowflake actually sent. The socket e2e
`a_captured_run_replays_through_the_production_driver` proves the full loop
over TLS against the mock. To turn a live run into regression fixtures, review
the transcripts and commit the steps under
`crates/franken-snowflake-testkit/fixtures/replay/<step>/`.

## Questions the First Credentialed Run Answers

Besides the lanes above, `scripts/live-proof-cli.sh` answers three open questions
in the same run:

- **Statement counts (bead oj0.23):** ten SELECT-only `sql_guard_*` shapes run
  (semicolons in strings, in `--`/`//`/block comments, in `$$` and quoted
  identifiers; a trailing `;` with and without a comment; two statements). Every
  request pins `MULTI_STATEMENT_COUNT` to the lexer's count, so Snowflake refuses,
  without executing, any request whose count differs. A failing probe is a
  finding that names the shape. Nested block comments are not probed, because
  the lexer refuses them locally.
- **Correctness against the incumbent (bead oj0.22):** when `uv` is available,
  `scripts/differential-python-connector.py` runs one type-matrix SELECT through
  fsnow and through `snowflake-connector-python==4.7.5`, then compares the cells
  in `differential.json`. Times and timestamps are compared to the microsecond,
  because Python's datetime stops there. `--self-test` checks the normalization
  and the documented `connect()` arguments offline.
- **Result encoding (bead w0i.13):** `scripts/capture-jsonv2-golden.sh` is run
  separately.

## Spawned CLI Safety

Any helper that spawns the CLI from the live proof harness must build a sanitized
environment first. The contract is:

- remove `FRANKEN_SNOWFLAKE_LIVE_PROFILE`;
- force `FRANKEN_SNOWFLAKE_LIVE=0` for the child process;
- strip Snowflake secret-shaped env vars such as `_PAT`, `_OAUTH_BEARER`,
  `_PRIVATE_KEY_PEM`, `_PRIVATE_KEY_PASSPHRASE`, `_PASSWORD`, `_TOKEN`, and
  `_SECRET`.

This lets the live test exercise the real SQL API path only in the parent lane
that has explicit credentials, while spawned offline checks cannot accidentally
inherit live transport or raw credential values.
