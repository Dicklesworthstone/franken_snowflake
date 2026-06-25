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
