# Security Model

Date: 2026-06-24

The normative security contract for `franken_snowflake`. It distills the
"Security Model" and "Safety And Security" sections of
`COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md` and `AGENTS.md`. Three properties
are load-bearing and self-reinforcing: the connector **cannot leak secrets**,
**cannot run away with cost**, and is **read-only by default**.

## Security Defaults

- **Read-only by default**, enforced at runtime: `query run` accepts one read
  statement (the shared SQL lexer in `franken-snowflake-core::sql_lexer`; see
  "SQL Statement Guard" below), and `query write` refuses unless the profile
  sets `WRITE_ENABLED`. The target design also narrows Asupersync capability
  rows (planning under `cx_readonly()`, transport without `REMOTE`, only the
  write ladder wider); those types exist in `franken-snowflake-core` but no call
  path narrows its `Cx` yet. See `docs/asupersync_leverage.md`.
- **No secret values** in config files, `Debug`, `Display`, JSON output, error
  messages, panic text, Beads comments, support bundles, logs, or test fixtures.
- **TLS required** on every live connection.
- **No live query** without an explicit profile and credential source; the
  connector never silently falls back from live Snowflake to fixtures
  (`data_source` provenance is always stamped, and `--require-live` refuses any
  substitution).
- **No mutation** without the explicit write-intent ladder.

## Secret Handling

Profiles are non-secret TOML. They reference environment variable **names** or
external secret-provider handles — never raw token values. The profile file
never stores a PAT or a private key.

```toml
[profiles.demo-prod]
account   = "xy12345.us-east-1"
host      = "xy12345.us-east-1.snowflakecomputing.com"
user      = "SNOWFLAKE_SERVICE"
role      = "SNOWFLAKE_READONLY"
warehouse = "SNOWFLAKE_XS"
database  = "ANALYTICS"
schema    = "PUBLIC"
auth      = { kind = "pat", env = "SNOWFLAKE_PAT" }
# or: auth = { kind = "key_pair_jwt", private_key_env = "SNOWFLAKE_PRIVATE_KEY_PEM",
#              private_key_passphrase_env = "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE" }
```

Auth constructors return **redacted** `Debug` output by default. The real env var
name is `#[serde(skip_serializing)]`. Diagnostics reference opaque `cred_*`
handles, never the env var name or the secret. Account identifiers are redacted
when requested; tokens and private keys are **always** redacted.

## The Two Anti-Leak Mechanisms

1. **Credential `Debug`-leak gates.** The auth crate's build script scans its
   sources and fails the build if a struct with a credential-shaped field
   (`*_api_key`, `*_password`, `*_private_key`, `*_token`, ...) lacks a
   hand-rolled redacting `Debug` (bead `fsnow-native-snowflake-connector-w0i.5`).
   The workspace test `crates/franken-snowflake-testkit/tests/debug_leak_gate.rs`
   scans every crate's `src/` for structs and enums (named fields, tuple fields,
   and tuple variants named for a credential) whose derived `Debug` would print
   a credential-shaped field or credential type (`SecretValue`,
   `SecretString`, `EncodingKey`, `AuthorizationDescriptor`), or whose manual
   `Debug`/`Display` prints the field or never redacts. A field whose type
   has its own verified redacting `Debug` is safe under a derived one. Planted
   controls prove every shape is still caught (bead oj0.10).
2. **One composable redactor, one needle list.** The redactor sources its needle
   list from **one shared constant** — `franken-snowflake-core::redact::SECRET_PREFIXES`
   — so the redactor and the last-mile output scanner **cannot drift**. It uses
   token-boundary, longest-prefix detection over known secret shapes (`eyJ`,
   `AKIA`, `ASIA`, `ghp_`, `gho_`, `github_pat_`, `sk-`, `xoxb-`, `xoxp-`,
   `glpat-`, `AIza`, ...) via `redact::redact()` / `redact::contains_secret()`,
   replacing each match with `redact::REDACTION_PLACEHOLDER` (`[REDACTED]`). The
   canary-secret leak guards (`docs/proof_lanes.md`) **import the same
   `SECRET_PREFIXES` constant**: the testkit guard plants fake-but-detectable
   secrets in fixtures and scans all stdout / stderr / receipts / logs / exports,
   and any leak fails the build. Because the production redactor and the test-time
   guard read one constant, a newly observed secret shape is added in exactly one
   place and both sides stay in lock-step.
3. **Secret values inside SQL.** A statement can carry a secret as a string
   value, and the local store is append-only, so a leak there is permanent. The
   same `redact()` also replaces the value of every secret-bearing parameter
   (`<param> = '...'`, `<param> => '...'`, or `$$...$$`) with `[REDACTED]`,
   keeping the quotes; a name matches when it contains `PASSWORD`,
   `PASSPHRASE`, `SECRET`, `TOKEN`, `CREDENTIAL`, or `_KEY`
   (`redact::SECRET_SQL_PARAMETER_FRAGMENTS`). The families, per the Snowflake
   SQL reference (consulted 2026-09-24):
   [CREATE USER](https://docs.snowflake.com/en/sql-reference/sql/create-user)
   `PASSWORD`;
   [CREATE STAGE](https://docs.snowflake.com/en/sql-reference/sql/create-stage)
   and [COPY INTO](https://docs.snowflake.com/en/sql-reference/sql/copy-into-table)
   `CREDENTIALS = (AWS_KEY_ID, AWS_SECRET_KEY, AWS_TOKEN | AZURE_SAS_TOKEN)` and
   `ENCRYPTION = (MASTER_KEY, KMS_KEY_ID)`;
   [CREATE SECRET](https://docs.snowflake.com/en/sql-reference/sql/create-secret)
   `SECRET_STRING`, `OAUTH_REFRESH_TOKEN`, `PASSWORD`;
   [API authentication integrations](https://docs.snowflake.com/en/sql-reference/sql/create-security-integration-api-auth)
   `OAUTH_CLIENT_SECRET`;
   [CREATE API INTEGRATION](https://docs.snowflake.com/en/sql-reference/sql/create-api-integration)
   `API_KEY`. The scan is context-free, so it also catches a value inside a
   shell command or a message, and every envelope string, receipt preview,
   audit event (redacted again at the sink), and export provenance record passes
   through it. The SQL submitted to Snowflake is never altered. A suggested
   command (`confirm_command`, a dry-run hint) never embeds SQL that carried a
   secret, because a redacted copy would run with `[REDACTED]` as the value; it
   says `--sql <the same SQL; its secret values are not echoed>` instead.

## Auth Lanes

Implemented in this order; a later lane never blocks an earlier one:

1. **Programmatic access token (PAT)** — bearer header with
   `X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN`. Default
   15-day expiry (policy-capped, max 365).
2. **Key-pair JWT** — RS256 over the pure-Rust `jsonwebtoken`
   (`rust_crypto` + `use_pem`) path; `X-Snowflake-Authorization-Token-Type:
   KEYPAIR_JWT`. Claims: `iss = "<ACCOUNT>.<USER>.SHA256:<fp>"`,
   `sub = "<ACCOUNT>.<USER>"` (no fingerprint), uppercase ACCOUNT/USER, org-form
   `.`→`-`. Effective `exp` is capped at ≤ 3600s and re-signed before a poll or
   fetch that would outlive it (Snowflake caps JWT validity at 1 hour). See "Auth Crypto Path" in
   the plan.
3. **OAuth bearer** pass-through (short-lived, commonly ~10 min). The connector
   cannot refresh it: a token that expires mid-poll becomes a typed
   `credential_expired` error (with a remote cancel when a statement handle exists).
4. **Workload identity federation** — quarantined. The implementation exchanges
   the OIDC token through an RFC 7523 grant, which is not Snowflake's documented
   SQL API scheme (`Authorization: Bearer WIF.<provider>.<token>` with
   `X-Snowflake-Authorization-Token-Type: WORKLOAD_IDENTITY_FEDERATION`), so
   `profile validate` reports the lane as unusable and the live path refuses it.

`profile validate --json` checks shape and env-var presence without contacting
Snowflake and without reading a secret value. It fails (exit 3, `FSNOW-2002`) a
profile the live path would refuse: an `_ACCOUNT` that does not form a canonical
`https://<account>.snowflakecomputing.com` endpoint (checked with the same rule
the transport applies) or an unknown or quarantined lane. `profile doctor`
reports lifetime guidance for the configured lane from non-secret configuration
only (for example, a `_JWT_VALIDITY_SECONDS` above the 3600 s cap); it cannot see
a PAT or OAuth token's expiry offline. `profile doctor --online` reports what is
knowable once authenticated: a JWT-shaped OAuth bearer's `exp` (warning under 10
minutes; Snowflake's own OAuth tokens are opaque), and for the PAT lane the
user's active tokens from `SHOW USER PROGRAMMATIC ACCESS TOKENS` with a warning
when one expires within 7 days (the secret is never returned, so the profile's
own token cannot be singled out). RSA keys under 2048 bits are refused when
the live path loads the key.

## Fail-Closed Rights

- An unknown rights label parses to the **most restrictive** class.
- An expired entitlement is treated as **missing**, not as default-allow.
- Rights and sensitivity metadata travel with dataset manifests
  (`docs/dataset_manifest_contract.md`).

## SQL Statement Guard

Every guard that reasons about SQL text — statement counting, the read-path
classifier (`query plan` / `query run` / export / TUI), write classification, and
refusal messages — runs on one lexer, `franken_snowflake_core::sql_lexer`
(before 2026-09-24 there were four hand-rolled scanners, none of which knew
dollar-quoted strings, so `SELECT $$ it's $$; DROP ...` counted as one read).

Lexical rules (Snowflake docs consulted 2026-09-24:
[string constants](https://docs.snowflake.com/en/sql-reference/data-types-text#string-constants),
[identifiers](https://docs.snowflake.com/en/sql-reference/identifiers-syntax),
[comments](https://docs.snowflake.com/en/sql-reference/constructs/comments)):

- single-quoted strings with `''` and backslash escapes; `$$ ... $$` strings;
  double-quoted identifiers with `""`; `--` and `//` line comments; `/* */`
  block comments;
- `$` inside an unquoted identifier (`SYSTEM$TYPEOF`, `a$b`) is part of the
  identifier, and `$1` / `$name` are positional columns / session variables,
  never string openers.

Fail-closed decisions:

- **Nested block comments are refused.** Whether Snowflake nests `/* */` is not
  documented, and the readings disagree (`/* /* */ select 1 */ delete from t` is a
  DELETE if comments nest, a SELECT if not). Unterminated quotes, `$$` strings and
  comments are refused too. A live probe (reality-check bead D5) can relax this
  with evidence.
- **Read-path side effects are refused**: any `SYSTEM$` function outside a
  read-only allowlist (e.g. `SYSTEM$CANCEL_ALL_QUERIES`, `SYSTEM$ABORT_SESSION`)
  and sequence `NEXTVAL`. Allowlisted: `SYSTEM$TYPEOF`, `SYSTEM$WAIT`,
  `SYSTEM$CLUSTERING_*`, `SYSTEM$EXPLAIN_*`, `SYSTEM$GET_TAG*`,
  `SYSTEM$PIPE_STATUS`, `SYSTEM$STREAM_*` and a few other read-only functions
  (the list lives in `sql_lexer.rs`).
- **Server-side backstop:** every live submit sets `MULTI_STATEMENT_COUNT = "1"`,
  so Snowflake rejects a request whose statement count differs instead of
  running it, whatever the account-level default is. (The request default is 1
  per the [SQL API reference](https://docs.snowflake.com/en/developer-guide/sql-api/reference);
  the parameter can also be set at account level, so it is pinned explicitly.)

The strongest read-only guarantee is still Snowflake RBAC: give read profiles a
role that cannot write (reality-check bead L4 adds a `profile doctor --online`
check for this).

## Cost Safety

The enforceable guardrail is **server-side**: every query sets
`STATEMENT_TIMEOUT_IN_SECONDS` plus a result row cap. The client-side Asupersync
`Budget` cost quota is **advisory** telemetry layered on top — a breach surfaces
as `Cancelled(CostBudget)` with a distinct `outcome_kind`/exit code — because
warehouse credits cannot be metered precisely client-side. Large result sets
require `--export`, `--max-rows`, or an explicit confirmation token. Receipts
carry a cost vector (`statements_run`, `partitions_fetched`, `bytes_scanned`,
`warehouse_credits_estimate`).

## Write-Intent Ladder

Write support has landed as `query write` (see `docs/write_intent_ladder.md` for
what each rung does today). By design it is the only code path that may request
a capability row wider than read-only (capability rows are not wired yet), and
it proceeds in fixed rungs:

1. `write plan --dry-run --json`
2. typed safety classification
3. explicit allowlist of statements
4. idempotency request ID
5. exact confirmation token
6. execution receipt
7. append-only audit

First supported writes are narrow (`INSERT` into configured staging tables,
`MERGE` with an explicit key manifest, `COPY INTO <table>` from configured
stages). DDL stays disabled until there is a clear, public, documented use case.
The append-only query audit log is enforced by a build-failing test that forbids
any `UPDATE`/`DELETE` against it.

## Private Connectivity

Private connectivity is not special-cased into the protocol client. AWS
PrivateLink, Azure Private Link, and GCP Private Service Connect all reduce to
"this account host resolves/routes privately from this environment" — a
host/profile setting plus connectivity doctor checks, with an optional host
allowlist.

## Public-Repository Hygiene

This is public open-source infrastructure. No private downstream product names,
non-public use cases, or deployment-specific business context appear in any repo
file, fixture, doc, or Beads comment.

## Stable Error Codes And Exact Next Commands

Every diagnostic carries a stable `error.code` and a default recovery path, so an
agent always has an exact next command. These are owned by
`franken-snowflake-core::error`:

- **`SnowflakeErrorCode`** is the closed set of stable `FSNOW-<range><n>` codes:
  `1xxx` usage, `2xxx` credential/profile, `3xxx` safety refusal, `4xxx` upstream
  Snowflake, `5xxx` network/retry, `6xxx` async, `7xxx` local cache/metadata,
  `9xxx` internal. It serializes on the wire as its stable string (e.g.
  `FSNOW-2001`) and round-trips via `SnowflakeErrorCode::from_stable_code`.
- **The central registry** (`SnowflakeErrorCode::entry` → `ErrorEntry`) maps each
  code to its `ExitCode`, `retryable` / `policy_boundary` flags, a one-line
  summary, and default `safe_next_commands` / `repair_commands`.
- **`SnowflakeError::new(code, message)`** auto-populates those recovery commands
  from the registry, so **every error code ships a default recovery path** even
  when the caller passes none. A registry-completeness unit test asserts that no
  code is missing a `safe_next_commands` / `repair_commands` entry, and that
  stable codes are unique and `FSNOW-`prefixed.

For example, a missing profile is `FSNOW-2001` (`ProfileNotFound`, exit code 3,
non-retryable, not a policy boundary) whose default `safe_next_commands` is
`franken-snowflake profile validate <profile> --json`. The message itself is
passed through the redactor before it reaches any output channel, so an error
that quotes user input can never leak a secret. See `docs/agent_cli_contract.md`
for the full envelope and exit-code dictionary.

## Core Implementation Map

The security properties above are implemented (and unit-tested) in
`franken-snowflake-core`:

| Security property | `franken-snowflake-core` symbol |
|---|---|
| Single shared secret needle list | `redact::SECRET_PREFIXES` |
| Composable redactor / detector | `redact::redact`, `redact::contains_secret`, `redact::REDACTION_PLACEHOLDER` |
| Credential-shaped field detection | `redact::CREDENTIAL_FIELD_SUFFIXES`, `redact::is_credential_field` |
| Stable error codes + ranges | `error::SnowflakeErrorCode` (`FSNOW-*`) |
| Default recovery paths | `error::SnowflakeError`, `error::ErrorEntry` |
| Exit-code dictionary | `exit::ExitCode` |
| Outcome / provenance contract | `outcome::OutcomeKind`, `outcome::DataSource` |

The compile-time credential `Debug`-leak gate (bead
`fsnow-native-snowflake-connector-w0i.5`) keys off `redact::CREDENTIAL_FIELD_SUFFIXES`
(`*_api_key`, `*_password`, `*_private_key`, `*_token`, `*_secret`,
`*_passphrase`, ...): it fails the build if a `#[derive(Debug)]` struct has a
field whose name ends with one of those suffixes without a hand-rolled redacting
`Debug`. This is the type-level half of "no secret values in `Debug`"; the shared
needle list above is the value-level half.
