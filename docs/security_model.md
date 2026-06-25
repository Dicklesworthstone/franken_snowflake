# Security Model

Date: 2026-06-24

The normative security contract for `franken_snowflake`. It distills the
"Security Model" and "Safety And Security" sections of
`COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md` and `AGENTS.md`. Three properties
are load-bearing and self-reinforcing: the connector **cannot leak secrets**,
**cannot run away with cost**, and is **read-only by default**.

## Security Defaults

- **Read-only by default**, enforced at the type level via narrowed Asupersync
  capability rows. The pure planning / validation / SQL-compile path runs under
  `cx_readonly()` (`Cx<cap::None>` — zero capabilities, no IO); the transport
  layer runs under a narrowed `Cx` that grants `IO` (and `TIME`/`SPAWN`) but
  **never** `REMOTE`. Only the write-intent ladder widens authority further. See
  `docs/asupersync_leverage.md`.
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

1. **Compile-time credential `Debug`-leak gate.** A build-time check scans crate
   sources and fails the build if any `#[derive(Debug)]` struct has a
   credential-shaped field (`*_api_key`, `*_password`, `*_private_key`,
   `*_token`, ...) without a hand-rolled redacting `Debug`. Owned by bead
   `fsnow-native-snowflake-connector-w0i.5`.
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

## Auth Lanes

Implemented in this order; a later lane never blocks an earlier one:

1. **Programmatic access token (PAT)** — bearer header with
   `X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN`. Default
   15-day expiry (policy-capped, max 365).
2. **Key-pair JWT** — RS256 over the pure-Rust `jsonwebtoken`
   (`rust_crypto` + `use_pem`) path; `X-Snowflake-Authorization-Token-Type:
   KEYPAIR_JWT`. Claims: `iss = "<ACCOUNT>.<USER>.SHA256:<fp>"`,
   `sub = "<ACCOUNT>.<USER>"` (no fingerprint), uppercase ACCOUNT/USER, org-form
   `.`→`-`. Effective `exp` is capped at ≤ 3600s and re-signed mid-`bracket` for
   long polls (Snowflake caps JWT validity at 1 hour). See "Auth Crypto Path" in
   the plan.
3. **OAuth bearer** pass-through (short-lived ~10 min; refreshed during long polls).
4. **Workload identity federation** — only after the first three are stable.

`profile validate --json` checks shape and env-var presence without contacting
Snowflake unless `--online` is passed. `profile doctor` surfaces
credential-lifetime warnings ("your token expires in N days/minutes") where
derivable without leaking the secret, instead of a surprise 401 mid-poll.

## Fail-Closed Rights

- An unknown rights label parses to the **most restrictive** class.
- An expired entitlement is treated as **missing**, not as default-allow.
- Rights and sensitivity metadata travel with dataset manifests
  (`docs/dataset_manifest_contract.md`).

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

Write/update support is deferred until read/query/catalog is strong. When added,
it is the **only** code path permitted a capability row wider than read-only, and
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
