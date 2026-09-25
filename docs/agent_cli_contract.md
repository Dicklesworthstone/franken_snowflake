# Agent CLI And MCP Contract

Date: 2026-06-24

This document is the normative contract for the `franken-snowflake` CLI and the
feature-gated `mcp serve` surface. It distills and pins the "Agent CLI And MCP
Contract" section of `COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md`; where they
differ, the plan governs design intent and this document governs the wire shape.

The CLI and MCP surfaces are **one product contract**, not two. The MCP crate is
a thin adapter over the same command handlers, so every verb produces the same
envelope, error code, receipt, and safety class through both surfaces. A
CLI/MCP parity test enforces this.

## Output Discipline

- **Stdout is data. Stderr is diagnostics.** No diagnostic text, progress, or
  ANSI escapes ever contaminate a JSON payload on stdout.
- Every read command accepts `--json` (the default) or `--toon` (a
  token-efficient encoding that round-trips to the same data). `catalog graph`
  additionally accepts `--mermaid` / `--svg`.
- JSON output is **deterministic and versioned**: keys are emitted in a stable
  order, and `schema_version` / `output_contract_id` identify the shape.
- Non-TTY mode shows no interactive prompt. `NO_COLOR`, `CI`, and a non-TTY
  stdout each independently disable ANSI. TTY detection uses `IsTerminal`.
- Progress events are not emitted yet: a long-running command is silent until
  its envelope reaches stdout. When they land they will be typed NDJSON on
  **stderr** (Asupersync's `cli::progress::ProgressEvent`), never on stdout.

## Command Families

```bash
franken-snowflake capabilities --json
franken-snowflake robot-docs guide
franken-snowflake agent-handbook --json
franken-snowflake doctor --json
franken-snowflake selftest --json
franken-snowflake profile validate <profile> --json
franken-snowflake profile doctor <profile> --json          # --online attempts a minimal live check
franken-snowflake catalog scan <profile> --database <db> --schema <schema> --json
franken-snowflake catalog graph <profile> --mermaid
franken-snowflake catalog diff <profile> [--database <db>] [--schema <schema>] [--base <id>] [--target <id>] --json
franken-snowflake dataset inspect <dataset-id> --json
franken-snowflake dataset profile <dataset-id> --json       # column stats via SQL pushdown (APPROX_*)
franken-snowflake dataset describe-operator <operator> --jsonschema
franken-snowflake query plan --profile <profile> --sql <sql> --json
franken-snowflake query run --profile <profile> --sql <sql> --json
franken-snowflake query cancel <statement-handle> --json
franken-snowflake receipt show <receipt-hash> --json
franken-snowflake export ...                                # COPY INTO (primary) + local CSV/JSONL
franken-snowflake tui --profile <profile>                   # opt-in, default-off behind the `tui` feature
franken-snowflake mcp serve [--stdio | --http <addr>]       # feature-gated `mcp`
```

`selftest` runs the no-account testkit fixtures so an agent can verify the
binary's protocol behavior offline, before any credential exists.

### Self-description

- `agent-handbook --json` returns the whole contract in one binary-embedded
  call: the envelope-key spec, the exit-code dictionary, the first ~10 commands a
  new agent should try, an error-code → next-command recovery map, and the
  explicit non-goals.
- `capabilities --json` returns a self-describing command registry. Each command
  carries `input_schema` (JSON Schema 2020-12), `output_contract_id`,
  `error_families`, examples, and boolean safety facets (`mutates_local_state`,
  `provider_network`, `read_only`, `sensitive_output`). Commands default to
  non-mutating and non-sensitive; a command must **opt into** danger.

## JSON Envelope

Every JSON envelope includes:

| Key | Meaning |
|---|---|
| `ok` | Boolean success flag. |
| `outcome_kind` | `success \| partial_success \| refusal \| cancelled \| timeout \| error`, independent of `ok` and of the exit code. |
| `command_id` | Stable command identifier. |
| `output_contract_id` | Identifies the payload shape. |
| `schema_version` | Envelope schema version. |
| `data_source` | `live` (a statement ran against Snowflake in this invocation), `cache` (served from the local store: snapshots, manifests, receipts), `fixture`, or `empty`. |
| `profile_id` | Profile used (never a secret). |
| `request_id` | Client-generated, UUID-shaped, unique per invocation (the envelope trace id). The SQL API idempotency `requestId` is a separate per-statement id reported as `data.sql_api_request_id`. |
| `query_id` | Snowflake `query_id`, when applicable. |
| `statement_handle` | SQL API statement handle, when applicable. |
| `receipt_hash` | BLAKE3 content address of the query receipt written to the local store by every live statement: a completed one (`receipt_state = completed`) and one that ended without rows (`failed`, `cancelled`, or `timed_out`, with the error code and cancel kind in the receipt). `null` for offline commands, for refusals before execution (usage, profile, SQL guard), and when the store could not be written (a warning says so). |
| `started_at` / `finished_at` / `duration_ms` | Timing. |
| `warnings` | Non-fatal findings. |
| `safe_next_commands` | Suggested follow-ups. |
| `budget_consumed` | Measured `polls` and `rows`. A live run adds the bounds it ran under: `poll_quota` and `execution_timeout_ms` (the client-side execution deadline, `--statement-timeout` + 5 s per statement; absent when the timeout is 0). |
| `redactions_applied` | Redaction markers. |

Error envelopes additionally carry a stable `error.code`, `retryable`,
`policy_boundary`, redacted evidence handles, and `repair_commands` /
`did_you_mean`. `safe_next_commands` and `repair_commands` are auto-populated
from the central error registry when the caller passes none, so **every error
code ships a default recovery path**. `did_you_mean` uses Levenshtein distance
over known command / column / dataset names.

`outcome_kind` and `data_source` mirror the `OutcomeKind` and `DataSource` enums
owned by `franken-snowflake-core`, which derive from Asupersync's four-valued
`Outcome` (see `docs/asupersync_leverage.md`). A cancelled query is
`outcome_kind = cancelled`, not an error.

A local cancellation of a live statement carries error code `FSNOW-5004`, with
the Asupersync cancel kind in `error.evidence` (for example
`cancel_kind=Deadline`). `outcome_kind` is `timeout` for `Deadline` and
`Timeout` and `cancelled` for every other kind. The exit code follows the core
cancel policy: 5 for deadline, timeout, poll-quota, shutdown and drain kinds,
2 for a cost-budget breach (a safety boundary), and 0 for a user-requested
cancel. A panic inside a statement task is `FSNOW-9001` with its redacted
payload summary. A statement that exceeds `STATEMENT_TIMEOUT_IN_SECONDS` on the
server is `FSNOW-4003` with `outcome_kind = timeout`.

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success, including empty-but-valid results (an empty result set returns `[]` / an empty typed payload — **never** a non-zero exit). |
| 1 | Completed with non-fatal findings/warnings needing attention (e.g. `doctor` found problems, `profile validate` surfaced warnings). |
| 2 | Safety refusal. |
| 3 | Credential / profile error. |
| 4 | Upstream Snowflake error. |
| 5 | Network or retry budget exhausted. |
| 6 | Query still running (async handle returned, not yet complete). |
| 7 | Local cache or metadata error. |
| 64 | Usage error. |
| 74 | I/O error. |

An empty query result is success (exit 0), not a finding. Exit 1 is reserved for
non-fatal findings on a valid run; exits ≥ 2 are refusals and errors.
`outcome_kind` carries the finer-grained class independently of the exit code.

## Errors Should Teach

A missing-profile error names what failed, which profile was requested, where
profiles are read from, the exact command to validate or create the profile, and
whether live transport was attempted. Diagnostics redact account identifiers when
requested and always redact tokens / private keys (see `docs/security_model.md`).

## MCP Surface

`franken-snowflake mcp serve` (feature `mcp`, built on `fastmcp-rust`) exposes
each read verb, plus `query_cancel` and `export_run`, as an MCP tool whose input
schema (`additionalProperties: false`; unknown arguments are refused) maps onto
the CLI flags, and each call runs the same CLI handler. `ctx.checkpoint()`
provides cooperative cancel points before and after a call. Each call's
statement polls a cancel probe tied to its MCP request (not an Asupersync
`web::request_region`): a `notifications/cancelled` naming it (stdio or HTTP),
a stdio client closing its input, or an HTTP client closing the call's
connection cancels the statement, SQL API remote cancel included. `--http` requires a bearer token, refuses foreign `Host`
and `Origin` headers, and exposes only read-only tools unless `--allow-tool`
names more; data writes stay on the CLI `query write` ladder.

## Mutation Posture

Mutating operations are disabled by default: `query write` refuses unless the
profile sets `<PREFIX>_WRITE_ENABLED=true`, and DDL additionally needs
`<PREFIX>_WRITE_ALLOW_DDL=true`. Once enabled, a data write executes directly
and returns an execution receipt; `--dry-run` previews it and returns a
confirmation token bound to (profile, SQL), and `<PREFIX>_WRITE_REQUIRE_CONFIRM=true`
makes that dry-run/confirm ceremony mandatory (see
`docs/write_intent_ladder.md`). Result rows are `typed.v1` by default: every
column in `data.columns` carries a `json_repr` that holds for all of its cells
(the mapping is in the README, "Result cells", and in
`franken_snowflake_core::typed`; the JSON Schema is
`docs/protocol/typed_rows.v1.schema.json`); `--raw-cells` returns the jsonv2 wire strings
with `data.row_encoding = "jsonv2.wire"`. `query run` accepts only single read statements,
with `MULTI_STATEMENT_COUNT=1` pinned on every submit, unless
`--allow-multiple-statements` (MCP `allow_multiple_statements`) is passed: then a
batch of two or more reads runs as one request with `MULTI_STATEMENT_COUNT` set to
the batch size, each statement's rows come back in order under
`data.statements[]` (index, statement handle, redacted SQL preview, columns, rows,
counts; the envelope's `statement_handle` is the request's), and a mutation or a
side-effecting call anywhere in the batch, bindings (Snowflake does not support
them in multi-statement requests), or an empty statement is refused before any
request. Capability rows are not
wired, so read-only is enforced by the SQL guard and the write gate, not by the
type system.
