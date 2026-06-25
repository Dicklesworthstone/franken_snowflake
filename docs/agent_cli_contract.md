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
- Long-running commands emit typed NDJSON progress events on **stderr** (sourced
  from Asupersync's native `cli::progress::ProgressEvent`) while the final
  envelope goes to stdout.

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
| `data_source` | `live \| fixture \| empty`; omitted when `unspecified`. |
| `profile_id` | Profile used (never a secret). |
| `request_id` | Client-generated UUID; doubles as the SQL API idempotency `requestId`. |
| `query_id` | Snowflake `query_id`, when applicable. |
| `statement_handle` | SQL API statement handle, when applicable. |
| `receipt_hash` | BLAKE3 content address of the query receipt. |
| `started_at` / `finished_at` / `duration_ms` | Timing. |
| `warnings` | Non-fatal findings. |
| `safe_next_commands` | Suggested follow-ups. |
| `budget_consumed` | Deadline / poll-quota / cost-quota usage. |
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
each read verb as an MCP `#[tool]` whose JSON schema is generated from the
handler signature. Each call is wrapped in an Asupersync `web::request_region`
so an agent disconnect drains the statement `bracket` plus partition `Scope` as
one owned region; `ctx.checkpoint()` provides cooperative cancel points inside
it. Sequencing: `run_stdio()` + read-only tools first, `run_http()` second,
write tools deferred behind the same write-intent ladder as the CLI.

## Mutation Posture

Mutating operations are disabled by default. Any future DDL/DML/write path
requires `--dry-run`, explicit `--confirm`, an idempotency request ID, an exact
confirmation token, an execution receipt, and an append-only audit record — the
write-intent ladder in `docs/security_model.md`. It is the only path permitted to
request a capability row wider than read-only.
