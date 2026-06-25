# Deferred Write-Intent Mutation Ladder

`franken_snowflake` is read-only by default. Query, catalog, doctor, MCP, and
receipt paths must not execute DDL, DML, stage file mutation, stored procedures,
or session-state mutation. The deferred write-intent ladder below is the only
designated path that may ever request a capability row wider than read-only.

This document is a design contract, not an executor specification. The current
implementation provides core types, typed refusals, and non-executing dry-run
plans only. No Snowflake mutation transport is implemented by this bead.

## Non-Goals

- No actual mutation execution.
- No live mutation tests.
- No DDL support.
- No hidden fallback from read commands into write commands.
- No audit record updates or deletes.
- No raw secrets in plans, receipts, diagnostics, logs, or tests.

## Capability Boundary

The type-level capability rows stay ordered as:

1. `PlannerCaps`: pure planning, zero IO.
2. `TransportCaps`: read-side network transport, no `REMOTE`.
3. `WriteCaps`: reserved for the future write-intent ladder.

Only the ladder may ever request `WriteCaps`. Read commands, read-side MCP
tools, catalog scans, and result partition fetchers remain under narrower
capability rows. A future executor must compile through the ladder types before
it can receive wider authority.

## Ladder Rungs

Every future DDL/DML path must pass the rungs in this order:

1. **Read-only default**: mutation is refused unless a profile explicitly enables
   the write-intent policy.
2. **Dry-run plan**: the user must request `--dry-run`; planning emits data only
   and sets `execution_enabled=false`.
3. **Typed safety classification**: SQL is classified as DML, DDL, external-file
   mutation, procedure execution, session-state mutation, or unknown. DDL is
   refused.
4. **Statement allowlist**: the request must name a stable allowlist entry whose
   statement kind matches the classified SQL.
5. **Idempotency binding**: the request must carry an explicit request id used
   as the SQL API idempotency key and receipt key.
6. **Exact confirmation**: future execution preflight must echo the exact token
   emitted by the dry-run plan.
7. **Execution receipt**: future execution must produce a deterministic receipt
   before reporting success. Today this rung always refuses with
   `execution_unavailable`.
8. **Append-only audit**: future execution must append an audit record. The audit
   store must reject update/delete mutation by construction and by tests.

## CLI Shape

The future CLI entry point should be explicit and separate from read commands:

```text
franken-snowflake write plan --profile <profile> --sql <sql> --dry-run --json
franken-snowflake write plan --profile <profile> --sql <sql> --dry-run --toon
```

Dry-run output should include the classified statement kind, allowlist id,
request id, idempotency receipt, required confirmation token, append-only audit
requirement, and `execution_enabled=false`.

A future execution preflight may accept a confirmation token, but execution is
still out of scope until a separate bead lands transport, receipts, audit, and
no-account tests:

```text
franken-snowflake write execute --profile <profile> \
  --request-id <id> \
  --confirm <exact-token> \
  --audit-stream <append-only-stream> \
  --json
```

Read commands must keep refusing mutation. They must not accept `--confirm` as a
shortcut and must not call write-intent evaluators except to produce a typed
safety refusal.

## Core Types

`franken-snowflake-core::write_intent` owns the public contract:

- `WriteIntentPolicy`: disabled by default; requires dry-run, idempotency,
  exact confirmation, append-only audit, and an explicit allowlist.
- `WriteIntentRequest`: caller facts, including redacted SQL preview, dry-run
  flag, allowlist id, request id, confirmation token, and audit intent.
- `WriteStatementKind` and `WriteSafetyClass`: typed safety classification.
- `StatementAllowlistEntry`: stable allowlist row.
- `ConfirmationToken`: exact token emitted by a dry-run plan.
- `WriteIntentReceipt`: dry-run idempotency receipt, with
  `execution_enabled=false`.
- `WriteIntentPlan`: non-executing dry-run plan plus remaining required rungs.
- `WriteIntentDecision` / `WriteIntentRefusalCode`: structured accept/refuse
  output for CLI, MCP, logs, and tests.

All SQL previews in these types are passed through the core redactor before they
can be echoed.

## Initial Statement Policy

The first allowable write families, once a future executor exists, are narrow:

- `INSERT` into configured staging tables.
- `MERGE` with an explicit key manifest.
- `COPY INTO <table>` from configured stages.

The current core policy does not enable these by default. A profile must provide
specific `StatementAllowlistEntry` rows, and `WriteIntentPolicy::default()` keeps
`enabled=false`.

DDL remains refused even under an enabled dry-run policy. Procedure execution,
stage file mutation, and session-state mutation require separate design beads
before they can be allowlisted.

## Receipts And Audit

Dry-run receipts bind:

- schema version
- request id
- statement kind
- dry-run status
- `execution_enabled=false`

Future execution receipts must add upstream statement handle/query id, final
outcome, redaction markers, cost vector, and audit record address. They must be
deterministic enough for golden tests.

The audit stream is append-only. A future implementation must include a
build-failing or test-failing guard that rejects any `UPDATE` or `DELETE` against
the audit store.

## Test Requirements

No-account tests must cover:

- default policy refuses all mutation planning
- missing `--dry-run` refuses
- DDL refuses even when the policy is enabled
- non-allowlisted statements refuse
- dry-run plans produce idempotency receipts and exact confirmation tokens
- future execution preflight refuses missing or mismatched confirmation tokens
- future execution preflight refuses missing append-only audit intent
- all execution attempts refuse until a dedicated executor bead lands
- echoed SQL previews are redacted
