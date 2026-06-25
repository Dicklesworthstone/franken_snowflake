# Dataset Manifest Contract

Date: 2026-06-24

The dataset-manifest model is the headline feature: it lets an agent ask for rows
by entity and date range against a named dataset without memorizing raw database
names, column conventions, or SQL syntax. This document pins the three-part model
distilled from the "Dataset Manifest Model" and "Query Planning" sections of
`COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md`.

## Three-Part Model

Catalog discovery (`docs/protocol/` + the `catalog` crate, driven by
`INFORMATION_SCHEMA`) produces three separable artifacts. Keeping them separate
is more robust and more agent-discoverable than embedding operator legality
inline on each filter.

1. **Dataset manifest** — describes the object, its rights class, default and max
   row limits, and a per-field role assignment.
2. **Column catalog** — maps each column to its Snowflake logical type, scale,
   nullability, and aliases (the aliases power `did_you_mean`).
3. **Operator catalog** — maps each operator to its input arity, output-dtype
   rule, and refusal codes.

### Dataset manifest (TOML)

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

### Field roles

Field roles are drawn from a fixed enum:

| Role | Meaning |
|---|---|
| `entity_key` | The entity an agent filters by (`--entity`). |
| `time_index` | The primary time axis for range filters (`--from`/`--to`). |
| `known_at` | Point-in-time / as-of axis; enables Time Travel `AT(TIMESTAMP => ...)`. |
| `feature` | A value/feature column. |
| `label` | A target/label column. |
| `metadata` | Non-analytic metadata. |

`rights_class` is fail-closed: an unknown label parses to the most restrictive
class (see `docs/security_model.md`).

## Filters Are A Dumb Predicate AST

A filter is a predicate AST over column names. Operator-vs-dtype legality is
**not** stored on the filter; it is checked by a separate validation pass that
consults the operator catalog and emits typed refusals. Because the operator
catalog is a first-class model, `dataset describe-operator <operator>
--jsonschema` hands the agent a JSON Schema 2020-12 document for the operator's
parameters, so the agent constructs a valid filter without trial and error.

## Query Modes

Two modes share **one planner**:

1. **Raw SQL mode** for expert users — still supports `--dry-run` / `query plan`,
   typed positional bindings, and explicit safety checks. The MVP refuses
   non-`SELECT` and multiple statements unless explicitly allowed.
2. **Dataset mode** for agents:

```bash
franken-snowflake query run \
  --profile demo-prod \
  --dataset events_daily \
  --entity ENTITY123 \
  --from 2024-01-01 --to 2024-12-31 \
  --as-of 2024-12-31T23:59:59Z \
  --select EVENT_DATE,ENTITY_ID,VALUE \
  --json
```

The planner:

- quotes identifiers correctly and uses **positional typed bindings**, never
  string interpolation, for values;
- pushes down projection and predicates (pushdown-first; never pull a large table
  to aggregate locally);
- compiles `--as-of` to a Time Travel `AT(TIMESTAMP => ...)` clause when the
  dataset declares a `known_at` / `time_index` axis;
- requires a limit or export mode for large result sets;
- sets the enforceable server-side guardrail (`STATEMENT_TIMEOUT_IN_SECONDS` plus
  a result row cap) on every query — the client `Budget` cost quota is advisory
  telemetry on top (see `docs/security_model.md`);
- generates a deterministic plan identifier (a normalized-plan hash over plan +
  profile + time window), distinct from Snowflake's assigned `query_id`;
- sets `QUERY_TAG` to the envelope `command_id` / `trace_id` for end-to-end
  traceability into Snowflake's query history.

## Receipts And Re-Fetch

Every query ends with a content-addressed (BLAKE3) receipt that records the
redacted request fingerprint, normalized SQL hash, secret-free profile hash,
Snowflake statement handle and `query_id`, partition metadata hashes, row counts,
byte sizes, the cost vector, and final `OutcomeKind`. The stored `query_id`
(keyed by the normalized-plan hash) enables cheap `RESULT_SCAN('<query_id>')`
re-fetch within Snowflake's ~24h result-cache retention. Receipts never contain
secret values.
