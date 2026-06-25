# Dataset Manifest Contract

Date: 2026-06-25

The dataset-manifest model is the headline catalog feature. It lets an agent ask
for rows by entity, time range, and safe filters against a named dataset without
memorizing database names, column conventions, or SQL syntax. This document pins
the design contract for the future `franken-snowflake-catalog` crate while the
implementation beads remain blocked deeper in the DAG.

The implementation target is a no-account-testable discovery pipeline that emits
deterministic, versioned metadata artifacts from `INFORMATION_SCHEMA` fixtures
first, then from live Snowflake profiles when the transport and cache beads
unblock.

## Discovery Flow

Catalog discovery is a read-only pipeline. It never mutates Snowflake state and
never serializes secrets.

1. Resolve a profile and scope.
   The caller supplies a profile plus optional database/schema/object filters.
   Profile values are redacted according to `docs/security_model.md`; secrets are
   referenced only by handle or environment-variable name and are never copied
   into catalog output.

2. Collect raw catalog rows.
   The first implementation queries `INFORMATION_SCHEMA` for databases, schemas,
   tables, views, columns, stages, and file formats where available. It also
   captures table/view comments and tags when the authenticated role can see
   them. `ACCOUNT_USAGE` is a later enhancement because its availability depends
   on account-level privileges and latency.

3. Normalize object identity.
   Every discovered object is assigned a stable, fully-qualified identity:
   `profile.database.schema.object` for datasets and
   `profile.database.schema.object.column` for columns. Snowflake identifiers are
   preserved exactly for SQL compilation and also stored in a normalized
   comparison form for `did_you_mean`.

4. Infer candidate roles without granting authority.
   Column names and types can suggest `entity_key`, `time_index`, `known_at`,
   `feature`, `label`, or `metadata`, but inference is advisory. A generated
   manifest records the confidence and evidence for inferred roles. Downstream
   adapters or user-supplied overlays may confirm or override them.

5. Emit three separate artifacts.
   Discovery produces a dataset manifest, a column catalog, and an operator
   catalog. These are independently queryable so a CLI/MCP caller can inspect an
   object, ask what columns exist, or fetch operator schemas without parsing a
   large manifest blob.

6. Stamp provenance and receipt metadata.
   Every artifact carries a source fingerprint, discovery scope, timestamp,
   data-source class, command/trace identifiers, and redaction summary. Live,
   fixture, and offline-cache outputs are distinguishable at the envelope level
   and inside the artifact provenance block.

The discovery flow is pushdown-first. Column profiling, cardinality estimates,
null-rate checks, and sample previews are separate explicit operations that must
compile to bounded SQL, not local scans of large result sets.

## Artifact Model

Catalog discovery emits a `CatalogSnapshot` envelope containing three logical
collections:

| Artifact | Purpose |
|---|---|
| Dataset manifest | User-facing dataset identity, object location, rights class, row-limit policy, and per-field roles. |
| Column catalog | Snowflake logical type, precision, scale, length, nullability, aliases, tags, and comments for each column. |
| Operator catalog | Predicate operators, input arity, accepted dtype classes, output rule, refusal codes, and JSON Schema projection. |

Keeping operator legality separate from filters is intentional. Filters are a
dumb predicate AST over column names; a validation pass consults the column and
operator catalogs and emits typed refusals.

## Dataset Manifest Schema

The persisted hand-editable form is TOML. The CLI/MCP wire form is the same
logical model in deterministic JSON.

```toml
schema_version = "franken_snowflake.dataset_manifest.v1"

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
description = "Daily event facts."

[datasets.provenance]
source = "information_schema"
data_source = "fixture"
snapshot_id = "catalog-snapshot-fixture-events-v1"
discovered_at = "2026-06-25T00:00:00Z"
profile_fingerprint = "profile:demo-prod:redacted"
object_fingerprint = "snowflake-object:ANALYTICS.PUBLIC.EVENTS_DAILY"
command_id = "catalog.scan"
trace_id = "trace-fixture"
redactions_applied = ["profile.account"]

[[datasets.fields]]
column = "EVENT_DATE"
role = "time_index"
dtype = "date"
required = true
role_confidence = "confirmed"

[[datasets.fields]]
column = "ENTITY_ID"
role = "entity_key"
dtype = "string"
required = true
role_confidence = "confirmed"

[[datasets.fields]]
column = "VALUE"
role = "feature"
dtype = "number"
required = false
role_confidence = "inferred"
```

### Dataset Fields

| Field | Required | Meaning |
|---|---:|---|
| `schema_version` | yes | Manifest contract version. |
| `id` | yes | Stable dataset identifier used by `query run --dataset`. |
| `profile` | yes | Non-secret profile identifier. |
| `database` / `schema` / `object` | yes | Exact Snowflake object identifiers. |
| `kind` | yes | `table`, `view`, `materialized_view`, or `external_table`. Unknown values are refused until modeled. |
| `rights_class` | yes | Fail-closed rights label. Unknown labels parse to the most restrictive class. |
| `default_limit` | yes | Limit used when the caller does not request one. |
| `max_rows_without_export` | yes | Result-size ceiling before `--export`, `--max-rows`, or confirmation is required. |
| `description` | no | Human-readable summary from comments, tags, or overlays. |
| `provenance` | yes | Secret-free discovery evidence. |
| `fields` | yes | Per-column role assignments used by planner validation. |

### Field Roles

Field roles are drawn from a fixed enum:

| Role | Meaning |
|---|---|
| `entity_key` | The entity an agent filters by (`--entity`). |
| `time_index` | The primary time axis for range filters (`--from` / `--to`). |
| `known_at` | Point-in-time / as-of axis; enables Time Travel `AT(TIMESTAMP => ...)`. |
| `feature` | A value or feature column. |
| `label` | A target or label column. |
| `metadata` | Non-analytic metadata. |

`role_confidence` is one of `confirmed`, `inferred`, or `overlay`. Inference
never bypasses rights, cost, or dtype validation.

## Column Catalog Schema

The column catalog is keyed by fully-qualified column identity and aliases.

```toml
[[columns]]
dataset_id = "events_daily"
database = "ANALYTICS"
schema = "PUBLIC"
object = "EVENTS_DAILY"
column = "EVENT_DATE"
ordinal = 1
snowflake_type = "DATE"
dtype_class = "date"
nullable = false
precision = 0
scale = 0
length = 0
aliases = ["event_date", "date", "dt"]
comment = "Event date."
tags = []

[columns.provenance]
source = "information_schema.columns"
snapshot_id = "catalog-snapshot-fixture-events-v1"
```

`dtype_class` is the planner-facing class: `string`, `number`, `boolean`,
`date`, `time`, `timestamp`, `binary`, `variant`, or `unknown`. Unknown types are
allowed in the catalog but rejected by operators that do not explicitly support
them.

Aliases power `did_you_mean` for column selection and filters. Aliases are never
used for SQL generation; the planner always compiles exact identifiers from the
manifest and column catalog.

## Operator Catalog Schema

The operator catalog is static for built-in operators and extendable by adapters
that can prove equivalent validation.

```toml
[[operators]]
id = "between"
arity = 2
accepted_dtype_classes = ["number", "date", "time", "timestamp"]
output_dtype_rule = "boolean"
refusal_code = "FSNOW_FILTER_OPERATOR_DTYPE"
json_schema_contract_id = "franken_snowflake.operator.between.v1"
```

Required MVP operators:

| Operator | Arity | Dtype classes | Notes |
|---|---:|---|---|
| `eq` | 1 | all known scalar classes | Equality with one positional binding. |
| `neq` | 1 | all known scalar classes | Inequality with one positional binding. |
| `lt` / `lte` / `gt` / `gte` | 1 | number, date, time, timestamp | Ordered comparison only. |
| `between` | 2 | number, date, time, timestamp | Inclusive range. |
| `in` | n | all known scalar classes | Bounded list; empty list is a typed refusal. |
| `is_null` / `is_not_null` | 0 | all columns | No value binding. |
| `contains` | 1 | string | Compiles to a bounded string predicate, not regex. |

`dataset describe-operator <operator> --jsonschema` projects the operator entry
to JSON Schema 2020-12 so an agent can construct valid predicates before calling
`query plan`.

## Predicate AST

Filters are structural and value-bearing, but not SQL-bearing.

```json
{
  "and": [
    { "column": "ENTITY_ID", "op": "eq", "value": "ENTITY123" },
    { "column": "EVENT_DATE", "op": "between", "value": ["2024-01-01", "2024-12-31"] },
    { "column": "VALUE", "op": "gt", "value": "0" }
  ]
}
```

Validation resolves each column against the column catalog, resolves each
operator against the operator catalog, checks arity and dtype class, and emits
typed refusal codes before the planner can compile SQL.

## Provenance Contract

Every manifest, column, operator, and snapshot carries secret-free provenance.

| Field | Meaning |
|---|---|
| `source` | `information_schema`, `adapter_overlay`, `fixture`, `offline_cache`, or later `account_usage`. |
| `data_source` | Envelope-compatible `live`, `fixture`, or `empty`. |
| `snapshot_id` | Stable ID for the discovery run or fixture bundle. |
| `discovered_at` | Timestamp from the deterministic clock in tests or wall clock in live mode. |
| `profile_fingerprint` | Secret-free profile fingerprint; no host/account unless redaction policy allows it. |
| `object_fingerprint` | Stable object identity hash or redacted fully-qualified name. |
| `command_id` / `trace_id` | CLI/MCP traceability fields. |
| `redactions_applied` | Redaction markers applied while producing the artifact. |

Fixture and offline-cache snapshots must never masquerade as live data.
`--require-live` refuses them. Live snapshots that omit inaccessible metadata
must record warnings rather than silently fabricating fields.

## Query Planner Interface

Dataset mode and raw SQL mode share one planner. Dataset mode supplies a manifest
and predicate AST; raw SQL mode supplies a pre-authored `SELECT`. Both modes
produce:

- normalized SQL text with correctly quoted identifiers;
- Snowflake positional typed bindings (`{"1": {"type": "...", "value": "..."}}`);
- server-side guardrails (`STATEMENT_TIMEOUT_IN_SECONDS`, result row cap,
  `QUERY_TAG`);
- a deterministic plan ID over normalized plan fields, profile fingerprint, and
  time window;
- refusal or warning metadata for unconstrained or large-result plans.

The planner must never interpolate values into SQL strings. It may only embed
identifiers that were validated against the manifest/catalog or were accepted by
the raw-SQL safety checker.

Implementation details for pushdown planning and lineage graph output are in
`docs/catalog_graph_design.md`.
