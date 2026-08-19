# Comprehensive Background Research for Creating the fsnow Claude Code Skill

> Project: `/data/projects/franken_snowflake`
> Skill name: `fsnow`
> Research date: 2026-06-29

## Project Overview

`franken_snowflake` is a clean-room Rust-first Snowflake SQL API connector and
agent-facing CLI/MCP surface. The short CLI binary is `fsnow`; the longer binary
is `franken-snowflake`.

The project exists to give agents and Rust services a deterministic, safe,
secret-redacting way to authenticate to Snowflake, submit SQL API statements,
poll/cancel handles, stream partitions, discover catalog metadata, emit receipts,
and integrate Snowflake as a private data-lake source.

## Core Design Philosophy

1. Use Asupersync as the runtime and transport foundation.
2. Keep production feature graphs free of Tokio, reqwest, hyper, axum, tower,
   sqlx, diesel, sea-orm, and third-party Snowflake Rust drivers.
3. Make every agent-facing surface structured: JSON/toon envelopes, stable
   command IDs, stable error codes, and copy-paste repair commands.
4. Make no-account deterministic testing first-class before live proof.
5. Keep secrets out of files, logs, Beads, support bundles, fixtures, and skill
   notes.
6. Keep downstream Rust integration on a public adapter boundary rather than
   exposing SQL API internals as the default user-facing API.

## Architecture

```text
fsnow / franken-snowflake CLI
  -> command parser and deterministic renderer
  -> shared command contract runner
  -> core envelopes, errors, IDs, receipts, rights, redaction
  -> optional live auth/sqlapi/http path
  -> catalog/graph/frame/export/cache/text-indexing surfaces
  -> optional MCP adapter using the same command runner
  -> no-account testkit and mock protocol harness
```

Workspace crates inspected:

- `franken-snowflake-core`
- `franken-snowflake-auth`
- `franken-snowflake-sqlapi`
- `franken-snowflake-http`
- `franken-snowflake-catalog`
- `franken-snowflake-frame`
- `franken-snowflake-graph`
- `franken-snowflake-cache`
- `franken-snowflake-export`
- `franken-snowflake-text-indexing`
- `franken-snowflake-testkit`
- `franken-snowflake-cli`
- `franken-snowflake-mcp`
- `franken-snowflake-tui`

## CLI Commands Reference

Discovery:

```bash
fsnow onboard --json
fsnow capabilities --json
fsnow robot-docs guide
fsnow agent-handbook --json
fsnow doctor --json
```

Profiles:

```bash
fsnow profile validate <profile> --json
fsnow profile doctor <profile> --online --json
```

Catalog and dataset:

```bash
fsnow catalog scan <profile> --database <db> --schema <schema> --json
fsnow catalog graph <profile> --database <db> --schema <schema> --mermaid
fsnow dataset describe-operator <operator> --jsonschema
```

Queries:

```bash
fsnow query plan --profile <profile> --sql "select 1" --json
fsnow query run --profile <profile> --sql "select current_version()" --json
fsnow query cancel <statement-handle> --json
fsnow query write --profile <profile> --sql "insert into T values (1)" --dry-run --json
```

MCP:

```bash
fsnow mcp serve --stdio
fsnow mcp serve --http 127.0.0.1:8787
```

## Configuration System

Profiles use the prefix `FRANKEN_SNOWFLAKE_<PROFILE>`, where profile names are
uppercased and dots, dashes, and underscores become underscores.

Important profile handles:

- `<PREFIX>_ACCOUNT`
- `<PREFIX>_USER`
- `<PREFIX>_AUTH`
- `<PREFIX>_WAREHOUSE`
- `<PREFIX>_DATABASE`
- `<PREFIX>_SCHEMA`
- `<PREFIX>_ROLE`
- `<PREFIX>_PAT`
- `<PREFIX>_OAUTH_BEARER`
- `<PREFIX>_PRIVATE_KEY_PEM`
- `<PREFIX>_PRIVATE_KEY_PASSPHRASE`
- `<PREFIX>_WRITE_ENABLED`
- `<PREFIX>_WRITE_REQUIRE_CONFIRM`
- `<PREFIX>_WRITE_ALLOW_DDL`

## Real-World Usage Patterns

Pattern: discover before acting.

```bash
fsnow onboard --json
fsnow capabilities --json
fsnow doctor --json
```

Pattern: prove live path honestly.

```bash
cargo build -p franken-snowflake-cli --features live
fsnow profile validate demo-prod --json
fsnow query run --profile demo-prod --sql "select current_version()" --json
```

The proof is incomplete unless the envelope shows live provenance when live
provenance is required.

Pattern: downstream Rust adapter.

```rust
use franken_snowflake_core::adapter::SnowflakeDataLakeAdapter;
use franken_snowflake_core::prelude::*;
```

Downstream integrations should return `Envelope<T>` and preserve the shared
error/outcome/provenance model.

## Troubleshooting

If a command is unavailable, check `capabilities.feature_flags` and rebuild with
the required feature. If a live command succeeds with fixture provenance, it is
not live proof. If a write returns `FSNOW-3007`, the profile write gate is
disabled. If a DDL command returns `FSNOW-3009`, DDL is intentionally disabled.

## Integration With Other Tools

Use Beads as the project source of truth in `/data/projects/franken_snowflake`.
Use `bv --robot-*` only; bare `bv` opens a TUI. Use CASS for historical context
when the index is healthy, but proceed from repo evidence if it reports
index-busy.

## Key Insights For Skill Creation

1. The skill must trigger on both CLI operation and Rust library integration.
2. The entrypoint must stay compact; exhaustive details belong in references.
3. The first action should be contract discovery, not source spelunking.
4. Live proof must be provenance-aware.
5. Write execution must be policy-aware.
6. Adapter integration must be the recommended default for downstream Rust.
7. Testing instructions must separate no-account proof from live proof.

## Anti-Patterns To Avoid

- Trusting README examples over `capabilities --json` when they disagree.
- Treating fixture output as live proof.
- Logging secrets while debugging profiles.
- Adding forbidden async/web/ORM crates to production graphs.
- Bypassing write gates with lower-level APIs.
- Building an MCP path that does not share CLI handlers.
- Closing repo work without Beads synchronization when Beads changed.

## Skill Artifacts Created

- `.claude/skills/fsnow/SKILL.md`
- `.claude/skills/fsnow/SELF-TEST.md`
- `.claude/skills/fsnow/references/ARCHITECTURE.md`
- `.claude/skills/fsnow/references/COMMANDS.md`
- `.claude/skills/fsnow/references/CONFIGURATION.md`
- `.claude/skills/fsnow/references/LIBRARY-INTEGRATION.md`
- `.claude/skills/fsnow/references/SAFETY.md`
- `.claude/skills/fsnow/references/TESTING.md`
- `.claude/skills/fsnow/references/REPO-WORKFLOW.md`
- `.claude/skills/fsnow/references/TROUBLESHOOTING.md`
- `.claude/skills/fsnow/references/OPERATORS.md`
- `.claude/skills/fsnow/references/RESEARCH.md`
- `.claude/skills/fsnow/scripts/validate.py`

