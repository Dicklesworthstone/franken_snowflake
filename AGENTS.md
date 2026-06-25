# AGENTS.md - franken_snowflake

Guidelines for AI coding agents working in this repository.

## Project Direction

`franken_snowflake` is a clean-room, Rust-first Snowflake SQL API and data-lake
connector for agentic systems. This repository is public open-source
infrastructure and must not include private downstream product names,
deployment details, or non-public business context.

The implementation target is:

- A memory-safe Rust library stack for authenticating to Snowflake, submitting
  SQL API statements, polling and canceling statement handles, streaming result
  partitions, discovering catalog metadata, and emitting deterministic receipts.
- An agent-ergonomic CLI for humans and coding agents that need `--json`,
  capabilities, doctor, robot-docs, dry-run plans, stable handles, and precise
  errors.
- A no-account test harness that exercises protocol, pagination,
  authentication, cancellation, retry, and redaction behavior without live
  Snowflake credentials.
- Public extension points for downstream adapters that need to treat Snowflake as
  an authenticated private data-lake source.

## Core Technology Choices

Asupersync is the foundation. Keep it top of mind. Use it for structured
concurrency, cancel-correct statement lifecycles, bounded polling, retry
budgets, native HTTP/TLS work, deterministic lab tests, and capability-style
execution contexts.

Relevant FrankenSuite libraries:

- `/dp/asupersync`: primary runtime, networking, cancellation, budgets,
  deterministic tests, and protocol harness substrate.
- `/dp/frankensqlite`: local metadata, profile registry, result cache indexes,
  query receipts, and offline catalog snapshots.
- `/dp/sqlmodel_rust`: typed local metadata models and internal query builders
  where it improves ergonomics without adding a heavyweight ORM.
- `/dp/fastapi_rust`: test-only mock Snowflake SQL API server and optional local
  development control plane. It is not a production dependency for the core
  connector.
- `/dp/frankenpandas`: frame materialization and dtype handling through the
  focused `fp-columnar`/`fp-types` crates (never the umbrella crate, and never
  `fp-io` — its non-optional `orc-rust` dep pulls Tokio). Local export is CSV/JSONL
  only; large export uses Snowflake-side `COPY INTO`.
- `/dp/fastmcp_rust`: native MCP server surface (`mcp serve`); every read verb as
  an MCP tool sharing the CLI handlers and contract.
- `jsonwebtoken` (`rust_crypto`, `use_pem`): pure-Rust RS256 key-pair JWT signing,
  no OpenSSL/ring-signing/Tokio.
- `/dp/frankenmermaid` and the FrankenNetworkX `fnx-*` crates: catalog lineage
  graph model and Mermaid/SVG diagram output.
- `/dp/frankentui`: optional interactive TUI (never `charmed_rust`, which pulls
  Tokio).
- `toon`: token-efficient `--toon` output mode alongside `--json`.
- `/dp/frankensearch`: optional indexing of unstructured text extracted from
  Snowflake result sets or staged document catalogs (`hash`/`lexical` only).

Every non-`asupersync` dependency is a candidate until a per-crate `cargo tree`
proof shows no forbidden crate in the production feature graph it contributes.

## Dependency Policy

Production crates must not depend on Tokio, reqwest, hyper, axum, tower, sqlx,
diesel, sea-orm, or third-party Rust Snowflake drivers.

Third-party Snowflake Rust crates may be studied as read-only inspiration, but
they must not be vendored, copied, or added as production dependencies. The
authoritative behavioral sources are Snowflake's official documentation, live
protocol observations, and our own conformance fixtures.

Keep feature flags explicit:

- `default`: core types, auth model, SQL API request/response schemas, and the
  agent-friendly CLI surfaces that do not require live credentials.
- `live`: real Snowflake SQL API transport. Runtime-gated by explicit profile
  and credential availability.
- `testkit`: deterministic mock server, canned fixtures, replay harness, and
  golden protocol packets.
- `adapter-fixtures`: optional public adapter examples and contract fixtures.
- `mcp`: the `fastmcp_rust`-backed `mcp serve` surface.
- `frankenpandas`: frame materialization through focused `fp-*` crates.
- `export`: `COPY INTO` export plans plus local CSV/JSONL writers (no `fp-io`;
  Arrow/Parquet deferred unless a forbidden-dependency-clean writer is proven).
- `graph` / `toon`: default-on agent-legibility affordances (catalog lineage graph
  + Mermaid/SVG, token-efficient output) once each is cargo-tree-proven; droppable
  via `--no-default-features` for the leanest agent build.
- `tui`: interactive human TUI, first-class but **default-off / opt-in** until its
  cargo-tree and Windows cross-platform proofs are boring (it is the heaviest,
  most platform-sensitive, and least agent-relevant surface).
- `frankensearch`: unstructured text indexing helpers (`hash`/`lexical` only).

## Safety And Security

Secrets never belong in repo files, Beads comments, support bundles, logs, or
test fixtures. Profiles should reference environment variable names or secret
provider handles, not raw token values.

Supported auth lanes should be implemented in this order:

1. Programmatic access token (PAT) for fast administrator-managed onboarding.
2. Key-pair JWT for long-lived service users and rotation.
3. OAuth bearer tokens where the client already has an OAuth flow.
4. Workload identity federation only after the first three lanes are stable.

All user-facing diagnostics must redact account identifiers when requested,
always redact tokens/private keys, and include stable error codes with exact
next commands.

## Agent-Ergonomic CLI Requirements

Every read-side command must support `--json` or a `--robot-*` mode. Stdout is
data. Stderr is diagnostics. JSON output must be deterministic and versioned.

Required CLI surfaces:

- `franken-snowflake capabilities --json`
- `franken-snowflake robot-docs guide` / `franken-snowflake agent-handbook --json`
- `franken-snowflake doctor --json`
- `franken-snowflake profile validate --json`
- `franken-snowflake catalog scan --json`
- `franken-snowflake catalog graph --mermaid`
- `franken-snowflake dataset describe-operator <operator> --jsonschema`
- `franken-snowflake query --sql ... --json`
- `franken-snowflake query plan --json`
- `franken-snowflake query cancel <statement-handle> --json`
- `franken-snowflake mcp serve [--stdio | --http <addr>]`

Read commands accept `--json` (default) or `--toon`. Empty-but-valid results are
exit 0 with an empty payload, never a non-zero exit.

Mutating operations must be disabled by default. Any future DDL/DML/write path
requires `--dry-run`, explicit `--confirm`, idempotency receipts, and append-only
audit records.

## Git And Filesystem Rules

All work happens on `main`. Do not create feature branches or worktrees.

Never delete files without explicit written user permission. Do not run
destructive commands such as `git reset --hard`, `git clean -fd`, or recursive
removal commands unless the user provides the exact command and confirms the
irreversible consequences in writing.

Do not create sibling workspaces or temporary clones as a substitute for working
in this repository.

## Beads

Beads (`br`) is the task source of truth for this repository. Use `br --json`
for agent workflows, and run `br sync --flush-only` after creating or modifying
issues. Do not hand-edit `.beads` storage files.

Use dependency direction consistently:

```bash
br dep add <child> <parent>
```

This means `<child>` depends on `<parent>`.

## Testing Expectations

The first implementation must be testable without a live Snowflake account. Add
no-account golden fixtures before live tests.

Core proof lanes should include:

- request/response serialization goldens for SQL API objects
- auth-header construction tests with redacted evidence
- statement lifecycle tests through the mock server
- partition streaming and gzip partition tests
- cancellation tests that call the SQL API cancel endpoint on local cancellation
- deterministic output tests for CLI JSON envelopes
- secret redaction tests
- no-forbidden-dependency tests for production feature graphs

Live tests require explicit credentials and must be opt-in. A live test that is
missing credentials should emit a typed skip/refusal, not silently pass.

## External Documentation

When Snowflake behavior is uncertain, check official Snowflake documentation
first. Record the exact documentation URL and the date consulted in the relevant
plan, test fixture, or Beads comment.

<!-- bv-agent-instructions-v2 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking and [beads_viewer](https://github.com/Dicklesworthstone/beads_viewer) (`bv`) for graph-aware triage. Issues are stored in `.beads/` and tracked in git.

### Using bv as an AI sidecar

bv is a graph-aware triage engine for Beads projects (.beads/beads.jsonl). Instead of parsing JSONL or hallucinating graph traversal, use robot flags for deterministic, dependency-aware outputs with precomputed metrics (PageRank, betweenness, critical path, cycles, HITS, eigenvector, k-core).

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). `br` handles creating, modifying, and closing beads.

**CRITICAL: Use ONLY --robot-* flags. Bare bv launches an interactive TUI that blocks your session.**

#### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns everything you need in one call:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command

# Token-optimized output (TOON) for lower LLM context usage:
bv --robot-triage --format toon
```

Before claiming, verify current state with `br show <id> --json` or `br ready --json`. `recommendations` can include graph-important blocked or assigned work; only `quick_ref.top_picks` and non-empty `claim_command` fields represent claimable work.

#### Other bv Commands

| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with unblocks lists |
| `--robot-priority` | Priority misalignment detection with confidence |
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions, cycle breaks |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |

#### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work (no blockers)
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank scores
```

### br Commands for Issue Management

```bash
br ready              # Show issues ready to work (no blockers)
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason="Completed"
br close <id1> <id2>  # Close multiple issues at once
br sync --flush-only  # Export DB to JSONL
```

### Workflow Pattern

1. **Triage**: Run `bv --robot-triage` to find the highest-impact actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Always run `br sync --flush-only` at session end

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers 0-4, not words)
- **Types**: task, bug, feature, epic, chore, docs, question
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads changes to JSONL
git commit -m "..."     # Commit everything
git push                # Push to remote
```

<!-- end-bv-agent-instructions -->
