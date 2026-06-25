<div align="center">

# franken_snowflake

**A clean-room, Rust-first Snowflake SQL API connector built for coding agents.**

![License](https://img.shields.io/badge/license-MIT%20%2B%20OpenAI%2FAnthropic%20rider-blue)
![Status](https://img.shields.io/badge/status-no--account%20MVP%20%2F%20pre--release-orange)
![Language](https://img.shields.io/badge/language-Rust%202024-dea584)
![Runtime](https://img.shields.io/badge/runtime-Asupersync-8A2BE2)
![Forbidden deps](https://img.shields.io/badge/no-Tokio%20%C2%B7%20reqwest%20%C2%B7%20hyper-critical)

</div>

> **Status: no-account MVP and release-readiness pass.**
> The workspace now includes the core contracts, CLI surfaces, deterministic
> testkit, structured e2e harness, dependency gates, and cross-platform CI
> scaffolding. Live Snowflake use remains opt-in and pre-release; there is no
> crates.io package, installer, or production live-account release yet.

---

## The Problem

Snowflake ships official drivers for Go, JDBC, .NET, Node.js, ODBC, PHP, and
Python. It does not ship one for Rust. So a Rust service (or a coding agent that
wants to query Snowflake without standing up a Python sidecar) is left with ODBC
bridges, JDBC-over-JNI, or third-party crates whose dependency graphs pull in
Tokio, `reqwest`, and a transitive forest no one audited.

For an agent the situation is worse. Raw SQL plus scattered secrets is a poor
interface: there is no machine-readable capability list, no way to ask "what data
exists here," no deterministic JSON contract, and no guardrail against running an
expensive unbounded scan by accident.

## The Solution

`franken_snowflake` talks to the [Snowflake SQL API](https://docs.snowflake.com/en/developer-guide/sql-api/index)
directly over HTTPS, with no ODBC, no JDBC, and no third-party Snowflake crate. It
is built on [Asupersync](https://github.com/Dicklesworthstone/asupersync), a
spec-first, cancel-correct, capability-secure async runtime, so the networking,
cancellation, retry budgets, and deterministic tests come from a single audited
foundation instead of the Tokio ecosystem.

The interface is designed for agents first: deterministic versioned JSON on every
read command, a self-describing capability registry, a binary-embedded handbook,
exact next-command suggestions in errors, and an optional
[MCP](https://modelcontextprotocol.io) server so every read verb is a callable
tool. A no-account testkit proves the protocol before any live credential exists.

## Design Goals

These are the guarantees the implementation is built around. Live-account
hardening is still pre-release, but the no-account proof substrate is in place.

| Goal | How |
|---|---|
| Rust-first, memory-safe | No `unsafe`; workspace lints deny `unwrap`/`panic`/`todo` |
| No hidden async runtime | Built on Asupersync; production crates forbid Tokio/reqwest/hyper/axum/tower/sqlx/diesel/sea-orm |
| Agent-ergonomic by default | Deterministic `--json` (and `--toon`), capabilities, `agent-handbook`, `did_you_mean`, stable exit codes |
| Callable as a tool, not just a CLI | Optional `mcp serve` exposing the same handlers and contract |
| Provable without credentials | No-account testkit: deterministic codec lane + mock SQL API server |
| Never mistake a fixture for live data | `data_source` provenance on every envelope; `--require-live` refuses substitution |
| Read-only by default | Capability-narrowed contexts; mutation gated behind an explicit write-intent ladder |
| Secrets stay secret | No secret in config, `Debug`, JSON, panic text; a compile-time leak gate enforces it |
| Auditable after the fact | Content-addressed query receipts and an append-only audit log |

## Why It Exists

FrankenSuite needs a Snowflake connector with the same engineering posture as the
projects around it: Rust-first, Asupersync-native, agent-readable, no hidden Tokio
graph, no secrets in config or logs, no silent fallback from live data to mocks,
and local receipts that downstream systems can audit later.

---

## MVP Interface

The CLI contract is implemented as deterministic, agent-readable surfaces first.
Live-account lanes require explicit opt-in credentials and refuse clearly when
credentials are absent.

```bash
# Discover the tool itself
franken-snowflake capabilities --json
franken-snowflake agent-handbook --json
franken-snowflake doctor --json

# Validate a profile without contacting Snowflake (env presence only)
franken-snowflake profile validate demo-prod --json

# Discover data
franken-snowflake catalog scan demo-prod --database ANALYTICS --schema PUBLIC --json
franken-snowflake catalog graph demo-prod --mermaid
franken-snowflake dataset describe-operator between --jsonschema

# Plan and run a query (raw SQL or dataset mode)
franken-snowflake query plan --profile demo-prod --sql "select * from events limit 10" --json
franken-snowflake query run  --profile demo-prod --dataset events_daily \
  --entity ENTITY123 --from 2024-01-01 --to 2024-12-31 --json
franken-snowflake query cancel <statement-handle> --json

# Serve the same read verbs to an agent over MCP
franken-snowflake mcp serve --stdio
```

Every read command emits a deterministic JSON envelope (`--json`, default) or a
token-efficient `--toon` encoding. Stdout is data; stderr is diagnostics. An
empty-but-valid result is exit 0 with an empty payload, never a non-zero exit.

---

## Architecture

```text
agent or human
    |
    v
franken-snowflake CLI  +  mcp serve (shared handlers, same contract)
    |
    +-- capabilities / robot-docs / agent-handbook / doctor
    +-- profile validate / credential doctor
    +-- catalog scan / catalog graph --mermaid / dataset inspect / describe-operator
    +-- query plan / query run / query cancel
    +-- export  /  tui   (output: --json default, --toon optional)
    |
    v
franken-snowflake library stack
    |
    +-- auth: PAT, key-pair JWT (RS256), OAuth bearer
    +-- sqlapi: statement submit, poll, cancel, partitions
    +-- catalog: information schema discovery and dataset manifests
    +-- graph: catalog lineage graph + Mermaid/SVG
    +-- frames: optional FrankenPandas materialization (fp-columnar/fp-types)
    +-- export: content-addressed COPY INTO (primary) + local CSV/JSONL
    +-- cache: FrankenSQLite/sqlmodel metadata store
    +-- testkit: deterministic codec lane + mock SQL API server
    |
    v
Snowflake SQL API
```

Two query modes share one planner. Raw SQL mode is for experts. Dataset mode lets
an agent ask for rows by entity and date range against a named dataset, and the
planner compiles that to pushed-down SQL with positional typed bindings. A
submitted statement is modeled as an Asupersync `bracket`, so cancellation always
reaches Snowflake's remote cancel endpoint and no statement is orphaned.

---

## How It Compares

Positioning against the existing options. `franken_snowflake` is still
pre-release for live Snowflake use; the no-account CLI, protocol, and testkit
contracts are the current shipped surface.

| | franken_snowflake (pre-release) | Official drivers (Python/Go/JDBC/...) | Third-party Rust crates | ODBC / JDBC bridge |
|---|---|---|---|---|
| Language / runtime | Rust on Asupersync | Per language | Rust on Tokio | Native lib + bridge |
| Hidden Tokio/reqwest graph | None (by policy) | n/a | Usually | n/a |
| Agent JSON contract + MCP | First-class | No | No | No |
| No-account deterministic tests | Yes | Varies | Rare | No |
| Read-only-by-default capability security | Compile-time | No | No | No |
| Secret-leak compile gate | Yes | No | No | No |
| Maturity | No-account MVP / pre-release | Production | Varies | Production |

If you need a production Snowflake client today and you are not in Rust, use an
official driver. `franken_snowflake` exists for the Rust-first, agent-first,
Tokio-free niche the official drivers do not cover.

---

## FrankenSuite Dependencies

The plan is biased toward local sibling projects. Every non-`asupersync`
dependency is a candidate until a `cargo tree` scan proves it pulls no forbidden
crate (Tokio, reqwest, hyper, axum, tower, sqlx, diesel, sea-orm) into the
production feature graph.

| Project | Role |
|---|---|
| [`asupersync`](https://github.com/Dicklesworthstone/asupersync) | Runtime, structured concurrency, native HTTP/1.1+TLS+gzip, retries, cancellation, Budget/Outcome/capabilities, deterministic lab/DPOR tests |
| `frankensqlite` + `sqlmodel_rust` | Local metadata store and typed repositories (via the `sqlmodel-frankensqlite` driver): profiles, catalog snapshots, receipts, audit log |
| `fastmcp_rust` | Native MCP server surface (`mcp serve`); every read verb as an MCP tool |
| `jsonwebtoken` (`rust_crypto`, `use_pem`) | Pure-Rust RS256 key-pair JWT signing (no OpenSSL/ring-signing/Tokio) |
| `fastapi_rust` | Test-only mock SQL API server (dev-dependency) |
| `frankenpandas` | Frame materialization via focused `fp-columnar`/`fp-types` crates (never the umbrella crate or `fp-io`, which pulls Tokio); local CSV/JSONL export only, with large export via Snowflake `COPY INTO` |
| `frankenmermaid` + FrankenNetworkX `fnx-*` | Catalog lineage graph and Mermaid/SVG diagram output |
| `frankentui` | Interactive TUI (catalog browser, query runner, live progress); first-class but opt-in and default-off until cross-platform-proven |
| `toon` | Token-efficient `--toon` output mode alongside `--json` |
| `frankensearch` | Optional indexing of text-heavy datasets (`hash`/`lexical` only) |

---

## Security Model

- Read-only by default, narrowed to the capabilities a path actually needs.
- No secret values in config, `Debug`, JSON output, or panic text. A compile-time
  gate fails the build if a credential-shaped field has a derived `Debug`.
- Profiles reference environment variable names or secret-provider handles, never
  raw token values.
- Auth lanes, in implementation order: programmatic access token (PAT), key-pair
  JWT, OAuth bearer, then workload identity federation.
- Fail-closed rights: an unknown rights label parses to the most restrictive
  class; an expired entitlement is treated as missing, not as default-allow.
- TLS required. Mutation is disabled by default and gated behind an explicit
  write-intent ladder (dry-run, allowlist, idempotency key, confirmation token,
  receipt, append-only audit).

---

## Roadmap

Work is tracked in [Beads](https://github.com/Dicklesworthstone/beads_rust)
(`br`), not GitHub issues. The phases:

| Phase | Scope |
|---|---|
| 0 | Repo, docs, task graph, toolchain pin, dependency unification gate |
| 1 | Core types and SQL API schemas with deterministic golden fixtures |
| 2 | Auth: PAT, then key-pair JWT; redaction and secret-leak gates |
| 3 | Transport, two-lane testkit, statement lifecycle, DPOR race suite |
| 4 | CLI MVP and the `mcp serve` surface |
| 5 | Catalog, dataset manifests, lineage graph |
| 6 | Frame, export, cache, and the opt-in TUI |
| 7 | Opt-in live trial hardening |

To browse the live task graph:

```bash
br ready --json     # what is actionable now
br dep cycles       # dependency-graph health
```

The full design rationale lives in
[COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md](COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md),
and the Asupersync leverage contract in
[docs/asupersync_leverage.md](docs/asupersync_leverage.md).

---

## Downstream Integration Target

Downstream projects should consume Snowflake through a narrow adapter rather than
embedding protocol code directly. The adapter treats Snowflake as an
authenticated private data-lake source with provider/profile diagnostics, catalog
discovery, dataset manifests with time/entity/filter hints, rights and sensitivity
metadata, query receipts, and content-addressed exports into downstream storage.
Downstream projects keep their own command contracts, rights policy, storage, and
user-facing semantics.

---

## Limitations

- **No production live-account release yet.** The no-account contracts, testkit,
  and release proof lanes exist; crates.io publishing, an installer, and a
  production live-account claim are still deferred.
- Read, query, catalog, and export come first. Write and update support is
  deliberately deferred behind a write-intent ladder; DDL stays disabled until
  there is a documented public use case.
- The MVP rejects non-`SELECT` and multiple-statement requests unless explicitly
  allowed.
- Local Arrow/Parquet export is deferred until a forbidden-dependency-clean writer
  is proven; local export is CSV/JSONL, and large export uses Snowflake-side
  `COPY INTO`.
- The TUI is opt-in and default-off until its cross-platform proofs are boring.
- The whole stack requires a nightly Rust toolchain (edition 2024), inherited from
  the FrankenSQLite/sqlmodel/Asupersync dependency set.

---

## FAQ

**Is this usable today?** Yes for no-account contract work, deterministic
fixtures, dependency proof lanes, and the agent-facing CLI surfaces. Treat live
Snowflake use as pre-release and opt-in only.

**Why not just use an official driver?** Snowflake publishes none for Rust, and
the goal here is a Rust-first, Tokio-free, agent-ergonomic client, a niche the
official drivers do not cover.

**Why not a third-party Rust Snowflake crate?** Those may be studied as read-only
inspiration, but the policy forbids vendoring them or adding them as production
dependencies; the dependency graph and clean-room posture matter here.

**Why Asupersync instead of Tokio?** Cancellation correctness, capability
security, structured budgets, and deterministic Lab/DPOR tests come from one
audited runtime. The connector forbids Tokio, reqwest, hyper, axum, and tower in
production crates.

**Does it need a Snowflake account to develop against?** No. The no-account
testkit (deterministic codec lane plus a mock SQL API server) proves the protocol
before any live credential exists. Live tests are opt-in and refuse clearly when
credentials are absent.

**Where are the issues tracked?** In Beads (`br`), synced to JSONL in this repo,
not GitHub issues.

---

## About Contributions

Please don't take this the wrong way, but I do not accept outside contributions
for any of my projects. I simply don't have the mental bandwidth to review
anything, and it's my name on the thing, so I'm responsible for any problems it
causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also
have to worry about other "stakeholders," which seems unwise for tools I mostly
make for myself for free. Feel free to submit issues, and even PRs if you want to
illustrate a proposed fix, but know I won't merge them directly. Instead, I'll
have Claude or Codex review submissions via `gh` and independently decide whether
and how to address them. Bug reports in particular are welcome. Sorry if this
offends, but I want to avoid wasted time and hurt feelings. I understand this
isn't in sync with the prevailing open-source ethos that seeks community
contributions, but it's the only way I can move at this velocity and keep my
sanity.

---

## License

MIT License (with OpenAI/Anthropic Rider). See [LICENSE](LICENSE).
