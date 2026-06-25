# Changelog

All notable changes to `franken_snowflake` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it ships a
release.

## Scope and method

This project is at the no-account MVP and release-readiness stage. The Cargo
workspace, protocol/auth/catalog/cache/export/text-indexing/TUI/MCP boundary
crates, deterministic testkit, structured e2e harness, dependency gates, and
cross-platform CI scaffolding are in place. There is still no crate publish, git
tag, or GitHub Release, so this changelog has no version history to reconstruct.
The record below is drawn from the durable sources in the repository:

- the design documents (`COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md` and
  `docs/asupersync_leverage.md`)
- the executable task graph in `.beads/issues.jsonl`, tracked with Beads (`br`)
- the release-readiness checklist in `RELEASE.md`

Once the first public release is tagged, each landed capability will get a dated
entry with links to the commits that delivered it.

## [Unreleased]

No-account MVP and release-readiness phase (2026-06-24 to 2026-06-25). The
deliverable is the agent-facing connector substrate, deterministic proof lanes,
and the release checklist required before any public tag or crates.io publish.

### Added

- **Workspace scaffold and boundary crates.** A Cargo workspace (`resolver = "3"`,
  edition 2024) with the `franken-snowflake-{core,auth,http,sqlapi,catalog,frame,
  graph,cache,export,text-indexing,testkit,cli,mcp,tui}` crates building as one
  release candidate workspace and producing the `franken-snowflake` binary.
- **Workspace lint policy.** `forbid(unsafe_code)` plus `deny` on
  `clippy::unwrap_used` / `expect_used` / `panic` / `todo` / `dbg_macro`, inherited
  by every crate via `[lints] workspace = true` and verified to actually fail a
  build/clippy run. The toolchain pin, `[patch.crates-io]` Asupersync unification,
  `deny.toml`, and the single-Asupersync-version CI gate remain owned by a
  dedicated toolchain bead.
- **Governance contract docs.** `docs/agent_cli_contract.md` (envelope keys, exit
  codes, command families, MCP parity), `docs/security_model.md` (secret handling,
  the two anti-leak mechanisms, auth lanes, cost safety, write-intent ladder),
  `docs/dataset_manifest_contract.md` (the three-part model and the shared
  planner), and `docs/proof_lanes.md` (the eight proof lanes plus cross-cutting
  testing standards), with a `docs/protocol/` placeholder and a `.gitattributes`
  pinning golden newline discipline.
- **Architecture plan.** The clean-room design for a Rust-first Snowflake SQL API
  connector that talks HTTPS directly, with no ODBC, JDBC, or third-party
  Snowflake crate, and no Tokio/reqwest/hyper/axum/tower in production crates.
- **Asupersync leverage contract** (`docs/asupersync_leverage.md`). A mapping from
  each hard part of the connector to a concrete Asupersync primitive: four-valued
  `Outcome`, structured `CancelReason`, `Budget` with a cost quota, capability-row
  narrowing for read-only-by-default, `bracket` for orphan-free statement
  cancellation, and `LabRuntime`/DPOR for deterministic race tests. It also
  records the HTTP client realities the implementation must engineer around
  (manual gzip, no injected transport, HTTP/1.1-only, submit-POST retry ownership).
- **Agent-ergonomic contract.** A deterministic, versioned JSON envelope with a
  typed `outcome_kind`, `data_source` provenance, `did_you_mean`, a central error
  registry that gives every code a default recovery path, a binary-embedded
  `agent-handbook`, a self-describing capability registry, and a documented
  exit-code scheme where empty-but-valid results are exit 0.
- **MCP surface design.** A feature-gated `mcp serve` that exposes the read verbs
  as MCP tools over shared CLI handlers, so the CLI and MCP cannot drift into two
  contracts. Sequenced stdio and read-only first, HTTP second, writes deferred.
- **Three-part dataset model.** A dataset manifest with per-field roles, a column
  catalog, and an operator catalog, with filters kept as a dumb predicate AST
  validated against the catalogs.
- **Security model.** Read-only by default, secrets absent from config, `Debug`,
  JSON, and panic text, a compile-time credential-leak gate, fail-closed rights,
  content-addressed receipts, and an append-only audit log.
- **No-account test strategy.** Two lanes: a deterministic codec lane over
  `VirtualTcp` under `LabRuntime` with DPOR race coverage, and an integration lane
  against a mock SQL API server, plus a shared golden/clock/canary harness and a
  cross-platform proof matrix.
- **Governance docs.** `AGENTS.md`, `README.md`, the dependency-admissibility and
  single-Asupersync-version policy, and the auth-lane ordering (PAT, key-pair JWT,
  OAuth, then workload identity federation).
- **Task graph.** 33 Beads issues under the `fsnow-native-snowflake-connector-w0i`
  epic, dependency-wired across seven phases with no cycles, in
  [`.beads/issues.jsonl`](.beads/issues.jsonl).
- **No-account implementation proof lanes.** Auth-header construction, SQL API
  statement lifecycle, polling, partition streaming, cancellation, pagination,
  golden fixture comparison, CRLF-safe goldens, and redaction lanes are covered
  by deterministic unit/integration tests and the structured JSON-line e2e
  harness.
- **Release and dependency gates.** Linux/macOS/Windows CI runs workspace checks,
  the per-crate forbidden-dependency admissibility gate, the single-Asupersync
  gate, LF-golden validation, and the deterministic e2e harness. `RELEASE.md`
  records the commands and evidence expected before a public tag.

### Notes for agents

- Start from `br ready --json` for actionable work and `br dep cycles` for
  graph health.
- The full rationale is in
  [`COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md`](COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md).
- Live Snowflake use remains pre-release and opt-in. Do not treat local fixtures
  as live data; every live lane must either provide explicit credential evidence
  or emit a typed skip/refusal.

[Unreleased]: https://github.com/Dicklesworthstone/franken_snowflake
