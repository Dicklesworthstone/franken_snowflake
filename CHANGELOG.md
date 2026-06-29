# Changelog

All notable changes to `franken_snowflake` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will
adopt [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it ships a
tagged release.

## Scope and method

This is the development history of `franken_snowflake` to date. As of this
writing the repository holds **166 non-merge commits from 2026-06-24 to
2026-06-29**, with **no git tags and no GitHub Releases**. There is no published
crate and no tagged release yet, so there is no version timeline to reconstruct;
everything below sits under a single `Unreleased` heading.

The record is organized by landed capability wave rather than raw commit order,
with representative commit links so another agent can navigate from a theme to
the evidence. Chronology is preserved through the timeline table below and the
dates noted in each section. The sources used to build this changelog are:

- the git history (`git log --reverse --no-merges`)
- the design documents (`COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md`,
  `docs/asupersync_leverage.md`, and the rest of `docs/`)
- the executable task graph in `.beads/issues.jsonl`, tracked with Beads (`br`)
- the release-readiness checklist in `RELEASE.md`

A note on commit subjects: many early commits are tagged "code-first, batch-test
pending." That reflects the project's working style, where a swarm lands the
implementation first and the test/hardening pass follows in a later wave. The
"Hardening and fresh-eyes review" section captures that follow-up.

## Version state

- Package version: `0.0.0` across the workspace; all crates inherit
  `publish = false`.
- Releases: none yet. No git tag, no GitHub Release, no crates.io publish.
- Live Snowflake transport is enabled with the `live` feature (default-off, so
  the default build is a credential-free slice) and is gated at runtime by
  credential availability.

## Timeline

| Window | Theme |
|---|---|
| 2026-06-24 | Architecture plan, workspace scaffold, lint policy, and the first pass at core, auth, http, sqlapi, catalog, cache, frame, export, graph, testkit, and CLI |
| 2026-06-25 | Hardening wave: MCP serve adapter, optional TUI, redaction and safety fixes across every crate, write-intent ladder types, cross-platform CI |
| 2026-06-26 | Live proof lanes, opt-in live transport wired into `query run` / `catalog scan` / `profile doctor --online`, and the agent-ergonomics CLI pass (`onboard`, `fsnow` alias) |
| 2026-06-29 | Hero illustration and GitHub social preview image |

---

## [Unreleased]

### Workspace scaffold and lint policy

The repository opened with the architecture plan, the task graph, and the design
docs, then a Phase 0 commit established the Cargo workspace (`resolver = "3"`,
edition 2024), the minimal crate skeletons, and the governance docs. The
workspace-wide lint policy is load-bearing: `forbid(unsafe_code)` plus `deny` on
`clippy::unwrap_used`, `expect_used`, `panic`, `todo`, and `dbg_macro`, inherited
by every crate via `[lints] workspace = true`. CI gates were added in the same
window: a toolchain and single-Asupersync-version gate, a per-crate
forbidden-dependency admissibility scan, and a cross-platform check matrix for
Linux, macOS, and Windows.

**Representative commits**
- [`1b5bed6`](https://github.com/Dicklesworthstone/franken_snowflake/commit/1b5bed6) Initial commit: architecture plan, task graph, and design docs
- [`95b4965`](https://github.com/Dicklesworthstone/franken_snowflake/commit/95b4965) Phase 0: Cargo workspace, minimal-five crate skeletons, governance docs
- [`df2b0aa`](https://github.com/Dicklesworthstone/franken_snowflake/commit/df2b0aa) ci: enforce toolchain and asupersync gates
- [`b1466f2`](https://github.com/Dicklesworthstone/franken_snowflake/commit/b1466f2) ci: add dependency admissibility cargo-tree gate
- [`cc353cb`](https://github.com/Dicklesworthstone/franken_snowflake/commit/cc353cb) ci: establish cross-platform support

**Notes for agents**: the forbidden list (Tokio, reqwest, hyper, axum, tower,
sqlx, diesel, sea-orm, third-party Snowflake drivers) is enforced by
`scripts/check-dependency-admissibility.py`. Run the gates listed in `RELEASE.md`
before assuming a change is admissible.

### Core contracts: envelope, capabilities, guardrails, budgets

`franken-snowflake-core` is the contract hub. It defines the deterministic,
versioned JSON envelope, the central error-code registry (each `FSNOW-<code>`
maps once to a default recovery path), the capability registry, the exit-code
dictionary, and the id newtypes. It then adopted the Asupersync `Outcome`,
`Budget`, `CancelReason`, and capability primitives so the connector's
four-valued result and cost-quota model come straight from the runtime. Security
and cost guardrails, the redactor, and the deferred write-intent ladder types
landed here too. Later fixes tightened the read-only guard against block-comment
evasion, projected policy refusals and statement timeouts as typed outcome
kinds, and added the `SurfaceReserved` code (`FSNOW-9002`, an exit-2 refusal).

**Representative commits**
- [`82b1a7e`](https://github.com/Dicklesworthstone/franken_snowflake/commit/82b1a7e) core: shared types, error registry, JSON envelope
- [`d086813`](https://github.com/Dicklesworthstone/franken_snowflake/commit/d086813) core: adopt Asupersync Outcome/Budget/CancelReason/capabilities
- [`2b01739`](https://github.com/Dicklesworthstone/franken_snowflake/commit/2b01739) core: add security and cost guardrails
- [`ac83c11`](https://github.com/Dicklesworthstone/franken_snowflake/commit/ac83c11) core: fix redactor token-boundary so secrets after `=`/`:` are redacted
- [`f16c117`](https://github.com/Dicklesworthstone/franken_snowflake/commit/f16c117) Add deferred write-intent ladder types
- [`b137675`](https://github.com/Dicklesworthstone/franken_snowflake/commit/b137675) fix(core): close read-only-guard fail-open on nested block comments
- [`1a33396`](https://github.com/Dicklesworthstone/franken_snowflake/commit/1a33396) feat(core): add SurfaceReserved error code (FSNOW-9002, exit 2 refusal)

**Notes for agents**: exit codes are coarse and stable (0 success, 2 safety
refusal, 3 credential error, 4 upstream, 5 network/budget, 6 still running, 7
local cache, 64 usage, 74 I/O). The richer signal is the envelope's
`outcome_kind` and `FSNOW-` code.

### Auth, redaction, and the secret-leak gate

Authentication landed in lane order. The RS256 key-pair JWT signer came first,
then a secret-safe PAT and OAuth bearer model. The compile-time credential
`Debug`-leak gate fails the build if a credential-shaped field derives `Debug`;
follow-up commits hardened it, tightened credential-field leak detection,
rejected secret-shaped auth source handles, and normalized Snowflake JWT locator
accounts. Profiles reference env-var names, never raw token values.

**Representative commits**
- [`cbd8129`](https://github.com/Dicklesworthstone/franken_snowflake/commit/cbd8129) auth: implement RS256 key-pair JWT signer
- [`501d3c4`](https://github.com/Dicklesworthstone/franken_snowflake/commit/501d3c4) auth: add secret-safe PAT OAuth auth model
- [`14cae15`](https://github.com/Dicklesworthstone/franken_snowflake/commit/14cae15) auth: add credential debug leak gate
- [`379334f`](https://github.com/Dicklesworthstone/franken_snowflake/commit/379334f) Tighten credential field leak detection
- [`e46e88b`](https://github.com/Dicklesworthstone/franken_snowflake/commit/e46e88b) Reject secret-shaped auth source handles

**Notes for agents**: the secret needle lists used by the redactor and the cache
are shared on purpose; if you add a credential prefix, update the shared list so
every surface redacts it. See `docs/security_model.md`.

### HTTP transport on Asupersync

`franken-snowflake-http` is the native transport, built on Asupersync HTTP/1.1
plus TLS plus gzip with no injected Tokio transport. It owns retry policy and the
subtleties around it: a 408 statement-timeout is terminal rather than retryable,
unsafe submit retries are blocked, child budgets bound transport work, the
idempotent cancel route is retried, and `Retry-After` is parsed (including the
HTTP-date form, measured against the real wall clock). Hardening hid HTTP body
bytes from `Debug`, redacted transport error messages, encoded submit query
parameters, and tightened Snowflake URL boundaries.

**Representative commits**
- [`012a9f6`](https://github.com/Dicklesworthstone/franken_snowflake/commit/012a9f6) http: implement Asupersync native transport
- [`8734101`](https://github.com/Dicklesworthstone/franken_snowflake/commit/8734101) http: block unsafe submit retries
- [`1d89de0`](https://github.com/Dicklesworthstone/franken_snowflake/commit/1d89de0) http: treat 408 statement-timeout as terminal (not retryable)
- [`e8a8b1d`](https://github.com/Dicklesworthstone/franken_snowflake/commit/e8a8b1d) http: parse Retry-After HTTP dates
- [`627abb8`](https://github.com/Dicklesworthstone/franken_snowflake/commit/627abb8) fix(http): measure HTTP-date Retry-After against the real wall clock
- [`96825a3`](https://github.com/Dicklesworthstone/franken_snowflake/commit/96825a3) Hide HTTP body bytes from Debug

**Notes for agents**: retry ownership is split. The submit POST is not blindly
retried; idempotency is the SQL API `requestId` plus `retry=true` contract. See
`docs/transport_design.md` and `docs/asupersync_leverage.md`.

### SQL API client: request, response, lifecycle, wire

`franken-snowflake-sqlapi` carries the protocol. The request/response/status
schemas landed with no-account golden fixtures and round-trip proofs, including a
fix for the jsonv2 codec decoding negative pre-1970 fractional timestamps. The
statement lifecycle is a state machine driving submit, poll, partition stream,
and cancel; later fixes preserved poll cancellation attribution, closed the
lifecycle machine on terminal failure, preserved terminal-failure projection, and
hardened partition and cancel integrity (including rejecting invalid partition
stream seeds).

**Representative commits**
- [`d5e08d3`](https://github.com/Dicklesworthstone/franken_snowflake/commit/d5e08d3) sqlapi: SQL API request/response/status protocol schemas (kx6)
- [`b67b393`](https://github.com/Dicklesworthstone/franken_snowflake/commit/b67b393) sqlapi: no-account golden fixtures + round-trip proofs (kx6)
- [`149ff13`](https://github.com/Dicklesworthstone/franken_snowflake/commit/149ff13) sqlapi: fix jsonv2 codec negative pre-1970 fractional timestamp decode
- [`0685e1e`](https://github.com/Dicklesworthstone/franken_snowflake/commit/0685e1e) sqlapi: complete statement lifecycle driver
- [`89ed6b3`](https://github.com/Dicklesworthstone/franken_snowflake/commit/89ed6b3) fix(sqlapi): close lifecycle machine on terminal failure
- [`8219eb6`](https://github.com/Dicklesworthstone/franken_snowflake/commit/8219eb6) Harden SQL API partition and cancel integrity

**Notes for agents**: the jsonv2 cell codec is golden-pinned. Changes to decoding
must keep `test(sqlapi): pin jsonv2 codec cell golden` green.

### Catalog discovery and planner

`franken-snowflake-catalog` covers `INFORMATION_SCHEMA` discovery, the dataset
model, the operator catalog, and the safe query planner. The manifest discovery
and the dataset query planner landed first, then a series of correctness fixes:
discovery scope filters are bound, raw SQL scanning is literal-aware, time-travel
timestamps render as cast literals, unsupported predicate operators are refused,
operator schemas accept singleton arrays, dataset ids are collision-resistant,
and time-index enum boundaries are pinned.

**Representative commits**
- [`cfed05b`](https://github.com/Dicklesworthstone/franken_snowflake/commit/cfed05b) catalog: implement information schema manifest discovery
- [`959e899`](https://github.com/Dicklesworthstone/franken_snowflake/commit/959e899) catalog: implement safe dataset query planner
- [`1c7dc94`](https://github.com/Dicklesworthstone/franken_snowflake/commit/1c7dc94) fix(catalog): make raw SQL scanning literal-aware
- [`d131968`](https://github.com/Dicklesworthstone/franken_snowflake/commit/d131968) fix(catalog): refuse unsupported predicate operators
- [`9938375`](https://github.com/Dicklesworthstone/franken_snowflake/commit/9938375) fix(catalog): make dataset ids collision-resistant

**Notes for agents**: filters are a dumb predicate AST validated against the
column and operator catalogs, not free-form SQL. See
`docs/dataset_manifest_contract.md` and `docs/catalog_graph_design.md`.

### Graph, frame, export, cache, and text-indexing

The lineage graph (`franken-snowflake-graph`) models catalog containment and
renders Mermaid/SVG; fixes escaped Mermaid labels per the Mermaid rules, locked
the cycle loop-order, rebuilt graph indexes after deserialize, rejected
conflicting output formats, and excluded a seed node from its own neighborhood.
Frame materialization (`franken-snowflake-frame`, via the focused `fp-columnar`
and `fp-types` crates) preserved scaled NUMBER decimals and i64 boundary
fidelity, and emits VARIANT/OBJECT/ARRAY cells verbatim to preserve precision.
Export (`franken-snowflake-export`) added content-addressed result exports, fixed
CSV correctness against its goldens, and rejected `COPY INTO` injection inputs.
The cache (`franken-snowflake-cache`) added the local repository layer, fails
closed on an unknown content-address algorithm, and aligns the in-memory backend
with the SQLite append-only contract. Text-indexing (`franken-snowflake-text-indexing`)
planned and hardened the optional frankensearch lane (`hash`/`lexical` only).

**Representative commits**
- [`ecd4696`](https://github.com/Dicklesworthstone/franken_snowflake/commit/ecd4696) graph: model catalog lineage output
- [`0d9d492`](https://github.com/Dicklesworthstone/franken_snowflake/commit/0d9d492) graph: escape Mermaid labels per Mermaid rules; lock in cycle loop-order
- [`1e86495`](https://github.com/Dicklesworthstone/franken_snowflake/commit/1e86495) fix(export,frame): emit VARIANT/OBJECT/ARRAY cells verbatim to preserve precision
- [`d1d1ba8`](https://github.com/Dicklesworthstone/franken_snowflake/commit/d1d1ba8) export: add content-addressed result exports
- [`5d0af38`](https://github.com/Dicklesworthstone/franken_snowflake/commit/5d0af38) fix(export): reject COPY INTO injection inputs
- [`c234120`](https://github.com/Dicklesworthstone/franken_snowflake/commit/c234120) cache: fail closed on unknown content-address algorithm

**Notes for agents**: local export is CSV/JSONL only; `fp-io` is forbidden (its
`orc-rust` dependency pulls Tokio). Large export goes through Snowflake-side
`COPY INTO`. See `docs/cache_repository_design.md`.

### Deterministic testkit, mock server, replay, and DPOR race suite

`franken-snowflake-testkit` is the no-account proof substrate. It provides a
shared harness (a golden framework, a JSON-line logger, a deterministic clock,
and a canary guard), determinism and schema-stability self-tests, a deterministic
Snowflake SQL API mock with replay, a deterministic cancel/retry race suite, and
a deterministic mock e2e harness. Hardening made the DPOR race suite fully
deterministic (treating step-budget truncation as inconclusive), avoided a panic
when truncating long multi-byte diff values, and redacted replay packet
recordings, recorded mock request paths, and mock HTTP `Debug` surfaces.

**Representative commits**
- [`f88883b`](https://github.com/Dicklesworthstone/franken_snowflake/commit/f88883b) testkit: shared harness (golden framework, json-line logger, deterministic clock, canary guard)
- [`16add23`](https://github.com/Dicklesworthstone/franken_snowflake/commit/16add23) testkit: add deterministic Snowflake SQL API mock replay
- [`c6a4ae0`](https://github.com/Dicklesworthstone/franken_snowflake/commit/c6a4ae0) testkit: add deterministic cancel retry race suite
- [`dcaea80`](https://github.com/Dicklesworthstone/franken_snowflake/commit/dcaea80) test: add deterministic mock e2e harness
- [`f734ace`](https://github.com/Dicklesworthstone/franken_snowflake/commit/f734ace) fix(testkit): make the DPOR cancel/retry race suite deterministic

**Notes for agents**: the two no-account lanes are a deterministic codec lane
under the lab runtime (over virtual TCP, with DPOR coverage) and an integration
lane against the mock server. See `docs/proof_lanes.md`.

### Agent-ergonomic CLI

`franken-snowflake-cli` owns the public command contract and produces both the
canonical `franken-snowflake` binary and the short `fsnow` alias. The draft
command surface, required-argument enforcement, offline profile
diagnostics, and the initial command contracts landed first, with live query
surfaces mapped to clean safety refusals. The agent-ergonomics pass added the
`onboard` mega-command, the `fsnow` alias with accurate compiled `feature_flags`,
exit-code precision, query-error pedagogy, and a `catalog graph` rendered from a
live scan. A long tail of parser fixes hardened flag handling: equals-style flag
values, rejecting missing or ambiguous flag values, keeping help positional
values parseable, gating the `toon` feature, and reporting the `mcp` feature in
`capabilities`.

**Representative commits**
- [`29e2cd9`](https://github.com/Dicklesworthstone/franken_snowflake/commit/29e2cd9) cli: draft agent command surface
- [`90c27aa`](https://github.com/Dicklesworthstone/franken_snowflake/commit/90c27aa) cli: integrate MVP command contracts
- [`d08f600`](https://github.com/Dicklesworthstone/franken_snowflake/commit/d08f600) feat(cli): add `fsnow` short bin alias + report accurate compiled feature_flags
- [`90e7485`](https://github.com/Dicklesworthstone/franken_snowflake/commit/90e7485) feat(cli): add `onboard` mega-command (one-call agent orientation)
- [`3f687f5`](https://github.com/Dicklesworthstone/franken_snowflake/commit/3f687f5) fix(cli): exit-code precision + query error pedagogy + feature-aware tests
- [`69a6fc3`](https://github.com/Dicklesworthstone/franken_snowflake/commit/69a6fc3) feat(cli): render `catalog graph` from a live catalog scan

**Notes for agents**: read commands default to `--json`; `--toon` needs the
default `toon` feature. There is no `completions` subcommand; discover the
surface through `fsnow capabilities --json`. See `docs/agent_cli_contract.md`.

### MCP and TUI surfaces

The MCP serve adapter (`franken-snowflake-mcp`) exposes the read verbs as MCP
tools over shared CLI handlers, so the CLI and MCP share one envelope contract.
The crate skeleton went in first to unblock the workspace check, then the serve
adapter, the `query cancel` parity tool, redaction of invalid-parameter errors,
a fix to strip exactly one `http:` tag from the serve address, and a
single-version dependency-gate fix. The optional FrankenTUI surface
(`franken-snowflake-tui`) landed behind its own feature (default-off), with a fix
to make the query-pane keys executable and a combined MCP/TUI review-defect pass.

**Representative commits**
- [`1b31bd0`](https://github.com/Dicklesworthstone/franken_snowflake/commit/1b31bd0) feat: implement MCP serve adapter
- [`49d0b73`](https://github.com/Dicklesworthstone/franken_snowflake/commit/49d0b73) fix(mcp): expose query cancel parity tool
- [`cc46bdd`](https://github.com/Dicklesworthstone/franken_snowflake/commit/cc46bdd) fix(mcp): strip only one `http:` tag from the serve address
- [`b2d987e`](https://github.com/Dicklesworthstone/franken_snowflake/commit/b2d987e) feat: add optional FrankenTUI surface
- [`21beeec`](https://github.com/Dicklesworthstone/franken_snowflake/commit/21beeec) Fix MCP and TUI review defects

**Notes for agents**: `mcp serve` is read-only and stdio-first by design. The
tool roster mirrors the CLI verbs (capabilities, onboard, doctor,
agent_handbook, robot_docs_guide, selftest, profile_validate, profile_doctor,
catalog_scan, catalog_graph, dataset_inspect, dataset_profile,
dataset_describe_operator, query_plan, query_run, query_cancel, receipt_show,
export_plan).

### Auth/redaction and live transport (opt-in)

The opt-in live lane is the `live` feature. Live proof lanes landed first, then
two rounds of live-protocol decode fixes (each guarded by no-account regression
goldens so the no-account build still proves the change). The CLI live wiring
went in as three slices: `query run`, `catalog scan`, and the
`profile doctor --online` probe. The runtime contract is strict: with the
feature compiled and credentials present, the command runs and the envelope
carries `data_source = "live"` and the real statement handle; with the feature
compiled but a credential handle absent, the command returns a typed credential
error (exit 3); without the feature, the command refuses cleanly rather than
substituting fixture or empty data.

**Representative commits**
- [`1e48db8`](https://github.com/Dicklesworthstone/franken_snowflake/commit/1e48db8) Add opt-in Snowflake live proof lanes
- [`7a50a0e`](https://github.com/Dicklesworthstone/franken_snowflake/commit/7a50a0e) fix(sqlapi): land live-testing protocol decode fixes (hij)
- [`0b30bc6`](https://github.com/Dicklesworthstone/franken_snowflake/commit/0b30bc6) test(sqlapi): no-account regression guards for the live partition decode fixes (ko8)
- [`71cff91`](https://github.com/Dicklesworthstone/franken_snowflake/commit/71cff91) feat(cli): wire live SQL API transport into `query run` (9o1, slice 1/3)
- [`4a0b791`](https://github.com/Dicklesworthstone/franken_snowflake/commit/4a0b791) feat(cli): wire live transport into `catalog scan` (9o1, slice 2/3)
- [`99dfb10`](https://github.com/Dicklesworthstone/franken_snowflake/commit/99dfb10) feat(cli): wire live `profile doctor --online` probe (9o1, slice 3/3)

**Notes for agents**: live results are capped into the envelope with a
`truncated` flag and a warning; full extraction uses a Snowflake-side `LIMIT` or
`COPY INTO`. Live session parameters are pinned (UTC, fixed date/time formats,
result cache disabled) for stable output. See `docs/live_proof.md`.

### Hardening, fresh-eyes review, and release readiness

Several waves were dedicated to review rather than new features. The
open-source-readiness prep, the downstream adapter contract fixtures, and
repeated fresh-eyes review rounds landed verified bug and chore fixes across the
workspace (recorded in Beads). Dependency-lane coverage was extended to the graph
and toon lanes. The most recent commit added the hero illustration and the GitHub
social preview image.

**Representative commits**
- [`2680b71`](https://github.com/Dicklesworthstone/franken_snowflake/commit/2680b71) release: prepare open-source readiness
- [`fab86f5`](https://github.com/Dicklesworthstone/franken_snowflake/commit/fab86f5) Add downstream adapter contract fixtures
- [`6f0851a`](https://github.com/Dicklesworthstone/franken_snowflake/commit/6f0851a) fix: land stalled fresh-eyes-review fix round to verified green
- [`fcf049d`](https://github.com/Dicklesworthstone/franken_snowflake/commit/fcf049d) Cover graph and toon dependency lanes
- [`8bacec5`](https://github.com/Dicklesworthstone/franken_snowflake/commit/8bacec5) docs: add hero illustration to README + GitHub social preview image

**Notes for agents**: the gate that decides whether the tree is releasable is
`RELEASE.md`. A SemVer version and the first tagged release come once `RELEASE.md` is
satisfied and `publish = false` is flipped deliberately.

---

## Notes for agents

- Start from `br ready --json` for actionable work and `br dep cycles` for graph
  health. Beads is the task source of truth, not GitHub issues.
- The full rationale lives in
  [`COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md`](COMPREHENSIVE_PLAN_FOR_FRANKEN_SNOWFLAKE.md)
  and the Asupersync leverage contract in
  [`docs/asupersync_leverage.md`](docs/asupersync_leverage.md).
- Live Snowflake use is enabled with the `live` feature. Do not treat local fixtures
  as live data; every live lane either provides explicit credential evidence or
  emits a typed skip/refusal.
- Once the first public release is tagged, this file gains a dated, versioned
  entry with the commit range and the proof evidence from `RELEASE.md`.

[Unreleased]: https://github.com/Dicklesworthstone/franken_snowflake
</content>
