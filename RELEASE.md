# Release Readiness Checklist

This repository is public open-source infrastructure. A release must prove the
no-account connector substrate without exposing private downstream context or
requiring live Snowflake credentials.

## Current Release State

- Package version: `0.0.0` workspace pre-release.
- Publish state: workspace crates inherit `publish = false`; crates.io publish
  remains blocked until the first tagged public release intentionally chooses a
  SemVer version and flips that flag.
- License metadata: workspace crates inherit `license-file = "LICENSE"` because
  the repository uses MIT plus the OpenAI/Anthropic rider.
- Default feature policy: default features are intentionally lean; live, MCP,
  TUI, export, frame materialization, graph, and Frankensearch helpers stay
  feature-gated or opt-in according to `AGENTS.md`.

## Required Local Proof

Run these from the workspace root:

```bash
export CARGO_TARGET_DIR=/data/tmp/fsnow_targets/pane7
cargo check --workspace
cargo check --workspace --no-default-features
python3 scripts/check-dependency-admissibility.py
scripts/check-asupersync-single-version.sh
python3 scripts/check-golden-lf.py
cargo test --locked -p franken-snowflake-testkit --lib
cargo test --locked -p franken-snowflake-testkit --test e2e_harness
```

The dependency admissibility gate must emit passing JSON verdicts for the
default production graph, the no-default-features graph, each production feature
lane, all production features combined, and each dev/test feature lane. Any
Tokio, reqwest, hyper, hyper-util, axum, tower, tower-http, sqlx, diesel,
sea-orm, sea-orm-migration, `fp-io`, `orc-rust`, or third-party Snowflake driver
in a scanned lane blocks release.

## Required CI Proof

The GitHub Actions matrix must pass on Linux, macOS, and Windows:

- `cargo check --workspace --locked`
- `python3 scripts/check-dependency-admissibility.py`
- `python3 scripts/check-golden-lf.py`
- `cargo test --locked -p franken-snowflake-testkit --test e2e_harness`

The Linux lint lane must also pass:

- `cargo clippy --workspace --all-targets -- -D warnings`
- `scripts/check-asupersync-single-version.sh`

The cache crate currently depends on FrankenSQLite candidate crates. On Windows,
keep the fsqlite `cfg(unix)` prerequisite documented in
`docs/dependency_admissibility.md` and set the CI skip variable only for that
known upstream prerequisite, not for forbidden-dependency failures.

## No-Account Proof Lanes

Before tagging, confirm `docs/proof_lanes.md` has current evidence for:

- request/response serialization goldens for SQL API objects;
- auth-header construction with redacted evidence;
- deterministic statement lifecycle through the testkit mock:
  submit, poll, partition fetch, pagination, and cancel;
- DPOR/lab cancellation and retry race coverage;
- CLI/MCP JSON envelope parity and deterministic output;
- secret redaction, canary scans, and the credential `Debug` leak gate;
- CRLF-safe golden comparisons and portable config-dir handling;
- live-test skip/refusal behavior when credentials are absent.

## Public-Safety Scan

Before packaging, scan the public tree and Beads export for private downstream
names, deployment details, secrets, raw account identifiers, tokens, private key
material, and canary fixtures outside test-only contexts:

```bash
rg -n "PRIVATE|SECRET|TOKEN|PASSWORD|BEGIN .*PRIVATE KEY|SNOWFLAKE_ACCOUNT|AKIA|sk-" \
  README.md AGENTS.md CHANGELOG.md LICENSE RELEASE.md docs crates .beads
```

False positives are allowed only when the surrounding file is a documented
redaction or canary fixture and the value is synthetic.

## Packaging Steps

1. Choose the first public SemVer version and update `workspace.package.version`.
2. Re-run the local proof commands above and commit the resulting `Cargo.lock`
   change in the same release commit.
3. If crates.io publish is intended, change `publish = false` deliberately and
   ensure every internal path dependency has a matching version requirement.
4. Tag the release and build release artifacts from the clean tag.
5. Publish checksums and install smoke-test the artifact in a clean environment.
6. Update `CHANGELOG.md` with the tag date, commit range, and proof evidence.
