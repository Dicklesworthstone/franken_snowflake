# Dependency Admissibility Gate

`scripts/check-dependency-admissibility.py` is the CI gate for
`fsnow-native-snowflake-connector-w0i.7`.

It runs `cargo metadata --locked`, discovers workspace packages, then runs
`cargo tree --locked` for each package across these lanes:

- default production graph
- `--no-default-features` production graph
- each production feature
- all production features combined
- workspace-level `--no-default-features`
- workspace-level `--features <production-feature>` for every policy-listed
  production feature
- workspace-level all-production-features combined
- each dev/test feature as a separate lane

Every lane emits a structured JSON verdict. The gate fails if any lane, including
a dev/test feature lane, resolves Tokio, reqwest, hyper, axum, tower, sqlx,
diesel, sea-orm, `fp-io`, `orc-rust`, or a third-party Snowflake driver. The
`fp-io` / `orc-rust` negative assertion is global, so future frame and export
crates are covered as soon as they enter the workspace.

The policy-listed production features must also have at least one workspace
crate owner. Missing owners fail the gate before any `cargo tree` scan, which
keeps product-level lanes such as `graph` and `toon` from silently dropping out
of CI coverage.

To extend the harness for a new dependency:

1. Add the dependency normally in the owning bead.
2. If it is a FrankenSuite candidate, add its package names to
   `CANDIDATE_GROUPS` in `scripts/check-dependency-admissibility.py`.
3. If it introduces a new feature flag, classify that feature in
   `PRODUCTION_FEATURES` or `DEV_FEATURES`. Unknown features are treated as
   production by default.
4. Run the script under the required target dir:

```bash
export CARGO_TARGET_DIR=/data/tmp/fsnow_targets/pane10
scripts/check-dependency-admissibility.py
```

The script has a built-in parser self-test that injects the known bad
`fp-io -> orc-rust -> tokio` path plus a third-party Snowflake package and
asserts that the gate catches it.

Windows CI has one explicit upstream prerequisite for the non-default cache
feature: FrankenSQLite must re-gate the Unix-only `nix` dependency in
`fsqlite-vfs` and `fsqlite-mvcc` from `cfg(not(target_arch = "wasm32"))` to
`cfg(unix)`, then add its own full-workspace Windows build. Until that lands,
the CI matrix runs this gate on Windows with only the cache crate's
`frankensqlite` lane skipped and emits a structured `lane_skipped` event. The
default cache crate and all other workspace lanes still run on Windows.
