# Release Readiness Checklist

This repository is public open-source infrastructure. A release must prove the
no-account connector substrate without exposing private downstream context or
requiring live Snowflake credentials.

## Current Release State

- Package version: `0.0.2` (GitHub Release 2026-08-25). Its binaries were
  built with the default feature set (no `live`, no `mcp`) and no Windows
  assets, contrary to the README at the time; the next release must be built
  with `--features live,mcp` for every target including
  `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`, and `capabilities`
  on each artifact must report `live=true, mcp=true` before upload.
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
cargo test --workspace --locked
cargo test --locked -p franken-snowflake-cli --features live,mcp
cargo test --locked -p franken-snowflake-cli --features tui
cargo test --locked -p franken-snowflake-cache --features frankensqlite
cargo test --locked -p franken-snowflake-frame --features frankenpandas
cargo test --locked -p franken-snowflake-tui --features tui
cargo test --locked -p franken-snowflake-text-indexing --features frankensearch
cargo clippy --workspace --all-targets --locked -- -D warnings
```

`cargo test -p franken-snowflake-cli` includes the binary-spawning e2e lane
(`tests/cli_e2e.rs`, planted canary secrets) and, with `mcp`, the stdio
handshake/parity test (`tests/mcp_stdio.rs`).

The dependency admissibility gate must emit passing JSON verdicts for the
default production graph, the no-default-features graph, each production feature
lane, all production features combined, and each dev/test feature lane. Any
Tokio, reqwest, hyper, hyper-util, axum, tower, tower-http, sqlx, diesel,
sea-orm, sea-orm-migration, `fp-io`, `orc-rust`, or third-party Snowflake driver
in a scanned lane blocks release.

## Required Cross-Platform Proof (dsr, never GitHub Actions)

This repository does not use GitHub Actions. There is no `.github/workflows`
directory and none may be added. Cross-platform builds, tests, and release
artifacts run through `dsr` (Doodlestein Self-Releaser) on its Linux, macOS,
and Windows build hosts. The repository is registered with `dsr` as the tool
`franken_snowflake` (six targets: x86_64/aarch64 Linux, macOS, and Windows;
built with `--features live,mcp`; assets named
`franken-snowflake-v<version>-<target-triple>.tar.gz|zip` as the installers
expect):

```bash
dsr repos validate                     # config sanity (naming vs install.sh)
dsr quality franken_snowflake          # the check list below, locally
dsr build franken_snowflake --dry-run  # the six-target build plan
dsr build franken_snowflake            # build on the dsr hosts
dsr release franken_snowflake <ver>    # upload the artifacts + checksums
``` Before tagging, the following must pass on each of
the three platforms via `dsr`, and the release notes must cite the `dsr`
run output:

- `cargo check --workspace --locked`
- `python3 scripts/check-dependency-admissibility.py`
- `python3 scripts/check-golden-lf.py`
- `cargo test --workspace --locked` plus every optional feature lane listed
  above (the `frankensqlite` lane is Unix-only)

The Linux lint lane must also pass:

- `cargo clippy --workspace --all-targets -- -D warnings`
- `scripts/check-asupersync-single-version.sh`

The cache crate currently depends on FrankenSQLite candidate crates. On Windows,
keep the fsqlite `cfg(unix)` prerequisite documented in
`docs/dependency_admissibility.md` and set `FSNOW_SKIP_FSQLITE_WINDOWS_PREREQ`
only for that known upstream prerequisite, not for forbidden-dependency
failures.

History: a GitHub Actions workflow existed until 2026-09-03 and never executed
a single job (52 runs failed at workflow parse; the 10 after a fix were never
assigned a runner). It was removed; any "CI proof" wording older than this
note is unbacked.

## Cross-Compile Status (2026-09-03, local, `--features live,mcp --locked`)

| target | result | how |
|---|---|---|
| `x86_64-unknown-linux-gnu` | builds, tests pass | native |
| `aarch64-unknown-linux-gnu` | builds (ELF aarch64 PIE) **and runs** under `qemu-aarch64`: `capabilities` reports `live=true, mcp=true`, `doctor` ok, `selftest` 7/7 | `cargo zigbuild`, `qemu-aarch64 -L /usr/aarch64-linux-gnu` |
| `x86_64-pc-windows-msvc` | builds (PE32+ console exe, both binaries) | `cargo xwin build` |
| `aarch64-pc-windows-msvc` | **does not build** | `cargo xwin` exports clang-cl-style `/imsvc` include flags, but `ring 0.17` compiles its arm64 C sources with plain `clang`, which rejects them; overriding `CFLAGS_aarch64_pc_windows_msvc` is ignored by cargo-xwin. Needs a native Windows-on-ARM host or an upstream fix; the target is out of the release set until then (v0.0.1's arm64 asset came from a hosted Windows runner). |
| `aarch64-apple-darwin` | builds on the dsr macOS host (Mach-O arm64 PIE bundle) | `dsr build` |
| `x86_64-apple-darwin` | builds on the dsr macOS host once the cross target is installed there (the dsr `build_cmd` now runs `rustup target add` first) | `dsr build` |

The Windows binary above was produced, not executed: no Windows machine or
emulator was available in this session, so for that row "builds" means the
linker produced the executable, not that `capabilities` was run on it.

`dsr build franken_snowflake` (build only, no upload) produced all five
archives on 2026-09-03 across two runs. The first run built both Linux targets
and macOS arm64, and failed macOS x86_64 (cross target not installed on the
host) and Windows (dsr's native Windows runner emits PowerShell with its
variable names stripped; a dsr bug, not a repository issue). The second run,
after routing `windows/amd64` to the Linux host with `cargo xwin` through
`cross_compile.host` and installing the cross target in `build_cmd`, built
both remaining targets. The x86_64 Linux archive was executed here
(`capabilities` reports `live=true, mcp=true`, `selftest` 7/7, a typed
`FSNOW-2003` without credentials); the aarch64 Linux archive was executed
under `qemu-aarch64` with the same result. Every archive holds
`franken-snowflake`, `fsnow`, README, LICENSE, `install.sh`, and
`install.ps1`. dsr quarantines a partial run's archives and writes the
manifest only for the targets of one run, so the release build must be a
single five-target run.

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
  README.md AGENTS.md CHANGELOG.md LICENSE docs crates .beads
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
