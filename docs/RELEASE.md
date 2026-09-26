# Release Readiness Checklist

This repository is public open-source infrastructure. A release must prove the
no-account connector substrate without exposing private downstream context or
requiring live Snowflake credentials.

## Current Release State

- Package version: `0.0.5`, a security release (GitHub Release 2026-09-25, tag
  `v0.0.5` at `07ef0af`). Built by `dsr` in one run (`39a0a638`) on all six
  targets with `--features live,mcp`; every binary reports `build.git_sha
  07ef0af`, `dirty: false`, `profile: release`, `testkit: false` and source
  digest `68cb0560...`. See "v0.0.5 release record" below.
- Publish state: all 14 crates are published on crates.io at `0.0.5` (first
  published 2026-09-12); they configure `publish = ["crates-io"]` and declare
  version requirements across internal path dependencies (sqlapi's testkit
  dev-dependency is path-only: testkit depends on sqlapi).

### v0.0.5 release record (2026-09-25)

- Operator go-ahead: 2026-09-24, in this session ("Go: build and release", and
  "Also publish crates" for crates.io).
- Linux proof on `07ef0af`'s tree: every lane of "Required Local Proof" through
  rch, plus `dsr quality franken_snowflake` 13/13 (receipt
  `~/.local/state/dsr/quality-logs/franken_snowflake/20260925T023047-3245208`,
  bound to `5666a1b`, whose crate sources and `Cargo.lock` are byte-identical to
  `07ef0af`: same source digest). A first quality run passed 13/13 but was
  invalidated by dsr because `HEAD` moved during it; it was rerun on a frozen
  tree rather than accepted.
- macOS and Windows: see "Cross-OS test runs" below.
- Build: `dsr build franken_snowflake` (run `39a0a638`, 2385 s). The build
  identity came from `FSNOW_BUILD_SHA`/`FSNOW_BUILD_DIRTY` set in
  `repos.d/franken_snowflake.yaml` `env:` for this build only (dsr buildroots
  carry no `.git`); set it again, naming the release commit, before the next
  release build. dsr's rsync to the Windows host failed on its path conversion,
  so the tagged tree reached it through `git archive` (verified by SHA-256).
- Artifacts executed: Linux x86_64 (here), macOS arm64 and x86_64 (Rosetta) on
  mmini, Windows x86_64 on wlap: `capabilities`, `selftest`, `doctor`, the
  credential refusal (exit 3, `FSNOW-2003`), `mcp serve --http` startup. Linux
  arm64 ran the same checks under qemu user-mode emulation.
  `aarch64-pc-windows-msvc` has not been executed; its embedded git sha and
  source digest match.
- Release: `dsr release franken_snowflake 0.0.5 --verify-tag` (14 assets: six
  archives, six `.sha256`, `SHA256SUMS`, the dsr manifest; no signatures);
  `dsr release verify` passed. Notes carry the security advisory.
- Installer smoke: `install.sh --version 0.0.5 --dest <empty dir> --verify` in a
  clean `HOME`; the installed binary reports 0.0.5 and `07ef0af`.
- crates.io: `scripts/publish-crates.py` stopped after four crates on the
  sqlapi/testkit dev-dependency cycle; fixed in `e3c60d0` (path-only
  dev-dependency) and resumed; all 14 crates at 0.0.5.
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
# README capability claims against their evidence (docs/claims.toml): every
# tagged claim names tests that exist, and live evidence is fresh.
python3 scripts/check-claims.py --self-test
python3 scripts/check-claims.py
cargo test --workspace --locked
cargo test --locked -p franken-snowflake-cli --features live,mcp
# Socket e2e: the real binary over real TLS to a loopback mock SQL API
# (tests/socket_e2e.rs). `testkit-endpoint` is test-only: a release artifact
# must report `capabilities` `feature_flags.testkit=false`.
cargo test --locked -p franken-snowflake-cli --features live,mcp,testkit-endpoint
cargo test --locked -p franken-snowflake-cli --features tui
cargo test --locked -p franken-snowflake-cli --features frankenpandas
cargo test --locked -p franken-snowflake-cli --features frankensearch
cargo test --locked -p franken-snowflake-cache --features frankensqlite
cargo test --locked -p franken-snowflake-export --features export
# Parquet read back by PyArrow and DuckDB (needs `uv`); a missing uv fails here:
FSNOW_REQUIRE_EXTERNAL_PARQUET=1 cargo test --locked -p franken-snowflake-export --all-features --test parquet_conformance
FSNOW_PRIVATE_DENYLIST=<path outside the repo> scripts/check-public-safety.sh
cargo test --locked -p franken-snowflake-frame --features frankenpandas
# Perf lane (wall-clock, so never in the default suite): the jsonv2 decoder's
# 350 MB/s release target, with the host and CPU governor it ran on.
cargo test --locked --release -p franken-snowflake-frame --features frankenpandas --test zero_copy_parity -- --ignored --nocapture
cargo test --locked -p franken-snowflake-graph --features graph
cargo test --locked -p franken-snowflake-http --features compression
cargo test --locked -p franken-snowflake-tui --features tui
cargo test --locked -p franken-snowflake-text-indexing --features frankensearch
cargo clippy --workspace --all-targets --locked -- -D warnings
scripts/check-feature-lanes.sh   # clippy -D warnings for every feature lane + coverage check
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

This repository does not use GitHub Actions: Actions are disabled in the
repository settings, and no workflow may be added (the leftover
`.github/workflows/ci.yml` was removed on 2026-09-24 with the operator's
go-ahead). Cross-platform builds, tests, and release
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
  above
- `scripts/e2e/socket_e2e.sh`: the hermetic socket-level e2e (the real binary
  over TLS to a loopback mock SQL API, every scenario of
  `crates/franken-snowflake-cli/tests/socket_e2e.rs`); its run directory keeps
  each scenario's requests, envelopes and store plus `summary.json`, and it
  exits non-zero when a scenario fails

The Linux lint lane must also pass:

- `cargo clippy --workspace --all-targets -- -D warnings`
- `scripts/check-asupersync-single-version.sh`

The cache crate's `frankensqlite` feature builds on Windows since FrankenSQLite
0.4.x (fsqlite 0.4.4 with sqlmodel-frankensqlite 0.5.0): its 29 tests passed
natively on wlap on 2026-09-25, so no lane is skipped on Windows any more.

History: through 2026-09-03 the GitHub Actions workflow never executed a job
(52 runs failed at workflow parse; the 10 after a fix were never assigned a
runner). Runs on 2026-09-12/13 did execute and failed on real defects (a
`cli_e2e` TLS connection to `127.0.0.1.snowflakecomputing.com`, fixed in
`9297728`, and a macOS installer step exiting 127); Actions were then disabled.
Any "CI proof" wording older than this note is unbacked.

### Cross-OS test runs

2026-09-24, on the dsr build hosts, native toolchain `nightly-2026-08-31`,
tree = commit `f374716` plus the two Windows fixes below (verified by file
SHA-256 on each host). macOS got the tree through
`dsr build franken_snowflake --target darwin/arm64 --sync-only`; dsr's rsync to
the Windows host failed on a path-conversion bug, so Windows got it through
`git archive HEAD` over ssh into the same buildroot. mmini's cargo is an rch
shim, so the macOS runs set `RCH_SHIM_LOCAL_IDE=1 RCH_CARGO_WRAPPER_BYPASS=1
RCH_REAL_CARGO=<toolchain>/bin/cargo-rch-real` to build locally; Windows ran
inside `VsDevCmd.bat -arch=amd64`.

| host | OS | lanes | result |
|---|---|---|---|
| mmini | macOS 26.2 arm64 | `cargo test --workspace --locked` and every feature lane above, including `franken-snowflake-cache --features frankensqlite`; `socket_e2e` + `mcp_http` with `live,mcp,testkit-endpoint,frankenpandas` | all green (socket 24/24, mcp_http 3/3) |
| wlap | Windows 10.0.26220 x64 | the same, minus the Unix-only `frankensqlite` lane | all green after the fixes (socket 23/23; the SIGINT scenario is Unix-only; mcp_http 3/3) |

The first Windows run failed 20 of 23 socket scenarios and 2 of 3 MCP HTTP
tests. Two defects, both fixed: every live command and `mcp serve` overflowed
the 1 MiB Windows main-thread stack in a debug build (the CLI build script now
links the binaries with an 8 MiB stack, the Unix default), and the MCP HTTP test
scrubbed `SYSTEMROOT`, which Windows sockets need. Not covered then: Ctrl-C on
Windows, the `frankensqlite` lane on Windows, and a release-profile live run on
Windows (whether the published v0.0.4 Windows binary also overflows on the live
path is unknown). The first two are covered since 2026-09-25 (Asupersync 0.5
tree): socket e2e `ctrl_c_cancels_the_statement_in_flight_on_windows` raises a
real console CTRL_C_EVENT (28/28 on wlap), and `cargo test -p
franken-snowflake-cache --features frankensqlite` passes 29/29 there.

2026-09-25, Asupersync 0.5 tree (b541d30 plus the socket e2e artifact
harness), file SHA-256 verified on each host:

| host | platform | ran | result |
|---|---|---|---|
| mmini | macOS 26.2 arm64 | `scripts/e2e/socket_e2e.sh`; `cargo test --workspace`; every feature lane above | all green (socket e2e 28/28, cache frankensqlite 29/29) |
| wlap | Windows 10.0.26220 x64 | `cargo test --workspace`; cli `live,mcp,testkit-endpoint,frankenpandas`; cache `frankensqlite`; text-indexing `frankensearch`; tui | all green (socket e2e 28/28 incl. the Ctrl-C scenario) |
| rch workers | Linux x64 | workspace default and `--all-features` tests, the cli lanes, clippy `-D warnings` both configurations; `scripts/e2e/socket_e2e.sh` as an rch job | all green (socket e2e 28/28) |

## Cross-Compile Status (2026-09-03, local, `--features live,mcp --locked`)

| target | result | how |
|---|---|---|
| `x86_64-unknown-linux-gnu` | builds, tests pass | native |
| `aarch64-unknown-linux-gnu` | builds (ELF aarch64 PIE) **and runs** under `qemu-aarch64`: `capabilities` reports `live=true, mcp=true`, `doctor` ok, `selftest` 7/7 | `cargo zigbuild`, `qemu-aarch64 -L /usr/aarch64-linux-gnu` |
| `x86_64-pc-windows-msvc` | builds (PE32+ console exe, both binaries) | `cargo xwin build` |
| `aarch64-pc-windows-msvc` | builds (PE32+ ARM64 console exe) from Linux via `scripts/cross-build-windows-arm64.sh`, and natively on the Windows host through dsr (MSVC + VS 2022 clang; both binaries plus the installers in the zip) | `cargo xwin --cross-compiler clang` plus two workarounds baked into the script: blake3 uses its pure-Rust implementation on this target only (its NEON C path includes MSVC's `arm_neon.h`, which the clang driver cannot compile), and capitalized import-library aliases (`Kernel32.lib`) are added to cargo-xwin's clang sysroot because asupersync links `Kernel32` with a capital K. Linked, not executed: no ARM Windows machine or emulator is available. |
| `aarch64-apple-darwin` | builds on the dsr macOS host (Mach-O arm64 PIE bundle) | `dsr build` |
| `x86_64-apple-darwin` | builds on the dsr macOS host once the cross target is installed there (the dsr `build_cmd` now runs `rustup target add` first) | `dsr build` |

The Windows binary above was produced, not executed: no Windows machine or
emulator was available in this session, so for that row "builds" means the
linker produced the executable, not that `capabilities` was run on it.

**Windows through dsr.** dsr's native Windows runner could not run on a host
whose OpenSSH login shell is PowerShell (it sent `powershell -Command "..."`
and cmd-style lines that the outer PowerShell re-parsed, stripping every
variable); that was fixed in dsr itself (commit `6fad86b`, `-EncodedCommand`
for every generated PowerShell script and a base64 `cmd.exe /d /s /c` wrapper
for cmd lines). With that fix both Windows targets build natively on the
Windows host (`cross_compile.windows/*` in the dsr registry: `host: wlap`,
`CARGO_BUILD_TARGET`, a one-line cmd-compatible `build_cmd`), and cargo-xwin
on the Linux host remains the fallback. Three more facts the native path
depends on, each of which cost one failed run: dsr's strict isolation strips
the inherited `LIB`/`INCLUDE`, so the `build_cmd` initializes
`VsDevCmd.bat -arch=amd64|arm64` itself; the host's login `PATH` is about
7.6 K characters and VsDevCmd's additions push cmd.exe past its 8191-char
limit ("The input line is too long"), so the `build_cmd` first resets `PATH`
to the essentials; and rsync to a Windows receiver over a multiplexed ssh
channel fails intermittently with `EAGAIN` (exit 12), so dsr now uses
`--blocking-io` on a dedicated transport for Windows hosts and retries a
dropped stream up to three times (dsr commits `3e5c7bf`, `627fc95`). A PowerShell 5.1 login shell reports any non-zero remote exit as
`1` over OpenSSH; dsr's Windows paths rely on zero/non-zero only.

**Executed on the real hosts (2026-09-03).** Both macOS archives were copied
to the Mac host and run there: `capabilities` reports `live=true, mcp=true`,
`selftest` 7/7, `doctor` ok, and a typed `FSNOW-2003` refusal without
credentials, for `aarch64-apple-darwin` natively and `x86_64-apple-darwin`
under Rosetta. The `x86_64-pc-windows-msvc` zip built natively by dsr was
copied to the Windows host (Windows 11, x64) and run there with the same
four results. The `aarch64-pc-windows-msvc` zip is linked, not executed: no
ARM Windows machine or emulator is available. The `x86_64-pc-windows-msvc`
row above was also re-linked natively by dsr, superseding the cargo-xwin
artifact for release purposes.

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
single full run.

**v0.0.3 release run (2026-09-04, dsr run `5a13735f`, 2436 s, build +
release).** All six targets succeeded in one clean-tree `dsr build
franken_snowflake` from pushed main (`ef32fd76`, no `--allow-dirty`; the
manifest records the git sha), then `dsr release franken_snowflake 0.0.3`
uploaded the six archives with per-file `.sha256` sidecars and
`SHA256SUMS` to the GitHub release. Built natively on each platform host:

| archive | built on |
|---|---|
| `franken-snowflake-v0.0.3-x86_64-unknown-linux-gnu.tar.gz` | trj (native) |
| `franken-snowflake-v0.0.3-aarch64-unknown-linux-gnu.tar.gz` | trj (native) |
| `franken-snowflake-v0.0.3-aarch64-apple-darwin.tar.gz` | mmini (native) |
| `franken-snowflake-v0.0.3-x86_64-apple-darwin.tar.gz` | mmini (native) |
| `franken-snowflake-v0.0.3-x86_64-pc-windows-msvc.zip` | wlap (native MSVC) |
| `franken-snowflake-v0.0.3-aarch64-pc-windows-msvc.zip` | wlap (native MSVC) |

Executed proof on this workstation: both Linux archives report `capabilities`
`version 0.0.3, live=true, mcp=true`, `selftest` 7/7, `doctor` ok, and a
typed `FSNOW-2003` refusal without credentials; the aarch64 archive runs
under `qemu-aarch64`. The installer was smoke-tested in a clean prefix:
`install.sh --version v0.0.3 --dest <dir>` installs and the installed binary
reports `0.0.3 / live=true / mcp=true`. The containerized canary lane
(`dsr canary run franken_snowflake`, ubuntu:24.04) installs from the
published release and verifies the same feature set; its PATH check
requires adding `~/.local/bin` manually, which is installer output, not a
defect.

**Executed on the real hosts (2026-09-04).** Both macOS archives were
copied to the Mac host (mmini, macOS 26.2 arm64) and run there:
`capabilities` reports `0.0.3 / live=true / mcp=true`, `selftest` ok,
`doctor` ok, and a typed `FSNOW-2003` refusal without credentials —
`aarch64-apple-darwin` natively and `x86_64-apple-darwin` under Rosetta
(Mach-O x86_64 confirmed with `file`). The `x86_64-pc-windows-msvc` zip
was copied to the Windows host (wlap, Windows 11 x64) and run natively
with the same four results (`capabilities`, `selftest` ok, `doctor` ok,
`FSNOW-2003`). The `aarch64-pc-windows-msvc` zip remains linked, not
executed: no ARM Windows machine or emulator is available. The PowerShell
installer was not exercised; the installer archive contents were extracted
and the executables run directly. Session temp files from the macOS run
were left in place (`/tmp/fsnow-v003-verify` on mmini); the wlap session
files (extraction, data dir, a tui-lane clippy attempt) were removed after
the runs — that attempt found the VS installer shell hangs in hidden
non-interactive windows on that host, so the Windows tui lane stays a
hand-run residual — CLOSED 2026-09-04: the Windows tui lane passed on wlap
(`cargo clippy -p franken-snowflake-cli --features tui --all-targets
--locked -- -D warnings`, EXIT=0 in 4m33s) when launched the dsr way — a
held ssh session running an encoded-command PowerShell script that drives
cmd.exe with its /d /s /c switches; detached hidden-window launches hang
VsDevCmd on that host, so held-session launch is the documented mechanic.
The macOS tui lane passed the same day on mmini (pinned nightly). Pre-tag
local proof: workspace tests, every feature-lane
test, workspace + 18-lane clippy `-D warnings`, `cargo fmt --check`,
admissibility, single-version, golden-LF (via `dsr quality` plus the
per-lane rerun after its first-pass findings were fixed: a fmt violation
and an unused-import in the new tui lane).

**Single full run (2026-09-03, dsr run `a33ba45c`, 3059 s, build only;
v0.0.2 history).**
All six targets succeeded in one `dsr build franken_snowflake` and the
manifest lists every archive with its SHA-256:

| archive | built on |
|---|---|
| `franken-snowflake-v0.0.2-x86_64-unknown-linux-gnu.tar.gz` | trj |
| `franken-snowflake-v0.0.2-aarch64-unknown-linux-gnu.tar.gz` | trj (zigbuild) |
| `franken-snowflake-v0.0.2-aarch64-apple-darwin.tar.gz` | mmini |
| `franken-snowflake-v0.0.2-x86_64-apple-darwin.tar.gz` | mmini |
| `franken-snowflake-v0.0.2-x86_64-pc-windows-msvc.zip` | wlap (native MSVC) |
| `franken-snowflake-v0.0.2-aarch64-pc-windows-msvc.zip` | wlap (native MSVC + clang) |

Every archive holds `franken-snowflake`, `fsnow`, README, LICENSE,
`install.sh`, and `install.ps1`. Two caveats, stated so the run is not
overstated: the run was started with `--allow-dirty` (the manifest records
no git sha), and its rsync to the Windows host dropped once before the
retry landed in dsr, so the Windows targets were compiled from the tree the
previous run had synced; that tree differs from HEAD only in
`docs/RELEASE.md` and the bead journal, so the Windows binaries are built
from identical code. The per-file `.sha256` sidecars and `SHA256SUMS` are
produced by `dsr release`, not by `dsr build`.

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

Private names cannot be listed in a public pattern, so they are checked from a
denylist kept outside the repository (one literal token per line):

```bash
FSNOW_PRIVATE_DENYLIST=~/private/fsnow-denylist.txt scripts/check-public-safety.sh
FSNOW_PRIVATE_DENYLIST=~/private/fsnow-denylist.txt scripts/check-public-safety.sh --selftest
```

It scans the tree and `.beads/issues.jsonl` (not git history), reports only
`file:count`, exits 1 on any hit, and refuses (exit 2) without a denylist or
with one inside the repository.

## Packaging Steps

1. Choose the next SemVer version and update `workspace.package.version` and the
   internal path dependencies' version requirements to match.
2. Re-run the local proof commands above and commit the resulting `Cargo.lock`
   change in the same release commit.
3. Publish the crates to crates.io in dependency order with
   `scripts/publish-crates.py` (it waits for each crate to propagate).
4. Tag the release and build release artifacts from the clean tag.
5. Publish checksums and install smoke-test the artifact in a clean environment.
6. Update `CHANGELOG.md` with the tag date, commit range, and proof evidence.
