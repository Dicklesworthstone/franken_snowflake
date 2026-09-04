# Release Readiness Checklist

This repository is public open-source infrastructure. A release must prove the
no-account connector substrate without exposing private downstream context or
requiring live Snowflake credentials.

## Current Release State

- Package version: `0.0.3` (GitHub Release 2026-09-04). Built by `dsr` on all
  six targets with `--features live,mcp`; the `v0.0.2` release (2026-08-25)
  had shipped default-feature binaries with no Windows assets, which this
  release corrects; `capabilities` on each executed artifact reports
  `live=true, mcp=true` before upload.
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
reports `0.0.3 / live=true / mcp=true`.

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
and the executables run directly. Session temp files from the host runs
were left in place (`/tmp/fsnow-v003-verify` on mmini, `%HOME%\fsnow-v003*`
on wlap). Pre-tag local proof: workspace tests, every feature-lane test,
workspace + 18-lane clippy `-D warnings`, `cargo fmt --check`,
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

## Packaging Steps

1. Choose the first public SemVer version and update `workspace.package.version`.
2. Re-run the local proof commands above and commit the resulting `Cargo.lock`
   change in the same release commit.
3. If crates.io publish is intended, change `publish = false` deliberately and
   ensure every internal path dependency has a matching version requirement.
4. Tag the release and build release artifacts from the clean tag.
5. Publish checksums and install smoke-test the artifact in a clean environment.
6. Update `CHANGELOG.md` with the tag date, commit range, and proof evidence.
