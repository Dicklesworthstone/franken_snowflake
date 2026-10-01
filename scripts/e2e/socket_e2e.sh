#!/usr/bin/env bash
# Hermetic socket-level e2e (bead oj0.31): every scenario of
# crates/franken-snowflake-cli/tests/socket_e2e.rs, i.e. the real binary over
# TLS to a loopback mock SQL API. One run directory collects:
#   events.jsonl        one JSON line per test event (libtest's JSON format)
#   socket/<scenario>/  the binary's store, the mock's requests.jsonl (bearer
#                       tokens redacted) and each run's envelope (runs.jsonl)
#   summary.json        pass/fail per scenario, totals, build identity
# No credential variable reaches the run. Exits non-zero if any scenario fails.
#
# Usage: scripts/e2e/socket_e2e.sh [extra libtest args, e.g. a name filter]
# FSNOW_E2E_RUN_DIR picks the run directory (default target/fsnow-e2e-runs/...).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 2
RUN_DIR="${FSNOW_E2E_RUN_DIR:-$ROOT/target/fsnow-e2e-runs/socket-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$RUN_DIR" || exit 2
# Absolute: the test process runs from the crate directory, not from here.
RUN_DIR="$(cd "$RUN_DIR" && pwd)" || exit 2

# Nothing that could name a real account or credential reaches the run.
while IFS= read -r name; do
  unset "$name"
done < <(env | sed -E -n 's/^((FRANKEN_)?SNOWFLAKE_[A-Za-z0-9_]*)=.*/\1/p')
export FRANKEN_SNOWFLAKE_LIVE=0
export FSNOW_E2E_ARTIFACTS_DIR="$RUN_DIR"

cargo test --locked -p franken-snowflake-cli --features live,mcp,testkit-endpoint \
  --test socket_e2e -- -Z unstable-options --format json --report-time "$@" \
  >"$RUN_DIR/events.jsonl" 2>"$RUN_DIR/cargo.stderr"
status=$?

# The build identity the tested binary reports about itself (its source
# digest is content-based, so it holds on a host without a matching .git).
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug/franken-snowflake"
if [ -x "$BIN" ]; then
  "$BIN" capabilities --json >"$RUN_DIR/capabilities.json" 2>/dev/null
fi

python3 - "$RUN_DIR" "$status" <<'PY'
import json, platform, sys
run_dir, status = sys.argv[1], int(sys.argv[2])
build = {"host": platform.platform()}
try:
    with open(f"{run_dir}/capabilities.json", encoding="utf-8") as caps:
        build.update(json.load(caps)["data"]["build"])
except (OSError, ValueError, KeyError, TypeError):
    build["identity"] = "unavailable (the binary did not report one)"
scenarios = {}
with open(f"{run_dir}/events.jsonl", encoding="utf-8") as events:
    for line in events:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("type") == "test" and event.get("event") in ("ok", "failed", "ignored"):
            scenarios[event["name"]] = {"result": event["event"], "exec_time_s": event.get("exec_time")}
summary = {
    "suite": "socket_e2e",
    "exit_status": status,
    "passed": sum(1 for s in scenarios.values() if s["result"] == "ok"),
    "failed": sorted(n for n, s in scenarios.items() if s["result"] == "failed"),
    "ignored": sum(1 for s in scenarios.values() if s["result"] == "ignored"),
    "scenarios": dict(sorted(scenarios.items())),
    "build": build,
}
with open(f"{run_dir}/summary.json", "w", encoding="utf-8") as out:
    json.dump(summary, out, indent=2)
print(json.dumps({k: summary[k] for k in ("suite", "exit_status", "passed", "failed", "ignored")}))
print(f"run directory: {run_dir}")
PY
exit "$status"
