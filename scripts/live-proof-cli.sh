#!/usr/bin/env bash
# One-command live battery over the wired CLI surfaces.
#
# Opt-in only. Without FRANKEN_SNOWFLAKE_LIVE=1 and FRANKEN_SNOWFLAKE_LIVE_PROFILE
# it writes a typed skip event and exits 0, so it is safe in no-account runs.
# With opt-in it runs each surface through the real binary with --json, checks
# the typed fields with jq, writes every envelope plus an events.jsonl under an
# artifacts directory, scans everything it captured for the profile's secret
# values (planted-canary style), and exits non-zero on the first hard failure.
#
# Usage:
#   FRANKEN_SNOWFLAKE_LIVE=1 FRANKEN_SNOWFLAKE_LIVE_PROFILE=trial \
#   FRANKEN_SNOWFLAKE_TRIAL_ACCOUNT=... FRANKEN_SNOWFLAKE_TRIAL_USER=... \
#   FRANKEN_SNOWFLAKE_TRIAL_AUTH=pat FRANKEN_SNOWFLAKE_TRIAL_PAT=... \
#   FRANKEN_SNOWFLAKE_TRIAL_WAREHOUSE=... FRANKEN_SNOWFLAKE_TRIAL_DATABASE=... \
#   FRANKEN_SNOWFLAKE_TRIAL_SCHEMA=... scripts/live-proof-cli.sh
#
#   scripts/live-proof-cli.sh --selftest   # proves the harness itself offline
#
# Optional: FSNOW_BIN=<path to a live+mcp binary> (else it is built),
#           FRANKEN_SNOWFLAKE_LIVE_ARTIFACTS_DIR=<dir>,
#           <PREFIX>_SMALL_SQL, <PREFIX>_PARTITION_SQL (see docs/live_proof.md).
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
: "${CARGO_TARGET_DIR:=$REPO_ROOT/target}"
export CARGO_TARGET_DIR
ARTIFACTS_ROOT="${FRANKEN_SNOWFLAKE_LIVE_ARTIFACTS_DIR:-$CARGO_TARGET_DIR/fsnow-live-proof}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RUN_DIR="$ARTIFACTS_ROOT/cli-$STAMP"
EVENTS="$RUN_DIR/events.jsonl"
HARD_FAILURES=0
SOFT_FINDINGS=0

log() { printf '[live-proof-cli] %s\n' "$*" >&2; }

need() {
  command -v "$1" >/dev/null 2>&1 || { log "missing required tool: $1"; exit 74; }
}
need jq
need date

mkdir -p "$RUN_DIR"

event() {
  # event <step> <status:pass|fail|skip|finding> <exit> <ms> <note>
  jq -cn --arg step "$1" --arg status "$2" --argjson exit "$3" --argjson ms "$4" --arg note "$5" \
    '{schema:"franken_snowflake.live_proof_cli.v1",step:$step,status:$status,exit:$exit,ms:$ms,note:$note}' >>"$EVENTS"
}

now_ms() { local ns; ns=$(date +%s%N); printf '%s' "$((ns / 1000000))"; }

# ---------------------------------------------------------------- opt-in gate
profile_prefix() {
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]' | tr '.-' '__' | sed 's/^/FRANKEN_SNOWFLAKE_/'
}

SELFTEST=0
[ "${1:-}" = "--selftest" ] && SELFTEST=1

if [ "$SELFTEST" -eq 0 ] && { [ "${FRANKEN_SNOWFLAKE_LIVE:-0}" != "1" ] || [ -z "${FRANKEN_SNOWFLAKE_LIVE_PROFILE:-}" ]; }; then
  event credential_gate skip 0 0 "FRANKEN_SNOWFLAKE_LIVE=1 and FRANKEN_SNOWFLAKE_LIVE_PROFILE are required; nothing was resolved and no network I/O happened"
  log "not opted in; typed skip written to $EVENTS"
  exit 0
fi

# ---------------------------------------------------------------- binary
resolve_bin() {
  if [ -n "${FSNOW_BIN:-}" ]; then
    printf '%s' "$FSNOW_BIN"
    return
  fi
  log "building franken-snowflake with --features live,mcp"
  (cd "$REPO_ROOT" && cargo build --locked --release -p franken-snowflake-cli --features live,mcp >"$RUN_DIR/build.log" 2>&1) || {
    log "build failed; see $RUN_DIR/build.log"
    exit 74
  }
  printf '%s' "$CARGO_TARGET_DIR/release/franken-snowflake"
}

# ---------------------------------------------------------------- runner
# run_step <step> <hard|soft> <jq-assertion> -- <args...>
# Captures stdout to <step>.json, stderr to <step>.stderr, records the event.
run_step() {
  local step="$1" severity="$2" assertion="$3"; shift 3
  [ "$1" = "--" ] && shift
  local out="$RUN_DIR/$step.json" err="$RUN_DIR/$step.stderr"
  local started rc ms
  started=$(now_ms)
  "$BIN" "$@" >"$out" 2>"$err"
  rc=$?
  ms=$(( $(now_ms) - started ))
  if jq -e "$assertion" "$out" >/dev/null 2>&1; then
    event "$step" pass "$rc" "$ms" "ok"
    log "PASS $step (${ms}ms)"
    return 0
  fi
  local code
  code=$(jq -r '.error.code // "n/a"' "$out" 2>/dev/null || echo "unparseable")
  if [ "$severity" = "soft" ]; then
    SOFT_FINDINGS=$((SOFT_FINDINGS + 1))
    event "$step" finding "$rc" "$ms" "assertion failed: $assertion (error.code=$code)"
    log "FINDING $step: exit=$rc error.code=$code"
    return 1
  fi
  HARD_FAILURES=$((HARD_FAILURES + 1))
  event "$step" fail "$rc" "$ms" "assertion failed: $assertion (error.code=$code)"
  log "FAIL $step: exit=$rc error.code=$code; envelope at $out"
  return 1
}

field() { jq -r "$2" "$RUN_DIR/$1.json" 2>/dev/null; }

# ---------------------------------------------------------------- canary scan
secret_scan() {
  # Every secret-shaped handle value must be absent from everything captured.
  local prefix="$1" hits=0 name value
  for name in PAT OAUTH_BEARER PRIVATE_KEY_PASSPHRASE; do
    value=$(printenv "${prefix}_${name}" 2>/dev/null || true)
    if [ -n "$value" ] && grep -rqF -- "$value" "$RUN_DIR"; then
      hits=$((hits + 1))
      log "CANARY HIT: value of ${prefix}_${name} appears in the artifacts"
    fi
  done
  value=$(printenv "${prefix}_PRIVATE_KEY_PEM" 2>/dev/null || true)
  if [ -n "$value" ]; then
    # Any non-header line of the key must be absent.
    local line
    while IFS= read -r line; do
      case "$line" in
        ""|*"-----"*) continue ;;
      esac
      if grep -rqF -- "$line" "$RUN_DIR"; then
        hits=$((hits + 1))
        log "CANARY HIT: a private key line appears in the artifacts"
        break
      fi
    done <<<"$value"
  fi
  if grep -rqE 'Bearer [A-Za-z0-9._-]{16,}' "$RUN_DIR"; then
    hits=$((hits + 1))
    log "CANARY HIT: a bearer token shape appears in the artifacts"
  fi
  if [ "$hits" -gt 0 ]; then
    HARD_FAILURES=$((HARD_FAILURES + hits))
    event secret_scan fail 0 0 "$hits secret-shaped value(s) leaked into the artifacts"
    return 1
  fi
  event secret_scan pass 0 0 "no secret handle value or bearer shape in any captured output"
  log "PASS secret_scan"
}

# ---------------------------------------------------------------- selftest
if [ "$SELFTEST" -eq 1 ]; then
  # Proves the harness offline: the gate, the runner, and the canary scanner.
  BIN=$(resolve_bin)
  export FRANKEN_SNOWFLAKE_DATA_DIR="$RUN_DIR/data"
  run_step selftest_capabilities hard '.ok == true and .command_id == "capabilities"' -- capabilities --json
  run_step selftest_offline_refusal hard '.ok == false and (.error.code | startswith("FSNOW-"))' -- query run --profile no_such_profile_for_selftest --sql "select 1" --json
  # Planted canary: the scanner must catch a secret value written into the run
  # dir. The `fail` event this produces is the planted negative, not a defect.
  log "planting a canary secret; the next secret_scan MUST report a hit"
  export FRANKEN_SNOWFLAKE_SELFTEST_PAT="sfpat_planted_canary_do_not_leak_0123456789"
  printf 'leak: %s\n' "$FRANKEN_SNOWFLAKE_SELFTEST_PAT" >"$RUN_DIR/planted.txt"
  if secret_scan FRANKEN_SNOWFLAKE_SELFTEST; then
    log "selftest FAILED: the scanner did not catch the planted canary"
    exit 1
  fi
  rm -f "$RUN_DIR/planted.txt"
  HARD_FAILURES=0
  if secret_scan FRANKEN_SNOWFLAKE_SELFTEST; then
    log "selftest PASSED: gate, runner, and canary scanner behave; events at $EVENTS"
    exit 0
  fi
  log "selftest FAILED: the scanner reported a leak after the canary was removed"
  exit 1
fi

# ---------------------------------------------------------------- live battery
PROFILE="$FRANKEN_SNOWFLAKE_LIVE_PROFILE"
PREFIX=$(profile_prefix "$PROFILE")
DATABASE=$(printenv "${PREFIX}_DATABASE" 2>/dev/null || true)
SCHEMA=$(printenv "${PREFIX}_SCHEMA" 2>/dev/null || true)
SMALL_SQL=$(printenv "${PREFIX}_SMALL_SQL" 2>/dev/null || true)
[ -n "$SMALL_SQL" ] || SMALL_SQL='SELECT 1 AS FSNOW_LIVE_PROOF'
PARTITION_SQL=$(printenv "${PREFIX}_PARTITION_SQL" 2>/dev/null || true)
[ -n "$PARTITION_SQL" ] || PARTITION_SQL='SELECT SEQ4() AS N FROM TABLE(GENERATOR(ROWCOUNT => 50000))'

BIN=$(resolve_bin)
export FRANKEN_SNOWFLAKE_DATA_DIR="$RUN_DIR/data"
log "profile=$PROFILE artifacts=$RUN_DIR bin=$BIN"
event credential_gate pass 0 0 "opted in for profile $PROFILE (handle names only; values never logged)"

run_step profile_validate hard '.ok == true' -- profile validate "$PROFILE" --json
run_step profile_doctor_online hard '.ok == true and .data_source == "live" and (.receipt_hash | length) == 64' -- profile doctor "$PROFILE" --online --json

run_step query_run_small hard '.ok == true and .data_source == "live" and .data.row_count >= 1 and (.receipt_hash | length) == 64' -- query run --profile "$PROFILE" --sql "$SMALL_SQL" --limit 5 --json
RECEIPT=$(field query_run_small '.receipt_hash')
HANDLE=$(field query_run_small '.statement_handle')
if [ -n "$RECEIPT" ] && [ "$RECEIPT" != "null" ]; then
  run_step receipt_show hard ".ok == true and .data_source == \"cache\" and (tostring | contains(\"$HANDLE\"))" -- receipt show "$RECEIPT" --json
fi

# The row cap must stop the fetch early on a partitioned result. A trial account
# that returns one partition is a finding (set <PREFIX>_PARTITION_SQL larger),
# not a failure.
run_step query_run_partitioned hard '.ok == true and .data.returned_rows == 10 and .data.truncated == true' -- query run --profile "$PROFILE" --sql "$PARTITION_SQL" --limit 10 --json
run_step partition_early_stop soft '.data.partition_count > 1 and .data.partitions_fetched < .data.partition_count' -- query run --profile "$PROFILE" --sql "$PARTITION_SQL" --limit 10 --json

if [ -n "$HANDLE" ] && [ "$HANDLE" != "null" ]; then
  # The statement is already complete; Snowflake answers the cancel endpoint
  # with a typed result either way. The assertion is "well-formed typed
  # envelope from the cancel route", never "cancel succeeded".
  run_step query_cancel_completed_handle soft '(.ok | type) == "boolean" and .command_id == "query.cancel"' -- query cancel "$HANDLE" --profile "$PROFILE" --json
fi

if [ -n "$DATABASE" ] && [ -n "$SCHEMA" ]; then
  run_step catalog_scan hard '.ok == true and .data_source == "live" and (.receipt_hash | length) == 64' -- catalog scan "$PROFILE" --database "$DATABASE" --schema "$SCHEMA" --json
  DATASET=$(field catalog_scan '.data.datasets[0].dataset_id // empty')
  run_step catalog_graph_mermaid hard 'true' -- catalog graph "$PROFILE" --database "$DATABASE" --schema "$SCHEMA" --json
  if [ -n "$DATASET" ]; then
    run_step dataset_inspect hard '.ok == true and .data_source == "cache"' -- dataset inspect "$DATASET" --json
    run_step query_plan_dataset hard '.ok == true and (.data.sql | length) > 0' -- query plan --dataset "$DATASET" --limit 5 --json
    run_step query_run_dataset hard '.ok == true and .data_source == "live" and (.receipt_hash | length) == 64' -- query run --dataset "$DATASET" --limit 5 --json
    run_step dataset_profile_execute hard '.ok == true and .data_source == "live"' -- dataset profile "$DATASET" --execute --json
  else
    event dataset_lanes skip 0 0 "catalog scan found no datasets in $DATABASE.$SCHEMA; dataset lanes not exercised"
    SOFT_FINDINGS=$((SOFT_FINDINGS + 1))
  fi
else
  event catalog_lanes skip 0 0 "${PREFIX}_DATABASE / ${PREFIX}_SCHEMA not set; catalog and dataset lanes not exercised"
  SOFT_FINDINGS=$((SOFT_FINDINGS + 1))
fi

run_step export_plan hard '.ok == true and (tostring | contains("COPY INTO"))' -- export plan --profile "$PROFILE" --sql "$SMALL_SQL" --location "@~/fsnow_live_proof/$STAMP" --format csv --json
run_step export_run_csv hard '.ok == true and .data_source == "live"' -- export run --profile "$PROFILE" --sql "$SMALL_SQL" --format csv --out "$RUN_DIR/export.csv" --json
if [ -s "$RUN_DIR/export.csv" ]; then
  event export_file pass 0 0 "export.csv written ($(wc -l <"$RUN_DIR/export.csv") lines)"
else
  HARD_FAILURES=$((HARD_FAILURES + 1))
  event export_file fail 0 0 "export.csv missing or empty"
fi

secret_scan "$PREFIX" || true

# ---------------------------------------------------------------- summary
jq -s '{schema:"franken_snowflake.live_proof_cli.summary.v1",profile:$profile,run_dir:$dir,
        passed:(map(select(.status=="pass"))|length),failed:(map(select(.status=="fail"))|length),
        findings:(map(select(.status=="finding"))|length),skipped:(map(select(.status=="skip"))|length),
        steps:map({step,status,exit,ms})}' --arg profile "$PROFILE" --arg dir "$RUN_DIR" "$EVENTS" >"$RUN_DIR/summary.json"
log "summary: $(jq -c '{passed,failed,findings,skipped}' "$RUN_DIR/summary.json") -> $RUN_DIR/summary.json"
if [ "$HARD_FAILURES" -gt 0 ]; then
  exit 1
fi
exit 0
