#!/usr/bin/env bash
# Capture an empirical golden of the Snowflake SQL API jsonv2 result-data
# encoding (bead fsnow-native-snowflake-connector-w0i.13). Runs ONE SELECT
# covering every wire type at known instants through the live-capable binary
# and saves the envelope — whose `data.rows` cells are the literal wire
# strings and whose `data.columns` mirror the response rowType — into the
# artifact directory for diffing against the kx6 protocol fixtures and the
# frame wire codec.
#
# Opt-in (typed skip otherwise; no credentials resolved without it):
#   export FRANKEN_SNOWFLAKE_LIVE=1
#   export FRANKEN_SNOWFLAKE_LIVE_PROFILE=<profile>   # e.g. trial
#   <profile handles: _ACCOUNT/_USER/_AUTH/_WAREHOUSE + lane secret>
# Optional:
#   FSNOW_BIN=/path/to/franken-snowflake   # else builds --features live
#   FRANKEN_SNOWFLAKE_LIVE_ARTIFACTS_DIR   # else target/fsnow-jsonv2-golden
#
# Docs consulted 2026-06-24: docs.snowflake.com/en/developer-guide/sql-api/handling-responses
# The official docs are internally inconsistent on timestamp units (one
# passage says nanoseconds; the per-type table implies fractional epoch
# seconds) — this capture exists to settle that empirically.

set -u
cd "$(dirname "$0")/.."

emit() { printf '{"gate":"jsonv2-golden","event":"%s"%s}\n' "$1" "${2:-}"; }

ARTIFACTS="${FRANKEN_SNOWFLAKE_LIVE_ARTIFACTS_DIR:-${CARGO_TARGET_DIR:-target}/fsnow-jsonv2-golden}"
mkdir -p "$ARTIFACTS"

# --- gate (names only; secret values are never read here) -------------------
if [ "${FRANKEN_SNOWFLAKE_LIVE:-}" != "1" ]; then
  emit skip ',"reason":"FRANKEN_SNOWFLAKE_LIVE!=1"'
  echo "skip: set FRANKEN_SNOWFLAKE_LIVE=1 and the profile handles to capture the jsonv2 golden"
  exit 0
fi
PROFILE="${FRANKEN_SNOWFLAKE_LIVE_PROFILE:-}"
if [ -z "$PROFILE" ]; then
  emit skip ',"reason":"FRANKEN_SNOWFLAKE_LIVE_PROFILE missing"'
  echo "skip: set FRANKEN_SNOWFLAKE_LIVE_PROFILE=<profile>"
  exit 0
fi
PREFIX="FRANKEN_SNOWFLAKE_$(printf '%s' "$PROFILE" | tr '[:lower:]-.' '[:upper:]__')"
missing=0
for suffix in ACCOUNT USER AUTH WAREHOUSE; do
  name="${PREFIX}_${suffix}"
  if [ -z "${!name:-}" ]; then
    emit skip ",\"reason\":\"${name} missing\""
    missing=1
  fi
done
if [ "$missing" != 0 ]; then
  echo "skip: set the $PREFIX handles first"
  exit 0
fi

# --- binary -----------------------------------------------------------------
if [ -n "${FSNOW_BIN:-}" ]; then
  BIN="$FSNOW_BIN"
else
  echo "building the live binary (set FSNOW_BIN to skip this build)..."
  cargo build --release -p franken-snowflake-cli --features live --bin franken-snowflake || exit 1
  BIN="target/release/franken-snowflake"
fi

export FRANKEN_SNOWFLAKE_DATA_DIR="${FRANKEN_SNOWFLAKE_DATA_DIR:-$ARTIFACTS/data}"
mkdir -p "$FRANKEN_SNOWFLAKE_DATA_DIR"

# --- the all-types capture statement ---------------------------------------
# Known instants; one row; every documented wire type. CURRENT_SETTING keeps
# the session timezone in the capture so TIMESTAMP_LTZ strings are interpretable.
SQL="SELECT
  12345::NUMBER(38,0) AS num_int,
  123.45::NUMBER(10,2) AS num_scale,
  -0.000001::NUMBER(38,9) AS num_negative_scale,
  1.5::FLOAT AS float_val,
  1.5::DECFLOAT AS decfloat_val,
  TRUE AS bool_true,
  FALSE AS bool_false,
  DATE'2026-09-04' AS date_val,
  TIME'12:34:56.123456' AS time_val,
  TIMESTAMP_NTZ'2026-09-04 12:34:56.123456789' AS ts_ntz,
  TIMESTAMP_TZ'2026-09-04 12:34:56.123456789 +05:30' AS ts_tz,
  TIMESTAMP_LTZ'2026-09-04 12:34:56.123456789' AS ts_ltz,
  HEX_ENCODE('golden') AS binary_val,
  PARSE_JSON('{"k":[1,{"nested":true}],"s":"v"}') AS variant_val,
  ARRAY_CONSTRUCT_COMPACT(1, NULL, 'two')::VARIANT AS array_val,
  NULL AS null_val,
  CURRENT_SETTING('TIMEZONE') AS session_tz,
  'text'::VARCHAR AS varchar_val"

echo "capturing the all-types wire encoding through the live binary..."
if ! "$BIN" query run --profile "$PROFILE" --sql "$SQL" --json \
    > "$ARTIFACTS/all-types-envelope.json" 2> "$ARTIFACTS/all-types-stderr.txt"; then
  emit fail ',"stage":"query_run"'
  echo "FAIL: query run exited nonzero - see $ARTIFACTS/all-types-envelope.json"
  exit 1
fi

python3 - "$ARTIFACTS/all-types-envelope.json" "$ARTIFACTS" <<'PYEOF'
import json, sys
envelope = json.load(open(sys.argv[1]))
if not envelope.get("ok") or envelope.get("data_source") != "live":
    print("FAIL: envelope is not a live success:", envelope.get("error"))
    sys.exit(1)
data = envelope["data"]
tz_index = next((i for i, c in enumerate(data["columns"]) if c["name"] == "SESSION_TZ"), None)
golden = {
    "schema": "franken_snowflake.jsonv2_wire_golden.v1",
    "captured_via": "cli query run (cells are literal wire strings)",
    "columns": data["columns"],
    "rows": data["rows"],
    "session_tz": data["rows"][0][tz_index] if tz_index is not None and data["rows"] else None,
}
with open(sys.argv[2] + "/jsonv2-wire-golden.json", "w") as f:
    json.dump(golden, f, indent=1)
    f.write("\n")
print("golden written: %d columns, %d row(s)" % (len(data["columns"]), len(data["rows"])))
for c in data["columns"]:
    print("  %-24s %s" % (c["name"], c["type"]))
PYEOF
emit pass ',"stage":"captured"'
# Pin the captured golden into the frame crate so the codec-validation test
# (crates/franken-snowflake-frame/tests/jsonv2_golden.rs) runs it in every
# environment. Commit the copied file.
PINNED="crates/franken-snowflake-frame/tests/captured/jsonv2-wire-golden.json"
mkdir -p "$(dirname "$PINNED")"
cp "$ARTIFACTS/jsonv2-wire-golden.json" "$PINNED"
echo "next: diff $ARTIFACTS/jsonv2-wire-golden.json against the kx6 fixtures, commit $PINNED, and run the frame jsonv2_golden test (bead w0i.13)." 
