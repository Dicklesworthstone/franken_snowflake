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
elif [ -x "${CARGO_TARGET_DIR:-target}/release/franken-snowflake" ]; then
  BIN="${CARGO_TARGET_DIR:-target}/release/franken-snowflake"
elif [ -x "${CARGO_TARGET_DIR:-target}/debug/franken-snowflake" ]; then
  BIN="${CARGO_TARGET_DIR:-target}/debug/franken-snowflake"
elif [ -x "target/release/franken-snowflake" ]; then
  BIN="target/release/franken-snowflake"
elif [ -x "target/debug/franken-snowflake" ]; then
  BIN="target/debug/franken-snowflake"
else
  echo "building the live binary (set FSNOW_BIN to skip this build)..."
  FSNOW_BUILD_SHA="$(git rev-parse HEAD 2>/dev/null)" \
    cargo build --release -p franken-snowflake-cli --features live --bin franken-snowflake || exit 1
  BIN="target/release/franken-snowflake"
fi

# --- binary identity (reality-check bead H1) --------------------------------
# A reused binary must be built from this tree: its self-reported
# build.source_digest (same recipe as crates/franken-snowflake-cli/build.rs)
# must equal the tree's. FSNOW_ALLOW_STALE_BIN=1 captures with a mismatched one
# and records that.
HASHER=sha256sum
command -v sha256sum >/dev/null 2>&1 || HASHER="shasum -a 256"
# $HASHER is split on purpose ("shasum -a 256").
TREE_DIGEST=$({ find crates -type f \( -name '*.rs' -o -name Cargo.toml \) -not -path '*/target/*'; echo Cargo.toml; echo Cargo.lock; } \
  | LC_ALL=C sort | xargs $HASHER | $HASHER | cut -d' ' -f1)
"$BIN" capabilities --with-exe-hash --json >"$ARTIFACTS/binary-identity.json" 2>/dev/null
BIN_DIGEST=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["data"]["build"]["source_digest"])' \
  "$ARTIFACTS/binary-identity.json" 2>/dev/null || echo unknown)
if [ "$BIN_DIGEST" != "$TREE_DIGEST" ] || [ "$BIN_DIGEST" = unknown ]; then
  if [ "${FSNOW_ALLOW_STALE_BIN:-0}" != 1 ]; then
    emit refused ",\"reason\":\"binary sources $BIN_DIGEST differ from the tree $TREE_DIGEST\""
    echo "refusing: $BIN was not built from these sources (rebuild it, or set FSNOW_ALLOW_STALE_BIN=1)"
    exit 1
  fi
  emit stale_binary ",\"bin_digest\":\"$BIN_DIGEST\",\"tree_digest\":\"$TREE_DIGEST\""
fi

export FRANKEN_SNOWFLAKE_DATA_DIR="${FRANKEN_SNOWFLAKE_DATA_DIR:-$ARTIFACTS/data}"
mkdir -p "$FRANKEN_SNOWFLAKE_DATA_DIR"

# --- the all-types capture statement ---------------------------------------
# Known instants; one row; every documented wire type. A quoted heredoc keeps
# the SQL verbatim (inside a double-quoted string bash strips the JSON's
# quotes). String casts rather than TIMESTAMP_NTZ'...' literals (only DATE,
# TIME and TIMESTAMP literals are documented); DECFLOAT from a string (the
# numeric-types page: numeric literals are cast through NUMBER/FLOAT first);
# TO_BINARY for a BINARY column (HEX_ENCODE returns a string). The CLI pins
# TIMEZONE=UTC in every request, so TIMESTAMP_LTZ cells are UTC instants, and
# pins no DATE/TIME/TIMESTAMP output format, so cells keep the default
# encoding. Docs consulted 2026-09-27: sql-reference/data-types-datetime,
# data-types-numeric, functions/hex_encode, functions/to_binary.
SQL=$(cat <<'SQL_EOF'
SELECT
  12345::NUMBER(38,0) AS num_int,
  99999999999999999999::NUMBER(38,0) AS num_beyond_i64,
  123.45::NUMBER(10,2) AS num_scale,
  -0.000001::NUMBER(38,9) AS num_negative_scale,
  1.5::FLOAT AS float_val,
  'NaN'::FLOAT AS float_nan,
  '1.5'::DECFLOAT AS decfloat_val,
  TRUE AS bool_true,
  FALSE AS bool_false,
  '2026-09-04'::DATE AS date_val,
  '1969-12-31'::DATE AS date_pre_epoch,
  '12:34:56.123456'::TIME AS time_val,
  '2026-09-04 12:34:56.123456789'::TIMESTAMP_NTZ AS ts_ntz,
  '1969-12-31 23:59:59.5'::TIMESTAMP_NTZ AS ts_ntz_pre_epoch,
  '2026-09-04 12:34:56.123456789 +05:30'::TIMESTAMP_TZ AS ts_tz,
  '2026-09-04 12:34:56.123456789'::TIMESTAMP_LTZ AS ts_ltz,
  TO_BINARY('676F6C64656E', 'HEX') AS binary_val,
  PARSE_JSON('{"k":[1,{"nested":true}],"s":"v"}') AS variant_val,
  OBJECT_CONSTRUCT('k', 1) AS object_val,
  ARRAY_CONSTRUCT(1, 'two') AS array_val,
  NULL AS null_val,
  'text'::VARCHAR AS varchar_val
SQL_EOF
)

echo "capturing the all-types wire encoding through the live binary..."
# --raw-cells: rows default to typed.v1 (decoded by the codec under test);
# the golden must hold the strings Snowflake sent.
if ! "$BIN" query run --profile "$PROFILE" --sql "$SQL" --raw-cells --json \
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
if data.get("row_encoding") != "jsonv2.wire":
    print("FAIL: rows are not wire strings (row_encoding=%r)" % data.get("row_encoding"))
    sys.exit(1)
golden = {
    "schema": "franken_snowflake.jsonv2_wire_golden.v1",
    "captured_via": "cli query run (cells are literal wire strings)",
    "columns": data["columns"],
    "rows": data["rows"],
    "session_tz": "UTC (pinned in the request by the CLI)",
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
echo "next: diff $ARTIFACTS/jsonv2-wire-golden.json against the kx6 fixtures, commit $PINNED, and run the frame jsonv2_golden test (--features frankenpandas) and the core typed test a_checked_in_live_capture_types_every_column (bead w0i.13)." 
