#!/usr/bin/env bash
# Lint every feature lane, not just the default graph.
#
# The workspace clippy gate compiles each crate with its default features, so
# code behind an optional feature (and the tests that come with it) can carry
# lint failures for months. This gate runs `cargo clippy --all-targets
# -D warnings` for every lane below and then checks, from `cargo metadata`,
# that every (package, feature) pair in the workspace is covered by at least
# one lane, so adding a feature without a lane fails here instead of nowhere.
#
# Usage: scripts/check-feature-lanes.sh [--list]
# Exit: 0 all lanes clean and every feature covered; 1 otherwise.
set -u
cd "$(dirname "$0")/.."

# lane spec: "<package-or-workspace>|<features-or-empty>"
LANES=(
  "--workspace|"
  "-p franken-snowflake-cli|live,mcp,tui"
  "-p franken-snowflake-cli|live"
  "-p franken-snowflake-cli|mcp"
  "-p franken-snowflake-cli|tui"
  "-p franken-snowflake-cli|toon"
  "-p franken-snowflake-mcp|mcp"
  "-p franken-snowflake-tui|tui"
  "-p franken-snowflake-frame|frankenpandas"
  "-p franken-snowflake-text-indexing|frankensearch"
  "-p franken-snowflake-export|export"
  "-p franken-snowflake-graph|graph"
  "-p franken-snowflake-http|compression"
  "-p franken-snowflake-core|adapter-fixtures"
  "-p franken-snowflake-cache|frankensqlite"
)

if [ "${1:-}" = "--list" ]; then
  printf '%s\n' "${LANES[@]}"
  exit 0
fi

failures=0
emit() { printf '{"gate":"feature-lanes","event":"%s",%s}\n' "$1" "$2"; }

for lane in "${LANES[@]}"; do
  scope="${lane%%|*}"
  features="${lane#*|}"
  if [ "$features" = "frankensqlite" ] && [ "$(uname -s)" != "Linux" ] && [ "$(uname -s)" != "Darwin" ]; then
    emit lane_skipped "\"scope\":\"$scope\",\"features\":\"$features\",\"reason\":\"fsqlite is Unix-only\""
    continue
  fi
  # shellcheck disable=SC2086
  if [ -n "$features" ]; then
    cargo clippy $scope --features "$features" --all-targets --locked -- -D warnings >/dev/null 2>"/tmp/fsnow-lane-$$.err"
  else
    cargo clippy $scope --all-targets --locked -- -D warnings >/dev/null 2>"/tmp/fsnow-lane-$$.err"
  fi
  rc=$?
  if [ "$rc" -eq 0 ]; then
    emit lane_clean "\"scope\":\"$scope\",\"features\":\"$features\""
  else
    failures=$((failures + 1))
    emit lane_failed "\"scope\":\"$scope\",\"features\":\"$features\",\"exit\":$rc"
    grep -E '^(error|warning)' "/tmp/fsnow-lane-$$.err" | head -5 | sed 's/^/  /' >&2
  fi
  rm -f "/tmp/fsnow-lane-$$.err"
done

# Coverage: every declared feature of every workspace package must appear in
# some lane (default and pure-dependency toggles excluded).
missing=()
while IFS=$'\t' read -r package feature; do
  covered=0
  for lane in "${LANES[@]}"; do
    scope="${lane%%|*}"
    features="${lane#*|}"
    if [ "$scope" = "-p $package" ] && [[ ",$features," == *",$feature,"* ]]; then
      covered=1
      break
    fi
  done
  [ "$covered" -eq 1 ] || missing+=("$package:$feature")
done < <(cargo metadata --no-deps --locked --format-version 1 2>/dev/null \
  | jq -r '.packages[] | .name as $n | (.features | keys[]) | select(. != "default") | "\($n)\t\(.)"')

if [ "${#missing[@]}" -gt 0 ]; then
  failures=$((failures + 1))
  emit coverage_gap "\"uncovered\":$(printf '%s\n' "${missing[@]}" | jq -R . | jq -sc .)"
else
  emit coverage_ok "\"lanes\":${#LANES[@]}"
fi

if [ "$failures" -gt 0 ]; then
  emit failure "\"failures\":$failures"
  exit 1
fi
emit success "\"lanes\":${#LANES[@]}"
