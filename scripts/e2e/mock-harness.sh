#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

: "${CARGO_TARGET_DIR:=/data/tmp/fsnow_targets/pane7}"
: "${FSNOW_E2E_ARTIFACTS_DIR:=$ROOT/target/fsnow-e2e-artifacts}"
export CARGO_TARGET_DIR
export FSNOW_E2E_ARTIFACTS_DIR

cargo test -p franken-snowflake-testkit --test e2e_harness -- "$@"
