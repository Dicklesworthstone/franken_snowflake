#!/usr/bin/env sh
set -eu

: "${CARGO_TARGET_DIR:=target}"
export CARGO_TARGET_DIR

cargo test -p franken-snowflake-sqlapi --test live_proof -- --nocapture
