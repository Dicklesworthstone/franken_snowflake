#!/usr/bin/env sh
set -eu

: "${CARGO_TARGET_DIR:=target}"
export CARGO_TARGET_DIR

cargo test -p franken-snowflake-sqlapi --test live_proof -- --nocapture

# The CLI battery over the wired surfaces (opt-in; typed skip otherwise).
exec "$(dirname "$0")/live-proof-cli.sh"
