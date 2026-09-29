#!/usr/bin/env bash
# Public-safety scan for private tokens (reality-check bead A3).
#
# This repository is public: it must not contain private downstream product
# names, real account locators, or other non-public identifiers. The tokens to
# look for are themselves private, so they are read from a denylist file that
# lives OUTSIDE the repository (one literal token per line, matched
# case-insensitively); this script never prints a token, only file:count.
#
# Usage:
#   FSNOW_PRIVATE_DENYLIST=/path/outside/repo/denylist.txt scripts/check-public-safety.sh
#   FSNOW_PRIVATE_DENYLIST=... scripts/check-public-safety.sh --selftest
#
# Exit: 0 clean; 1 a token was found (or the selftest's planted token was
# missed); 2 the denylist is missing, empty, or inside the repository.
set -u

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
LIST="${FSNOW_PRIVATE_DENYLIST:-}"

refuse() { printf '[public-safety] %s\n' "$*" >&2; exit 2; }

command -v rg >/dev/null 2>&1 || refuse "ripgrep (rg) is required"
[ -n "$LIST" ] || refuse "set FSNOW_PRIVATE_DENYLIST to a denylist file outside the repository; without it private names cannot be checked"
[ -f "$LIST" ] || refuse "denylist $LIST does not exist"
LIST=$(cd "$(dirname "$LIST")" && pwd)/$(basename "$LIST")
case "$LIST" in
  "$REPO_ROOT"/*) refuse "the denylist must live outside the repository (committing it would publish the names)" ;;
esac
TOKENS=$(grep -cv '^[[:space:]]*$' "$LIST")
[ "$TOKENS" -gt 0 ] || refuse "denylist $LIST has no tokens"

if [ "${1:-}" = "--selftest" ]; then
  # Teeth: the first token, planted on stdin, must be found.
  first=$(grep -v '^[[:space:]]*$' "$LIST" | head -n 1)
  if printf 'planted: x%sx\n' "$first" | rg -q -i -F -f "$LIST" -; then
    printf '[public-safety] selftest PASSED: a planted denylisted token is detected\n' >&2
    exit 0
  fi
  printf '[public-safety] selftest FAILED: the planted token was not detected\n' >&2
  exit 1
fi

# The whole tree, including the Beads export, excluding git history and builds.
# (Git history is not rewritten here; see the A3 bead close comment.)
hits=$(cd "$REPO_ROOT" && rg -c -i -F -f "$LIST" --hidden -g '!.git' -g '!target' . || true)
if [ -n "$hits" ]; then
  printf '[public-safety] FAIL: denylisted tokens found (file:count; tokens not shown):\n%s\n' "$hits" >&2
  exit 1
fi
printf '[public-safety] PASS: %s denylisted token(s), 0 hits in the tree and .beads\n' "$TOKENS" >&2
