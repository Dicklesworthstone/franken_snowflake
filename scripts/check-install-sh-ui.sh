#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALLER="$ROOT/install.sh"
PS_INSTALLER="$ROOT/install.ps1"

bash -n "$INSTALLER"

python3 - "$INSTALLER" "$PS_INSTALLER" <<'PY'
import sys
import re
from pathlib import Path

path = Path(sys.argv[1])
ps_path = Path(sys.argv[2])
terminator = re.compile(r"(^|[\s\\])--($|[\s\\])")
commands = []
buf = []
for line in path.read_text(encoding="utf-8").splitlines():
    buf.append(line)
    if line.rstrip().endswith("\\"):
        continue
    commands.append("\n".join(buf))
    buf = []
if buf:
    commands.append("\n".join(buf))

missing = []
for command in commands:
    if "gum style" not in command:
        continue
    parts = command.split("gum style")
    for index, tail in enumerate(parts[1:], start=1):
        segment = tail.split("gum style", 1)[0]
        if not terminator.search(segment):
            first_line = command.splitlines()[0]
            missing.append(first_line)

if missing:
    print("gum style calls must pass -- before text arguments:", file=sys.stderr)
    for line in missing:
        print(f"  {line}", file=sys.stderr)
    sys.exit(1)

shell_text = path.read_text(encoding="utf-8")
ps_text = ps_path.read_text(encoding="utf-8")

forbidden = [
    "falls back to BUILD-FROM-SOURCE",
    "falling back to build-from-source",
    "All artifact downloads failed",
    "Versionless artifact failed",
    "trying latest/download",
    "No releases yet",
]
violations = []
for needle in forbidden:
    if needle in shell_text:
        violations.append(f"install.sh contains forbidden automatic fallback text: {needle}")
    if needle in ps_text:
        violations.append(f"install.ps1 contains forbidden automatic fallback text: {needle}")

required_shell = [
    'TAR="${BINARY_NAME}-v${VERSION_BARE}-${TARGET}.${EXT}"',
    'TARGET="x86_64-unknown-linux-gnu"',
    'TARGET="aarch64-unknown-linux-gnu"',
    'This installer will not build from source automatically.',
]
for needle in required_shell:
    if needle not in shell_text:
        violations.append(f"install.sh missing required release-binary policy text: {needle}")

required_ps = [
    '$tar = "$BinaryName-v$($script:VersionBare)-$target.$ext"',
    'This installer will not build from source automatically.',
    '$script:FromSourceEffective = [bool]$FromSource',
]
for needle in required_ps:
    if needle not in ps_text:
        violations.append(f"install.ps1 missing required release-binary policy text: {needle}")

if re.search(r"NO_RELEASE[^\\n]*&&[^\\n]*FROM_SOURCE=1|FROM_SOURCE=1[^\\n]*NO_RELEASE", shell_text):
    violations.append("install.sh appears to convert missing releases into source builds")

if violations:
    print("installer release-binary policy checks failed:", file=sys.stderr)
    for violation in violations:
        print(f"  {violation}", file=sys.stderr)
    sys.exit(1)
PY

gum() {
subcommand="${1:-}"
shift || true

case "$subcommand" in
  style)
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --)
          shift
          printf '%s\n' "$*"
          return 0
          ;;
        --foreground|--background|--border|--border-background|--border-foreground|--align|--height|--width|--margin|--padding)
          shift
          [ "$#" -gt 0 ] && shift
          ;;
        --bold|--faint|--italic|--strikethrough|--underline|--trim|--strip-ansi|--no-strip-ansi)
          shift
          ;;
        -*)
          printf 'fake gum: unknown flag %s\n' "$1" >&2
          return 80
          ;;
        *)
          shift
          ;;
      esac
    done
    ;;
  spin)
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--" ]; then
        shift
        exec "$@"
      fi
      shift
    done
    ;;
esac
}

# shellcheck disable=SC1090
source <(awk '
  /^# ── Colors / { copy = 1 }
  /^# Strip ANSI / { copy = 0 }
  copy { print }
' "$INSTALLER")

# shellcheck disable=SC2034
HAS_GUM=1
# shellcheck disable=SC2034
NO_GUM=0
# shellcheck disable=SC2034
QUIET=0
info "Resolving latest version..."
ok "Installed alias /tmp/fsnow"
err "Release artifact not found or download failed: franken-snowflake-v0.0.0-x86_64-unknown-linux-gnu.tar.gz"
err "cargo build failed."

gum style \
  --border rounded --border-foreground 39 \
  --padding "0 2" --margin "1 0" \
  -- \
  "$(gum style --foreground 42 --bold -- 'franken-snowflake installer')" \
  "$(gum style --foreground 245 -- 'Clean-room, Asupersync-native Snowflake SQL API CLI for agents')" \
  >/dev/null

DEST="/tmp/fsnow-dash-test"
BINARY_NAME="franken-snowflake"
ALIAS_NAME="fsnow"
VERSION="0.0.0"
mode="source build"
gum style \
  --border rounded --border-foreground 42 --padding "0 2" --margin "0" \
  -- \
  "$(gum style --foreground 42 --bold -- 'Installation complete')" \
  "" \
  "$(gum style --foreground 245 -- "Binary:  $(gum style --bold -- "$DEST/$BINARY_NAME")")" \
  "$(gum style --foreground 245 -- "Alias:   $(gum style --bold -- "$DEST/$ALIAS_NAME")")" \
  "$(gum style --foreground 245 -- "Version: $(gum style --bold -- "$VERSION") ($mode)")" \
  "" \
  "$(gum style --foreground 39 --bold -- 'Quick start:')" \
  "$(gum style --foreground 245 -- '  franken-snowflake capabilities --json    # self-describing capability list')" \
  "$(gum style --foreground 245 -- '  franken-snowflake agent-handbook         # embedded handbook')" \
  "$(gum style --foreground 245 -- '  fsnow doctor --json                      # environment diagnostics')" \
  "$(gum style --foreground 245 -- '  franken-snowflake mcp serve --stdio      # serve over MCP')" \
  "" \
      "$(gum style --foreground 214 -- 'Release binaries include the published live/MCP feature set; credentials are still runtime-gated.')" \
      "" \
  "$(gum style --foreground 245 -- "Uninstall:  rm -f $DEST/$BINARY_NAME $DEST/$ALIAS_NAME")" \
  >/dev/null

echo "install.sh UI checks passed"
