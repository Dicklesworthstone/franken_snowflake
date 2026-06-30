#!/usr/bin/env bash
#
# franken-snowflake installer  (binaries: franken-snowflake + short alias fsnow)
#
# A clean-room, Asupersync-native Snowflake SQL API connector built for coding
# agents. This installs the agent-ergonomic CLI tool (not the library).
#
# One-liner install:
#   curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/franken_snowflake/main/install.sh | bash
#
# With cache buster (bypass CDN/proxy caches):
#   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/franken_snowflake/main/install.sh?$(date +%s)" | bash
#
# Options:
#   --version vX.Y.Z   Install a specific released version (default: latest)
#   --dest DIR         Install into DIR (default: ~/.local/bin)
#   --system           Install into /usr/local/bin (uses sudo)
#   --easy-mode        Auto-update PATH in shell rc files
#   --verify           Run a post-install self-test (selftest + capabilities)
#   --from-source      Developer-only: build from source with cargo instead of
#                      downloading a prepared release binary
#   --live             Build the CLI with the `live` feature (real Snowflake SQL API
#                      transport). Applies to every from-source build path.
#   --offline TARBALL  Install from a local artifact tarball (airgapped, no network)
#   --artifact-url URL Download the artifact from an explicit URL
#   --checksum HEX     Expected SHA256 of the artifact (overrides remote SHA256SUMS)
#   --checksum-url URL URL of a SHA256SUMS file to verify against
#   --no-verify        Skip checksum verification (NOT recommended)
#   --quiet, -q        Suppress non-error output
#   --no-gum           Disable gum formatting even if gum is installed
#   --force            Reinstall even if the same version is already present
#   -h, --help         Show help and exit
#
# Release binaries:
#   The normal installer path downloads prepared GitHub release archives named:
#       franken-snowflake-vX.Y.Z-<target-triple>.tar.gz
#   This installer never builds from source automatically. If no release or no
#   matching platform archive exists, it fails with the exact missing asset.
#   --from-source is an explicit developer escape hatch only.
#
# Optional MCP surface:
#   The installed binary can also serve Model Context Protocol so every read
#   verb becomes a callable tool:  franken-snowflake mcp serve --stdio
#
set -euo pipefail
umask 022
shopt -s lastpipe 2>/dev/null || true

# ── Defaults / configuration ────────────────────────────────────────────────
OWNER="${OWNER:-Dicklesworthstone}"
REPO="${REPO:-franken_snowflake}"
BINARY_NAME="franken-snowflake"        # canonical binary
ALIAS_NAME="fsnow"                     # short agent-ergonomic alias
CLI_PACKAGE="franken-snowflake-cli"    # cargo -p package that builds both bins

VERSION="${VERSION:-}"
DEST_DEFAULT="$HOME/.local/bin"
DEST="${DEST:-$DEST_DEFAULT}"
SYSTEM=0
EASY=0
QUIET=0
VERIFY=0
FROM_SOURCE=0
LIVE=0
NO_GUM=0
FORCE_INSTALL=0
NO_VERIFY=0
OFFLINE_TARBALL=""
ARTIFACT_URL="${ARTIFACT_URL:-}"
CHECKSUM="${CHECKSUM:-}"
CHECKSUM_URL="${CHECKSUM_URL:-}"
LOCK_FILE="/tmp/franken-snowflake-install.lock"

# Filled in later.
OS=""; ARCH=""; TARGET=""; EXT="tar.gz"
VERSION_BARE=""; TAR=""; URL=""
NO_RELEASE=0            # set when no real release tag could be resolved
LOCAL_CHECKOUT=""       # set when run inside a franken_snowflake source tree
TMP=""; LOCKED=0

# ── Colors ──────────────────────────────────────────────────────────────────
ESC=$'\033'
RESET="${ESC}[0m"
C_BLUE="${ESC}[0;34m"
C_GREEN="${ESC}[0;32m"
C_GREENB="${ESC}[1;32m"
C_YELLOW="${ESC}[1;33m"
C_RED="${ESC}[0;31m"
C_CYAN="${ESC}[1;36m"
C_DIM="${ESC}[2m"

# ── gum detection + output stack ────────────────────────────────────────────
HAS_GUM=0
if command -v gum >/dev/null 2>&1 && [ -t 1 ]; then
  HAS_GUM=1
fi

log() { [ "$QUIET" -eq 1 ] && return 0; echo -e "$@"; }

info() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 39 -- "-> $*"
  else
    echo -e "${C_BLUE}->${RESET} $*"
  fi
}

ok() {
  [ "$QUIET" -eq 1 ] && return 0
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 42 -- "OK $*"
  else
    echo -e "${C_GREEN}OK${RESET} $*"
  fi
}

warn() {
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 214 -- "!  $*"
  else
    echo -e "${C_YELLOW}!${RESET}  $*"
  fi
}

err() {
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style --foreground 196 -- "x  $*"
  else
    echo -e "${C_RED}x${RESET}  $*"
  fi
}

run_with_spinner() {
  local title="$1"; shift
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ] && [ "$QUIET" -eq 0 ]; then
    gum spin --spinner dot --title "$title" -- "$@"
  else
    info "$title"
    "$@"
  fi
}

# Strip ANSI sequences (for box width math).
strip_ansi() { LC_ALL=C sed -E "s/${ESC}\[[0-9;]*m//g"; }

# draw_box COLOR LINE [LINE...] — double-line box with ANSI-aware width.
draw_box() {
  local color="$1"; shift
  local -a lines=("$@")
  local width=0 line plain
  for line in "${lines[@]}"; do
    plain=$(printf '%s' "$line" | strip_ansi)
    [ "${#plain}" -gt "$width" ] && width=${#plain}
  done
  local bar="" i
  for (( i = 0; i < width + 2; i++ )); do bar+="═"; done
  printf '%s╔%s╗%s\n' "$color" "$bar" "$RESET"
  for line in "${lines[@]}"; do
    plain=$(printf '%s' "$line" | strip_ansi)
    local pad=$(( width - ${#plain} ))
    [ "$pad" -lt 0 ] && pad=0
    printf '%s║%s %s%*s %s║%s\n' "$color" "$RESET" "$line" "$pad" "" "$color" "$RESET"
  done
  printf '%s╚%s╝%s\n' "$color" "$bar" "$RESET"
}

prompt_yes() {
  # prompt_yes "Question?" -> returns 0 on y/Y. Non-tty => no.
  local q="$1" ans
  [ -t 0 ] || return 1
  printf '%s (y/N): ' "$q"
  read -r ans || return 1
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ── Proxy support (applied to every curl) ───────────────────────────────────
PROXY_ARGS=()
setup_proxy() {
  if [ -n "${HTTPS_PROXY:-}" ]; then
    PROXY_ARGS=(--proxy "$HTTPS_PROXY")
  elif [ -n "${https_proxy:-}" ]; then
    PROXY_ARGS=(--proxy "$https_proxy")
  elif [ -n "${HTTP_PROXY:-}" ]; then
    PROXY_ARGS=(--proxy "$HTTP_PROXY")
  elif [ -n "${http_proxy:-}" ]; then
    PROXY_ARGS=(--proxy "$http_proxy")
  fi
}

# ── Usage ───────────────────────────────────────────────────────────────────
usage() {
  cat <<EOFU
franken-snowflake installer — installs the agent-ergonomic CLI (binaries:
${BINARY_NAME} + short alias ${ALIAS_NAME}).

Usage: install.sh [OPTIONS]

Options:
  --version vX.Y.Z   Install a specific released version (default: latest)
  --dest DIR         Install into DIR (default: ~/.local/bin)
  --system           Install into /usr/local/bin (uses sudo)
  --easy-mode        Auto-update PATH in shell rc files
  --verify           Run a post-install self-test (selftest + capabilities)
  --from-source      Developer-only: build from source with cargo instead of
                     downloading a prepared release binary
  --live             Build the CLI with the 'live' feature (real Snowflake transport)
  --offline TARBALL  Install from a local artifact tarball (airgapped)
  --artifact-url URL Download the artifact from an explicit URL
  --checksum HEX     Expected SHA256 of the artifact
  --checksum-url URL URL of a SHA256SUMS file to verify against
  --no-verify        Skip checksum verification (not recommended)
  --quiet, -q        Suppress non-error output
  --no-gum           Disable gum formatting even if gum is installed
  --force            Reinstall even if the same version is already present
  -h, --help         Show this help and exit

Notes:
  * The default path requires a prepared GitHub release binary and never falls
    back to cargo. Missing releases or assets are installer errors.
  * --from-source is explicit developer mode. Without --from-source, --live is
    ignored because release binaries are already built with the published
    feature set.
  * MCP server:   ${BINARY_NAME} mcp serve --stdio
EOFU
}

# ── Argument parsing ────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --version)      VERSION="${2:?--version needs a value}"; shift 2 ;;
    --dest)         DEST="${2:?--dest needs a value}"; shift 2 ;;
    --system)       SYSTEM=1; DEST="/usr/local/bin"; shift ;;
    --easy-mode)    EASY=1; shift ;;
    --verify)       VERIFY=1; shift ;;
    --from-source)  FROM_SOURCE=1; shift ;;
    --live)         LIVE=1; shift ;;
    --offline)      OFFLINE_TARBALL="${2:?--offline needs a TARBALL path}"; shift 2 ;;
    --artifact-url) ARTIFACT_URL="${2:?--artifact-url needs a value}"; shift 2 ;;
    --checksum)     CHECKSUM="${2:?--checksum needs a value}"; shift 2 ;;
    --checksum-url) CHECKSUM_URL="${2:?--checksum-url needs a value}"; shift 2 ;;
    --no-verify)    NO_VERIFY=1; shift ;;
    --quiet|-q)     QUIET=1; shift ;;
    --no-gum)       NO_GUM=1; shift ;;
    --force)        FORCE_INSTALL=1; shift ;;
    -h|--help)      usage; exit 0 ;;
    *)              warn "Ignoring unknown option: $1"; shift ;;
  esac
done

setup_proxy

# ── Header ──────────────────────────────────────────────────────────────────
if [ "$QUIET" -eq 0 ]; then
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    gum style \
      --border rounded --border-foreground 39 \
      --padding "0 2" --margin "1 0" \
      -- \
      "$(gum style --foreground 42 --bold -- 'franken-snowflake installer')" \
      "$(gum style --foreground 245 -- 'Clean-room, Asupersync-native Snowflake SQL API CLI for agents')"
  else
    echo ""
    draw_box "$C_CYAN" \
      "${C_GREENB}franken-snowflake installer${RESET}" \
      "${C_DIM}Asupersync-native Snowflake SQL API CLI for coding agents${RESET}" \
      "${C_DIM}binaries: ${BINARY_NAME}  +  ${ALIAS_NAME}${RESET}"
    echo ""
  fi
fi

# ── Platform detection ──────────────────────────────────────────────────────
detect_platform() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  case "$ARCH" in
    x86_64|amd64)  ARCH="x86_64" ;;
    arm64|aarch64) ARCH="aarch64" ;;
    *)
      if [ "$FROM_SOURCE" -eq 1 ] || [ -n "$ARTIFACT_URL" ] || [ -n "$OFFLINE_TARBALL" ]; then
        warn "Unknown architecture '$ARCH'; continuing because an explicit source/artifact path was requested"
      else
        err "Unsupported architecture '$ARCH'. This installer requires a prepared release binary."
        err "Use --from-source only for an explicit developer build."
        exit 1
      fi
      ;;
  esac

  TARGET=""
  case "${OS}-${ARCH}" in
    linux-x86_64)   TARGET="x86_64-unknown-linux-gnu" ;;
    linux-aarch64)  TARGET="aarch64-unknown-linux-gnu" ;;
    darwin-x86_64)  TARGET="x86_64-apple-darwin" ;;
    darwin-aarch64) TARGET="aarch64-apple-darwin" ;;
    *)
      if [ "$FROM_SOURCE" -eq 1 ] || [ -n "$ARTIFACT_URL" ] || [ -n "$OFFLINE_TARBALL" ]; then
        warn "No prepared release target for ${OS}/${ARCH}; continuing because an explicit source/artifact path was requested"
      else
        err "No prepared release target for ${OS}/${ARCH}."
        err "Use install.ps1 on Windows, or --from-source only for an explicit developer build."
        exit 1
      fi
      ;;
  esac

  if [ "$OS" = "linux" ] && grep -qi microsoft /proc/version 2>/dev/null; then
    warn "WSL detected — continuing with the linux build (some features may need extra setup)"
  fi
}

# ── Version resolution (GitHub API -> redirect; source builds may use Cargo.toml) ─
resolve_version() {
  if [ -n "$VERSION" ]; then
    VERSION_BARE="${VERSION#v}"
    VERSION="v${VERSION_BARE}"
    return 0
  fi

  info "Resolving latest version..."
  local tag=""
  local api="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"
  tag=$(curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 15 --max-time 45 \
          -H "Accept: application/vnd.github+json" "$api" 2>/dev/null \
        | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)

  if [ -z "$tag" ]; then
    local redir="https://github.com/${OWNER}/${REPO}/releases/latest"
    local eff
    eff=$(curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 15 --max-time 45 \
            -o /dev/null -w '%{url_effective}' "$redir" 2>/dev/null || true)
    case "$eff" in
      */tag/*) tag="${eff##*/tag/}" ;;
    esac
    [[ "$tag" == *"/"* ]] && tag=""
  fi

  if [ -n "$tag" ] && [[ "$tag" =~ ^v?[0-9] ]]; then
    VERSION="$tag"
    VERSION_BARE="${VERSION#v}"
    info "Resolved latest release: $VERSION"
    return 0
  fi

  # No release tag. Only explicit developer source builds may continue.
  local cb raw cv
  cb=$(date +%s)
  raw="https://raw.githubusercontent.com/${OWNER}/${REPO}/main/Cargo.toml?${cb}"
  cv=$(curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 15 --max-time 45 "$raw" 2>/dev/null \
        | sed -nE 's/^version = "([0-9][^"]*)".*/\1/p' | head -n1 || true)
  if [ "$FROM_SOURCE" -eq 1 ] || [ -n "$ARTIFACT_URL" ] || [ -n "$OFFLINE_TARBALL" ]; then
    VERSION="${cv:-0.0.0}"
    VERSION_BARE="${VERSION#v}"
    NO_RELEASE=1
    warn "No tagged release found upstream; continuing with explicit source/artifact input."
    return 0
  fi

  err "No tagged GitHub release found for ${OWNER}/${REPO}."
  err "This installer requires prepared release binaries and will not build from source automatically."
  err "Use --version vX.Y.Z for a specific release, --artifact-url, --offline, or explicit --from-source for developer builds."
  exit 1
}

# ── Local checkout detection (build in place when possible) ─────────────────
detect_local_checkout() {
  local d="$PWD"
  while [ -n "$d" ] && [ "$d" != "/" ]; do
    if [ -f "$d/crates/${CLI_PACKAGE}/Cargo.toml" ] && [ -f "$d/Cargo.toml" ]; then
      LOCAL_CHECKOUT="$d"
      return 0
    fi
    d=$(dirname "$d")
  done
  return 1
}

# ── Preflight ───────────────────────────────────────────────────────────────
preflight_checks() {
  info "Running preflight checks"

  # Disk space (need a few hundred MB for a source build; >=10MB for a binary).
  local need_kb=20480
  [ "$FROM_SOURCE" -eq 1 ] && need_kb=786432
  local avail_kb
  avail_kb=$(df -Pk "${TMPDIR:-/tmp}" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
  if [ -n "$avail_kb" ] && [ "$avail_kb" -gt 0 ] 2>/dev/null; then
    if [ "$avail_kb" -lt "$need_kb" ]; then
      warn "Low free space in ${TMPDIR:-/tmp} ($(( avail_kb / 1024 )) MB); build/download may fail"
    fi
  fi

  # Write permission to DEST.
  if [ "$SYSTEM" -eq 1 ]; then
    info "System install: will use sudo for $DEST"
  else
    if ! mkdir -p "$DEST" 2>/dev/null; then
      err "Cannot create destination directory: $DEST"; exit 1
    fi
    if ! ( : > "$DEST/.fsnow_write_test" ) 2>/dev/null; then
      err "Destination not writable: $DEST (use --system or --dest DIR)"; exit 1
    fi
    rm -f "$DEST/.fsnow_write_test"
  fi

  # Existing install.
  if [ -e "$DEST/$BINARY_NAME" ]; then
    info "Existing install detected at $DEST/$BINARY_NAME"
  fi

  # Network (best-effort; never blocks).
  if [ -z "$OFFLINE_TARBALL" ]; then
    if ! curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 5 --max-time 10 \
          -o /dev/null "https://github.com" 2>/dev/null; then
      warn "Network check to github.com failed; downloads may not work"
    fi
  fi
}

# ── Already-installed short-circuit (released versions only) ────────────────
check_installed_version() {
  # Returns 0 if the installed binary already reports VERSION.
  [ "$NO_RELEASE" -eq 1 ] && return 1
  [ -x "$DEST/$BINARY_NAME" ] || return 1
  local out
  out=$("$DEST/$BINARY_NAME" capabilities --json 2>/dev/null || true)
  if printf '%s' "$out" | grep -Eq "\"version\"[[:space:]]*:[[:space:]]*\"${VERSION_BARE}\""; then
    return 0
  fi
  return 1
}

# ── PATH helper ─────────────────────────────────────────────────────────────
maybe_add_path() {
  case ":$PATH:" in
    *:"$DEST":*) return 0 ;;
  esac
  if [ "$EASY" -eq 1 ]; then
    local updated=0 rc
    for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
      if [ -e "$rc" ] && [ -w "$rc" ]; then
        if ! grep -qF "$DEST" "$rc" 2>/dev/null; then
          # shellcheck disable=SC2016
          printf '\nexport PATH="%s:$PATH"\n' "$DEST" >> "$rc"
        fi
        updated=1
      fi
    done
    if [ "$updated" -eq 1 ]; then
      warn "Updated PATH in shell config; restart your shell to use ${BINARY_NAME}"
    else
      warn "Add ${DEST} to PATH to use ${BINARY_NAME}"
    fi
  else
    warn "Add ${DEST} to PATH to use ${BINARY_NAME} (or re-run with --easy-mode)"
  fi
}

# ── Rust / cargo ────────────────────────────────────────────────────────────
ensure_cargo() {
  if command -v cargo >/dev/null 2>&1; then
    return 0
  fi
  warn "cargo (the Rust toolchain) was not found — it is required to build from source."
  info "franken-snowflake pins a nightly toolchain via rust-toolchain.toml; rustup"
  info "will fetch it automatically once installed."
  local do_install=0
  if [ "$EASY" -eq 1 ]; then
    do_install=1
  elif [ "${RUSTUP_INIT_SKIP:-0}" = "0" ] && prompt_yes "Install Rust now via rustup?"; then
    do_install=1
  fi
  if [ "$do_install" -eq 1 ]; then
    info "Installing rustup..."
    curl -fsSL "${PROXY_ARGS[@]}" --proto '=https' --tlsv1.2 --connect-timeout 30 --max-time 300 \
      https://sh.rustup.rs | sh -s -- -y --profile minimal
    # shellcheck disable=SC1091
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
    export PATH="$HOME/.cargo/bin:$PATH"
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    err "cargo is still unavailable. Install Rust and re-run:"
    err "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    err "    # then: source \$HOME/.cargo/env"
    err "See https://rustup.rs for details."
    exit 1
  fi
}

# ── Install one binary file (sudo-aware) ────────────────────────────────────
install_file() {
  local src="$1" name="$2"
  if [ "$SYSTEM" -eq 1 ]; then
    sudo install -m 0755 "$src" "$DEST/$name"
  else
    install -m 0755 "$src" "$DEST/$name"
  fi
}

# ── Install the fsnow alias (real binary if present, else symlink) ──────────
install_alias() {
  local stage_dir="$1"
  local alias_src="$stage_dir/$ALIAS_NAME"
  if [ ! -x "$alias_src" ]; then
    alias_src=$(find "$stage_dir" -maxdepth 4 -type f -name "$ALIAS_NAME" -perm -111 2>/dev/null | head -n1 || true)
  fi
  if [ -n "$alias_src" ] && [ -x "$alias_src" ]; then
    install_file "$alias_src" "$ALIAS_NAME"
    ok "Installed alias ${DEST}/${ALIAS_NAME}"
  else
    # No standalone fsnow binary shipped — symlink it to the canonical binary.
    if [ "$SYSTEM" -eq 1 ]; then
      sudo ln -sf "$BINARY_NAME" "$DEST/$ALIAS_NAME"
    else
      ln -sf "$BINARY_NAME" "$DEST/$ALIAS_NAME"
    fi
    ok "Linked alias ${DEST}/${ALIAS_NAME} -> ${BINARY_NAME}"
  fi
}

# ── Checksum verification (dual tool) ───────────────────────────────────────
verify_checksum() {
  local file="$1" tarname="$2"
  if [ "$NO_VERIFY" -eq 1 ]; then
    warn "Skipping checksum verification (--no-verify)"
    return 0
  fi

  if [ -z "$CHECKSUM" ]; then
    local cksum_url="$CHECKSUM_URL"
    [ -z "$cksum_url" ] && cksum_url="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/SHA256SUMS"
    local cf="$TMP/SHA256SUMS"
    info "Fetching checksums from ${cksum_url}"
    if curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 15 --max-time 45 "$cksum_url" -o "$cf" 2>/dev/null; then
      CHECKSUM=$(grep -E "[[:space:]]\*?${tarname}\$" "$cf" 2>/dev/null | awk '{print $1}' | head -n1)
    fi
    if [ -z "$CHECKSUM" ]; then
      local side="${URL}.sha256"
      if curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 15 --max-time 45 "$side" -o "$cf" 2>/dev/null; then
        CHECKSUM=$(awk 'NF>=1 && $1 ~ /^[0-9a-fA-F]{64}$/ {print $1; exit}' "$cf")
      fi
    fi
  fi

  if [ -z "$CHECKSUM" ]; then
    warn "No checksum available for ${tarname}; skipping verification"
    return 0
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    if echo "${CHECKSUM}  ${file}" | sha256sum -c - >/dev/null 2>&1; then
      ok "Checksum verified"
      return 0
    fi
    err "Checksum mismatch for ${tarname}"
    exit 1
  elif command -v shasum >/dev/null 2>&1; then
    if echo "${CHECKSUM}  ${file}" | shasum -a 256 -c - >/dev/null 2>&1; then
      ok "Checksum verified"
      return 0
    fi
    err "Checksum mismatch for ${tarname}"
    exit 1
  else
    warn "Neither sha256sum nor shasum found; skipping checksum verification"
  fi
}

# ── Sigstore verification (best-effort; soft-skip without cosign) ───────────
verify_sigstore() {
  local file="$1" tarname="$2"
  command -v cosign >/dev/null 2>&1 || return 0
  local bundle="$TMP/${tarname}.sigstore"
  local bundle_url="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/${tarname}.sigstore"
  if curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 15 --max-time 45 "$bundle_url" -o "$bundle" 2>/dev/null; then
    info "Verifying Sigstore bundle"
    if cosign verify-blob --bundle "$bundle" "$file" >/dev/null 2>&1; then
      ok "Sigstore signature verified"
    else
      err "Sigstore verification FAILED for ${tarname}"; exit 1
    fi
  else
    info "No Sigstore bundle published; skipping signature verification"
  fi
}

# ── Extract a downloaded/offline archive into $TMP and return staging dir ────
extract_archive() {
  local archive="$1"
  info "Extracting $(basename "$archive")"
  case "$archive" in
    *.tar.xz)  tar -xJf "$archive" -C "$TMP" ;;
    *.tar.gz|*.tgz) tar -xzf "$archive" -C "$TMP" ;;
    *.tar)     tar -xf  "$archive" -C "$TMP" ;;
    *.zip)     command -v unzip >/dev/null 2>&1 || { err "unzip not found"; exit 1; }
               unzip -qo "$archive" -d "$TMP" ;;
    *) err "Unknown archive format: $archive"; exit 1 ;;
  esac
}

# ── Build from source ───────────────────────────────────────────────────────
# Preflight: this pre-release tree path-depends on ~10 sibling FrankenSuite repos
# by absolute path (none on crates.io yet), so cargo cannot even resolve a fresh
# external clone. Detect that up front and explain it, rather than letting cargo
# fail with a cryptic "can't read /dp/asupersync/Cargo.toml" after a delay.
preflight_frankensuite_deps() {
  local src="$1" r missing=()
  local roots
  roots=$(grep -oE '(/dp|/data/projects)/[A-Za-z0-9_]+' "$src/Cargo.toml" 2>/dev/null | sort -u)
  for r in $roots; do
    [ -d "$r" ] || missing+=("$r")
  done
  [ "${#missing[@]}" -eq 0 ] && return 0
  err "franken_snowflake is not yet standalone-buildable."
  err "Its workspace path-depends on sibling FrankenSuite crates that are not present"
  err "(this looks like a standalone clone). Missing sibling roots:"
  for r in "${missing[@]}"; do err "    $r"; done
  err ""
  err "Until the FrankenSuite is published to crates.io, build only inside a full"
  err "FrankenSuite checkout where these siblings exist at their expected paths."
  err "Sources: https://github.com/Dicklesworthstone/{asupersync,frankensqlite,fastmcp_rust,sqlmodel_rust,toon_rust}"
  return 1
}

build_from_source() {
  ensure_cargo

  local src
  if [ -n "$LOCAL_CHECKOUT" ]; then
    src="$LOCAL_CHECKOUT"
    info "Building from local checkout: $src"
  else
    command -v git >/dev/null 2>&1 || { err "git is required to fetch the source"; exit 1; }
    src="$TMP/src"
    info "Cloning ${OWNER}/${REPO}"
    if [ "$NO_RELEASE" -eq 0 ] && [ -n "$VERSION" ]; then
      git clone --depth 1 --branch "$VERSION" \
        "https://github.com/${OWNER}/${REPO}.git" "$src" 2>/dev/null \
        || git clone --depth 1 "https://github.com/${OWNER}/${REPO}.git" "$src"
    else
      git clone --depth 1 "https://github.com/${OWNER}/${REPO}.git" "$src"
    fi
  fi

  # Fail fast and clearly on a standalone external clone, before cargo emits a
  # cryptic "can't read /dp/asupersync/Cargo.toml" after a delay.
  preflight_frankensuite_deps "$src" || exit 2

  # Default build omits the live transport; --live opts into the real Snowflake
  # SQL API transport via `--features live`. The guarded array expansion keeps an
  # empty feature list safe under `set -u` on every bash version.
  local feature_args=()
  local feature_label="default features (no live transport)"
  if [ "$LIVE" -eq 1 ]; then
    feature_args=(--features live)
    feature_label="--features live (real Snowflake transport)"
  fi

  info "Compiling ${CLI_PACKAGE} (cargo build --release, ${feature_label})"
  info "This downloads crates and can take several minutes on first build..."
  # Unset target redirection so binaries land where we expect.
  (
    cd "$src" \
      && unset CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR CARGO_BUILD_TARGET \
      && cargo build --release -p "$CLI_PACKAGE" ${feature_args[@]+"${feature_args[@]}"}
  ) || {
    err "cargo build failed."
    if [ "$NO_RELEASE" -eq 1 ] && [ -z "$LOCAL_CHECKOUT" ]; then
      err "This pre-release tree pins sibling FrankenSuite crates by path (Asupersync,"
      err "etc.). A fresh external clone needs those crates present until the repo"
      err "migrates to crates.io dependencies. Build inside a full FrankenSuite checkout,"
      err "or run this installer from within a franken_snowflake source tree."
    fi
    exit 1
  }

  local rel="$src/target/release"
  local bin="$rel/$BINARY_NAME"
  if [ ! -x "$bin" ]; then
    bin=$(find "$src/target" -maxdepth 4 -type f -name "$BINARY_NAME" -perm -111 2>/dev/null | head -n1 || true)
  fi
  if [ -z "$bin" ] || [ ! -x "$bin" ]; then
    err "Build succeeded but ${BINARY_NAME} not found under $rel"
    exit 1
  fi

  install_file "$bin" "$BINARY_NAME"
  ok "Installed ${DEST}/${BINARY_NAME} (source build)"
  install_alias "$rel"
}

# ── Download + install a prebuilt artifact ──────────────────────────────────
download_with_progress() {
  local url="$1" dest="$2" label="${3:-Downloading}"
  if [ -t 1 ] && [ "$QUIET" -eq 0 ]; then
    printf '%s↓%s %s %s%s%s\n' "$C_CYAN" "$RESET" "$label" "$C_DIM" "$(basename "$url")" "$RESET"
    curl -fL "${PROXY_ARGS[@]}" --progress-bar --connect-timeout 30 --max-time 1800 "$url" -o "$dest"
  else
    info "$label"
    curl -fsSL "${PROXY_ARGS[@]}" --connect-timeout 30 --max-time 1800 "$url" -o "$dest"
  fi
}

install_from_artifact() {
  local archive="$1" tarname="$2"
  verify_checksum "$archive" "$tarname"
  verify_sigstore "$archive" "$tarname"
  extract_archive "$archive"

  local bin="$TMP/$BINARY_NAME"
  if [ ! -x "$bin" ]; then
    bin=$(find "$TMP" -maxdepth 4 -type f -name "$BINARY_NAME" -perm -111 2>/dev/null | head -n1 || true)
  fi
  if [ -z "$bin" ] || [ ! -x "$bin" ]; then
    err "Binary ${BINARY_NAME} not found in archive"
    exit 1
  fi

  install_file "$bin" "$BINARY_NAME"
  ok "Installed ${DEST}/${BINARY_NAME}"
  install_alias "$(dirname "$bin")"
}

acquire_artifact() {
  # Decide the artifact name/URL, download it, then install. Missing artifacts
  # are release errors; the installer never falls back to source builds.
  VERSION_BARE="${VERSION#v}"
  if [ -n "$ARTIFACT_URL" ]; then
    TAR=$(basename "$ARTIFACT_URL"); URL="$ARTIFACT_URL"
  elif [ -n "$TARGET" ]; then
    TAR="${BINARY_NAME}-v${VERSION_BARE}-${TARGET}.${EXT}"
    URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/${TAR}"
  else
    err "No prepared release target for ${OS}/${ARCH}."
    err "Use --from-source only for an explicit developer build."
    exit 1
  fi

  if ! download_with_progress "$URL" "$TMP/$TAR" "Downloading ${BINARY_NAME} ${VERSION}"; then
    err "Release artifact not found or download failed: ${TAR}"
    err "Expected URL: ${URL}"
    err "This installer will not build from source automatically."
    exit 1
  fi
  install_from_artifact "$TMP/$TAR" "$TAR"
}

# ── Optional shell completions (probe; this CLI has none today) ─────────────
maybe_install_completions() {
  local bin="$DEST/$BINARY_NAME"
  [ -x "$bin" ] || return 0
  # Only wire completions if the CLI actually exposes a `completions` subcommand.
  if "$bin" completions --help >/dev/null 2>&1; then
    local shell_name target
    shell_name=$(basename "${SHELL:-}")
    case "$shell_name" in
      bash) target="${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions/${BINARY_NAME}" ;;
      zsh)  target="${XDG_DATA_HOME:-$HOME/.local/share}/zsh/site-functions/_${BINARY_NAME}" ;;
      fish) target="${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions/${BINARY_NAME}.fish" ;;
      *)    return 0 ;;
    esac
    if mkdir -p "$(dirname "$target")" 2>/dev/null \
        && "$bin" completions "$shell_name" > "$target" 2>/dev/null; then
      ok "Installed ${shell_name} completions -> ${target}"
    fi
  fi
  # No `completions` subcommand exists in this CLI yet — skip silently.
  return 0
}

# ── Self-test (--verify): real no-account commands only ─────────────────────
run_self_test() {
  local bin="$DEST/$BINARY_NAME"
  info "Running self-test"
  # This CLI has no --version flag; use the dedicated `selftest` command and the
  # no-account `capabilities` smoke (which emits the version in its envelope).
  if ! "$bin" selftest >/dev/null 2>&1; then
    # selftest may print a structured envelope to stdout regardless; capture it.
    local out
    out=$("$bin" selftest 2>&1 || true)
    err "selftest failed:"; [ "$QUIET" -eq 0 ] && echo "$out" | head -n 20
    return 1
  fi
  ok "selftest passed"
  if "$bin" capabilities --json >/dev/null 2>&1; then
    ok "capabilities smoke passed"
  else
    warn "capabilities smoke did not succeed"
  fi
  return 0
}

# ── Cleanup / lock ──────────────────────────────────────────────────────────
cleanup() {
  [ -n "$TMP" ] && rm -rf "$TMP"
  if [ "$LOCKED" -eq 1 ]; then rm -rf "${LOCK_FILE}.d"; fi
}

acquire_lock() {
  local lockdir="${LOCK_FILE}.d"
  if mkdir "$lockdir" 2>/dev/null; then
    LOCKED=1; echo $$ > "$lockdir/pid"; return 0
  fi
  if [ -f "$lockdir/pid" ]; then
    local old; old=$(cat "$lockdir/pid" 2>/dev/null || echo "")
    if [ -n "$old" ] && ! kill -0 "$old" 2>/dev/null; then
      rm -rf "$lockdir"
      if mkdir "$lockdir" 2>/dev/null; then
        LOCKED=1; echo $$ > "$lockdir/pid"; return 0
      fi
    fi
  fi
  err "Another installer appears to be running (lock: $lockdir)"
  exit 1
}

# ── Final summary ───────────────────────────────────────────────────────────
print_summary() {
  [ "$QUIET" -eq 1 ] && return 0
  local mode="binary"
  [ "$FROM_SOURCE" -eq 1 ] && mode="source build"
  if [ "$HAS_GUM" -eq 1 ] && [ "$NO_GUM" -eq 0 ]; then
    echo ""
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
      "$(gum style --foreground 245 -- "Uninstall:  rm -f $DEST/$BINARY_NAME $DEST/$ALIAS_NAME")"
    echo ""
  else
    echo ""
    draw_box "$C_GREENB" \
      "${C_GREENB}Installation complete${RESET}" \
      "" \
      "Binary:  ${DEST}/${BINARY_NAME}" \
      "Alias:   ${DEST}/${ALIAS_NAME}" \
      "Version: ${VERSION} (${mode})" \
      "" \
      "${C_CYAN}Quick start:${RESET}" \
      "  franken-snowflake capabilities --json" \
      "  franken-snowflake agent-handbook" \
      "  fsnow doctor --json" \
      "  franken-snowflake mcp serve --stdio" \
      "" \
      "${C_YELLOW}Release binaries include the published live/MCP feature set; credentials are still runtime-gated.${RESET}" \
      "" \
      "Uninstall: rm -f ${DEST}/${BINARY_NAME} ${DEST}/${ALIAS_NAME}"
    echo ""
  fi
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
  detect_platform
  detect_local_checkout || true
  resolve_version

  acquire_lock
  TMP=$(mktemp -d)
  trap cleanup EXIT

  preflight_checks

  # Already-installed short-circuit (released versions only).
  if [ "$FORCE_INSTALL" -eq 0 ] && check_installed_version; then
    ok "${BINARY_NAME} ${VERSION} is already installed"
    info "Use --force to reinstall"
    print_summary
    exit 0
  fi

  if [ -n "$OFFLINE_TARBALL" ]; then
    [ -f "$OFFLINE_TARBALL" ] || { err "Offline tarball not found: $OFFLINE_TARBALL"; exit 1; }
    info "Installing from offline tarball: $OFFLINE_TARBALL"
    install_from_artifact "$OFFLINE_TARBALL" "$(basename "$OFFLINE_TARBALL")"
  elif [ "$FROM_SOURCE" -eq 1 ]; then
    build_from_source
  else
    acquire_artifact
  fi

  maybe_add_path
  maybe_install_completions

  if [ "$VERIFY" -eq 1 ]; then
    run_self_test || { err "Self-test failed"; exit 1; }
  fi

  print_summary
  ok "Done."
}

main
