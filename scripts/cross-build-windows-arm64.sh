#!/usr/bin/env bash
# Cross-compile the CLI for aarch64-pc-windows-msvc from Linux with cargo-xwin.
#
# Why this needs a script (2026-09-03):
#   * `ring` compiles its arm64 C sources with plain `clang` and rejects the
#     clang-cl style `/imsvc` include flags cargo-xwin exports in its default
#     mode, so the clang driver (`--cross-compiler clang`) is required.
#   * In clang mode blake3's NEON C path includes MSVC's arm_neon.h, which that
#     driver cannot compile; the cache and export crates select blake3's
#     pure-Rust implementation for this target only (same digests).
#   * cargo-xwin's clang-mode sysroot ships lowercase import libraries but
#     asupersync links `Kernel32` with a capital K; on a case-sensitive
#     filesystem lld-link cannot find it. This script adds capitalized aliases
#     next to the lowercase files (idempotent, cache-local).
# The native build on a Windows host with MSVC + clang needs none of this; this
# is the Linux-only fallback documented in docs/RELEASE.md.
#
# Usage: scripts/cross-build-windows-arm64.sh [extra cargo args]
set -eu
cd "$(dirname "$0")/.."

command -v cargo-xwin >/dev/null 2>&1 || { echo "cargo-xwin is required (cargo install cargo-xwin)" >&2; exit 74; }
command -v clang >/dev/null 2>&1 || { echo "clang is required" >&2; exit 74; }

SYSROOT="${XWIN_SYSROOT:-$HOME/.cache/cargo-xwin/windows-msvc-sysroot/windows-msvc-sysroot}"
LIBDIR="$SYSROOT/lib/aarch64-unknown-windows-msvc"
if [ -d "$LIBDIR" ]; then
  for name in kernel32 user32 advapi32 ws2_32 bcrypt secur32 crypt32 ntdll userenv ole32 oleaut32 shell32; do
    upper="$(printf '%s' "$name" | sed 's/./\U&/')"
    [ -e "$LIBDIR/$upper.lib" ] || ln -s "$name.lib" "$LIBDIR/$upper.lib"
  done
fi

# The rch cargo shim refuses Windows targets when the fleet has no Windows
# worker; run the real cargo locally for this build.
export RCH_SHIM_LOCAL_IDE=1 RCH_CARGO_WRAPPER_BYPASS=1
if [ -z "${RCH_REAL_CARGO:-}" ]; then
  sysroot_rust=$(rustc --print sysroot)
  [ -x "$sysroot_rust/bin/cargo-rch-real" ] && export RCH_REAL_CARGO="$sysroot_rust/bin/cargo-rch-real"
fi

exec cargo xwin build --cross-compiler clang --locked --release \
  --target aarch64-pc-windows-msvc -p franken-snowflake-cli --features live,mcp "$@"
