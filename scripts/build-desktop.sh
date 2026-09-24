#!/usr/bin/env bash
# Build the Aegis desktop app (`docs/08`): builds the aegis-server sidecar,
# copies it into the Tauri sidecar slot with the target-triple suffix, builds
# the web bundle, and runs `tauri build`.
#
# Usage: scripts/build-desktop.sh          (debug-ish dev build)
#        RELEASE=1 scripts/build-desktop.sh  (release bundle)
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE_FLAG=""
if [[ "${RELEASE:-0}" == "1" ]]; then
  PROFILE_FLAG="--release"
  cargo build -p aegis-server --release
  SERVER=target/release/aegis-server
else
  cargo build -p aegis-server
  SERVER=target/debug/aegis-server
fi

# Tauri sidecars must be named <name>-<target-triple>[.exe].
TRIPLE=$(rustc -vV | awk '/host:/ {print $2}')
EXE=""
[[ "$TRIPLE" == *windows* ]] && EXE=".exe"
SIDECAR_DIR=crates/aegis-web/src-tauri/binaries
mkdir -p "$SIDECAR_DIR"
cp "$SERVER$EXE" "$SIDECAR_DIR/aegis-server-$TRIPLE$EXE"

cd crates/aegis-web
npm run build
npx tauri build $PROFILE_FLAG
