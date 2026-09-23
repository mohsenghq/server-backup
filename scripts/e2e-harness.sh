#!/usr/bin/env bash
# E2E harness (CI + local): starts the in-process SSH test server, seeds an
# admin user and a host entry pointing at it, then runs aegis-server on
# 127.0.0.1:8080. Used by the `e2e` CI job; locally:
#   ./scripts/e2e-harness.sh &
#   cd crates/aegis-web && npx playwright test
set -euo pipefail

cd "$(dirname "$0")/.."

export AEGIS_PASSPHRASE="${AEGIS_PASSPHRASE:-e2e-passphrase}"
SSH_PORT="${AEGIS_E2E_SSH_PORT:-2222}"
CATALOG="${AEGIS_CATALOG:-/tmp/aegis-e2e/catalog.db}"

mkdir -p "$(dirname "$CATALOG")"

# 1. Start the in-process SSH test server on the fixed port (binary below
#    reuses the aegis-core test harness). It seeds /srv/backup-me with a few
#    files and accepts password auth (aegis / test-passphrase).
export AEGIS_E2E_SSH_PORT="$SSH_PORT"
cargo run -q -p aegis-server --bin aegis-e2e-sshd &
SSHD_PID=$!
trap 'kill $SSHD_PID 2>/dev/null || true' EXIT

wait_for_port() {
  for _ in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then exec 3>&-; return 0; fi
    sleep 1
  done
  echo "e2e-harness: port $1 never came up" >&2
  return 1
}
wait_for_port "$SSH_PORT"

# 2. Seed the catalog: admin user (password via env, never argv) and the
#    SSH target host (password auth via AEGIS_SSH_PASSWORD at backup time).
AEGIS_USER_PASSWORD=admin-password-123 \
  cargo run -q -p aegis-cli -- user add --catalog "$CATALOG" --username admin

AEGIS_SSH_PASSWORD=test-passphrase \
  cargo run -q -p aegis-cli -- host add --catalog "$CATALOG" \
  --name e2e-host --address 127.0.0.1 --port "$SSH_PORT" \
  --user aegis-test --mode agentless

# 2b. Create the target repository the E2E backups will write into.
REPO="${AEGIS_E2E_REPO:-/tmp/aegis-e2e/repo}"
AEGIS_PASSPHRASE=e2e-passphrase cargo run -q -p aegis-cli -- init --repo "$REPO" >/dev/null

# 3. Start the control plane server itself.
export AEGIS_CATALOG="$CATALOG"
export AEGIS_LISTEN="127.0.0.1:8080"
export AEGIS_SSH_PASSWORD=test-passphrase
exec cargo run -q -p aegis-server --bin aegis-server
