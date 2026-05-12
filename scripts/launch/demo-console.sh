#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

echo "==> HELM Launch Demo: Console Smoke"

pick_port() {
  python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    print(s.getsockname()[1])
PY
}

wait_for() {
  local url="$1"
  for _ in $(seq 1 60); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "timed out waiting for $url" >&2
  return 1
}

PORT="$(pick_port)"
HEALTH_PORT="$(pick_port)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/helm-console-demo.XXXXXX")"
ADMIN_KEY="launch-console-admin-key"
LOG_FILE="$TMP_DIR/console.log"

cleanup() {
  if [[ -n "${HELM_PID:-}" ]]; then
    kill "$HELM_PID" >/dev/null 2>&1 || true
    wait "$HELM_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

make build-console >/dev/null
make build >/dev/null

HELM_ADMIN_API_KEY="$ADMIN_KEY" \
HELM_HEALTH_PORT="$HEALTH_PORT" \
./bin/helm serve \
  --console \
  --console-dir apps/console/dist \
  --policy examples/launch/policies/agent_tool_call_boundary.toml \
  --addr 127.0.0.1 \
  --port "$PORT" \
  --data-dir "$TMP_DIR/state" \
  >"$LOG_FILE" 2>&1 &
HELM_PID=$!

wait_for "http://127.0.0.1:$HEALTH_PORT/healthz"

curl -fsS "http://127.0.0.1:$PORT/" >/dev/null
BOOTSTRAP="$(curl -fsS \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "X-Helm-Tenant-ID: launch-demo" \
  "http://127.0.0.1:$PORT/api/v1/console/bootstrap")"

python3 - "$BOOTSTRAP" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
health = payload.get("health", {})
if health.get("kernel") != "ready" or health.get("policy") != "ready" or health.get("store") != "ready":
    raise SystemExit(f"unexpected console health: {payload.get('health')}")
if payload.get("version", {}).get("version") not in {"0.5.0", "v0.5.0"}:
    raise SystemExit(f"unexpected console version: {payload.get('version')}")
mcp = payload.get("mcp", {})
if mcp.get("authorization") != "local" or not mcp.get("scopes"):
    raise SystemExit(f"unexpected console MCP summary: {mcp}")
PY

echo "✅ Console build and localhost runtime smoke passed"
