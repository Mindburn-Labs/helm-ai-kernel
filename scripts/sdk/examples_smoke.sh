#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
PORT="${HELM_SDK_EXAMPLES_PORT:-$((18000 + (RANDOM % 1000)))}"
HEALTH_PORT="${HELM_SDK_EXAMPLES_HEALTH_PORT:-$((19000 + (RANDOM % 1000)))}"
HELM_URL="http://127.0.0.1:${PORT}"
SERVER_LOG="$TMP/helm-server.log"
ADMIN_KEY="${HELM_ADMIN_API_KEY:-sdk-examples-local-admin-key}"
TENANT_ID="${HELM_TENANT_ID:-sdk-examples}"

cleanup() {
  if [ -n "${HELM_PID:-}" ]; then
    kill "$HELM_PID" 2>/dev/null || true
    wait "$HELM_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

cd "$ROOT"

make build

cd "$ROOT/sdk/python"
python -m pip install -q .

cd "$ROOT/sdk/ts"
npm ci
npm run build

cd "$ROOT"
HELM_ADMIN_API_KEY="$ADMIN_KEY" HELM_HEALTH_PORT="$HEALTH_PORT" ./bin/helm serve \
  --policy examples/launch/policies/agent_tool_call_boundary.toml \
  --addr 127.0.0.1 \
  --port "$PORT" \
  --data-dir "$TMP/state" \
  >"$SERVER_LOG" 2>&1 &
HELM_PID=$!

for _ in $(seq 1 60); do
  if curl -fsS "$HELM_URL/api/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

if ! curl -fsS "$HELM_URL/api/health" >/dev/null 2>&1; then
  cat "$SERVER_LOG"
  echo "HELM server did not become healthy"
  exit 1
fi

PYTHONPATH="$ROOT/sdk/python" HELM_URL="$HELM_URL" HELM_ADMIN_API_KEY="$ADMIN_KEY" HELM_TENANT_ID="$TENANT_ID" python "$ROOT/examples/python_sdk/main.py" | tee "$TMP/python_sdk.json"

"$ROOT/sdk/ts/node_modules/.bin/tsc" -p "$ROOT/examples/ts_sdk/tsconfig.json"
HELM_URL="$HELM_URL" HELM_ADMIN_API_KEY="$ADMIN_KEY" HELM_TENANT_ID="$TENANT_ID" node "$ROOT/examples/ts_sdk/dist/main.js" | tee "$TMP/ts_sdk.json"

if grep -R -E '"(DEFER|REQUIRE_APPROVAL)"' "$TMP/python_sdk.json" "$TMP/ts_sdk.json"; then
  echo "SDK examples emitted a non-canonical public verdict"
  exit 1
fi

echo "SDK examples smoke passed."
