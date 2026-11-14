#!/usr/bin/env bash
# Same-tree server -> authenticated evaluate -> exact receipt fetch -> SDK verify.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d "${HELM_SDK_SCRATCH_ROOT:-${TMPDIR:-/tmp}}/helm-sdk-offline.XXXXXX")"
PORT="${HELM_SDK_OFFLINE_PORT:-$((20000 + RANDOM % 10000))}"
HEALTH_PORT="${HELM_SDK_OFFLINE_HEALTH_PORT:-$((30000 + RANDOM % 10000))}"
cleanup() {
  if [[ -n "${HELM_PID:-}" ]]; then kill "$HELM_PID" 2>/dev/null || true; wait "$HELM_PID" 2>/dev/null || true; fi
  if [[ "${HELM_SDK_KEEP_EVIDENCE:-0}" != 1 ]]; then rm -rf "$TMP"; fi
}
trap cleanup EXIT
mkdir -p "$TMP/state" "$TMP/receipts" "$TMP/home"
cp "$ROOT/examples/launch/policies/agent_tool_call_boundary.json" "$TMP/"
python3 - "$ROOT" "$TMP" <<'PYTHON'
from pathlib import Path
import sys
root, temporary = map(Path, sys.argv[1:])
policy = (root / "examples/launch/policies/agent_tool_call_boundary.toml").read_text()
(temporary / "policy.toml").write_text(policy.replace("./data/launch_receipts.db", str(temporary / "state/receipts.db")))
PYTHON
(cd "$ROOT/core" && go build -o "$TMP/helm" ./cmd/helm-ai-kernel)
python3 -m venv "$TMP/venv"
"$TMP/venv/bin/python" -m pip install --quiet --require-hashes -r "$ROOT/sdk/python/requirements-runtime.txt"
npm --prefix "$ROOT/sdk/ts" ci
npm --prefix "$ROOT/sdk/ts" run build
export HELM_URL="http://127.0.0.1:$PORT"
export HELM_ADMIN_API_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export HELM_RUNTIME_TENANT_ID=sdk-offline-tenant HELM_RUNTIME_PRINCIPAL_ID=sdk-offline-principal
export HELM_SDK_EVIDENCE_DIR="$TMP/receipts"
# Keep host database/provider credentials and configuration out of this local run.
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
export NO_PROXY=127.0.0.1,localhost
env -i PATH="$PATH" HOME="$TMP/home" HELM_ADMIN_API_KEY="$HELM_ADMIN_API_KEY" \
  HELM_RUNTIME_TENANT_ID="$HELM_RUNTIME_TENANT_ID" \
  HELM_RUNTIME_PRINCIPAL_ID="$HELM_RUNTIME_PRINCIPAL_ID" \
  HELM_RECEIPT_PROFILE=classical HELM_HEALTH_PORT="$HEALTH_PORT" "$TMP/helm" serve \
  --policy "$TMP/policy.toml" \
  --addr 127.0.0.1 --port "$PORT" --data-dir "$TMP/state" > "$TMP/server.log" 2>&1 &
HELM_PID=$!
for _ in {1..120}; do
  kill -0 "$HELM_PID" 2>/dev/null || { cat "$TMP/server.log"; exit 1; }
  if curl -fsS "$HELM_URL/api/health" > "$TMP/health.json"; then break; fi
  sleep .25
done
if ! curl -fsS "$HELM_URL/api/health" > "$TMP/health.json"; then cat "$TMP/server.log"; exit 1; fi
status="$(curl -sS -o "$TMP/unauthorized.json" -w '%{http_code}' "$HELM_URL/api/v1/evaluate" -H 'Content-Type: application/json' -d '{"tool":"read-ticket","effect_level":"ticket:SDK-100","session_id":"unauthorized-sdk"}')"
[[ "$status" == 401 ]] || { echo "Unauthenticated evaluate returned $status"; exit 1; }
# The test operator pins the locally provisioned public key, independently of
# receipt content. No API-served or embedded key becomes the SDK trust root.
export HELM_TRUSTED_RECEIPT_KEY="$(cat "$TMP/state/root.pub")"
(cd "$ROOT/sdk/go" && go run "$ROOT/scripts/sdk/offline_roundtrip/main.go") | tee "$TMP/go.jsonl"
PYTHONPATH="$ROOT/sdk/python" "$TMP/venv/bin/python" "$ROOT/scripts/sdk/offline_roundtrip/main.py" | tee "$TMP/python.jsonl"
node "$ROOT/scripts/sdk/offline_roundtrip/main.mjs" | tee "$TMP/ts.jsonl"
# Only the SDK verifiers run from here: the same-tree server has exited.
kill -INT "$HELM_PID"
wait "$HELM_PID"
HELM_PID=""
(cd "$ROOT/sdk/go" && go run "$ROOT/scripts/sdk/offline_roundtrip/main.go" --offline) | tee "$TMP/go-offline.jsonl"
PYTHONPATH="$ROOT/sdk/python" "$TMP/venv/bin/python" "$ROOT/scripts/sdk/offline_roundtrip/main.py" --offline | tee "$TMP/python-offline.jsonl"
node "$ROOT/scripts/sdk/offline_roundtrip/main.mjs" --offline | tee "$TMP/ts-offline.jsonl"
echo 'SDK offline receipt round trips passed.'
if [[ "${HELM_SDK_KEEP_EVIDENCE:-0}" == 1 ]]; then printf 'Evidence: %s\n' "$TMP"; fi
