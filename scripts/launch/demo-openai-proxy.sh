#!/usr/bin/env bash
set -e

echo "==> HELM Launch Demo: OpenAI Governance Proxy"
echo "Demonstrating how HELM acts as a transparent, governed proxy for the OpenAI SDK."
echo ""

make build > /dev/null

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/helm-openai-proxy-demo.XXXXXX")"
UPSTREAM_PORT="${HELM_MOCK_OPENAI_PORT:-19090}"
PROXY_PORT="${HELM_PROXY_PORT:-19091}"
UPSTREAM_PID=""
PROXY_PID=""

cleanup() {
  if [ -n "$PROXY_PID" ]; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if [ -n "$UPSTREAM_PID" ]; then
    kill "$UPSTREAM_PID" 2>/dev/null || true
    wait "$UPSTREAM_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "==> 1. Starting local OpenAI-compatible mock upstream on :$UPSTREAM_PORT"
python3 scripts/launch/mock-openai-upstream.py --port "$UPSTREAM_PORT" > "$TMP_DIR/upstream.log" 2>&1 &
UPSTREAM_PID=$!
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/healthz" > /dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://127.0.0.1:$UPSTREAM_PORT/healthz" > /dev/null

echo "==> 2. Starting HELM Proxy on :$PROXY_PORT"
./bin/helm-ai-kernel proxy \
  --upstream "http://127.0.0.1:$UPSTREAM_PORT/v1" \
  --port "$PROXY_PORT" \
  --tenant-id "launch-demo-tenant" \
  --daily-limit 5000 \
  --receipts-dir "$TMP_DIR/proxy-receipts" > "$TMP_DIR/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$PROXY_PORT/healthz" > /dev/null 2>&1 && break
  sleep 0.1
done
curl -fsS "http://127.0.0.1:$PROXY_PORT/healthz" > /dev/null

echo ""
echo "==> 3. Sending ChatCompletion request via proxy"
echo "We configure the OpenAI SDK to use http://127.0.0.1:$PROXY_PORT/v1 as the base URL."
echo ""

curl -fsS -X POST "http://127.0.0.1:$PROXY_PORT/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer mock-key" \
  -d '{
    "model": "helm-local-mock",
    "messages": [{"role": "user", "content": "Hello, HELM!"}]
  }' > "$TMP_DIR/proxy-response.json"
python3 - "$TMP_DIR/proxy-response.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
assert payload["id"] == "chatcmpl-helm-local-fixture"
assert payload["choices"][0]["message"]["content"] == "local fixture response"
PY
cat "$TMP_DIR/proxy-response.json"

echo ""
echo "==> 4. Verifying the Intercepted Receipt"
echo "HELM logs the input token intent, enforces the daily budget, and outputs a cryptographically signed receipt."
echo ""
receipt_file="$(find "$TMP_DIR/proxy-receipts" -name '*.jsonl' -type f | sort | tail -n 1)"
test -s "$receipt_file"
tail -n 1 "$receipt_file" | python3 -c 'import json,sys; payload=json.load(sys.stdin); assert payload["status"] == "APPROVED"; assert payload["upstream"].startswith("http://127.0.0.1:")'
